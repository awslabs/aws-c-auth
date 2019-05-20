/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_query.h>
#include <aws/common/clock.h>
#include <aws/common/environment.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/io/logging.h>

#include <inttypes.h>

#define DEFAULT_CREDENTIAL_PROVIDER_REFRESH_MS (15 * 60 * 1000)

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

/*
 * Credentials API implementations
 */

struct aws_credentials *aws_credentials_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token) {

    struct aws_credentials *credentials = aws_mem_acquire(allocator, sizeof(struct aws_credentials));
    if (credentials == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*credentials);

    credentials->allocator = allocator;

    if (access_key_id != NULL) {
        credentials->access_key_id = aws_string_new_from_string(allocator, access_key_id);
    }

    if (secret_access_key != NULL) {
        credentials->secret_access_key = aws_string_new_from_string(allocator, secret_access_key);
    }

    if (session_token != NULL) {
        credentials->session_token = aws_string_new_from_string(allocator, session_token);
    }

    return credentials;
}

struct aws_credentials *aws_credentials_new_copy(struct aws_allocator *allocator, struct aws_credentials *credentials) {
    if (credentials != NULL) {
        return aws_credentials_new(
            allocator, credentials->access_key_id, credentials->secret_access_key, credentials->session_token);
    }

    return NULL;
}

void aws_credentials_destroy(struct aws_credentials *credentials) {
    if (credentials == NULL) {
        return;
    }

    if (credentials->access_key_id != NULL) {
        aws_string_destroy(credentials->access_key_id);
    }

    if (credentials->secret_access_key != NULL) {
        aws_string_destroy_secure(credentials->secret_access_key);
    }

    if (credentials->session_token != NULL) {
        aws_string_destroy(credentials->session_token);
    }

    aws_mem_release(credentials->allocator, credentials);
}

/*
 * global provider APIs
 */

static void s_aws_credentials_provider_destroy(struct aws_credentials_provider *provider) {
    if (provider != NULL) {
        /* allow this to be null to support partial construction cleanup */
        if (provider->vtable->clean_up) {
            provider->vtable->clean_up(provider);
        }

        aws_mem_release(provider->allocator, provider);
    }
}

void aws_credentials_provider_shutdown(struct aws_credentials_provider *provider) {
    aws_atomic_store_int(&provider->shutting_down, 1);

    AWS_ASSERT(provider->vtable->shutdown);
    provider->vtable->shutdown(provider);
}

void aws_credentials_provider_release(struct aws_credentials_provider *provider) {
    size_t old_value = aws_atomic_fetch_sub(&provider->ref_count, 1);
    if (old_value == 1) {
        s_aws_credentials_provider_destroy(provider);
    }
}

void aws_credentials_provider_acquire(struct aws_credentials_provider *provider) {
    aws_atomic_fetch_add(&provider->ref_count, 1);
}

int aws_credentials_provider_get_credentials(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    AWS_ASSERT(provider->vtable->get_credentials);

    return provider->vtable->get_credentials(provider, callback, user_data);
}

static void s_credentials_provider_init_base(
    struct aws_credentials_provider *provider,
    struct aws_allocator *allocator,
    struct aws_credentials_provider_vtable *vtable,
    void *impl) {
    provider->allocator = allocator;
    provider->vtable = vtable;
    provider->impl = impl;
    aws_atomic_store_int(&provider->shutting_down, 0);
    aws_atomic_store_int(&provider->ref_count, 1);
}

/*
 * Static provider implementation
 *
 * Just stuff the credentials in the impl member, and don't bother wrapping them
 */
static int s_static_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials *credentials = provider->impl;

    AWS_LOGF_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Static credentials provider successfully sourced credentials",
        (void *)provider);
    callback(credentials, user_data);

    return AWS_OP_SUCCESS;
}

static void s_static_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials *credentials = provider->impl;

    if (credentials != NULL) {
        aws_credentials_destroy(credentials);
    }
}

/*
 * shared across all providers that do not need to do anything special on shutdown
 */
static void s_sync_credentials_provider_shutdown(struct aws_credentials_provider *provider) {
    (void)provider;
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_static_vtable = {
    .get_credentials = s_static_credentials_provider_get_credentials_async,
    .clean_up = s_static_credentials_provider_clean_up,
    .shutdown = s_sync_credentials_provider_shutdown};

struct aws_credentials_provider *aws_credentials_provider_static_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token) {

    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    struct aws_credentials *credentials =
        aws_credentials_new(allocator, access_key_id, secret_access_key, session_token);
    if (credentials == NULL) {
        goto on_new_credentials_failure;
    }

    s_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_static_vtable, credentials);

    return provider;

on_new_credentials_failure:

    aws_mem_release(allocator, provider);

    return NULL;
}

/*
 *  Environment provider implementation.
 */
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_env_var, "AWS_ACCESS_KEY_ID");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_env_var, "AWS_SECRET_ACCESS_KEY");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_env_var, "AWS_SESSION_TOKEN");

static int s_credentials_provider_environment_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_allocator *allocator = provider->allocator;

    struct aws_credentials *credentials = aws_mem_acquire(allocator, sizeof(struct aws_credentials));
    if (credentials == NULL) {
        callback(NULL, user_data);
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*credentials);
    credentials->allocator = allocator;

    if (aws_get_environment_value(allocator, s_access_key_id_env_var, &credentials->access_key_id) != 0 ||
        aws_get_environment_value(allocator, s_secret_access_key_env_var, &credentials->secret_access_key) != 0 ||
        credentials->access_key_id == NULL || credentials->secret_access_key == NULL) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Environment credentials provider was unable to source credentials",
            (void *)provider);
        callback(NULL, user_data);
    } else {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Environment credentials provider successfully sourced credentials",
            (void *)provider);
        aws_get_environment_value(allocator, s_session_token_env_var, &credentials->session_token);
        callback(credentials, user_data);
    }

    if (credentials != NULL) {
        aws_credentials_destroy(credentials);
    }

    return AWS_OP_SUCCESS;
}

static void s_credentials_provider_environment_clean_up(struct aws_credentials_provider *provider) {
    (void)provider;
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_environment_vtable = {
    .get_credentials = s_credentials_provider_environment_get_credentials_async,
    .clean_up = s_credentials_provider_environment_clean_up,
    .shutdown = s_sync_credentials_provider_shutdown};

struct aws_credentials_provider *aws_credentials_provider_new_environment(struct aws_allocator *allocator) {
    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    s_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_environment_vtable, NULL);

    return provider;
}

/*
 * Cached provider implementation
 */

/*

 ToDo: credentials expiration environment overrides

AWS_STATIC_STRING_FROM_LITERAL(s_credential_expiration_env_var, "AWS_CREDENTIAL_EXPIRATION");

*/

struct aws_credentials_provider_cached {
    struct aws_credentials_provider *source;
    struct aws_credentials *cached_credentials;
    struct aws_mutex lock;
    uint64_t refresh_interval_in_ns;
    uint64_t next_refresh_time;
    aws_io_clock_fn *clock_fn;
    struct aws_linked_list pending_queries;
};

static void s_aws_credentials_query_list_notify_and_clean_up(
    struct aws_linked_list *query_list,
    struct aws_allocator *allocator,
    struct aws_credentials *credentials) {
    while (!aws_linked_list_empty(query_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(query_list);
        struct aws_credentials_query *query = AWS_CONTAINER_OF(node, struct aws_credentials_query, node);
        query->callback(credentials, query->user_data);
        aws_credentials_query_clean_up(query);
        aws_mem_release(allocator, query);
    }
}

static void s_cached_credentials_provider_get_credentials_async_callback(
    struct aws_credentials *credentials,
    void *user_data) {

    struct aws_credentials_provider *provider = user_data;
    struct aws_credentials_provider_cached *impl = provider->impl;

    aws_mutex_lock(&impl->lock);

    /*
     * Move pending queries so that we can do notifications outside the lock
     */
    struct aws_linked_list pending_queries;
    aws_linked_list_init(&pending_queries);

    aws_linked_list_swap_contents(&pending_queries, &impl->pending_queries);

    if (impl->refresh_interval_in_ns > 0) {
        uint64_t now = 0;
        if (!impl->clock_fn(&now)) {
            impl->next_refresh_time = now + impl->refresh_interval_in_ns;
        }
    } else {
        impl->next_refresh_time = UINT64_MAX;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Cached credentials provider next refresh time set to %" PRIu64,
        (void *)provider,
        impl->next_refresh_time);

    if (impl->cached_credentials != NULL) {
        aws_credentials_destroy(impl->cached_credentials);
    }

    if (credentials != NULL) {
        impl->cached_credentials = aws_credentials_new_copy(provider->allocator, credentials);
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider succesfully sourced credentials on refresh",
            (void *)provider);
    } else {
        impl->cached_credentials = NULL;
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider was unable to source credentials on refresh",
            (void *)provider);
    }

    aws_mutex_unlock(&impl->lock);

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Cached credentials provider notifying pending queries of new credentials",
        (void *)provider);

    s_aws_credentials_query_list_notify_and_clean_up(&pending_queries, provider->allocator, credentials);
}

static int s_cached_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_cached *impl = provider->impl;

    uint64_t current_time = 0;
    impl->clock_fn(&current_time);

    bool should_submit_query = false;
    bool perform_callback = false;
    struct aws_credentials *credentials = NULL;
    bool is_shutting_down = aws_atomic_load_int(&provider->shutting_down) != 0;

    aws_mutex_lock(&impl->lock);

    if (current_time < impl->next_refresh_time || is_shutting_down) {
        perform_callback = true;
        credentials = aws_credentials_new_copy(provider->allocator, impl->cached_credentials);
    } else {
        struct aws_credentials_query *query =
            aws_mem_acquire(provider->allocator, sizeof(struct aws_credentials_query));
        if (query != NULL) {
            aws_credentials_query_init(query, provider, callback, user_data);
            should_submit_query = aws_linked_list_empty(&impl->pending_queries);
            aws_linked_list_push_back(&impl->pending_queries, &query->node);
        } else {
            perform_callback = true;
        }
    }

    aws_mutex_unlock(&impl->lock);

    if (should_submit_query) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider has expired credentials.  Requerying.",
            (void *)provider);

        aws_credentials_provider_get_credentials(
            impl->source, s_cached_credentials_provider_get_credentials_async_callback, provider);

    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider has expired credentials.  Waiting on existing query.",
            (void *)provider);
    }

    if (perform_callback) {
        if (credentials != NULL) {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Cached credentials provider successfully sourced from cache",
                (void *)provider);
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Cached credentials provider failed to source credentials while skipping requery",
                (void *)provider);
        }
        callback(credentials, user_data);
        aws_credentials_destroy(credentials);
    }

    return AWS_OP_SUCCESS;
}

static void s_cached_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_cached *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_credentials_provider_release(impl->source);

    if (impl->cached_credentials != NULL) {
        aws_credentials_destroy(impl->cached_credentials);
    }

    aws_mutex_clean_up(&impl->lock);
}

static void s_cached_credentials_provider_shutdown(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_cached *impl = provider->impl;
    aws_credentials_provider_shutdown(impl->source);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_cached_vtable = {
    .get_credentials = s_cached_credentials_provider_get_credentials_async,
    .clean_up = s_cached_credentials_provider_clean_up,
    .shutdown = s_cached_credentials_provider_shutdown};

struct aws_credentials_provider *aws_credentials_provider_new_cached(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_cached_options *options) {
    AWS_ASSERT(options->source != NULL);

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_cached *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_cached));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    s_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_cached_vtable, impl);

    if (aws_mutex_init(&impl->lock)) {
        goto on_error;
    }

    aws_linked_list_init(&impl->pending_queries);

    impl->source = options->source;
    aws_credentials_provider_acquire(impl->source);

    if (options->refresh_time_in_milliseconds > 0) {
        impl->refresh_interval_in_ns = aws_timestamp_convert(
            options->refresh_time_in_milliseconds, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    } else {
        /*
         * TODO: query AWS_CREDENTIAL_EXPIRATION for a refresh override
         *
         * This must be an ISO 8601 time interval which we don't have a parser for yet (one could be cobbled
         * together from the existing timestamp parser).  Does not seem important enough to get bogged down in atm.
         * Punting for now.
         */
        impl->refresh_interval_in_ns = 0;
    }

    if (options->clock_fn != NULL) {
        impl->clock_fn = options->clock_fn;
    } else {
        impl->clock_fn = &aws_high_res_clock_get_ticks;
    }

    return provider;

on_error:
    s_aws_credentials_provider_destroy(provider);

    return NULL;
}

/*
 * Profile provider implementation
 */

struct aws_credentials_provider_profile_file_impl {
    struct aws_string *config_file_path;
    struct aws_string *credentials_file_path;
    struct aws_string *profile_name;
};

static int s_profile_file_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_profile_file_impl *impl = provider->impl;
    struct aws_credentials *credentials = NULL;

    /*
     * Parse config file, if it exists
     */
    struct aws_profile_collection *config_profiles =
        aws_profile_collection_new_from_file(provider->allocator, impl->config_file_path, AWS_PST_CONFIG);

    if (config_profiles != NULL) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider successfully built config profile collection from file at (%s)",
            (void *)provider,
            (const char *)impl->config_file_path->bytes);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed to build config profile collection from file at (%s)",
            (void *)provider,
            (const char *)impl->config_file_path->bytes);
    }

    /*
     * Parse credentials file, if it exists
     */
    struct aws_profile_collection *credentials_profiles =
        aws_profile_collection_new_from_file(provider->allocator, impl->credentials_file_path, AWS_PST_CREDENTIALS);

    if (credentials_profiles != NULL) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider successfully built credentials profile collection from file at (%s)",
            (void *)provider,
            (const char *)impl->credentials_file_path->bytes);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed to build credentials profile collection from file at (%s)",
            (void *)provider,
            (const char *)impl->credentials_file_path->bytes);
    }

    /*
     * Merge the (up to) two sources into a single unified profile
     */
    struct aws_profile_collection *merged_profiles =
        aws_profile_collection_new_from_merge(provider->allocator, config_profiles, credentials_profiles);
    if (merged_profiles != NULL) {
        struct aws_profile *profile = aws_profile_collection_get_profile(merged_profiles, impl->profile_name);
        if (profile != NULL) {
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Profile credentials provider attempting to pull credentials from profile \"%s\"",
                (void *)provider,
                (const char *)impl->profile_name->bytes);
            credentials = aws_credentials_new_from_profile(provider->allocator, profile);
        } else {
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Profile credentials provider could not find a profile named \"%s\"",
                (void *)provider,
                (const char *)impl->profile_name->bytes);
        }
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed to merge config and credentials profile collections",
            (void *)provider);
    }

    callback(credentials, user_data);

    /*
     * clean up
     */
    aws_credentials_destroy(credentials);
    aws_profile_collection_destroy(merged_profiles);
    aws_profile_collection_destroy(config_profiles);
    aws_profile_collection_destroy(credentials_profiles);

    return AWS_OP_SUCCESS;
}

static void s_profile_file_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_profile_file_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_string_destroy(impl->config_file_path);
    aws_string_destroy(impl->credentials_file_path);
    aws_string_destroy(impl->profile_name);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_profile_file_vtable = {
    .get_credentials = s_profile_file_credentials_provider_get_credentials_async,
    .clean_up = s_profile_file_credentials_provider_clean_up,
    .shutdown = s_sync_credentials_provider_shutdown};

struct aws_credentials_provider *aws_credentials_provider_new_profile(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_profile_options *options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_profile_file_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_profile_file_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    s_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_profile_file_vtable, impl);

    impl->credentials_file_path = aws_get_credentials_file_path(allocator, options->credentials_file_name_override);
    if (impl->credentials_file_path == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed resolve credentials file path",
            (void *)provider);
        goto on_error;
    }

    impl->config_file_path = aws_get_config_file_path(allocator, options->config_file_name_override);
    if (impl->config_file_path == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed resolve config file path",
            (void *)provider);
        goto on_error;
    }

    impl->profile_name = aws_get_profile_name(allocator, options->profile_name_override);
    if (impl->profile_name == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed to resolve profile name",
            (void *)provider);
        goto on_error;
    }

    return provider;

on_error:
    s_aws_credentials_provider_destroy(provider);

    return NULL;
}

/*
 * Provider chain implementation
 */

struct aws_credentials_provider_chain_impl {
    struct aws_array_list providers;
};

struct aws_credentials_provider_chain_user_data {
    struct aws_allocator *allocator;
    struct aws_credentials_provider *provider_chain;
    size_t current_provider_index;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;
};

void aws_provider_chain_member_callback(struct aws_credentials *credentials, void *user_data) {
    struct aws_credentials_provider_chain_user_data *wrapped_user_data = user_data;
    struct aws_credentials_provider *provider = wrapped_user_data->provider_chain;
    struct aws_credentials_provider_chain_impl *impl = provider->impl;

    size_t provider_count = aws_array_list_length(&impl->providers);
    bool is_shutting_down = aws_atomic_load_int(&provider->shutting_down) != 0;

    if (credentials != NULL || wrapped_user_data->current_provider_index + 1 >= provider_count || is_shutting_down) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Credentials provider chain ending query on chain member %zu with %s credentials",
            (void *)provider,
            wrapped_user_data->current_provider_index + 1,
            (credentials != NULL) ? "valid" : "invalid");

        goto on_terminate_chain;
    }

    wrapped_user_data->current_provider_index++;

    /*
     * TODO: Immutable data, shouldn't need a lock, but we might need a fence and we don't have one atm
     */
    struct aws_credentials_provider *next_provider = NULL;
    if (aws_array_list_get_at(&impl->providers, &next_provider, wrapped_user_data->current_provider_index)) {
        goto on_terminate_chain;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Credentials provider chain invoking chain member #%zu",
        (void *)provider,
        wrapped_user_data->current_provider_index);

    aws_credentials_provider_get_credentials(next_provider, aws_provider_chain_member_callback, wrapped_user_data);

    return;

on_terminate_chain:

    wrapped_user_data->original_callback(credentials, wrapped_user_data->original_user_data);
    aws_credentials_provider_release(provider);
    aws_mem_release(wrapped_user_data->allocator, wrapped_user_data);
}

static int s_credentials_provider_chain_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_chain_impl *impl = provider->impl;

    struct aws_credentials_provider *first_provider = NULL;
    if (aws_array_list_get_at(&impl->providers, &first_provider, 0)) {
        return AWS_OP_ERR;
    }

    struct aws_credentials_provider_chain_user_data *wrapped_user_data =
        aws_mem_acquire(provider->allocator, sizeof(struct aws_credentials_provider_chain_user_data));
    if (wrapped_user_data == NULL) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*wrapped_user_data);

    wrapped_user_data->allocator = provider->allocator;
    wrapped_user_data->provider_chain = provider;
    wrapped_user_data->current_provider_index = 0;
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    aws_credentials_provider_acquire(provider);

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Credentials provider chain get credentials dispatch",
        (void *)provider);

    aws_credentials_provider_get_credentials(first_provider, aws_provider_chain_member_callback, wrapped_user_data);

    return AWS_OP_SUCCESS;
}

static void s_credentials_provider_chain_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_chain_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    size_t provider_count = aws_array_list_length(&impl->providers);
    for (size_t i = 0; i < provider_count; ++i) {
        struct aws_credentials_provider *chain_member = NULL;
        if (aws_array_list_get_at(&impl->providers, &chain_member, i)) {
            continue;
        }

        aws_credentials_provider_release(chain_member);
    }

    aws_array_list_clean_up(&impl->providers);
}

static void s_credentials_provider_chain_shutdown(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_chain_impl *impl = provider->impl;
    size_t provider_count = aws_array_list_length(&impl->providers);
    for (size_t i = 0; i < provider_count; ++i) {
        struct aws_credentials_provider *chain_member = NULL;
        if (aws_array_list_get_at(&impl->providers, &chain_member, i)) {
            continue;
        }

        aws_credentials_provider_shutdown(chain_member);
    }
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_chain_vtable = {
    .get_credentials = s_credentials_provider_chain_get_credentials_async,
    .clean_up = s_credentials_provider_chain_clean_up,
    .shutdown = s_credentials_provider_chain_shutdown};

struct aws_credentials_provider *aws_credentials_provider_new_chain(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_chain_options *options) {

    if (options->provider_count == 0) {
        return NULL;
    }

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_chain_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_chain_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    s_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_chain_vtable, impl);

    if (aws_array_list_init_dynamic(
            &impl->providers, allocator, options->provider_count, sizeof(struct aws_credentials_provider *))) {
        goto on_error;
    }

    for (size_t i = 0; i < options->provider_count; ++i) {
        struct aws_credentials_provider *sub_provider = options->providers[i];
        if (aws_array_list_push_back(&impl->providers, &sub_provider)) {
            goto on_error;
        }

        aws_credentials_provider_acquire(sub_provider);
    }

    return provider;

on_error:
    s_aws_credentials_provider_destroy(provider);

    return NULL;
}

/*
 * Default provider chain implementation
 */
struct aws_credentials_provider *aws_credentials_provider_new_chain_default(struct aws_allocator *allocator) {
    struct aws_credentials_provider *environment_provider = NULL;
    struct aws_credentials_provider *profile_provider = NULL;
    struct aws_credentials_provider *chain_provider = NULL;
    struct aws_credentials_provider *cached_provider = NULL;

    environment_provider = aws_credentials_provider_new_environment(allocator);
    if (environment_provider == NULL) {
        goto on_error;
    }

    struct aws_credentials_provider_profile_options profile_options;
    AWS_ZERO_STRUCT(profile_options);
    profile_provider = aws_credentials_provider_new_profile(allocator, &profile_options);
    if (profile_provider == NULL) {
        goto on_error;
    }

    struct aws_credentials_provider *providers[] = {environment_provider, profile_provider};
    struct aws_credentials_provider_chain_options chain_options;
    AWS_ZERO_STRUCT(chain_options);
    chain_options.provider_count = 2;
    chain_options.providers = providers;

    chain_provider = aws_credentials_provider_new_chain(allocator, &chain_options);
    if (chain_provider == NULL) {
        goto on_error;
    }

    /*
     * Transfer ownership
     */
    aws_credentials_provider_release(environment_provider);
    aws_credentials_provider_release(profile_provider);

    struct aws_credentials_provider_cached_options cached_options;
    AWS_ZERO_STRUCT(cached_options);

    cached_options.source = chain_provider;
    cached_options.refresh_time_in_milliseconds = DEFAULT_CREDENTIAL_PROVIDER_REFRESH_MS;

    cached_provider = aws_credentials_provider_new_cached(allocator, &cached_options);
    if (cached_provider == NULL) {
        goto on_error;
    }

    /*
     * Transfer ownership
     */
    aws_credentials_provider_release(chain_provider);

    return cached_provider;

on_error:

    /*
     * Have to be a bit more careful than normal with this clean up pattern since the chain/cache will
     * recursively destroy the other providers via ref release.
     *
     * Technically, the cached_provider can never be non-null here, but let's handle it anyways
     * in case someone does something weird in the future.
     */
    if (cached_provider) {
        aws_credentials_provider_release(cached_provider);
    } else if (chain_provider) {
        aws_credentials_provider_release(chain_provider);
    } else {
        aws_credentials_provider_release(profile_provider);
        aws_credentials_provider_release(environment_provider);
    }

    return NULL;
}
