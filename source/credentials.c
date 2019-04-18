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
#include <aws/common/clock.h>
#include <aws/common/environment.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/weak_ref.h>
#include <aws/io/logging.h>

#include <inttypes.h>

#define INITIAL_PENDING_QUERY_LIST_SIZE 10
#define DEFAULT_CREDENTIAL_PROVIDER_REFRESH_MS (15 * 60 * 1000)

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
    return aws_credentials_new(
        allocator, credentials->access_key_id, credentials->secret_access_key, credentials->session_token);
}

void aws_credentials_destroy(struct aws_credentials *credentials) {
    if (credentials == NULL) {
        return;
    }

    if (credentials->access_key_id != NULL) {
        aws_string_destroy(credentials->access_key_id);
    }

    if (credentials->secret_access_key != NULL) {
        aws_string_destroy(credentials->secret_access_key);
    }

    if (credentials->session_token != NULL) {
        aws_string_destroy(credentials->session_token);
    }

    aws_mem_release(credentials->allocator, credentials);
}

/*
 * credentials query new/destroy
 */

struct aws_credentials_query *aws_credentials_query_new(struct aws_allocator *allocator, struct aws_credentials_provider *provider, aws_on_get_credentials_callback_fn *callback, void *user_data) {
    struct aws_credentials_query *query = aws_mem_acquire(allocator, sizeof(struct aws_credentials_query));
    if (query == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*query);

    query->allocator = allocator;
    query->provider = provider;
    query->user_data = user_data;
    query->callback = callback;

    return query;
}

void aws_credentials_query_destroy(struct aws_credentials_query *query) {
    if (query != NULL) {
        aws_mem_release(query->allocator, query);
    }
}

/*
 * provider API via vtable
 */
static void s_aws_credentials_provider_destroy(struct aws_credentials_provider *provider) {
    if (provider != NULL) {
        assert(provider->vtable->clean_up);

        provider->vtable->clean_up(provider);

        aws_mem_release(provider->allocator, provider);
    }
}

void aws_credentials_provider_shutdown(struct aws_credentials_provider *provider) {
    aws_atomic_store_int(&provider->shutting_down, 1);

    assert(provider->vtable->shutdown);
    provider->vtable->shutdown(provider);

    aws_credentials_provider_release(provider);
}

void aws_credentials_provider_release(struct aws_credentials_provider *provider) {
    size_t old_value = aws_atomic_fetch_sub(&provider->ref_count, 1);
    if (old_value == 1) {
        s_aws_credentials_provider_destroy(provider);
    }
}

int aws_credentials_provider_get_credentials(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    assert(provider->vtable->get_credentials);

    /*
     * Callback functions are contractually obligated to dec the ref count
     * on the provider they are returning an answer to
     */
    aws_atomic_fetch_sub(&provider->ref_count, 1);

    return provider->vtable->get_credentials(provider, callback, user_data);
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
        "Static credentials provider (id=%p) successfully sourced credentials",
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

static struct aws_credentials_provider_vtable s_aws_credentials_provider_static_vtable = {
    .get_credentials = s_static_credentials_provider_get_credentials_async,
    .clean_up = s_static_credentials_provider_clean_up};

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

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_static_vtable;
    provider->impl = credentials;

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
            "Environment credentials provider (id=%p) was unable to source credentials",
            (void *)provider);
        callback(NULL, user_data);
    } else {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Environment credentials provider (id=%p) successfully sourced credentials",
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
    .clean_up = s_credentials_provider_environment_clean_up};

struct aws_credentials_provider *aws_credentials_provider_new_environment(struct aws_allocator *allocator) {
    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_environment_vtable;
    provider->impl = NULL;

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

static void s_aws_credentials_query_list_notify_and_clean_up(struct aws_linked_list *query_list, struct aws_credentials *credentials) {
    while (!aws_linked_list_empty(query_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(query_list);
        struct aws_credentials_query *query = AWS_CONTAINER_OF(node, struct aws_credentials_query, node);
        query->callback(credentials, query->user_data);
        aws_credentials_query_destroy(query);
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
        "Cached credentials provider (id=%p) next refresh time set to %" PRIu64,
        (void *)provider,
        impl->next_refresh_time);

    if (impl->cached_credentials != NULL) {
        aws_credentials_destroy(impl->cached_credentials);
    }

    if (credentials != NULL) {
        impl->cached_credentials = aws_credentials_new_copy(provider->allocator, credentials);
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (id=%p) succesfully sourced credentials on refresh",
            (void *)provider);
    } else {
        impl->cached_credentials = NULL;
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (id=%p) was unable to source credentials on refresh",
            (void *)provider);
    }

    aws_mutex_unlock(&impl->lock);

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Cached credentials provider (id=%p) notifying pending queries of new credentials",
        (void *)provider);

    s_aws_credentials_query_list_notify_and_clean_up(&pending_queries, credentials);
}

static int s_cached_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_cached *impl = provider->impl;

    uint64_t current_time = 0;
    if (impl->clock_fn(&current_time)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (id=%p) failed to get current time",
            (void *)provider);
        return AWS_OP_ERR;
    }

    bool should_submit_query = false;
    bool perform_callback = false;
    struct aws_credentials *credentials = NULL;

    aws_mutex_lock(&impl->lock);

    if (current_time < impl->next_refresh_time) {
        perform_callback = true;
        credentials = aws_credentials_new_copy(provider->allocator, impl->cached_credentials);
    } else {
        struct aws_credentials_query *query = aws_credentials_query_new(provider->allocator, provider, callback, user_data);
        if (query != NULL) {
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
            "Cached credentials provider (id=%p) has expired credentials.  Requerying.",
            (void *)provider);

        aws_credentials_provider_get_credentials(
            impl->source, s_cached_credentials_provider_get_credentials_async_callback, provider);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (id=%p) has expired credentials.  Waiting on existing query.",
            (void *)provider);
    }

    if (perform_callback) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (id=%p) successfully sourced from cache",
            (void *)provider);
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

    aws_credentials_provider_destroy(impl->source);

    /*
     * The basic provider destruction contract is that destroying a provider should cause all
     * pending queries on it to receive their callbacks.  So we expect that after destroying
     * the linked provider, all of our pending queries should have been cleared by one or more
     * callback invocations.
     *
     * Applying this contract transitively, it should be 100% safe to access internals without the lock
     * because everything that might want access has been torn down.
     */
    assert(aws_linked_list_empty(&impl->pending_queries));

    /*
     * Unnecessary but paranoid
     */
    s_aws_credentials_query_list_notify_and_clean_up(&impl->pending_queries, impl->cached_credentials);

    if (impl->cached_credentials != NULL) {
        aws_credentials_destroy(impl->cached_credentials);
    }

    aws_mutex_clean_up(&impl->lock);

    aws_mem_release(provider->allocator, impl);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_cached_vtable = {
    .get_credentials = s_cached_credentials_provider_get_credentials_async,
    .clean_up = s_cached_credentials_provider_clean_up};

struct aws_credentials_provider *aws_credentials_provider_new_cached(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_cached_options *options) {
    assert(options->source != NULL);

    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_cached_vtable;
    struct aws_credentials_provider_cached *impl =
        aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider_cached));
    if (impl == NULL) {
        goto on_error;
    }

    AWS_ZERO_STRUCT(*impl);
    provider->impl = impl;

    if (aws_mutex_init(&impl->lock)) {
        goto on_error;
    }

    aws_linked_list_init(&impl->pending_queries);

    impl->source = options->source;

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
    aws_credentials_provider_destroy(provider);

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
            "Profile credentials provider (id=%p) successfully built config profile collection from file at (%s)",
            (void *)provider,
            (const char *)impl->config_file_path->bytes);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (id=%p) failed to build config profile collection from file at (%s)",
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
            "Profile credentials provider (id=%p) successfully built credentials profile collection from file at (%s)",
            (void *)provider,
            (const char *)impl->credentials_file_path->bytes);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (id=%p) failed to build credentials profile collection from file at (%s)",
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
                "Profile credentials provider (id=%p) attempting to pull credentials from profile \"%s\"",
                (void *)provider,
                (const char *)impl->profile_name->bytes);
            credentials = aws_credentials_new_from_profile(provider->allocator, profile);
        } else {
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Profile credentials provider (id=%p) could not find a profile named \"%s\"",
                (void *)provider,
                (const char *)impl->profile_name->bytes);
        }
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (id=%p) failed to merge config and credentials profile collections",
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

    aws_mem_release(provider->allocator, impl);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_profile_file_vtable = {
    .get_credentials = s_profile_file_credentials_provider_get_credentials_async,
    .clean_up = s_profile_file_credentials_provider_clean_up};

struct aws_credentials_provider *aws_credentials_provider_new_profile(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_profile_options *options) {

    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*provider);

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_profile_file_vtable;

    struct aws_credentials_provider_profile_file_impl *impl =
        aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider_profile_file_impl));
    if (impl == NULL) {
        goto on_error;
    }
    AWS_ZERO_STRUCT(*impl);

    provider->impl = impl;

    impl->credentials_file_path = aws_get_credentials_file_path(allocator, options->credentials_file_name_override);
    if (impl->credentials_file_path == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (id=%p) failed resolve credentials file path",
            (void *)provider);
        goto on_error;
    }

    impl->config_file_path = aws_get_config_file_path(allocator, options->config_file_name_override);
    if (impl->config_file_path == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (id=%p) failed resolve config file path",
            (void *)provider);
        goto on_error;
    }

    impl->profile_name = aws_get_profile_name(allocator, options->profile_name_override);
    if (impl->profile_name == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (id=%p) failed to resolve profile name",
            (void *)provider);
        goto on_error;
    }

    return provider;

on_error:
    aws_credentials_provider_destroy(provider);

    return NULL;
}

/*
 * Provider chain implementation
 */

struct aws_credentials_provider_chain_impl {
    struct aws_array_list providers;
    struct aws_weak_ref *weak_provider;
};

struct aws_credentials_provider_chain_user_data {
    struct aws_allocator *allocator;
    struct aws_weak_ref *weak_provider_chain;
    size_t current_provider_index;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;
};

void aws_provider_chain_member_callback(struct aws_credentials *credentials, void *user_data) {
    struct aws_credentials_provider_chain_user_data *wrapped_user_data = user_data;
    struct aws_credentials_provider *provider = aws_weak_ref_lock(wrapped_user_data->weak_provider_chain);
    struct aws_credentials_provider_chain_impl *impl = provider->impl;

    size_t provider_count = aws_array_list_length(&impl->providers);

    if (credentials != NULL || wrapped_user_data->current_provider_index + 1 >= provider_count) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Credentials provider chain (id=%p) ending query on chain member %zu with %s credentials",
            (void *)provider,
            wrapped_user_data->current_provider_index + 1,
            (credentials != NULL) ? "valid" : "invalid");

        goto on_terminate_chain;
    }

    wrapped_user_data->current_provider_index++;

    /*
     * TODO: Immutable data, shouldn't need a lock, but we probably need a fence and we don't have one atm
     */
    struct aws_credentials_provider *next_provider = NULL;
    if (aws_array_list_get_at(&impl->providers, &next_provider, wrapped_user_data->current_provider_index)) {
        goto on_terminate_chain;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Credentials provider chain (id=%p) invoking chain member #%zu",
        (void *)provider,
        wrapped_user_data->current_provider_index);

    aws_credentials_provider_get_credentials(next_provider, aws_provider_chain_member_callback, wrapped_user_data);

    return;

on_terminate_chain:

    wrapped_user_data->original_callback(credentials, wrapped_user_data->original_user_data);
    aws_mem_release(wrapped_user_data->allocator, wrapped_user_data);

    return;
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
    wrapped_user_data->weak_provider_chain = impl->weak_provider;
    wrapped_user_data->current_provider_index = 0;
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    aws_weak_ref_acquire(impl->weak_provider);

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Credentials provider chain (id=%p) get credentials dispatch",
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

        aws_credentials_provider_destroy(chain_member);
    }

    aws_array_list_clean_up(&impl->providers);

    if (impl->weak_provider) {
        aws_weak_ref_release(impl->weak_provider);
    }

    aws_mem_release(provider->allocator, impl);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_chain_vtable = {
    .get_credentials = s_credentials_provider_chain_get_credentials_async,
    .clean_up = s_credentials_provider_chain_clean_up};

struct aws_credentials_provider *aws_credentials_provider_new_chain(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_chain_options *options) {

    if (options->provider_count == 0) {
        return NULL;
    }

    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*provider);

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_chain_vtable;

    struct aws_credentials_provider_chain_impl *impl =
        aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider_chain_impl));
    if (impl == NULL) {
        goto on_error;
    }

    AWS_ZERO_STRUCT(*impl);
    provider->impl = impl;

    if (aws_array_list_init_dynamic(
            &impl->providers, allocator, options->provider_count, sizeof(struct aws_credentials_provider *))) {
        goto on_error;
    }

    for (size_t i = 0; i < options->provider_count; ++i) {
        if (aws_array_list_push_back(&impl->providers, &options->providers[i])) {
            goto on_error;
        }
    }

    impl->weak_provider = aws_weak_ref_new(allocator, provider);
    if (impl->weak_provider == NULL) {
        goto on_error;
    }

    return provider;

on_error:
    aws_credentials_provider_destroy(provider);

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

    struct aws_credentials_provider_cached_options cached_options;
    AWS_ZERO_STRUCT(cached_options);

    cached_options.source = chain_provider;
    cached_options.refresh_time_in_milliseconds = DEFAULT_CREDENTIAL_PROVIDER_REFRESH_MS;

    cached_provider = aws_credentials_provider_new_cached(allocator, &cached_options);
    if (cached_provider == NULL) {
        goto on_error;
    }

    return cached_provider;

on_error:

    /*
     * Have to be a bit more careful than normal with this clean up pattern since the chain/cache will
     * recursively destroy the other providers.
     *
     * Technically, the cached_provider can never be non-null here, but let's handle it anyways
     * in case someone does something weird in the future.
     */
    if (cached_provider) {
        aws_credentials_provider_destroy(cached_provider);
    } else if (chain_provider) {
        aws_credentials_provider_destroy(chain_provider);
    } else {
        aws_credentials_provider_destroy(profile_provider);
        aws_credentials_provider_destroy(environment_provider);
    }

    return NULL;
}
