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
#include <aws/common/string.h>
#include <aws/io/logging.h>

#include <inttypes.h>

#define INITIAL_PENDING_QUERY_LIST_SIZE 10

struct aws_credentials *aws_credentials_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token) {

    struct aws_credentials *credentials =
        (struct aws_credentials *)(aws_mem_acquire(allocator, sizeof(struct aws_credentials)));
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
 * provider API via vtable
 */
void aws_credentials_provider_destroy(struct aws_credentials_provider *provider) {
    if (provider != NULL) {
        assert(provider->vtable->clean_up);

        provider->vtable->clean_up(provider);

        aws_mem_release(provider->allocator, provider);
    }
}

int aws_credentials_provider_get_credentials(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    assert(provider->vtable->get_credentials);

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

    struct aws_credentials *credentials = (struct aws_credentials *)provider->impl;

    AWS_LOGF_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Static credentials provider (%p) successfully sourced credentials",
        (void *)provider);
    callback(credentials, user_data);

    return AWS_OP_SUCCESS;
}

static void s_static_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials *credentials = (struct aws_credentials *)provider->impl;

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

    struct aws_credentials *credentials =
        (struct aws_credentials *)aws_mem_acquire(allocator, sizeof(struct aws_credentials));
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
            "Environment credentials provider (%p) was unable to source credentials",
            (void *)provider);
        callback(NULL, user_data);
    } else {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Environment credentials provider (%p) successfully sourced credentials",
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
    uint64_t refresh_interval_in_ns;
    uint64_t next_refresh_time;
    aws_io_clock_fn *clock_fn;
    struct aws_array_list pending_queries;
};

static void s_cached_credentials_provider_get_credentials_async_callback(
    struct aws_credentials *credentials,
    void *user_data) {

    struct aws_credentials_provider *provider = (struct aws_credentials_provider *)user_data;
    struct aws_credentials_provider_cached *impl = (struct aws_credentials_provider_cached *)provider->impl;

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
        "Cached credentials provider (%p) next refresh time set to %" PRIu64,
        (void *)provider,
        impl->next_refresh_time);

    if (impl->cached_credentials != NULL) {
        aws_credentials_destroy(impl->cached_credentials);
    }

    if (credentials != NULL) {
        impl->cached_credentials = aws_credentials_new_copy(provider->allocator, credentials);
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (%p) succesfully sourced credentials on refresh",
            (void *)provider);
    } else {
        impl->cached_credentials = NULL;
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (%p) was unable to source credentials on refresh",
            (void *)provider);
    }

    size_t pending_query_count = aws_array_list_length(&impl->pending_queries);
    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Cached credentials provider (%p) notifying %zu queries of new credentials",
        (void *)provider,
        pending_query_count);

    for (size_t i = 0; i < pending_query_count; ++i) {
        struct aws_credentials_query query;
        if (aws_array_list_get_at(&impl->pending_queries, &query, i)) {
            continue;
        }

        query.callback(credentials, query.user_data);
    }

    aws_array_list_clear(&impl->pending_queries);
}

static int s_cached_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_cached *impl = (struct aws_credentials_provider_cached *)provider->impl;

    uint64_t current_time = 0;
    if (impl->clock_fn(&current_time)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (%p) failed to get current time",
            (void *)provider);
        return AWS_OP_ERR;
    }

    if (current_time < impl->next_refresh_time) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Cached credentials provider (%p) successfully sourced from cache",
            (void *)provider);
        callback(impl->cached_credentials, user_data);
    } else {
        struct aws_credentials_query query;
        AWS_ZERO_STRUCT(query);
        query.callback = callback;
        query.provider = provider;
        query.user_data = user_data;

        aws_array_list_push_back(&impl->pending_queries, &query);

        if (aws_array_list_length(&impl->pending_queries) == 1) {
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Cached credentials provider (%p) has expired credentials.  Requerying.",
                (void *)provider);
            aws_credentials_provider_get_credentials(
                impl->source, s_cached_credentials_provider_get_credentials_async_callback, provider);
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Cached credentials provider (%p) has expired credentials.  Waiting on existing query.",
                (void *)provider);
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_cache_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_cached *impl = (struct aws_credentials_provider_cached *)provider->impl;

    size_t pending_query_count = aws_array_list_length(&impl->pending_queries);
    for (size_t i = 0; i < pending_query_count; ++i) {
        struct aws_credentials_query query;
        if (aws_array_list_get_at(&impl->pending_queries, &query, i)) {
            continue;
        }

        query.callback(impl->cached_credentials, query.user_data);
    }

    aws_array_list_clean_up(&impl->pending_queries);

    aws_credentials_provider_destroy(impl->source);

    if (impl->cached_credentials != NULL) {
        aws_credentials_destroy(impl->cached_credentials);
    }

    aws_mem_release(provider->allocator, impl);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_cached_vtable = {
    .get_credentials = s_cached_credentials_provider_get_credentials_async,
    .clean_up = s_cache_credentials_provider_clean_up};

struct aws_credentials_provider *aws_credentials_provider_new_cached(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_cached_options *options) {
    assert(options->source != NULL);

    struct aws_credentials_provider_cached *impl =
        aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider_cached));
    if (impl == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*impl);

    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        goto on_allocate_provider_failure;
    }

    AWS_ZERO_STRUCT(*provider);

    if (aws_array_list_init_dynamic(
            &impl->pending_queries, allocator, INITIAL_PENDING_QUERY_LIST_SIZE, sizeof(struct aws_credentials_query))) {
        goto on_array_list_init_failure;
    }

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

    provider->impl = impl;
    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_cached_vtable;

    return provider;

on_array_list_init_failure:
    aws_mem_release(allocator, provider);

on_allocate_provider_failure:
    aws_mem_release(allocator, impl);

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
            "Profile credentials provider (%p) successfully built config profile collection from file at (%s)",
            (void *)provider,
            (const char *)impl->config_file_path->bytes);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (%p) failed to build config profile collection from file at (%s)",
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
            "Profile credentials provider (%p) successfully built credentials profile collection from file at (%s)",
            (void *)provider,
            (const char *)impl->credentials_file_path->bytes);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (%p) failed to build credentials profile collection from file at (%s)",
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
                "Profile credentials provider (%p) attempting to pull credentials from profile \"%s\"",
                (void *)provider,
                (const char *)impl->profile_name->bytes);
            credentials = aws_credentials_new_from_profile(provider->allocator, profile);
        } else {
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Profile credentials provider (%p) could not find a profile named \"%s\"",
                (void *)provider,
                (const char *)impl->profile_name->bytes);
        }
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (%p) failed to merge config and credentials profile collections",
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
            "Profile credentials provider (%p) failed resolve credentials file path",
            (void *)provider);
        goto on_error;
    }

    impl->config_file_path = aws_get_config_file_path(allocator, options->config_file_name_override);
    if (impl->config_file_path == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (%p) failed resolve config file path",
            (void *)provider);
        goto on_error;
    }

    impl->profile_name = aws_get_profile_name(allocator, options->profile_name_override);
    if (impl->profile_name == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Profile credentials provider (%p) failed to resolve profile name",
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
};

struct aws_credentials_provider_chain_user_data {
    struct aws_credentials_provider *provider_chain;
    size_t current_provider_index;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;
};

void aws_provider_chain_member_callback(struct aws_credentials *credentials, void *user_data) {
    struct aws_credentials_provider_chain_user_data *wrapped_user_data =
        (struct aws_credentials_provider_chain_user_data *)user_data;
    struct aws_credentials_provider_chain_impl *impl =
        (struct aws_credentials_provider_chain_impl *)wrapped_user_data->provider_chain->impl;

    size_t provider_count = aws_array_list_length(&impl->providers);

    if (credentials != NULL || wrapped_user_data->current_provider_index + 1 >= provider_count) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Credentials provider chain (%p) ending query on chain member %zu with %s credentials",
            (void *)wrapped_user_data->provider_chain,
            wrapped_user_data->current_provider_index + 1,
            (credentials != NULL) ? "valid" : "invalid");

        wrapped_user_data->original_callback(credentials, wrapped_user_data->original_user_data);
        aws_mem_release(wrapped_user_data->provider_chain->allocator, wrapped_user_data);
        return;
    }

    wrapped_user_data->current_provider_index++;

    struct aws_credentials_provider *next_provider = NULL;
    if (aws_array_list_get_at(&impl->providers, &next_provider, wrapped_user_data->current_provider_index)) {
        wrapped_user_data->original_callback(NULL, wrapped_user_data->original_user_data);
        aws_mem_release(wrapped_user_data->provider_chain->allocator, wrapped_user_data);
        return;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Credentials provider chain (%p) invoking chain member #%zu",
        (void *)wrapped_user_data->provider_chain,
        wrapped_user_data->current_provider_index + 1);

    aws_credentials_provider_get_credentials(next_provider, aws_provider_chain_member_callback, wrapped_user_data);
}

static int s_credentials_provider_chain_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_chain_impl *impl = (struct aws_credentials_provider_chain_impl *)provider->impl;

    struct aws_credentials_provider *first_provider = NULL;
    if (aws_array_list_get_at(&impl->providers, &first_provider, 0)) {
        return AWS_OP_ERR;
    }

    struct aws_credentials_provider_chain_user_data *wrapped_user_data =
        (struct aws_credentials_provider_chain_user_data *)(aws_mem_acquire(
            provider->allocator, sizeof(struct aws_credentials_provider_chain_user_data)));
    if (wrapped_user_data == NULL) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*wrapped_user_data);

    wrapped_user_data->provider_chain = provider;
    wrapped_user_data->current_provider_index = 0;
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Credentials provider chain (%p) get credentials dispatch", (void *)provider);

    aws_credentials_provider_get_credentials(first_provider, aws_provider_chain_member_callback, wrapped_user_data);

    return AWS_OP_SUCCESS;
}

static void s_credentials_provider_chain_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_chain_impl *impl = (struct aws_credentials_provider_chain_impl *)provider->impl;
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

    struct aws_credentials_provider *provider =
        (struct aws_credentials_provider *)aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*provider);

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_chain_vtable;

    struct aws_credentials_provider_chain_impl *impl = (struct aws_credentials_provider_chain_impl *)aws_mem_acquire(
        allocator, sizeof(struct aws_credentials_provider_chain_impl));
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

    return provider;

on_error:
    aws_credentials_provider_destroy(provider);

    return NULL;
}

/*
 * Default provider chain implementation
 */
struct aws_credentials_provider *aws_credentials_provider_new_chain_default(struct aws_allocator *allocator) {
    (void)allocator;

    return NULL;
}
