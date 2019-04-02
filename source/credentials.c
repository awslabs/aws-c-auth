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
#define DEFAULT_CREDENTIALS_CACHE_REFRESH_TIME_MS (15 * 60 * 1000)

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
    assert(provider && provider->vtable->clean_up);

    provider->vtable->clean_up(provider);

    aws_mem_release(provider->allocator, provider);
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
 */

struct aws_credentials_provider_static_impl {
    struct aws_credentials *credentials;
};

static int s_static_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_static_impl *impl = (struct aws_credentials_provider_static_impl *)provider->impl;

    AWS_LOGF_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Static credentials provider (%p) successfully sourced credentials",
        (void *)provider);
    callback(impl->credentials, user_data);

    return AWS_OP_SUCCESS;
}

static void s_static_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_static_impl *impl = (struct aws_credentials_provider_static_impl *)provider->impl;

    if (impl->credentials != NULL) {
        aws_credentials_destroy(impl->credentials);
    }

    aws_mem_release(provider->allocator, impl);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_static_vtable = {
    .get_credentials = s_static_credentials_provider_get_credentials_async,
    .clean_up = s_static_credentials_provider_clean_up};

struct aws_credentials_provider *aws_credentials_provider_static_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token) {

    struct aws_credentials_provider_static_impl *impl = (struct aws_credentials_provider_static_impl *)aws_mem_acquire(
        allocator, sizeof(struct aws_credentials_provider_static_impl));
    if (impl == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*impl);

    struct aws_credentials_provider *provider =
        (struct aws_credentials_provider *)aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        goto on_allocate_provider_failure;
    }

    AWS_ZERO_STRUCT(*provider);

    impl->credentials = aws_credentials_new(allocator, access_key_id, secret_access_key, session_token);
    if (impl->credentials == NULL) {
        goto on_new_credentials_failure;
    }

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_static_vtable;
    provider->impl = impl;

    return provider;

on_new_credentials_failure:
    aws_mem_release(allocator, provider);

on_allocate_provider_failure:
    aws_mem_release(allocator, impl);

    return NULL;
}

/*
 *  Environment provider implementation.  Ends up a variant of the static implementation
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
    struct aws_credentials_provider *provider =
        (struct aws_credentials_provider *)aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_environment_vtable;
    provider->impl = NULL;

    return provider;
}
