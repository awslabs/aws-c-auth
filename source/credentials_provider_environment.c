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

#include <aws/auth/private/credentials_utils.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_env_var, "AWS_ACCESS_KEY_ID");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_env_var, "AWS_SECRET_ACCESS_KEY");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_env_var, "AWS_SESSION_TOKEN");

static int s_credentials_provider_environment_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_allocator *allocator = provider->allocator;

    struct aws_string *access_key_id = NULL;
    struct aws_string *secret_access_key = NULL;
    struct aws_string *session_token = NULL;
    struct aws_credentials *credentials = NULL;
    int error_code = AWS_ERROR_SUCCESS;

    aws_get_environment_value(allocator, s_access_key_id_env_var, &access_key_id);
    aws_get_environment_value(allocator, s_secret_access_key_env_var, &secret_access_key);
    aws_get_environment_value(allocator, s_session_token_env_var, &session_token);

    if (access_key_id != NULL && secret_access_key != NULL) {
        struct aws_byte_cursor session_token_cursor;
        AWS_ZERO_STRUCT(session_token_cursor);

        if (session_token != NULL) {
            session_token_cursor = aws_byte_cursor_from_string(session_token);
        }

        credentials = aws_credentials_new(
            allocator,
            aws_byte_cursor_from_string(access_key_id),
            aws_byte_cursor_from_string(secret_access_key),
            session_token_cursor,
            UINT64_MAX);
        if (credentials == NULL) {
            error_code = aws_last_error();
        }
    } else {
        error_code = AWS_AUTH_CREDENTIALS_PROVIDER_INVALID_ENVIRONMENT;
    }

    callback(credentials, error_code, user_data);

    aws_credentials_release(credentials);
    aws_string_destroy(session_token);
    aws_string_destroy(secret_access_key);
    aws_string_destroy(access_key_id);

    return AWS_OP_SUCCESS;
}

static void s_credentials_provider_environment_destroy(struct aws_credentials_provider *provider) {
    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_environment_vtable = {
    .get_credentials = s_credentials_provider_environment_get_credentials_async,
    .destroy = s_credentials_provider_environment_destroy,
};

struct aws_credentials_provider *aws_credentials_provider_new_environment(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_environment_options *options) {
    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_environment_vtable, NULL);

    provider->shutdown_options = options->shutdown_options;

    return provider;
}
