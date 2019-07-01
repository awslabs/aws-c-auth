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

static struct aws_credentials_provider_vtable s_aws_credentials_provider_static_vtable = {
    .get_credentials = s_static_credentials_provider_get_credentials_async,
    .clean_up = s_static_credentials_provider_clean_up,
    .shutdown = aws_credentials_provider_shutdown_nil};

struct aws_credentials_provider *aws_credentials_provider_new_static(
    struct aws_allocator *allocator,
    struct aws_byte_cursor access_key_id,
    struct aws_byte_cursor secret_access_key,
    struct aws_byte_cursor session_token) {

    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    struct aws_credentials *credentials =
        aws_credentials_new_from_cursors(allocator, &access_key_id, &secret_access_key, &session_token);
    if (credentials == NULL) {
        goto on_new_credentials_failure;
    }

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_static_vtable, credentials);

    return provider;

on_new_credentials_failure:

    aws_mem_release(allocator, provider);

    return NULL;
}
