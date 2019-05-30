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

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_chain_vtable, impl);

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

    aws_credentials_provider_destroy(provider);

    return NULL;
}
