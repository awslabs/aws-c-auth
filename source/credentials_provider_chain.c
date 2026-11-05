/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/credentials_utils.h>
#include <aws/common/atomics.h>

/* pinned_index value until a member returns credentials */
#define CHAIN_MEMBER_NOT_PINNED SIZE_MAX

struct aws_credentials_provider_chain_impl {
    struct aws_array_list providers;
    bool enable_new_cred_refresh_strategy;
    struct aws_atomic_var pinned_index;
};

struct aws_credentials_provider_chain_user_data {
    struct aws_allocator *allocator;
    struct aws_credentials_provider *provider_chain;
    size_t current_provider_index;
    bool pinned_query;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;
};

static void s_aws_provider_chain_member_callback(struct aws_credentials *credentials, int error_code, void *user_data) {
    struct aws_credentials_provider_chain_user_data *wrapped_user_data = user_data;
    struct aws_credentials_provider *provider = wrapped_user_data->provider_chain;
    struct aws_credentials_provider_chain_impl *impl = provider->impl;

    size_t provider_count = aws_array_list_length(&impl->providers);

    /* A pinned member's result is returned as is, never falling through to other members */
    if (wrapped_user_data->pinned_query) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Credentials provider chain pinned member #%zu returned %s credentials and error code %d",
            (void *)provider,
            wrapped_user_data->current_provider_index + 1,
            (credentials != NULL) ? "valid" : "invalid",
            error_code);

        goto on_terminate_chain;
    }

    /* Pin the first member that returns credentials */
    if (credentials != NULL && impl->enable_new_cred_refresh_strategy) {
        size_t expected = CHAIN_MEMBER_NOT_PINNED;
        if (aws_atomic_compare_exchange_int(
                &impl->pinned_index, &expected, wrapped_user_data->current_provider_index)) {
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Credentials provider chain pinned member #%zu",
                (void *)provider,
                wrapped_user_data->current_provider_index + 1);
        }
    }

    if (credentials != NULL || wrapped_user_data->current_provider_index + 1 >= provider_count) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Credentials provider chain callback terminating on index %zu, with %s credentials and error code "
            "%d",
            (void *)provider,
            wrapped_user_data->current_provider_index + 1,
            (credentials != NULL) ? "valid" : "invalid",
            error_code);

        goto on_terminate_chain;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Credentials provider chain callback %zu invoked with %s credentials and error code %d",
        (void *)provider,
        wrapped_user_data->current_provider_index + 1,
        (credentials != NULL) ? "valid" : "invalid",
        error_code);

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

    aws_credentials_provider_get_credentials(next_provider, s_aws_provider_chain_member_callback, wrapped_user_data);

    return;

on_terminate_chain:

    wrapped_user_data->original_callback(credentials, error_code, wrapped_user_data->original_user_data);
    aws_credentials_provider_release(provider);
    aws_mem_release(wrapped_user_data->allocator, wrapped_user_data);
}

static int s_credentials_provider_chain_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_chain_impl *impl = provider->impl;

    /* Once a member is pinned, query only that member */
    size_t start_index = 0;
    bool pinned_query = false;
    if (impl->enable_new_cred_refresh_strategy) {
        size_t pinned_index = aws_atomic_load_int(&impl->pinned_index);
        if (pinned_index != CHAIN_MEMBER_NOT_PINNED) {
            start_index = pinned_index;
            pinned_query = true;
        }
    }

    struct aws_credentials_provider *first_provider = NULL;
    if (aws_array_list_get_at(&impl->providers, &first_provider, start_index)) {
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
    wrapped_user_data->current_provider_index = start_index;
    wrapped_user_data->pinned_query = pinned_query;
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    aws_credentials_provider_acquire(provider);

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Credentials provider chain get credentials dispatch",
        (void *)provider);

    aws_credentials_provider_get_credentials(first_provider, s_aws_provider_chain_member_callback, wrapped_user_data);

    return AWS_OP_SUCCESS;
}

static void s_credentials_provider_chain_destroy(struct aws_credentials_provider *provider) {
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

    /* Invoke our own shutdown callback */
    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_array_list_clean_up(&impl->providers);

    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_chain_vtable = {
    .get_credentials = s_credentials_provider_chain_get_credentials_async,
    .destroy = s_credentials_provider_chain_destroy,
};

struct aws_credentials_provider *aws_credentials_provider_new_chain(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_chain_options *options) {

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

    impl->enable_new_cred_refresh_strategy = options->enable_new_cred_refresh_strategy;
    aws_atomic_init_int(&impl->pinned_index, CHAIN_MEMBER_NOT_PINNED);

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

    provider->shutdown_options = options->shutdown_options;

    return provider;

on_error:

    aws_credentials_provider_destroy(provider);

    return NULL;
}
