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

#include "credentials_provider_utils.h"

#include <aws/auth/credentials.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/io/file_utils.h>

#include <errno.h>

/*
 * Support for async get testing
 */
void aws_get_credentials_test_callback_result_init(
    struct aws_get_credentials_test_callback_result *result,
    int required_count) {
    AWS_ZERO_STRUCT(*result);
    aws_mutex_init(&result->sync);
    aws_condition_variable_init(&result->signal);
    result->required_count = required_count;
}

void aws_get_credentials_test_callback_result_clean_up(struct aws_get_credentials_test_callback_result *result) {

    if (result->credentials) {
        aws_credentials_destroy(result->credentials);
    }

    aws_condition_variable_clean_up(&result->signal);
    aws_mutex_clean_up(&result->sync);
}

void aws_test_get_credentials_async_callback(struct aws_credentials *credentials, void *user_data) {
    struct aws_get_credentials_test_callback_result *result =
        (struct aws_get_credentials_test_callback_result *)user_data;

    aws_mutex_lock(&result->sync);

    result->count++;

    if (result->credentials != NULL) {
        aws_credentials_destroy(result->credentials);
        result->credentials = NULL;
    }

    if (credentials != NULL) {
        result->credentials = aws_credentials_new_copy(credentials->allocator, credentials);
    }

    aws_condition_variable_notify_one(&result->signal);

    aws_mutex_unlock(&result->sync);
}

static bool s_sync_credentials_predicate(void *context) {
    struct aws_get_credentials_test_callback_result *result =
        (struct aws_get_credentials_test_callback_result *)context;

    return result->count == result->required_count;
}

void aws_wait_on_credentials_callback(struct aws_get_credentials_test_callback_result *result) {
    bool done = false;
    while (!done) {
        aws_mutex_lock(&result->sync);

        aws_condition_variable_wait_pred(&result->signal, &result->sync, s_sync_credentials_predicate, result);

        done = result->count == result->required_count;
        aws_mutex_unlock(&result->sync);
    }
}

/*
 * Mock provider
 */
struct aws_credentials_provider_mock_impl {
    struct aws_array_list results;
    size_t next_result;
};

static int s_mock_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_mock_impl *impl = (struct aws_credentials_provider_mock_impl *)provider->impl;

    if (impl->next_result < aws_array_list_length(&impl->results)) {
        struct get_credentials_mock_result result;
        aws_array_list_get_at(&impl->results, &result, impl->next_result);
        callback(result.credentials, user_data);
        impl->next_result++;
    } else {
        AWS_FATAL_ASSERT(false);
    }

    return AWS_OP_SUCCESS;
}

static void s_mock_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_mock_impl *impl = (struct aws_credentials_provider_mock_impl *)provider->impl;

    aws_array_list_clean_up(&impl->results);
    aws_mem_release(provider->allocator, impl);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_mock_vtable = {
    .get_credentials = s_mock_credentials_provider_get_credentials_async,
    .clean_up = s_mock_credentials_provider_clean_up};

struct aws_credentials_provider *aws_credentials_provider_new_mock(
    struct aws_allocator *allocator,
    struct get_credentials_mock_result *results,
    size_t result_count) {
    struct aws_credentials_provider_mock_impl *impl = (struct aws_credentials_provider_mock_impl *)aws_mem_acquire(
        allocator, sizeof(struct aws_credentials_provider_mock_impl));
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

    if (aws_array_list_init_dynamic(
            &impl->results, allocator, result_count, sizeof(struct get_credentials_mock_result))) {
        goto on_init_result_list_failure;
    }

    for (size_t i = 0; i < result_count; ++i) {
        aws_array_list_push_back(&impl->results, results + i);
    }

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_mock_vtable;
    provider->impl = impl;

    return provider;

on_init_result_list_failure:
    aws_mem_release(allocator, provider);

on_allocate_provider_failure:
    aws_mem_release(allocator, impl);

    return NULL;
}

/*
Mock async controller
*/

void aws_credentials_provider_mock_async_controller_init(
    struct aws_credentials_provider_mock_async_controller *controller) {
    AWS_ZERO_STRUCT(*controller);
    aws_mutex_init(&controller->sync);
    aws_condition_variable_init(&controller->signal);
}

void aws_credentials_provider_mock_async_controller_clean_up(
    struct aws_credentials_provider_mock_async_controller *controller) {
    aws_condition_variable_clean_up(&controller->signal);
    aws_mutex_clean_up(&controller->sync);
}

struct aws_credentials_provider_mock_async_impl {
    struct aws_credentials_provider_mock_async_controller *controller;
    struct aws_thread background_thread;
    struct aws_array_list queries;
    struct aws_array_list mock_results;
    size_t next_result;
};

static int s_async_mock_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_mock_async_impl *impl =
        (struct aws_credentials_provider_mock_async_impl *)provider->impl;

    aws_mutex_lock(&impl->controller->sync);

    struct aws_credentials_query query;
    AWS_ZERO_STRUCT(query);
    query.provider = provider;
    query.callback = callback;
    query.user_data = user_data;

    aws_array_list_push_back(&impl->queries, &query);

    aws_mutex_unlock(&impl->controller->sync);

    return AWS_OP_SUCCESS;
}

static void s_async_mock_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_mock_async_impl *impl =
        (struct aws_credentials_provider_mock_async_impl *)provider->impl;

    aws_mutex_lock(&impl->controller->sync);
    impl->controller->should_quit = true;
    aws_condition_variable_notify_one(&impl->controller->signal);
    aws_mutex_unlock(&impl->controller->sync);

    aws_thread_join(&impl->background_thread);
    aws_thread_clean_up(&impl->background_thread);

    aws_array_list_clean_up(&impl->queries);
    aws_array_list_clean_up(&impl->mock_results);

    aws_mem_release(provider->allocator, impl);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_mock_async_vtable = {
    .get_credentials = s_async_mock_credentials_provider_get_credentials_async,
    .clean_up = s_async_mock_credentials_provider_clean_up};

bool invoke_credential_callback_predicate(void *arg) {
    struct aws_credentials_provider_mock_async_controller *controller =
        (struct aws_credentials_provider_mock_async_controller *)arg;

    return controller->should_fire_callback || controller->should_quit;
}

static void mock_async_background_thread_function(void *arg) {
    struct aws_credentials_provider_mock_async_impl *impl = (struct aws_credentials_provider_mock_async_impl *)arg;

    bool done = false;
    aws_mutex_lock(&impl->controller->sync);
    while (!done) {

        aws_condition_variable_wait_pred(
            &impl->controller->signal, &impl->controller->sync, invoke_credential_callback_predicate, impl->controller);

        done = impl->controller->should_quit;
        bool do_callback = impl->controller->should_fire_callback;
        impl->controller->should_fire_callback = false;

        if (do_callback) {
            size_t callback_count = aws_array_list_length(&impl->queries);
            if (callback_count == 0) {
                continue;
            }

            size_t result_count = aws_array_list_length(&impl->mock_results);
            struct get_credentials_mock_result result;
            if (impl->next_result >= result_count ||
                aws_array_list_get_at(&impl->mock_results, &result, impl->next_result)) {
                AWS_FATAL_ASSERT(false);
            }

            for (size_t i = 0; i < callback_count; ++i) {
                struct aws_credentials_query query;
                if (aws_array_list_get_at(&impl->queries, &query, i)) {
                    continue;
                }

                query.callback(result.credentials, query.user_data);
            }

            impl->next_result++;

            aws_array_list_clear(&impl->queries);
        }
    }

    aws_array_list_clear(&impl->queries);

    aws_mutex_unlock(&impl->controller->sync);
}

struct aws_credentials_provider *aws_credentials_provider_new_mock_async(
    struct aws_allocator *allocator,
    struct get_credentials_mock_result *results,
    size_t result_count,
    struct aws_credentials_provider_mock_async_controller *controller) {

    struct aws_credentials_provider *provider =
        (struct aws_credentials_provider *)aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    struct aws_credentials_provider_mock_async_impl *impl =
        (struct aws_credentials_provider_mock_async_impl *)aws_mem_acquire(
            allocator, sizeof(struct aws_credentials_provider_mock_async_impl));
    if (impl == NULL) {
        goto on_mock_async_provider_impl_allocate_failure;
    }
    AWS_ZERO_STRUCT(*impl);

    if (aws_array_list_init_dynamic(&impl->queries, allocator, 10, sizeof(struct aws_credentials_query))) {
        goto on_query_list_init_failure;
    }

    if (aws_array_list_init_dynamic(
            &impl->mock_results, allocator, result_count, sizeof(struct get_credentials_mock_result))) {
        goto on_mock_result_list_init_failure;
    }

    for (size_t i = 0; i < result_count; ++i) {
        aws_array_list_push_back(&impl->mock_results, results + i);
    }

    if (aws_thread_init(&impl->background_thread, allocator)) {
        goto on_init_thread_failure;
    }

    impl->controller = controller;

    struct aws_thread_options thread_options;
    AWS_ZERO_STRUCT(thread_options);

    if (aws_thread_launch(&impl->background_thread, mock_async_background_thread_function, impl, &thread_options)) {
        goto on_thread_launch_failure;
    }

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_mock_async_vtable;
    provider->impl = impl;

    return provider;

on_thread_launch_failure:
    aws_thread_clean_up(&impl->background_thread);

on_init_thread_failure:
    aws_array_list_clean_up(&impl->mock_results);

on_mock_result_list_init_failure:
    aws_array_list_clean_up(&impl->queries);

on_query_list_init_failure:
    aws_mem_release(allocator, impl);

on_mock_async_provider_impl_allocate_failure:
    aws_mem_release(allocator, provider);

    return NULL;
}

/*
 * mock clock
 */

static struct aws_mutex clock_sync = AWS_MUTEX_INIT;
static uint64_t clock_time = 0;

int mock_aws_get_time(uint64_t *current_time) {
    aws_mutex_lock(&clock_sync);

    *current_time = clock_time;

    aws_mutex_unlock(&clock_sync);

    return AWS_OP_SUCCESS;
}

void mock_aws_set_time(uint64_t current_time) {
    aws_mutex_lock(&clock_sync);

    clock_time = current_time;

    aws_mutex_unlock(&clock_sync);
}

/*
 * Null provider impl
 */

static int s_credentials_provider_null_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    callback(NULL, user_data);

    return AWS_OP_SUCCESS;
}

static void s_credentials_provider_null_clean_up(struct aws_credentials_provider *provider) {
    (void)provider;
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_null_vtable = {
    .get_credentials = s_credentials_provider_null_get_credentials_async,
    .clean_up = s_credentials_provider_null_clean_up};

struct aws_credentials_provider *aws_credentials_provider_new_null(struct aws_allocator *allocator) {
    struct aws_credentials_provider *provider =
        (struct aws_credentials_provider *)aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_null_vtable;
    provider->impl = NULL;

    return provider;
}
