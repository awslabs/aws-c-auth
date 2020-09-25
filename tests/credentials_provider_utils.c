/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "credentials_provider_utils.h"

#include <aws/auth/credentials.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>
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
        aws_credentials_release(result->credentials);
    }

    aws_condition_variable_clean_up(&result->signal);
    aws_mutex_clean_up(&result->sync);
}

void aws_test_get_credentials_async_callback(struct aws_credentials *credentials, int error_code, void *user_data) {
    struct aws_get_credentials_test_callback_result *result =
        (struct aws_get_credentials_test_callback_result *)user_data;

    aws_mutex_lock(&result->sync);

    result->count++;
    result->last_error = error_code;

    if (result->credentials != NULL) {
        aws_credentials_release(result->credentials);
    }

    result->credentials = credentials;
    if (credentials != NULL) {
        aws_credentials_acquire(credentials);
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
        if (aws_array_list_get_at(&impl->results, &result, impl->next_result)) {
            AWS_FATAL_ASSERT(false);
        } else {
            callback(result.credentials, result.error_code, user_data);
        }
        impl->next_result++;
    } else {
        AWS_FATAL_ASSERT(false);
    }

    return AWS_OP_SUCCESS;
}

static void s_mock_credentials_provider_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_mock_impl *impl = (struct aws_credentials_provider_mock_impl *)provider->impl;

    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_array_list_clean_up(&impl->results);

    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_mock_vtable = {
    .get_credentials = s_mock_credentials_provider_get_credentials_async,
    .destroy = s_mock_credentials_provider_destroy,
};

struct aws_credentials_provider *aws_credentials_provider_new_mock(
    struct aws_allocator *allocator,
    struct get_credentials_mock_result *results,
    size_t result_count,
    struct aws_credentials_provider_shutdown_options *shutdown_options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_mock_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_mock_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

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
    if (shutdown_options) {
        provider->shutdown_options = *shutdown_options;
    }
    aws_atomic_store_int(&provider->ref_count, 1);

    return provider;

on_init_result_list_failure:
    aws_mem_release(allocator, provider);

    return NULL;
}

/*
 * Mock async provider
 */

struct aws_credentials_provider_mock_async_impl {
    struct aws_event_loop_group *event_loop_group;
    struct aws_mutex sync;
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

    aws_mutex_lock(&impl->sync);

    struct aws_credentials_query query;
    AWS_ZERO_STRUCT(query);

    aws_credentials_query_init(&query, provider, callback, user_data);

    aws_array_list_push_back(&impl->queries, &query);

    aws_mutex_unlock(&impl->sync);

    return AWS_OP_SUCCESS;
}

static void s_async_mock_credentials_provider_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_mock_async_impl *impl =
        (struct aws_credentials_provider_mock_async_impl *)provider->impl;

    aws_array_list_clean_up(&impl->queries);
    aws_array_list_clean_up(&impl->mock_results);

    aws_event_loop_group_release(impl->event_loop_group);

    aws_mutex_clean_up(&impl->sync);

    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_mock_async_vtable = {
    .get_credentials = s_async_mock_credentials_provider_get_credentials_async,
    .destroy = s_async_mock_credentials_provider_destroy,
};

static void s_async_mock_credentials_provider_fire_callbacks_task(
    struct aws_task *task,
    void *arg,
    enum aws_task_status status) {

    (void)status;
    struct aws_credentials_provider *provider = arg;
    struct aws_credentials_provider_mock_async_impl *impl = provider->impl;

    aws_mem_release(provider->allocator, task);

    aws_mutex_lock(&impl->sync);

    /*
     * We need to make all of our callbacks outside the lock, in order to avoid deadlock
     * To make that easier, we keep this array list around and swap the callbacks we need to make into it
     */
    struct aws_array_list temp_queries;
    AWS_FATAL_ASSERT(
        aws_array_list_init_dynamic(&temp_queries, impl->queries.alloc, 10, sizeof(struct aws_credentials_query)) ==
        AWS_OP_SUCCESS);

    struct get_credentials_mock_result result;
    AWS_ZERO_STRUCT(result);

    size_t callback_count = aws_array_list_length(&impl->queries);
    if (callback_count != 0) {
        size_t result_count = aws_array_list_length(&impl->mock_results);
        if (impl->next_result >= result_count ||
            aws_array_list_get_at(&impl->mock_results, &result, impl->next_result)) {
            AWS_FATAL_ASSERT(false);
        }
        impl->next_result++;

        /*
         * move the callbacks we need to complete into the temporary list so that we can
         * safely use them outside the lock (we cannot safely use impl->queries outside the lock)
         */
        aws_array_list_swap_contents(&impl->queries, &temp_queries);
    }
    aws_mutex_unlock(&impl->sync);

    /* make the callbacks, not holding the lock */
    for (size_t i = 0; i < callback_count; ++i) {
        struct aws_credentials_query query;
        AWS_ZERO_STRUCT(query);
        if (aws_array_list_get_at(&temp_queries, &query, i)) {
            continue;
        }

        AWS_FATAL_ASSERT(query.callback != NULL);
        query.callback(result.credentials, result.error_code, query.user_data);

        aws_credentials_query_clean_up(&query);
    }

    aws_array_list_clean_up(&temp_queries);
    aws_credentials_provider_release(provider);
}

void aws_credentials_provider_mock_async_fire_callbacks(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_mock_async_impl *impl = provider->impl;

    struct aws_task *task = aws_mem_calloc(provider->allocator, 1, sizeof(struct aws_task));
    AWS_FATAL_ASSERT(task);
    aws_task_init(
        task,
        s_async_mock_credentials_provider_fire_callbacks_task,
        provider,
        "async_mock_credentials_provider_fire_callbacks_task");

    /* keep provider alive until task runs */
    aws_credentials_provider_acquire(provider);

    struct aws_event_loop *loop = aws_event_loop_group_get_next_loop(impl->event_loop_group);
    aws_event_loop_schedule_task_now(loop, task);
}

struct aws_credentials_provider *aws_credentials_provider_new_mock_async(
    struct aws_allocator *allocator,
    struct get_credentials_mock_result *results,
    size_t result_count,
    struct aws_event_loop_group *elg,
    struct aws_credentials_provider_shutdown_options *shutdown_options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_mock_async_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_mock_async_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    if (aws_mutex_init(&impl->sync)) {
        goto on_lock_init_failure;
    }

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

    impl->event_loop_group = aws_event_loop_group_acquire(elg);

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_mock_async_vtable;
    provider->impl = impl;
    if (shutdown_options) {
        provider->shutdown_options = *shutdown_options;
    }
    aws_atomic_store_int(&provider->ref_count, 1);

    return provider;

on_mock_result_list_init_failure:
    aws_array_list_clean_up(&impl->queries);

on_query_list_init_failure:
    aws_mutex_clean_up(&impl->sync);

on_lock_init_failure:
    aws_mem_release(allocator, provider);

    return NULL;
}

/*
 * mock system clock
 */

static struct aws_mutex system_clock_sync = AWS_MUTEX_INIT;
static uint64_t system_clock_time = 0;

int mock_aws_get_system_time(uint64_t *current_time) {
    aws_mutex_lock(&system_clock_sync);

    *current_time = system_clock_time;

    aws_mutex_unlock(&system_clock_sync);

    return AWS_OP_SUCCESS;
}

void mock_aws_set_system_time(uint64_t current_time) {
    aws_mutex_lock(&system_clock_sync);

    system_clock_time = current_time;

    aws_mutex_unlock(&system_clock_sync);
}

/*
 * mock high res clock
 */

static struct aws_mutex high_res_clock_sync = AWS_MUTEX_INIT;
static uint64_t high_res_clock_time = 0;

int mock_aws_get_high_res_time(uint64_t *current_time) {
    aws_mutex_lock(&high_res_clock_sync);

    *current_time = high_res_clock_time;

    aws_mutex_unlock(&high_res_clock_sync);

    return AWS_OP_SUCCESS;
}

void mock_aws_set_high_res_time(uint64_t current_time) {
    aws_mutex_lock(&high_res_clock_sync);

    high_res_clock_time = current_time;

    aws_mutex_unlock(&high_res_clock_sync);
}

/*
 * Null provider impl
 */

static int s_credentials_provider_null_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    (void)provider;
    callback(NULL, AWS_ERROR_UNKNOWN, user_data);

    return AWS_OP_SUCCESS;
}

static void s_credentials_provider_null_destroy(struct aws_credentials_provider *provider) {
    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_null_vtable = {
    .get_credentials = s_credentials_provider_null_get_credentials_async,
    .destroy = s_credentials_provider_null_destroy,
};

struct aws_credentials_provider *aws_credentials_provider_new_null(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_shutdown_options *shutdown_options) {
    struct aws_credentials_provider *provider =
        (struct aws_credentials_provider *)aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    provider->allocator = allocator;
    provider->vtable = &s_aws_credentials_provider_null_vtable;
    provider->impl = NULL;
    if (shutdown_options) {
        provider->shutdown_options = *shutdown_options;
    }
    aws_atomic_store_int(&provider->ref_count, 1);

    return provider;
}
