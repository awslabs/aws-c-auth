/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/testing/aws_test_harness.h>

#include <aws/auth/credentials.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/environment.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/io/file_utils.h>

#include <credentials_provider_utils.h>

#include <errno.h>

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_test_value, "My Access Key");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_test_value, "SekritKey");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_test_value, "Some Session Token");

static int s_credentials_create_destroy_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_credentials *credentials = aws_credentials_new(
        allocator, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value);

    ASSERT_TRUE(aws_string_compare(credentials->access_key_id, s_access_key_id_test_value) == 0);
    ASSERT_TRUE(aws_string_compare(credentials->secret_access_key, s_secret_access_key_test_value) == 0);
    ASSERT_TRUE(aws_string_compare(credentials->session_token, s_session_token_test_value) == 0);

    aws_credentials_destroy(credentials);

    return 0;
}

AWS_TEST_CASE(credentials_create_destroy_test, s_credentials_create_destroy_test);

static int s_credentials_copy_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_credentials *source = aws_credentials_new(
        allocator, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value);

    struct aws_credentials *credentials = aws_credentials_new_copy(allocator, source);

    // Verify string equality and pointer inequality
    ASSERT_TRUE(aws_string_compare(credentials->access_key_id, s_access_key_id_test_value) == 0);
    ASSERT_TRUE(credentials->access_key_id != source->access_key_id);

    ASSERT_TRUE(aws_string_compare(credentials->secret_access_key, s_secret_access_key_test_value) == 0);
    ASSERT_TRUE(credentials->secret_access_key != source->secret_access_key);

    ASSERT_TRUE(aws_string_compare(credentials->session_token, s_session_token_test_value) == 0);
    ASSERT_TRUE(credentials->session_token != source->session_token);

    aws_credentials_destroy(credentials);
    aws_credentials_destroy(source);

    return 0;
}

AWS_TEST_CASE(credentials_copy_test, s_credentials_copy_test);

/*
 * Helper function that takes a provider, expected results from a credentials query,
 * and uses the provider testing utils to query the results
 */
static int s_do_basic_provider_test(
    struct aws_credentials_provider *provider,
    int expected_calls,
    const struct aws_string *expected_access_key_id,
    const struct aws_string *expected_secret_access_key,
    const struct aws_string *expected_session_token) {

    struct aws_get_credentials_test_callback_result callback_results;
    aws_get_credentials_test_callback_result_init(&callback_results, expected_calls);

    int get_async_result =
        aws_credentials_provider_get_credentials(provider, aws_test_get_credentials_async_callback, &callback_results);
    ASSERT_TRUE(get_async_result == AWS_OP_SUCCESS);

    aws_wait_on_credentials_callback(&callback_results);

    ASSERT_TRUE(callback_results.count == expected_calls);

    if (callback_results.credentials != NULL) {
        if (expected_access_key_id != NULL) {
            ASSERT_TRUE(aws_string_compare(callback_results.credentials->access_key_id, expected_access_key_id) == 0);
        } else {
            ASSERT_TRUE(callback_results.credentials->access_key_id == NULL);
        }

        if (expected_secret_access_key != NULL) {
            ASSERT_TRUE(
                aws_string_compare(callback_results.credentials->secret_access_key, expected_secret_access_key) == 0);
        } else {
            ASSERT_TRUE(callback_results.credentials->secret_access_key == NULL);
        }

        if (expected_session_token != NULL) {
            ASSERT_TRUE(aws_string_compare(callback_results.credentials->session_token, expected_session_token) == 0);
        } else {
            ASSERT_TRUE(callback_results.credentials->session_token == NULL);
        }
    } else {
        ASSERT_TRUE(expected_access_key_id == NULL);
        ASSERT_TRUE(expected_secret_access_key == NULL);
        ASSERT_TRUE(expected_session_token == NULL);
    }

    aws_get_credentials_test_callback_result_clean_up(&callback_results);

    return AWS_OP_SUCCESS;
}

static int s_static_credentials_provider_basic_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_credentials_provider *provider = aws_credentials_provider_static_new(
        allocator, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value);

    ASSERT_TRUE(
        s_do_basic_provider_test(
            provider, 1, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value) ==
        AWS_OP_SUCCESS);

    aws_credentials_provider_destroy(provider);

    return 0;
}

AWS_TEST_CASE(static_credentials_provider_basic_test, s_static_credentials_provider_basic_test);

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_env_var, "AWS_ACCESS_KEY_ID");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_env_var, "AWS_SECRET_ACCESS_KEY");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_env_var, "AWS_SESSION_TOKEN");

static int s_environment_credentials_provider_basic_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_set_environment_value(s_access_key_id_env_var, s_access_key_id_test_value);
    aws_set_environment_value(s_secret_access_key_env_var, s_secret_access_key_test_value);
    aws_set_environment_value(s_session_token_env_var, s_session_token_test_value);

    struct aws_credentials_provider *provider = aws_credentials_provider_new_environment(allocator);

    ASSERT_TRUE(
        s_do_basic_provider_test(
            provider, 1, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value) ==
        AWS_OP_SUCCESS);

    aws_credentials_provider_destroy(provider);

    return 0;
}

AWS_TEST_CASE(environment_credentials_provider_basic_test, s_environment_credentials_provider_basic_test);

static int s_do_environment_credentials_provider_failure(struct aws_allocator *allocator) {
    struct aws_credentials_provider *provider = aws_credentials_provider_new_environment(allocator);

    ASSERT_TRUE(s_do_basic_provider_test(provider, 1, NULL, NULL, NULL) == AWS_OP_SUCCESS);

    aws_credentials_provider_destroy(provider);

    return 0;
}

/*
 * Set of related tests that all check and make sure that if you don't specify enough
 * of the credentials data in the environment, you get nothing when you query an
 * environment provider.
 */
static int s_environment_credentials_provider_negative_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* nothing in the environment */
    ASSERT_TRUE(s_do_environment_credentials_provider_failure(allocator) == 0);

    /* access key only shouldn't work */
    aws_set_environment_value(s_access_key_id_env_var, s_access_key_id_test_value);
    ASSERT_TRUE(s_do_environment_credentials_provider_failure(allocator) == 0);

    /* secret key only shouldn't work either */
    aws_unset_environment_value(s_access_key_id_env_var);
    aws_set_environment_value(s_secret_access_key_env_var, s_secret_access_key_test_value);
    ASSERT_TRUE(s_do_environment_credentials_provider_failure(allocator) == 0);

    return 0;
}

AWS_TEST_CASE(environment_credentials_provider_negative_test, s_environment_credentials_provider_negative_test);

#define TEST_CACHE_REFRESH_TIME_MS 10000

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_1, "AccessKey1");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_1, "SecretKey1");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_1, "SessionToken1");
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_2, "AccessKey2");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_2, "SecretKey2");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_2, "SessionToken2");

int s_wait_for_get_credentials(struct aws_get_credentials_test_callback_result *callback_results) {
    aws_wait_on_credentials_callback(callback_results);

    return 0;
}

int s_invoke_get_credentials(
    struct aws_credentials_provider *provider,
    struct aws_get_credentials_test_callback_result *callback_results,
    int call_count) {
    aws_get_credentials_test_callback_result_init(callback_results, call_count);

    for (int i = 0; i < call_count; ++i) {
        int get_async_result = aws_credentials_provider_get_credentials(
            provider, aws_test_get_credentials_async_callback, callback_results);
        ASSERT_TRUE(get_async_result == AWS_OP_SUCCESS);
    }

    return 0;
}

#define ASYNC_TEST_DELAY_NS 1000000

int s_wait_for_get_credentials_with_async_controller(
    struct aws_get_credentials_test_callback_result *callback_results,
    struct aws_credentials_provider_mock_async_controller *controller) {

    aws_thread_current_sleep(ASYNC_TEST_DELAY_NS);

    aws_mutex_lock(&controller->sync);
    controller->should_fire_callback = true;
    aws_condition_variable_notify_one(&controller->signal);
    aws_mutex_unlock(&controller->sync);

    aws_wait_on_credentials_callback(callback_results);

    return 0;
}

static int s_verify_callback_status(
    struct aws_get_credentials_test_callback_result *results,
    int expected_call_count,
    const struct aws_string *expected_access_key_id,
    const struct aws_string *expected_secret_access_key,
    const struct aws_string *expected_session_token) {

    aws_mutex_lock(&results->sync);
    ASSERT_TRUE(results->count == expected_call_count);

    if (expected_access_key_id != NULL) {
        ASSERT_TRUE(aws_string_compare(results->credentials->access_key_id, expected_access_key_id) == 0);
    } else {
        ASSERT_TRUE(results->credentials == NULL || results->credentials->access_key_id == NULL);
    }

    if (expected_secret_access_key != NULL) {
        ASSERT_TRUE(aws_string_compare(results->credentials->secret_access_key, expected_secret_access_key) == 0);
    } else {
        ASSERT_TRUE(results->credentials == NULL || results->credentials->secret_access_key == NULL);
    }

    if (expected_session_token != NULL) {
        ASSERT_TRUE(aws_string_compare(results->credentials->session_token, expected_session_token) == 0);
    } else {
        ASSERT_TRUE(results->credentials == NULL || results->credentials->session_token == NULL);
    }

    aws_mutex_unlock(&results->sync);

    return 0;
}

static int s_cached_credentials_provider_elapsed_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    mock_aws_set_time(0);

    struct aws_credentials *first_creds =
        aws_credentials_new(allocator, s_access_key_id_1, s_secret_access_key_1, s_session_token_1);
    struct aws_credentials *second_creds =
        aws_credentials_new(allocator, s_access_key_id_2, s_secret_access_key_2, s_session_token_2);

    struct get_credentials_mock_result mock_results[] = {{.error_code = 0, .credentials = first_creds},
                                                         {.error_code = 0, .credentials = second_creds}};

    struct aws_credentials_provider *mock_provider = aws_credentials_provider_new_mock(allocator, mock_results, 2);

    struct aws_credentials_provider_cached_options options;
    AWS_ZERO_STRUCT(options);
    options.source = mock_provider;
    options.refresh_time_in_milliseconds = TEST_CACHE_REFRESH_TIME_MS;
    options.clock_fn = mock_aws_get_time;

    struct aws_credentials_provider *cached_provider = aws_credentials_provider_new_cached(allocator, &options);

    struct aws_get_credentials_test_callback_result callback_results;
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 1) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials(&callback_results) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 1, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    /*
     * Invoke a couple more times to verify the mock isn't getting called
     */
    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 1) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials(&callback_results) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 1, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 1) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials(&callback_results) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 1, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    /*
     * Advance time, but not enough to cause a cache expiration, verify everything's the same
     */
    uint64_t refresh_in_ns =
        aws_timestamp_convert(TEST_CACHE_REFRESH_TIME_MS, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    uint64_t now = 0;
    mock_aws_get_time(&now);
    mock_aws_set_time(now + refresh_in_ns - 1);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 1) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials(&callback_results) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 1, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    /*
     * Advance time enough to cause cache expiration, verify we get the second set of mocked credentials
     */
    mock_aws_set_time(now + refresh_in_ns);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 1) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials(&callback_results) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 1, s_access_key_id_2, s_secret_access_key_2, s_session_token_2) ==
        0);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    aws_credentials_provider_destroy(cached_provider);
    aws_credentials_destroy(second_creds);
    aws_credentials_destroy(first_creds);

    return 0;
}

AWS_TEST_CASE(cached_credentials_provider_elapsed_test, s_cached_credentials_provider_elapsed_test);

static int s_cached_credentials_provider_queued_async_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    mock_aws_set_time(0);

    struct aws_credentials *first_creds =
        aws_credentials_new(allocator, s_access_key_id_1, s_secret_access_key_1, s_session_token_1);
    struct aws_credentials *second_creds =
        aws_credentials_new(allocator, s_access_key_id_2, s_secret_access_key_2, s_session_token_2);

    struct get_credentials_mock_result mock_results[] = {{.error_code = 0, .credentials = first_creds},
                                                         {.error_code = 0, .credentials = second_creds}};

    struct aws_credentials_provider_mock_async_controller controller;
    aws_credentials_provider_mock_async_controller_init(&controller);
    struct aws_credentials_provider *mock_provider =
        aws_credentials_provider_new_mock_async(allocator, mock_results, 2, &controller);

    struct aws_credentials_provider_cached_options options;
    AWS_ZERO_STRUCT(options);
    options.source = mock_provider;
    options.refresh_time_in_milliseconds = TEST_CACHE_REFRESH_TIME_MS;
    options.clock_fn = mock_aws_get_time;

    struct aws_credentials_provider *cached_provider = aws_credentials_provider_new_cached(allocator, &options);

    struct aws_get_credentials_test_callback_result callback_results;

    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 2) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials_with_async_controller(&callback_results, &controller) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 2, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    /*
     * Invoke a couple more times to verify the mock isn't getting called
     */
    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 2) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials_with_async_controller(&callback_results, &controller) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 2, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 2) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials_with_async_controller(&callback_results, &controller) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 2, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    /*
     * Advance time, but not enough to cause a cache expiration, verify everything's the same
     */
    uint64_t refresh_in_ns =
        aws_timestamp_convert(TEST_CACHE_REFRESH_TIME_MS, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    uint64_t now = 0;
    mock_aws_get_time(&now);
    mock_aws_set_time(now + refresh_in_ns - 1);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 2) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials_with_async_controller(&callback_results, &controller) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 2, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    /*
     * Advance time enough to cause cache expiration, verify we get the second set of mocked credentials
     */
    mock_aws_set_time(now + refresh_in_ns);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 2) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials_with_async_controller(&callback_results, &controller) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 2, s_access_key_id_2, s_secret_access_key_2, s_session_token_2) ==
        0);

    aws_credentials_provider_destroy(cached_provider);
    aws_credentials_provider_mock_async_controller_clean_up(&controller);
    aws_get_credentials_test_callback_result_clean_up(&callback_results);

    aws_credentials_destroy(second_creds);
    aws_credentials_destroy(first_creds);

    return 0;
}

AWS_TEST_CASE(cached_credentials_provider_queued_async_test, s_cached_credentials_provider_queued_async_test);