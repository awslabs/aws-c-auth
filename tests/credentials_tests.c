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
#include <aws/http/http.h>

#include <credentials_provider_utils.h>

#include "shared_credentials_test_definitions.h"

#ifdef _MSC_VER
#    pragma warning(disable : 4996)
#endif

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

struct aws_credentials_shutdown_checker {
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    bool is_shutdown_complete;
};

static struct aws_credentials_shutdown_checker s_shutdown_checker;

static void s_aws_credentials_shutdown_checker_init(void) {
    aws_mutex_init(&s_shutdown_checker.lock);
    aws_condition_variable_init(&s_shutdown_checker.signal);
    s_shutdown_checker.is_shutdown_complete = false;
}

static void s_aws_credentials_shutdown_checker_clean_up(void) {
    aws_mutex_clean_up(&s_shutdown_checker.lock);
    aws_condition_variable_clean_up(&s_shutdown_checker.signal);
}

static void s_on_shutdown_complete(void *user_data) {
    (void)user_data;

    aws_mutex_lock(&s_shutdown_checker.lock);
    s_shutdown_checker.is_shutdown_complete = true;
    aws_mutex_unlock(&s_shutdown_checker.lock);

    aws_condition_variable_notify_one(&s_shutdown_checker.signal);
}

static bool s_has_tester_received_shutdown_callback(void *user_data) {
    (void)user_data;

    return s_shutdown_checker.is_shutdown_complete;
}

static void s_aws_wait_for_provider_shutdown_callback(void) {
    aws_mutex_lock(&s_shutdown_checker.lock);
    aws_condition_variable_wait_pred(
        &s_shutdown_checker.signal, &s_shutdown_checker.lock, s_has_tester_received_shutdown_callback, NULL);
    aws_mutex_unlock(&s_shutdown_checker.lock);
}

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

    struct aws_credentials_provider_static_options options = {
        .access_key_id = aws_byte_cursor_from_string(s_access_key_id_test_value),
        .secret_access_key = aws_byte_cursor_from_string(s_secret_access_key_test_value),
        .session_token = aws_byte_cursor_from_string(s_session_token_test_value),
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    s_aws_credentials_shutdown_checker_init();

    struct aws_credentials_provider *provider = aws_credentials_provider_new_static(allocator, &options);

    ASSERT_TRUE(
        s_do_basic_provider_test(
            provider, 1, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value) ==
        AWS_OP_SUCCESS);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_credentials_shutdown_checker_clean_up();

    return 0;
}

AWS_TEST_CASE(static_credentials_provider_basic_test, s_static_credentials_provider_basic_test);

static int s_environment_credentials_provider_basic_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_credentials_shutdown_checker_init();

    aws_set_environment_value(s_access_key_id_env_var, s_access_key_id_test_value);
    aws_set_environment_value(s_secret_access_key_env_var, s_secret_access_key_test_value);
    aws_set_environment_value(s_session_token_env_var, s_session_token_test_value);

    struct aws_credentials_provider_environment_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_environment(allocator, &options);

    ASSERT_TRUE(
        s_do_basic_provider_test(
            provider, 1, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value) ==
        AWS_OP_SUCCESS);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_credentials_shutdown_checker_clean_up();

    return 0;
}

AWS_TEST_CASE(environment_credentials_provider_basic_test, s_environment_credentials_provider_basic_test);

static int s_do_environment_credentials_provider_failure(struct aws_allocator *allocator) {
    s_aws_credentials_shutdown_checker_init();

    struct aws_credentials_provider_environment_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_environment(allocator, &options);

    ASSERT_TRUE(s_do_basic_provider_test(provider, 1, NULL, NULL, NULL) == AWS_OP_SUCCESS);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_credentials_shutdown_checker_clean_up();

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

    if (results->credentials == NULL || results->credentials->access_key_id == NULL) {
        ASSERT_TRUE(expected_access_key_id == NULL);
    } else {
        ASSERT_TRUE(
            expected_access_key_id != NULL &&
            aws_string_compare(results->credentials->access_key_id, expected_access_key_id) == 0);
    }

    if (results->credentials == NULL || results->credentials->secret_access_key == NULL) {
        ASSERT_TRUE(expected_secret_access_key == NULL);
    } else {
        ASSERT_TRUE(
            expected_secret_access_key != NULL &&
            aws_string_compare(results->credentials->secret_access_key, expected_secret_access_key) == 0);
    }

    if (results->credentials == NULL || results->credentials->session_token == NULL) {
        ASSERT_TRUE(expected_session_token == NULL);
    } else {
        ASSERT_TRUE(
            expected_session_token != NULL &&
            aws_string_compare(results->credentials->session_token, expected_session_token) == 0);
    }

    aws_mutex_unlock(&results->sync);

    return 0;
}

static int s_cached_credentials_provider_elapsed_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    mock_aws_set_system_time(0);
    mock_aws_set_high_res_time(1);

    s_aws_credentials_shutdown_checker_init();

    struct aws_credentials *first_creds =
        aws_credentials_new(allocator, s_access_key_id_1, s_secret_access_key_1, s_session_token_1);
    struct aws_credentials *second_creds =
        aws_credentials_new(allocator, s_access_key_id_2, s_secret_access_key_2, s_session_token_2);

    struct get_credentials_mock_result mock_results[] = {{.error_code = 0, .credentials = first_creds},
                                                         {.error_code = 0, .credentials = second_creds}};

    struct aws_credentials_provider_shutdown_options shutdown_options = {
        .shutdown_callback = NULL,
        .shutdown_user_data = NULL,
    };

    struct aws_credentials_provider *mock_provider =
        aws_credentials_provider_new_mock(allocator, mock_results, 2, &shutdown_options);

    struct aws_credentials_provider_cached_options options;
    AWS_ZERO_STRUCT(options);
    options.source = mock_provider;
    options.refresh_time_in_milliseconds = TEST_CACHE_REFRESH_TIME_MS;
    options.high_res_clock_fn = mock_aws_get_high_res_time;
    options.system_clock_fn = mock_aws_get_system_time;
    options.shutdown_options.shutdown_callback = s_on_shutdown_complete;
    options.shutdown_options.shutdown_user_data = NULL;

    struct aws_credentials_provider *cached_provider = aws_credentials_provider_new_cached(allocator, &options);
    aws_credentials_provider_release(mock_provider);

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
    mock_aws_get_high_res_time(&now);
    mock_aws_set_high_res_time(now + refresh_in_ns - 1);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 1) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials(&callback_results) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 1, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    /*
     * Advance time enough to cause cache expiration, verify we get the second set of mocked credentials
     */
    mock_aws_set_high_res_time(now + refresh_in_ns);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 1) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials(&callback_results) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 1, s_access_key_id_2, s_secret_access_key_2, s_session_token_2) ==
        0);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    aws_credentials_provider_release(cached_provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_credentials_shutdown_checker_clean_up();

    aws_credentials_destroy(second_creds);
    aws_credentials_destroy(first_creds);

    return 0;
}

AWS_TEST_CASE(cached_credentials_provider_elapsed_test, s_cached_credentials_provider_elapsed_test);

static int s_cached_credentials_provider_queued_async_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_credentials_shutdown_checker_init();

    mock_aws_set_system_time(0);
    mock_aws_set_high_res_time(1);

    struct aws_credentials *first_creds =
        aws_credentials_new(allocator, s_access_key_id_1, s_secret_access_key_1, s_session_token_1);
    struct aws_credentials *second_creds =
        aws_credentials_new(allocator, s_access_key_id_2, s_secret_access_key_2, s_session_token_2);

    struct get_credentials_mock_result mock_results[] = {{.error_code = 0, .credentials = first_creds},
                                                         {.error_code = 0, .credentials = second_creds}};

    struct aws_credentials_provider_mock_async_controller controller;
    aws_credentials_provider_mock_async_controller_init(&controller);

    struct aws_credentials_provider_shutdown_options shutdown_options;
    AWS_ZERO_STRUCT(shutdown_options);

    struct aws_credentials_provider *mock_provider =
        aws_credentials_provider_new_mock_async(allocator, mock_results, 2, &controller, &shutdown_options);

    struct aws_credentials_provider_cached_options options;
    AWS_ZERO_STRUCT(options);
    options.source = mock_provider;
    options.refresh_time_in_milliseconds = TEST_CACHE_REFRESH_TIME_MS;
    options.high_res_clock_fn = mock_aws_get_high_res_time;
    options.system_clock_fn = mock_aws_get_system_time;
    options.shutdown_options.shutdown_callback = s_on_shutdown_complete;
    options.shutdown_options.shutdown_user_data = NULL;

    struct aws_credentials_provider *cached_provider = aws_credentials_provider_new_cached(allocator, &options);
    aws_credentials_provider_release(mock_provider);

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
    mock_aws_get_high_res_time(&now);
    mock_aws_set_high_res_time(now + refresh_in_ns - 1);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 2) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials_with_async_controller(&callback_results, &controller) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 2, s_access_key_id_1, s_secret_access_key_1, s_session_token_1) ==
        0);

    /*
     * Advance time enough to cause cache expiration, verify we get the second set of mocked credentials
     */
    mock_aws_set_high_res_time(now + refresh_in_ns);

    aws_get_credentials_test_callback_result_clean_up(&callback_results);
    ASSERT_TRUE(s_invoke_get_credentials(cached_provider, &callback_results, 2) == 0);
    ASSERT_TRUE(s_wait_for_get_credentials_with_async_controller(&callback_results, &controller) == 0);
    ASSERT_TRUE(
        s_verify_callback_status(&callback_results, 2, s_access_key_id_2, s_secret_access_key_2, s_session_token_2) ==
        0);

    aws_credentials_provider_release(cached_provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_credentials_shutdown_checker_clean_up();

    aws_credentials_provider_mock_async_controller_clean_up(&controller);
    aws_get_credentials_test_callback_result_clean_up(&callback_results);

    aws_credentials_destroy(second_creds);
    aws_credentials_destroy(first_creds);

    return 0;
}

AWS_TEST_CASE(cached_credentials_provider_queued_async_test, s_cached_credentials_provider_queued_async_test);

static int s_profile_credentials_provider_new_destroy_defaults_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    s_aws_credentials_shutdown_checker_init();

    struct aws_credentials_provider_profile_options options;
    AWS_ZERO_STRUCT(options);
    options.shutdown_options.shutdown_callback = s_on_shutdown_complete;
    options.shutdown_options.shutdown_user_data = NULL;

    struct aws_credentials_provider *provider = aws_credentials_provider_new_profile(allocator, &options);

    aws_credentials_provider_release(provider);

    if (provider) {
        s_aws_wait_for_provider_shutdown_callback();
    }

    s_aws_credentials_shutdown_checker_clean_up();

    return 0;
}

AWS_TEST_CASE(
    profile_credentials_provider_new_destroy_defaults_test,
    s_profile_credentials_provider_new_destroy_defaults_test);

AWS_STATIC_STRING_FROM_LITERAL(s_config_file_path, "~derp/.aws/config");
AWS_STATIC_STRING_FROM_LITERAL(s_credentials_file_path, "/Ithink/globalpaths/arebroken/.aws/credentials");
AWS_STATIC_STRING_FROM_LITERAL(s_profile_name, "notdefault");

static int s_profile_credentials_provider_new_destroy_overrides_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    s_aws_credentials_shutdown_checker_init();

    struct aws_credentials_provider_profile_options options;
    AWS_ZERO_STRUCT(options);
    options.config_file_name_override = aws_byte_cursor_from_string(s_config_file_path);
    options.credentials_file_name_override = aws_byte_cursor_from_string(s_credentials_file_path);
    options.profile_name_override = aws_byte_cursor_from_string(s_profile_name);
    options.shutdown_options.shutdown_callback = s_on_shutdown_complete;
    options.shutdown_options.shutdown_user_data = NULL;

    struct aws_credentials_provider *provider = aws_credentials_provider_new_profile(allocator, &options);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_credentials_shutdown_checker_clean_up();

    return 0;
}

AWS_TEST_CASE(
    profile_credentials_provider_new_destroy_overrides_test,
    s_profile_credentials_provider_new_destroy_overrides_test);

typedef int(s_verify_credentials_callback_fn)(struct aws_get_credentials_test_callback_result *callback_results);

static int s_do_credentials_provider_profile_test(
    struct aws_allocator *allocator,
    const struct aws_string *config_file_path,
    const struct aws_string *config_contents,
    const struct aws_string *creds_file_path,
    const struct aws_string *credentials_contents,
    struct aws_credentials_provider_profile_options *options,
    s_verify_credentials_callback_fn verifier,
    bool reset_environment) {

    s_aws_credentials_shutdown_checker_init();

    int result = AWS_OP_ERR;

    if (reset_environment) {
        /* Zero out all of the environment variables, just in case the user has it set (other tests may re-set it) */
        aws_unset_environment_value(s_default_profile_env_variable_name);
        aws_unset_environment_value(s_default_config_path_env_variable_name);
        aws_unset_environment_value(s_default_credentials_path_env_variable_name);
    }

    if (aws_create_profile_file(config_file_path, config_contents) ||
        aws_create_profile_file(creds_file_path, credentials_contents)) {
        return AWS_OP_ERR;
    }

    struct aws_credentials_provider *provider = aws_credentials_provider_new_profile(allocator, options);
    if (provider == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_get_credentials_test_callback_result callback_results;
    aws_get_credentials_test_callback_result_init(&callback_results, 1);

    int get_async_result =
        aws_credentials_provider_get_credentials(provider, aws_test_get_credentials_async_callback, &callback_results);

    if (get_async_result == AWS_OP_SUCCESS) {
        aws_wait_on_credentials_callback(&callback_results);

        result = verifier(&callback_results);
    }

    aws_get_credentials_test_callback_result_clean_up(&callback_results);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_credentials_shutdown_checker_clean_up();

    return result;
}

AWS_STATIC_STRING_FROM_LITERAL(
    s_config_contents,
    "[profile default]\naws_access_key_id=fake_access_key\naws_secret_access_key=fake_secret_key\n");
AWS_STATIC_STRING_FROM_LITERAL(
    s_credentials_contents,
    "[foo]\naws_access_key_id=foo_access\naws_secret_access_key=foo_secret\naws_session_token=foo_session\n");

int s_verify_default_credentials_callback(struct aws_get_credentials_test_callback_result *callback_results) {
    ASSERT_TRUE(callback_results->count == 1);
    ASSERT_TRUE(callback_results->credentials != NULL);
    ASSERT_TRUE(strcmp(aws_string_c_str(callback_results->credentials->access_key_id), "fake_access_key") == 0);
    ASSERT_TRUE(strcmp(aws_string_c_str(callback_results->credentials->secret_access_key), "fake_secret_key") == 0);
    ASSERT_TRUE(callback_results->credentials->session_token == NULL);

    return AWS_OP_SUCCESS;
}

static int s_profile_credentials_provider_default_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_string *creds_file_str = aws_create_process_unique_file_name(allocator);

    struct aws_credentials_provider_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
        .credentials_file_name_override = aws_byte_cursor_from_string(creds_file_str),
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    ASSERT_SUCCESS(s_do_credentials_provider_profile_test(
        allocator,
        config_file_str,
        s_config_contents,
        creds_file_str,
        s_credentials_contents,
        &options,
        s_verify_default_credentials_callback,
        true));

    aws_string_destroy(config_file_str);
    aws_string_destroy(creds_file_str);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(profile_credentials_provider_default_test, s_profile_credentials_provider_default_test);

AWS_STATIC_STRING_FROM_LITERAL(s_foo_profile, "foo");

int s_verify_nondefault_credentials_callback(struct aws_get_credentials_test_callback_result *callback_results) {
    ASSERT_TRUE(callback_results->count == 1);
    ASSERT_TRUE(callback_results->credentials != NULL);
    ASSERT_TRUE(strcmp(aws_string_c_str(callback_results->credentials->access_key_id), "foo_access") == 0);
    ASSERT_TRUE(strcmp(aws_string_c_str(callback_results->credentials->secret_access_key), "foo_secret") == 0);
    ASSERT_TRUE(strcmp(aws_string_c_str(callback_results->credentials->session_token), "foo_session") == 0);

    return AWS_OP_SUCCESS;
}

static int s_profile_credentials_provider_nondefault_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_string *creds_file_str = aws_create_process_unique_file_name(allocator);

    struct aws_credentials_provider_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
        .credentials_file_name_override = aws_byte_cursor_from_string(creds_file_str),
        .profile_name_override = aws_byte_cursor_from_string(s_foo_profile),
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    ASSERT_SUCCESS(s_do_credentials_provider_profile_test(
        allocator,
        config_file_str,
        s_config_contents,
        creds_file_str,
        s_credentials_contents,
        &options,
        s_verify_nondefault_credentials_callback,
        true));

    aws_string_destroy(config_file_str);
    aws_string_destroy(creds_file_str);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(profile_credentials_provider_nondefault_test, s_profile_credentials_provider_nondefault_test);

static int s_profile_credentials_provider_environment_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /*
     * Force a profile switch via environment variable
     */
    aws_set_environment_value(s_default_profile_env_variable_name, s_foo_profile);

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_string *creds_file_str = aws_create_process_unique_file_name(allocator);

    /*
     * Redirect config and credentials files by environment
     */
    aws_set_environment_value(s_default_config_path_env_variable_name, config_file_str);
    aws_set_environment_value(s_default_credentials_path_env_variable_name, creds_file_str);

    struct aws_credentials_provider_profile_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    ASSERT_SUCCESS(s_do_credentials_provider_profile_test(
        allocator,
        config_file_str,
        s_config_contents,
        creds_file_str,
        s_credentials_contents,
        &options,
        s_verify_nondefault_credentials_callback,
        false));

    aws_string_destroy(config_file_str);
    aws_string_destroy(creds_file_str);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(profile_credentials_provider_environment_test, s_profile_credentials_provider_environment_test);

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_value1, "Access1");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_value1, "Secret1");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_value1, "Session1");

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_value2, "Access2");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_value2, "Secret2");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_value2, "Session2");

static int s_do_provider_chain_test(
    struct aws_allocator *allocator,
    struct aws_credentials_provider *provider1,
    struct aws_credentials_provider *provider2,
    s_verify_credentials_callback_fn verifier) {

    s_aws_credentials_shutdown_checker_init();

    struct aws_credentials_provider *providers[2] = {provider1, provider2};

    struct aws_credentials_provider_chain_options options;
    AWS_ZERO_STRUCT(options);
    options.providers = providers;
    options.provider_count = 2;
    options.shutdown_options.shutdown_callback = s_on_shutdown_complete;
    options.shutdown_options.shutdown_user_data = NULL;

    struct aws_credentials_provider *provider_chain = aws_credentials_provider_new_chain(allocator, &options);
    aws_credentials_provider_release(provider1);
    aws_credentials_provider_release(provider2);
    if (provider_chain == NULL) {
        return 0;
    }

    struct aws_get_credentials_test_callback_result callback_results;
    aws_get_credentials_test_callback_result_init(&callback_results, 1);

    int get_async_result = aws_credentials_provider_get_credentials(
        provider_chain, aws_test_get_credentials_async_callback, &callback_results);

    int verification_result = AWS_OP_ERR;
    if (get_async_result == AWS_OP_SUCCESS) {
        aws_wait_on_credentials_callback(&callback_results);

        verification_result = verifier(&callback_results);
    }

    aws_get_credentials_test_callback_result_clean_up(&callback_results);

    aws_credentials_provider_release(provider_chain);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_credentials_shutdown_checker_clean_up();

    return verification_result;
}

int s_verify_first_credentials_callback(struct aws_get_credentials_test_callback_result *callback_results) {
    ASSERT_TRUE(callback_results->count == 1);
    ASSERT_TRUE(callback_results->credentials != NULL);
    ASSERT_TRUE(aws_string_eq(callback_results->credentials->access_key_id, s_access_key_id_value1));
    ASSERT_TRUE(aws_string_eq(callback_results->credentials->secret_access_key, s_secret_access_key_value1));
    ASSERT_TRUE(aws_string_eq(callback_results->credentials->session_token, s_session_token_value1));

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_first_in_chain_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_credentials_provider_static_options options1 = {
        .access_key_id = aws_byte_cursor_from_string(s_access_key_id_value1),
        .secret_access_key = aws_byte_cursor_from_string(s_secret_access_key_value1),
        .session_token = aws_byte_cursor_from_string(s_session_token_value1),
    };

    struct aws_credentials_provider_static_options options2 = {
        .access_key_id = aws_byte_cursor_from_string(s_access_key_id_value2),
        .secret_access_key = aws_byte_cursor_from_string(s_secret_access_key_value2),
        .session_token = aws_byte_cursor_from_string(s_session_token_value2),
    };

    return s_do_provider_chain_test(
        allocator,
        aws_credentials_provider_new_static(allocator, &options1),
        aws_credentials_provider_new_static(allocator, &options2),
        s_verify_first_credentials_callback);
}

AWS_TEST_CASE(credentials_provider_first_in_chain_test, s_credentials_provider_first_in_chain_test);

int s_verify_second_credentials_callback(struct aws_get_credentials_test_callback_result *callback_results) {
    ASSERT_TRUE(callback_results->count == 1);
    ASSERT_TRUE(callback_results->credentials != NULL);
    ASSERT_TRUE(strcmp(aws_string_c_str(callback_results->credentials->access_key_id), "Access2") == 0);
    ASSERT_TRUE(strcmp(aws_string_c_str(callback_results->credentials->secret_access_key), "Secret2") == 0);
    ASSERT_TRUE(strcmp(aws_string_c_str(callback_results->credentials->session_token), "Session2") == 0);

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_second_in_chain_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_credentials_provider_shutdown_options null_options;
    AWS_ZERO_STRUCT(null_options);

    struct aws_credentials_provider_static_options options = {
        .access_key_id = aws_byte_cursor_from_string(s_access_key_id_value2),
        .secret_access_key = aws_byte_cursor_from_string(s_secret_access_key_value2),
        .session_token = aws_byte_cursor_from_string(s_session_token_value2),
    };

    return s_do_provider_chain_test(
        allocator,
        aws_credentials_provider_new_null(allocator, &null_options),
        aws_credentials_provider_new_static(allocator, &options),
        s_verify_second_credentials_callback);
}

AWS_TEST_CASE(credentials_provider_second_in_chain_test, s_credentials_provider_second_in_chain_test);

int s_verify_null_credentials_callback(struct aws_get_credentials_test_callback_result *callback_results) {
    ASSERT_TRUE(callback_results->count == 1);
    ASSERT_TRUE(callback_results->credentials == NULL);

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_null_chain_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_credentials_provider_shutdown_options null_options;
    AWS_ZERO_STRUCT(null_options);

    return s_do_provider_chain_test(
        allocator,
        aws_credentials_provider_new_null(allocator, &null_options),
        aws_credentials_provider_new_null(allocator, &null_options),
        s_verify_null_credentials_callback);
}

AWS_TEST_CASE(credentials_provider_null_chain_test, s_credentials_provider_null_chain_test);

static int s_credentials_provider_default_basic_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_http_library_init(allocator);

    s_aws_credentials_shutdown_checker_init();
    /*
     * Do a basic environment provider test, but use the default provider chain
     */

    aws_set_environment_value(s_access_key_id_env_var, s_access_key_id_test_value);
    aws_set_environment_value(s_secret_access_key_env_var, s_secret_access_key_test_value);
    aws_set_environment_value(s_session_token_env_var, s_session_token_test_value);

    struct aws_credentials_provider_chain_default_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_chain_default(allocator, &options);

    ASSERT_TRUE(
        s_do_basic_provider_test(
            provider, 1, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value) ==
        AWS_OP_SUCCESS);

    /*
     * Verify that there's some caching before the environment by modifying the environment and requerying
     */
    aws_set_environment_value(s_access_key_id_env_var, s_access_key_id_1);
    aws_set_environment_value(s_secret_access_key_env_var, s_secret_access_key_1);
    aws_set_environment_value(s_session_token_env_var, s_session_token_1);

    ASSERT_TRUE(
        s_do_basic_provider_test(
            provider, 1, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value) ==
        AWS_OP_SUCCESS);

    aws_credentials_provider_release(provider);

    s_aws_credentials_shutdown_checker_clean_up();
    aws_http_library_clean_up();

    return 0;
}

AWS_TEST_CASE(credentials_provider_default_basic_test, s_credentials_provider_default_basic_test);
