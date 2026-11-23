/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/auth/credentials.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/event_loop.h>

#include "credentials_provider_utils.h"

/* High-res time starts far from system time so a mix-up between the two clocks fails the tests */
#define REFRESH_TEST_HIGH_RES_BASE_NS 1000000000000ULL

static struct aws_byte_cursor s_access_key_1 = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AccessKey1");
static struct aws_byte_cursor s_access_key_2 = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AccessKey2");
static struct aws_byte_cursor s_access_key_3 = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AccessKey3");
static struct aws_byte_cursor s_secret_key = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("SecretKey");
static struct aws_byte_cursor s_session_token = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("SessionToken");

static struct {
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    bool is_shutdown_complete;
} s_shutdown;

static void s_shutdown_init(void) {
    AWS_ZERO_STRUCT(s_shutdown);
    aws_mutex_init(&s_shutdown.lock);
    aws_condition_variable_init(&s_shutdown.signal);
}

static void s_on_shutdown_complete(void *user_data) {
    (void)user_data;
    aws_mutex_lock(&s_shutdown.lock);
    s_shutdown.is_shutdown_complete = true;
    aws_condition_variable_notify_one(&s_shutdown.signal);
    aws_mutex_unlock(&s_shutdown.lock);
}

static bool s_is_shutdown_complete(void *user_data) {
    (void)user_data;
    return s_shutdown.is_shutdown_complete;
}

static void s_wait_for_shutdown_and_clean_up(void) {
    aws_mutex_lock(&s_shutdown.lock);
    aws_condition_variable_wait_pred(&s_shutdown.signal, &s_shutdown.lock, s_is_shutdown_complete, NULL);
    aws_mutex_unlock(&s_shutdown.lock);
    aws_condition_variable_clean_up(&s_shutdown.signal);
    aws_mutex_clean_up(&s_shutdown.lock);
}

/* Sets both mock clocks to the same elapsed time */
static void s_set_time_ms(uint64_t elapsed_ms) {
    uint64_t elapsed_ns = aws_timestamp_convert(elapsed_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    mock_aws_set_system_time(elapsed_ns);
    mock_aws_set_high_res_time(REFRESH_TEST_HIGH_RES_BASE_NS + elapsed_ns);
}

static void s_set_time_secs(uint64_t elapsed_secs) {
    s_set_time_ms(elapsed_secs * 1000);
}

static struct aws_credentials *s_new_credentials(
    struct aws_allocator *allocator,
    struct aws_byte_cursor access_key_id,
    uint64_t expiration_secs) {
    return aws_credentials_new(allocator, access_key_id, s_secret_key, s_session_token, expiration_secs);
}

static struct aws_credentials_provider *s_new_refresh_cache(
    struct aws_allocator *allocator,
    struct aws_credentials_provider *source,
    bool with_shutdown_callback) {

    struct aws_credentials_provider_cached_options options = {
        .source = source,
        .high_res_clock_fn = mock_aws_get_high_res_time,
        .system_clock_fn = mock_aws_get_system_time,
    };
    if (with_shutdown_callback) {
        options.shutdown_options.shutdown_callback = s_on_shutdown_complete;
    }
    return aws_credentials_provider_new_refresh_cached(allocator, &options);
}

static int s_get_once(
    struct aws_credentials_provider *provider,
    struct aws_get_credentials_test_callback_result *result) {

    aws_get_credentials_test_callback_result_init(result, 1);
    ASSERT_SUCCESS(aws_credentials_provider_get_credentials(provider, aws_test_get_credentials_async_callback, result));
    aws_wait_on_credentials_callback(result);
    return AWS_OP_SUCCESS;
}

static int s_check_access_key(struct aws_credentials *credentials, struct aws_byte_cursor expected_access_key_id) {
    ASSERT_NOT_NULL(credentials);
    struct aws_byte_cursor access_key_id = aws_credentials_get_access_key_id(credentials);
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_access_key_id.ptr, expected_access_key_id.len, access_key_id.ptr, access_key_id.len);
    return AWS_OP_SUCCESS;
}

static int s_expect_credentials(
    struct aws_credentials_provider *provider,
    struct aws_byte_cursor expected_access_key_id) {
    struct aws_get_credentials_test_callback_result result;
    ASSERT_SUCCESS(s_get_once(provider, &result));
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, result.last_error);
    ASSERT_SUCCESS(s_check_access_key(result.credentials, expected_access_key_id));
    aws_get_credentials_test_callback_result_clean_up(&result);
    return AWS_OP_SUCCESS;
}

static int s_expect_error(struct aws_credentials_provider *provider, int expected_error_code) {
    struct aws_get_credentials_test_callback_result result;
    ASSERT_SUCCESS(s_get_once(provider, &result));
    ASSERT_NULL(result.credentials);
    ASSERT_INT_EQUALS(expected_error_code, result.last_error);
    aws_get_credentials_test_callback_result_clean_up(&result);
    return AWS_OP_SUCCESS;
}

/* Releases the cache, waits for its shutdown callback, then releases the mock */
static void s_release_cache_and_mock(struct aws_credentials_provider *cache, struct aws_credentials_provider *mock) {
    aws_credentials_provider_release(cache);
    s_wait_for_shutdown_and_clean_up();
    aws_credentials_provider_release(mock);
}

/* State 1 fetches once, then state 2 serves the cached credentials without calling the source */
static int s_refresh_cached_initial_fetch_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 1, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);
    ASSERT_NOT_NULL(cache);
    ASSERT_TRUE(aws_credentials_provider_is_refresh_cached(cache));

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    s_set_time_secs(60);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_initial_fetch_test, s_refresh_cached_initial_fetch_test);

/* A recoverable initial-fetch error returns the source error, and the next call fetches again with no backoff */
static int s_refresh_cached_initial_fetch_recoverable_error_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct get_credentials_mock_result results[] = {
        {.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE},
        {.credentials = creds1},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_error(cache, AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE));
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    refresh_cached_initial_fetch_recoverable_error_test,
    s_refresh_cached_initial_fetch_recoverable_error_test);

/* A non-recoverable initial-fetch error is returned as is and cached for 1-5 s */
static int s_refresh_cached_initial_fetch_non_recoverable_error_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct get_credentials_mock_result results[] = {
        {.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_SSO_UNAUTHORIZED},
        {.credentials = creds1},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_error(cache, AWS_AUTH_CREDENTIALS_PROVIDER_SSO_UNAUTHORIZED));

    /* Inside the 1 s minimum the cached error is returned without calling the source */
    s_set_time_ms(500);
    ASSERT_SUCCESS(s_expect_error(cache, AWS_AUTH_CREDENTIALS_PROVIDER_SSO_UNAUTHORIZED));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    /* After the 5 s maximum the source is called again */
    s_set_time_secs(6);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    refresh_cached_initial_fetch_non_recoverable_error_test,
    s_refresh_cached_initial_fetch_non_recoverable_error_test);

/* Expired credentials on the initial fetch are cached and returned, and the next call refreshes with no backoff */
static int s_refresh_cached_expired_initial_fetch_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(1000);

    struct aws_credentials *expired = s_new_credentials(allocator, s_access_key_1, 900);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 1900);
    struct get_credentials_mock_result results[] = {{.credentials = expired}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(expired);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_expired_initial_fetch_test, s_refresh_cached_expired_initial_fetch_test);

/* Checks that a refresh starts exactly when the advisory window for this lifetime opens */
static int s_check_advisory_window(struct aws_allocator *allocator, uint64_t lifetime_secs, uint64_t window_secs) {
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, lifetime_secs);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, lifetime_secs * 2);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    s_set_time_secs(lifetime_secs - window_secs - 1);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(lifetime_secs - window_secs + 1);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    return AWS_OP_SUCCESS;
}

/* Advisory window is 5 min up to 20 min lifetime, 15 min under 90 min, and 60 min otherwise */
static int s_refresh_cached_advisory_window_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);

    ASSERT_SUCCESS(s_check_advisory_window(allocator, 15 * 60, 5 * 60));
    ASSERT_SUCCESS(s_check_advisory_window(allocator, 20 * 60, 5 * 60));
    ASSERT_SUCCESS(s_check_advisory_window(allocator, 60 * 60, 15 * 60));
    ASSERT_SUCCESS(s_check_advisory_window(allocator, 90 * 60, 60 * 60));
    ASSERT_SUCCESS(s_check_advisory_window(allocator, 6 * 60 * 60, 60 * 60));

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_advisory_window_test, s_refresh_cached_advisory_window_test);

/* A failed advisory refresh keeps the credentials and backs off between 60 s and min(remaining / 2, 600 s) */
static int s_refresh_cached_advisory_failure_keeps_credentials_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 7200);
    struct get_credentials_mock_result results[] = {
        {.credentials = creds1},
        {.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE},
        {.credentials = creds2},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 3, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    /* 899 s left: the refresh fails and the cached credentials are returned */
    s_set_time_secs(2701);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    /* Still inside the 60 s minimum backoff */
    s_set_time_secs(2701 + 59);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    /* Past the upper bound of 449.5 s, the next call refreshes */
    s_set_time_secs(2701 + 450);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(3, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    refresh_cached_advisory_failure_keeps_credentials_test,
    s_refresh_cached_advisory_failure_keeps_credentials_test);

/* A successful refresh inside the 60 s mandatory window returns the new credentials */
static int s_refresh_cached_mandatory_refresh_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 900);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 1800);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    s_set_time_secs(850);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_mandatory_refresh_test, s_refresh_cached_mandatory_refresh_test);

/* After expiry a failed refresh still returns the cached credentials and backs off for 60-90 s */
static int s_refresh_cached_expired_refresh_failure_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 900);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 2000);
    struct get_credentials_mock_result results[] = {
        {.credentials = creds1},
        {.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE},
        {.credentials = creds2},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 3, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    s_set_time_secs(1000);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(1030);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(1091);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(3, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_expired_refresh_failure_test, s_refresh_cached_expired_refresh_failure_test);

/* Already-expired credentials from a refresh count as a failed refresh: old credentials kept, backoff applied */
static int s_refresh_cached_expired_on_refresh_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 900);
    struct aws_credentials *expired = s_new_credentials(allocator, s_access_key_2, 600);
    struct aws_credentials *creds3 = s_new_credentials(allocator, s_access_key_3, 2000);
    struct get_credentials_mock_result results[] = {
        {.credentials = creds1},
        {.credentials = expired},
        {.credentials = creds3},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 3, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    /* 200 s left: advisory refresh gets expired credentials */
    s_set_time_secs(700);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(730);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    /* Past the upper bound of 100 s */
    s_set_time_secs(801);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_3));
    ASSERT_UINT_EQUALS(3, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds3);
    aws_credentials_release(expired);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_expired_on_refresh_test, s_refresh_cached_expired_on_refresh_test);

/* Initial credentials already inside their refresh window are not refreshed again until one backoff has passed */
static int s_refresh_cached_short_initial_credentials_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *short_creds = s_new_credentials(allocator, s_access_key_1, 240);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 3600);
    struct get_credentials_mock_result results[] = {{.credentials = short_creds}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    /* Backoff is 60-120 s with 240 s left */
    s_set_time_secs(10);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(121);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(short_creds);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_short_initial_credentials_test, s_refresh_cached_short_initial_credentials_test);

/* A refresh that returns credentials already inside their refresh window waits one backoff before the next */
static int s_refresh_cached_short_refreshed_credentials_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 900);
    struct aws_credentials *short_creds = s_new_credentials(allocator, s_access_key_2, 940);
    struct aws_credentials *creds3 = s_new_credentials(allocator, s_access_key_3, 2000);
    struct get_credentials_mock_result results[] = {
        {.credentials = creds1},
        {.credentials = short_creds},
        {.credentials = creds3},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 3, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    /* 200 s left: the refresh returns credentials with only 240 s left */
    s_set_time_secs(700);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    /* Backoff is 60-120 s with 240 s left */
    s_set_time_secs(710);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(821);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_3));
    ASSERT_UINT_EQUALS(3, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds3);
    aws_credentials_release(short_creds);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_short_refreshed_credentials_test, s_refresh_cached_short_refreshed_credentials_test);

/* Initial credentials already in the mandatory window get no wait, so the next request refreshes */
static int s_refresh_cached_mandatory_initial_credentials_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *short_creds = s_new_credentials(allocator, s_access_key_1, 30);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 3600);
    struct get_credentials_mock_result results[] = {{.credentials = short_creds}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    s_set_time_secs(1);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(short_creds);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_mandatory_initial_credentials_test, s_refresh_cached_mandatory_initial_credentials_test);

/* The wait for short credentials ends when they enter the mandatory window */
static int s_refresh_cached_short_credentials_wait_capped_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *short_creds = s_new_credentials(allocator, s_access_key_1, 100);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 3600);
    struct get_credentials_mock_result results[] = {{.credentials = short_creds}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    /* Backoff is 60-90 s, capped at the 40 s until the mandatory window */
    s_set_time_secs(39);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(41);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(short_creds);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_short_credentials_wait_capped_test, s_refresh_cached_short_credentials_wait_capped_test);

/* A non-recoverable error on refresh is returned at once with no backoff, and cached for 1-5 s */
static int s_refresh_cached_non_recoverable_on_refresh_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 7200);
    struct get_credentials_mock_result results[] = {
        {.credentials = creds1},
        {.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_ACCESS_DENIED},
        {.credentials = creds2},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 3, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    s_set_time_ms(2701 * 1000);
    ASSERT_SUCCESS(s_expect_error(cache, AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_ACCESS_DENIED));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_ms(2701 * 1000 + 500);
    ASSERT_SUCCESS(s_expect_error(cache, AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_ACCESS_DENIED));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    /* No backoff was applied, so after the error cache the source is called again */
    s_set_time_secs(2701 + 6);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(3, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_non_recoverable_on_refresh_test, s_refresh_cached_non_recoverable_on_refresh_test);

/* Invalidate with the cached access key makes the next call refresh */
static int s_refresh_cached_invalidate_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 7200);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 2, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    s_set_time_secs(10);
    ASSERT_SUCCESS(aws_credentials_provider_invalidate(cache, creds1));
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_invalidate_test, s_refresh_cached_invalidate_test);

/* Invalidate with credentials the cache no longer holds is ignored */
static int s_refresh_cached_invalidate_other_credentials_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *other = s_new_credentials(allocator, s_access_key_2, 3600);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 1, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_SUCCESS(aws_credentials_provider_invalidate(cache, other));
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(other);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_invalidate_other_credentials_test, s_refresh_cached_invalidate_other_credentials_test);

/* A refresh after invalidate that returns the rejected access key counts as failed and backs off */
static int s_refresh_cached_invalidate_same_credentials_returned_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds1_again = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 7200);
    struct get_credentials_mock_result results[] = {
        {.credentials = creds1},
        {.credentials = creds1_again},
        {.credentials = creds2},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 3, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    s_set_time_secs(10);
    ASSERT_SUCCESS(aws_credentials_provider_invalidate(cache, creds1));
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    /* Backoff after invalidate is 60-90 s, because no lifetime remains */
    s_set_time_secs(40);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(101);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(3, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1_again);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    refresh_cached_invalidate_same_credentials_returned_test,
    s_refresh_cached_invalidate_same_credentials_returned_test);

/* Invalidate during a backoff does not bypass it */
static int s_refresh_cached_invalidate_keeps_backoff_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 7200);
    struct get_credentials_mock_result results[] = {
        {.credentials = creds1},
        {.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE},
        {.credentials = creds2},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 3, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));

    s_set_time_secs(2701);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(2702);
    ASSERT_SUCCESS(aws_credentials_provider_invalidate(cache, creds1));
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    /* Past the backoff upper bound of 449.5 s, the mandatory path refreshes */
    s_set_time_secs(2701 + 450);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_2));
    ASSERT_UINT_EQUALS(3, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_invalidate_keeps_backoff_test, s_refresh_cached_invalidate_keeps_backoff_test);

/* Number of callbacks delivered so far */
static int s_callback_count(struct aws_get_credentials_test_callback_result *result) {
    aws_mutex_lock(&result->sync);
    int count = result->count;
    aws_mutex_unlock(&result->sync);
    return count;
}

/* Requests during the initial fetch wait for it and share its result */
static int s_refresh_cached_initial_fetch_concurrency_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_event_loop_group *elg = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock_async(allocator, results, 1, elg, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    struct aws_get_credentials_test_callback_result result;
    aws_get_credentials_test_callback_result_init(&result, 2);
    ASSERT_SUCCESS(aws_credentials_provider_get_credentials(cache, aws_test_get_credentials_async_callback, &result));
    ASSERT_SUCCESS(aws_credentials_provider_get_credentials(cache, aws_test_get_credentials_async_callback, &result));
    ASSERT_INT_EQUALS(0, s_callback_count(&result));

    aws_credentials_provider_mock_async_fire_callbacks(mock);
    aws_wait_on_credentials_callback(&result);
    ASSERT_SUCCESS(s_check_access_key(result.credentials, s_access_key_1));
    aws_get_credentials_test_callback_result_clean_up(&result);

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds1);
    aws_event_loop_group_release(elg);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_initial_fetch_concurrency_test, s_refresh_cached_initial_fetch_concurrency_test);

/* During an advisory refresh in flight, other requests get the cached credentials at once */
static int s_refresh_cached_advisory_concurrency_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_event_loop_group *elg = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 7200);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock_async(allocator, results, 2, elg, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    struct aws_get_credentials_test_callback_result result;
    aws_get_credentials_test_callback_result_init(&result, 1);
    ASSERT_SUCCESS(aws_credentials_provider_get_credentials(cache, aws_test_get_credentials_async_callback, &result));
    aws_credentials_provider_mock_async_fire_callbacks(mock);
    aws_wait_on_credentials_callback(&result);
    aws_get_credentials_test_callback_result_clean_up(&result);

    /* The first request starts the refresh and waits; the second is answered from the cache */
    s_set_time_secs(2701);
    aws_get_credentials_test_callback_result_init(&result, 2);
    ASSERT_SUCCESS(aws_credentials_provider_get_credentials(cache, aws_test_get_credentials_async_callback, &result));
    ASSERT_SUCCESS(aws_credentials_provider_get_credentials(cache, aws_test_get_credentials_async_callback, &result));
    ASSERT_INT_EQUALS(1, s_callback_count(&result));
    ASSERT_SUCCESS(s_check_access_key(result.credentials, s_access_key_1));

    aws_credentials_provider_mock_async_fire_callbacks(mock);
    aws_wait_on_credentials_callback(&result);
    ASSERT_SUCCESS(s_check_access_key(result.credentials, s_access_key_2));
    aws_get_credentials_test_callback_result_clean_up(&result);

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_event_loop_group_release(elg);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_advisory_concurrency_test, s_refresh_cached_advisory_concurrency_test);

/* In the mandatory window every request waits for the one refresh and gets its result */
static int s_refresh_cached_mandatory_concurrency_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_event_loop_group *elg = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 900);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 1800);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock_async(allocator, results, 2, elg, NULL);
    struct aws_credentials_provider *cache = s_new_refresh_cache(allocator, mock, true);

    struct aws_get_credentials_test_callback_result result;
    aws_get_credentials_test_callback_result_init(&result, 1);
    ASSERT_SUCCESS(aws_credentials_provider_get_credentials(cache, aws_test_get_credentials_async_callback, &result));
    aws_credentials_provider_mock_async_fire_callbacks(mock);
    aws_wait_on_credentials_callback(&result);
    aws_get_credentials_test_callback_result_clean_up(&result);

    s_set_time_secs(850);
    aws_get_credentials_test_callback_result_init(&result, 3);
    for (int i = 0; i < 3; ++i) {
        ASSERT_SUCCESS(
            aws_credentials_provider_get_credentials(cache, aws_test_get_credentials_async_callback, &result));
    }
    ASSERT_INT_EQUALS(0, s_callback_count(&result));

    aws_credentials_provider_mock_async_fire_callbacks(mock);
    aws_wait_on_credentials_callback(&result);
    ASSERT_SUCCESS(s_check_access_key(result.credentials, s_access_key_2));
    aws_get_credentials_test_callback_result_clean_up(&result);

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_event_loop_group_release(elg);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(refresh_cached_mandatory_concurrency_test, s_refresh_cached_mandatory_concurrency_test);

/* new_cached gives a refreshable source the refresh cache, which keeps credentials after a failed refresh */
static int s_cached_provider_refreshable_source_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct get_credentials_mock_result results[] = {
        {.credentials = creds1},
        {.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE},
    };
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock_refreshable(allocator, results, 2, NULL);

    struct aws_credentials_provider_cached_options options = {
        .source = mock,
        .high_res_clock_fn = mock_aws_get_high_res_time,
        .system_clock_fn = mock_aws_get_system_time,
        .shutdown_options = {.shutdown_callback = s_on_shutdown_complete},
    };
    struct aws_credentials_provider *cache = aws_credentials_provider_new_cached(allocator, &options);
    ASSERT_NOT_NULL(cache);
    ASSERT_TRUE(aws_credentials_provider_is_refresh_cached(cache));

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    s_set_time_secs(3400);
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(cached_provider_refreshable_source_test, s_cached_provider_refreshable_source_test);

/* new_cached gives a standard source today's cache */
static int s_cached_provider_standard_source_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock(allocator, results, 1, NULL);

    struct aws_credentials_provider_cached_options options = {
        .source = mock,
        .high_res_clock_fn = mock_aws_get_high_res_time,
        .system_clock_fn = mock_aws_get_system_time,
        .shutdown_options = {.shutdown_callback = s_on_shutdown_complete},
    };
    struct aws_credentials_provider *cache = aws_credentials_provider_new_cached(allocator, &options);
    ASSERT_NOT_NULL(cache);
    ASSERT_FALSE(aws_credentials_provider_is_refresh_cached(cache));

    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_SUCCESS(s_expect_credentials(cache, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    s_release_cache_and_mock(cache, mock);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(cached_provider_standard_source_test, s_cached_provider_standard_source_test);

/* new_cached on a refresh cache returns a pass-through: one cache, invalidate forwarded, caller's shutdown fired */
static int s_cached_provider_pass_through_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 7200);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock_refreshable(allocator, results, 2, NULL);
    struct aws_credentials_provider *refresh_cache = s_new_refresh_cache(allocator, mock, false);

    struct aws_credentials_provider_cached_options options = {
        .source = refresh_cache,
        .refresh_time_in_milliseconds = 15 * 60 * 1000,
        .shutdown_options = {.shutdown_callback = s_on_shutdown_complete},
    };
    struct aws_credentials_provider *pass_through = aws_credentials_provider_new_cached(allocator, &options);
    ASSERT_NOT_NULL(pass_through);
    ASSERT_TRUE(pass_through != refresh_cache);
    ASSERT_FALSE(aws_credentials_provider_is_refresh_cached(pass_through));

    ASSERT_SUCCESS(s_expect_credentials(pass_through, s_access_key_1));
    ASSERT_SUCCESS(s_expect_credentials(pass_through, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    s_set_time_secs(10);
    ASSERT_SUCCESS(aws_credentials_provider_invalidate(pass_through, creds1));
    ASSERT_SUCCESS(s_expect_credentials(pass_through, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    aws_credentials_provider_release(refresh_cache);
    s_release_cache_and_mock(pass_through, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(cached_provider_pass_through_test, s_cached_provider_pass_through_test);

/* Wrapping a pass-through again forwards to the same refresh cache: one source call, invalidate still reaches it */
static int s_cached_provider_wrap_three_times_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 7200);
    struct get_credentials_mock_result results[] = {{.credentials = creds1}, {.credentials = creds2}};
    struct aws_credentials_provider *mock = aws_credentials_provider_new_mock_refreshable(allocator, results, 2, NULL);

    struct aws_credentials_provider_cached_options options = {
        .source = mock,
        .high_res_clock_fn = mock_aws_get_high_res_time,
        .system_clock_fn = mock_aws_get_system_time,
    };
    struct aws_credentials_provider *wrap1 = aws_credentials_provider_new_cached(allocator, &options);
    options.source = wrap1;
    struct aws_credentials_provider *wrap2 = aws_credentials_provider_new_cached(allocator, &options);
    options.source = wrap2;
    options.shutdown_options.shutdown_callback = s_on_shutdown_complete;
    struct aws_credentials_provider *wrap3 = aws_credentials_provider_new_cached(allocator, &options);
    ASSERT_NOT_NULL(wrap3);
    ASSERT_TRUE(aws_credentials_provider_is_refresh_cached(wrap1));
    ASSERT_FALSE(aws_credentials_provider_is_refresh_cached(wrap3));

    ASSERT_SUCCESS(s_expect_credentials(wrap3, s_access_key_1));
    ASSERT_SUCCESS(s_expect_credentials(wrap3, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock));

    /* An old cache in between would keep serving the rejected key without calling the source */
    s_set_time_secs(10);
    ASSERT_SUCCESS(aws_credentials_provider_invalidate(wrap3, creds1));
    ASSERT_SUCCESS(s_expect_credentials(wrap3, s_access_key_2));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock));

    aws_credentials_provider_release(wrap1);
    aws_credentials_provider_release(wrap2);
    s_release_cache_and_mock(wrap3, mock);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(cached_provider_wrap_three_times_test, s_cached_provider_wrap_three_times_test);

/* wrap_if_refreshable wraps only refreshable providers, and passes NULL and standard providers through */
static int s_wrap_if_refreshable_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);

    ASSERT_NULL(aws_credentials_provider_wrap_if_refreshable(allocator, NULL));

    struct get_credentials_mock_result results[] = {{.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE}};
    struct aws_credentials_provider *standard = aws_credentials_provider_new_mock(allocator, results, 1, NULL);
    ASSERT_PTR_EQUALS(standard, aws_credentials_provider_wrap_if_refreshable(allocator, standard));
    aws_credentials_provider_release(standard);

    struct aws_credentials_provider *refreshable =
        aws_credentials_provider_new_mock_refreshable(allocator, results, 1, NULL);
    struct aws_credentials_provider *wrapped = aws_credentials_provider_wrap_if_refreshable(allocator, refreshable);
    ASSERT_NOT_NULL(wrapped);
    ASSERT_TRUE(aws_credentials_provider_is_refresh_cached(wrapped));
    aws_credentials_provider_release(wrapped);

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(wrap_if_refreshable_test, s_wrap_if_refreshable_test);

static struct aws_credentials_provider *s_new_chain(
    struct aws_allocator *allocator,
    struct aws_credentials_provider *member1,
    struct aws_credentials_provider *member2) {

    struct aws_credentials_provider *providers[2] = {member1, member2};
    struct aws_credentials_provider_chain_options options = {
        .providers = providers,
        .provider_count = 2,
        .shutdown_options = {.shutdown_callback = s_on_shutdown_complete},
    };
    return aws_credentials_provider_new_chain(allocator, &options);
}

/* Chain invalidate reaches the member cache that holds the rejected credentials */
static int s_chain_invalidate_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();
    s_set_time_secs(0);

    struct aws_credentials *creds1 = s_new_credentials(allocator, s_access_key_1, 3600);
    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, 3600);
    struct aws_credentials *creds3 = s_new_credentials(allocator, s_access_key_3, 7200);
    struct get_credentials_mock_result results1[] = {{.credentials = creds1}, {.credentials = creds3}};
    struct get_credentials_mock_result results2[] = {{.credentials = creds2}};
    struct aws_credentials_provider *mock1 = aws_credentials_provider_new_mock(allocator, results1, 2, NULL);
    struct aws_credentials_provider *mock2 = aws_credentials_provider_new_mock(allocator, results2, 1, NULL);
    struct aws_credentials_provider *member1 = s_new_refresh_cache(allocator, mock1, false);
    struct aws_credentials_provider *chain = s_new_chain(allocator, member1, mock2);
    ASSERT_NOT_NULL(chain);

    ASSERT_SUCCESS(s_expect_credentials(chain, s_access_key_1));
    ASSERT_SUCCESS(s_expect_credentials(chain, s_access_key_1));
    ASSERT_UINT_EQUALS(1, aws_credentials_provider_mock_get_call_count(mock1));

    s_set_time_secs(10);
    ASSERT_SUCCESS(aws_credentials_provider_invalidate(chain, creds1));
    ASSERT_SUCCESS(s_expect_credentials(chain, s_access_key_3));
    ASSERT_UINT_EQUALS(2, aws_credentials_provider_mock_get_call_count(mock1));
    ASSERT_UINT_EQUALS(0, aws_credentials_provider_mock_get_call_count(mock2));

    aws_credentials_provider_release(member1);
    aws_credentials_provider_release(chain);
    s_wait_for_shutdown_and_clean_up();
    aws_credentials_provider_release(mock2);
    aws_credentials_provider_release(mock1);
    aws_credentials_release(creds3);
    aws_credentials_release(creds2);
    aws_credentials_release(creds1);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(chain_invalidate_test, s_chain_invalidate_test);

/* Runs a two-member chain whose members both fail and checks the returned error */
static int s_check_chain_all_fail(struct aws_allocator *allocator, int error1, int error2, int expected_error) {
    s_shutdown_init();

    struct get_credentials_mock_result results1[] = {{.error_code = error1}};
    struct get_credentials_mock_result results2[] = {{.error_code = error2}};
    struct aws_credentials_provider *mock1 = aws_credentials_provider_new_mock(allocator, results1, 1, NULL);
    struct aws_credentials_provider *mock2 = aws_credentials_provider_new_mock(allocator, results2, 1, NULL);
    struct aws_credentials_provider *chain = s_new_chain(allocator, mock1, mock2);
    ASSERT_NOT_NULL(chain);

    ASSERT_SUCCESS(s_expect_error(chain, expected_error));

    aws_credentials_provider_release(chain);
    s_wait_for_shutdown_and_clean_up();
    aws_credentials_provider_release(mock2);
    aws_credentials_provider_release(mock1);
    return AWS_OP_SUCCESS;
}

/* When every member fails, the chain returns the first non-recoverable error, otherwise no credentials */
static int s_chain_all_fail_error_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);

    ASSERT_SUCCESS(s_check_chain_all_fail(
        allocator,
        AWS_AUTH_CREDENTIALS_PROVIDER_SSO_UNAUTHORIZED,
        AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE,
        AWS_AUTH_CREDENTIALS_PROVIDER_SSO_UNAUTHORIZED));
    ASSERT_SUCCESS(s_check_chain_all_fail(
        allocator,
        AWS_AUTH_CREDENTIALS_PROVIDER_STS_NON_RECOVERABLE,
        AWS_AUTH_CREDENTIALS_PROVIDER_SSO_UNAUTHORIZED,
        AWS_AUTH_CREDENTIALS_PROVIDER_STS_NON_RECOVERABLE));
    ASSERT_SUCCESS(s_check_chain_all_fail(
        allocator,
        AWS_AUTH_CREDENTIALS_PROVIDER_STS_SOURCE_FAILURE,
        AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE,
        AWS_AUTH_SIGNING_NO_CREDENTIALS));

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(chain_all_fail_error_test, s_chain_all_fail_error_test);

/* A non-recoverable member error does not stop the walk when a later member returns credentials */
static int s_chain_non_recoverable_then_success_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    s_shutdown_init();

    struct aws_credentials *creds2 = s_new_credentials(allocator, s_access_key_2, UINT64_MAX);
    struct get_credentials_mock_result results1[] = {{.error_code = AWS_AUTH_CREDENTIALS_PROVIDER_STS_NON_RECOVERABLE}};
    struct get_credentials_mock_result results2[] = {{.credentials = creds2}};
    struct aws_credentials_provider *mock1 = aws_credentials_provider_new_mock(allocator, results1, 1, NULL);
    struct aws_credentials_provider *mock2 = aws_credentials_provider_new_mock(allocator, results2, 1, NULL);
    struct aws_credentials_provider *chain = s_new_chain(allocator, mock1, mock2);
    ASSERT_NOT_NULL(chain);

    ASSERT_SUCCESS(s_expect_credentials(chain, s_access_key_2));

    aws_credentials_provider_release(chain);
    s_wait_for_shutdown_and_clean_up();
    aws_credentials_provider_release(mock2);
    aws_credentials_provider_release(mock1);
    aws_credentials_release(creds2);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(chain_non_recoverable_then_success_test, s_chain_non_recoverable_then_success_test);
