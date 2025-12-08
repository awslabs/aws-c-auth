/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/testing/aws_test_harness.h>

#include "aws/auth/private/login_token_utils.h"
#include "credentials_provider_utils.h"
#include "shared_credentials_test_definitions.h"

#include <aws/common/clock.h>
#include <aws/common/environment.h>
#include <aws/http/status_code.h>

AWS_STATIC_STRING_FROM_LITERAL(s_login_profile, "login");
AWS_STATIC_STRING_FROM_LITERAL(s_login_session, "arn:aws:sts::123456789012:assumed-role/Admin/shinji");
AWS_STATIC_STRING_FROM_LITERAL(
    s_login_config_contents,
    "[profile login]\n"
    "login_session=arn:aws:sts::123456789012:assumed-role/Admin/shinji\n"
    "region = us-east-1\n");

AWS_STATIC_STRING_FROM_LITERAL(s_expected_login_request_path, "/v1/token");
AWS_STATIC_STRING_FROM_LITERAL(s_good_access_key_id, "Ritsuko");
AWS_STATIC_STRING_FROM_LITERAL(s_good_secret_access_key, "Ryoji");
AWS_STATIC_STRING_FROM_LITERAL(s_good_session_token, "PenPen");
AWS_STATIC_STRING_FROM_LITERAL(s_good_account_id, "123456789012");
static uint64_t s_login_token_expiration_s = 1426138519;
static int s_expire_token_assert_range = 5000;

static int s_aws_credentials_provider_login_test_init_config_profile(
    struct aws_allocator *allocator,
    const struct aws_string *config_contents) {

    struct aws_string *config_file_path_str = aws_create_process_unique_file_name(allocator);
    ASSERT_TRUE(config_file_path_str != NULL);
    ASSERT_TRUE(aws_create_profile_file(config_file_path_str, config_contents) == AWS_OP_SUCCESS);

    ASSERT_TRUE(
        aws_set_environment_value(s_default_config_path_env_variable_name, config_file_path_str) == AWS_OP_SUCCESS);

    ASSERT_TRUE(aws_set_environment_value(s_default_profile_env_variable_name, s_login_profile) == AWS_OP_SUCCESS);

    aws_string_destroy(config_file_path_str);
    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_login_failed_invalid_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct {
        const char *name;
        const char *text;
    } valid_config_examples[] = {
        {"empty", ""},

        {"profile without any login config", "[profile login]\naccessKey=access"},

        {"profile with region but no session any login config", "[profile login]\nregion=us-east-1"},
    };
    aws_credentials_provider_http_mock_tester_init(allocator);

    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };
    for (int i = 0; i < AWS_ARRAY_SIZE(valid_config_examples); i++) {
        printf("invalid config example [%d]: %s\n", i, valid_config_examples[i].name);
        struct aws_string *content = aws_string_new_from_c_str(allocator, valid_config_examples[i].text);
        ASSERT_TRUE(content != NULL);
        s_aws_credentials_provider_login_test_init_config_profile(allocator, content);
        aws_string_destroy(content);
        struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
        ASSERT_NULL(provider);
    }

    aws_credentials_provider_http_mock_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_login_failed_invalid_config, s_credentials_provider_login_failed_invalid_config);

static int s_credentials_provider_login_create_destroy_valid_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct {
        const char *name;
        const char *text;
    } valid_config_examples[] = {
        {"profile with region and login session",
         "[profile login]\n"
         "region=us-east-1\n"
         "login_session=arn:aws:sts::123456789012:assumed-role/Admin/shinji\n"},
    };

    aws_credentials_provider_http_mock_tester_init(allocator);

    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };
    for (int i = 0; i < AWS_ARRAY_SIZE(valid_config_examples); i++) {
        printf("valid config example [%d]: %s\n", i, valid_config_examples[i].name);
        struct aws_string *content = aws_string_new_from_c_str(allocator, valid_config_examples[i].text);
        ASSERT_TRUE(content != NULL);
        s_aws_credentials_provider_login_test_init_config_profile(allocator, content);
        aws_string_destroy(content);
        struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
        ASSERT_NOT_NULL(provider);
        aws_credentials_provider_release(provider);
    }

    aws_credentials_provider_http_mock_tester_cleanup();

    return 0;
}
AWS_TEST_CASE(
    credentials_provider_login_create_destroy_valid_config,
    s_credentials_provider_login_create_destroy_valid_config);

static int s_verify_credentials(bool request_made, bool got_credentials, int expected_attempts) {
    ASSERT_TRUE(credentials_provider_http_mock_tester.has_received_credentials_callback);

    if (got_credentials) {
        ASSERT_TRUE(credentials_provider_http_mock_tester.credentials != NULL);
        ASSERT_CURSOR_VALUE_STRING_EQUALS(
            aws_credentials_get_access_key_id(credentials_provider_http_mock_tester.credentials), s_good_access_key_id);
        ASSERT_CURSOR_VALUE_STRING_EQUALS(
            aws_credentials_get_secret_access_key(credentials_provider_http_mock_tester.credentials),
            s_good_secret_access_key);
        ASSERT_CURSOR_VALUE_STRING_EQUALS(
            aws_credentials_get_session_token(credentials_provider_http_mock_tester.credentials), s_good_session_token);
        ASSERT_CURSOR_VALUE_STRING_EQUALS(
            aws_credentials_get_account_id(credentials_provider_http_mock_tester.credentials), s_good_account_id);
        uint64_t credentials_expiration =
            aws_credentials_get_expiration_timepoint_seconds(credentials_provider_http_mock_tester.credentials);
        struct aws_date_time now;
        aws_date_time_init_now(&now);
        uint64_t approx_should_expire = (uint64_t)aws_date_time_as_epoch_secs(&now) + 90;
        ASSERT_TRUE(abs((int)(credentials_expiration - approx_should_expire)) < s_expire_token_assert_range);
    } else {
        ASSERT_TRUE(credentials_provider_http_mock_tester.error_code);
        ASSERT_TRUE(credentials_provider_http_mock_tester.credentials == NULL);
    }

    if (request_made) {
        ASSERT_CURSOR_VALUE_STRING_EQUALS(
            aws_byte_cursor_from_buf(&credentials_provider_http_mock_tester.request_path),
            s_expected_login_request_path);
    }
    ASSERT_INT_EQUALS(credentials_provider_http_mock_tester.attempts, expected_attempts);

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_login_connect_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_connection_acquire_successful = false;

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);

    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();
    ASSERT_SUCCESS(s_verify_credentials(false /*no request*/, false /*get creds*/, 0 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    return 0;
}
AWS_TEST_CASE(credentials_provider_login_connect_failure, s_credentials_provider_login_connect_failure);

static int s_credentials_provider_login_failure_token_missing(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;

    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);

    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(false /*no request*/, false /*get creds*/, 0 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();
    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);

    return 0;
}
AWS_TEST_CASE(credentials_provider_login_failure_token_missing, s_credentials_provider_login_failure_token_missing);

AWS_STATIC_STRING_FROM_LITERAL(
    s_login_token_expired,
    "{\"accessToken\":{\"accessKeyId\":\"shinji\",\"secretAccessKey\":\"rei\",\"sessionToken\":\"asuka\",\"accountId\":"
    "\"123456789012\",\"expiresAt\":\"2000-09-13T00:00:00Z\"},\"tokenType\":\"urn:aws:params:oauth:token-type:access_"
    "token_sigv4\",\"clientId\":\"arn:aws:signin:::devtools/"
    "same-device\",\"refreshToken\":\"Kaworu\",\"idToken\":\"toji\",\"dpopKey\":\"-----BEGIN EC PRIVATE "
    "KEY-----\nGendo\n-----END EC PRIVATE KEY-----\n\"}");

static int s_credentials_provider_login_failure_token_expired(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;

    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    /* create token file */
    struct aws_byte_buf token_path;
    AWS_ZERO_STRUCT(token_path);
    aws_login_token_construct_token_path(allocator, s_login_session, tmp_home, &token_path);
    struct aws_string *token_path_string = aws_string_new_from_buf(allocator, &token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path_string));
    ASSERT_SUCCESS(aws_create_profile_file(token_path_string, s_login_token_expired));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);
    uint64_t nano_expiration =
        aws_timestamp_convert(s_login_token_expiration_s + 100, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    mock_aws_set_system_time(nano_expiration);
    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .system_clock_fn = mock_aws_get_system_time,
        .login_cache_directory_override = aws_byte_cursor_from_string(tmp_home),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(false /*no request*/, false /*get creds*/, 0 /*expected attempts*/));
    ASSERT_INT_EQUALS(
        credentials_provider_http_mock_tester.error_code, AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_TOKEN_EXPIRED);

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();
    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);
    aws_byte_buf_clean_up(&token_path);
    aws_string_destroy(token_path_string);
    return 0;
}
AWS_TEST_CASE(credentials_provider_login_failure_token_expired, s_credentials_provider_login_failure_token_expired);

AWS_STATIC_STRING_FROM_LITERAL(
    s_login_empty_token,
    "{\"accessToken\": \"\",\"tokenType\":\"urn:aws:params:oauth:token-type:access_"
    "token_sigv4\",\"clientId\":\"arn:aws:signin:::devtools/"
    "same-device\",\"refreshToken\":\"Kaworu\",\"idToken\":\"toji\",\"dpopKey\":\"-----BEGIN EC PRIVATE "
    "KEY-----\nGendo\n-----END EC PRIVATE KEY-----\n\"}");
static int s_credentials_provider_login_failure_token_empty(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;

    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    /* create token file */
    struct aws_byte_buf token_path;
    AWS_ZERO_STRUCT(token_path);
    aws_login_token_construct_token_path(allocator, s_login_session, tmp_home, &token_path);
    struct aws_string *token_path_string = aws_string_new_from_buf(allocator, &token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path_string));
    ASSERT_SUCCESS(aws_create_profile_file(token_path_string, s_login_empty_token));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);
    mock_aws_set_system_time(0);
    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .system_clock_fn = mock_aws_get_system_time,
        .login_cache_directory_override = aws_byte_cursor_from_string(tmp_home),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(false /*no request*/, false /*get creds*/, 0 /*expected attempts*/));
    ASSERT_INT_EQUALS(
        credentials_provider_http_mock_tester.error_code, AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_FAILED_TO_CREATE_TOKEN);

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();
    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);
    aws_byte_buf_clean_up(&token_path);
    aws_string_destroy(token_path_string);
    return 0;
}
AWS_TEST_CASE(credentials_provider_login_failure_token_empty, s_credentials_provider_login_failure_token_empty);

AWS_STATIC_STRING_FROM_LITERAL(
    s_login_token_pembad,
    "{\"accessToken\":{\"accessKeyId\":\"shinji\",\"secretAccessKey\":\"rei\",\"sessionToken\":\"asuka\",\"accountId\":"
    "\"123456789012\",\"expiresAt\":\"3000-09-13T00:00:00Z\"},\"tokenType\":\"urn:aws:params:oauth:token-type:access_"
    "token_sigv4\",\"clientId\":\"arn:aws:signin:::devtools/"
    "same-device\",\"refreshToken\":\"Kaworu\",\"idToken\":\"toji\",\"dpopKey\":\"-----BEGIN EC PRIVATE "
    "KEY-----\nGendo\n-----END EC PRIVATE KEY-----\n\"}");

static int s_credentials_provider_login_bad_pem(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;
    credentials_provider_http_mock_tester.response_code = AWS_HTTP_STATUS_CODE_400_BAD_REQUEST;

    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    /* create token file */
    struct aws_byte_buf token_path;
    AWS_ZERO_STRUCT(token_path);
    aws_login_token_construct_token_path(allocator, s_login_session, tmp_home, &token_path);
    struct aws_string *token_path_string = aws_string_new_from_buf(allocator, &token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path_string));
    ASSERT_SUCCESS(aws_create_profile_file(token_path_string, s_login_token_pembad));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);

    mock_aws_set_system_time(0);
    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .system_clock_fn = mock_aws_get_system_time,
        .login_cache_directory_override = aws_byte_cursor_from_string(tmp_home),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(false /*request made*/, false /*get creds*/, 0 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);
    aws_byte_buf_clean_up(&token_path);
    aws_string_destroy(token_path_string);
    return 0;
}
AWS_TEST_CASE(credentials_provider_login_bad_pem, s_credentials_provider_login_bad_pem);

AWS_STATIC_STRING_FROM_LITERAL(
    s_login_token_good,
    "{\"accessToken\":{\"accessKeyId\":\"shinji\",\"secretAccessKey\":\"rei\",\"sessionToken\":\"asuka\",\"accountId\":"
    "\"123456789012\",\"expiresAt\":\"3000-09-13T00:00:00Z\"},\"tokenType\":\"urn:aws:params:oauth:token-type:access_"
    "token_sigv4\",\"clientId\":\"arn:aws:signin:::devtools/"
    "same-device\",\"refreshToken\":\"Kaworu\",\"idToken\":\"toji\",\"dpopKey\":\"-----BEGIN EC PRIVATE "
    "KEY-----\nMHcCAQEEIBDOA9C+wyEeYZYLa9fPAzzZLi43suMHc7GqUSD2wP9VoAoGCCqGSM49\nAwEHoUQDQgAE8p+"
    "kv53xQZSVnOvFFQZgYXafB8IQXc0boBiNwruEaIzNEi5/7m0I\nP8t5hwdP1bEyoLcHx9sIDcPy8W9str/Kow==\n-----END EC PRIVATE "
    "KEY-----\n\"}");

static int s_credentials_provider_login_request_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;
    credentials_provider_http_mock_tester.response_code = AWS_HTTP_STATUS_CODE_400_BAD_REQUEST;

    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    /* create token file */
    struct aws_byte_buf token_path;
    AWS_ZERO_STRUCT(token_path);
    aws_login_token_construct_token_path(allocator, s_login_session, tmp_home, &token_path);
    struct aws_string *token_path_string = aws_string_new_from_buf(allocator, &token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path_string));
    ASSERT_SUCCESS(aws_create_profile_file(token_path_string, s_login_token_good));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);

    mock_aws_set_system_time(0);
    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .system_clock_fn = mock_aws_get_system_time,
        .login_cache_directory_override = aws_byte_cursor_from_string(tmp_home),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, false /*get creds*/, 1 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);
    aws_byte_buf_clean_up(&token_path);
    aws_string_destroy(token_path_string);
    return 0;
}
AWS_TEST_CASE(credentials_provider_login_request_failure, s_credentials_provider_login_request_failure);

AWS_STATIC_STRING_FROM_LITERAL(s_bad_json_response, "{ \"third\": \"impact\" }");
static int s_credentials_provider_login_bad_response(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);

    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    /* create token file */
    struct aws_byte_buf token_path;
    AWS_ZERO_STRUCT(token_path);
    aws_login_token_construct_token_path(allocator, s_login_session, tmp_home, &token_path);
    struct aws_string *token_path_string = aws_string_new_from_buf(allocator, &token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path_string));
    ASSERT_SUCCESS(aws_create_profile_file(token_path_string, s_login_token_good));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);

    struct aws_byte_cursor bad_json_cursor = aws_byte_cursor_from_string(s_bad_json_response);
    aws_array_list_push_back(&credentials_provider_http_mock_tester.response_data_callbacks, &bad_json_cursor);

    mock_aws_set_system_time(0);
    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .system_clock_fn = mock_aws_get_system_time,
        .login_cache_directory_override = aws_byte_cursor_from_string(tmp_home),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, false /*get creds*/, 1 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);
    aws_byte_buf_clean_up(&token_path);
    aws_string_destroy(token_path_string);
    return 0;
}
AWS_TEST_CASE(credentials_provider_login_bad_response, s_credentials_provider_login_bad_response);

static int s_credentials_provider_login_retryable_error(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.response_code = AWS_HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;

    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    /* create token file */
    struct aws_byte_buf token_path;
    AWS_ZERO_STRUCT(token_path);
    aws_login_token_construct_token_path(allocator, s_login_session, tmp_home, &token_path);
    struct aws_string *token_path_string = aws_string_new_from_buf(allocator, &token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path_string));
    ASSERT_SUCCESS(aws_create_profile_file(token_path_string, s_login_token_good));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);

    struct aws_byte_cursor bad_json_cursor = aws_byte_cursor_from_string(s_bad_json_response);
    aws_array_list_push_back(&credentials_provider_http_mock_tester.response_data_callbacks, &bad_json_cursor);

    mock_aws_set_system_time(0);
    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .system_clock_fn = mock_aws_get_system_time,
        .login_cache_directory_override = aws_byte_cursor_from_string(tmp_home),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, false /*get creds*/, 4 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);
    aws_byte_buf_clean_up(&token_path);
    aws_string_destroy(token_path_string);
    return 0;
}
AWS_TEST_CASE(credentials_provider_login_retryable_error, s_credentials_provider_login_retryable_error);

AWS_STATIC_STRING_FROM_LITERAL(
    s_good_response,
    "{\"accessToken\":{\"accessKeyId\":\"Ritsuko\",\"secretAccessKey\":\"Ryoji\",\"sessionToken\":\"PenPen\"},"
    "\"tokenType\":\"urn:aws:params:oauth:token-type:access_token_sigv4\",\"expiresIn\":900,\"refreshToken\":"
    "\"Kensuke\"}");
static int s_credentials_provider_login_basic_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);

    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    /* create token file */
    struct aws_byte_buf token_path;
    AWS_ZERO_STRUCT(token_path);
    aws_login_token_construct_token_path(allocator, s_login_session, tmp_home, &token_path);
    struct aws_string *token_path_string = aws_string_new_from_buf(allocator, &token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path_string));
    ASSERT_SUCCESS(aws_create_profile_file(token_path_string, s_login_token_good));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);

    /* set the response */
    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&credentials_provider_http_mock_tester.response_data_callbacks, &good_response_cursor);

    mock_aws_set_system_time(0);
    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .system_clock_fn = mock_aws_get_system_time,
        .login_cache_directory_override = aws_byte_cursor_from_string(tmp_home),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, true /*get creds*/, 1 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);
    aws_byte_buf_clean_up(&token_path);
    aws_string_destroy(token_path_string);
    return 0;
}
AWS_TEST_CASE(credentials_provider_login_basic_success, s_credentials_provider_login_basic_success);

static int s_credentials_provider_login_basic_success_after_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.failure_count = 2;
    credentials_provider_http_mock_tester.failure_response_code = AWS_HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    /* redirect $HOME */
    struct aws_string *tmp_home;
    ASSERT_SUCCESS(aws_create_random_home_directory(allocator, &tmp_home));

    /* create token file */
    struct aws_byte_buf token_path;
    AWS_ZERO_STRUCT(token_path);
    aws_login_token_construct_token_path(allocator, s_login_session, tmp_home, &token_path);
    struct aws_string *token_path_string = aws_string_new_from_buf(allocator, &token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path_string));
    ASSERT_SUCCESS(aws_create_profile_file(token_path_string, s_login_token_good));

    s_aws_credentials_provider_login_test_init_config_profile(allocator, s_login_config_contents);

    /* set the response */
    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&credentials_provider_http_mock_tester.response_data_callbacks, &good_response_cursor);

    mock_aws_set_system_time(0);
    struct aws_credentials_provider_login_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .system_clock_fn = mock_aws_get_system_time,
        .login_cache_directory_override = aws_byte_cursor_from_string(tmp_home),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_login(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, true /*get creds*/, 3 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    aws_directory_delete(tmp_home, true);
    aws_string_destroy(tmp_home);
    aws_byte_buf_clean_up(&token_path);
    aws_string_destroy(token_path_string);
    return 0;
}
AWS_TEST_CASE(
    credentials_provider_login_basic_success_after_failure,
    s_credentials_provider_login_basic_success_after_failure);