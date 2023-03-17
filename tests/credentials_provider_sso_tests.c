/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include "credentials_provider_utils.h"
#include "shared_credentials_test_definitions.h"

#include <aws/auth/private/sso_token_utils.h>
#include <aws/common/environment.h>
#include <aws/http/status_code.h>

AWS_STATIC_STRING_FROM_LITERAL(s_sso_profile, "sso");
static int s_aws_credentials_provider_sso_test_init_config_profile(
    struct aws_allocator *allocator,
    const struct aws_string *config_contents) {

    struct aws_string *config_file_path_str = aws_create_process_unique_file_name(allocator);
    ASSERT_TRUE(config_file_path_str != NULL);
    ASSERT_TRUE(aws_create_profile_file(config_file_path_str, config_contents) == AWS_OP_SUCCESS);

    ASSERT_TRUE(
        aws_set_environment_value(s_default_config_path_env_variable_name, config_file_path_str) == AWS_OP_SUCCESS);

    ASSERT_TRUE(aws_set_environment_value(s_default_profile_env_variable_name, s_sso_profile) == AWS_OP_SUCCESS);

    aws_string_destroy(config_file_path_str);
    return AWS_OP_SUCCESS;
}

/* start_url should be same in `s_sso_profile_start_url` and `s_sso_profile_config_contents` */
AWS_STATIC_STRING_FROM_LITERAL(s_sso_profile_start_url, "https://d-123.awsapps.com/start");
AWS_STATIC_STRING_FROM_LITERAL(
    s_sso_profile_config_contents,
    "[profile sso]\n"
    "sso_start_url = https://d-123.awsapps.com/start\n"
    "sso_region = us-west-2\n"
    "sso_account_id = 123\n"
    "sso_role_name = roleName\n");
/* session name should be same in both `s_sso_session_name` and `s_sso_session_config_contents`*/
AWS_STATIC_STRING_FROM_LITERAL(s_sso_session_name, "session");
AWS_STATIC_STRING_FROM_LITERAL(
    s_sso_session_config_contents,
    "[profile sso]\n"
    "sso_start_url = https://d-123.awsapps.com/start\n"
    "sso_region = us-west-2\n"
    "sso_account_id = 123\n"
    "sso_role_name = roleName\n"
    "sso_session = session\n"
    "[sso-session session]\n"
    "sso_start_url = https://d-123.awsapps.com/start\n"
    "sso_region = us-west-2\n");

static int s_credentials_provider_sso_failed_invalid_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct {
        const char *name;
        const char *text;
    } invalid_config_examples[] = {
        {"empty", ""},

        {"profile without any sso config", "[profile sso]\naccessKey=access"},

        {"profile without role_name",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_region=us-west-2\n"},

        {"profile without account_id",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_region=us-west-2\n"
         "sso_role_name=roleName\n"},

        {"profile without region",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"},

        {"profile without start_url",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_region=us-west-2\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"},

        {"profile with invalid session",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_region=us-west-2\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"
         "sso_session = session\n"
         "[sso-session session]\n"},

        {"session without start_url",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_region=us-west-2\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"
         "sso_session = session\n"
         "[sso-session session]\n"
         "sso_region = us-west-2\n"},

        {"session without region",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_region=us-west-2\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"
         "sso_session = session\n"
         "[sso-session session]\n"
         "sso_start_url = https://d-123.awsapps.com/start\n"},

        {"session with different region",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_region=us-east-1\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"
         "sso_session = session\n"
         "[sso-session session]\n"
         "sso_start_url = https://d-123.awsapps.com/start\n"
         "sso_region = us-west-2\n"},

        {"session with different start-url",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_region=us-west-2\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"
         "sso_session = session\n"
         "[sso-session session]\n"
         "sso_start_url = https://d-321.awsapps.com/start\n"
         "sso_region = us-west-2\n"},
    };

    aws_credentials_provider_http_mock_tester_init(allocator);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };
    for (int i = 0; i < AWS_ARRAY_SIZE(invalid_config_examples); i++) {
        printf("invalid config example [%d]: %s\n", i, invalid_config_examples[i].name);
        struct aws_string *content = aws_string_new_from_c_str(allocator, invalid_config_examples[i].text);
        ASSERT_TRUE(content != NULL);
        s_aws_credentials_provider_sso_test_init_config_profile(allocator, content);
        aws_string_destroy(content);
        struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
        ASSERT_NULL(provider);
    }

    aws_credentials_provider_http_mock_tester_cleanup();

    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_failed_invalid_config, s_credentials_provider_sso_failed_invalid_config);

static int s_credentials_provider_sso_create_destroy_valid_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct {
        const char *name;
        const char *text;
    } valid_config_examples[] = {

        {"profile",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_account_id=123\n"
         "sso_region=us-west-2\n"
         "sso_role_name=roleName\n"},

        {"session",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"
         "sso_session = session\n"
         "[sso-session session]\n"
         "sso_start_url = https://d-123.awsapps.com/start\n"
         "sso_region = us-west-2\n"},

        {"session with profile",
         "[profile sso]\n"
         "accessKey=access\n"
         "sso_start_url=https://d-123.awsapps.com/start\n"
         "sso_region=us-west-2\n"
         "sso_account_id=123\n"
         "sso_role_name=roleName\n"
         "sso_session = session\n"
         "[sso-session session]\n"
         "sso_start_url = https://d-123.awsapps.com/start\n"
         "sso_region = us-west-2\n"},

    };

    aws_credentials_provider_http_mock_tester_init(allocator);

    struct aws_credentials_provider_sso_options options = {
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
        s_aws_credentials_provider_sso_test_init_config_profile(allocator, content);
        aws_string_destroy(content);
        struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
        ASSERT_NOT_NULL(provider);
        aws_credentials_provider_release(provider);
    }

    aws_credentials_provider_http_mock_tester_cleanup();

    return 0;
}
AWS_TEST_CASE(
    credentials_provider_sso_create_destroy_valid_config,
    s_credentials_provider_sso_create_destroy_valid_config);

AWS_STATIC_STRING_FROM_LITERAL(
    s_expected_sso_request_path,
    "/federation/credentials?account_id=123&role_name=roleName");

AWS_STATIC_STRING_FROM_LITERAL(
    s_good_response,
    "{\"roleCredentials\": {\"accessKeyId\": \"SuccessfulAccessKey\",\"secretAccessKey\": "
    "\"SuccessfulSecret\",\"sessionToken\": \"SuccessfulToken\",\"expiration\": 1678574216000}}");
AWS_STATIC_STRING_FROM_LITERAL(s_good_access_key_id, "SuccessfulAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_good_secret_access_key, "SuccessfulSecret");
AWS_STATIC_STRING_FROM_LITERAL(s_good_session_token, "SuccessfulToken");
static int s_good_response_expiration = 1678574216;
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
        ASSERT_INT_EQUALS(
            aws_credentials_get_expiration_timepoint_seconds(credentials_provider_http_mock_tester.credentials),
            s_good_response_expiration);
    } else {
        ASSERT_TRUE(credentials_provider_http_mock_tester.error_code);
        ASSERT_TRUE(credentials_provider_http_mock_tester.credentials == NULL);
    }

    if (request_made) {
        ASSERT_CURSOR_VALUE_STRING_EQUALS(
            aws_byte_cursor_from_buf(&credentials_provider_http_mock_tester.request_path), s_expected_sso_request_path);
    }
    ASSERT_INT_EQUALS(credentials_provider_http_mock_tester.attempts, expected_attempts);

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_sso_connect_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_connection_acquire_successful = false;

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_session_config_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_credentials_provider_sso_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
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
AWS_TEST_CASE(credentials_provider_sso_connect_failure, s_credentials_provider_sso_connect_failure);

static int s_credentials_provider_sso_failure_token_missing(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_session_config_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_credentials_provider_sso_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
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
AWS_TEST_CASE(credentials_provider_sso_failure_token_missing, s_credentials_provider_sso_failure_token_missing);

AWS_STATIC_STRING_FROM_LITERAL(s_home_env_var, "HOME");
AWS_STATIC_STRING_FROM_LITERAL(s_home_env_current_directory, ".");
AWS_STATIC_STRING_FROM_LITERAL(
    s_expired_sso_token,
    "{\"accessToken\": \"ValidAccessToken\",\"expiresAt\": \"2015-03-12T05:35:19Z\"}");
static int s_credentials_provider_sso_failure_token_expired(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;

    struct aws_string *actual_home;
    aws_get_environment_value(allocator, s_home_env_var, &actual_home);
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path));
    ASSERT_SUCCESS(aws_create_profile_file(token_path, s_expired_sso_token));

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_session_config_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_credentials_provider_sso_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(false /*no request*/, false /*get creds*/, 0 /*expected attempts*/));
    ASSERT_INT_EQUALS(credentials_provider_http_mock_tester.error_code, AWS_AUTH_SSO_TOKEN_EXPIRED);

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    /* reset $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);
    aws_string_destroy(token_path);
    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_failure_token_expired, s_credentials_provider_sso_failure_token_expired);

AWS_STATIC_STRING_FROM_LITERAL(
    s_valid_sso_token,
    "{\"accessToken\": \"ValidAccessToken\",\"expiresAt\": \"2099-03-12T05:35:19Z\"}");

static int s_credentials_provider_sso_request_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;
    credentials_provider_http_mock_tester.response_code = AWS_HTTP_STATUS_CODE_400_BAD_REQUEST;

    struct aws_string *actual_home;
    aws_get_environment_value(allocator, s_home_env_var, &actual_home);
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);
    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path));
    ASSERT_SUCCESS(aws_create_profile_file(token_path, s_valid_sso_token));

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_session_config_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_credentials_provider_sso_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, false /*get creds*/, 1 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    /* reset $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);
    aws_string_destroy(token_path);
    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_request_failure, s_credentials_provider_sso_request_failure);

AWS_STATIC_STRING_FROM_LITERAL(s_bad_json_response, "{ \"accessKey\": \"bad\"}");
static int s_credentials_provider_sso_bad_response(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);

    struct aws_string *actual_home;
    aws_get_environment_value(allocator, s_home_env_var, &actual_home);
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path));
    ASSERT_SUCCESS(aws_create_profile_file(token_path, s_valid_sso_token));

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_session_config_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_credentials_provider_sso_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_byte_cursor bad_json_cursor = aws_byte_cursor_from_string(s_bad_json_response);
    aws_array_list_push_back(&credentials_provider_http_mock_tester.response_data_callbacks, &bad_json_cursor);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, false /*get creds*/, 1 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    /* reset $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);
    aws_string_destroy(token_path);
    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_bad_response, s_credentials_provider_sso_bad_response);

static int s_credentials_provider_sso_retryable_error(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.response_code = AWS_HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    struct aws_string *actual_home;
    aws_get_environment_value(allocator, s_home_env_var, &actual_home);
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path));
    ASSERT_SUCCESS(aws_create_profile_file(token_path, s_valid_sso_token));

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_session_config_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_credentials_provider_sso_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_byte_cursor bad_json_cursor = aws_byte_cursor_from_string(s_bad_json_response);
    aws_array_list_push_back(&credentials_provider_http_mock_tester.response_data_callbacks, &bad_json_cursor);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, false /*get creds*/, 4 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    /* reset $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);
    aws_string_destroy(token_path);
    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_retryable_error, s_credentials_provider_sso_retryable_error);

static int s_credentials_provider_sso_basic_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    struct aws_string *actual_home;
    aws_get_environment_value(allocator, s_home_env_var, &actual_home);
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path));
    ASSERT_SUCCESS(aws_create_profile_file(token_path, s_valid_sso_token));

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_session_config_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_credentials_provider_sso_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    /* set the response */
    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&credentials_provider_http_mock_tester.response_data_callbacks, &good_response_cursor);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, true /*get creds*/, 1 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    /* reset $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);
    aws_string_destroy(token_path);
    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_basic_success, s_credentials_provider_sso_basic_success);

static int s_credentials_provider_sso_basic_success_profile(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    struct aws_string *actual_home;
    aws_get_environment_value(allocator, s_home_env_var, &actual_home);
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_profile_start_url);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(aws_create_directory_components(allocator, token_path));
    ASSERT_SUCCESS(aws_create_profile_file(token_path, s_valid_sso_token));

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_profile_config_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_credentials_provider_sso_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    /* set the response */
    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&credentials_provider_http_mock_tester.response_data_callbacks, &good_response_cursor);

    struct aws_credentials_provider_sso_options options = {
        .bootstrap = credentials_provider_http_mock_tester.bootstrap,
        .tls_ctx = credentials_provider_http_mock_tester.tls_ctx,
        .function_table = &aws_credentials_provider_http_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = aws_credentials_provider_http_mock_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(
        provider, aws_credentials_provider_http_mock_get_credentials_callback, NULL);

    aws_credentials_provider_http_mock_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(true /*request made*/, true /*get creds*/, 1 /*expected attempts*/));

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    /* reset $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);
    aws_string_destroy(token_path);
    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_basic_success_profile, s_credentials_provider_sso_basic_success_profile);
