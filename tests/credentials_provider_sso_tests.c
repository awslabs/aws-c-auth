/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include "credentials_provider_utils.h"
#include "shared_credentials_test_definitions.h"

#include <aws/auth/credentials.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/auth/private/sso_token_utils.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/date_time.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>

static bool received_callback = false;
static struct aws_mutex lock;
static struct aws_condition_variable tester_signal;
static bool s_has_tester_received_credentials_callback(void *user_data) {
    (void)user_data;

    return received_callback;
}
static void s_get_credentials_callback(struct aws_credentials *credentials, int error_code, void *user_data) {
    (void)user_data;
    (void)credentials;
    printf("credentials callback, %d", error_code);
    AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "waahm7 callback %d", error_code);

    received_callback = true;
    AWS_FATAL_ASSERT(credentials != NULL);
    aws_condition_variable_notify_one(&tester_signal);
}

static int s_credentials_provider_sso_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    struct aws_credentials_provider_sso_options options;
    AWS_ZERO_STRUCT(options);
    options.profile_name_override = aws_byte_cursor_from_c_str("AdministratorAccess-069542832437");

    struct aws_tls_ctx_options tls_options;
    aws_tls_ctx_options_init_default_client(&tls_options, allocator);
    options.tls_ctx = aws_tls_client_ctx_new(allocator, &tls_options);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 0, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 8,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = el_group,
        .host_resolver = resolver,
    };
    options.bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    if (aws_mutex_init(&lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&tester_signal)) {
        return AWS_OP_ERR;
    }

    aws_condition_variable_wait_pred(&tester_signal, &lock, s_has_tester_received_credentials_callback, NULL);

    AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "waahm7 releasing");

    aws_credentials_provider_release(provider);
    aws_event_loop_group_release(el_group);
    aws_host_resolver_release(resolver);
    aws_client_bootstrap_release(options.bootstrap);
    aws_tls_ctx_release(options.tls_ctx);
    aws_auth_library_clean_up();
    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_new_destroy, s_credentials_provider_sso_new_destroy);

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
// TODO: add config tests

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

static int s_credentials_provider_sso_new_destroy_from_profile_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_sso_profile_config_contents));
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

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    return 0;
}
AWS_TEST_CASE(
    credentials_provider_sso_new_destroy_from_profile_config,
    s_credentials_provider_sso_new_destroy_from_profile_config);

static int s_credentials_provider_sso_new_destroy_from_sso_session_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);

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

    aws_credentials_provider_release(provider);

    aws_credentials_provider_http_mock_wait_for_shutdown_callback();

    aws_credentials_provider_http_mock_tester_cleanup();

    return 0;
}
AWS_TEST_CASE(
    credentials_provider_sso_new_destroy_from_sso_session_config,
    s_credentials_provider_sso_new_destroy_from_sso_session_config);

static int s_credentials_provider_sso_failed_without_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    struct aws_string *empty_content = aws_string_new_from_c_str(allocator, "");
    ASSERT_TRUE(empty_content != NULL);
    s_aws_credentials_provider_sso_test_init_config_profile(allocator, empty_content);
    aws_string_destroy(empty_content);

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
    ASSERT_NULL(provider);

    aws_credentials_provider_http_mock_tester_cleanup();

    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_failed_without_config, s_credentials_provider_sso_failed_without_config);

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
AWS_STATIC_STRING_FROM_LITERAL(s_good_response_expiration, "2020-02-25T06:03:31Z");

static int s_verify_credentials(bool request_made, bool got_credentials, int expected_attempts) {

    if (request_made) {
        ASSERT_CURSOR_VALUE_STRING_EQUALS(
            aws_byte_cursor_from_buf(&credentials_provider_http_mock_tester.request_path), s_expected_sso_request_path);
    }

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
    } else {
        ASSERT_TRUE(credentials_provider_http_mock_tester.credentials == NULL);
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

static int s_credentials_provider_sso_token_failure(struct aws_allocator *allocator, void *ctx) {
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
AWS_TEST_CASE(credentials_provider_sso_token_failure, s_credentials_provider_sso_token_failure);

/**
 * Create the directory components of @path:
 * - if @path ends in a path separator, create every directory component;
 * - else, stop at the last path separator (parent directory of @path).
 */
static int s_create_directory_components(struct aws_allocator *allocator, const struct aws_string *path) {
    const char local_platform_separator = aws_get_platform_directory_separator();

    /* Create directory components and ensure use of platform separator at the same time. */
    for (size_t i = 0; i < path->len; ++i) {
        if (aws_is_any_directory_separator((char)path->bytes[i])) {
            ((char *)path->bytes)[i] = local_platform_separator;

            struct aws_string *segment = aws_string_new_from_array(allocator, path->bytes, i);
            int rc = aws_directory_create(segment);
            aws_string_destroy(segment);

            if (rc != AWS_OP_SUCCESS) {
                return rc;
            }
        }
    }
    return AWS_OP_SUCCESS;
}

AWS_STATIC_STRING_FROM_LITERAL(s_home_env_var, "HOME");
AWS_STATIC_STRING_FROM_LITERAL(s_home_env_current_directory, ".");

AWS_STATIC_STRING_FROM_LITERAL(
    s_valid_sso_token,
    "{\"accessToken\": \"ValidAccessToken\",\"expiresAt\": \"2030-03-12T05:35:19Z\"}");

static int s_credentials_provider_sso_request_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);
    credentials_provider_http_mock_tester.is_request_successful = false;

    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(s_create_directory_components(allocator, token_path));
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
AWS_TEST_CASE(credentials_provider_sso_request_failure, s_credentials_provider_sso_request_failure);

AWS_STATIC_STRING_FROM_LITERAL(s_bad_json_response, "{ \"accessKey\": \"bad\"}");
static int s_credentials_provider_sso_bad_response(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_credentials_provider_http_mock_tester_init(allocator);

    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(s_create_directory_components(allocator, token_path));
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
    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(s_create_directory_components(allocator, token_path));
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
    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_session_name);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(s_create_directory_components(allocator, token_path));
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
    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    /* redirect $HOME */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_env_current_directory));

    /* create token file */
    struct aws_string *token_path = aws_construct_token_path(allocator, s_sso_profile_start_url);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(s_create_directory_components(allocator, token_path));
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
