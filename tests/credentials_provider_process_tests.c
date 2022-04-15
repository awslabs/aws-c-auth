/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include "shared_credentials_test_definitions.h"
#include <aws/auth/credentials.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/date_time.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/io/logging.h>

static struct aws_mock_process_tester {
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    struct aws_credentials *credentials;
    bool has_received_credentials_callback;
    bool has_received_shutdown_callback;
    int error_code;
} s_tester;

static void s_on_shutdown_complete(void *user_data) {
    (void)user_data;

    aws_mutex_lock(&s_tester.lock);
    s_tester.has_received_shutdown_callback = true;
    aws_mutex_unlock(&s_tester.lock);

    aws_condition_variable_notify_one(&s_tester.signal);
}

static bool s_has_tester_received_shutdown_callback(void *user_data) {
    (void)user_data;

    return s_tester.has_received_shutdown_callback;
}

static void s_aws_wait_for_provider_shutdown_callback(void) {
    aws_mutex_lock(&s_tester.lock);
    aws_condition_variable_wait_pred(&s_tester.signal, &s_tester.lock, s_has_tester_received_shutdown_callback, NULL);
    aws_mutex_unlock(&s_tester.lock);
}

AWS_STATIC_STRING_FROM_LITERAL(s_credentials_process_profile, "foo");

static int s_aws_process_test_init_config_profile(
    struct aws_allocator *allocator,
    const struct aws_string *config_contents) {

    struct aws_string *config_file_path_str = aws_create_process_unique_file_name(allocator);
    ASSERT_TRUE(config_file_path_str != NULL);
    ASSERT_TRUE(aws_create_profile_file(config_file_path_str, config_contents) == AWS_OP_SUCCESS);

    ASSERT_TRUE(
        aws_set_environment_value(s_default_config_path_env_variable_name, config_file_path_str) == AWS_OP_SUCCESS);

    ASSERT_TRUE(
        aws_set_environment_value(s_default_profile_env_variable_name, s_credentials_process_profile) ==
        AWS_OP_SUCCESS);

    aws_string_destroy(config_file_path_str);
    return AWS_OP_SUCCESS;
}

static int s_aws_process_tester_init(struct aws_allocator *allocator) {
    (void)allocator;
    if (aws_mutex_init(&s_tester.lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&s_tester.signal)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_aws_process_tester_cleanup(void) {
    aws_condition_variable_clean_up(&s_tester.signal);
    aws_mutex_clean_up(&s_tester.lock);
    aws_credentials_release(s_tester.credentials);
}

static bool s_has_tester_received_credentials_callback(void *user_data) {
    (void)user_data;

    return s_tester.has_received_credentials_callback;
}

static void s_aws_wait_for_credentials_result(void) {
    aws_mutex_lock(&s_tester.lock);
    aws_condition_variable_wait_pred(
        &s_tester.signal, &s_tester.lock, s_has_tester_received_credentials_callback, NULL);
    aws_mutex_unlock(&s_tester.lock);
}

static void s_get_credentials_callback(struct aws_credentials *credentials, int error_code, void *user_data) {
    (void)user_data;

    aws_mutex_lock(&s_tester.lock);
    s_tester.has_received_credentials_callback = true;
    s_tester.credentials = credentials;
    s_tester.error_code = error_code;
    if (credentials != NULL) {
        aws_credentials_acquire(credentials);
    }
    aws_condition_variable_notify_one(&s_tester.signal);
    aws_mutex_unlock(&s_tester.lock);
}

#ifdef _WIN32
AWS_STATIC_STRING_FROM_LITERAL(
    s_test_command,
    "echo {\"Version\": 1, \"AccessKeyId\": \"AccessKey123\", "
    "\"SecretAccessKey\": \"SecretAccessKey321\", \"Token\":\"TokenSuccess\", "
    "\"Expiration\":\"2020-02-25T06:03:31Z\"}");
#else
AWS_STATIC_STRING_FROM_LITERAL(
    s_test_command,
    "echo '{\"Version\": 1, \"AccessKeyId\": \"AccessKey123\", "
    "\"SecretAccessKey\": \"SecretAccessKey321\", \"Token\":\"TokenSuccess\", "
    "\"Expiration\":\"2020-02-25T06:03:31Z\"}'");
#endif

AWS_STATIC_STRING_FROM_LITERAL(s_bad_test_command, "/i/dont/know/what/is/this/command");
AWS_STATIC_STRING_FROM_LITERAL(s_bad_command_output, "echo \"Hello, World!\"");

AWS_STATIC_STRING_FROM_LITERAL(s_good_access_key_id, "AccessKey123");
AWS_STATIC_STRING_FROM_LITERAL(s_good_secret_access_key, "SecretAccessKey321");
AWS_STATIC_STRING_FROM_LITERAL(s_good_session_token, "TokenSuccess");
AWS_STATIC_STRING_FROM_LITERAL(s_good_expiration, "2020-02-25T06:03:31Z");

AWS_STATIC_STRING_FROM_LITERAL(
    s_process_config_file_contents,
    "[profile default]\n"
    "region=us-east-1\n"
    "[profile foo]\n"
    "region=us-west-2\n"
    "credential_process=");

static int s_credentials_provider_process_new_destroy_from_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_process_tester_init(allocator);

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_process_config_file_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);
    struct aws_byte_cursor cursor = aws_byte_cursor_from_string(s_test_command);
    ASSERT_TRUE(aws_byte_buf_append_dynamic(&content_buf, &cursor) == AWS_OP_SUCCESS);
    cursor = aws_byte_cursor_from_c_str("\n");
    ASSERT_TRUE(aws_byte_buf_append_dynamic(&content_buf, &cursor) == AWS_OP_SUCCESS);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_process_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_credentials_provider_process_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .profile_to_use = aws_byte_cursor_from_string(s_credentials_process_profile),
    };
    struct aws_credentials_provider *provider = aws_credentials_provider_new_process(allocator, &options);

    aws_credentials_provider_release(provider);
    s_aws_wait_for_provider_shutdown_callback();
    s_aws_process_tester_cleanup();
    return 0;
}
AWS_TEST_CASE(
    credentials_provider_process_new_destroy_from_config,
    s_credentials_provider_process_new_destroy_from_config);

AWS_STATIC_STRING_FROM_LITERAL(
    s_process_config_file_no_process_contents,
    "[profile default]\n"
    "region=us-east-1\n"
    "[profile foo]\n"
    "region=us-west-2\n");

static int s_credentials_provider_process_new_failed(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_process_tester_init(allocator);

    s_aws_process_test_init_config_profile(allocator, s_process_config_file_no_process_contents);

    struct aws_credentials_provider_process_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .profile_to_use = aws_byte_cursor_from_string(s_credentials_process_profile),
    };
    struct aws_credentials_provider *provider = aws_credentials_provider_new_process(allocator, &options);
    ASSERT_NULL(provider);

    s_aws_process_tester_cleanup();
    return 0;
}
AWS_TEST_CASE(credentials_provider_process_new_failed, s_credentials_provider_process_new_failed);

static int s_credentials_provider_process_bad_command(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_process_tester_init(allocator);

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_process_config_file_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);
    struct aws_byte_cursor cursor = aws_byte_cursor_from_string(s_bad_test_command);
    ASSERT_TRUE(aws_byte_buf_append_dynamic(&content_buf, &cursor) == AWS_OP_SUCCESS);
    cursor = aws_byte_cursor_from_c_str("\n");
    ASSERT_TRUE(aws_byte_buf_append_dynamic(&content_buf, &cursor) == AWS_OP_SUCCESS);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_process_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_credentials_provider_process_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .profile_to_use = aws_byte_cursor_from_string(s_credentials_process_profile),
    };
    struct aws_credentials_provider *provider = aws_credentials_provider_new_process(allocator, &options);
    ASSERT_NOT_NULL(provider);
    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);

    aws_credentials_provider_release(provider);
    s_aws_wait_for_provider_shutdown_callback();
    s_aws_process_tester_cleanup();
    return 0;
}
AWS_TEST_CASE(credentials_provider_process_bad_command, s_credentials_provider_process_bad_command);

static int s_credentials_provider_process_incorrect_command_output(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_process_tester_init(allocator);

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_process_config_file_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);
    struct aws_byte_cursor cursor = aws_byte_cursor_from_string(s_bad_command_output);
    ASSERT_TRUE(aws_byte_buf_append_dynamic(&content_buf, &cursor) == AWS_OP_SUCCESS);
    cursor = aws_byte_cursor_from_c_str("\n");
    ASSERT_TRUE(aws_byte_buf_append_dynamic(&content_buf, &cursor) == AWS_OP_SUCCESS);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_process_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_credentials_provider_process_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .profile_to_use = aws_byte_cursor_from_string(s_credentials_process_profile),
    };
    struct aws_credentials_provider *provider = aws_credentials_provider_new_process(allocator, &options);
    ASSERT_NOT_NULL(provider);
    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);

    aws_credentials_provider_release(provider);
    s_aws_wait_for_provider_shutdown_callback();
    s_aws_process_tester_cleanup();
    return 0;
}
AWS_TEST_CASE(
    credentials_provider_process_incorrect_command_output,
    s_credentials_provider_process_incorrect_command_output);

static int s_verify_credentials(struct aws_credentials *credentials) {
    ASSERT_NOT_NULL(credentials);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_access_key_id(credentials), s_good_access_key_id);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_secret_access_key(credentials), s_good_secret_access_key);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_session_token(credentials), s_good_session_token);

    struct aws_date_time expiration;
    struct aws_byte_cursor date_cursor = aws_byte_cursor_from_string(s_good_expiration);
    aws_date_time_init_from_str_cursor(&expiration, &date_cursor, AWS_DATE_FORMAT_ISO_8601);
    ASSERT_TRUE(
        aws_credentials_get_expiration_timepoint_seconds(s_tester.credentials) == (uint64_t)expiration.timestamp);

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_process_basic_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_process_tester_init(allocator);

    struct aws_byte_buf content_buf;
    struct aws_byte_buf existing_content = aws_byte_buf_from_c_str(aws_string_c_str(s_process_config_file_contents));
    aws_byte_buf_init_copy(&content_buf, allocator, &existing_content);
    struct aws_byte_cursor cursor = aws_byte_cursor_from_string(s_test_command);
    ASSERT_TRUE(aws_byte_buf_append_dynamic(&content_buf, &cursor) == AWS_OP_SUCCESS);
    cursor = aws_byte_cursor_from_c_str("\n");
    ASSERT_TRUE(aws_byte_buf_append_dynamic(&content_buf, &cursor) == AWS_OP_SUCCESS);

    struct aws_string *config_file_contents = aws_string_new_from_array(allocator, content_buf.buffer, content_buf.len);
    ASSERT_TRUE(config_file_contents != NULL);
    aws_byte_buf_clean_up(&content_buf);

    s_aws_process_test_init_config_profile(allocator, config_file_contents);
    aws_string_destroy(config_file_contents);

    struct aws_credentials_provider_process_options options = {
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .profile_to_use = aws_byte_cursor_from_string(s_credentials_process_profile),
    };
    struct aws_credentials_provider *provider = aws_credentials_provider_new_process(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_SUCCESS(s_verify_credentials(s_tester.credentials));

    aws_credentials_provider_release(provider);
    s_aws_wait_for_provider_shutdown_callback();
    s_aws_process_tester_cleanup();
    return 0;
}
AWS_TEST_CASE(credentials_provider_process_basic_success, s_credentials_provider_process_basic_success);
