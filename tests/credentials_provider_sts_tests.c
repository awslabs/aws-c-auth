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

#include <aws/auth/credentials.h>
#include <aws/common/condition_variable.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/stream.h>

#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>

#include <aws/auth/private/credentials_utils.h>
#include <aws/testing/aws_test_harness.h>

#include "shared_credentials_test_definitions.h"

struct aws_mock_sts_tester {
    struct aws_allocator *allocator;
    struct aws_byte_buf request_path;
    struct aws_byte_buf method;
    struct aws_byte_buf host_header;
    struct aws_byte_buf request_body;
    bool had_auth_header;

    int mock_response_code;
    struct aws_byte_buf mock_body;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_credentials *credentials;
    bool has_received_credentials_callback;

    bool fail_connection;
};

static struct aws_mock_sts_tester s_tester;

static struct aws_http_connection_manager *s_aws_http_connection_manager_new_mock(
    struct aws_allocator *allocator,
    struct aws_http_connection_manager_options *options) {

    (void)allocator;
    (void)options;

    return (struct aws_http_connection_manager *)1;
}

static void s_aws_http_connection_manager_release_mock(struct aws_http_connection_manager *manager) {
    (void)manager;
}

static void s_aws_http_connection_manager_acquire_connection_mock(
    struct aws_http_connection_manager *manager,
    aws_http_connection_manager_on_connection_setup_fn *callback,
    void *user_data) {

    (void)manager;
    (void)callback;
    (void)user_data;

    if (!s_tester.fail_connection) {
        callback((struct aws_http_connection *)1, AWS_OP_SUCCESS, user_data);
    } else {
        aws_raise_error(AWS_ERROR_HTTP_UNKNOWN);
        callback(NULL, AWS_OP_ERR, user_data);
    }
}

static int s_aws_http_connection_manager_release_connection_mock(
    struct aws_http_connection_manager *manager,
    struct aws_http_connection *connection) {

    (void)manager;
    (void)connection;

    return AWS_OP_SUCCESS;
}

static void s_invoke_mock_request_callbacks(
    const struct aws_http_make_request_options *options,
    bool is_request_successful) {

    struct aws_http_header headers[1];
    AWS_ZERO_ARRAY(headers);

    headers[0].name = aws_byte_cursor_from_c_str("some-header");
    headers[0].value = aws_byte_cursor_from_c_str("value");

    if (options->on_response_headers) {
        options->on_response_headers(
            (struct aws_http_stream *)1, AWS_HTTP_HEADER_BLOCK_MAIN, headers, 1, options->user_data);
    }

    if (options->on_response_header_block_done) {
        options->on_response_header_block_done((struct aws_http_stream *)1, true, options->user_data);
    }

    struct aws_byte_cursor data_callback_cur = aws_byte_cursor_from_buf(&s_tester.mock_body);
    options->on_response_body((struct aws_http_stream *)1, &data_callback_cur, options->user_data);

    options->on_complete(
        (struct aws_http_stream *)1,
        is_request_successful ? AWS_ERROR_SUCCESS : AWS_ERROR_HTTP_UNKNOWN,
        options->user_data);
}

static struct aws_http_stream *s_aws_http_connection_make_request_mock(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options) {

    (void)client_connection;
    (void)options;

    struct aws_byte_cursor path;
    AWS_ZERO_STRUCT(path);
    aws_http_message_get_request_path(options->request, &path);
    aws_byte_buf_init_copy_from_cursor(&s_tester.request_path, s_tester.allocator, path);

    struct aws_byte_cursor method;
    AWS_ZERO_STRUCT(method);
    aws_http_message_get_request_method(options->request, &method);
    aws_byte_buf_init_copy_from_cursor(&s_tester.method, s_tester.allocator, method);

    size_t header_count = aws_http_message_get_header_count(options->request);

    for (size_t i = 0; i < header_count; ++i) {
        struct aws_http_header header;
        AWS_ZERO_STRUCT(header);

        aws_http_message_get_header(options->request, &header, i);

        if (aws_byte_cursor_eq_c_str_ignore_case(&header.name, "host")) {
            aws_byte_buf_init_copy_from_cursor(&s_tester.host_header, s_tester.allocator, header.value);
        }

        if (aws_byte_cursor_eq_c_str_ignore_case(&header.name, "authorization")) {
            s_tester.had_auth_header = true;
        }
    }

    struct aws_input_stream *input_stream = aws_http_message_get_body_stream(options->request);
    int64_t body_len = 0;

    aws_input_stream_get_length(input_stream, &body_len);
    aws_byte_buf_init(&s_tester.request_body, s_tester.allocator, (size_t)body_len);
    aws_input_stream_read(input_stream, &s_tester.request_body);

    s_invoke_mock_request_callbacks(options, s_tester.mock_response_code == 200);

    return (struct aws_http_stream *)1;
}

static int s_aws_http_stream_get_incoming_response_status_mock(
    const struct aws_http_stream *stream,
    int *out_status_code) {
    (void)stream;

    *out_status_code = s_tester.mock_response_code;

    return AWS_OP_SUCCESS;
}

static void s_aws_http_stream_release_mock(struct aws_http_stream *stream) {
    (void)stream;
}

static void s_aws_http_connection_close_mock(struct aws_http_connection *connection) {
    (void)connection;
}

static struct aws_credentials_provider_http_function_table s_mock_function_table = {
    .aws_http_connection_manager_new = s_aws_http_connection_manager_new_mock,
    .aws_http_connection_manager_release = s_aws_http_connection_manager_release_mock,
    .aws_http_connection_manager_acquire_connection = s_aws_http_connection_manager_acquire_connection_mock,
    .aws_http_connection_manager_release_connection = s_aws_http_connection_manager_release_connection_mock,
    .aws_http_connection_make_request = s_aws_http_connection_make_request_mock,
    .aws_http_stream_get_incoming_response_status = s_aws_http_stream_get_incoming_response_status_mock,
    .aws_http_stream_release = s_aws_http_stream_release_mock,
    .aws_http_connection_close = s_aws_http_connection_close_mock};

static int s_aws_sts_tester_init(struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(s_tester);
    s_tester.allocator = allocator;

    if (aws_mutex_init(&s_tester.lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&s_tester.signal)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_aws_sts_tester_cleanup(void) {

    aws_condition_variable_clean_up(&s_tester.signal);
    aws_mutex_clean_up(&s_tester.lock);

    if (s_tester.credentials) {
        aws_credentials_destroy(s_tester.credentials);
    }

    aws_byte_buf_clean_up(&s_tester.host_header);
    aws_byte_buf_clean_up(&s_tester.method);
    aws_byte_buf_clean_up(&s_tester.request_path);
    aws_byte_buf_clean_up(&s_tester.mock_body);
    aws_byte_buf_clean_up(&s_tester.request_body);
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

static void s_get_credentials_callback(struct aws_credentials *credentials, void *user_data) {
    (void)user_data;

    aws_mutex_lock(&s_tester.lock);
    s_tester.has_received_credentials_callback = true;
    if (credentials != NULL) {
        s_tester.credentials = aws_credentials_new_copy(credentials->allocator, credentials);
    }
    aws_condition_variable_notify_one(&s_tester.signal);
    aws_mutex_unlock(&s_tester.lock);
}

static struct aws_byte_cursor s_access_key_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("accessKey12345");
static struct aws_byte_cursor s_secret_key_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("secretKey12345");
static struct aws_byte_cursor s_session_token_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("sessionToken123456789");
static struct aws_byte_cursor s_role_arn_cur =
    AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("arn:aws:iam::67895:role/test_role");
static struct aws_byte_cursor s_session_name_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("test_session");

static const char *success_creds_doc = "<AssumeRoleResponse xmlns=\"who cares\">\n"
                                       "     <AssumeRoleResult>\n"
                                       "         <fuzzMePlz>\n"
                                       "         </fuzzMePlz>\n"
                                       "         <Credentials>\n"
                                       "             <AccessKeyId>accessKeyIdResp</AccessKeyId>\n"
                                       "             <SecretAccessKey>secretKeyResp</SecretAccessKey>\n"
                                       "             <SessionToken>sessionTokenResp</SessionToken>\n"
                                       "         </Credentials>\n"
                                       "         <AssumeRoleUser>\n"
                                       "             ... a bunch of other stuff we don't care about\n"
                                       "         </AssumeRoleUser>\n"
                                       "         ... more stuff we don't care about\n"
                                       "      </AssumeRoleResult>\n"
                                       "</AssumeRoleResponse>";

static struct aws_byte_cursor s_expected_payload =
    AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Version=2011-06-15&Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A67895%"
                                          "3Arole%2Ftest_role&RoleSessionName=test_session&DurationSeconds=900");

static int s_credentials_provider_sts_direct_config_succeeds_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);
    s_aws_sts_tester_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 0);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 10, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_credentials_provider *static_provider =
        aws_credentials_provider_new_static(allocator, s_access_key_cur, s_secret_key_cur, s_session_token_cur);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = bootstrap,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
    };

    s_tester.mock_body = aws_byte_buf_from_c_str(success_creds_doc);
    s_tester.mock_response_code = 200;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_NOT_NULL(s_tester.credentials);
    ASSERT_STR_EQUALS("accessKeyIdResp", aws_string_c_str(s_tester.credentials->access_key_id));
    ASSERT_STR_EQUALS("secretKeyResp", aws_string_c_str(s_tester.credentials->secret_access_key));
    ASSERT_STR_EQUALS("sessionTokenResp", aws_string_c_str(s_tester.credentials->session_token));

    const char *expected_method = "POST";
    ASSERT_BIN_ARRAYS_EQUALS(expected_method, strlen(expected_method), s_tester.method.buffer, s_tester.method.len);

    const char *expected_path = "/";
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_path, strlen(expected_path), s_tester.request_path.buffer, s_tester.request_path.len);

    ASSERT_TRUE(s_tester.had_auth_header);

    const char *expected_host_header = "sts.amazonaws.com";
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_host_header, strlen(expected_host_header), s_tester.host_header.buffer, s_tester.host_header.len);

    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_payload.ptr, s_expected_payload.len, s_tester.request_body.buffer, s_tester.request_body.len);

    aws_credentials_provider_release(sts_provider);
    aws_credentials_provider_release(static_provider);
    s_aws_sts_tester_cleanup();

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(credentials_provider_sts_direct_config_succeeds, s_credentials_provider_sts_direct_config_succeeds_fn)

static const char *malformed_creds_doc = "<AssumeRoleResponse xmlns=\"who cares\">\n"
                                         "     <AssumeRoleResult>\n"
                                         "         <AssumeRoleUser>\n"
                                         "             <Credentials>\n"
                                         "                 <AccessKeyId>accessKeyIdResp</AccessKeyId>\n"
                                         "                ";

static int s_credentials_provider_sts_direct_config_invalid_doc_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);
    s_aws_sts_tester_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 0);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 10, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_credentials_provider *static_provider =
        aws_credentials_provider_new_static(allocator, s_access_key_cur, s_secret_key_cur, s_session_token_cur);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = bootstrap,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
    };

    s_tester.mock_body = aws_byte_buf_from_c_str(malformed_creds_doc);
    s_tester.mock_response_code = 200;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_NULL(s_tester.credentials);

    const char *expected_method = "POST";
    ASSERT_BIN_ARRAYS_EQUALS(expected_method, strlen(expected_method), s_tester.method.buffer, s_tester.method.len);

    const char *expected_path = "/";
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_path, strlen(expected_path), s_tester.request_path.buffer, s_tester.request_path.len);

    ASSERT_TRUE(s_tester.had_auth_header);

    const char *expected_host_header = "sts.amazonaws.com";
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_host_header, strlen(expected_host_header), s_tester.host_header.buffer, s_tester.host_header.len);

    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_payload.ptr, s_expected_payload.len, s_tester.request_body.buffer, s_tester.request_body.len);

    aws_credentials_provider_release(sts_provider);
    aws_credentials_provider_release(static_provider);
    s_aws_sts_tester_cleanup();

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_direct_config_invalid_doc,
    s_credentials_provider_sts_direct_config_invalid_doc_fn)

static int s_credentials_provider_sts_direct_config_connection_failed_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);
    s_aws_sts_tester_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 0);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 10, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_credentials_provider *static_provider =
        aws_credentials_provider_new_static(allocator, s_access_key_cur, s_secret_key_cur, s_session_token_cur);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = bootstrap,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
    };

    s_tester.fail_connection = true;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_NULL(s_tester.credentials);

    aws_credentials_provider_release(sts_provider);
    aws_credentials_provider_release(static_provider);
    s_aws_sts_tester_cleanup();

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_direct_config_connection_failed,
    s_credentials_provider_sts_direct_config_connection_failed_fn)

static int s_credentials_provider_sts_direct_config_service_fails_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);
    s_aws_sts_tester_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 0);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 10, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_credentials_provider *static_provider =
        aws_credentials_provider_new_static(allocator, s_access_key_cur, s_secret_key_cur, s_session_token_cur);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = bootstrap,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
    };

    s_tester.mock_response_code = 529;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_NULL(s_tester.credentials);

    aws_credentials_provider_release(sts_provider);
    aws_credentials_provider_release(static_provider);
    s_aws_sts_tester_cleanup();

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_direct_config_service_fails,
    s_credentials_provider_sts_direct_config_service_fails_fn)

static const char *s_soure_profile_config_file = "[default]\n"
                                                 "aws_access_key_id=BLAHBLAH\n"
                                                 "aws_secret_access_key=BLAHBLAHBLAH\n"
                                                 "\n"
                                                 "[roletest]\n"
                                                 "role_arn=arn:aws:iam::67895:role/test_role\n"
                                                 "source_profile=default\n"
                                                 "role_session_name=test_session";

static int s_credentials_provider_sts_from_profile_config_succeeds_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);

    aws_unset_environment_value(s_default_profile_env_variable_name);
    aws_unset_environment_value(s_default_config_path_env_variable_name);
    aws_unset_environment_value(s_default_credentials_path_env_variable_name);

    s_aws_sts_tester_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 0);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 10, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_string *config_contents = aws_string_new_from_c_str(allocator, s_soure_profile_config_file);
    ASSERT_SUCCESS(aws_create_profile_file(s_credentials_file_name, config_contents));
    aws_string_destroy(config_contents);

    struct aws_credentials_provider_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(s_config_file_name),
        .credentials_file_name_override = aws_byte_cursor_from_string(s_credentials_file_name),
        .profile_name_override = aws_byte_cursor_from_c_str("roletest"),
        .bootstrap = bootstrap,
        .function_table = &s_mock_function_table,
    };

    s_aws_sts_tester_init(allocator);

    s_tester.mock_body = aws_byte_buf_from_c_str(success_creds_doc);
    s_tester.mock_response_code = 200;

    struct aws_credentials_provider *provider = aws_credentials_provider_new_profile(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_NOT_NULL(s_tester.credentials);
    ASSERT_STR_EQUALS("accessKeyIdResp", aws_string_c_str(s_tester.credentials->access_key_id));
    ASSERT_STR_EQUALS("secretKeyResp", aws_string_c_str(s_tester.credentials->secret_access_key));
    ASSERT_STR_EQUALS("sessionTokenResp", aws_string_c_str(s_tester.credentials->session_token));

    const char *expected_method = "POST";
    ASSERT_BIN_ARRAYS_EQUALS(expected_method, strlen(expected_method), s_tester.method.buffer, s_tester.method.len);

    const char *expected_path = "/";
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_path, strlen(expected_path), s_tester.request_path.buffer, s_tester.request_path.len);

    ASSERT_TRUE(s_tester.had_auth_header);

    const char *expected_host_header = "sts.amazonaws.com";
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_host_header, strlen(expected_host_header), s_tester.host_header.buffer, s_tester.host_header.len);

    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_payload.ptr, s_expected_payload.len, s_tester.request_body.buffer, s_tester.request_body.len);

    remove(aws_string_c_str(s_credentials_file_name));
    aws_credentials_provider_release(provider);

    s_aws_sts_tester_cleanup();

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_from_profile_config_succeeds,
    s_credentials_provider_sts_from_profile_config_succeeds_fn)

static const char *s_env_source_config_file = "[default]\n"
                                              "aws_access_key_id=BLAHBLAH\n"
                                              "aws_secret_access_key=BLAHBLAHBLAH\n"
                                              "\n"
                                              "[roletest]\n"
                                              "role_arn=arn:aws:iam::67895:role/test_role\n"
                                              "credential_source=Environment\n"
                                              "role_session_name=test_session";

AWS_STRING_FROM_LITERAL(s_env_access_key_val, "EnvAccessKeyId");
AWS_STRING_FROM_LITERAL(s_env_secret_access_key_val, "EnvSecretAccessKeyId");

static int s_credentials_provider_sts_from_profile_config_environment_succeeds_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);

    aws_unset_environment_value(s_default_profile_env_variable_name);
    aws_unset_environment_value(s_default_config_path_env_variable_name);
    aws_unset_environment_value(s_default_credentials_path_env_variable_name);

    aws_set_environment_value(s_access_key_id_env_var, s_env_access_key_val);
    aws_set_environment_value(s_secret_access_key_env_var, s_env_secret_access_key_val);

    s_aws_sts_tester_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 0);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 10, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_string *config_contents = aws_string_new_from_c_str(allocator, s_env_source_config_file);
    ASSERT_SUCCESS(aws_create_profile_file(s_credentials_file_name, config_contents));
    aws_string_destroy(config_contents);

    struct aws_credentials_provider_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(s_config_file_name),
        .credentials_file_name_override = aws_byte_cursor_from_string(s_credentials_file_name),
        .profile_name_override = aws_byte_cursor_from_c_str("roletest"),
        .bootstrap = bootstrap,
        .function_table = &s_mock_function_table,
    };

    s_aws_sts_tester_init(allocator);

    s_tester.mock_body = aws_byte_buf_from_c_str(success_creds_doc);
    s_tester.mock_response_code = 200;

    struct aws_credentials_provider *provider = aws_credentials_provider_new_profile(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_NOT_NULL(s_tester.credentials);
    ASSERT_STR_EQUALS("accessKeyIdResp", aws_string_c_str(s_tester.credentials->access_key_id));
    ASSERT_STR_EQUALS("secretKeyResp", aws_string_c_str(s_tester.credentials->secret_access_key));
    ASSERT_STR_EQUALS("sessionTokenResp", aws_string_c_str(s_tester.credentials->session_token));

    const char *expected_method = "POST";
    ASSERT_BIN_ARRAYS_EQUALS(expected_method, strlen(expected_method), s_tester.method.buffer, s_tester.method.len);

    const char *expected_path = "/";
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_path, strlen(expected_path), s_tester.request_path.buffer, s_tester.request_path.len);

    ASSERT_TRUE(s_tester.had_auth_header);

    const char *expected_host_header = "sts.amazonaws.com";
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_host_header, strlen(expected_host_header), s_tester.host_header.buffer, s_tester.host_header.len);

    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_payload.ptr, s_expected_payload.len, s_tester.request_body.buffer, s_tester.request_body.len);

    remove(aws_string_c_str(s_credentials_file_name));
    aws_credentials_provider_release(provider);

    s_aws_sts_tester_cleanup();

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_from_profile_config_environment_succeeds,
    s_credentials_provider_sts_from_profile_config_environment_succeeds_fn)
