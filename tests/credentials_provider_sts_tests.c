/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>

#include <aws/auth/private/credentials_utils.h>
#include <aws/testing/aws_test_harness.h>

#include "credentials_provider_utils.h"
#include "shared_credentials_test_definitions.h"

struct aws_mock_sts_tester {
    struct aws_allocator *allocator;
    struct aws_byte_buf request_path;
    struct aws_byte_buf method;
    struct aws_byte_buf host_header;
    struct aws_byte_buf request_body;
    bool had_auth_header;

    int mock_response_code;
    int mock_failure_code;
    int return_response_code;
    size_t fail_operations;

    struct aws_byte_buf mock_body;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_credentials *credentials;
    bool has_received_credentials_callback;
    int error_code;

    bool fail_connection;

    struct aws_event_loop_group *el_group;

    struct aws_host_resolver *resolver;

    struct aws_client_bootstrap *bootstrap;

    struct aws_tls_ctx *tls_ctx;
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
    aws_byte_buf_clean_up(&s_tester.request_path);
    aws_byte_buf_init_copy_from_cursor(&s_tester.request_path, s_tester.allocator, path);

    struct aws_byte_cursor method;
    AWS_ZERO_STRUCT(method);
    aws_http_message_get_request_method(options->request, &method);
    aws_byte_buf_clean_up(&s_tester.method);
    aws_byte_buf_init_copy_from_cursor(&s_tester.method, s_tester.allocator, method);

    size_t header_count = aws_http_message_get_header_count(options->request);

    for (size_t i = 0; i < header_count; ++i) {
        struct aws_http_header header;
        AWS_ZERO_STRUCT(header);

        aws_http_message_get_header(options->request, &header, i);

        if (aws_byte_cursor_eq_c_str_ignore_case(&header.name, "host")) {
            aws_byte_buf_clean_up(&s_tester.host_header);
            aws_byte_buf_init_copy_from_cursor(&s_tester.host_header, s_tester.allocator, header.value);
        }

        if (aws_byte_cursor_eq_c_str_ignore_case(&header.name, "authorization")) {
            s_tester.had_auth_header = true;
        }
    }

    struct aws_input_stream *input_stream = aws_http_message_get_body_stream(options->request);
    int64_t body_len = 0;

    aws_input_stream_get_length(input_stream, &body_len);
    aws_byte_buf_clean_up(&s_tester.request_body);
    aws_byte_buf_init(&s_tester.request_body, s_tester.allocator, (size_t)body_len);
    aws_input_stream_read(input_stream, &s_tester.request_body);

    bool fail_request = false;

    if (s_tester.fail_operations) {
        fail_request = true;
        s_tester.fail_operations--;
        s_tester.return_response_code = s_tester.mock_failure_code;
    } else {
        s_tester.return_response_code = s_tester.mock_response_code;
    }
    s_invoke_mock_request_callbacks(options, !fail_request);

    return (struct aws_http_stream *)1;
}

static int s_aws_http_stream_get_incoming_response_status_mock(
    const struct aws_http_stream *stream,
    int *out_status_code) {
    (void)stream;

    *out_status_code = s_tester.return_response_code;

    return AWS_OP_SUCCESS;
}

static int s_aws_http_stream_activate_mock(struct aws_http_stream *stream) {
    (void)stream;
    return AWS_OP_SUCCESS;
}

static void s_aws_http_stream_release_mock(struct aws_http_stream *stream) {
    (void)stream;
}

static void s_aws_http_connection_close_mock(struct aws_http_connection *connection) {
    (void)connection;
}

static struct aws_auth_http_system_vtable s_mock_function_table = {
    .aws_http_connection_manager_new = s_aws_http_connection_manager_new_mock,
    .aws_http_connection_manager_release = s_aws_http_connection_manager_release_mock,
    .aws_http_connection_manager_acquire_connection = s_aws_http_connection_manager_acquire_connection_mock,
    .aws_http_connection_manager_release_connection = s_aws_http_connection_manager_release_connection_mock,
    .aws_http_connection_make_request = s_aws_http_connection_make_request_mock,
    .aws_http_stream_activate = s_aws_http_stream_activate_mock,
    .aws_http_stream_get_incoming_response_status = s_aws_http_stream_get_incoming_response_status_mock,
    .aws_http_stream_release = s_aws_http_stream_release_mock,
    .aws_http_connection_close = s_aws_http_connection_close_mock};

static int s_aws_sts_tester_init(struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(s_tester);
    s_tester.allocator = allocator;

    aws_auth_library_init(allocator);

    if (aws_mutex_init(&s_tester.lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&s_tester.signal)) {
        return AWS_OP_ERR;
    }

    s_tester.el_group = aws_event_loop_group_new_default(allocator, 0, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = s_tester.el_group,
        .max_entries = 8,
    };
    s_tester.resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = s_tester.el_group,
        .host_resolver = s_tester.resolver,
    };
    s_tester.bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_tls_ctx_options tls_options;
    aws_tls_ctx_options_init_default_client(&tls_options, allocator);
    s_tester.tls_ctx = aws_tls_client_ctx_new(allocator, &tls_options);
    ASSERT_NOT_NULL(s_tester.tls_ctx);
    aws_tls_ctx_options_clean_up(&tls_options);

    return AWS_OP_SUCCESS;
}

static void s_cleanup_creds_callback_data(void) {
    aws_mutex_lock(&s_tester.lock);
    s_tester.has_received_credentials_callback = false;

    if (s_tester.credentials) {
        aws_credentials_release(s_tester.credentials);
        s_tester.credentials = NULL;
    }

    aws_byte_buf_clean_up(&s_tester.method);
    aws_byte_buf_clean_up(&s_tester.request_path);
    aws_byte_buf_clean_up(&s_tester.host_header);
    aws_byte_buf_clean_up(&s_tester.request_body);

    aws_mutex_unlock(&s_tester.lock);
}

static int s_aws_sts_tester_cleanup(void) {

    s_cleanup_creds_callback_data();

    aws_condition_variable_clean_up(&s_tester.signal);
    aws_mutex_clean_up(&s_tester.lock);

    aws_byte_buf_clean_up(&s_tester.mock_body);

    aws_client_bootstrap_release(s_tester.bootstrap);
    aws_host_resolver_release(s_tester.resolver);
    aws_event_loop_group_release(s_tester.el_group);
    aws_tls_ctx_release(s_tester.tls_ctx);

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
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
    s_tester.error_code = error_code;
    s_tester.credentials = credentials;
    aws_credentials_acquire(credentials);
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

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_response, "accessKeyIdResp");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_response, "secretKeyResp");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_response, "sessionTokenResp");

static int s_verify_credentials(struct aws_credentials *credentials) {
    ASSERT_NOT_NULL(credentials);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_access_key_id(credentials), s_access_key_id_response);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_secret_access_key(credentials), s_secret_access_key_response);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_session_token(credentials), s_session_token_response);

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_sts_direct_config_succeeds_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_sts_tester_init(allocator);

    struct aws_credentials_provider_static_options static_options = {
        .access_key_id = s_access_key_cur,
        .secret_access_key = s_secret_key_cur,
        .session_token = s_session_token_cur,
    };
    struct aws_credentials_provider *static_provider = aws_credentials_provider_new_static(allocator, &static_options);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = s_tester.bootstrap,
        .tls_ctx = s_tester.tls_ctx,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
        .system_clock_fn = mock_aws_get_system_time,
    };

    mock_aws_set_system_time(0);
    s_tester.mock_body = aws_byte_buf_from_c_str(success_creds_doc);
    s_tester.mock_response_code = 200;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(s_tester.credentials));
    ASSERT_TRUE(aws_credentials_get_expiration_timepoint_seconds(s_tester.credentials) == 900);

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
    ASSERT_SUCCESS(s_aws_sts_tester_cleanup());

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(credentials_provider_sts_direct_config_succeeds, s_credentials_provider_sts_direct_config_succeeds_fn)

static int s_credentials_provider_sts_direct_config_succeeds_after_retry_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    s_aws_sts_tester_init(allocator);

    struct aws_credentials_provider_static_options static_options = {
        .access_key_id = s_access_key_cur,
        .secret_access_key = s_secret_key_cur,
        .session_token = s_session_token_cur,
    };
    struct aws_credentials_provider *static_provider = aws_credentials_provider_new_static(allocator, &static_options);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = s_tester.bootstrap,
        .tls_ctx = s_tester.tls_ctx,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
        .system_clock_fn = mock_aws_get_system_time,
    };

    mock_aws_set_system_time(0);
    s_tester.mock_body = aws_byte_buf_from_c_str(success_creds_doc);
    s_tester.mock_response_code = 200;
    s_tester.mock_failure_code = 429;
    s_tester.fail_operations = 2;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(s_tester.credentials));
    ASSERT_TRUE(aws_credentials_get_expiration_timepoint_seconds(s_tester.credentials) == 900);

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
    ASSERT_SUCCESS(s_aws_sts_tester_cleanup());

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_direct_config_succeeds_after_retry,
    s_credentials_provider_sts_direct_config_succeeds_after_retry_fn)

static const char *malformed_creds_doc = "<AssumeRoleResponse xmlns=\"who cares\">\n"
                                         "     <AssumeRoleResult>\n"
                                         "         <AssumeRoleUser>\n"
                                         "             <Credentials>\n"
                                         "                 <AccessKeyId>accessKeyIdResp</AccessKeyId>\n"
                                         "                ";

static int s_credentials_provider_sts_direct_config_invalid_doc_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_sts_tester_init(allocator);

    struct aws_credentials_provider_static_options static_options = {
        .access_key_id = s_access_key_cur,
        .secret_access_key = s_secret_key_cur,
        .session_token = s_session_token_cur,
    };
    struct aws_credentials_provider *static_provider = aws_credentials_provider_new_static(allocator, &static_options);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = s_tester.bootstrap,
        .tls_ctx = s_tester.tls_ctx,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
        .system_clock_fn = mock_aws_get_system_time,
    };

    mock_aws_set_system_time(0);
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
    ASSERT_SUCCESS(s_aws_sts_tester_cleanup());

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_direct_config_invalid_doc,
    s_credentials_provider_sts_direct_config_invalid_doc_fn)

static int s_credentials_provider_sts_direct_config_connection_failed_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_sts_tester_init(allocator);

    struct aws_credentials_provider_static_options static_options = {
        .access_key_id = s_access_key_cur,
        .secret_access_key = s_secret_key_cur,
        .session_token = s_session_token_cur,
    };
    struct aws_credentials_provider *static_provider = aws_credentials_provider_new_static(allocator, &static_options);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = s_tester.bootstrap,
        .tls_ctx = s_tester.tls_ctx,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
        .system_clock_fn = mock_aws_get_system_time,
    };

    mock_aws_set_system_time(0);

    s_tester.fail_connection = true;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_NULL(s_tester.credentials);

    aws_credentials_provider_release(sts_provider);
    aws_credentials_provider_release(static_provider);
    ASSERT_SUCCESS(s_aws_sts_tester_cleanup());

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_direct_config_connection_failed,
    s_credentials_provider_sts_direct_config_connection_failed_fn)

static int s_credentials_provider_sts_direct_config_service_fails_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_sts_tester_init(allocator);

    struct aws_credentials_provider_static_options static_options = {
        .access_key_id = s_access_key_cur,
        .secret_access_key = s_secret_key_cur,
        .session_token = s_session_token_cur,
    };
    struct aws_credentials_provider *static_provider = aws_credentials_provider_new_static(allocator, &static_options);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = s_tester.bootstrap,
        .tls_ctx = s_tester.tls_ctx,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
        .system_clock_fn = mock_aws_get_system_time,
    };

    mock_aws_set_system_time(0);
    s_tester.mock_response_code = 529;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_NULL(s_tester.credentials);

    aws_credentials_provider_release(sts_provider);
    aws_credentials_provider_release(static_provider);
    ASSERT_SUCCESS(s_aws_sts_tester_cleanup());

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

static int s_credentials_provider_sts_from_profile_config_succeeds(
    struct aws_allocator *allocator,
    void *ctx,
    bool manual_tls) {
    (void)ctx;

    aws_unset_environment_value(s_default_profile_env_variable_name);
    aws_unset_environment_value(s_default_config_path_env_variable_name);
    aws_unset_environment_value(s_default_credentials_path_env_variable_name);

    s_aws_sts_tester_init(allocator);

    struct aws_string *config_contents = aws_string_new_from_c_str(allocator, s_soure_profile_config_file);

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_string *creds_file_str = aws_create_process_unique_file_name(allocator);

    ASSERT_SUCCESS(aws_create_profile_file(creds_file_str, config_contents));
    aws_string_destroy(config_contents);

    struct aws_credentials_provider_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
        .credentials_file_name_override = aws_byte_cursor_from_string(creds_file_str),
        .profile_name_override = aws_byte_cursor_from_c_str("roletest"),
        .bootstrap = s_tester.bootstrap,
        /* tls_ctx is optional, test it both ways */
        .tls_ctx = manual_tls ? s_tester.tls_ctx : NULL,
        .function_table = &s_mock_function_table,
    };

    s_tester.mock_body = aws_byte_buf_from_c_str(success_creds_doc);
    s_tester.mock_response_code = 200;

    struct aws_credentials_provider *provider = aws_credentials_provider_new_profile(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_string_destroy(config_file_str);
    aws_string_destroy(creds_file_str);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(s_tester.credentials));

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

    aws_credentials_provider_release(provider);

    ASSERT_SUCCESS(s_aws_sts_tester_cleanup());

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_sts_from_profile_config_succeeds_fn(struct aws_allocator *allocator, void *ctx) {
    return s_credentials_provider_sts_from_profile_config_succeeds(allocator, ctx, false /*manual_tls*/);
}

AWS_TEST_CASE(
    credentials_provider_sts_from_profile_config_succeeds,
    s_credentials_provider_sts_from_profile_config_succeeds_fn)

static int credentials_provider_sts_from_profile_config_manual_tls_succeeds_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    return s_credentials_provider_sts_from_profile_config_succeeds(allocator, ctx, true /*manual_tls*/);
}

AWS_TEST_CASE(
    credentials_provider_sts_from_profile_config_manual_tls_succeeds,
    credentials_provider_sts_from_profile_config_manual_tls_succeeds_fn)

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

    aws_unset_environment_value(s_default_profile_env_variable_name);
    aws_unset_environment_value(s_default_config_path_env_variable_name);
    aws_unset_environment_value(s_default_credentials_path_env_variable_name);

    aws_set_environment_value(s_access_key_id_env_var, s_env_access_key_val);
    aws_set_environment_value(s_secret_access_key_env_var, s_env_secret_access_key_val);

    s_aws_sts_tester_init(allocator);

    struct aws_string *config_contents = aws_string_new_from_c_str(allocator, s_env_source_config_file);

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_string *creds_file_str = aws_create_process_unique_file_name(allocator);

    ASSERT_SUCCESS(aws_create_profile_file(creds_file_str, config_contents));
    aws_string_destroy(config_contents);

    struct aws_credentials_provider_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
        .credentials_file_name_override = aws_byte_cursor_from_string(creds_file_str),
        .profile_name_override = aws_byte_cursor_from_c_str("roletest"),
        .bootstrap = s_tester.bootstrap,
        .tls_ctx = s_tester.tls_ctx,
        .function_table = &s_mock_function_table,
    };

    s_tester.mock_body = aws_byte_buf_from_c_str(success_creds_doc);
    s_tester.mock_response_code = 200;

    struct aws_credentials_provider *provider = aws_credentials_provider_new_profile(allocator, &options);
    ASSERT_NOT_NULL(provider);

    aws_string_destroy(creds_file_str);
    aws_string_destroy(config_file_str);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(s_tester.credentials));

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

    aws_credentials_provider_release(provider);

    ASSERT_SUCCESS(s_aws_sts_tester_cleanup());

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    credentials_provider_sts_from_profile_config_environment_succeeds,
    s_credentials_provider_sts_from_profile_config_environment_succeeds_fn)

#define HIGH_RES_BASE_TIME_NS 101000000000ULL

/*
 * In this test, we set up a cached provider with a longer and out-of-sync refresh period than the sts
 * provider that it wraps.  We verify that the cached provider factors in the shorter-lived sts credentials
 * properly and refreshes when the credentials expire and not when the cache would expire.
 */
static int s_credentials_provider_sts_cache_expiration_conflict(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_sts_tester_init(allocator);

    struct aws_credentials_provider_static_options static_options = {
        .access_key_id = s_access_key_cur,
        .secret_access_key = s_secret_key_cur,
        .session_token = s_session_token_cur,
    };
    struct aws_credentials_provider *static_provider = aws_credentials_provider_new_static(allocator, &static_options);

    struct aws_credentials_provider_sts_options options = {
        .creds_provider = static_provider,
        .bootstrap = s_tester.bootstrap,
        .tls_ctx = s_tester.tls_ctx,
        .role_arn = s_role_arn_cur,
        .session_name = s_session_name_cur,
        .duration_seconds = 0,
        .function_table = &s_mock_function_table,
        .system_clock_fn = mock_aws_get_system_time,
    };

    /* make sure high res time and system time are sufficiently diverged that a mistake in the
     * respective calculations would fail the test */
    mock_aws_set_system_time(0);
    mock_aws_set_high_res_time(HIGH_RES_BASE_TIME_NS);

    s_tester.mock_body = aws_byte_buf_from_c_str(success_creds_doc);
    s_tester.mock_response_code = 200;

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    struct aws_credentials_provider_cached_options cached_options = {
        .system_clock_fn = mock_aws_get_system_time,
        .high_res_clock_fn = mock_aws_get_high_res_time,
        .refresh_time_in_milliseconds = 1200 * 1000,
        .source = sts_provider,
    };
    struct aws_credentials_provider *cached_provider = aws_credentials_provider_new_cached(allocator, &cached_options);

    aws_credentials_provider_get_credentials(cached_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_SUCCESS(s_verify_credentials(s_tester.credentials));
    ASSERT_TRUE(aws_credentials_get_expiration_timepoint_seconds(s_tester.credentials) == 900);

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

    /* advance each time to a little before expiration, verify we get creds with the same expiration */
    uint64_t eight_hundred_seconds_in_ns = aws_timestamp_convert(800, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    mock_aws_set_system_time(eight_hundred_seconds_in_ns);
    mock_aws_set_high_res_time(HIGH_RES_BASE_TIME_NS + eight_hundred_seconds_in_ns);

    s_cleanup_creds_callback_data();

    aws_credentials_provider_get_credentials(cached_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();
    ASSERT_TRUE(aws_credentials_get_expiration_timepoint_seconds(s_tester.credentials) == 900);

    /* advance each time to after expiration but before cached provider timeout, verify we get new creds */
    uint64_t nine_hundred_and_one_seconds_in_ns =
        aws_timestamp_convert(901, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    mock_aws_set_system_time(nine_hundred_and_one_seconds_in_ns);
    mock_aws_set_high_res_time(HIGH_RES_BASE_TIME_NS + nine_hundred_and_one_seconds_in_ns);

    s_cleanup_creds_callback_data();

    aws_credentials_provider_get_credentials(cached_provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();
    ASSERT_TRUE(aws_credentials_get_expiration_timepoint_seconds(s_tester.credentials) == 1801);

    aws_credentials_provider_release(cached_provider);
    aws_credentials_provider_release(sts_provider);
    aws_credentials_provider_release(static_provider);

    ASSERT_SUCCESS(s_aws_sts_tester_cleanup());

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(credentials_provider_sts_cache_expiration_conflict, s_credentials_provider_sts_cache_expiration_conflict)
