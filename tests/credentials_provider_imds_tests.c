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
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>

struct aws_mock_imds_tester {
    struct aws_byte_buf first_request_uri;
    struct aws_byte_buf second_request_uri;

    struct aws_array_list first_response_data_callbacks;
    struct aws_array_list second_response_data_callbacks;
    int current_request;
    bool is_connection_acquire_successful;
    bool is_first_request_successful;
    bool is_second_request_successful;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_credentials *credentials;
    bool has_received_credentials_callback;
    bool has_received_shutdown_callback;
};

static struct aws_mock_imds_tester s_tester;

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

static struct aws_http_connection_manager *s_aws_http_connection_manager_new_mock(
    struct aws_allocator *allocator,
    struct aws_http_connection_manager_options *options) {

    (void)allocator;
    (void)options;

    return (struct aws_http_connection_manager *)1;
}

static void s_aws_http_connection_manager_release_mock(struct aws_http_connection_manager *manager) {
    (void)manager;

    s_on_shutdown_complete(NULL);
}

static void s_aws_http_connection_manager_acquire_connection_mock(
    struct aws_http_connection_manager *manager,
    aws_http_connection_manager_on_connection_setup_fn *callback,
    void *user_data) {

    (void)manager;
    (void)callback;
    (void)user_data;

    if (s_tester.is_connection_acquire_successful) {
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
    struct aws_array_list *data_callbacks,
    bool is_request_successful) {

    size_t data_callback_count = aws_array_list_length(data_callbacks);

    struct aws_http_header headers[1];
    AWS_ZERO_ARRAY(headers);

    headers[0].name = aws_byte_cursor_from_c_str("some-header");
    headers[0].value = aws_byte_cursor_from_c_str("value");

    options->on_response_headers(
        (struct aws_http_stream *)1, AWS_HTTP_HEADER_BLOCK_MAIN, headers, 1, options->user_data);

    if (options->on_response_header_block_done) {
        options->on_response_header_block_done(
            (struct aws_http_stream *)1, data_callback_count > 0, options->user_data);
    }

    for (size_t i = 0; i < data_callback_count; ++i) {
        struct aws_byte_cursor data_callback_cursor;
        if (aws_array_list_get_at(data_callbacks, &data_callback_cursor, i)) {
            continue;
        }

        options->on_response_body((struct aws_http_stream *)1, &data_callback_cursor, options->user_data);
    }

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

    if (s_tester.current_request == 0) {
        ++s_tester.current_request;
        aws_byte_buf_append_dynamic(&s_tester.first_request_uri, &path);
        s_invoke_mock_request_callbacks(
            options, &s_tester.first_response_data_callbacks, s_tester.is_first_request_successful);
    } else {
        aws_byte_buf_append_dynamic(&s_tester.second_request_uri, &path);
        s_invoke_mock_request_callbacks(
            options, &s_tester.second_response_data_callbacks, s_tester.is_second_request_successful);
    }

    return (struct aws_http_stream *)1;
}

static int s_aws_http_stream_get_incoming_response_status_mock(
    const struct aws_http_stream *stream,
    int *out_status_code) {
    (void)stream;

    *out_status_code = 200;

    return AWS_OP_SUCCESS;
}

static void s_aws_http_stream_release_mock(struct aws_http_stream *stream) {
    (void)stream;
}

static void s_aws_http_connection_close_mock(struct aws_http_connection *connection) {
    (void)connection;
}

static struct aws_credentials_provider_system_vtable s_mock_function_table = {
    .aws_http_connection_manager_new = s_aws_http_connection_manager_new_mock,
    .aws_http_connection_manager_release = s_aws_http_connection_manager_release_mock,
    .aws_http_connection_manager_acquire_connection = s_aws_http_connection_manager_acquire_connection_mock,
    .aws_http_connection_manager_release_connection = s_aws_http_connection_manager_release_connection_mock,
    .aws_http_connection_make_request = s_aws_http_connection_make_request_mock,
    .aws_http_stream_get_incoming_response_status = s_aws_http_stream_get_incoming_response_status_mock,
    .aws_http_stream_release = s_aws_http_stream_release_mock,
    .aws_http_connection_close = s_aws_http_connection_close_mock};

static int s_aws_imds_tester_init(struct aws_allocator *allocator) {
    if (aws_array_list_init_dynamic(
            &s_tester.first_response_data_callbacks, allocator, 10, sizeof(struct aws_byte_cursor)) ||
        aws_array_list_init_dynamic(
            &s_tester.second_response_data_callbacks, allocator, 10, sizeof(struct aws_byte_cursor))) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init(&s_tester.first_request_uri, allocator, 100) ||
        aws_byte_buf_init(&s_tester.second_request_uri, allocator, 100)) {
        return AWS_OP_ERR;
    }

    if (aws_mutex_init(&s_tester.lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&s_tester.signal)) {
        return AWS_OP_ERR;
    }

    s_tester.current_request = 0;

    /* default to everything successful */
    s_tester.is_connection_acquire_successful = true;
    s_tester.is_first_request_successful = true;
    s_tester.is_second_request_successful = true;

    return AWS_OP_SUCCESS;
}

static void s_aws_imds_tester_cleanup(void) {
    aws_array_list_clean_up(&s_tester.first_response_data_callbacks);
    aws_array_list_clean_up(&s_tester.second_response_data_callbacks);
    aws_byte_buf_clean_up(&s_tester.first_request_uri);
    aws_byte_buf_clean_up(&s_tester.second_request_uri);
    aws_condition_variable_clean_up(&s_tester.signal);
    aws_mutex_clean_up(&s_tester.lock);
    aws_credentials_destroy(s_tester.credentials);
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

static int s_credentials_provider_imds_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = NULL,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);
    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_new_destroy, s_credentials_provider_imds_new_destroy);

static int s_credentials_provider_imds_connect_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);
    s_tester.is_connection_acquire_successful = false;

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = NULL,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_connect_failure, s_credentials_provider_imds_connect_failure);

AWS_STATIC_STRING_FROM_LITERAL(s_expected_imds_base_uri, "/latest/meta-data/iam/security-credentials/");
AWS_STATIC_STRING_FROM_LITERAL(s_expected_imds_role_uri, "/latest/meta-data/iam/security-credentials/test-role");
AWS_STATIC_STRING_FROM_LITERAL(s_test_role_response, "test-role");

static int s_credentials_provider_imds_first_request_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);
    s_tester.is_first_request_successful = false;

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = NULL,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.first_request_uri.buffer,
        s_tester.first_request_uri.len,
        s_expected_imds_base_uri->bytes,
        s_expected_imds_base_uri->len);
    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_first_request_failure, s_credentials_provider_imds_first_request_failure);

static int s_credentials_provider_imds_second_request_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);
    s_tester.is_second_request_successful = false;

    struct aws_byte_cursor test_role_cursor = aws_byte_cursor_from_string(s_test_role_response);
    aws_array_list_push_back(&s_tester.first_response_data_callbacks, &test_role_cursor);

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = NULL,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.first_request_uri.buffer,
        s_tester.first_request_uri.len,
        s_expected_imds_base_uri->bytes,
        s_expected_imds_base_uri->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.second_request_uri.buffer,
        s_tester.second_request_uri.len,
        s_expected_imds_role_uri->bytes,
        s_expected_imds_role_uri->len);
    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_second_request_failure, s_credentials_provider_imds_second_request_failure);

AWS_STATIC_STRING_FROM_LITERAL(s_bad_document_response, "{\"NotTheExpectedDocumentFormat\":\"Error\"}");

static int s_credentials_provider_imds_bad_document_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);

    struct aws_byte_cursor test_role_cursor = aws_byte_cursor_from_string(s_test_role_response);
    aws_array_list_push_back(&s_tester.first_response_data_callbacks, &test_role_cursor);

    struct aws_byte_cursor bad_document_cursor = aws_byte_cursor_from_string(s_bad_document_response);
    aws_array_list_push_back(&s_tester.second_response_data_callbacks, &bad_document_cursor);

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = NULL,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.first_request_uri.buffer,
        s_tester.first_request_uri.len,
        s_expected_imds_base_uri->bytes,
        s_expected_imds_base_uri->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.second_request_uri.buffer,
        s_tester.second_request_uri.len,
        s_expected_imds_role_uri->bytes,
        s_expected_imds_role_uri->len);
    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_bad_document_failure, s_credentials_provider_imds_bad_document_failure);

AWS_STATIC_STRING_FROM_LITERAL(
    s_good_response,
    "{\"AccessKeyId\":\"SuccessfulAccessKey\", \n  \"SecretAccessKey\":\"SuccessfulSecret\", \n  "
    "\"Token\":\"TokenSuccess\"\n}");
AWS_STATIC_STRING_FROM_LITERAL(s_good_access_key_id, "SuccessfulAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_good_secret_access_key, "SuccessfulSecret");
AWS_STATIC_STRING_FROM_LITERAL(s_good_session_token, "TokenSuccess");

static int s_credentials_provider_imds_basic_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);

    struct aws_byte_cursor test_role_cursor = aws_byte_cursor_from_string(s_test_role_response);
    aws_array_list_push_back(&s_tester.first_response_data_callbacks, &test_role_cursor);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.second_response_data_callbacks, &good_response_cursor);

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = NULL,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.first_request_uri.buffer,
        s_tester.first_request_uri.len,
        s_expected_imds_base_uri->bytes,
        s_expected_imds_base_uri->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.second_request_uri.buffer,
        s_tester.second_request_uri.len,
        s_expected_imds_role_uri->bytes,
        s_expected_imds_role_uri->len);
    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials != NULL);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->access_key_id->bytes,
        s_tester.credentials->access_key_id->len,
        s_good_access_key_id->bytes,
        s_good_access_key_id->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->secret_access_key->bytes,
        s_tester.credentials->secret_access_key->len,
        s_good_secret_access_key->bytes,
        s_good_secret_access_key->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->session_token->bytes,
        s_tester.credentials->session_token->len,
        s_good_session_token->bytes,
        s_good_session_token->len);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_basic_success, s_credentials_provider_imds_basic_success);

AWS_STATIC_STRING_FROM_LITERAL(s_test_role_response_first_half, "test-");
AWS_STATIC_STRING_FROM_LITERAL(s_test_role_response_second_half, "role");

static int s_credentials_provider_imds_success_multi_part_role_name(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);

    struct aws_byte_cursor test_role_cursor1 = aws_byte_cursor_from_string(s_test_role_response_first_half);
    struct aws_byte_cursor test_role_cursor2 = aws_byte_cursor_from_string(s_test_role_response_second_half);
    aws_array_list_push_back(&s_tester.first_response_data_callbacks, &test_role_cursor1);
    aws_array_list_push_back(&s_tester.first_response_data_callbacks, &test_role_cursor2);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.second_response_data_callbacks, &good_response_cursor);

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = NULL,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.first_request_uri.buffer,
        s_tester.first_request_uri.len,
        s_expected_imds_base_uri->bytes,
        s_expected_imds_base_uri->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.second_request_uri.buffer,
        s_tester.second_request_uri.len,
        s_expected_imds_role_uri->bytes,
        s_expected_imds_role_uri->len);
    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials != NULL);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->access_key_id->bytes,
        s_tester.credentials->access_key_id->len,
        s_good_access_key_id->bytes,
        s_good_access_key_id->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->secret_access_key->bytes,
        s_tester.credentials->secret_access_key->len,
        s_good_secret_access_key->bytes,
        s_good_secret_access_key->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->session_token->bytes,
        s_tester.credentials->session_token->len,
        s_good_session_token->bytes,
        s_good_session_token->len);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(
    credentials_provider_imds_success_multi_part_role_name,
    s_credentials_provider_imds_success_multi_part_role_name);

AWS_STATIC_STRING_FROM_LITERAL(s_good_response_first_part, "{\"AccessKeyId\":\"SuccessfulAccessKey\", \n  \"Secret");
AWS_STATIC_STRING_FROM_LITERAL(s_good_response_second_part, "AccessKey\":\"SuccessfulSecr");
AWS_STATIC_STRING_FROM_LITERAL(s_good_response_third_part, "et\", \n  \"Token\":\"TokenSuccess\"\n}");

static int s_credentials_provider_imds_success_multi_part_doc(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);

    struct aws_byte_cursor test_role_cursor = aws_byte_cursor_from_string(s_test_role_response);
    aws_array_list_push_back(&s_tester.first_response_data_callbacks, &test_role_cursor);

    struct aws_byte_cursor good_response_cursor1 = aws_byte_cursor_from_string(s_good_response_first_part);
    struct aws_byte_cursor good_response_cursor2 = aws_byte_cursor_from_string(s_good_response_second_part);
    struct aws_byte_cursor good_response_cursor3 = aws_byte_cursor_from_string(s_good_response_third_part);
    aws_array_list_push_back(&s_tester.second_response_data_callbacks, &good_response_cursor1);
    aws_array_list_push_back(&s_tester.second_response_data_callbacks, &good_response_cursor2);
    aws_array_list_push_back(&s_tester.second_response_data_callbacks, &good_response_cursor3);

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = NULL,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.first_request_uri.buffer,
        s_tester.first_request_uri.len,
        s_expected_imds_base_uri->bytes,
        s_expected_imds_base_uri->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.second_request_uri.buffer,
        s_tester.second_request_uri.len,
        s_expected_imds_role_uri->bytes,
        s_expected_imds_role_uri->len);
    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials != NULL);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->access_key_id->bytes,
        s_tester.credentials->access_key_id->len,
        s_good_access_key_id->bytes,
        s_good_access_key_id->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->secret_access_key->bytes,
        s_tester.credentials->secret_access_key->len,
        s_good_secret_access_key->bytes,
        s_good_secret_access_key->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.credentials->session_token->bytes,
        s_tester.credentials->session_token->len,
        s_good_session_token->bytes,
        s_good_session_token->len);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_success_multi_part_doc, s_credentials_provider_imds_success_multi_part_doc);

static int s_credentials_provider_imds_real_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    struct aws_logger logger;
    ASSERT_SUCCESS(aws_logger_init_standard(&logger, allocator, &logger_options));
    aws_logger_set(&logger);

    s_aws_imds_tester_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 1);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 8, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = bootstrap,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    s_aws_imds_tester_cleanup();

    aws_auth_library_clean_up();
    aws_http_library_clean_up();

    aws_logger_set(NULL);
    aws_logger_clean_up(&logger);

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_real_new_destroy, s_credentials_provider_imds_real_new_destroy);

static int s_credentials_provider_imds_real_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);

    struct aws_logger_standard_options logger_options = {
        .level = AWS_LOG_LEVEL_TRACE,
        .file = stderr,
    };

    struct aws_logger logger;
    ASSERT_SUCCESS(aws_logger_init_standard(&logger, allocator, &logger_options));
    aws_logger_set(&logger);

    s_aws_imds_tester_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 1);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 8, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_credentials_provider_imds_options options = {
        .bootstrap = bootstrap,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    ASSERT_TRUE(s_tester.credentials != NULL);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_imds_tester_cleanup();

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_clean_up(&resolver);
    aws_event_loop_group_clean_up(&el_group);

    aws_auth_library_clean_up();
    aws_http_library_clean_up();

    aws_logger_set(NULL);
    aws_logger_clean_up(&logger);

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_real_success, s_credentials_provider_imds_real_success);
