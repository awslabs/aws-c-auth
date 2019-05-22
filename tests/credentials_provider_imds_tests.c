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
#include <aws/http/request_response.h>

struct aws_imds_tester {
    struct aws_array_list first_response_data_callbacks;
    struct aws_array_list second_response_data_callbacks;
    int current_request;
    bool is_connection_acquire_successful;
    bool is_first_request_successful;
    bool is_second_request_successful;
};

static struct aws_imds_tester s_tester;

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
    const struct aws_http_request_options *options,
    struct aws_array_list *data_callbacks,
    bool is_request_successful) {

    size_t data_callback_count = aws_array_list_length(data_callbacks);

    struct aws_http_header headers[1];
    AWS_ZERO_ARRAY(headers);

    headers[0].name = aws_byte_cursor_from_c_str("some-header");
    headers[0].value = aws_byte_cursor_from_c_str("value");

    options->on_response_headers((struct aws_http_stream *)1, headers, 1, options->user_data);

    options->on_response_header_block_done((struct aws_http_stream *)1, data_callback_count > 0, options->user_data);

    for (size_t i = 0; i < data_callback_count; ++i) {
        struct aws_byte_cursor data_callback_cursor;
        if (aws_array_list_get_at(data_callbacks, &data_callback_cursor, i)) {
            continue;
        }

        size_t window_size = 0;
        options->on_response_body((struct aws_http_stream *)1, &data_callback_cursor, &window_size, options->user_data);
    }

    options->on_complete(
        (struct aws_http_stream *)1,
        is_request_successful ? AWS_ERROR_SUCCESS : AWS_ERROR_HTTP_UNKNOWN,
        options->user_data);
}

static struct aws_http_stream *s_aws_http_stream_new_client_request_mock(
    const struct aws_http_request_options *options) {
    (void)options;

    if (s_tester.current_request == 0) {
        ++s_tester.current_request;
        s_invoke_mock_request_callbacks(
            options, &s_tester.first_response_data_callbacks, s_tester.is_first_request_successful);
    } else {
        s_invoke_mock_request_callbacks(
            options, &s_tester.second_response_data_callbacks, s_tester.is_second_request_successful);
    }

    return (struct aws_http_stream *)1;
}

static void s_aws_http_stream_release_mock(struct aws_http_stream *stream) {
    (void)stream;
}

static void s_aws_http_connection_close_mock(struct aws_http_connection *connection) {
    (void)connection;
}

static struct aws_credentials_provider_imds_function_table s_mock_function_table = {
    .aws_http_connection_manager_new = s_aws_http_connection_manager_new_mock,
    .aws_http_connection_manager_release = s_aws_http_connection_manager_release_mock,
    .aws_http_connection_manager_acquire_connection = s_aws_http_connection_manager_acquire_connection_mock,
    .aws_http_connection_manager_release_connection = s_aws_http_connection_manager_release_connection_mock,
    .aws_http_stream_new_client_request = s_aws_http_stream_new_client_request_mock,
    .aws_http_stream_release = s_aws_http_stream_release_mock,
    .aws_http_connection_close = s_aws_http_connection_close_mock};

static int s_aws_imds_tester_init(struct aws_allocator *allocator) {
    if (aws_array_list_init_dynamic(
            &s_tester.first_response_data_callbacks, allocator, 10, sizeof(struct aws_byte_cursor)) ||
        aws_array_list_init_dynamic(
            &s_tester.second_response_data_callbacks, allocator, 10, sizeof(struct aws_byte_cursor))) {
        return AWS_OP_ERR;
    }

    s_tester.current_request = 0;

    return AWS_OP_SUCCESS;
}

static void s_aws_imds_tester_cleanup(void) {
    aws_array_list_clean_up(&s_tester.first_response_data_callbacks);
    aws_array_list_clean_up(&s_tester.second_response_data_callbacks);
}

static int s_credentials_provider_imds_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_imds_tester_init(allocator);

    struct aws_credentials_provider_imds_options options = {.bootstrap = NULL,
                                                            .function_table = &s_mock_function_table};

    struct aws_credentials_provider *provider = aws_credentials_provider_new_imds(allocator, &options);
    aws_credentials_provider_release(provider);

    s_aws_imds_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_imds_new_destroy, s_credentials_provider_imds_new_destroy);