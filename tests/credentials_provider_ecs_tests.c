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
#include <aws/common/thread.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>

struct aws_mock_ecs_tester {
    struct aws_byte_buf request_uri;
    struct aws_byte_buf request_authorization_header;

    struct aws_array_list response_data_callbacks;
    bool is_connection_acquire_successful;
    bool is_request_successful;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_credentials *credentials;
    bool has_received_credentials_callback;
    bool has_received_shutdown_callback;
    uint32_t selected_port;

    int error_code;

    struct aws_event_loop_group *el_group;
    struct aws_host_resolver *host_resolver;
    struct aws_client_bootstrap *bootstrap;
};

static struct aws_mock_ecs_tester s_tester;

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
    const struct aws_http_connection_manager_options *options) {

    (void)allocator;
    (void)options;

    aws_mutex_lock(&s_tester.lock);
    s_tester.selected_port = options->port;
    aws_mutex_unlock(&s_tester.lock);

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

    aws_byte_buf_append_dynamic(&s_tester.request_uri, &path);
    struct aws_byte_cursor authorization_header_value;
    AWS_ZERO_STRUCT(authorization_header_value);
    aws_http_headers_get(
        aws_http_message_get_headers(options->request),
        aws_byte_cursor_from_c_str("Authorization"),
        &authorization_header_value);

    aws_byte_buf_append_dynamic(&s_tester.request_authorization_header, &authorization_header_value);

    s_invoke_mock_request_callbacks(options, &s_tester.response_data_callbacks, s_tester.is_request_successful);

    return (struct aws_http_stream *)1;
}

static int s_aws_http_stream_activate_mock(struct aws_http_stream *stream) {
    (void)stream;
    return AWS_OP_SUCCESS;
}

static int s_aws_http_stream_get_incoming_response_status_mock(
    const struct aws_http_stream *stream,
    int *out_status_code) {
    (void)stream;

    *out_status_code = AWS_HTTP_STATUS_CODE_200_OK;

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

static int s_aws_ecs_tester_init(struct aws_allocator *allocator) {
    if (aws_array_list_init_dynamic(&s_tester.response_data_callbacks, allocator, 10, sizeof(struct aws_byte_cursor))) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init(&s_tester.request_uri, allocator, 100)) {
        return AWS_OP_ERR;
    }

    aws_byte_buf_init(&s_tester.request_authorization_header, allocator, 20);

    if (aws_mutex_init(&s_tester.lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&s_tester.signal)) {
        return AWS_OP_ERR;
    }

    aws_auth_library_init(allocator);

    /* default to everything successful */
    s_tester.is_connection_acquire_successful = true;
    s_tester.is_request_successful = true;

    s_tester.el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = s_tester.el_group,
        .max_entries = 8,
    };
    s_tester.host_resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = s_tester.el_group,
        .host_resolver = s_tester.host_resolver,
    };
    s_tester.bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    return AWS_OP_SUCCESS;
}

static void s_aws_ecs_tester_cleanup(void) {
    aws_array_list_clean_up(&s_tester.response_data_callbacks);
    aws_byte_buf_clean_up(&s_tester.request_uri);
    aws_byte_buf_clean_up(&s_tester.request_authorization_header);
    aws_condition_variable_clean_up(&s_tester.signal);
    aws_mutex_clean_up(&s_tester.lock);
    aws_credentials_release(s_tester.credentials);
    aws_client_bootstrap_release(s_tester.bootstrap);
    aws_host_resolver_release(s_tester.host_resolver);
    aws_event_loop_group_release(s_tester.el_group);
    aws_auth_library_clean_up();
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

static int s_credentials_provider_ecs_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = aws_byte_cursor_from_c_str("test-token-1234-abcd"),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);
    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_ecs_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_new_destroy, s_credentials_provider_ecs_new_destroy);

static int s_credentials_provider_ecs_connect_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);
    s_tester.is_connection_acquire_successful = false;

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = aws_byte_cursor_from_c_str("test-token-1234-abcd"),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    aws_mutex_lock(&s_tester.lock);
    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);
    ASSERT_UINT_EQUALS(80, s_tester.selected_port);
    aws_mutex_unlock(&s_tester.lock);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_ecs_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_connect_failure, s_credentials_provider_ecs_connect_failure);

AWS_STATIC_STRING_FROM_LITERAL(s_expected_ecs_relative_uri, "/path/to/resource/?a=b&c=d");

static int s_credentials_provider_ecs_request_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);
    s_tester.is_request_successful = false;

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = aws_byte_cursor_from_c_str("test-token-1234-abcd"),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    aws_mutex_lock(&s_tester.lock);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.request_uri.buffer,
        s_tester.request_uri.len,
        s_expected_ecs_relative_uri->bytes,
        s_expected_ecs_relative_uri->len);
    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);
    ASSERT_UINT_EQUALS(80, s_tester.selected_port);
    aws_mutex_unlock(&s_tester.lock);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_ecs_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_request_failure, s_credentials_provider_ecs_request_failure);

AWS_STATIC_STRING_FROM_LITERAL(s_bad_document_response, "{\"NotTheExpectedDocumentFormat\":\"Error\"}");

static int s_credentials_provider_ecs_bad_document_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_byte_cursor bad_document_cursor = aws_byte_cursor_from_string(s_bad_document_response);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &bad_document_cursor);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = aws_byte_cursor_from_c_str("test-token-1234-abcd"),
        .port = 555,
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    aws_mutex_lock(&s_tester.lock);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.request_uri.buffer,
        s_tester.request_uri.len,
        s_expected_ecs_relative_uri->bytes,
        s_expected_ecs_relative_uri->len);

    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials == NULL);
    ASSERT_UINT_EQUALS(555, s_tester.selected_port);
    aws_mutex_unlock(&s_tester.lock);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    s_aws_ecs_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_bad_document_failure, s_credentials_provider_ecs_bad_document_failure);

AWS_STATIC_STRING_FROM_LITERAL(
    s_good_response,
    "{\"AccessKeyId\":\"SuccessfulAccessKey\", \n  \"SecretAccessKey\":\"SuccessfulSecret\", \n  "
    "\"Token\":\"TokenSuccess\", \n \"Expiration\":\"2020-02-25T06:03:31Z\"}");
AWS_STATIC_STRING_FROM_LITERAL(s_good_access_key_id, "SuccessfulAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_good_secret_access_key, "SuccessfulSecret");
AWS_STATIC_STRING_FROM_LITERAL(s_good_session_token, "TokenSuccess");
AWS_STATIC_STRING_FROM_LITERAL(s_good_response_expiration, "2020-02-25T06:03:31Z");

static int s_do_ecs_success_test(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_ecs_options *options) {
    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    aws_mutex_lock(&s_tester.lock);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.request_uri.buffer,
        s_tester.request_uri.len,
        s_expected_ecs_relative_uri->bytes,
        s_expected_ecs_relative_uri->len);

    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials != NULL);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_access_key_id(s_tester.credentials), s_good_access_key_id);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(
        aws_credentials_get_secret_access_key(s_tester.credentials), s_good_secret_access_key);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_session_token(s_tester.credentials), s_good_session_token);

    struct aws_date_time expiration;
    struct aws_byte_cursor date_cursor = aws_byte_cursor_from_string(s_good_response_expiration);
    aws_date_time_init_from_str_cursor(&expiration, &date_cursor, AWS_DATE_FORMAT_ISO_8601);
    ASSERT_TRUE(
        aws_credentials_get_expiration_timepoint_seconds(s_tester.credentials) == (uint64_t)expiration.timestamp);
    aws_mutex_unlock(&s_tester.lock);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);

    return AWS_OP_SUCCESS;
}

static int s_credentials_provider_ecs_basic_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = aws_byte_cursor_from_c_str("test-token-1234-abcd"),
    };

    ASSERT_SUCCESS(s_do_ecs_success_test(allocator, &options));

    s_aws_ecs_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_basic_success, s_credentials_provider_ecs_basic_success);

static int s_credentials_provider_ecs_mocked_server_basic_ipv4_invalid(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("google.com"),
        .port = 80,
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);
    s_aws_wait_for_credentials_result();
    ASSERT_NULL(s_tester.credentials);
    ASSERT_TRUE(s_tester.error_code == AWS_AUTH_CREDENTIALS_PROVIDER_ECS_INVALID_HOST);

    aws_credentials_provider_release(provider);
    s_aws_wait_for_provider_shutdown_callback();

    s_aws_ecs_tester_cleanup();

    aws_auth_library_clean_up();

    return 0;
}

AWS_TEST_CASE(
    credentials_provider_ecs_mocked_server_basic_ipv4_invalid,
    s_credentials_provider_ecs_mocked_server_basic_ipv4_invalid);

static int s_credentials_provider_ecs_mocked_server_basic_ipv4_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .port = 7070,
        .path_and_query = aws_byte_cursor_from_c_str("/credentials_provider_ecs_success_response"),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);
    s_aws_wait_for_credentials_result();
    ASSERT_NOT_NULL(s_tester.credentials);
    ASSERT_TRUE(s_tester.error_code == AWS_OP_SUCCESS);

    aws_credentials_provider_release(provider);
    s_aws_wait_for_provider_shutdown_callback();

    s_aws_ecs_tester_cleanup();

    aws_auth_library_clean_up();

    return 0;
}

AWS_TEST_CASE(
    credentials_provider_ecs_mocked_server_basic_ipv4_success,
    s_credentials_provider_ecs_mocked_server_basic_ipv4_success);

AWS_STATIC_STRING_FROM_LITERAL(s_ecs_creds_env_token_file, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_creds_env_token, "AWS_CONTAINER_AUTHORIZATION_TOKEN");

static int s_credentials_provider_ecs_basic_success_token_file(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_string *auth_token = aws_string_new_from_c_str(allocator, "test-token-1234-abcd");
    struct aws_byte_cursor auth_token_cursor = aws_byte_cursor_from_string(auth_token);
    struct aws_string *token_file_path = aws_create_process_unique_file_name(allocator);
    ASSERT_NOT_NULL(token_file_path);
    ASSERT_TRUE(aws_create_profile_file(token_file_path, auth_token) == AWS_OP_SUCCESS);
    ASSERT_TRUE(aws_set_environment_value(s_ecs_creds_env_token_file, token_file_path) == AWS_OP_SUCCESS);

    /* test that static auth token is not preferred over file token */
    struct aws_string *bad_auth_token = aws_string_new_from_c_str(allocator, "badtoken");
    ASSERT_TRUE(aws_set_environment_value(s_ecs_creds_env_token, bad_auth_token) == AWS_OP_SUCCESS);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor);
    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
    };

    ASSERT_SUCCESS(s_do_ecs_success_test(allocator, &options));
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.request_authorization_header.buffer,
        s_tester.request_authorization_header.len,
        auth_token_cursor.ptr,
        auth_token_cursor.len);

    /* update the file with updated token */
    struct aws_string *auth_token2 = aws_string_new_from_c_str(allocator, "test-token2-4321-qwer");
    struct aws_byte_cursor auth_token2_cursor = aws_byte_cursor_from_string(auth_token2);
    ASSERT_TRUE(aws_create_profile_file(token_file_path, auth_token2) == AWS_OP_SUCCESS);

    /* reset tester */
    s_aws_ecs_tester_cleanup();
    s_aws_ecs_tester_init(allocator);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor);

    ASSERT_SUCCESS(s_do_ecs_success_test(allocator, &options));
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.request_authorization_header.buffer,
        s_tester.request_authorization_header.len,
        auth_token2_cursor.ptr,
        auth_token2_cursor.len);

    s_aws_ecs_tester_cleanup();
    aws_file_delete(token_file_path);
    aws_string_destroy(auth_token);
    aws_string_destroy(auth_token2);
    aws_string_destroy(token_file_path);
    aws_string_destroy(bad_auth_token);
    return 0;
}
AWS_TEST_CASE(credentials_provider_ecs_basic_success_token_file, s_credentials_provider_ecs_basic_success_token_file);

static int s_credentials_provider_ecs_basic_success_token_env(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor);
    struct aws_string *auth_token = aws_string_new_from_c_str(allocator, "t-token-1234-abcd");
    struct aws_byte_cursor auth_token_cursor = aws_byte_cursor_from_string(auth_token);
    aws_set_environment_value(s_ecs_creds_env_token, auth_token);
    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
    };

    ASSERT_SUCCESS(s_do_ecs_success_test(allocator, &options));
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.request_authorization_header.buffer,
        s_tester.request_authorization_header.len,
        auth_token_cursor.ptr,
        auth_token_cursor.len);

    s_aws_ecs_tester_cleanup();
    aws_string_destroy(auth_token);
    return 0;
}
AWS_TEST_CASE(credentials_provider_ecs_basic_success_token_env, s_credentials_provider_ecs_basic_success_token_env);

static int s_credentials_provider_ecs_basic_success_token_env_with_parameter_token(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor);

    struct aws_string *auth_token = aws_string_new_from_c_str(allocator, "t-token-1234-abcd");
    aws_set_environment_value(s_ecs_creds_env_token, auth_token);

    struct aws_byte_cursor expected_token_cursor = aws_byte_cursor_from_c_str("t-token-4321-xyz");
    struct aws_credentials_provider_ecs_options options = {

        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = expected_token_cursor,
    };

    ASSERT_SUCCESS(s_do_ecs_success_test(allocator, &options));
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.request_authorization_header.buffer,
        s_tester.request_authorization_header.len,
        expected_token_cursor.ptr,
        expected_token_cursor.len);

    s_aws_ecs_tester_cleanup();
    aws_string_destroy(auth_token);
    return 0;
}
AWS_TEST_CASE(
    credentials_provider_ecs_basic_success_token_env_with_parameter_token,
    s_credentials_provider_ecs_basic_success_token_env_with_parameter_token);

static int s_credentials_provider_ecs_no_auth_token_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_byte_cursor good_response_cursor = aws_byte_cursor_from_string(s_good_response);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
    };

    ASSERT_SUCCESS(s_do_ecs_success_test(allocator, &options));

    s_aws_ecs_tester_cleanup();
    ASSERT_TRUE(s_tester.request_authorization_header.len == 0);

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_no_auth_token_success, s_credentials_provider_ecs_no_auth_token_success);

AWS_STATIC_STRING_FROM_LITERAL(s_good_response_first_part, "{\"AccessKeyId\":\"SuccessfulAccessKey\", \n  \"Secret");
AWS_STATIC_STRING_FROM_LITERAL(s_good_response_second_part, "AccessKey\":\"SuccessfulSecret\", \n  \"Token\":\"Token");
AWS_STATIC_STRING_FROM_LITERAL(s_good_response_third_part, "Success\", \n \"Expiration\":\"2020-02-25T06:03:31Z\"}");

static int s_credentials_provider_ecs_success_multi_part_doc(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_aws_ecs_tester_init(allocator);

    struct aws_byte_cursor good_response_cursor1 = aws_byte_cursor_from_string(s_good_response_first_part);
    struct aws_byte_cursor good_response_cursor2 = aws_byte_cursor_from_string(s_good_response_second_part);
    struct aws_byte_cursor good_response_cursor3 = aws_byte_cursor_from_string(s_good_response_third_part);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor1);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor2);
    aws_array_list_push_back(&s_tester.response_data_callbacks, &good_response_cursor3);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .function_table = &s_mock_function_table,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = aws_byte_cursor_from_c_str("test-token-1234-abcd"),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    aws_mutex_lock(&s_tester.lock);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_tester.request_uri.buffer,
        s_tester.request_uri.len,
        s_expected_ecs_relative_uri->bytes,
        s_expected_ecs_relative_uri->len);

    ASSERT_TRUE(s_tester.has_received_credentials_callback == true);
    ASSERT_TRUE(s_tester.credentials != NULL);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_access_key_id(s_tester.credentials), s_good_access_key_id);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(
        aws_credentials_get_secret_access_key(s_tester.credentials), s_good_secret_access_key);
    ASSERT_CURSOR_VALUE_STRING_EQUALS(aws_credentials_get_session_token(s_tester.credentials), s_good_session_token);

    struct aws_date_time expiration;
    struct aws_byte_cursor date_cursor = aws_byte_cursor_from_string(s_good_response_expiration);
    aws_date_time_init_from_str_cursor(&expiration, &date_cursor, AWS_DATE_FORMAT_ISO_8601);
    ASSERT_TRUE(
        aws_credentials_get_expiration_timepoint_seconds(s_tester.credentials) == (uint64_t)expiration.timestamp);
    aws_mutex_unlock(&s_tester.lock);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Because we mock the http connection manager, we never get a callback back from it */
    aws_mem_release(provider->allocator, provider);
    s_aws_ecs_tester_cleanup();

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_success_multi_part_doc, s_credentials_provider_ecs_success_multi_part_doc);

static int s_credentials_provider_ecs_real_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);

    s_aws_ecs_tester_init(allocator);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = aws_byte_cursor_from_c_str("test-token-1234-abcd"),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_ecs_tester_cleanup();

    aws_auth_library_clean_up();

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_real_new_destroy, s_credentials_provider_ecs_real_new_destroy);

static int s_credentials_provider_ecs_real_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);

    s_aws_ecs_tester_init(allocator);

    struct aws_credentials_provider_ecs_options options = {
        .bootstrap = s_tester.bootstrap,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
        .host = aws_byte_cursor_from_c_str("www.xxx123321testmocknonexsitingawsservice.com"),
        .path_and_query = aws_byte_cursor_from_c_str("/path/to/resource/?a=b&c=d"),
        .auth_token = aws_byte_cursor_from_c_str("test-token-1234-abcd"),
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_ecs(allocator, &options);

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);

    s_aws_wait_for_credentials_result();

    aws_mutex_lock(&s_tester.lock);
    ASSERT_TRUE(s_tester.credentials != NULL);
    aws_mutex_unlock(&s_tester.lock);

    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    s_aws_ecs_tester_cleanup();

    aws_auth_library_clean_up();

    return 0;
}

AWS_TEST_CASE(credentials_provider_ecs_real_success, s_credentials_provider_ecs_real_success);
