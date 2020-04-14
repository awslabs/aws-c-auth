/*
 * Copyright 2010-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/auth/external/cJSON.h>
#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/auth/private/xml_parser.h>
#include <aws/common/clock.h>
#include <aws/common/date_time.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/file_utils.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

#define STS_WEB_IDENTITY_RESPONSE_SIZE_INITIAL 2048
#define STS_WEB_IDENTITY_RESPONSE_SIZE_LIMIT 10000
#define STS_WEB_IDENTITY_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS 2
#define STS_WEB_IDENTITY_CREDS_DEFAULT_DURATION_SECONDS 900
#define STS_WEB_IDENTITY_MAX_ATTEMPTS 3

struct aws_credentials_provider_sts_web_identity_impl {
    struct aws_http_connection_manager *connection_manager;
    struct aws_credentials_provider_system_vtable *function_table;
    struct aws_string *role_arn;
    struct aws_string *role_session_name;
    struct aws_string *token_file_path;
    struct aws_tls_ctx *ctx;
    struct aws_tls_connection_options connection_options;
};

static struct aws_credentials_provider_system_vtable s_default_function_table = {
    .aws_http_connection_manager_new = aws_http_connection_manager_new,
    .aws_http_connection_manager_release = aws_http_connection_manager_release,
    .aws_http_connection_manager_acquire_connection = aws_http_connection_manager_acquire_connection,
    .aws_http_connection_manager_release_connection = aws_http_connection_manager_release_connection,
    .aws_http_connection_make_request = aws_http_connection_make_request,
    .aws_http_stream_activate = aws_http_stream_activate,
    .aws_http_stream_get_connection = aws_http_stream_get_connection,
    .aws_http_stream_get_incoming_response_status = aws_http_stream_get_incoming_response_status,
    .aws_http_stream_release = aws_http_stream_release,
    .aws_http_connection_close = aws_http_connection_close};

/*
 * Tracking structure for each outstanding async query to an sts_web_identity provider
 */
struct sts_web_identity_user_data {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_credentials_provider *sts_web_identity_provider;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;

    /* mutable */
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_byte_buf response;
    int status_code;
    int attempt_count;
};

static void s_user_data_destroy(struct sts_web_identity_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    struct aws_credentials_provider_sts_web_identity_impl *impl = user_data->sts_web_identity_provider->impl;

    if (user_data->connection) {
        impl->function_table->aws_http_connection_manager_release_connection(
            impl->connection_manager, user_data->connection);
    }

    aws_byte_buf_clean_up(&user_data->response);

    if (user_data->request) {
        aws_http_message_destroy(user_data->request);
    }
    aws_credentials_provider_release(user_data->sts_web_identity_provider);
    aws_mem_release(user_data->allocator, user_data);
}

static struct sts_web_identity_user_data *s_user_data_new(
    struct aws_credentials_provider *sts_web_identity_provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct sts_web_identity_user_data *wrapped_user_data =
        aws_mem_calloc(sts_web_identity_provider->allocator, 1, sizeof(struct sts_web_identity_user_data));
    if (wrapped_user_data == NULL) {
        goto on_error;
    }

    wrapped_user_data->allocator = sts_web_identity_provider->allocator;
    wrapped_user_data->sts_web_identity_provider = sts_web_identity_provider;
    aws_credentials_provider_acquire(sts_web_identity_provider);
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    if (aws_byte_buf_init(
            &wrapped_user_data->response,
            sts_web_identity_provider->allocator,
            STS_WEB_IDENTITY_RESPONSE_SIZE_INITIAL)) {
        goto on_error;
    }

    return wrapped_user_data;

on_error:

    s_user_data_destroy(wrapped_user_data);

    return NULL;
}

static void s_user_data_reset_response(struct sts_web_identity_user_data *sts_web_identity_user_data) {
    sts_web_identity_user_data->response.len = 0;
    sts_web_identity_user_data->status_code = 0;

    if (sts_web_identity_user_data->request) {
        aws_http_message_destroy(sts_web_identity_user_data->request);
        sts_web_identity_user_data->request = NULL;
    }
}

/*
 * In general, the STS_WEB_IDENTITY response document looks something like:
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>amzn1.account.AF6RHO7KZU5XRVQJGXK6HB56KR2A</SubjectFromWebIdentityToken>
    <Audience>client.5498841531868486423.1548@apps.example.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/FederatedWebIdentityRole/app1</Arn>
      <AssumedRoleId>AROACLKWSDQRAOEXAMPLE:app1</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <SessionToken>AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <Expiration>2014-10-24T23:00:23Z</Expiration>
      <AccessKeyId>ASgeIAIOSFODNN7EXAMPLE</AccessKeyId>
    </Credentials>
    <Provider>www.amazon.com</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>

Error Response looks like:
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>ExceptionName</Code>
  <Message>XXX</Message>
  <Resource>YYY</Resource>
  <RequestId>4442587FB7D0A2F9</RequestId>
</Error>
*/

static bool s_on_error_node_encountered_fn(struct aws_xml_parser *parser, struct aws_xml_node *node, void *user_data) {

    if (aws_byte_cursor_eq_c_str_ignore_case(&node->name, "Error")) {
        return aws_xml_node_traverse(parser, node, s_on_error_node_encountered_fn, user_data);
    }

    bool *get_retryable_error = user_data;
    struct aws_byte_cursor data_cursor;
    AWS_ZERO_STRUCT(data_cursor);

    if (aws_byte_cursor_eq_c_str_ignore_case(&node->name, "Code")) {
        aws_xml_node_as_body(parser, node, &data_cursor);
        if (aws_byte_cursor_eq_c_str_ignore_case(&data_cursor, "IDPCommunicationError") ||
            aws_byte_cursor_eq_c_str_ignore_case(&data_cursor, "InvalidIdentityToken")) {
            *get_retryable_error = true;
        }
    }

    return true;
}

static bool s_parse_retryable_error_from_response(struct aws_allocator *allocator, struct aws_byte_buf *response) {

    struct aws_xml_parser xml_parser;
    struct aws_byte_cursor response_cursor = aws_byte_cursor_from_buf(response);
    if (aws_xml_parser_init(&xml_parser, allocator, &response_cursor, 0)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to init xml parser for sts web identity credentials provider to parse error information.")
        return false;
    }
    bool get_retryable_error = false;
    if (aws_xml_parser_parse(&xml_parser, s_on_error_node_encountered_fn, &get_retryable_error)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to parse xml error response for sts web identity with error %s",
            aws_error_str(aws_last_error()));
        aws_xml_parser_clean_up(&xml_parser);
        return false;
    }

    aws_xml_parser_clean_up(&xml_parser);
    return get_retryable_error;
}

static bool s_on_creds_node_encountered_fn(struct aws_xml_parser *parser, struct aws_xml_node *node, void *user_data) {
    if (aws_byte_cursor_eq_c_str_ignore_case(&node->name, "AssumeRoleWithWebIdentityResponse") ||
        aws_byte_cursor_eq_c_str_ignore_case(&node->name, "AssumeRoleWithWebIdentityResult") ||
        aws_byte_cursor_eq_c_str_ignore_case(&node->name, "Credentials")) {
        return aws_xml_node_traverse(parser, node, s_on_creds_node_encountered_fn, user_data);
    }

    struct aws_credentials *credentials = user_data;
    struct aws_byte_cursor credential_data;
    AWS_ZERO_STRUCT(credential_data);
    if (aws_byte_cursor_eq_c_str_ignore_case(&node->name, "AccessKeyId")) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->access_key_id =
            aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);

        if (credentials->access_key_id) {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(credentials=%p): AccessKeyId: %s",
                (void *)credentials,
                aws_string_c_str(credentials->access_key_id));
        }
    }

    if (aws_byte_cursor_eq_c_str_ignore_case(&node->name, "SecretAccessKey")) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->secret_access_key =
            aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);
    }

    if (aws_byte_cursor_eq_c_str_ignore_case(&node->name, "SessionToken")) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->session_token =
            aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);
    }

    /* As long as we parsed an usable expiration, use it, otherwise use
     * the existing one: now + 900s, initialized before parsing.
     */
    if (aws_byte_cursor_eq_c_str_ignore_case(&node->name, "Expiration")) {
        aws_xml_node_as_body(parser, node, &credential_data);
        if (credential_data.len != 0) {
            struct aws_date_time expiration;
            if (aws_date_time_init_from_str_cursor(&expiration, &credential_data, AWS_DATE_FORMAT_ISO_8601) ==
                AWS_OP_SUCCESS) {
                credentials->expiration_timepoint_seconds = (uint64_t)aws_date_time_as_epoch_secs(&expiration);
            } else {
                AWS_LOGF_ERROR(
                    AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                    "Failed to parse time string from sts web identity xml response: %s",
                    aws_error_str(aws_last_error()));
            }
        }
    }
    return true;
}

static struct aws_credentials *s_parse_credentials_from_response(
    struct aws_allocator *allocator,
    struct aws_byte_buf *response) {

    if (!allocator || !response || response->len == 0) {
        return NULL;
    }

    struct aws_xml_parser xml_parser;
    struct aws_credentials *credentials = NULL;
    bool parse_success = false;
    struct aws_byte_cursor response_cursor = aws_byte_cursor_from_buf(response);
    if (aws_xml_parser_init(&xml_parser, allocator, &response_cursor, 0)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to init xml parser for sts web identity credentials provider to parse error information.")
        return NULL;
    }
    uint64_t now = UINT64_MAX;
    if (aws_sys_clock_get_ticks(&now) != AWS_OP_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to get sys clock for sts web identity credentials provider to parse error information.")
        goto on_finish;
    }
    uint64_t now_seconds = aws_timestamp_convert(now, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_SECS, NULL);
    credentials = aws_mem_calloc(allocator, 1, sizeof(struct aws_credentials));
    if (!credentials) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to allocate required memory for credentials: %s",
            aws_error_str(aws_last_error()));
        goto on_finish;
    }
    credentials->allocator = allocator;
    credentials->expiration_timepoint_seconds = now_seconds + STS_WEB_IDENTITY_CREDS_DEFAULT_DURATION_SECONDS;

    if (aws_xml_parser_parse(&xml_parser, s_on_creds_node_encountered_fn, credentials)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to parse xml response for sts web identity with error: %s",
            aws_error_str(aws_last_error()));
        goto on_finish;
    }

    if (!credentials->access_key_id || !credentials->secret_access_key) {
        goto on_finish;
    }
    parse_success = true;

on_finish:
    aws_xml_parser_clean_up(&xml_parser);
    if (!parse_success) {
        aws_credentials_destroy(credentials);
        return NULL;
    }
    return credentials;
}

/*
 * No matter the result, this always gets called assuming that user_data is successfully allocated
 */
static void s_finalize_get_credentials_query(struct sts_web_identity_user_data *sts_web_identity_user_data) {
    /* Try to build credentials from whatever, if anything, was in the result */
    struct aws_credentials *credentials = NULL;
    if (sts_web_identity_user_data->status_code == AWS_HTTP_STATUS_CODE_200_OK) {
        credentials = s_parse_credentials_from_response(
            sts_web_identity_user_data->allocator, &sts_web_identity_user_data->response);
    }

    if (credentials != NULL) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) STS_WEB_IDENTITY credentials provider successfully queried credentials",
            (void *)sts_web_identity_user_data->sts_web_identity_provider);
    } else {
        AWS_LOGF_WARN(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) STS_WEB_IDENTITY credentials provider failed to query credentials",
            (void *)sts_web_identity_user_data->sts_web_identity_provider);
    }

    /* pass the credentials back */
    sts_web_identity_user_data->original_callback(credentials, sts_web_identity_user_data->original_user_data);

    /* clean up */
    s_user_data_destroy(sts_web_identity_user_data);
    aws_credentials_destroy(credentials);
}

static int s_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {

    (void)stream;

    struct sts_web_identity_user_data *sts_web_identity_user_data = user_data;
    struct aws_credentials_provider_sts_web_identity_impl *impl =
        sts_web_identity_user_data->sts_web_identity_provider->impl;

    AWS_LOGF_TRACE(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) STS_WEB_IDENTITY credentials provider received %zu response bytes",
        (void *)sts_web_identity_user_data->sts_web_identity_provider,
        data->len);

    if (data->len + sts_web_identity_user_data->response.len > STS_WEB_IDENTITY_RESPONSE_SIZE_LIMIT) {
        impl->function_table->aws_http_connection_close(sts_web_identity_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) STS_WEB_IDENTITY credentials provider query response exceeded maximum allowed length",
            (void *)sts_web_identity_user_data->sts_web_identity_provider);

        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (aws_byte_buf_append_dynamic(&sts_web_identity_user_data->response, data)) {
        impl->function_table->aws_http_connection_close(sts_web_identity_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) STS_WEB_IDENTITY credentials provider query error appending response: %s",
            (void *)sts_web_identity_user_data->sts_web_identity_provider,
            aws_error_str(aws_last_error()));

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_on_incoming_headers_fn(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)header_array;
    (void)num_headers;

    if (header_block != AWS_HTTP_HEADER_BLOCK_MAIN) {
        return AWS_OP_SUCCESS;
    }

    struct sts_web_identity_user_data *sts_web_identity_user_data = user_data;
    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        if (sts_web_identity_user_data->status_code == 0) {
            struct aws_credentials_provider_sts_web_identity_impl *impl =
                sts_web_identity_user_data->sts_web_identity_provider->impl;
            if (impl->function_table->aws_http_stream_get_incoming_response_status(
                    stream, &sts_web_identity_user_data->status_code)) {

                AWS_LOGF_ERROR(
                    AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                    "(id=%p) STS_WEB_IDENTITY credentials provider failed to get http status code: %s",
                    (void *)sts_web_identity_user_data->sts_web_identity_provider,
                    aws_error_str(aws_last_error()));

                return AWS_OP_ERR;
            }
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) STS_WEB_IDENTITY credentials provider query received http status code %d",
                (void *)sts_web_identity_user_data->sts_web_identity_provider,
                sts_web_identity_user_data->status_code);
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_query_credentials(struct sts_web_identity_user_data *sts_web_identity_user_data);

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct sts_web_identity_user_data *sts_web_identity_user_data = user_data;

    aws_http_message_destroy(sts_web_identity_user_data->request);
    sts_web_identity_user_data->request = NULL;

    struct aws_credentials_provider_sts_web_identity_impl *impl =
        sts_web_identity_user_data->sts_web_identity_provider->impl;
    struct aws_http_connection *connection = impl->function_table->aws_http_stream_get_connection(stream);
    impl->function_table->aws_http_stream_release(stream);
    impl->function_table->aws_http_connection_manager_release_connection(impl->connection_manager, connection);

    /*
     * On anything other than a 200, if we can retry the request based on
     * error response, retry it, otherwise, call the finalize function.
     */
    if (sts_web_identity_user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK || error_code != AWS_OP_SUCCESS) {
        if (++sts_web_identity_user_data->attempt_count < STS_WEB_IDENTITY_MAX_ATTEMPTS &&
            sts_web_identity_user_data->response.len) {
            if (s_parse_retryable_error_from_response(
                    sts_web_identity_user_data->allocator, &sts_web_identity_user_data->response)) {
                s_query_credentials(sts_web_identity_user_data);
                return;
            }
        }
    }

    s_finalize_get_credentials_query(sts_web_identity_user_data);
}

AWS_STATIC_STRING_FROM_LITERAL(s_accept_header, "Accept");
AWS_STATIC_STRING_FROM_LITERAL(s_accept_header_value, "*/*");
AWS_STATIC_STRING_FROM_LITERAL(s_user_agent_header, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_user_agent_header_value, "aws-sdk-crt/sts-web-identity-credentials-provider");
AWS_STATIC_STRING_FROM_LITERAL(s_h1_0_keep_alive_header, "Connection");
AWS_STATIC_STRING_FROM_LITERAL(s_h1_0_keep_alive_header_value, "keep-alive");

static int s_make_sts_web_identity_http_query(
    struct sts_web_identity_user_data *sts_web_identity_user_data,
    struct aws_byte_cursor *uri) {
    AWS_FATAL_ASSERT(sts_web_identity_user_data->connection);

    struct aws_http_stream *stream = NULL;
    struct aws_http_message *request = aws_http_message_new_request(sts_web_identity_user_data->allocator);
    if (request == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_credentials_provider_sts_web_identity_impl *impl =
        sts_web_identity_user_data->sts_web_identity_provider->impl;

    struct aws_http_header accept_header = {
        .name = aws_byte_cursor_from_string(s_accept_header),
        .value = aws_byte_cursor_from_string(s_accept_header_value),
    };
    if (aws_http_message_add_header(request, accept_header)) {
        goto on_error;
    }

    struct aws_http_header user_agent_header = {
        .name = aws_byte_cursor_from_string(s_user_agent_header),
        .value = aws_byte_cursor_from_string(s_user_agent_header_value),
    };
    if (aws_http_message_add_header(request, user_agent_header)) {
        goto on_error;
    }

    struct aws_http_header keep_alive_header = {
        .name = aws_byte_cursor_from_string(s_h1_0_keep_alive_header),
        .value = aws_byte_cursor_from_string(s_h1_0_keep_alive_header_value),
    };
    if (aws_http_message_add_header(request, keep_alive_header)) {
        goto on_error;
    }

    if (aws_http_message_set_request_path(request, *uri)) {
        goto on_error;
    }

    if (aws_http_message_set_request_method(request, aws_http_method_get)) {
        goto on_error;
    }

    sts_web_identity_user_data->request = request;

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .on_response_headers = s_on_incoming_headers_fn,
        .on_response_header_block_done = NULL,
        .on_response_body = s_on_incoming_body_fn,
        .on_complete = s_on_stream_complete_fn,
        .user_data = sts_web_identity_user_data,
        .request = request,
    };

    stream = impl->function_table->aws_http_connection_make_request(
        sts_web_identity_user_data->connection, &request_options);

    if (!stream) {
        goto on_error;
    }

    if (impl->function_table->aws_http_stream_activate(stream)) {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    impl->function_table->aws_http_stream_release(stream);
    aws_http_message_destroy(request);

    return AWS_OP_ERR;
}

static void s_query_credentials(struct sts_web_identity_user_data *sts_web_identity_user_data) {
    AWS_FATAL_ASSERT(sts_web_identity_user_data->connection);

    struct aws_credentials_provider_sts_web_identity_impl *impl =
        sts_web_identity_user_data->sts_web_identity_provider->impl;

    /* "Clear" the result */
    s_user_data_reset_response(sts_web_identity_user_data);

    /*
     * Calculate query string:
     * "/?Action=AssumeRoleWithWebIdentity"
     * + "&Version=2011-06-15"
     * + "&RoleSessionName=" + url_encode(role_session_name)
     * + "&RoleArn=" + url_encode(role_arn)
     * + "&WebIdentityToken=" + url_encode(token);
     */
    struct aws_byte_buf query_buf;
    struct aws_byte_buf token_buf;
    bool success = false;

    AWS_ZERO_STRUCT(query_buf);
    AWS_ZERO_STRUCT(token_buf);

    struct aws_byte_cursor work_cursor =
        aws_byte_cursor_from_c_str("/Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=");
    if (aws_byte_buf_init_copy_from_cursor(&query_buf, sts_web_identity_user_data->allocator, work_cursor)) {
        goto on_finish;
    }

    work_cursor = aws_byte_cursor_from_string(impl->role_arn);
    if (aws_byte_buf_append_encoding_uri_param(&query_buf, &work_cursor)) {
        goto on_finish;
    }

    work_cursor = aws_byte_cursor_from_c_str("&RoleSessionName=");
    if (aws_byte_buf_append_dynamic(&query_buf, &work_cursor)) {
        goto on_finish;
    }

    work_cursor = aws_byte_cursor_from_string(impl->role_session_name);
    if (aws_byte_buf_append_encoding_uri_param(&query_buf, &work_cursor)) {
        goto on_finish;
    }

    work_cursor = aws_byte_cursor_from_c_str("&WebIdentityToken=");
    if (aws_byte_buf_append_dynamic(&query_buf, &work_cursor)) {
        goto on_finish;
    }

    if (aws_byte_buf_init_from_file(
            &token_buf, sts_web_identity_user_data->allocator, aws_string_c_str(impl->token_file_path))) {
        goto on_finish;
    }
    work_cursor = aws_byte_cursor_from_buf(&token_buf);
    if (aws_byte_buf_append_encoding_uri_param(&query_buf, &work_cursor)) {
        goto on_finish;
    }
    struct aws_byte_cursor query_cursor = aws_byte_cursor_from_buf(&query_buf);

    if (s_make_sts_web_identity_http_query(sts_web_identity_user_data, &query_cursor) == AWS_OP_ERR) {
        goto on_finish;
    }
    success = true;

on_finish:
    aws_byte_buf_clean_up(&token_buf);
    aws_byte_buf_clean_up(&query_buf);
    if (!success) {
        s_finalize_get_credentials_query(sts_web_identity_user_data);
    }
}

static void s_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct sts_web_identity_user_data *sts_web_identity_user_data = user_data;

    if (connection == NULL) {
        AWS_LOGF_WARN(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "id=%p: STS_WEB_IDENTITY provider failed to acquire a connection, error code %d(%s)",
            (void *)sts_web_identity_user_data->sts_web_identity_provider,
            error_code,
            aws_error_str(error_code));

        s_finalize_get_credentials_query(sts_web_identity_user_data);
        return;
    }

    sts_web_identity_user_data->connection = connection;

    s_query_credentials(sts_web_identity_user_data);
}

static int s_credentials_provider_sts_web_identity_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_sts_web_identity_impl *impl = provider->impl;

    struct sts_web_identity_user_data *wrapped_user_data = s_user_data_new(provider, callback, user_data);
    if (wrapped_user_data == NULL) {
        goto error;
    }

    impl->function_table->aws_http_connection_manager_acquire_connection(
        impl->connection_manager, s_on_acquire_connection, wrapped_user_data);

    return AWS_OP_SUCCESS;

error:
    s_user_data_destroy(wrapped_user_data);
    return AWS_OP_ERR;
}

static void s_credentials_provider_sts_web_identity_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_sts_web_identity_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    impl->function_table->aws_http_connection_manager_release(impl->connection_manager);

    aws_string_destroy(impl->role_arn);
    aws_string_destroy(impl->role_session_name);
    aws_string_destroy(impl->token_file_path);

    /* freeing the provider takes place in the shutdown callback below */
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_sts_web_identity_vtable = {
    .get_credentials = s_credentials_provider_sts_web_identity_get_credentials_async,
    .destroy = s_credentials_provider_sts_web_identity_destroy,
};

static void s_on_connection_manager_shutdown(void *user_data) {
    struct aws_credentials_provider *provider = user_data;
    struct aws_credentials_provider_sts_web_identity_impl *impl = provider->impl;

    aws_credentials_provider_invoke_shutdown_callback(provider);
    aws_tls_ctx_destroy(impl->ctx);
    aws_tls_connection_options_clean_up(&impl->connection_options);
    aws_mem_release(provider->allocator, provider);
}

AWS_STATIC_STRING_FROM_LITERAL(s_region_config, "region");
AWS_STATIC_STRING_FROM_LITERAL(s_region_env, "AWS_DEFAULT_REGION");
AWS_STATIC_STRING_FROM_LITERAL(s_role_arn_config, "role_arn");
AWS_STATIC_STRING_FROM_LITERAL(s_role_arn_env, "AWS_ROLE_ARN");
AWS_STATIC_STRING_FROM_LITERAL(s_role_session_name_config, "role_session_name");
AWS_STATIC_STRING_FROM_LITERAL(s_role_session_name_env, "AWS_ROLE_SESSION_NAME");
AWS_STATIC_STRING_FROM_LITERAL(s_token_file_path_config, "web_identity_token_file");
AWS_STATIC_STRING_FROM_LITERAL(s_token_file_path_env, "AWS_WEB_IDENTITY_TOKEN_FILE");

struct sts_web_identity_parameters {
    struct aws_allocator *allocator;
    /* region is actually used to construct endpoint */
    struct aws_byte_buf endpoint;
    struct aws_byte_buf role_arn;
    struct aws_byte_buf role_session_name;
    struct aws_byte_buf token_file_path;
};

struct aws_profile_collection *s_load_profile(struct aws_allocator *allocator) {

    struct aws_profile_collection *config_profiles = NULL;
    struct aws_string *config_file_path = NULL;

    config_file_path = aws_get_config_file_path(allocator, NULL);
    if (!config_file_path) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to resolve config file path during sts web identity provider initialization: %s",
            aws_error_str(aws_last_error()));
        goto on_error;
    }

    config_profiles = aws_profile_collection_new_from_file(allocator, config_file_path, AWS_PST_CONFIG);
    if (config_profiles != NULL) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Successfully built config profile collection from file at (%s)",
            aws_string_c_str(config_file_path));
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to build config profile collection from file at (%s) : %s",
            aws_string_c_str(config_file_path),
            aws_error_str(aws_last_error()));
        goto on_error;
    }

    aws_string_destroy(config_file_path);
    return config_profiles;

on_error:
    aws_string_destroy(config_file_path);
    aws_profile_collection_destroy(config_profiles);
    return NULL;
}

static struct aws_byte_cursor s_default_profile_name_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("default");
static struct aws_byte_cursor s_dot_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(".");
static struct aws_byte_cursor s_amazonaws_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(".amazonaws.com");
static struct aws_byte_cursor s_cn_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(".cn");
AWS_STATIC_STRING_FROM_LITERAL(s_sts_service_name, "sts");

static int s_construct_endpoint(
    struct aws_allocator *allocator,
    struct aws_byte_buf *endpoint,
    const struct aws_string *region,
    const struct aws_string *service_name) {

    if (!allocator || !endpoint || !region || !service_name) {
        return AWS_ERROR_INVALID_ARGUMENT;
    }
    aws_byte_buf_clean_up(endpoint);

    struct aws_byte_cursor service_cursor = aws_byte_cursor_from_string(service_name);
    if (aws_byte_buf_init_copy_from_cursor(endpoint, allocator, service_cursor)) {
        goto on_error;
    }

    if (aws_byte_buf_append_dynamic(endpoint, &s_dot_cursor)) {
        goto on_error;
    }

    struct aws_byte_cursor region_cursor;
    region_cursor = aws_byte_cursor_from_array(region->bytes, region->len);
    if (aws_byte_buf_append_dynamic(endpoint, &region_cursor)) {
        goto on_error;
    }

    if (aws_byte_buf_append_dynamic(endpoint, &s_amazonaws_cursor)) {
        goto on_error;
    }

    if (aws_string_eq_c_str_ignore_case(region, "cn-north-1") ||
        aws_string_eq_c_str_ignore_case(region, "cn-northwest-1")) {
        if (aws_byte_buf_append_dynamic(endpoint, &s_cn_cursor)) {
            goto on_error;
        }
    }
    return AWS_OP_SUCCESS;

on_error:
    aws_byte_buf_clean_up(endpoint);
    return AWS_OP_ERR;
}

static int s_generate_uuid_to_buf(struct aws_allocator *allocator, struct aws_byte_buf *dst) {

    if (!allocator || !dst) {
        return AWS_ERROR_INVALID_ARGUMENT;
    }

    struct aws_uuid uuid;
    if (aws_uuid_init(&uuid)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to initiate an uuid struct: %s", aws_error_str(aws_last_error()));
        return aws_last_error();
    }

    char uuid_str[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_array(uuid_str, sizeof(uuid_str));
    uuid_buf.len = 0;
    if (aws_uuid_to_str(&uuid, &uuid_buf)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to stringify uuid: %s", aws_error_str(aws_last_error()));
        return aws_last_error();
    }
    if (aws_byte_buf_init_copy(dst, allocator, &uuid_buf)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to generate role session name during sts web identity provider initialization: %s",
            aws_error_str(aws_last_error()));
        return aws_last_error();
    }
    return AWS_OP_SUCCESS;
}

void s_check_or_get_with_profile_config(
    struct aws_allocator *allocator,
    struct aws_profile *profile,
    struct aws_string **target,
    const struct aws_string *config_key) {

    if (!allocator || !profile || !config_key) {
        return;
    }
    if ((!(*target) || !(*target)->len)) {
        if (*target) {
            aws_string_destroy(*target);
        }
        struct aws_profile_property *property = aws_profile_get_property(profile, config_key);
        if (property) {
            *target = aws_string_new_from_string(allocator, property->value);
        }
    }
}

void s_parameters_destroy(struct sts_web_identity_parameters *parameters) {
    if (!parameters) {
        return;
    }
    aws_byte_buf_clean_up(&parameters->endpoint);
    aws_byte_buf_clean_up(&parameters->role_arn);
    aws_byte_buf_clean_up(&parameters->role_session_name);
    aws_byte_buf_clean_up(&parameters->token_file_path);
    aws_mem_release(parameters->allocator, parameters);
}

struct sts_web_identity_parameters *s_parameters_new(struct aws_allocator *allocator) {

    struct sts_web_identity_parameters *parameters =
        aws_mem_calloc(allocator, 1, sizeof(struct sts_web_identity_parameters));
    if (parameters == NULL) {
        return NULL;
    }
    parameters->allocator = allocator;

    bool success = false;
    struct aws_string *region = NULL;
    struct aws_string *role_arn = NULL;
    struct aws_string *role_session_name = NULL;
    struct aws_string *token_file_path = NULL;

    /* check environment variables */
    aws_get_environment_value(allocator, s_region_env, &region);
    aws_get_environment_value(allocator, s_role_arn_env, &role_arn);
    aws_get_environment_value(allocator, s_role_session_name_env, &role_session_name);
    aws_get_environment_value(allocator, s_token_file_path_env, &token_file_path);

    /**
     * check config profile if either region, role_arn or token_file_path or role_session_name is not resolved from
     * environment variable. Role session name can also be generated by us using uuid if not found from both sources.
     */
    struct aws_profile_collection *config_profile = NULL;
    struct aws_string *profile_name = NULL;
    struct aws_profile *profile = NULL;
    bool get_all_parameters =
        (region && region->len && role_arn && role_arn->len && token_file_path && token_file_path->len);
    if (!get_all_parameters) {
        config_profile = s_load_profile(allocator);
        profile_name = aws_get_profile_name(allocator, &s_default_profile_name_cursor);
        if (config_profile && profile_name) {
            profile = aws_profile_collection_get_profile(config_profile, profile_name);
        }

        if (!profile) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Failed to resolve either region, role arn or token file path during sts web identity provider "
                "initialization.")
            goto on_finish;

        } else {
            s_check_or_get_with_profile_config(allocator, profile, &region, s_region_config);
            s_check_or_get_with_profile_config(allocator, profile, &role_arn, s_role_arn_config);
            s_check_or_get_with_profile_config(allocator, profile, &role_session_name, s_role_session_name_config);
            s_check_or_get_with_profile_config(allocator, profile, &token_file_path, s_token_file_path_config);
        }
    }

    /* determin endpoint */
    if (s_construct_endpoint(allocator, &parameters->endpoint, region, s_sts_service_name)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to construct sts endpoint with, probably region is missing.");
        goto on_finish;
    }

    /* determine role_arn */
    if (!role_arn || !role_arn->len ||
        aws_byte_buf_init_copy_from_cursor(&parameters->role_arn, allocator, aws_byte_cursor_from_string(role_arn))) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to resolve role arn during sts web identity provider initialization.")
        goto on_finish;
    }

    /* determine token_file_path */
    if (!token_file_path || !token_file_path->len ||
        aws_byte_buf_init_copy_from_cursor(
            &parameters->token_file_path, allocator, aws_byte_cursor_from_string(token_file_path))) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to resolve token file path during sts web identity provider initialization.")
        goto on_finish;
    }

    /* determine role_session_name */
    if (role_session_name && role_session_name->len) {
        if (aws_byte_buf_init_copy_from_cursor(
                &parameters->role_session_name, allocator, aws_byte_cursor_from_string(role_session_name))) {
            goto on_finish;
        }
    } else if (s_generate_uuid_to_buf(allocator, &parameters->role_session_name)) {
        goto on_finish;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Successfully loaded all required parameters for sts web identity credentials provider.")
    success = true;

on_finish:
    aws_string_destroy(region);
    aws_string_destroy(role_arn);
    aws_string_destroy(role_session_name);
    aws_string_destroy(token_file_path);
    aws_string_destroy(profile_name);
    aws_profile_collection_destroy(config_profile);
    if (!success) {
        s_parameters_destroy(parameters);
        parameters = NULL;
    }
    return parameters;
}

struct aws_credentials_provider *aws_credentials_provider_new_sts_web_identity(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_sts_web_identity_options *options) {

    struct sts_web_identity_parameters *parameters = s_parameters_new(allocator);
    if (!parameters) {
        return NULL;
    }

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_sts_web_identity_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_sts_web_identity_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_sts_web_identity_vtable, impl);

    AWS_LOGF_TRACE(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p): initializing a new tlx context", (void *)provider);
    struct aws_tls_ctx_options tls_options;
    aws_tls_ctx_options_init_default_client(&tls_options, allocator);
    impl->ctx = aws_tls_client_ctx_new(allocator, &tls_options);

    if (!impl->ctx) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to create a tls context with error %s",
            (void *)provider,
            aws_error_str(aws_last_error()));
        aws_tls_ctx_options_clean_up(&tls_options);
        goto on_error;
    }

    aws_tls_connection_options_init_from_ctx(&impl->connection_options, impl->ctx);
    struct aws_byte_cursor host = aws_byte_cursor_from_buf(&parameters->endpoint);
    if (aws_tls_connection_options_set_server_name(&impl->connection_options, allocator, &host)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to create a tls connection options with error %s",
            (void *)provider,
            aws_error_str(aws_last_error()));
        goto on_error;
    }

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV4;
    socket_options.connect_timeout_ms = (uint32_t)aws_timestamp_convert(
        STS_WEB_IDENTITY_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);

    struct aws_http_connection_manager_options manager_options;
    AWS_ZERO_STRUCT(manager_options);
    manager_options.bootstrap = options->bootstrap;
    manager_options.initial_window_size = STS_WEB_IDENTITY_RESPONSE_SIZE_LIMIT;
    manager_options.socket_options = &socket_options;
    manager_options.host = host;
    manager_options.port = 443;
    manager_options.max_connections = 2;
    manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    manager_options.shutdown_complete_user_data = provider;
    manager_options.tls_connection_options = &(impl->connection_options);

    impl->function_table = options->function_table;
    if (impl->function_table == NULL) {
        impl->function_table = &s_default_function_table;
    }

    impl->connection_manager = impl->function_table->aws_http_connection_manager_new(allocator, &manager_options);
    if (impl->connection_manager == NULL) {
        goto on_error;
    }

    impl->role_arn = aws_string_new_from_array(allocator, parameters->role_arn.buffer, parameters->role_arn.len);
    if (impl->role_arn == NULL) {
        goto on_error;
    }

    impl->role_session_name =
        aws_string_new_from_array(allocator, parameters->role_session_name.buffer, parameters->role_session_name.len);
    if (impl->role_session_name == NULL) {
        goto on_error;
    }

    impl->token_file_path =
        aws_string_new_from_array(allocator, parameters->token_file_path.buffer, parameters->token_file_path.len);
    if (impl->token_file_path == NULL) {
        goto on_error;
    }

    provider->shutdown_options = options->shutdown_options;
    s_parameters_destroy(parameters);
    return provider;

on_error:

    aws_credentials_provider_destroy(provider);
    s_parameters_destroy(parameters);
    return NULL;
}
