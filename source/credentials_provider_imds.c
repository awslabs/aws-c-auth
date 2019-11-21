/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

/* instance role credentials body response is currently ~ 1300 characters + name length */
#define IMDS_RESPONSE_SIZE_INITIAL 2048
#define IMDS_RESPONSE_SIZE_LIMIT 10000
#define IMDS_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS 2

struct aws_credentials_provider_imds_impl {
    struct aws_http_connection_manager *connection_manager;
    struct aws_credentials_provider_system_vtable *function_table;
};

static struct aws_credentials_provider_system_vtable s_default_function_table = {
    .aws_http_connection_manager_new = aws_http_connection_manager_new,
    .aws_http_connection_manager_release = aws_http_connection_manager_release,
    .aws_http_connection_manager_acquire_connection = aws_http_connection_manager_acquire_connection,
    .aws_http_connection_manager_release_connection = aws_http_connection_manager_release_connection,
    .aws_http_connection_make_request = aws_http_connection_make_request,
    .aws_http_stream_get_incoming_response_status = aws_http_stream_get_incoming_response_status,
    .aws_http_stream_release = aws_http_stream_release,
    .aws_http_connection_close = aws_http_connection_close};

/*
 * It takes two http requests to get IMDS credentials.  This tracks which request we're on.
 */
enum aws_imds_query_state { AWS_IMDS_QS_ROLE_NAME, AWS_IMDS_QS_ROLE_CREDENTIALS };

/*
 * Tracking structure for each outstanding async query to an imds provider
 */
struct aws_credentials_provider_imds_user_data {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_credentials_provider *imds_provider;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;

    /* mutable */
    enum aws_imds_query_state query_state;
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_byte_buf current_result;
    int status_code;
};

static void s_aws_credentials_provider_imds_user_data_destroy(
    struct aws_credentials_provider_imds_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    struct aws_credentials_provider_imds_impl *impl = user_data->imds_provider->impl;

    if (user_data->connection) {
        impl->function_table->aws_http_connection_manager_release_connection(
            impl->connection_manager, user_data->connection);
    }

    aws_byte_buf_clean_up(&user_data->current_result);

    if (user_data->request) {
        aws_http_message_destroy(user_data->request);
    }

    aws_mem_release(user_data->allocator, user_data);
}

static struct aws_credentials_provider_imds_user_data *s_aws_credentials_provider_imds_user_data_new(
    struct aws_credentials_provider *imds_provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_imds_user_data *wrapped_user_data =
        aws_mem_acquire(imds_provider->allocator, sizeof(struct aws_credentials_provider_imds_user_data));
    if (wrapped_user_data == NULL) {
        goto on_error;
    }

    AWS_ZERO_STRUCT(*wrapped_user_data);

    wrapped_user_data->allocator = imds_provider->allocator;
    wrapped_user_data->imds_provider = imds_provider;
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    if (aws_byte_buf_init(&wrapped_user_data->current_result, imds_provider->allocator, IMDS_RESPONSE_SIZE_INITIAL)) {
        goto on_error;
    }

    return wrapped_user_data;

on_error:

    s_aws_credentials_provider_imds_user_data_destroy(wrapped_user_data);

    return NULL;
}

static void s_aws_credentials_provider_imds_user_data_reset_response(
    struct aws_credentials_provider_imds_user_data *imds_user_data) {
    imds_user_data->current_result.len = 0;
    imds_user_data->status_code = 0;

    if (imds_user_data->request) {
        aws_http_message_destroy(imds_user_data->request);
        imds_user_data->request = NULL;
    }
}

AWS_STATIC_STRING_FROM_LITERAL(s_empty_empty_string, "\0");
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_name, "AccessKeyId");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_name, "SecretAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_name, "Token");

/*
 * In general, the IMDS document looks something like:

{
  "Code" : "Success",
  "LastUpdated" : "2019-05-28T18:03:09Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "...",
  "SecretAccessKey" : "...",
  "Token" : "...",
  "Expiration" : "2019-05-29T00:21:43Z"
}

 */
static struct aws_credentials *s_parse_credentials_from_imds_document(
    struct aws_allocator *allocator,
    struct aws_byte_buf *document) {

    struct aws_credentials *credentials = NULL;
    cJSON *document_root = NULL;

    struct aws_byte_cursor null_terminator_cursor = aws_byte_cursor_from_string(s_empty_empty_string);
    if (aws_byte_buf_append_dynamic(document, &null_terminator_cursor)) {
        goto done;
    }

    document_root = cJSON_Parse((const char *)document->buffer);
    if (document_root == NULL) {
        goto done;
    }

    /*
     * Pull out the three credentials components
     */
    cJSON *access_key_id = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_access_key_id_name));
    if (!cJSON_IsString(access_key_id) || (access_key_id->valuestring == NULL)) {
        goto done;
    }

    cJSON *secret_access_key =
        cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_secret_access_key_name));
    if (!cJSON_IsString(secret_access_key) || (secret_access_key->valuestring == NULL)) {
        goto done;
    }

    cJSON *session_token = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_session_token_name));
    if (!cJSON_IsString(session_token) || (session_token->valuestring == NULL)) {
        goto done;
    }

    /*
     * Build the credentials
     */
    struct aws_byte_cursor access_key_id_cursor = aws_byte_cursor_from_c_str(access_key_id->valuestring);
    struct aws_byte_cursor secret_access_key_cursor = aws_byte_cursor_from_c_str(secret_access_key->valuestring);
    struct aws_byte_cursor session_token_cursor = aws_byte_cursor_from_c_str(session_token->valuestring);

    if (access_key_id_cursor.len == 0 || secret_access_key_cursor.len == 0 || session_token_cursor.len == 0) {
        goto done;
    }

    credentials = aws_credentials_new_from_cursors(
        allocator, &access_key_id_cursor, &secret_access_key_cursor, &session_token_cursor);

done:

    if (document_root != NULL) {
        cJSON_Delete(document_root);
    }

    return credentials;
}

/*
 * No matter the result, this always gets called assuming that imds_user_data is successfully allocated
 */
static void s_imds_finalize_get_credentials_query(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    /* Try to build credentials from whatever, if anything, was in the result */
    struct aws_credentials *credentials =
        s_parse_credentials_from_imds_document(imds_user_data->allocator, &imds_user_data->current_result);

    /* pass the credentials back */
    imds_user_data->original_callback(credentials, imds_user_data->original_user_data);
    if (credentials != NULL) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) IMDS credentials provider successfully queried instance role credentials",
            (void *)imds_user_data->imds_provider);
    } else {
        AWS_LOGF_WARN(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) IMDS credentials provider failed to query instance role credentials",
            (void *)imds_user_data->imds_provider);
    }

    /* clean up */
    struct aws_credentials_provider *provider = imds_user_data->imds_provider;
    s_aws_credentials_provider_imds_user_data_destroy(imds_user_data);
    aws_credentials_provider_release(provider);
    aws_credentials_destroy(credentials);
}

static int s_imds_on_incoming_body_fn(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;
    (void)data;

    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;
    struct aws_credentials_provider_imds_impl *impl = imds_user_data->imds_provider->impl;

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) IMDS credentials provider received %zu response bytes",
        (void *)imds_user_data->imds_provider,
        data->len);

    if (data->len + imds_user_data->current_result.len > IMDS_RESPONSE_SIZE_LIMIT) {
        impl->function_table->aws_http_connection_close(imds_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) IMDS credentials provider query response exceeded maximum allowed length",
            (void *)imds_user_data->imds_provider);

        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append_dynamic(&imds_user_data->current_result, data)) {
        impl->function_table->aws_http_connection_close(imds_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) IMDS credentials provider query error appending response",
            (void *)imds_user_data->imds_provider);

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_imds_on_incoming_headers_fn(
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

    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;
    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        if (imds_user_data->status_code == 0) {
            struct aws_credentials_provider_imds_impl *impl = imds_user_data->imds_provider->impl;
            if (impl->function_table->aws_http_stream_get_incoming_response_status(
                    stream, &imds_user_data->status_code)) {

                AWS_LOGF_ERROR(
                    AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                    "(id=%p) IMDS credentials provider failed to get http status code",
                    (void *)imds_user_data->imds_provider);

                return AWS_OP_ERR;
            }
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) IMDS credentials provider query received http status code %d",
                (void *)imds_user_data->imds_provider,
                imds_user_data->status_code);
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_imds_query_instance_role_credentials(struct aws_credentials_provider_imds_user_data *imds_user_data);

static void s_imds_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;

    aws_http_message_destroy(imds_user_data->request);
    imds_user_data->request = NULL;

    struct aws_credentials_provider_imds_impl *impl = imds_user_data->imds_provider->impl;
    impl->function_table->aws_http_stream_release(stream);

    /*
     * On anything other than a 200, nullify the response and pretend there was
     * an error
     */
    if (imds_user_data->status_code != 200) {
        imds_user_data->current_result.len = 0;
        error_code = AWS_ERROR_HTTP_UNKNOWN;
    }

    if (error_code == AWS_ERROR_SUCCESS && imds_user_data->query_state == AWS_IMDS_QS_ROLE_NAME) {
        imds_user_data->query_state = AWS_IMDS_QS_ROLE_CREDENTIALS;
        s_imds_query_instance_role_credentials(imds_user_data);
    } else {
        s_imds_finalize_get_credentials_query(imds_user_data);
    }
}

AWS_STATIC_STRING_FROM_LITERAL(s_imds_metadata_resource_path, "/latest/meta-data/iam/security-credentials/");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_accept_header, "Accept");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_accept_header_value, "*/*");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_host, "169.254.169.254");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_user_agent_header, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_user_agent_header_value, "aws-sdk-crt/imds-credentials-provider");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_h1_0_keep_alive_header, "Connection");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_h1_0_keep_alive_header_value, "keep-alive");

static int s_make_imds_http_query(
    struct aws_credentials_provider_imds_user_data *imds_user_data,
    struct aws_byte_cursor *uri) {
    AWS_FATAL_ASSERT(imds_user_data->connection);

    struct aws_http_message *request = aws_http_message_new_request(imds_user_data->allocator);
    if (request == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_http_header accept_header = {
        .name = aws_byte_cursor_from_string(s_imds_accept_header),
        .value = aws_byte_cursor_from_string(s_imds_accept_header_value),
    };
    if (aws_http_message_add_header(request, accept_header)) {
        goto on_error;
    }

    struct aws_http_header user_agent_header = {
        .name = aws_byte_cursor_from_string(s_imds_user_agent_header),
        .value = aws_byte_cursor_from_string(s_imds_user_agent_header_value),
    };
    if (aws_http_message_add_header(request, user_agent_header)) {
        goto on_error;
    }

    struct aws_http_header keep_alive_header = {
        .name = aws_byte_cursor_from_string(s_imds_h1_0_keep_alive_header),
        .value = aws_byte_cursor_from_string(s_imds_h1_0_keep_alive_header_value),
    };
    if (aws_http_message_add_header(request, keep_alive_header)) {
        goto on_error;
    }

    if (aws_http_message_set_request_path(request, *uri)) {
        goto on_error;
    }

    if (aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("GET"))) {
        goto on_error;
    }

    imds_user_data->request = request;

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .on_response_headers = s_imds_on_incoming_headers_fn,
        .on_response_header_block_done = NULL,
        .on_response_body = s_imds_on_incoming_body_fn,
        .on_complete = s_imds_on_stream_complete_fn,
        .user_data = imds_user_data,
        .request = request,
    };

    struct aws_credentials_provider_imds_impl *impl = imds_user_data->imds_provider->impl;
    struct aws_http_stream *stream =
        impl->function_table->aws_http_connection_make_request(imds_user_data->connection, &request_options);

    return stream == NULL ? AWS_OP_ERR : AWS_OP_SUCCESS;

on_error:

    aws_http_message_destroy(request);

    return AWS_OP_ERR;
}

static void s_imds_query_instance_role_credentials(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_FATAL_ASSERT(imds_user_data->connection);

    int result = AWS_OP_ERR;
    struct aws_byte_buf uri;
    AWS_ZERO_STRUCT(uri);

    /*
     * Take the result of the base query, which should be the name of the instance role
     */
    if (imds_user_data->current_result.len == 0) {
        goto cleanup;
    }

    /*
     * Append the role name to the base uri to get the final uri
     */
    if (aws_byte_buf_init(
            &uri, imds_user_data->allocator, s_imds_metadata_resource_path->len + imds_user_data->current_result.len)) {
        goto cleanup;
    }

    struct aws_byte_cursor imds_path = aws_byte_cursor_from_string(s_imds_metadata_resource_path);
    if (aws_byte_buf_append(&uri, &imds_path)) {
        goto cleanup;
    }

    struct aws_byte_cursor role_name = aws_byte_cursor_from_buf(&imds_user_data->current_result);
    if (aws_byte_buf_append(&uri, &role_name)) {
        goto cleanup;
    }

    /* "Clear" the result */
    s_aws_credentials_provider_imds_user_data_reset_response(imds_user_data);

    struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_buf(&uri);
    if (s_make_imds_http_query(imds_user_data, &uri_cursor) == AWS_OP_SUCCESS) {
        result = AWS_OP_SUCCESS;
    }

cleanup:

    if (result == AWS_OP_ERR) {
        s_imds_finalize_get_credentials_query(imds_user_data);
    }

    aws_byte_buf_clean_up(&uri);
}

static void s_imds_query_instance_role_name(struct aws_credentials_provider_imds_user_data *imds_user_data) {

    struct aws_byte_cursor uri = aws_byte_cursor_from_string(s_imds_metadata_resource_path);
    if (s_make_imds_http_query(imds_user_data, &uri)) {
        s_imds_finalize_get_credentials_query(imds_user_data);
    }
}

static void s_imds_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;

    if (connection == NULL) {
        AWS_LOGF_WARN(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "id=%p: Instance metadata provider failed to acquire a connection, error code %d(%s)",
            (void *)imds_user_data->imds_provider,
            error_code,
            aws_error_str(error_code));

        s_imds_finalize_get_credentials_query(imds_user_data);
        return;
    }

    imds_user_data->connection = connection;
    imds_user_data->query_state = AWS_IMDS_QS_ROLE_NAME;

    s_imds_query_instance_role_name(imds_user_data);
}

static int s_credentials_provider_imds_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_imds_impl *impl = provider->impl;

    struct aws_credentials_provider_imds_user_data *wrapped_user_data =
        s_aws_credentials_provider_imds_user_data_new(provider, callback, user_data);
    if (wrapped_user_data == NULL) {
        goto error;
    }

    aws_credentials_provider_acquire(provider);

    impl->function_table->aws_http_connection_manager_acquire_connection(
        impl->connection_manager, s_imds_on_acquire_connection, wrapped_user_data);

    return AWS_OP_SUCCESS;

error:

    s_aws_credentials_provider_imds_user_data_destroy(wrapped_user_data);

    return AWS_OP_ERR;
}

static void s_credentials_provider_imds_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_imds_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    impl->function_table->aws_http_connection_manager_release(impl->connection_manager);

    /* freeing the provider takes place in the shutdown callback below */
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_imds_vtable = {
    .get_credentials = s_credentials_provider_imds_get_credentials_async,
    .destroy = s_credentials_provider_imds_destroy,
};

static void s_on_connection_manager_shutdown(void *user_data) {
    struct aws_credentials_provider *provider = user_data;

    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_mem_release(provider->allocator, provider);
}

struct aws_credentials_provider *aws_credentials_provider_new_imds(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_imds_options *options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_imds_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_imds_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_imds_vtable, impl);

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV4;
    socket_options.connect_timeout_ms = (uint32_t)aws_timestamp_convert(
        IMDS_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);

    struct aws_http_connection_manager_options manager_options;
    AWS_ZERO_STRUCT(manager_options);
    manager_options.bootstrap = options->bootstrap;
    manager_options.initial_window_size = IMDS_RESPONSE_SIZE_LIMIT;
    manager_options.socket_options = &socket_options;
    manager_options.tls_connection_options = NULL;
    manager_options.host = aws_byte_cursor_from_string(s_imds_host);
    manager_options.port = 80;
    manager_options.max_connections = 2;
    manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    manager_options.shutdown_complete_user_data = provider;

    impl->function_table = options->function_table;
    if (impl->function_table == NULL) {
        impl->function_table = &s_default_function_table;
    }

    impl->connection_manager = impl->function_table->aws_http_connection_manager_new(allocator, &manager_options);
    if (impl->connection_manager == NULL) {
        goto on_error;
    }

    provider->shutdown_options = options->shutdown_options;

    return provider;

on_error:

    aws_credentials_provider_destroy(provider);

    return NULL;
}
