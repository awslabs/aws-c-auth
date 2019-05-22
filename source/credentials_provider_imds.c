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

#include <aws/auth/private/cJSON.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>

/*
 * Provider ec2 instance metadata implementation
 */

struct aws_credentials_provider_imds_impl {
    struct aws_http_connection_manager *connection_manager;
};

enum aws_imds_query_state {
    AWS_IMDS_QS_ROLE_NAME,
    AWS_IMDS_QS_ROLE_CREDENTIALS
};

#define IMDS_RESPONSE_SIZE_LIMIT 10000

struct aws_credentials_provider_imds_user_data {
    struct aws_allocator *allocator;
    struct aws_credentials_provider *imds_provider;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;
    enum aws_imds_query_state query_state;
    struct aws_http_connection *connection;
    struct aws_http_stream *current_stream;
    struct aws_byte_buf current_result;
};

static void s_aws_credentials_provider_imds_user_data_destroy(struct aws_credentials_provider_imds_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    if (user_data->current_stream) {
        aws_http_stream_release(user_data->current_stream);
    }

    if (user_data->connection) {
        struct aws_credentials_provider_imds_impl *imds_impl = user_data->imds_provider->impl;
        aws_http_connection_manager_release_connection(imds_impl->connection_manager, user_data->connection);
    }

    aws_byte_buf_clean_up(&user_data->current_result);

    aws_mem_release(user_data->allocator, user_data);
}

AWS_STATIC_STRING_FROM_LITERAL(s_empty_empty_string, "\0");

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_name, "AccessKeyId");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_name, "SecretAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_name, "Token");

static struct aws_credentials *s_parse_credentials_from_imds_document(struct aws_allocator *allocator, struct aws_byte_buf *document) {

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

    cJSON *access_key_id = cJSON_GetObjectItemCaseSensitive(document_root, (const char *)s_access_key_id_name->bytes);
    if (!cJSON_IsString(access_key_id) || (access_key_id->valuestring == NULL))
    {
        goto done;
    }

    cJSON *secret_access_key = cJSON_GetObjectItemCaseSensitive(document_root, (const char *)s_secret_access_key_name->bytes);
    if (!cJSON_IsString(secret_access_key) || (secret_access_key->valuestring == NULL))
    {
        goto done;
    }

    cJSON *session_token = cJSON_GetObjectItemCaseSensitive(document_root, (const char *)s_session_token_name->bytes);
    if (!cJSON_IsString(session_token) || (session_token->valuestring == NULL))
    {
        goto done;
    }

    struct aws_byte_cursor access_key_id_cursor = aws_byte_cursor_from_c_str(access_key_id->valuestring);
    struct aws_byte_cursor secret_access_key_cursor = aws_byte_cursor_from_c_str(secret_access_key->valuestring);
    struct aws_byte_cursor session_token_cursor = aws_byte_cursor_from_c_str(session_token->valuestring);

    credentials = aws_credentials_new_from_cursors(allocator, &access_key_id_cursor, &secret_access_key_cursor, &session_token_cursor);

    done:

    if (document_root != NULL) {
        cJSON_Delete(document_root);
    }

    return credentials;
}

static void s_imds_finalize_get_credentials_query(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    struct aws_credentials *credentials = s_parse_credentials_from_imds_document(imds_user_data->allocator, &imds_user_data->current_result);
    imds_user_data->original_callback(credentials, imds_user_data->original_user_data);
    s_aws_credentials_provider_imds_user_data_destroy(imds_user_data);
}

static void s_imds_on_incoming_body_fn(
        struct aws_http_stream *stream,
        const struct aws_byte_cursor *data,
        /* NOLINTNEXTLINE(readability-non-const-parameter) */
        size_t *out_window_update_size,
        void *user_data) {

    (void)stream;
    (void)out_window_update_size;
    (void)data;

    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;

    if (data->len + imds_user_data->current_result.len > IMDS_RESPONSE_SIZE_LIMIT) {
        aws_http_connection_close(imds_user_data->connection);
        return;
    }

    if (aws_byte_buf_append_dynamic(&imds_user_data->current_result, data)) {
        aws_http_connection_close(imds_user_data->connection);
    }
}

static void s_imds_on_incoming_headers_fn(
        struct aws_http_stream *stream,
        const struct aws_http_header *header_array,
        size_t num_headers,
        void *user_data) {

    (void)stream;
    (void)header_array;
    (void)num_headers;
    (void)user_data;
}

static void s_imds_on_incoming_header_block_done_fn(struct aws_http_stream *stream, bool has_body, void *user_data) {
    (void)stream;
    (void)has_body;
    (void)user_data;
}

static void s_imds_query_instance_role_credentials(struct aws_credentials_provider_imds_user_data *imds_user_data);

static void s_imds_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)error_code;
    (void)user_data;

    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;
    AWS_FATAL_ASSERT(imds_user_data->current_stream == stream);

    aws_http_stream_release(stream);

    imds_user_data->current_stream = NULL;

    if (error_code == AWS_ERROR_SUCCESS && imds_user_data->query_state == AWS_IMDS_QS_ROLE_NAME) {
        imds_user_data->query_state = AWS_IMDS_QS_ROLE_CREDENTIALS;
        s_imds_query_instance_role_credentials(imds_user_data);
    } else {
        s_imds_finalize_get_credentials_query(imds_user_data);
    }
}

AWS_STATIC_STRING_FROM_LITERAL(s_imds_metadata_resource_path, "/latest/meta-data/iam/security-credentials/");

static int s_make_imds_http_query(struct aws_credentials_provider_imds_user_data *imds_user_data, struct aws_byte_cursor *uri) {
    AWS_FATAL_ASSERT(imds_user_data->connection);
    AWS_FATAL_ASSERT(imds_user_data->current_stream == NULL);

    struct aws_http_header headers[2];
    AWS_ZERO_ARRAY(headers);

    headers[0].name = aws_byte_cursor_from_c_str("accept");
    headers[0].value = aws_byte_cursor_from_c_str("*/*");
    headers[1].name = aws_byte_cursor_from_c_str("host");
    headers[1].value = aws_byte_cursor_from_c_str("169.254.169.254");

    struct aws_http_request_options request = AWS_HTTP_REQUEST_OPTIONS_INIT;
    request.client_connection = imds_user_data->connection;
    request.method = aws_byte_cursor_from_c_str("GET");
    request.uri = *uri;
    request.num_headers = 2;
    request.header_array = headers;
    request.on_response_headers = s_imds_on_incoming_headers_fn;
    request.on_response_header_block_done = s_imds_on_incoming_header_block_done_fn;
    request.on_response_body = s_imds_on_incoming_body_fn;
    request.on_complete = s_imds_on_stream_complete_fn;

    imds_user_data->current_stream = aws_http_stream_new_client_request(&request);

    return imds_user_data->current_stream == NULL ? AWS_OP_ERR : AWS_OP_SUCCESS;
}

static void s_imds_query_instance_role_credentials(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_FATAL_ASSERT(imds_user_data->connection);
    AWS_FATAL_ASSERT(imds_user_data->current_stream == NULL);

    int result = AWS_OP_ERR;
    struct aws_byte_buf uri;
    AWS_ZERO_STRUCT(uri);

    if (imds_user_data->current_result.len == 0) {
        goto cleanup;
    }

    if (aws_byte_buf_init(&uri, imds_user_data->allocator, s_imds_metadata_resource_path->len + imds_user_data->current_result.len)) {
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

    imds_user_data->current_result.len = 0;

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
        AWS_LOGF_WARN(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
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
            aws_mem_acquire(provider->allocator, sizeof(struct aws_credentials_provider_imds_user_data));
    if (wrapped_user_data == NULL) {
        goto error;
    }

    AWS_ZERO_STRUCT(*wrapped_user_data);

    wrapped_user_data->allocator = provider->allocator;
    wrapped_user_data->imds_provider = provider;
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    if (aws_byte_buf_init(&wrapped_user_data->current_result, provider->allocator, 300)) {
        goto error;
    }

    aws_http_connection_manager_acquire_connection(impl->connection_manager, s_imds_on_acquire_connection, wrapped_user_data);

    return AWS_OP_SUCCESS;

    error:

    s_aws_credentials_provider_imds_user_data_destroy(wrapped_user_data);

    return AWS_OP_ERR;
}

static void s_credentials_provider_imds_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_imds_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_http_connection_manager_release(impl->connection_manager);
}

static void s_credentials_provider_imds_shutdown(struct aws_credentials_provider *provider) {
    (void)provider;
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_imds_vtable = {
        .get_credentials = s_credentials_provider_imds_get_credentials_async,
        .clean_up = s_credentials_provider_imds_clean_up,
        .shutdown = s_credentials_provider_imds_shutdown};

struct aws_credentials_provider *aws_credentials_provider_new_imds(
        struct aws_allocator *allocator,
        struct aws_credentials_provider_imds_options *options) {

    (void)options;

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


    struct aws_http_connection_manager_options manager_options;
    AWS_ZERO_STRUCT(manager_options);

    /* TODO: Initialize options */

    impl->connection_manager = aws_http_connection_manager_new(allocator, &manager_options);
    if (impl->connection_manager == NULL) {
        goto on_error;
    }

    return provider;

on_error:

    aws_credentials_provider_destroy(provider);

    return NULL;
}
