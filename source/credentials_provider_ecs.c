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
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/date_time.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

/* ecs task role credentials body response is currently ~ 1300 characters + name length */
#define ECS_RESPONSE_SIZE_INITIAL 2048
#define ECS_RESPONSE_SIZE_LIMIT 10000
#define ECS_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS 2

struct aws_credentials_provider_ecs_impl {
    struct aws_http_connection_manager *connection_manager;
    struct aws_credentials_provider_system_vtable *function_table;
    struct aws_string *path_and_query;
    struct aws_string *auth_token;
    struct aws_tls_ctx *ctx;
    struct aws_tls_connection_options connection_options;
    bool owns_ctx;
};

static struct aws_credentials_provider_system_vtable s_default_function_table = {
    .aws_http_connection_manager_new = aws_http_connection_manager_new,
    .aws_http_connection_manager_release = aws_http_connection_manager_release,
    .aws_http_connection_manager_acquire_connection = aws_http_connection_manager_acquire_connection,
    .aws_http_connection_manager_release_connection = aws_http_connection_manager_release_connection,
    .aws_http_connection_make_request = aws_http_connection_make_request,
    .aws_http_stream_activate = aws_http_stream_activate,
    .aws_http_stream_get_incoming_response_status = aws_http_stream_get_incoming_response_status,
    .aws_http_stream_release = aws_http_stream_release,
    .aws_http_connection_close = aws_http_connection_close};

/*
 * Tracking structure for each outstanding async query to an ecs provider
 */
struct aws_credentials_provider_ecs_user_data {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_credentials_provider *ecs_provider;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;

    /* mutable */
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_byte_buf current_result;
    int status_code;
};

static void s_aws_credentials_provider_ecs_user_data_destroy(struct aws_credentials_provider_ecs_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    struct aws_credentials_provider_ecs_impl *impl = user_data->ecs_provider->impl;

    if (user_data->connection) {
        impl->function_table->aws_http_connection_manager_release_connection(
            impl->connection_manager, user_data->connection);
    }

    aws_byte_buf_clean_up(&user_data->current_result);

    if (user_data->request) {
        aws_http_message_destroy(user_data->request);
    }
    aws_credentials_provider_release(user_data->ecs_provider);
    aws_mem_release(user_data->allocator, user_data);
}

static struct aws_credentials_provider_ecs_user_data *s_aws_credentials_provider_ecs_user_data_new(
    struct aws_credentials_provider *ecs_provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_ecs_user_data *wrapped_user_data =
        aws_mem_calloc(ecs_provider->allocator, 1, sizeof(struct aws_credentials_provider_ecs_user_data));
    if (wrapped_user_data == NULL) {
        goto on_error;
    }

    wrapped_user_data->allocator = ecs_provider->allocator;
    wrapped_user_data->ecs_provider = ecs_provider;
    aws_credentials_provider_acquire(ecs_provider);
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    if (aws_byte_buf_init(&wrapped_user_data->current_result, ecs_provider->allocator, ECS_RESPONSE_SIZE_INITIAL)) {
        goto on_error;
    }

    return wrapped_user_data;

on_error:

    s_aws_credentials_provider_ecs_user_data_destroy(wrapped_user_data);

    return NULL;
}

static void s_aws_credentials_provider_ecs_user_data_reset_response(
    struct aws_credentials_provider_ecs_user_data *ecs_user_data) {
    ecs_user_data->current_result.len = 0;
    ecs_user_data->status_code = 0;

    if (ecs_user_data->request) {
        aws_http_message_destroy(ecs_user_data->request);
        ecs_user_data->request = NULL;
    }
}

AWS_STATIC_STRING_FROM_LITERAL(s_empty_string, "\0");
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_name, "AccessKeyId");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_name, "SecretAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_name, "Token");
AWS_STATIC_STRING_FROM_LITERAL(s_creds_expiration_name, "Expiration");
/*
 * In general, the ECS document looks something like:

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
static struct aws_credentials *s_parse_credentials_from_ecs_document(
    struct aws_allocator *allocator,
    struct aws_byte_buf *document) {

    struct aws_credentials *credentials = NULL;
    cJSON *document_root = NULL;
    bool success = false;
    bool parse_error = true;
    struct aws_byte_cursor null_terminator_cursor = aws_byte_cursor_from_string(s_empty_string);
    if (aws_byte_buf_append_dynamic(document, &null_terminator_cursor)) {
        parse_error = false;
        goto done;
    }

    document_root = cJSON_Parse((const char *)document->buffer);
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse ECS response as Json document.");
        goto done;
    }

    /*
     * Pull out the three credentials components
     */
    cJSON *access_key_id = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_access_key_id_name));
    if (!cJSON_IsString(access_key_id) || (access_key_id->valuestring == NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse AccessKeyId from ECS response Json document.");
        goto done;
    }

    cJSON *secret_access_key =
        cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_secret_access_key_name));
    if (!cJSON_IsString(secret_access_key) || (secret_access_key->valuestring == NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse SecretAccessKey from ECS response Json document.");
        goto done;
    }

    cJSON *session_token = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_session_token_name));
    if (!cJSON_IsString(session_token) || (session_token->valuestring == NULL)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Token from ECS response Json document.");
        goto done;
    }

    cJSON *creds_expiration =
        cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_creds_expiration_name));
    if (!cJSON_IsString(creds_expiration) || (creds_expiration->valuestring == NULL)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Expiration from ECS response Json document.");
        goto done;
    }

    /*
     * Build the credentials
     */
    struct aws_byte_cursor access_key_id_cursor = aws_byte_cursor_from_c_str(access_key_id->valuestring);
    struct aws_byte_cursor secret_access_key_cursor = aws_byte_cursor_from_c_str(secret_access_key->valuestring);
    struct aws_byte_cursor session_token_cursor = aws_byte_cursor_from_c_str(session_token->valuestring);
    struct aws_byte_cursor creds_expiration_cursor = aws_byte_cursor_from_c_str(creds_expiration->valuestring);

    if (access_key_id_cursor.len == 0 || secret_access_key_cursor.len == 0 || session_token_cursor.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "ECS credentials provider received unexpected credentials response,"
            " either access key, secret key or token is empty.")
        goto done;
    }

    credentials = aws_credentials_new_from_cursors(
        allocator, &access_key_id_cursor, &secret_access_key_cursor, &session_token_cursor);

    if (credentials == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "ECS credentials provider failed to allocate memory for credentials.");
        parse_error = false;
        goto done;
    }

    if (creds_expiration_cursor.len != 0) {
        struct aws_date_time expiration;
        if (aws_date_time_init_from_str_cursor(&expiration, &creds_expiration_cursor, AWS_DATE_FORMAT_ISO_8601) ==
            AWS_OP_ERR) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Expiration in ECS response Json document is not a valid ISO_8601 date string.");
            aws_credentials_destroy(credentials);
            credentials = NULL;
            goto done;
        }
        credentials->expiration_timepoint_seconds = (uint64_t)aws_date_time_as_epoch_secs(&expiration);
    }
    success = true;
done:
    if (!success && parse_error) {
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
    }

    if (document_root != NULL) {
        cJSON_Delete(document_root);
    }

    return credentials;
}

/*
 * No matter the result, this always gets called assuming that esc_user_data is successfully allocated
 */
static void s_ecs_finalize_get_credentials_query(struct aws_credentials_provider_ecs_user_data *ecs_user_data) {
    /* Try to build credentials from whatever, if anything, was in the result */
    struct aws_credentials *credentials =
        s_parse_credentials_from_ecs_document(ecs_user_data->allocator, &ecs_user_data->current_result);

    if (credentials != NULL) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) ECS credentials provider successfully queried instance role credentials",
            (void *)ecs_user_data->ecs_provider);
    } else {
        AWS_LOGF_WARN(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) ECS credentials provider failed to query instance role credentials",
            (void *)ecs_user_data->ecs_provider);
    }

    /* pass the credentials back */
    ecs_user_data->original_callback(credentials, ecs_user_data->original_user_data);

    /* clean up */
    s_aws_credentials_provider_ecs_user_data_destroy(ecs_user_data);
    aws_credentials_destroy(credentials);
}

static int s_ecs_on_incoming_body_fn(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;

    struct aws_credentials_provider_ecs_user_data *ecs_user_data = user_data;
    struct aws_credentials_provider_ecs_impl *impl = ecs_user_data->ecs_provider->impl;

    AWS_LOGF_TRACE(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) ECS credentials provider received %zu response bytes",
        (void *)ecs_user_data->ecs_provider,
        data->len);

    if (data->len + ecs_user_data->current_result.len > ECS_RESPONSE_SIZE_LIMIT) {
        impl->function_table->aws_http_connection_close(ecs_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) ECS credentials provider query response exceeded maximum allowed length",
            (void *)ecs_user_data->ecs_provider);

        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (aws_byte_buf_append_dynamic(&ecs_user_data->current_result, data)) {
        impl->function_table->aws_http_connection_close(ecs_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) ECS credentials provider query error appending response",
            (void *)ecs_user_data->ecs_provider);

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_ecs_on_incoming_headers_fn(
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

    struct aws_credentials_provider_ecs_user_data *ecs_user_data = user_data;
    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        if (ecs_user_data->status_code == 0) {
            struct aws_credentials_provider_ecs_impl *impl = ecs_user_data->ecs_provider->impl;
            if (impl->function_table->aws_http_stream_get_incoming_response_status(
                    stream, &ecs_user_data->status_code)) {

                AWS_LOGF_ERROR(
                    AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                    "(id=%p) ECS credentials provider failed to get http status code",
                    (void *)ecs_user_data->ecs_provider);

                return AWS_OP_ERR;
            }
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) ECS credentials provider query received http status code %d",
                (void *)ecs_user_data->ecs_provider,
                ecs_user_data->status_code);
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_ecs_query_task_role_credentials(struct aws_credentials_provider_ecs_user_data *ecs_user_data);

static void s_ecs_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_credentials_provider_ecs_user_data *ecs_user_data = user_data;

    aws_http_message_destroy(ecs_user_data->request);
    ecs_user_data->request = NULL;

    struct aws_credentials_provider_ecs_impl *impl = ecs_user_data->ecs_provider->impl;
    impl->function_table->aws_http_stream_release(stream);

    /*
     * On anything other than a 200, nullify the response and pretend there was
     * an error
     */
    if (ecs_user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK || error_code != AWS_OP_SUCCESS) {
        ecs_user_data->current_result.len = 0;
    }

    s_ecs_finalize_get_credentials_query(ecs_user_data);
}

AWS_STATIC_STRING_FROM_LITERAL(s_ecs_accept_header, "Accept");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_accept_header_value, "*/*");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_user_agent_header, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_user_agent_header_value, "aws-sdk-crt/ecs-credentials-provider");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_h1_0_keep_alive_header, "Connection");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_h1_0_keep_alive_header_value, "keep-alive");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_authorization_header, "authorization");

static int s_make_ecs_http_query(
    struct aws_credentials_provider_ecs_user_data *ecs_user_data,
    struct aws_byte_cursor *uri) {
    AWS_FATAL_ASSERT(ecs_user_data->connection);

    struct aws_http_stream *stream = NULL;
    struct aws_http_message *request = aws_http_message_new_request(ecs_user_data->allocator);
    if (request == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_credentials_provider_ecs_impl *impl = ecs_user_data->ecs_provider->impl;

    struct aws_http_header auth_header = {
        .name = aws_byte_cursor_from_string(s_ecs_authorization_header),
        .value = aws_byte_cursor_from_string(impl->auth_token),
    };
    if (aws_http_message_add_header(request, auth_header)) {
        goto on_error;
    }

    struct aws_http_header accept_header = {
        .name = aws_byte_cursor_from_string(s_ecs_accept_header),
        .value = aws_byte_cursor_from_string(s_ecs_accept_header_value),
    };
    if (aws_http_message_add_header(request, accept_header)) {
        goto on_error;
    }

    struct aws_http_header user_agent_header = {
        .name = aws_byte_cursor_from_string(s_ecs_user_agent_header),
        .value = aws_byte_cursor_from_string(s_ecs_user_agent_header_value),
    };
    if (aws_http_message_add_header(request, user_agent_header)) {
        goto on_error;
    }

    struct aws_http_header keep_alive_header = {
        .name = aws_byte_cursor_from_string(s_ecs_h1_0_keep_alive_header),
        .value = aws_byte_cursor_from_string(s_ecs_h1_0_keep_alive_header_value),
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

    ecs_user_data->request = request;

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .on_response_headers = s_ecs_on_incoming_headers_fn,
        .on_response_header_block_done = NULL,
        .on_response_body = s_ecs_on_incoming_body_fn,
        .on_complete = s_ecs_on_stream_complete_fn,
        .user_data = ecs_user_data,
        .request = request,
    };

    stream = impl->function_table->aws_http_connection_make_request(ecs_user_data->connection, &request_options);

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

static void s_ecs_query_task_role_credentials(struct aws_credentials_provider_ecs_user_data *ecs_user_data) {
    AWS_FATAL_ASSERT(ecs_user_data->connection);

    struct aws_credentials_provider_ecs_impl *impl = ecs_user_data->ecs_provider->impl;

    /* "Clear" the result */
    s_aws_credentials_provider_ecs_user_data_reset_response(ecs_user_data);

    struct aws_byte_cursor uri_cursor = aws_byte_cursor_from_string(impl->path_and_query);
    if (s_make_ecs_http_query(ecs_user_data, &uri_cursor) == AWS_OP_ERR) {
        s_ecs_finalize_get_credentials_query(ecs_user_data);
    }
}

static void s_ecs_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct aws_credentials_provider_ecs_user_data *ecs_user_data = user_data;

    if (connection == NULL) {
        AWS_LOGF_WARN(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "id=%p: ECS provider failed to acquire a connection, error code %d(%s)",
            (void *)ecs_user_data->ecs_provider,
            error_code,
            aws_error_str(error_code));

        s_ecs_finalize_get_credentials_query(ecs_user_data);
        return;
    }

    ecs_user_data->connection = connection;

    s_ecs_query_task_role_credentials(ecs_user_data);
}

static int s_credentials_provider_ecs_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_ecs_impl *impl = provider->impl;

    struct aws_credentials_provider_ecs_user_data *wrapped_user_data =
        s_aws_credentials_provider_ecs_user_data_new(provider, callback, user_data);
    if (wrapped_user_data == NULL) {
        goto error;
    }

    impl->function_table->aws_http_connection_manager_acquire_connection(
        impl->connection_manager, s_ecs_on_acquire_connection, wrapped_user_data);

    return AWS_OP_SUCCESS;

error:

    s_aws_credentials_provider_ecs_user_data_destroy(wrapped_user_data);

    return AWS_OP_ERR;
}

static void s_credentials_provider_ecs_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_ecs_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    impl->function_table->aws_http_connection_manager_release(impl->connection_manager);

    aws_string_destroy(impl->path_and_query);
    aws_string_destroy(impl->auth_token);
    if (impl->owns_ctx) {
        aws_tls_ctx_destroy(impl->ctx);
    }
    aws_tls_connection_options_clean_up(&impl->connection_options);

    /* freeing the provider takes place in the shutdown callback below */
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_ecs_vtable = {
    .get_credentials = s_credentials_provider_ecs_get_credentials_async,
    .destroy = s_credentials_provider_ecs_destroy,
};

static void s_on_connection_manager_shutdown(void *user_data) {
    struct aws_credentials_provider *provider = user_data;

    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_mem_release(provider->allocator, provider);
}

struct aws_credentials_provider *aws_credentials_provider_new_ecs(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_ecs_options *options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_ecs_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_ecs_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_ecs_vtable, impl);

    if (options->use_tls) {
        AWS_LOGF_TRACE(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): tls context not provided, initializing a new one",
            (void *)provider);
        struct aws_tls_ctx_options tls_options;
        aws_tls_ctx_options_init_default_client(&tls_options, allocator);
        impl->ctx = aws_tls_client_ctx_new(allocator, &tls_options);

        if (!impl->ctx) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p): failed to create a tls context with error %s",
                (void *)provider,
                aws_error_debug_str(aws_last_error()));
            aws_tls_ctx_options_clean_up(&tls_options);
            goto on_error;
        }

        impl->owns_ctx = true;
        aws_tls_connection_options_init_from_ctx(&impl->connection_options, impl->ctx);
        struct aws_byte_cursor host = options->host;
        if (aws_tls_connection_options_set_server_name(&impl->connection_options, allocator, &host)) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p): failed to create a tls connection options with error %s",
                (void *)provider,
                aws_error_debug_str(aws_last_error()));
            goto on_error;
        }
    }

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV4;
    socket_options.connect_timeout_ms = (uint32_t)aws_timestamp_convert(
        ECS_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);

    struct aws_http_connection_manager_options manager_options;
    AWS_ZERO_STRUCT(manager_options);
    manager_options.bootstrap = options->bootstrap;
    manager_options.initial_window_size = ECS_RESPONSE_SIZE_LIMIT;
    manager_options.socket_options = &socket_options;
    manager_options.host = options->host;
    manager_options.port = impl->owns_ctx ? 443 : 80;
    manager_options.max_connections = 2;
    manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    manager_options.shutdown_complete_user_data = provider;
    manager_options.tls_connection_options = impl->owns_ctx ? &(impl->connection_options) : NULL;

    impl->function_table = options->function_table;
    if (impl->function_table == NULL) {
        impl->function_table = &s_default_function_table;
    }

    impl->connection_manager = impl->function_table->aws_http_connection_manager_new(allocator, &manager_options);
    if (impl->connection_manager == NULL) {
        goto on_error;
    }
    if (options->auth_token.len != 0) {
        impl->auth_token = aws_string_new_from_array(allocator, options->auth_token.ptr, options->auth_token.len);
        if (impl->auth_token == NULL) {
            goto on_error;
        }
    }
    impl->path_and_query =
        aws_string_new_from_array(allocator, options->path_and_query.ptr, options->path_and_query.len);
    if (impl->path_and_query == NULL) {
        goto on_error;
    }
    provider->shutdown_options = options->shutdown_options;

    return provider;

on_error:

    aws_credentials_provider_destroy(provider);

    return NULL;
}
