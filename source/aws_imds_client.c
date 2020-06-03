/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/auth/aws_imds_client.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/socket.h>
#include <ctype.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

/* instance role credentials body response is currently ~ 1300 characters + name length */
#define IMDS_RESPONSE_SIZE_INITIAL 2048
#define IMDS_RESPONSE_TOKEN_SIZE_INITIAL 64
#define IMDS_RESPONSE_SIZE_LIMIT 65535
#define IMDS_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS 2
#define IMDS_DEFAULT_RETRIES 1

enum imds_token_state {
    AWS_IMDS_TS_INVALID,
    AWS_IMDS_TS_VALID,
    AWS_IMDS_TS_UPDATE_IN_PROGRESS,
};

enum imds_token_copy_result {
    /* Token is valid and copied to requester */
    AWS_IMDS_TCR_SUCCESS,
    /* Token is updating, so requester is added in waiting queue */
    AWS_IMDS_TCR_WAITING_IN_QUEUE,
    /* unexpected error,like mem allocation error */
    AWS_IMDS_TCR_UNEXPECTED_ERROR,
};

struct imds_token_query {
    struct aws_linked_list_node node;
    void *user_data;
};

struct aws_imds_client {
    struct aws_allocator *allocator;
    struct aws_http_connection_manager *connection_manager;
    struct aws_retry_strategy *retry_strategy;
    struct aws_imds_client_system_vtable *function_table;
    struct aws_imds_client_shutdown_options shutdown_options;
    /* will be set to true by default, means using IMDS V2 */
    bool token_required;
    struct aws_byte_buf cached_token;
    enum imds_token_state token_state;
    struct aws_linked_list pending_queries;
    struct aws_mutex token_lock;
    struct aws_condition_variable token_signal;

    struct aws_atomic_var ref_count;
};

static struct aws_imds_client_system_vtable s_default_function_table = {
    .aws_http_connection_manager_new = aws_http_connection_manager_new,
    .aws_http_connection_manager_release = aws_http_connection_manager_release,
    .aws_http_connection_manager_acquire_connection = aws_http_connection_manager_acquire_connection,
    .aws_http_connection_manager_release_connection = aws_http_connection_manager_release_connection,
    .aws_http_connection_make_request = aws_http_connection_make_request,
    .aws_http_stream_activate = aws_http_stream_activate,
    .aws_http_stream_get_connection = aws_http_stream_get_connection,
    .aws_http_stream_get_incoming_response_status = aws_http_stream_get_incoming_response_status,
    .aws_http_stream_release = aws_http_stream_release,
    .aws_http_connection_close = aws_http_connection_close,
};

static void s_aws_imds_client_destroy(struct aws_imds_client *client) {
    if (!client) {
        return;
    }
    /**
     * s_aws_imds_client_destroy is only called after all in-flight requests are finished,
     * thus nothing is going to try and access retry_strategy again at this point.
     */
    aws_retry_strategy_release(client->retry_strategy);
    aws_condition_variable_clean_up(&client->token_signal);
    aws_mutex_clean_up(&client->token_lock);
    aws_byte_buf_clean_up(&client->cached_token);
    client->function_table->aws_http_connection_manager_release(client->connection_manager);
    /* freeing the client takes place in the shutdown callback below */
}

static void s_on_connection_manager_shutdown(void *user_data) {
    struct aws_imds_client *client = user_data;

    if (client && client->shutdown_options.shutdown_callback) {
        client->shutdown_options.shutdown_callback(client->shutdown_options.shutdown_user_data);
    }

    aws_mem_release(client->allocator, client);
}

void aws_imds_client_release(struct aws_imds_client *client) {
    if (!client) {
        return;
    }

    size_t old_value = aws_atomic_fetch_sub(&client->ref_count, 1);
    if (old_value == 1) {
        s_aws_imds_client_destroy(client);
    }
}

void aws_imds_client_acquire(struct aws_imds_client *client) {
    aws_atomic_fetch_add(&client->ref_count, 1);
}

struct aws_imds_client *aws_imds_client_new(
    struct aws_allocator *allocator,
    const struct aws_imds_client_options *options) {

    struct aws_imds_client *client = aws_mem_calloc(allocator, 1, sizeof(struct aws_imds_client));
    if (!client) {
        return NULL;
    }

    if (aws_mutex_init(&client->token_lock)) {
        goto on_error;
    }

    if (aws_condition_variable_init(&client->token_signal)) {
        goto on_error;
    }

    if (aws_byte_buf_init(&client->cached_token, allocator, IMDS_RESPONSE_TOKEN_SIZE_INITIAL)) {
        goto on_error;
    }

    aws_linked_list_init(&client->pending_queries);

    aws_atomic_store_int(&client->ref_count, 1);
    client->allocator = allocator;
    client->function_table = options->function_table ? options->function_table : &s_default_function_table;
    client->token_required = options->imds_version == IMDS_PROTOCOL_V1 ? false : true;
    client->shutdown_options = options->shutdown_options;

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
    manager_options.host = aws_byte_cursor_from_c_str("169.254.169.254");
    manager_options.port = 80;
    manager_options.max_connections = 10;
    manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    manager_options.shutdown_complete_user_data = client;

    client->connection_manager = client->function_table->aws_http_connection_manager_new(allocator, &manager_options);
    if (!client->connection_manager) {
        goto on_error;
    }

    if (options->retry_strategy) {
        client->retry_strategy = options->retry_strategy;
        aws_retry_strategy_acquire(client->retry_strategy);
    } else {
        struct aws_exponential_backoff_retry_options retry_options = {
            .el_group = options->bootstrap->event_loop_group,
            .max_retries = IMDS_DEFAULT_RETRIES,
        };
        client->retry_strategy = aws_retry_strategy_new_exponential_backoff(allocator, &retry_options);
    }
    if (!client->retry_strategy) {
        goto on_error;
    }

    return client;

on_error:
    s_aws_imds_client_destroy(client);
    return NULL;
}

/*
 * Tracking structure for each outstanding async query to an imds client
 */
struct imds_user_data {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_imds_client *client;
    aws_imds_client_on_get_resource_callback_fn *original_callback;
    void *original_user_data;

    /* mutable */
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_byte_buf current_result;
    struct aws_byte_buf imds_token;
    struct aws_string *resource_path;
    struct aws_retry_token *retry_token;
    /*
     * initial value is copy of client->token_required,
     * will be adapted according to response.
     */
    bool imds_token_required;
    bool is_imds_token_request;
    int status_code;
    int error_code;

    struct aws_atomic_var ref_count;
};

static void s_user_data_destroy(struct imds_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }
    struct aws_imds_client *client = user_data->client;

    if (user_data->connection) {
        client->function_table->aws_http_connection_manager_release_connection(
            client->connection_manager, user_data->connection);
    }

    aws_byte_buf_clean_up(&user_data->current_result);
    aws_byte_buf_clean_up(&user_data->imds_token);
    aws_string_destroy(user_data->resource_path);

    if (user_data->request) {
        aws_http_message_destroy(user_data->request);
    }
    aws_retry_strategy_release_retry_token(user_data->retry_token);
    aws_imds_client_release(client);
    aws_mem_release(user_data->allocator, user_data);
}

static struct imds_user_data *s_user_data_new(
    struct aws_imds_client *client,
    struct aws_byte_cursor resource_path,
    aws_imds_client_on_get_resource_callback_fn *callback,
    void *user_data) {

    struct imds_user_data *wrapped_user_data = aws_mem_calloc(client->allocator, 1, sizeof(struct imds_user_data));
    if (!wrapped_user_data) {
        goto on_error;
    }

    wrapped_user_data->allocator = client->allocator;
    wrapped_user_data->client = client;
    aws_imds_client_acquire(client);
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    if (aws_byte_buf_init(&wrapped_user_data->current_result, client->allocator, IMDS_RESPONSE_SIZE_INITIAL)) {
        goto on_error;
    }

    if (aws_byte_buf_init(&wrapped_user_data->imds_token, client->allocator, IMDS_RESPONSE_TOKEN_SIZE_INITIAL)) {
        goto on_error;
    }

    wrapped_user_data->resource_path =
        aws_string_new_from_array(client->allocator, resource_path.ptr, resource_path.len);
    if (!wrapped_user_data->resource_path) {
        goto on_error;
    }

    wrapped_user_data->imds_token_required = client->token_required;
    aws_atomic_store_int(&wrapped_user_data->ref_count, 1);
    return wrapped_user_data;

on_error:
    s_user_data_destroy(wrapped_user_data);
    return NULL;
}

static void s_user_data_acquire(struct imds_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }
    aws_atomic_fetch_add(&user_data->ref_count, 1);
}

static void s_user_data_release(struct imds_user_data *user_data) {
    if (!user_data) {
        return;
    }
    size_t old_value = aws_atomic_fetch_sub(&user_data->ref_count, 1);
    if (old_value == 1) {
        s_user_data_destroy(user_data);
    }
}

static void s_reset_scratch_user_data(struct imds_user_data *user_data) {
    user_data->current_result.len = 0;
    user_data->status_code = 0;

    if (user_data->request) {
        aws_http_message_destroy(user_data->request);
        user_data->request = NULL;
    }
}

static enum imds_token_copy_result s_copy_token_safely(struct imds_user_data *user_data);
static void s_invalidate_cached_token_safely(struct imds_user_data *user_data);
static bool s_update_token_safely(struct aws_imds_client *client, struct aws_byte_buf *token, bool token_required);
static void s_query_complete(struct imds_user_data *user_data);
static void s_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data);
static void s_on_retry_token_acquired(struct aws_retry_strategy *, int, struct aws_retry_token *, void *);

static int s_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;
    (void)data;

    struct imds_user_data *imds_user_data = user_data;
    struct aws_imds_client *client = imds_user_data->client;

    if (data->len + imds_user_data->current_result.len > IMDS_RESPONSE_SIZE_LIMIT) {
        client->function_table->aws_http_connection_close(imds_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_IMDS_CLIENT, "(id=%p) IMDS client query response exceeded maximum allowed length", (void *)client);

        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append_dynamic(&imds_user_data->current_result, data)) {
        client->function_table->aws_http_connection_close(imds_user_data->connection);
        AWS_LOGF_ERROR(AWS_LS_IMDS_CLIENT, "(id=%p) IMDS client query error appending response", (void *)client);

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

    struct imds_user_data *imds_user_data = user_data;
    struct aws_imds_client *client = imds_user_data->client;
    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        if (imds_user_data->status_code == 0) {
            if (client->function_table->aws_http_stream_get_incoming_response_status(
                    stream, &imds_user_data->status_code)) {
                AWS_LOGF_ERROR(
                    AWS_LS_IMDS_CLIENT, "(id=%p) IMDS client failed to get http status code", (void *)client);
                return AWS_OP_ERR;
            }
            AWS_LOGF_DEBUG(
                AWS_LS_IMDS_CLIENT,
                "(id=%p) IMDS client query received http status code %d for requester %p.",
                (void *)client,
                imds_user_data->status_code,
                user_data);
        }
    }

    return AWS_OP_SUCCESS;
}

AWS_STATIC_STRING_FROM_LITERAL(s_imds_accept_header, "Accept");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_accept_header_value, "*/*");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_user_agent_header, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_user_agent_header_value, "aws-sdk-crt/aws-imds-client");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_h1_0_keep_alive_header, "Connection");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_h1_0_keep_alive_header_value, "keep-alive");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_token_resource_path, "/latest/api/token");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_token_ttl_header, "x-aws-ec2-metadata-token-ttl-seconds");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_token_header, "x-aws-ec2-metadata-token");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_token_ttl_default_value, "21600");

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data);

static int s_make_imds_http_query(
    struct imds_user_data *user_data,
    const struct aws_byte_cursor *verb,
    const struct aws_byte_cursor *uri,
    const struct aws_http_header *headers,
    size_t header_count) {

    AWS_FATAL_ASSERT(user_data->connection);
    struct aws_imds_client *client = user_data->client;
    struct aws_http_stream *stream = NULL;
    struct aws_http_message *request = aws_http_message_new_request(user_data->allocator);

    if (request == NULL) {
        return AWS_OP_ERR;
    }

    s_user_data_acquire(user_data);

    if (headers && aws_http_message_add_header_array(request, headers, header_count)) {
        goto on_error;
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

    if (aws_http_message_set_request_method(request, *verb)) {
        goto on_error;
    }

    if (aws_http_message_set_request_path(request, *uri)) {
        goto on_error;
    }

    user_data->request = request;

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .on_response_headers = s_on_incoming_headers_fn,
        .on_response_header_block_done = NULL,
        .on_response_body = s_on_incoming_body_fn,
        .on_complete = s_on_stream_complete_fn,
        .user_data = user_data,
        .request = request,
    };

    stream = client->function_table->aws_http_connection_make_request(user_data->connection, &request_options);
    if (!stream || client->function_table->aws_http_stream_activate(stream)) {
        goto on_error;
    }

    s_user_data_release(user_data);
    return AWS_OP_SUCCESS;

on_error:
    user_data->client->function_table->aws_http_stream_release(stream);
    aws_http_message_destroy(request);
    user_data->request = NULL;
    s_user_data_release(user_data);
    return AWS_OP_ERR;
}

/*
 * Process the http response from the token put request.
 */
static void s_client_on_token_response(struct imds_user_data *user_data) {
    /* Gets 400 means token is required but the request itself failed. */
    if (user_data->status_code == AWS_HTTP_STATUS_CODE_400_BAD_REQUEST) {
        s_update_token_safely(user_data->client, NULL, true);
        return;
    }
    /*
     * Other than that, if meets any error, then token is not required,
     * we should fall back to insecure request. Otherwise, we should use
     * token in following requests.
     */
    if (user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK || user_data->current_result.len == 0) {
        s_update_token_safely(user_data->client, NULL, false);
    } else {
        struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&(user_data->current_result));
        aws_byte_cursor_trim_pred(&cursor, aws_char_is_space);
        aws_byte_buf_reset(&user_data->imds_token, true /*zero contents*/);
        if (aws_byte_buf_append_and_update(&user_data->imds_token, &cursor)) {
            s_update_token_safely(user_data->client, NULL, true);
            return;
        }
        s_update_token_safely(user_data->client, cursor.len == 0 ? NULL : &user_data->imds_token, cursor.len != 0);
    }
}

static int s_client_start_query_token(struct aws_imds_client *client) {
    struct imds_user_data *user_data = s_user_data_new(client, aws_byte_cursor_from_c_str(""), NULL, (void *)client);
    if (!user_data) {
        AWS_LOGF_ERROR(
            AWS_LS_IMDS_CLIENT,
            "(id=%p) IMDS client failed to query token with error: %s.",
            (void *)client,
            aws_error_str(aws_last_error()));
        return AWS_OP_ERR;
    }
    user_data->is_imds_token_request = true;
    if (aws_retry_strategy_acquire_retry_token(
            client->retry_strategy, NULL, s_on_retry_token_acquired, user_data, 100)) {
        s_user_data_release(user_data);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/* Make an http request to put a ttl and hopefully get a token back. */
static void s_client_do_query_token(struct imds_user_data *user_data) {
    /* start query token for imds client */
    struct aws_byte_cursor uri = aws_byte_cursor_from_string(s_imds_token_resource_path);

    struct aws_http_header token_ttl_header = {
        .name = aws_byte_cursor_from_string(s_imds_token_ttl_header),
        .value = aws_byte_cursor_from_string(s_imds_token_ttl_default_value),
    };

    struct aws_http_header headers[] = {
        token_ttl_header,
    };

    struct aws_byte_cursor verb = aws_byte_cursor_from_c_str("PUT");

    if (s_make_imds_http_query(user_data, &verb, &uri, headers, AWS_ARRAY_SIZE(headers))) {
        user_data->error_code = aws_last_error();
        if (user_data->error_code == AWS_ERROR_SUCCESS) {
            user_data->error_code = AWS_ERROR_UNKNOWN;
        }
        s_query_complete(user_data);
    }
}

/*
 * Make the http request to fetch the resource
 */
static void s_do_query_resource(struct imds_user_data *user_data) {

    struct aws_http_header token_header = {
        .name = aws_byte_cursor_from_string(s_imds_token_header),
        .value = aws_byte_cursor_from_buf(&user_data->imds_token),
    };

    struct aws_http_header headers[] = {
        token_header,
    };

    size_t headers_count = 0;
    struct aws_http_header *headers_array_ptr = NULL;

    if (user_data->imds_token_required) {
        headers_count = 1;
        headers_array_ptr = headers;
    }

    struct aws_byte_cursor verb = aws_byte_cursor_from_c_str("GET");

    struct aws_byte_cursor path_cursor = aws_byte_cursor_from_string(user_data->resource_path);
    if (s_make_imds_http_query(user_data, &verb, &path_cursor, headers_array_ptr, headers_count)) {
        user_data->error_code = aws_last_error();
        if (user_data->error_code == AWS_ERROR_SUCCESS) {
            user_data->error_code = AWS_ERROR_UNKNOWN;
        }
        s_query_complete(user_data);
    }
}

int s_get_resource_async_with_imds_token(struct imds_user_data *user_data);

static void s_query_complete(struct imds_user_data *user_data) {
    if (user_data->is_imds_token_request) {
        s_client_on_token_response(user_data);
        s_user_data_release(user_data);
        return;
    }

    /* In this case we fallback to the secure imds flow. */
    if (user_data->status_code == AWS_HTTP_STATUS_CODE_401_UNAUTHORIZED) {
        s_invalidate_cached_token_safely(user_data);
        s_reset_scratch_user_data(user_data);
        aws_retry_strategy_release_retry_token(user_data->retry_token);
        if (s_get_resource_async_with_imds_token(user_data)) {
            s_user_data_release(user_data);
        }
        return;
    }

    user_data->original_callback(
        user_data->error_code ? NULL : &user_data->current_result,
        user_data->error_code,
        user_data->original_user_data);

    s_user_data_release(user_data);
}

static void s_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct imds_user_data *imds_user_data = user_data;
    imds_user_data->connection = connection;

    if (!connection) {
        AWS_LOGF_WARN(
            AWS_LS_IMDS_CLIENT,
            "id=%p: IMDS Client failed to acquire a connection, error code %d(%s)",
            (void *)imds_user_data->client,
            error_code,
            aws_error_str(error_code));
        imds_user_data->error_code = error_code;
        s_query_complete(imds_user_data);
        return;
    }

    if (imds_user_data->is_imds_token_request) {
        s_client_do_query_token(imds_user_data);
    } else {
        s_do_query_resource(imds_user_data);
    }
}

static void s_on_retry_ready(struct aws_retry_token *token, int error_code, void *user_data) {
    (void)token;

    struct imds_user_data *imds_user_data = user_data;
    struct aws_imds_client *client = imds_user_data->client;

    if (!error_code) {
        client->function_table->aws_http_connection_manager_acquire_connection(
            client->connection_manager, s_on_acquire_connection, user_data);
    } else {
        AWS_LOGF_WARN(
            AWS_LS_IMDS_CLIENT,
            "id=%p: IMDS Client failed to retry the request with error code %d(%s)",
            (void *)client,
            error_code,
            aws_error_str(error_code));
        imds_user_data->error_code = error_code;
        s_query_complete(imds_user_data);
    }
}

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct imds_user_data *imds_user_data = user_data;
    struct aws_imds_client *client = imds_user_data->client;

    aws_http_message_destroy(imds_user_data->request);
    imds_user_data->request = NULL;
    imds_user_data->connection = NULL;

    struct aws_http_connection *connection = client->function_table->aws_http_stream_get_connection(stream);
    client->function_table->aws_http_stream_release(stream);
    client->function_table->aws_http_connection_manager_release_connection(client->connection_manager, connection);

    /* on encountering error, see if we could try again */
    if (error_code) {
        AWS_LOGF_WARN(
            AWS_LS_IMDS_CLIENT,
            "id=%p: Connection was closed with error code %d(%s)",
            (void *)client,
            error_code,
            aws_error_str(error_code));

        if (!aws_retry_strategy_schedule_retry(
                imds_user_data->retry_token, AWS_RETRY_ERROR_TYPE_TRANSIENT, s_on_retry_ready, user_data)) {
            AWS_LOGF_DEBUG(
                AWS_LS_IMDS_CLIENT,
                "id=%p: Connection was closed, retrying the last request on a new connection.",
                (void *)client);
            return;
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_IMDS_CLIENT, "id=%p: Connection was closed, retries have been exhausted.", (void *)client);
            imds_user_data->error_code = error_code;
        }
    } else if (aws_retry_strategy_token_record_success(imds_user_data->retry_token)) {
        AWS_LOGF_ERROR(
            AWS_LS_IMDS_CLIENT,
            "id=%p: Error while recording successful retry: %s",
            (void *)client,
            aws_error_str(aws_last_error()));
    }

    s_query_complete(imds_user_data);
}

static void s_on_retry_token_acquired(
    struct aws_retry_strategy *strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {
    (void)strategy;

    struct imds_user_data *imds_user_data = user_data;
    struct aws_imds_client *client = imds_user_data->client;

    if (!error_code) {
        AWS_LOGF_WARN(AWS_LS_IMDS_CLIENT, "id=%p: IMDS Client successfully acquired retry token.", (void *)client);
        imds_user_data->retry_token = token;
        client->function_table->aws_http_connection_manager_acquire_connection(
            client->connection_manager, s_on_acquire_connection, imds_user_data);
    } else {
        AWS_LOGF_WARN(
            AWS_LS_IMDS_CLIENT,
            "id=%p: IMDS Client failed to acquire retry token, error code %d(%s)",
            (void *)client,
            error_code,
            aws_error_str(error_code));
        imds_user_data->error_code = error_code;
        s_query_complete(imds_user_data);
    }
}

static enum imds_token_copy_result s_copy_token_safely(struct imds_user_data *user_data) {
    struct aws_imds_client *client = user_data->client;
    enum imds_token_copy_result ret = AWS_IMDS_TCR_UNEXPECTED_ERROR;

    struct aws_linked_list pending_queries;
    aws_linked_list_init(&pending_queries);
    aws_mutex_lock(&client->token_lock);

    if (client->token_state == AWS_IMDS_TS_VALID) {
        aws_byte_buf_reset(&user_data->imds_token, true);
        struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&client->cached_token);
        if (aws_byte_buf_append_dynamic(&user_data->imds_token, &cursor)) {
            ret = AWS_IMDS_TCR_UNEXPECTED_ERROR;
        } else {
            ret = AWS_IMDS_TCR_SUCCESS;
        }
    } else {
        ret = AWS_IMDS_TCR_WAITING_IN_QUEUE;
        struct imds_token_query *query = aws_mem_calloc(client->allocator, 1, sizeof(struct imds_token_query));
        if (query != NULL) {
            query->user_data = user_data;
            aws_linked_list_push_back(&client->pending_queries, &query->node);
        } else {
            ret = AWS_IMDS_TCR_UNEXPECTED_ERROR;
        }

        if (client->token_state == AWS_IMDS_TS_INVALID) {
            if (s_client_start_query_token(client)) {
                ret = AWS_IMDS_TCR_UNEXPECTED_ERROR;
                aws_linked_list_swap_contents(&pending_queries, &client->pending_queries);
            } else {
                client->token_state = AWS_IMDS_TS_UPDATE_IN_PROGRESS;
            }
        }
    }
    aws_mutex_unlock(&client->token_lock);

    /* poll swapped out pending queries if there is any */
    while (!aws_linked_list_empty(&pending_queries)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_back(&pending_queries);
        struct imds_token_query *query = AWS_CONTAINER_OF(node, struct imds_token_query, node);
        struct imds_user_data *requester = query->user_data;
        aws_mem_release(client->allocator, query);

        requester->error_code = aws_last_error();
        if (requester->error_code == AWS_ERROR_SUCCESS) {
            requester->error_code = AWS_ERROR_UNKNOWN;
        }
        s_query_complete(requester);
    }

    switch (ret) {
        case AWS_IMDS_TCR_SUCCESS:
            AWS_LOGF_DEBUG(
                AWS_LS_IMDS_CLIENT,
                "(id=%p) IMDS client copied token to requester %p successfully.",
                (void *)client,
                (void *)user_data);
            break;

        case AWS_IMDS_TCR_WAITING_IN_QUEUE:
            AWS_LOGF_DEBUG(
                AWS_LS_IMDS_CLIENT, "(id=%p) IMDS client's token is invalid and is now updating.", (void *)client);
            break;

        case AWS_IMDS_TCR_UNEXPECTED_ERROR:
            AWS_LOGF_DEBUG(
                AWS_LS_IMDS_CLIENT,
                "(id=%p) IMDS client encountered unexpected error when processing token query for requester %p, error: "
                "%s.",
                (void *)client,
                (void *)user_data,
                aws_error_str(aws_last_error()));
            break;
    }
    return ret;
}

static void s_invalidate_cached_token_safely(struct imds_user_data *user_data) {
    bool invalidated = false;
    struct aws_imds_client *client = user_data->client;
    aws_mutex_lock(&client->token_lock);
    if (aws_byte_buf_eq(&user_data->imds_token, &client->cached_token)) {
        client->token_state = AWS_IMDS_TS_INVALID;
        invalidated = true;
    }
    aws_mutex_unlock(&client->token_lock);
    if (invalidated) {
        AWS_LOGF_DEBUG(
            AWS_LS_IMDS_CLIENT,
            "(id=%p) IMDS client's cached token is set to be invalid by requester %p.",
            (void *)client,
            (void *)user_data);
    }
}

/**
 * Once a requseter returns from token request, it should call this function to unblock all other
 * waiting requesters. When the token parameter is NULL, means the token request failed. Now we need
 * a new requester to acquire the token again.
 */
static bool s_update_token_safely(struct aws_imds_client *client, struct aws_byte_buf *token, bool token_required) {
    AWS_FATAL_ASSERT(client);
    bool updated = false;

    struct aws_linked_list pending_queries;
    aws_linked_list_init(&pending_queries);

    aws_mutex_lock(&client->token_lock);
    client->token_required = token_required;
    if (token) {
        aws_byte_buf_reset(&client->cached_token, true);
        struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&client->cached_token);
        if (aws_byte_buf_append_dynamic(&client->cached_token, &cursor) == AWS_OP_SUCCESS) {
            client->token_state = AWS_IMDS_TS_VALID;
            updated = true;
        }
    } else {
        client->token_state = AWS_IMDS_TS_INVALID;
    }
    aws_linked_list_swap_contents(&pending_queries, &client->pending_queries);
    aws_mutex_unlock(&client->token_lock);

    /* poll all pending queries if there is any */
    while (!aws_linked_list_empty(&pending_queries)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_back(&pending_queries);
        struct imds_token_query *query = AWS_CONTAINER_OF(node, struct imds_token_query, node);
        struct imds_user_data *user_data = query->user_data;
        aws_mem_release(client->allocator, query);

        bool success = true;
        user_data->imds_token_required = token_required;
        if (token) {
            aws_byte_buf_reset(&user_data->imds_token, true);
            struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(token);
            if (aws_byte_buf_append_dynamic(&user_data->imds_token, &cursor)) {
                AWS_LOGF_ERROR(
                    AWS_LS_IMDS_CLIENT,
                    "(id=%p) IMDS client failed to copy IMDS token for requester %p.",
                    (void *)client,
                    (void *)user_data);
                success = false;
            }
        } else if (token_required) {
            success = false;
        }

        if (success && aws_retry_strategy_acquire_retry_token(
                           client->retry_strategy, NULL, s_on_retry_token_acquired, user_data, 100)) {
            AWS_LOGF_ERROR(
                AWS_LS_IMDS_CLIENT,
                "(id=%p) IMDS client failed to allocate retry token for requester %p to send resource request.",
                (void *)client,
                (void *)user_data);
            success = false;
        }

        if (!success) {
            user_data->error_code = aws_last_error();
            if (user_data->error_code == AWS_ERROR_SUCCESS) {
                user_data->error_code = AWS_ERROR_UNKNOWN;
            }
            s_query_complete(user_data);
        }
    }

    if (updated) {
        AWS_LOGF_DEBUG(
            AWS_LS_IMDS_CLIENT, "(id=%p) IMDS client updated the cached token successfully.", (void *)client);
    } else {
        AWS_LOGF_ERROR(AWS_LS_IMDS_CLIENT, "(id=%p) IMDS client failed to update the token from IMDS.", (void *)client);
    }
    return updated;
}

int s_get_resource_async_with_imds_token(struct imds_user_data *user_data) {
    enum imds_token_copy_result res = s_copy_token_safely(user_data);
    if (res == AWS_IMDS_TCR_UNEXPECTED_ERROR) {
        return AWS_OP_ERR;
    }

    if (res == AWS_IMDS_TCR_WAITING_IN_QUEUE) {
        return AWS_OP_SUCCESS;
    }

    if (aws_retry_strategy_acquire_retry_token(
            user_data->client->retry_strategy, NULL, s_on_retry_token_acquired, user_data, 100)) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

int aws_imds_client_get_resource_async(
    struct aws_imds_client *client,
    struct aws_byte_cursor resource_path,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data) {

    struct imds_user_data *wrapped_user_data = s_user_data_new(client, resource_path, callback, user_data);
    if (wrapped_user_data == NULL) {
        goto error;
    }

    if (!wrapped_user_data->imds_token_required) {
        if (aws_retry_strategy_acquire_retry_token(
                client->retry_strategy, NULL, s_on_retry_token_acquired, wrapped_user_data, 100)) {
            goto error;
        }
    } else if (s_get_resource_async_with_imds_token(wrapped_user_data)) {
        goto error;
    }
    return AWS_OP_SUCCESS;

error:
    s_user_data_release(wrapped_user_data);

    return AWS_OP_ERR;
}
