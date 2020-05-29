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

struct aws_imds_client {
    struct aws_allocator *allocator;
    struct aws_http_connection_manager *connection_manager;
    struct aws_retry_strategy *retry_strategy;
    struct aws_imds_client_system_vtable *function_table;
    struct aws_imds_client_shutdown_options shutdown_options;
    /* will be set to true by default, means using IMDS V2 */
    bool token_required;
    struct aws_byte_buf cached_token;
    bool cached_token_available;
    bool in_progress_token_update;
    bool token_update_failed;
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
    /* freeing the provider takes place in the shutdown callback below */
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
 * This tracks which request we're on.
 */
enum aws_imds_query_state {
    AWS_IMDS_QS_TOKEN_REQ,
    AWS_IMDS_QS_TOKEN_RESP,
    AWS_IMDS_QS_RESOURCE_REQ,
    AWS_IMDS_QS_RESOURCE_RESP,
    AWS_IMDS_QS_COMPLETE,
    AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK,
    AWS_IMDS_QS_UNRECOVERABLE_ERROR,
    AWS_IMDS_QS_PENDING_DESTROY,
};

/*
 * Tracking structure for each outstanding async query to an imds provider
 */
struct aws_imds_client_user_data {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_imds_client *client;
    aws_imds_client_on_get_resource_callback_fn *original_callback;
    void *original_user_data;

    /* mutable */
    enum aws_imds_query_state query_state;
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_byte_buf current_result;
    struct aws_byte_buf token_result;
    struct aws_string *resource_path;
    struct aws_retry_token *retry_token;
    /*
     * initial value is copy of client->token_required,
     * will be adapted according to response.
     */
    bool token_required;
    int status_code;
    int error_code;

    struct aws_atomic_var ref_count;
    bool callback_invoked;
};

static void s_user_data_destroy(struct aws_imds_client_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }
    struct aws_imds_client *client = user_data->client;

    if (user_data->connection) {
        client->function_table->aws_http_connection_manager_release_connection(
            client->connection_manager, user_data->connection);
    }

    aws_byte_buf_clean_up(&user_data->current_result);
    aws_byte_buf_clean_up(&user_data->token_result);
    aws_string_destroy(user_data->resource_path);

    if (user_data->request) {
        aws_http_message_destroy(user_data->request);
    }
    aws_retry_strategy_release_retry_token(user_data->retry_token);
    aws_imds_client_release(client);
    aws_mem_release(user_data->allocator, user_data);
}

static struct aws_imds_client_user_data *s_user_data_new(
    struct aws_imds_client *client,
    struct aws_byte_cursor resource_path,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data) {

    struct aws_imds_client_user_data *wrapped_user_data =
        aws_mem_calloc(client->allocator, 1, sizeof(struct aws_imds_client_user_data));
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

    if (aws_byte_buf_init(&wrapped_user_data->token_result, client->allocator, IMDS_RESPONSE_TOKEN_SIZE_INITIAL)) {
        goto on_error;
    }

    wrapped_user_data->resource_path =
        aws_string_new_from_array(client->allocator, resource_path.ptr, resource_path.len);
    if (!wrapped_user_data->resource_path) {
        goto on_error;
    }

    wrapped_user_data->token_required = client->token_required;

    if (client->token_required) {
        wrapped_user_data->query_state = AWS_IMDS_QS_TOKEN_REQ;
    } else {
        wrapped_user_data->query_state = AWS_IMDS_QS_RESOURCE_REQ;
    }

    aws_atomic_store_int(&wrapped_user_data->ref_count, 1);

    return wrapped_user_data;

on_error:

    s_user_data_destroy(wrapped_user_data);

    return NULL;
}

static void s_user_data_release(struct aws_imds_client_user_data *user_data) {
    if (!user_data) {
        return;
    }
    size_t old_value = aws_atomic_fetch_sub(&user_data->ref_count, 1);
    if (old_value == 1) {
        s_user_data_destroy(user_data);
    }
}

static void s_user_data_acquire(struct aws_imds_client_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }
    aws_atomic_fetch_add(&user_data->ref_count, 1);
}

static void s_reset_scratch_user_data(struct aws_imds_client_user_data *user_data) {
    user_data->current_result.len = 0;
    user_data->status_code = 0;

    if (user_data->request) {
        aws_http_message_destroy(user_data->request);
        user_data->request = NULL;
    }
}

static bool s_imds_client_should_update_cached_token(struct aws_imds_client *client) {
    return (!client->cached_token_available && !client->in_progress_token_update);
}

static bool s_requester_test_and_try_dominate_cached_token_update(struct aws_imds_client_user_data *user_data) {
    AWS_FATAL_ASSERT(user_data);
    struct aws_imds_client *client = user_data->client;
    aws_mutex_lock(&client->token_lock);
    bool ret = false;
    if (s_imds_client_should_update_cached_token(client)) {
        client->in_progress_token_update = true;
        ret = true;
    }
    aws_mutex_unlock(&client->token_lock);
    return ret;
}

static bool s_imds_client_cached_token_available(void *user_data) {
    struct aws_imds_client *client = user_data;
    return client->cached_token_available;
}

static bool s_imds_client_copy_token_to_user_data_safely(struct aws_imds_client_user_data *user_data) {
    AWS_FATAL_ASSERT(user_data);
    struct aws_imds_client *client = user_data->client;
    aws_mutex_lock(&client->token_lock);
    aws_condition_variable_wait_pred(
        &client->token_signal, &client->token_lock, s_imds_client_cached_token_available, (void *)client);
    if (client->token_update_failed) {
        aws_mutex_unlock(&client->token_lock);
        return false;
    }
    aws_byte_buf_reset(&user_data->token_result, true);
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&client->cached_token);
    aws_byte_buf_append_dynamic(&user_data->token_result, &cursor);
    aws_mutex_unlock(&client->token_lock);
    return true;
}

static void s_requester_try_invalidate_cached_token_safely(struct aws_imds_client_user_data *user_data) {
    AWS_FATAL_ASSERT(user_data);
    aws_mutex_lock(&user_data->client->token_lock);
    if (aws_byte_buf_eq(&user_data->token_result, &user_data->client->cached_token)) {
        user_data->client->cached_token_available = false;
    }
    aws_mutex_unlock(&user_data->client->token_lock);
}

/**
 * Once a requseter returns from token request, it should call this function to unblock all other
 * waiting requesters. When the token parameter is NULL, means the token request failed. Now we need
 * a new requester to acquire the token again.
 */
static void s_imds_client_update_token_safely(struct aws_imds_client *client, struct aws_byte_buf *token) {
    AWS_FATAL_ASSERT(client);
    aws_mutex_lock(&client->token_lock);
    if (token) {
        aws_byte_buf_reset(&client->cached_token, true);
        struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&client->cached_token);
        aws_byte_buf_append_dynamic(&client->cached_token, &cursor);
    } else {
        client->token_update_failed = true;
    }
    client->cached_token_available = true;
    client->in_progress_token_update = false;
    aws_condition_variable_notify_all(&client->token_signal);
    aws_mutex_unlock(&client->token_lock);
}

static int s_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {

    (void)stream;
    (void)data;

    struct aws_imds_client_user_data *imds_user_data = user_data;
    struct aws_imds_client *client = imds_user_data->client;

    AWS_LOGF_DEBUG(AWS_LS_IMDS_CLIENT, "(id=%p) IMDS client received %zu response bytes", (void *)client, data->len);

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

    struct aws_imds_client_user_data *imds_user_data = user_data;
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
                "(id=%p) IMDS client query received http status code %d",
                (void *)client,
                imds_user_data->status_code);
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
    struct aws_imds_client_user_data *user_data,
    const struct aws_byte_cursor *verb,
    const struct aws_byte_cursor *uri,
    const struct aws_http_header *headers,
    size_t header_count) {

    AWS_FATAL_ASSERT(user_data->connection);

    struct aws_http_stream *stream = NULL;
    struct aws_http_message *request = aws_http_message_new_request(user_data->allocator);

    if (request == NULL) {
        return AWS_OP_ERR;
    }

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

    stream =
        user_data->client->function_table->aws_http_connection_make_request(user_data->connection, &request_options);

    if (!stream) {
        goto on_error;
    }

    if (user_data->client->function_table->aws_http_stream_activate(stream)) {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    user_data->client->function_table->aws_http_stream_release(stream);
    aws_http_message_destroy(request);
    return AWS_OP_ERR;
}

typedef void(imds_state_fn)(struct aws_imds_client_user_data *);
static void s_query_resource(struct aws_imds_client_user_data *user_data);

/* Make an http request to put a ttl and hopefully get a token back. */
static void s_query_token(struct aws_imds_client_user_data *user_data) {
    AWS_PRECONDITION(user_data->query_state == AWS_IMDS_QS_TOKEN_REQ);

    /**
     * If this requester shouldn't update token, meaning either the token is available,
     * or the token is updating by other requester, this requester should just either copy
     * token or wait for the update then copy.
     */
    while (!s_requester_test_and_try_dominate_cached_token_update(user_data)) {
        /* if then token copied. */
        if (s_imds_client_copy_token_to_user_data_safely(user_data)) {
            user_data->query_state = AWS_IMDS_QS_RESOURCE_REQ;
            s_query_resource(user_data);
            return;
        }
        /* try dominate the token update */
    }

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

    user_data->query_state = AWS_IMDS_QS_TOKEN_RESP;

    if (s_make_imds_http_query(user_data, &verb, &uri, headers, AWS_ARRAY_SIZE(headers))) {
        user_data->query_state = AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK;
    }
}

/*
 * Process the http response from the token put.
 */
static void s_on_token_response(struct aws_imds_client_user_data *user_data) {
    AWS_PRECONDITION(user_data->query_state == AWS_IMDS_QS_TOKEN_RESP);

    /* Gets 400 means token is required but the request itself failed. */
    if (user_data->status_code == AWS_HTTP_STATUS_CODE_400_BAD_REQUEST) {
        user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        s_imds_client_update_token_safely(user_data->client, NULL);
        return;
    }

    /*
     * Other than that, if meets any error, then token is not required,
     * we should fall back to insecure request. Otherwise, we should use
     * token in following requests.
     */
    if (user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK || user_data->current_result.len == 0) {
        user_data->token_required = false;
    } else {
        struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&(user_data->current_result));
        aws_byte_cursor_trim_pred(&cursor, aws_char_is_space);
        if (cursor.len == 0) {
            user_data->token_required = false;
        } else {
            aws_byte_buf_reset(&user_data->token_result, true /*zero contents*/);
            if (aws_byte_buf_append_and_update(&user_data->token_result, &cursor)) {
                user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
                s_imds_client_update_token_safely(user_data->client, NULL);
                return;
            }
        }
        s_imds_client_update_token_safely(user_data->client, cursor.len == 0 ? NULL : &user_data->token_result);
    }
    s_reset_scratch_user_data(user_data);
    /* No matter token acquire succeeded or not, moving forward to next step. */
    user_data->query_state = AWS_IMDS_QS_RESOURCE_REQ;
}

/*
 * Make the http request to fetch the resource
 */
static void s_query_resource(struct aws_imds_client_user_data *user_data) {
    AWS_PRECONDITION(user_data->query_state == AWS_IMDS_QS_RESOURCE_REQ);

    struct aws_http_header token_header = {
        .name = aws_byte_cursor_from_string(s_imds_token_header),
        .value = aws_byte_cursor_from_buf(&user_data->token_result),
    };

    struct aws_http_header headers[] = {
        token_header,
    };

    size_t headers_count = 0;
    struct aws_http_header *headers_array_ptr = NULL;

    if (user_data->token_required) {
        headers_count = 1;
        headers_array_ptr = headers;
    }

    struct aws_byte_cursor verb = aws_byte_cursor_from_c_str("GET");

    user_data->query_state = AWS_IMDS_QS_RESOURCE_RESP;

    struct aws_byte_cursor path_cursor = aws_byte_cursor_from_string(user_data->resource_path);
    if (s_make_imds_http_query(user_data, &verb, &path_cursor, headers_array_ptr, headers_count)) {
        user_data->query_state = AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK;
        return;
    }
}

/*
 * Process the http response for fetching the role name for the ec2 instance.
 */
static void s_on_resource_response(struct aws_imds_client_user_data *user_data) {
    AWS_PRECONDITION(user_data->query_state == AWS_IMDS_QS_RESOURCE_RESP);

    /* In this case we fallback to the secure imds flow. */
    if (user_data->status_code == AWS_HTTP_STATUS_CODE_401_UNAUTHORIZED) {
        s_requester_try_invalidate_cached_token_safely(user_data);
        s_reset_scratch_user_data(user_data);
        user_data->token_required = true;
        user_data->query_state = AWS_IMDS_QS_TOKEN_REQ;
        return;
    }

    /*
     * At this step, on anything other than a 200, nullify the
     * response and treat as an error
     */
    if (user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK) {
        user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        return;
    }

    if (user_data->current_result.len == 0) {
        user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        return;
    }

    user_data->query_state = AWS_IMDS_QS_COMPLETE;
}

static void s_query_complete(struct aws_imds_client_user_data *user_data) {
    AWS_PRECONDITION(user_data->query_state == AWS_IMDS_QS_COMPLETE);

    user_data->original_callback(&user_data->current_result, user_data->error_code, user_data->original_user_data);
    AWS_LOGF_INFO(
        AWS_LS_IMDS_CLIENT,
        "(id=%p) IMDS client successfully queried resource %s.",
        (void *)user_data->client,
        aws_string_c_str(user_data->resource_path));
}

static void s_query_error(struct aws_imds_client_user_data *user_data) {
    AWS_PRECONDITION(
        user_data->query_state == AWS_IMDS_QS_UNRECOVERABLE_ERROR ||
        user_data->query_state == AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK);

    if (!user_data->callback_invoked) {
        user_data->error_code = aws_last_error();
        if (user_data->error_code == AWS_ERROR_SUCCESS) {
            user_data->error_code = AWS_ERROR_UNKNOWN;
        }
        user_data->original_callback(NULL, user_data->error_code, user_data->original_user_data);
        user_data->callback_invoked = true;
    }
    AWS_LOGF_WARN(
        AWS_LS_IMDS_CLIENT,
        "(id=%p) IMDS client failed to query resource %s.",
        (void *)user_data->client,
        aws_string_c_str(user_data->resource_path));
}

/* Okay, some explanation on this state machine. There are two drivers.
 *
 * Upon receiving a connection from the connection manager, we drive the machine. This should always be in a
 * request state (we assert this) request states are even numbers.
 *
 * Upon receiving a response from the http request, we drive the machine. This should always be in a response state.
 *
 * Each state is responsible for crafting it's own http requests AND processing the meaning of it's own response.
 *
 * For your convenience, the functions in this table are in order above.
 */
static imds_state_fn *s_query_state_machine[] = {
    [AWS_IMDS_QS_TOKEN_REQ] = s_query_token,
    [AWS_IMDS_QS_TOKEN_RESP] = s_on_token_response,
    [AWS_IMDS_QS_RESOURCE_REQ] = s_query_resource,
    [AWS_IMDS_QS_RESOURCE_RESP] = s_on_resource_response,
    [AWS_IMDS_QS_COMPLETE] = s_query_complete,
    [AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK] = s_query_error,
    [AWS_IMDS_QS_UNRECOVERABLE_ERROR] = s_query_error,
};

static inline bool s_state_machine_is_terminal_state(struct aws_imds_client_user_data *user_data) {
    return user_data->query_state >= AWS_IMDS_QS_COMPLETE && user_data->query_state <= AWS_IMDS_QS_UNRECOVERABLE_ERROR;
}

static inline bool s_state_machine_is_request_state(struct aws_imds_client_user_data *user_data) {
    return !s_state_machine_is_terminal_state(user_data) && !(user_data->query_state & 0x01);
}

static inline void s_state_machine_roll_back_to_request_state(struct aws_imds_client_user_data *user_data) {
    AWS_FATAL_ASSERT(
        !s_state_machine_is_terminal_state(user_data) && "State machine can't be rolled back from a terminal state.");
    user_data->query_state -= 1;
    /* request states are evenly numbered. */
    AWS_FATAL_ASSERT(s_state_machine_is_request_state(user_data) && "Can only rollback to a request state.");
}

static void s_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct aws_imds_client_user_data *imds_user_data = user_data;

    AWS_FATAL_ASSERT(
        s_state_machine_is_request_state(user_data) && "Invalid query state, we should be in a request state.")
    imds_user_data->connection = connection;

    bool user_data_destroyed = false;
    if (!connection) {
        AWS_LOGF_WARN(
            AWS_LS_IMDS_CLIENT,
            "id=%p: IMDS Client failed to acquire a connection, error code %d(%s)",
            (void *)imds_user_data->client,
            error_code,
            aws_error_str(error_code));
        imds_user_data->error_code = error_code;
        imds_user_data->query_state = AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK;
    } else {
        /* prevent user_data from being destroyed under the hood. */
        s_user_data_acquire(imds_user_data);
        s_query_state_machine[imds_user_data->query_state](imds_user_data);
        if (imds_user_data->query_state == AWS_IMDS_QS_PENDING_DESTROY) {
            user_data_destroyed = true;
        }
        s_user_data_release(imds_user_data);
    }

    /* there's no universe where we should have moved to COMPLETE, but an error could have occurred. */
    if (!user_data_destroyed && imds_user_data->query_state == AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK) {
        s_query_state_machine[AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK](imds_user_data);
        s_user_data_release(imds_user_data);
    }
}

static void s_on_retry_ready(struct aws_retry_token *token, int error_code, void *user_data) {
    (void)token;

    struct aws_imds_client_user_data *imds_user_data = user_data;
    struct aws_imds_client *client = imds_user_data->client;

    if (!error_code) {
        s_state_machine_roll_back_to_request_state(user_data);
        client->function_table->aws_http_connection_manager_acquire_connection(
            client->connection_manager, s_on_acquire_connection, user_data);
    } else {
        AWS_LOGF_WARN(
            AWS_LS_IMDS_CLIENT,
            "id=%p: IMDS Client failed to retry the request with error code %d(%s)",
            (void *)client,
            error_code,
            aws_error_str(error_code));
        s_query_state_machine[AWS_IMDS_QS_UNRECOVERABLE_ERROR](imds_user_data);
        imds_user_data->query_state = AWS_IMDS_QS_PENDING_DESTROY;
        s_user_data_release(imds_user_data);
    }
}

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_imds_client_user_data *imds_user_data = user_data;
    struct aws_imds_client *client = imds_user_data->client;

    aws_http_message_destroy(imds_user_data->request);
    imds_user_data->request = NULL;

    struct aws_http_connection *connection = client->function_table->aws_http_stream_get_connection(stream);
    client->function_table->aws_http_stream_release(stream);
    client->function_table->aws_http_connection_manager_release_connection(client->connection_manager, connection);

    /* try again, just drop the state from the response to the request state by subtracting one.
     * Don't run the state machine in this callback in this case, let the acquire connection callback handle it.
     * Note these are connection level errors, not http level. Since we obviously connected, it's likely
     * we're on EC2, plus we have max retries so it's likely safer to just retry everything.*/
    if (error_code) {
        AWS_LOGF_WARN(
            AWS_LS_IMDS_CLIENT,
            "id=%p: Connection was closed with error code %d(%s)",
            (void *)client,
            error_code,
            aws_error_str(error_code));
        /* for now we're only going to retry transient errors. If we find IMDS consistently throttles, we'll come back
         * and retry http errors as well. */
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
            /* roll back to the last request we made, and let it retry. */
            imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
            imds_user_data->error_code = error_code;
        }
    } else {
        /* treat everything else as success on the retry token for now. if we decide we need to retry
         * http errors, we'll come back and rework this. */
        if (aws_retry_strategy_token_record_success(imds_user_data->retry_token)) {
            AWS_LOGF_ERROR(
                AWS_LS_IMDS_CLIENT,
                "id=%p: Error while recording successful retry: %s",
                (void *)client,
                aws_error_str(aws_last_error()));
            /* roll back to the last request we made, and let it retry. */
            imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        } else {
            s_query_state_machine[imds_user_data->query_state](imds_user_data);
        }
    }

    /* if there's more work to do, acquire a connection, and run the machine again. */
    if (!s_state_machine_is_terminal_state(imds_user_data)) {
        client->function_table->aws_http_connection_manager_acquire_connection(
            client->connection_manager, s_on_acquire_connection, user_data);
    } else {
        /* terminal state, invoke the terminal state and cleanup. */
        s_query_state_machine[imds_user_data->query_state](imds_user_data);
        imds_user_data->query_state = AWS_IMDS_QS_PENDING_DESTROY;
        s_user_data_release(imds_user_data);
    }
}

static void s_on_retry_token_acquired(
    struct aws_retry_strategy *strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {
    (void)strategy;

    struct aws_imds_client_user_data *imds_user_data = user_data;
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
        s_query_state_machine[AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK](imds_user_data);
        s_user_data_release(imds_user_data);
    }
}

int aws_imds_client_get_resource_async(
    struct aws_imds_client *client,
    struct aws_byte_cursor resource_path,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data) {

    struct aws_imds_client_user_data *wrapped_user_data = s_user_data_new(client, resource_path, callback, user_data);
    if (wrapped_user_data == NULL) {
        goto error;
    }

    if (aws_retry_strategy_acquire_retry_token(
            client->retry_strategy, NULL, s_on_retry_token_acquired, wrapped_user_data, 100)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    s_user_data_release(wrapped_user_data);

    return AWS_OP_ERR;
}
