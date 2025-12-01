/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>
#include <aws/auth/private/aws_http_credentials_provider.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#define HTTP_RESPONSE_SIZE_INITIAL 2048
#define HTTP_RESPONSE_SIZE_LIMIT 10000
#define HTTP_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS 2
#define HTTP_MAX_ATTEMPTS 3
#define HTTP_RETRY_TIMEOUT_MS 100

struct aws_credentials_provider_http_impl {
    struct aws_http_connection_manager *connection_manager;
    const struct aws_auth_http_system_vtable *function_table;
    struct aws_string *endpoint;
    struct aws_retry_strategy *retry_strategy;
    struct aws_http_credentials_provider_user_data *user_data;
};

static void s_http_query_context_reset_request_specific_data(struct aws_http_query_context *http_query_context) {
    struct aws_credentials_provider_http_impl *impl = http_query_context->provider->impl;
    impl->user_data->request_vtable->reset_request_data_fn(http_query_context);
    if (http_query_context->request) {
        http_query_context->request = aws_http_message_release(http_query_context->request);
    }
    if (http_query_context->connection) {
        int result = impl->function_table->aws_http_connection_manager_release_connection(
            impl->connection_manager, http_query_context->connection);
        (void)result;
        AWS_ASSERT(result == AWS_OP_SUCCESS);
        http_query_context->connection = NULL;
    }
    http_query_context->status_code = 0;
    http_query_context->error_code = 0;
    aws_byte_buf_clean_up(&http_query_context->path_and_query);
}

static void s_http_query_context_destroy(struct aws_http_query_context *http_query_context) {
    if (http_query_context == NULL) {
        return;
    }

    s_http_query_context_reset_request_specific_data(http_query_context);
    aws_mem_release(http_query_context->allocator, http_query_context->request_data);
    aws_byte_buf_clean_up(&http_query_context->payload);
    aws_credentials_provider_release(http_query_context->provider);
    aws_retry_token_release(http_query_context->retry_token);
    aws_mem_release(http_query_context->allocator, http_query_context);
}

static struct aws_http_query_context *s_http_query_context_new(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_http_impl *impl = provider->impl;

    struct aws_http_query_context *http_query_context =
        aws_mem_calloc(provider->allocator, 1, sizeof(struct aws_http_query_context));
    http_query_context->allocator = provider->allocator;
    http_query_context->provider = aws_credentials_provider_acquire(provider);
    http_query_context->original_user_data = user_data;
    http_query_context->original_callback = callback;
    http_query_context->parameters = impl->user_data->parameters;
    aws_byte_buf_init(&http_query_context->payload, provider->allocator, HTTP_RESPONSE_SIZE_INITIAL);

    return http_query_context;
}

/*
 * No matter the result, this always gets called assuming that http_query_context is successfully allocated
 */
static void s_finalize_get_credentials_query(struct aws_http_query_context *http_query_context) {
    struct aws_credentials_provider_http_impl *impl = http_query_context->provider->impl;
    impl->user_data->request_vtable->finalize_credentials_fn(http_query_context);

    /* clean up */
    s_http_query_context_destroy(http_query_context);
}

static void s_on_retry_ready(struct aws_retry_token *token, int error_code, void *user_data);

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_http_query_context *http_query_context = user_data;

    struct aws_credentials_provider_http_impl *impl = http_query_context->provider->impl;
    impl->function_table->aws_http_stream_release(stream);

    /* set error code */
    http_query_context->error_code = error_code;
    impl->function_table->aws_http_stream_get_incoming_response_status(stream, &http_query_context->status_code);
    if (error_code == AWS_OP_SUCCESS && http_query_context->status_code != AWS_HTTP_STATUS_CODE_200_OK) {
        http_query_context->error_code = AWS_AUTH_CREDENTIALS_PROVIDER_HTTP_STATUS_FAILURE;
    }

    /*
     * If we can retry the request based on error response or http status code failure, retry it, otherwise, call the
     * finalize function.
     */
    if (error_code || http_query_context->status_code != AWS_HTTP_STATUS_CODE_200_OK) {
        enum aws_retry_error_type error_type =
            aws_credentials_provider_compute_retry_error_type(http_query_context->status_code, error_code);

        /* don't retry client errors at all. */
        if (error_type != AWS_RETRY_ERROR_TYPE_CLIENT_ERROR) {
            if (aws_retry_strategy_schedule_retry(
                    http_query_context->retry_token, error_type, s_on_retry_ready, http_query_context) ==
                AWS_OP_SUCCESS) {
                AWS_LOGF_INFO(
                    AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                    "(id=%p): successfully scheduled a retry",
                    (void *)http_query_context->provider);
                return;
            }
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p): failed to schedule retry: %s",
                (void *)http_query_context->provider,
                aws_error_str(aws_last_error()));
            http_query_context->error_code = aws_last_error();
        }
    } else {
        int result = aws_retry_token_record_success(http_query_context->retry_token);
        (void)result;
        AWS_ASSERT(result == AWS_ERROR_SUCCESS);
    }

    s_finalize_get_credentials_query(http_query_context);
}

static int s_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *body, void *user_data) {

    (void)stream;

    struct aws_http_query_context *http_query_context = user_data;

    AWS_LOGF_TRACE(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) received %zu response bytes",
        (void *)http_query_context->provider,
        body->len);

    if (body->len + http_query_context->payload.len > HTTP_RESPONSE_SIZE_LIMIT) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) response exceeded maximum allowed length",
            (void *)http_query_context->provider);

        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (aws_byte_buf_append_dynamic(&http_query_context->payload, body)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) error appending response payload: %s",
            (void *)http_query_context->provider,
            aws_error_str(aws_last_error()));

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_query_credentials(struct aws_http_query_context *http_query_context) {
    AWS_FATAL_ASSERT(http_query_context->connection);
    struct aws_http_stream *stream = NULL;
    struct aws_credentials_provider_http_impl *impl = http_query_context->provider->impl;

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .on_response_headers = NULL,
        .on_response_header_block_done = NULL,
        .on_response_body = s_on_incoming_body_fn,
        .on_complete = s_on_stream_complete_fn,
        .user_data = http_query_context,
        .request = http_query_context->request,
    };

    stream = impl->function_table->aws_http_connection_make_request(http_query_context->connection, &request_options);
    if (!stream) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to make request with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    if (impl->function_table->aws_http_stream_activate(stream)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to activate the stream with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    return;

on_error:
    http_query_context->error_code = aws_last_error();
    impl->function_table->aws_http_stream_release(stream);
    s_finalize_get_credentials_query(http_query_context);
}

static void s_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct aws_http_query_context *http_query_context = user_data;

    if (error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "id=%p: failed to acquire a connection, error code %d(%s)",
            (void *)http_query_context->provider,
            error_code,
            aws_error_str(error_code));
        http_query_context->error_code = error_code;
        s_finalize_get_credentials_query(http_query_context);
        return;
    }
    AWS_LOGF_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): successfully acquired a connection",
        (void *)http_query_context->provider);
    http_query_context->connection = connection;

    http_query_context->request = aws_http_message_new_request(http_query_context->allocator);
    if (http_query_context->request == NULL) {
        goto on_error;
    }

    struct aws_credentials_provider_http_impl *impl = http_query_context->provider->impl;
    if (impl->user_data->request_vtable->create_request_fn(http_query_context, user_data)) {
        goto on_error;
    }
    s_query_credentials(http_query_context);
    return;
on_error:
    http_query_context->error_code = aws_last_error();
    s_finalize_get_credentials_query(http_query_context);
}

static void s_on_retry_ready(struct aws_retry_token *token, int error_code, void *user_data) {
    (void)token;
    struct aws_http_query_context *http_query_context = user_data;

    struct aws_credentials_provider_http_impl *impl = http_query_context->provider->impl;

    if (error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to schedule retry with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(error_code));
        http_query_context->error_code = error_code;
        s_finalize_get_credentials_query(http_query_context);
        return;
    }

    /* clear the result from previous attempt */
    s_http_query_context_reset_request_specific_data(http_query_context);

    impl->function_table->aws_http_connection_manager_acquire_connection(
        impl->connection_manager, s_on_acquire_connection, http_query_context);
}

static void s_on_retry_token_acquired(
    struct aws_retry_strategy *strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {
    struct aws_http_query_context *http_query_context = user_data;
    (void)strategy;

    if (error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to acquire retry token: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(error_code));
        http_query_context->error_code = error_code;
        s_finalize_get_credentials_query(http_query_context);
        return;
    }

    http_query_context->retry_token = token;
    struct aws_credentials_provider_http_impl *impl = http_query_context->provider->impl;
    impl->function_table->aws_http_connection_manager_acquire_connection(
        impl->connection_manager, s_on_acquire_connection, user_data);
}

static int s_aws_http_credentials_provider_get_credentials(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_http_query_context *http_query_context = s_http_query_context_new(provider, callback, user_data);

    struct aws_credentials_provider_http_impl *impl = http_query_context->provider->impl;
    impl->user_data->request_vtable->create_request_data_fn(http_query_context);
    if (aws_retry_strategy_acquire_retry_token(
            impl->retry_strategy, NULL, s_on_retry_token_acquired, http_query_context, HTTP_RETRY_TIMEOUT_MS)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to acquire retry token: %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    s_http_query_context_destroy(http_query_context);
    return aws_last_error();
}

static void s_on_connection_manager_shutdown(void *user_data) {
    struct aws_credentials_provider *provider = user_data;

    aws_credentials_provider_invoke_shutdown_callback(provider);
    struct aws_credentials_provider_http_impl *impl = provider->impl;
    impl->user_data->request_vtable->clean_up_parameters_fn(impl->user_data->parameters);
    aws_mem_release(provider->allocator, provider->impl);
    aws_mem_release(provider->allocator, provider);
}

static void s_credentials_provider_http_destroy(struct aws_credentials_provider *provider) {

    struct aws_credentials_provider_http_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }
    aws_string_destroy(impl->endpoint);
    aws_retry_strategy_release(impl->retry_strategy);

    /* aws_http_connection_manager_release will eventually leads to call of s_on_connection_manager_shutdown,
     * which will do memory release for provider and impl. So We should be freeing impl
     * related memory first, then call aws_http_connection_manager_release.
     */
    if (impl->connection_manager) {
        impl->function_table->aws_http_connection_manager_release(impl->connection_manager);
    } else {
        /* If provider setup failed halfway through, connection_manager might not exist.
         * In this case invoke shutdown completion callback directly to finish cleanup */
        s_on_connection_manager_shutdown(provider);
    }
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_http_vtable = {
    .get_credentials = s_aws_http_credentials_provider_get_credentials,
    .destroy = s_credentials_provider_http_destroy,
};

int aws_http_credentials_provider_init_base(
    struct aws_allocator *allocator,
    struct aws_credentials_provider *provider,
    struct aws_credentials_provider_http_options *options,
    struct aws_http_credentials_provider_user_data *user_data) {

    struct aws_credentials_provider_http_impl *impl =
        aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider_http_impl));

    AWS_ZERO_STRUCT(*impl);
    impl->user_data = user_data;

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_http_vtable, impl);

    struct aws_tls_connection_options tls_connection_options;
    AWS_ZERO_STRUCT(tls_connection_options);

    if (!options->tls_ctx) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p): a TLS context must be provided", (void *)provider);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto on_error;
    }

    if (!options->bootstrap) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p): a bootstrap instance must be provided", (void *)provider);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto on_error;
    }

    aws_tls_connection_options_init_from_ctx(&tls_connection_options, options->tls_ctx);
    if (aws_tls_connection_options_set_server_name(&tls_connection_options, allocator, &options->endpoint)) {
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
        HTTP_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);

    struct aws_http_connection_manager_options manager_options;
    AWS_ZERO_STRUCT(manager_options);
    manager_options.bootstrap = options->bootstrap;
    manager_options.initial_window_size = HTTP_RESPONSE_SIZE_LIMIT;
    manager_options.socket_options = &socket_options;
    manager_options.host = options->endpoint;
    manager_options.port = 443;
    manager_options.max_connections = options->max_connections;
    manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    manager_options.shutdown_complete_user_data = provider;
    manager_options.tls_connection_options = &tls_connection_options;
    manager_options.proxy_ev_settings = options->proxy_ev_settings;

    impl->function_table = options->function_table;
    if (impl->function_table == NULL) {
        impl->function_table = g_aws_credentials_provider_http_function_table;
    }

    impl->endpoint = aws_string_new_from_cursor(allocator, &options->endpoint);
    impl->connection_manager = impl->function_table->aws_http_connection_manager_new(allocator, &manager_options);
    if (impl->connection_manager == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to create a connection manager %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    provider->shutdown_options = options->shutdown_options;

    if (options->retry_strategy == NULL) {
        struct aws_standard_retry_options retry_options = {
            .backoff_retry_options =
                {
                    .el_group = options->bootstrap->event_loop_group,
                    .max_retries = HTTP_MAX_ATTEMPTS,
                },
        };

        impl->retry_strategy = aws_retry_strategy_new_standard(allocator, &retry_options);
    } else {
        impl->retry_strategy = options->retry_strategy;
    }

    if (!impl->retry_strategy) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to create a retry strategy with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    aws_tls_connection_options_clean_up(&tls_connection_options);
    return AWS_OP_SUCCESS;
on_error:
    aws_tls_connection_options_clean_up(&tls_connection_options);
    aws_mem_release(allocator, impl);
    return aws_last_error();
}
