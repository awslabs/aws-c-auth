/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/retry_strategy.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#define COGNITO_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS 5
#define COGNITO_MAX_RETRIES 8

static void s_on_connection_manager_shutdown(void *user_data);

struct aws_cognito_login {
    struct aws_byte_cursor identity_provider_name;
    struct aws_byte_cursor identity_provider_token;
    struct aws_byte_buf login_buffer;
};

static int s_aws_cognito_login_init(
    struct aws_cognito_login *login,
    struct aws_allocator *allocator,
    struct aws_byte_cursor identity_provider_name,
    struct aws_byte_cursor identity_provider_token) {
    AWS_ZERO_STRUCT(*login);

    size_t combined_len = 0;
    if (aws_add_u64_checked(identity_provider_name.len, identity_provider_token.len, &combined_len)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init(&login->login_buffer, allocator, combined_len)) {
        return AWS_OP_ERR;
    }

    login->identity_provider_name = identity_provider_name;
    login->identity_provider_token = identity_provider_token;

    if (aws_byte_buf_append_and_update(&login->login_buffer, &login->identity_provider_name)) {
        goto on_error;
    }

    if (aws_byte_buf_append_and_update(&login->login_buffer, &login->identity_provider_token)) {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:

    /* return to zeroed state */
    aws_byte_buf_clean_up(&login->login_buffer);
    AWS_ZERO_STRUCT(*login);

    return AWS_OP_ERR;
}

static void s_aws_cognito_login_clean_up(struct aws_cognito_login *login) {
    aws_byte_buf_clean_up(&login->login_buffer);
}

struct aws_credentials_provider_cognito_impl {
    struct aws_http_connection_manager *connection_manager;
    struct aws_retry_strategy *retry_strategy;
    const struct aws_auth_http_system_vtable *function_table;

    struct aws_string *endpoint;

    struct aws_string *identity;

    struct aws_array_list logins;

    struct aws_string *custom_role_arn;
};

struct cognito_user_data {
    struct aws_allocator *allocator;

    struct aws_credentials_provider *provider;

    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;

    struct aws_retry_token *retry_token;
    struct aws_credentials *credentials;
    int error_code;
};

static void s_user_data_destroy(struct cognito_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    aws_retry_token_release(user_data->retry_token);
    aws_credentials_provider_release(user_data->provider);

    aws_mem_release(user_data->allocator, user_data);
}

static struct cognito_user_data *s_user_data_new(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_allocator *allocator = provider->allocator;
    struct cognito_user_data *cognito_user_data = aws_mem_calloc(allocator, 1, sizeof(struct cognito_user_data));
    if (cognito_user_data == NULL) {
        return NULL;
    }

    cognito_user_data->allocator = allocator;
    cognito_user_data->provider = aws_credentials_provider_acquire(provider);
    cognito_user_data->original_callback = callback;
    cognito_user_data->original_user_data = user_data;

    return user_data;
}

static void s_finalize_credentials_query(struct cognito_user_data *user_data) {
    AWS_FATAL_ASSERT(user_data != NULL);

    int error_code = user_data->error_code;
    if (user_data->credentials == NULL && error_code == AWS_ERROR_SUCCESS) {
        error_code = AWS_AUTH_CREDENTIALS_PROVIDER_COGNITO_SOURCE_FAILURE;
    }

    (user_data->original_callback)(user_data->credentials, error_code, user_data->original_user_data);

    s_user_data_destroy(user_data);
}

static void s_start_http_request(struct cognito_user_data *user_data) {
    (void)user_data;

    s_finalize_credentials_query(user_data);
}

static void s_on_retry_token_acquired(
    struct aws_retry_strategy *strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {
    (void)strategy;
    struct cognito_user_data *wrapped_user_data = user_data;

    if (error_code != AWS_ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): Cognito credentials provider failed to acquire retry token: %s",
            (void *)wrapped_user_data->provider,
            aws_error_debug_str(error_code));
        wrapped_user_data->error_code = error_code;
        s_finalize_credentials_query(wrapped_user_data);
        return;
    }

    wrapped_user_data->retry_token = token;
    s_start_http_request(wrapped_user_data);
}

static int s_credentials_provider_cognito_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_cognito_impl *impl = provider->impl;

    struct cognito_user_data *wrapped_user_data = s_user_data_new(provider, callback, user_data);
    if (wrapped_user_data == NULL) {
        goto on_error;
    }

    if (aws_retry_strategy_acquire_retry_token(
            impl->retry_strategy, NULL, s_on_retry_token_acquired, wrapped_user_data, 100)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): Cognito credentials provider failed to acquire retry token with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:

    s_user_data_destroy(wrapped_user_data);

    return AWS_OP_ERR;
}

static void s_credentials_provider_cognito_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_cognito_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    /* aws_http_connection_manager_release will eventually leads to call of s_on_connection_manager_shutdown,
     * which will do memory release for provider and impl.
     */
    if (impl->connection_manager) {
        impl->function_table->aws_http_connection_manager_release(impl->connection_manager);
    } else {
        /* If provider setup failed halfway through, connection_manager might not exist.
         * In this case invoke shutdown completion callback directly to finish cleanup */
        s_on_connection_manager_shutdown(provider);
    }

    /* freeing the provider takes place in the shutdown callback below */
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_cognito_vtable = {
    .get_credentials = s_credentials_provider_cognito_get_credentials_async,
    .destroy = s_credentials_provider_cognito_destroy,
};

static void s_on_connection_manager_shutdown(void *user_data) {
    struct aws_credentials_provider *provider = user_data;

    aws_credentials_provider_invoke_shutdown_callback(provider);

    struct aws_credentials_provider_cognito_impl *impl = provider->impl;

    aws_retry_strategy_release(impl->retry_strategy);

    aws_string_destroy(impl->endpoint);
    aws_string_destroy(impl->identity);
    aws_string_destroy(impl->custom_role_arn);

    for (size_t i = 0; i < aws_array_list_length(&impl->logins); ++i) {
        struct aws_cognito_login login;
        if (aws_array_list_get_at(&impl->logins, &login, i)) {
            continue;
        }

        s_aws_cognito_login_clean_up(&login);
    }

    aws_array_list_clean_up(&impl->logins);

    aws_mem_release(provider->allocator, provider);
}

static int s_validate_options(const struct aws_credentials_provider_cognito_options *options) {
    if (options == NULL) {
        return AWS_OP_ERR;
    }

    if (options->tls_ctx == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(static) Cognito credentials provider options must include a TLS context");
        return AWS_OP_ERR;
    }

    if (options->bootstrap == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(static) Cognito credentials provider options must include a client bootstrap");
        return AWS_OP_ERR;
    }

    if (options->endpoint.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(static) Cognito credentials provider options must have a non-empty endpoint");
        return AWS_OP_ERR;
    }

    if (options->identity.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(static) Cognito credentials provider options must have a non-empty identity");
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

struct aws_credentials_provider *aws_credentials_provider_new_cognito(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_cognito_options *options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_cognito_impl *impl = NULL;

    if (s_validate_options(options)) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_cognito_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_cognito_vtable, impl);

    struct aws_tls_connection_options tls_connection_options;
    AWS_ZERO_STRUCT(tls_connection_options);
    aws_tls_connection_options_init_from_ctx(&tls_connection_options, options->tls_ctx);
    struct aws_byte_cursor host = options->endpoint;
    if (aws_tls_connection_options_set_server_name(&tls_connection_options, allocator, &host)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): Cognito credentials provider failed to create tls connection options with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV4;
    socket_options.connect_timeout_ms = (uint32_t)aws_timestamp_convert(
        COGNITO_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);

    struct aws_http_connection_manager_options manager_options;
    AWS_ZERO_STRUCT(manager_options);
    manager_options.bootstrap = options->bootstrap;
    manager_options.initial_window_size = SIZE_MAX;
    manager_options.socket_options = &socket_options;
    manager_options.host = options->endpoint;
    manager_options.port = 443;
    manager_options.max_connections = 2;
    manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    manager_options.shutdown_complete_user_data = provider;
    manager_options.tls_connection_options = &tls_connection_options;

    impl->function_table = options->function_table;
    if (impl->function_table == NULL) {
        impl->function_table = g_aws_credentials_provider_http_function_table;
    }

    impl->connection_manager = impl->function_table->aws_http_connection_manager_new(allocator, &manager_options);
    if (impl->connection_manager == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): Cognito credentials provider failed to create http connection manager with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    impl->endpoint = aws_string_new_from_cursor(allocator, &options->endpoint);
    if (impl->endpoint == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): Cognito credentials provider failed to copy endpoint with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    impl->identity = aws_string_new_from_cursor(allocator, &options->identity);
    if (impl->identity == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): Cognito credentials provider failed to copy identity with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    if (options->custom_role_arn != NULL) {
        impl->custom_role_arn = aws_string_new_from_cursor(allocator, options->custom_role_arn);
        if (impl->custom_role_arn == NULL) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p): Cognito credentials provider failed to copy custom_role_arn with error %s",
                (void *)provider,
                aws_error_debug_str(aws_last_error()));
            goto on_error;
        }
    }

    if (aws_array_list_init_dynamic(&impl->logins, allocator, options->login_count, sizeof(struct aws_cognito_login))) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): Cognito credentials provider failed to initialize login list with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    for (size_t i = 0; i < options->login_count; ++i) {
        struct aws_cognito_identity_provider_token_pair *login_token_pair = &options->logins[i];

        struct aws_cognito_login login;
        if (s_aws_cognito_login_init(
                &login,
                allocator,
                login_token_pair->identity_provider_name,
                login_token_pair->identity_provider_token)) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p): Cognito credentials provider failed to initialize login entry with error %s",
                (void *)provider,
                aws_error_debug_str(aws_last_error()));
            goto on_error;
        }

        aws_array_list_push_back(&impl->logins, &login);
    }

    struct aws_standard_retry_options retry_options = {
        .backoff_retry_options =
            {
                .el_group = options->bootstrap->event_loop_group,
                .max_retries = COGNITO_MAX_RETRIES,
            },
    };

    impl->retry_strategy = aws_retry_strategy_new_standard(allocator, &retry_options);
    if (!impl->retry_strategy) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): Cognito credentials provider failed to create a retry strategy with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    provider->shutdown_options = options->shutdown_options;

    aws_tls_connection_options_clean_up(&tls_connection_options);

    return provider;

on_error:

    aws_tls_connection_options_clean_up(&tls_connection_options);
    aws_credentials_provider_destroy(provider);

    return NULL;
}

/*************************************************************************/

#define DEFAULT_CREDENTIAL_PROVIDER_REFRESH_MS (15 * 60 * 1000)

/*
 * Cognito provider with caching implementation
 */
struct aws_credentials_provider *aws_credentials_provider_new_cognito_caching(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_cognito_options *options) {

    struct aws_credentials_provider *cognito_provider = NULL;
    struct aws_credentials_provider *caching_provider = NULL;

    cognito_provider = aws_credentials_provider_new_cognito(allocator, options);
    if (cognito_provider == NULL) {
        goto on_error;
    }

    struct aws_credentials_provider_cached_options cached_options = {
        .source = cognito_provider,
        .refresh_time_in_milliseconds = DEFAULT_CREDENTIAL_PROVIDER_REFRESH_MS,
    };

    caching_provider = aws_credentials_provider_new_cached(allocator, &cached_options);
    if (caching_provider == NULL) {
        goto on_error;
    }

    aws_credentials_provider_release(cognito_provider);

    return caching_provider;

on_error:

    aws_credentials_provider_release(caching_provider);
    aws_credentials_provider_release(cognito_provider);

    return NULL;
}
