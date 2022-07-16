/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <inttypes.h>

#include <aws/auth/credentials.h>
#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/cal/hash.h>
#include <aws/common/clock.h>
#include <aws/common/date_time.h>
#include <aws/common/encoding.h>
#include <aws/common/json.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/file_utils.h>
#include <aws/io/retry_strategy.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#ifdef _MSC_VER
/* allow non-constant declared initializers. */
#    pragma warning(disable : 4204)
#endif

/*
 * SSO credentials provider implementation.
 */
struct aws_credentials_provider_sso_impl {
    struct aws_http_connection_manager *connection_manager;
    struct aws_auth_http_system_vtable *function_table;
    struct aws_retry_strategy *retry_strategy;

    struct aws_string *endpoint;
    struct aws_string *access_token;
    struct aws_string *account_id;
    struct aws_string *role_name;
};

/* Credential response JSON data is circa 1300 bytes. */
#define SSO_RESPONSE_SIZE_INITIAL 2048
#define SSO_RESPONSE_SIZE_LIMIT 10000

/* Network and retry strategy parameters. */
#define SSO_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS 15
#define SSO_MAX_RETRIES 10

/* Timeout (in milliseconds) for acquiring a retry token. */
#define SSO_RETRY_TOKEN_MSEC 100

/* Location of the token cache directory relative to the home directory of the user. */
AWS_STATIC_STRING_FROM_LITERAL(s_sso_cache_directory, "/.aws/sso/cache/");

static struct aws_auth_http_system_vtable s_default_function_table = {
    .aws_http_connection_manager_new = aws_http_connection_manager_new,
    .aws_http_connection_manager_release = aws_http_connection_manager_release,
    .aws_http_connection_manager_acquire_connection = aws_http_connection_manager_acquire_connection,
    .aws_http_connection_manager_release_connection = aws_http_connection_manager_release_connection,
    .aws_http_connection_make_request = aws_http_connection_make_request,
    .aws_http_stream_activate = aws_http_stream_activate,
    .aws_http_stream_get_incoming_response_status = aws_http_stream_get_incoming_response_status,
    .aws_http_stream_release = aws_http_stream_release,
    .aws_http_connection_close = aws_http_connection_close,
};

/**
 * sso_user_data - scratch data for each outstanding SSO query.
 */
struct sso_user_data {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_credentials_provider *sso_provider;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;

    /* mutable */
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_byte_buf response;
    struct aws_retry_token *retry_token;

    /* URI path and query string. */
    struct aws_byte_buf path_and_query;

    /* Track last HTTP response status and last error code. */
    int status_code;
    int error_code;
};

/* Called in between retries. */
static void s_user_data_reset_request_and_response(struct sso_user_data *user_data) {
    aws_http_message_destroy(user_data->request);
    user_data->request = NULL;

    aws_byte_buf_reset(&user_data->response, true /*zero out*/);

    user_data->status_code = 0;
    user_data->error_code = AWS_OP_SUCCESS;
}

static void s_user_data_destroy(struct sso_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }

    s_user_data_reset_request_and_response(user_data);

    if (user_data->connection) {
        struct aws_credentials_provider_sso_impl *impl = user_data->sso_provider->impl;

        impl->function_table->aws_http_connection_manager_release_connection(
            impl->connection_manager, user_data->connection);
    }

    aws_byte_buf_clean_up(&user_data->response);
    aws_retry_token_release(user_data->retry_token);

    aws_byte_buf_clean_up(&user_data->path_and_query);

    aws_credentials_provider_release(user_data->sso_provider);
    aws_mem_release(user_data->allocator, user_data);
}

/* URL path and query components. */
static struct aws_byte_cursor s_path = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/federation/credentials");
static struct aws_byte_cursor s_question = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("?");
static struct aws_byte_cursor s_ampersand = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("&");
static struct aws_byte_cursor s_equal = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("=");
static struct aws_byte_cursor s_account_id = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("account_id");
static struct aws_byte_cursor s_role_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("role_name");

static struct sso_user_data *s_user_data_new(
    struct aws_credentials_provider *sso_provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_sso_impl *impl = sso_provider->impl;

    struct sso_user_data *wrapped_user_data =
        aws_mem_calloc(sso_provider->allocator, 1, sizeof(struct sso_user_data));
    if (wrapped_user_data == NULL) {
        goto done;
    }

    wrapped_user_data->allocator = sso_provider->allocator;
    wrapped_user_data->sso_provider = sso_provider;
    aws_credentials_provider_acquire(sso_provider);

    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    struct aws_byte_cursor c_account_id = aws_byte_cursor_from_string(impl->account_id);
    struct aws_byte_cursor c_role_name = aws_byte_cursor_from_string(impl->role_name);

    // Length for "<path>?account_id=&role_name=":
    size_t init_len = s_path.len + s_account_id.len + s_role_name.len + 4;
    if (aws_byte_buf_init(&wrapped_user_data->path_and_query, sso_provider->allocator, init_len)  ||
        aws_byte_buf_append_dynamic(&wrapped_user_data->path_and_query, &s_path)                  ||
        aws_byte_buf_append_dynamic(&wrapped_user_data->path_and_query, &s_question)              ||
        aws_byte_buf_append_dynamic(&wrapped_user_data->path_and_query, &s_account_id)            ||
        aws_byte_buf_append_dynamic(&wrapped_user_data->path_and_query, &s_equal)                 ||
        aws_byte_buf_append_encoding_uri_param(&wrapped_user_data->path_and_query, &c_account_id) ||
        aws_byte_buf_append_dynamic(&wrapped_user_data->path_and_query, &s_ampersand)             ||
        aws_byte_buf_append_dynamic(&wrapped_user_data->path_and_query, &s_role_name)             ||
        aws_byte_buf_append_dynamic(&wrapped_user_data->path_and_query, &s_equal)                 ||
        aws_byte_buf_append_encoding_uri_param(&wrapped_user_data->path_and_query, &c_role_name)) {
        goto done;
    }

    if (aws_byte_buf_init(&wrapped_user_data->response, sso_provider->allocator, SSO_RESPONSE_SIZE_INITIAL)) {
        goto done;
    }

    return wrapped_user_data;

done:
    s_user_data_destroy(wrapped_user_data);

    return NULL;
}

/*
 * Parse the JSON response returned by the SSO Portal:
 * {
 *   "roleCredentials": {
 *     "accessKeyId": "...",
 *     "secretAccessKey": "...",
 *     "sessionToken": "..."
 *     "expiration": 1654567794000
 *   }
 * }
 * This is similar to aws_parse_credentials_from_cjson_object, but differs in the format of the
 * 'expiration' field, which uses epoch milliseconds rather than an ISO-8601 formatted string.
 */
static struct aws_credentials *s_parse_credentials_from_response(
    struct sso_user_data *user_data,
    struct aws_byte_buf *document) {
    struct aws_json_value *document_root = NULL;
    struct aws_credentials *credentials = NULL;

    if (aws_byte_buf_append_null_terminator(document)) {
        goto done;
    }

    struct aws_byte_cursor document_cursor = aws_byte_cursor_from_buf(document);
    document_root = aws_json_value_new_from_string(user_data->allocator, document_cursor);
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p) sso: failed to parse JSON response", (void*)user_data);
        goto done;
    }

    /* Top-level of the document. */
    struct aws_json_value *role_credentials =
        aws_json_value_get_from_object(document_root, aws_byte_cursor_from_c_str("roleCredentials"));
    if (!aws_json_value_is_object(role_credentials)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to extract roleCredentials from JSON response", (void*)user_data);
        goto done;
    }

    /* roleCredentials object. */
    struct aws_byte_cursor access_key_cursor;
    struct aws_json_value *access_key =
        aws_json_value_get_from_object(role_credentials, aws_byte_cursor_from_c_str("accessKeyId"));
    if (!aws_json_value_is_string(access_key) ||
        aws_json_value_get_string(access_key, &access_key_cursor) == AWS_OP_ERR) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to extract accessKeyId from JSON response", (void*)user_data);
        goto done;
    }

    struct aws_byte_cursor secret_key_cursor;
    struct aws_json_value *secret_key =
        aws_json_value_get_from_object(role_credentials, aws_byte_cursor_from_c_str("secretAccessKey"));
    if (!aws_json_value_is_string(secret_key) ||
        aws_json_value_get_string(secret_key, &secret_key_cursor) == AWS_OP_ERR) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to extract secretAccessKey from JSON response", (void*)user_data);
        goto done;
    }

    struct aws_byte_cursor session_token_cursor;
    struct aws_json_value *session_token =
        aws_json_value_get_from_object(role_credentials, aws_byte_cursor_from_c_str("sessionToken"));
    if (!aws_json_value_is_string(session_token) ||
        aws_json_value_get_string(session_token, &session_token_cursor) == AWS_OP_ERR) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to extract sessionToken from JSON response", (void*)user_data);
        goto done;
    }

    double expiration_value;
    struct aws_json_value *expiration =
        aws_json_value_get_from_object(role_credentials, aws_byte_cursor_from_c_str("expiration"));
    if (!aws_json_value_is_number(expiration) ||
        aws_json_value_get_number(expiration, &expiration_value) == AWS_OP_ERR || expiration_value <= 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to extract expiration from JSON response", (void*)user_data);
        goto done;
    }

    /*
     * Build the credentials.
     */
    const uint64_t expiration_timepoint_milliseconds = (uint64_t)expiration_value;

    if (access_key_cursor.len == 0 || secret_key_cursor.len == 0 || session_token_cursor.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: one of accessKeyId, secretAccessKey, or sessionToken is empty",
            (void*)user_data);
        goto done;
    }

    credentials = aws_credentials_new(user_data->allocator,
        access_key_cursor,
        secret_key_cursor,
        session_token_cursor,
        aws_timestamp_convert(expiration_timepoint_milliseconds, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_SECS, NULL));

done:
    if (credentials == NULL) {
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
    } else {
        AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p) sso: new credentials expire at %" PRIu64,
            (void*)user_data, aws_credentials_get_expiration_timepoint_seconds(credentials));
    }
    aws_json_value_destroy(document_root);

    return credentials;
}

/* Pass the sucess/error response back via callback. Always called as the last step. */
static void s_finalize_get_credentials_query(struct sso_user_data *user_data) {
    struct aws_credentials *credentials = NULL;

    if (user_data->status_code == AWS_HTTP_STATUS_CODE_200_OK) {
        credentials = s_parse_credentials_from_response(user_data, &user_data->response);
    }

    if (credentials == NULL) {
        if (user_data->error_code == AWS_ERROR_SUCCESS) {
            user_data->error_code = aws_last_error();
        }
        if (user_data->error_code == AWS_ERROR_SUCCESS) {
            user_data->error_code = AWS_ERROR_UNKNOWN;
        }
        AWS_LOGF_WARN(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to query credentials (%s)",
            (void*)user_data, aws_error_str(user_data->error_code));
    }

    /* pass the credentials back */
    user_data->original_callback(credentials, user_data->error_code, user_data->original_user_data);

    /* clean up */
    s_user_data_destroy(user_data);
    aws_credentials_release(credentials);
}

static int s_on_incoming_body_fn(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *body,
    void *wrapped_user_data) {
    struct sso_user_data *user_data = wrapped_user_data;
    struct aws_credentials_provider_sso_impl *impl = user_data->sso_provider->impl;

    (void)stream;

    if (body->len + user_data->response.len > SSO_RESPONSE_SIZE_LIMIT) {
        impl->function_table->aws_http_connection_close(user_data->connection);
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: response too big", wrapped_user_data);

        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (aws_byte_buf_append_dynamic(&user_data->response, body)) {
        impl->function_table->aws_http_connection_close(user_data->connection);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_on_incoming_headers_fn(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *wrapped_user_data) {
    struct sso_user_data *user_data = wrapped_user_data;

    (void)header_array;
    (void)num_headers;

    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN && user_data->status_code == 0) {
        struct aws_credentials_provider_sso_impl *impl = user_data->sso_provider->impl;

        if (impl->function_table->aws_http_stream_get_incoming_response_status(stream, &user_data->status_code)) {
            AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) sso: failed to get http status code: %s",
                wrapped_user_data, aws_error_str(aws_last_error()));
            return AWS_OP_ERR;
        }
    }
    return AWS_OP_SUCCESS;
}

static void s_on_retry_ready(struct aws_retry_token *token, int error_code, void *wrapped_user_data);

/* Ported from aws-cpp-sdk-core/include/aws/core/http/HttpResponse.h */
static bool s_is_retryable_http_response_code(int http_response_code) {
    switch (http_response_code) {
        case AWS_HTTP_STATUS_CODE_408_REQUEST_TIMEOUT:
        case 419 /* Authentication Timeout (no enum value defined). */:
        case 440 /* Login Timeout (no enum value defined). */:
        case AWS_HTTP_STATUS_CODE_429_TOO_MANY_REQUESTS:
            return true;
        default:
            return http_response_code >= 500 && http_response_code < 600;
    }
}

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *data) {
    struct sso_user_data *user_data = data;
    struct aws_credentials_provider_sso_impl *impl = user_data->sso_provider->impl;

    user_data->error_code = error_code;
    if (user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK) {
        user_data->error_code = AWS_AUTH_CREDENTIALS_PROVIDER_HTTP_STATUS_FAILURE;
    }

    if (stream != NULL) {
        /* Release existing connection */
        impl->function_table->aws_http_stream_release(stream);
        impl->function_table->aws_http_connection_manager_release_connection(impl->connection_manager, user_data->connection);
    }
    user_data->connection = NULL;

    if (error_code || user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK) {
        if (error_code || s_is_retryable_http_response_code(user_data->status_code)) {
            /* For exponential backoff, any value other than AWS_RETRY_ERROR_TYPE_CLIENT_ERROR works. */
            const enum aws_retry_error_type error_type = AWS_RETRY_ERROR_TYPE_SERVER_ERROR;

            /* Clear data used by the previous attempt. */
            s_user_data_reset_request_and_response(user_data);

            if (!aws_retry_strategy_schedule_retry(user_data->retry_token, error_type, s_on_retry_ready, user_data)) {
                return;
            }
            AWS_LOGF_WARN(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) sso: failed to schedule retry: %s", data, aws_error_str(aws_last_error()));
        }
    } else if (aws_retry_token_record_success(user_data->retry_token)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to register retry success: %s", data, aws_error_str(aws_last_error()));
    }

    s_finalize_get_credentials_query(user_data);
}

/* Request headers. */
AWS_STATIC_STRING_FROM_LITERAL(s_sso_token_header, "x-amz-sso_bearer_token");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_user_agent_header, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_user_agent_header_value, "aws-sdk-crt/sso-credentials-provider");

static void s_query_credentials(struct sso_user_data *user_data) {
    struct aws_credentials_provider_sso_impl *impl = user_data->sso_provider->impl;
    struct aws_http_stream *stream = NULL;

    AWS_FATAL_ASSERT(user_data->connection);

   user_data->request = aws_http_message_new_request(user_data->allocator);
    if (user_data->request == NULL) {
        goto on_error;
    }

    struct aws_http_header auth_header = {
        .name = aws_byte_cursor_from_string(s_sso_token_header),
        .value = aws_byte_cursor_from_string(impl->access_token),
    };
    struct aws_http_header host_header = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
        .value = aws_byte_cursor_from_string(impl->endpoint),
    };
    struct aws_http_header user_agent_header = {
        .name = aws_byte_cursor_from_string(s_sso_user_agent_header),
        .value = aws_byte_cursor_from_string(s_sso_user_agent_header_value),
    };

    if (aws_http_message_add_header(user_data->request, auth_header) ||
        aws_http_message_add_header(user_data->request, host_header) ||
        aws_http_message_add_header(user_data->request, user_agent_header)) {
        goto on_error;
    }

    if (aws_http_message_set_request_method(user_data->request, aws_http_method_get)) {
        goto on_error;
    }

    if (aws_http_message_set_request_path(user_data->request,
                                          aws_byte_cursor_from_buf(&user_data->path_and_query))) {
        goto on_error;
    }

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .on_response_headers = s_on_incoming_headers_fn,
        .on_response_header_block_done = NULL,
        .on_response_body = s_on_incoming_body_fn,
        .on_complete = s_on_stream_complete_fn,
        .user_data = user_data,
        .request = user_data->request,
    };

    stream = impl->function_table->aws_http_connection_make_request(user_data->connection, &request_options);
    if (!stream) {
        goto on_error;
    }

    if (impl->function_table->aws_http_stream_activate(stream)) {
        goto on_error;
    }

    return;

on_error:
    impl->function_table->aws_http_stream_release(stream);

    s_finalize_get_credentials_query(user_data);
}

static void s_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *data) {
    struct sso_user_data *user_data = data;

    if (connection == NULL) {
        AWS_LOGF_WARN(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to acquire connection (%s)", data, aws_error_str(error_code));
        /* Retry all connection errors: */
        s_on_stream_complete_fn(NULL, error_code, user_data);
        return;
    }

    user_data->connection = connection;

    s_query_credentials(user_data);
}

/* Called for the first request attempt, fills in retry token for subsequent attempts. */
static void s_on_retry_token_acquired(
    struct aws_retry_strategy *strategy,
    int error_code,
    struct aws_retry_token *token,
    void *wrapped_user_data) {
    (void)strategy;
    struct sso_user_data *user_data = wrapped_user_data;
    struct aws_credentials_provider_sso_impl *impl = user_data->sso_provider->impl;

    if (error_code) {
        AWS_LOGF_WARN(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) sso: failed to acquire retry token: %s", wrapped_user_data, aws_error_str(error_code));
        user_data->error_code = error_code;

        s_finalize_get_credentials_query(user_data);
        return;
    }

    user_data->retry_token = token;

    impl->function_table->aws_http_connection_manager_acquire_connection(
        impl->connection_manager, s_on_acquire_connection, user_data);
}

/* Called for each retry. */
static void s_on_retry_ready(struct aws_retry_token *token, int error_code, void *wrapped_user_data) {
    (void)token;
    struct sso_user_data *user_data = wrapped_user_data;
    struct aws_credentials_provider_sso_impl *impl = user_data->sso_provider->impl;

    if (error_code) {
        user_data->error_code = error_code;
        s_finalize_get_credentials_query(user_data);
        return;
    }

    impl->function_table->aws_http_connection_manager_acquire_connection(
        impl->connection_manager, s_on_acquire_connection, user_data);
}

/* Implementation for the get_credentials() function pointer. */
static int s_sso_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_credentials_provider_sso_impl *impl = provider->impl;

    struct sso_user_data *wrapped_user_data = s_user_data_new(provider, callback, user_data);
    if (wrapped_user_data == NULL) {
        return AWS_OP_ERR;
    }

    if (aws_retry_strategy_acquire_retry_token(
        impl->retry_strategy, NULL, s_on_retry_token_acquired, wrapped_user_data, SSO_RETRY_TOKEN_MSEC)) {
        s_user_data_destroy(wrapped_user_data);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/* Called after the connection_manager has completely shut down. */
static void s_on_connection_manager_shutdown(void *user_data) {
    struct aws_credentials_provider *provider = user_data;

    aws_credentials_provider_invoke_shutdown_callback(provider);
    aws_mem_release(provider->allocator, provider);
}

static void s_sso_credentials_provider_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_sso_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_retry_strategy_release(impl->retry_strategy);

    aws_string_destroy(impl->endpoint);
    aws_string_destroy(impl->access_token);
    aws_string_destroy(impl->account_id);
    aws_string_destroy(impl->role_name);

    /* See the STS web identity provider comments for the rationale of this shutdown sequence. */
    if (impl->connection_manager) {
        impl->function_table->aws_http_connection_manager_release(impl->connection_manager);
    } else {
        s_on_connection_manager_shutdown(provider);
    }
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_sso_vtable = {
    .get_credentials = s_sso_credentials_provider_get_credentials_async,
    .destroy = s_sso_credentials_provider_destroy,
};

/* Constructs the access-token path, at "~/" @s_sso_cache_directory <sha1 of @sso_start_url> ".json". */
struct aws_string *sso_access_token_path(
        struct aws_allocator *allocator,
        const struct aws_string *sso_start_url) {
    struct aws_string *home_directory = NULL;
    struct aws_byte_buf sha1_output_buf = {0};
    struct aws_byte_buf sha1_hex = {0};
    struct aws_byte_buf access_token_path = {0};
    struct aws_string *access_token_path_str = NULL;

    AWS_FATAL_ASSERT(allocator);
    AWS_FATAL_ASSERT(sso_start_url);

    home_directory = aws_get_home_directory(allocator);
    if (home_directory == NULL) {
        goto done;
    }

    if (aws_byte_buf_init(&sha1_output_buf, allocator, AWS_SHA1_LEN)) {
        goto done;
    }

    // The hex-encoded length of the SHA1 hash (2 characters per byte):
    const size_t sha1_len = sha1_output_buf.capacity * 2;

    struct aws_byte_cursor home_dir_cursor = aws_byte_cursor_from_string(home_directory);
    struct aws_byte_cursor cache_dir_cursor = aws_byte_cursor_from_string(s_sso_cache_directory);
    struct aws_byte_cursor json_cursor = aws_byte_cursor_from_c_str(".json");

    // Length of the Access Token path: <home-dir> + "/.aws/sso/cache/" + 40 bytes sha1 + ".json".
    size_t full_length = home_dir_cursor.len + cache_dir_cursor.len + sha1_len + json_cursor.len;
    if (aws_byte_buf_init(&access_token_path, allocator, full_length)) {
        goto done;
    }

    // Cache root directory (~/.aws/sso/cache):
    if (aws_byte_buf_append(&access_token_path, &home_dir_cursor) ||
        aws_byte_buf_append(&access_token_path, &cache_dir_cursor)) {
        goto done;
    }

    // SHA1 hash filename of the JSON Access Path Token.
    struct aws_byte_cursor input = aws_byte_cursor_from_string(sso_start_url);
    if (aws_sha1_compute(allocator, &input, &sha1_output_buf, 0)) {
        goto done;
    }

    // Since hex_encode() '0'-terminates the string, need to allocate room for 1 more character:
    if (aws_byte_buf_init(&sha1_hex, allocator, sha1_len + 1)) {
        goto done;
    }

    struct aws_byte_cursor sha1_cursor = aws_byte_cursor_from_buf(&sha1_output_buf);
    if (aws_hex_encode(&sha1_cursor, &sha1_hex)) {
        goto done;
    }

    // Note the use of sha1_len below.
    struct aws_byte_cursor sha1_hex_cursor = aws_byte_cursor_from_array(sha1_hex.buffer, sha1_len);
    if (aws_byte_buf_append(&access_token_path, &sha1_hex_cursor) ||
        aws_byte_buf_append(&access_token_path, &json_cursor)) {
        goto done;
    }

    access_token_path_str = aws_string_new_from_buf(allocator, &access_token_path);

    // Use platform-specific directory separator.
    const char local_platform_separator = aws_get_platform_directory_separator();
    for (size_t i = 0; i < access_token_path_str->len; ++i) {
        if (aws_is_any_directory_separator((char)access_token_path_str->bytes[i])) {
            ((char *)access_token_path_str->bytes)[i] = local_platform_separator;
        }
    }

done:
    aws_string_destroy(home_directory);
    aws_byte_buf_clean_up(&sha1_output_buf);
    aws_byte_buf_clean_up(&sha1_hex);
    aws_byte_buf_clean_up(&access_token_path);

    return access_token_path_str;
}

/*
 * Attempts to load JSON-encoded SSO Access Token from @token_path.
 * Returns token contents if it could successfully be loaded and has not yet expired.
 * Returns NULL otherwise.
 *
 * Access Token Format:
 * --------------------
 * {
 *   "startUrl": "https://your-domain.awsapps.com/start",
 *   "region": "us-east-1",
 *   "accessToken": "...",
 *   "expiresAt": "2022-06-03T05:53:48Z"
 * }
 */
static int s_load_access_token_from_file(
        struct aws_allocator *allocator,
        const struct aws_string *token_path,
        struct aws_byte_buf *token_buf) {
    struct aws_json_value *document_root = NULL;
    struct aws_byte_buf file_contents = {0};
    struct aws_date_time now, expiration;
    bool success = false;

    if (!allocator || !token_path || !token_buf) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (aws_byte_buf_init_from_file(&file_contents, allocator, aws_string_c_str(token_path))) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: failed to load access token file %s", aws_string_c_str(token_path));
        goto done;
    }

    struct aws_byte_cursor document_cursor = aws_byte_cursor_from_buf(&file_contents);
    document_root = aws_json_value_new_from_string(allocator, document_cursor);
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: failed to parse access token file %s", aws_string_c_str(token_path));
        goto done;
    }


    struct aws_byte_cursor access_token_cursor;
    struct aws_json_value *access_token =
        aws_json_value_get_from_object(document_root, aws_byte_cursor_from_c_str("accessToken"));
    if (!aws_json_value_is_string(access_token) ||
        aws_json_value_get_string(access_token, &access_token_cursor) == AWS_OP_ERR) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: failed to parse accessToken from %s", aws_string_c_str(token_path));
        goto done;
    }

    struct aws_byte_cursor expires_at_cursor;
    struct aws_json_value *expires_at =
        aws_json_value_get_from_object(document_root, aws_byte_cursor_from_c_str("expiresAt"));
    if (!aws_json_value_is_string(expires_at) ||
        aws_json_value_get_string(expires_at, &expires_at_cursor) == AWS_OP_ERR) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: failed to parse expiresAt from %s", aws_string_c_str(token_path));
        goto done;
    }

    if (aws_date_time_init_from_str_cursor(&expiration, &expires_at_cursor, AWS_DATE_FORMAT_ISO_8601)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: expiresAt '" PRInSTR "' in %s is not a valid ISO-8601 date string",
            AWS_BYTE_CURSOR_PRI(expires_at_cursor), aws_string_c_str(token_path));
        goto done;
    }

    aws_date_time_init_now(&now);
    if (aws_date_time_diff(&expiration, &now) < 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: cached token %s expired at " PRInSTR " - please refresh login",
             aws_string_c_str(token_path), AWS_BYTE_CURSOR_PRI(expires_at_cursor));
        goto done;
    }

    if (aws_byte_buf_init_copy_from_cursor(token_buf, allocator, access_token_cursor)) {
        goto done;
    }

    success = true;

done:
    aws_json_value_destroy(document_root);
    aws_byte_buf_clean_up(&file_contents);

    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

/* Returns the SSO endpoint corresponding to @region. Returns NULL on error. */
static int s_construct_endpoint(
        struct aws_allocator *allocator,
        const struct aws_string *region,
        struct aws_byte_buf *endpoint_buf) {

    if (!allocator || !region || !endpoint_buf) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    // TODO: maybe add support for CN_NORTH_1/CN_NORTHWEST_1.
    struct aws_byte_cursor c_prefix = aws_byte_cursor_from_c_str("portal.sso.");
    struct aws_byte_cursor c_region = aws_byte_cursor_from_string(region);
    struct aws_byte_cursor c_suffix = aws_byte_cursor_from_c_str(".amazonaws.com");

    if (aws_byte_buf_init(endpoint_buf, allocator, c_prefix.len + c_region.len + c_suffix.len)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append(endpoint_buf, &c_prefix) ||
        aws_byte_buf_append(endpoint_buf, &c_region) ||
        aws_byte_buf_append(endpoint_buf, &c_suffix)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/**
 * sso_parameters - Access Token parameters to pass into the SSO Provider.
 */
struct sso_parameters {
    struct aws_allocator *allocator;
    struct aws_byte_buf endpoint;
    struct aws_byte_buf access_token;
    struct aws_string *account_id;
    struct aws_string *role_name;
};

static void s_parameters_destroy(struct sso_parameters *parameters) {
    if (parameters == NULL) {
        return;
    }
    aws_byte_buf_clean_up(&parameters->endpoint);
    aws_byte_buf_clean_up(&parameters->access_token);
    aws_string_destroy(parameters->account_id);
    aws_string_destroy(parameters->role_name);
    aws_mem_release(parameters->allocator, parameters);
}

/* Profile field names. */
AWS_STRING_FROM_LITERAL(s_sso_start_url, "sso_start_url");
AWS_STRING_FROM_LITERAL(s_sso_region, "sso_region");
AWS_STRING_FROM_LITERAL(s_sso_account_id, "sso_account_id");
AWS_STRING_FROM_LITERAL(s_sso_role_name, "sso_role_name");

static struct sso_parameters *s_parameters_new(struct aws_allocator *allocator) {
    struct aws_profile_collection *config_profile = NULL;
    struct aws_string *config_file_path = NULL;
    struct aws_string *profile_name = NULL;
    struct aws_string *token_path = NULL;
    bool success = false;

    struct sso_parameters *parameters = aws_mem_calloc(allocator, 1, sizeof(*parameters));
    if (parameters == NULL) {
        return NULL;
    }
    parameters->allocator = allocator;

    config_file_path = aws_get_config_file_path(allocator, NULL);
    if (!config_file_path) {
        AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: failed to resolve config file path");
        goto done;
    }

    profile_name = aws_get_profile_name(allocator, NULL);
    if (!profile_name) {
        AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: failed to resolve profile name");
        goto done;
    }

    config_profile = aws_profile_collection_new_from_file(allocator, config_file_path, AWS_PST_CONFIG);
    if (!config_profile) {
        AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: failed to parse configuration file");
        goto done;
    }

    const struct aws_profile *profile = aws_profile_collection_get_profile(config_profile, profile_name);
    if (!profile) {
        AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: failed to load \"%s\" profile", aws_string_c_str(profile_name));
        goto done;
    }

    const struct aws_profile_property *sso_start_url  = aws_profile_get_property(profile, s_sso_start_url);
    const struct aws_profile_property *sso_region     = aws_profile_get_property(profile, s_sso_region);
    const struct aws_profile_property *sso_account_id = aws_profile_get_property(profile, s_sso_account_id);
    const struct aws_profile_property *sso_role_name  = aws_profile_get_property(profile, s_sso_role_name);

    if (!sso_start_url || !sso_region || !sso_account_id || !sso_role_name) {
        AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: invalid configuration for \"%s\" profile", aws_string_c_str(profile_name));
        goto done;
    }

    token_path = sso_access_token_path(allocator, aws_profile_property_get_value(sso_start_url));
    if (token_path == NULL) {
        AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: unable to resolve access token path: %s", aws_error_name(aws_last_error()));
        goto done;
    }

    if (s_load_access_token_from_file(allocator, token_path, &parameters->access_token)) {
        goto done;
    }

    if (s_construct_endpoint(allocator, aws_profile_property_get_value(sso_region),
                             &parameters->endpoint)) {
        goto done;
    }
    parameters->account_id = aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_account_id));
    parameters->role_name  = aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_role_name));

    success = true;

done:
    if (!success) {
        s_parameters_destroy(parameters);
        parameters = NULL;
    }
    aws_profile_collection_destroy(config_profile);
    aws_string_destroy(config_file_path);
    aws_string_destroy(profile_name);
    aws_string_destroy(token_path);

    return parameters;
}

struct aws_credentials_provider *aws_credentials_provider_new_sso(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_profile_options *options) {
    struct sso_parameters *parameters = NULL;
    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_sso_impl *impl = NULL;
    struct aws_tls_connection_options tls_connection_options = {0};
    bool success = false;

    AWS_FATAL_ASSERT(options);
    AWS_FATAL_ASSERT(options->tls_ctx);

    aws_json_module_init(allocator);

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_sso_impl));
    if (!provider || !impl) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_sso_vtable, impl);

    aws_tls_connection_options_init_from_ctx(&tls_connection_options, options->tls_ctx);
    /* Override the default TLS negotiation timeout (see #169). */
    tls_connection_options.timeout_ms = 3 * SSO_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS * 1000 /*msec*/;

    parameters = s_parameters_new(allocator);
    if (!parameters) {
        goto done;
    }

    struct aws_byte_cursor host = aws_byte_cursor_from_buf(&parameters->endpoint);
    if (aws_tls_connection_options_set_server_name(&tls_connection_options, allocator, &host)) {
        AWS_LOGF_INFO(AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso: failed to create TLS connection: %s", aws_error_str(aws_last_error()));
        goto done;
    }

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV4;
    socket_options.connect_timeout_ms = (uint32_t)aws_timestamp_convert(
        SSO_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);

    struct aws_http_connection_manager_options manager_options;
    AWS_ZERO_STRUCT(manager_options);
    manager_options.bootstrap = options->bootstrap;
    manager_options.initial_window_size = SSO_RESPONSE_SIZE_LIMIT;
    manager_options.socket_options = &socket_options;
    manager_options.host = host;
    manager_options.port = 443;
    manager_options.max_connections = 2;
    manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    manager_options.shutdown_complete_user_data = provider;
    manager_options.tls_connection_options = &tls_connection_options;

    impl->function_table = options->function_table;
    if (impl->function_table == NULL) {
        impl->function_table = &s_default_function_table;
    }

    impl->connection_manager = impl->function_table->aws_http_connection_manager_new(allocator, &manager_options);
    if (impl->connection_manager == NULL) {
        goto done;
    }

    struct aws_exponential_backoff_retry_options retry_options = {
        .el_group = options->bootstrap->event_loop_group,
        .max_retries = SSO_MAX_RETRIES,
    };
    impl->retry_strategy = aws_retry_strategy_new_exponential_backoff(allocator, &retry_options);
    if (!impl->retry_strategy) {
        goto done;
    }

    impl->endpoint = aws_string_new_from_buf(allocator, &parameters->endpoint);
    if (impl->endpoint == NULL) {
        goto done;
    }

    impl->access_token = aws_string_new_from_buf(allocator, &parameters->access_token);
    if (impl->access_token == NULL) {
        goto done;
    }

    impl->account_id = aws_string_new_from_string(allocator, parameters->account_id);
    if (impl->account_id == NULL) {
        goto done;
    }

    impl->role_name = aws_string_new_from_string(allocator, parameters->role_name);
    if (impl->role_name == NULL) {
        goto done;
    }

    provider->shutdown_options = options->shutdown_options;
    success = true;

done:
    if (!success) {
        aws_credentials_provider_destroy(provider);
        provider = NULL;
    }
    s_parameters_destroy(parameters);
    aws_tls_connection_options_clean_up(&tls_connection_options);

    return provider;
}
