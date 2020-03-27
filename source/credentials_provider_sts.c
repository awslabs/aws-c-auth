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
#include <aws/auth/private/credentials_utils.h>
#include <aws/auth/private/xml_parser.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/auth/signing_config.h>
#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>

#include <inttypes.h>

#ifdef _MSC_VER
/* allow non-constant declared initializers. */
#    pragma warning(disable : 4204)
/* allow passing of address of automatic variable */
#    pragma warning(disable : 4221)
#endif

static struct aws_http_header s_host_header = {
    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("host"),
    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("sts.amazonaws.com"),
};

static struct aws_http_header s_content_type_header = {
    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("content-type"),
    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("application/x-www-form-urlencoded"),
};

static struct aws_http_header s_api_version_header = {
    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("x-amz-api-version"),
    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("2011-06-15"),
};

static struct aws_byte_cursor s_content_length = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("content-length");
static struct aws_byte_cursor s_path = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/");
static struct aws_byte_cursor s_signing_region = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("us-east-1");
static struct aws_byte_cursor s_service_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("sts");
static struct aws_byte_cursor s_assume_role_root_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AssumeRoleResponse");
static struct aws_byte_cursor s_assume_role_result_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AssumeRoleResult");
static struct aws_byte_cursor s_assume_role_credentials_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Credentials");
static struct aws_byte_cursor s_assume_role_session_token_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("SessionToken");
static struct aws_byte_cursor s_assume_role_secret_key_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("SecretAccessKey");
static struct aws_byte_cursor s_assume_role_access_key_id_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AccessKeyId");

const uint16_t aws_sts_assume_role_default_duration_secs = 900;

static struct aws_credentials_provider_system_vtable s_default_function_table = {
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

struct aws_credentials_provider_sts_impl {
    struct aws_http_connection_manager *connection_manager;
    struct aws_string *assume_role_profile;
    struct aws_string *role_session_name;
    uint16_t duration_seconds;
    struct aws_credentials_provider *provider;
    struct aws_tls_ctx *ctx;
    struct aws_tls_connection_options connection_options;
    struct aws_credentials_provider_shutdown_options source_shutdown_options;
    struct aws_credentials_provider_system_vtable *function_table;
    bool owns_ctx;
    aws_io_clock_fn *system_clock_fn;
};

struct sts_creds_provider_user_data {
    struct aws_allocator *allocator;
    struct aws_credentials_provider *provider;
    struct aws_credentials *credentials;
    aws_on_get_credentials_callback_fn *callback;
    struct aws_http_connection *connection;
    struct aws_byte_buf payload_body;
    struct aws_input_stream *input_stream;
    struct aws_signable *signable;
    struct aws_signing_config_aws signing_config;
    struct aws_http_message *message;
    struct aws_byte_buf output_buf;
    void *user_data;
};

static void s_clean_up_user_data(struct sts_creds_provider_user_data *user_data) {
    user_data->callback(user_data->credentials, user_data->user_data);

    if (user_data->credentials) {
        aws_credentials_destroy(user_data->credentials);
    }

    if (user_data->connection) {
        struct aws_credentials_provider_sts_impl *provider_impl = user_data->provider->impl;
        provider_impl->function_table->aws_http_connection_manager_release_connection(
            provider_impl->connection_manager, user_data->connection);
    }

    aws_credentials_provider_release(user_data->provider);

    if (user_data->signable) {
        aws_signable_destroy(user_data->signable);
    }

    if (user_data->input_stream) {
        aws_input_stream_destroy(user_data->input_stream);
    }

    aws_byte_buf_clean_up(&user_data->payload_body);

    if (user_data->message) {
        aws_http_message_destroy(user_data->message);
    }

    aws_byte_buf_clean_up(&user_data->output_buf);
    aws_mem_release(user_data->allocator, user_data);
}

static int s_write_body_to_buffer(struct aws_credentials_provider *provider, struct aws_byte_buf *body) {
    struct aws_credentials_provider_sts_impl *provider_impl = provider->impl;

    struct aws_byte_cursor working_cur = aws_byte_cursor_from_c_str("Version=2011-06-15&Action=AssumeRole&RoleArn=");
    if (aws_byte_buf_append_dynamic(body, &working_cur)) {
        return AWS_OP_ERR;
    }
    struct aws_byte_cursor role_cur = aws_byte_cursor_from_string(provider_impl->assume_role_profile);
    if (aws_byte_buf_append_encoding_uri_param(body, &role_cur)) {
        return AWS_OP_ERR;
    }
    working_cur = aws_byte_cursor_from_c_str("&RoleSessionName=");
    if (aws_byte_buf_append_dynamic(body, &working_cur)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor session_cur = aws_byte_cursor_from_string(provider_impl->role_session_name);
    if (aws_byte_buf_append_encoding_uri_param(body, &session_cur)) {
        return AWS_OP_ERR;
    }

    working_cur = aws_byte_cursor_from_c_str("&DurationSeconds=");
    if (aws_byte_buf_append_dynamic(body, &working_cur)) {
        return AWS_OP_ERR;
    }

    char duration_seconds[6];
    AWS_ZERO_ARRAY(duration_seconds);
    snprintf(duration_seconds, sizeof(duration_seconds), "%" PRIu16, provider_impl->duration_seconds);
    working_cur = aws_byte_cursor_from_c_str(duration_seconds);
    if (aws_byte_buf_append_dynamic(body, &working_cur)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;

    struct sts_creds_provider_user_data *provider_user_data = user_data;
    return aws_byte_buf_append_dynamic(&provider_user_data->output_buf, data);
}

/* parse doc of form
<AssumeRoleResponse>
     <AssumeRoleResult>
          <Credentials>
             <AccessKeyId>accessKeyId</AccessKeyId>
             <SecretKey>secretKey</SecretKey>
             <SessionToken>sessionToken</SessionToken>
          </Credentials>
         <AssumedRoleUser>
             ... more stuff we don't care about.
         </AssumedRoleUser>
         ... more stuff we don't care about
      </AssumeRoleResult>
</AssumeRoleResponse>
 */
static bool s_on_node_encountered_fn(struct aws_xml_parser *parser, struct aws_xml_node *node, void *user_data) {
    if (aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_root_name) ||
        aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_result_name) ||
        aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_credentials_name)) {
        return aws_xml_node_traverse(parser, node, s_on_node_encountered_fn, user_data);
    }

    struct aws_credentials *credentials = user_data;
    struct aws_byte_cursor credential_data;
    AWS_ZERO_STRUCT(credential_data);
    if (aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_access_key_id_name)) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->access_key_id =
            aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);

        if (credentials->access_key_id) {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(credentials=%p): AccessKeyId %s",
                (void *)credentials,
                aws_string_c_str(credentials->access_key_id));
        }
    }

    if (aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_secret_key_name)) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->secret_access_key =
            aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);
    }

    if (aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_session_token_name)) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->session_token =
            aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);
    }

    return true;
}

/* called upon completion of http request */
static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    int http_response_code = 0;
    struct sts_creds_provider_user_data *provider_user_data = user_data;
    struct aws_credentials_provider_sts_impl *provider_impl = provider_user_data->provider->impl;

    if (provider_impl->function_table->aws_http_stream_get_incoming_response_status(stream, &http_response_code)) {
        goto finish;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): AssumeRole call completed with http status %d",
        (void *)provider_user_data->provider,
        http_response_code);
    if (!error_code && http_response_code == AWS_HTTP_STATUS_CODE_200_OK) {
        struct aws_xml_parser xml_parser;
        struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&provider_user_data->output_buf);

        if (aws_xml_parser_init(&xml_parser, provider_user_data->provider->allocator, &payload_cur, 0)) {
            goto finish;
        }

        provider_user_data->credentials =
            aws_mem_calloc(provider_user_data->allocator, 1, sizeof(struct aws_credentials));

        uint64_t now = UINT64_MAX;
        if (provider_impl->system_clock_fn(&now) != AWS_OP_SUCCESS) {
            goto finish;
        }

        uint64_t now_seconds = aws_timestamp_convert(now, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_SECS, NULL);
        provider_user_data->credentials->expiration_timepoint_seconds = now_seconds + provider_impl->duration_seconds;

        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(credentials=%p): parsing credentials",
            (void *)provider_user_data->credentials);
        provider_user_data->credentials->allocator = provider_user_data->allocator;
        if (aws_xml_parser_parse(&xml_parser, s_on_node_encountered_fn, provider_user_data->credentials)) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "{credentials=%p): parsing failed with error %s",
                (void *)provider_user_data->credentials,
                aws_error_debug_str(aws_last_error()));
            goto finish;
        }

        aws_xml_parser_clean_up(&xml_parser);

        if (!(provider_user_data->credentials->access_key_id && provider_user_data->credentials->secret_access_key &&
              provider_user_data->credentials->session_token)) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p): credentials document was corrupted, treating as an error.",
                (void *)provider_user_data->provider);
            aws_credentials_destroy(provider_user_data->credentials);
            provider_user_data->credentials = NULL;
        }
    }

finish:
    provider_impl->function_table->aws_http_stream_release(stream);
    s_clean_up_user_data(provider_user_data);
}

/* called upon acquiring a connection from the pool */
static void s_on_connection_setup_fn(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct sts_creds_provider_user_data *provider_user_data = user_data;
    struct aws_credentials_provider_sts_impl *provider_impl = provider_user_data->provider->impl;
    struct aws_http_stream *stream = NULL;

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): connection returned with error code %d",
        (void *)provider_user_data->provider,
        error_code);

    if (error_code) {
        aws_raise_error(error_code);
        goto error;
    }
    provider_user_data->connection = connection;

    if (aws_byte_buf_init(&provider_user_data->output_buf, provider_impl->provider->allocator, 2048)) {
        goto error;
    }

    struct aws_http_make_request_options options = {
        .user_data = user_data,
        .request = provider_user_data->message,
        .self_size = sizeof(struct aws_http_make_request_options),
        .on_response_headers = NULL,
        .on_response_header_block_done = NULL,
        .on_response_body = s_on_incoming_body_fn,
        .on_complete = s_on_stream_complete_fn,
    };

    stream = provider_impl->function_table->aws_http_connection_make_request(connection, &options);

    if (!stream) {
        goto error;
    }

    if (provider_impl->function_table->aws_http_stream_activate(stream)) {
        goto error;
    }

    return;
error:
    provider_impl->function_table->aws_http_stream_release(stream);
    s_clean_up_user_data(provider_user_data);
}

/* called once sigv4 signing is complete. */
void s_on_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {
    (void)result;
    (void)error_code;
    struct sts_creds_provider_user_data *provider_user_data = userdata;
    struct aws_credentials_provider_sts_impl *sts_impl = provider_user_data->provider->impl;

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): signing completed with error code %d",
        (void *)provider_user_data->provider,
        error_code);

    if (error_code) {
        aws_raise_error(error_code);
        goto error;
    }

    if (aws_apply_signing_result_to_http_request(
            provider_user_data->message, provider_user_data->provider->allocator, result)) {
        goto error;
    }

    sts_impl->function_table->aws_http_connection_manager_acquire_connection(
        sts_impl->connection_manager, s_on_connection_setup_fn, provider_user_data);
    return;

error:
    s_clean_up_user_data(provider_user_data);
}

static int s_sts_get_creds(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p): fetching credentials", (void *)provider);

    struct aws_credentials_provider_sts_impl *sts_impl = provider->impl;
    struct sts_creds_provider_user_data *provider_user_data =
        aws_mem_calloc(provider->allocator, 1, sizeof(struct sts_creds_provider_user_data));

    if (!provider_user_data) {
        return AWS_OP_ERR;
    }

    provider_user_data->allocator = provider->allocator;
    provider_user_data->provider = provider;
    aws_credentials_provider_acquire(provider);
    provider_user_data->callback = callback;
    provider_user_data->user_data = user_data;

    provider_user_data->message = aws_http_message_new_request(provider->allocator);

    if (!provider_user_data->message) {
        goto error;
    }

    if (aws_http_message_add_header(provider_user_data->message, s_host_header)) {
        goto error;
    }

    if (aws_http_message_add_header(provider_user_data->message, s_content_type_header)) {
        goto error;
    }

    if (aws_http_message_add_header(provider_user_data->message, s_api_version_header)) {
        goto error;
    }

    if (aws_byte_buf_init(&provider_user_data->payload_body, provider->allocator, 256)) {
        goto error;
    }

    if (s_write_body_to_buffer(provider, &provider_user_data->payload_body)) {
        goto error;
    }

    char content_length[21];
    AWS_ZERO_ARRAY(content_length);
    snprintf(content_length, sizeof(content_length), "%" PRIu64, (uint64_t)provider_user_data->payload_body.len);

    struct aws_http_header content_len_header = {
        .name = s_content_length,
        .value = aws_byte_cursor_from_c_str(content_length),
    };

    if (aws_http_message_add_header(provider_user_data->message, content_len_header)) {
        goto error;
    }

    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&provider_user_data->payload_body);
    provider_user_data->input_stream =
        aws_input_stream_new_from_cursor(provider_user_data->provider->allocator, &payload_cur);

    if (!provider_user_data->input_stream) {
        goto error;
    }

    aws_http_message_set_body_stream(provider_user_data->message, provider_user_data->input_stream);

    if (aws_http_message_set_request_method(provider_user_data->message, aws_http_method_post)) {
        goto error;
    }

    if (aws_http_message_set_request_path(provider_user_data->message, s_path)) {
        goto error;
    }

    provider_user_data->signable = aws_signable_new_http_request(provider->allocator, provider_user_data->message);

    if (!provider_user_data->signable) {
        goto error;
    }

    provider_user_data->signing_config.algorithm = AWS_SIGNING_ALGORITHM_SIG_V4_HEADER;
    provider_user_data->signing_config.body_signing_type = AWS_BODY_SIGNING_ON;
    provider_user_data->signing_config.config_type = AWS_SIGNING_CONFIG_AWS;
    provider_user_data->signing_config.credentials_provider = sts_impl->provider;
    aws_date_time_init_now(&provider_user_data->signing_config.date);
    provider_user_data->signing_config.region = s_signing_region;
    provider_user_data->signing_config.service = s_service_name;
    provider_user_data->signing_config.use_double_uri_encode = false;

    if (aws_sign_request_aws(
            provider->allocator,
            provider_user_data->signable,
            (struct aws_signing_config_base *)&provider_user_data->signing_config,
            s_on_signing_complete,
            provider_user_data)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:
    AWS_LOGF_ERROR(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): error occurred while creating an http request for signing: %s",
        (void *)provider_user_data->provider,
        aws_error_debug_str(aws_last_error()));
    if (provider_user_data) {
        s_clean_up_user_data(provider_user_data);
    } else {
        callback(NULL, user_data);
    }
    return AWS_OP_ERR;
}

static void s_on_credentials_provider_shutdown(void *user_data) {
    struct aws_credentials_provider *provider = user_data;
    if (provider == NULL) {
        return;
    }

    struct aws_credentials_provider_sts_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    /* The wrapped provider has shut down, invoke its shutdown callback if there was one */
    if (impl->source_shutdown_options.shutdown_callback != NULL) {
        impl->source_shutdown_options.shutdown_callback(impl->source_shutdown_options.shutdown_user_data);
    }

    /* Invoke our own shutdown callback */
    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_string_destroy(impl->role_session_name);
    aws_string_destroy(impl->assume_role_profile);

    if (impl->owns_ctx) {
        aws_tls_ctx_destroy(impl->ctx);
    }

    aws_tls_connection_options_clean_up(&impl->connection_options);
    aws_mem_release(provider->allocator, provider);
}

void s_destroy(struct aws_credentials_provider *provider) {
    AWS_LOGF_TRACE(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p): cleaning up credentials provider", (void *)provider);

    struct aws_credentials_provider_sts_impl *sts_impl = provider->impl;

    if (sts_impl->connection_manager) {
        sts_impl->function_table->aws_http_connection_manager_release(sts_impl->connection_manager);
    }

    aws_credentials_provider_release(sts_impl->provider);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_sts_vtable = {
    .get_credentials = s_sts_get_creds,
    .destroy = s_destroy,
};

struct aws_credentials_provider *aws_credentials_provider_new_sts(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_sts_options *options) {
    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_sts_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_sts_impl));

    AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "static: creating STS credentials provider");
    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_sts_vtable, impl);

    impl->function_table = &s_default_function_table;

    if (options->function_table) {
        impl->function_table = options->function_table;
    }

    if (options->tls_ctx) {
        AWS_LOGF_TRACE(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): tls context provided, using pre-built tls context.",
            (void *)provider);
        impl->ctx = options->tls_ctx;
    } else {
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
            goto cleanup_provider;
        }

        impl->owns_ctx = true;
    }

    if (!options->creds_provider) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p): A credentials provider must be specified", (void *)provider);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto cleanup_provider;
    }

    impl->role_session_name =
        aws_string_new_from_array(allocator, options->session_name.ptr, options->session_name.len);

    if (!impl->role_session_name) {
        goto cleanup_provider;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): using session_name %s",
        (void *)provider,
        aws_string_c_str(impl->role_session_name));

    impl->assume_role_profile = aws_string_new_from_array(allocator, options->role_arn.ptr, options->role_arn.len);

    if (!impl->assume_role_profile) {
        goto cleanup_provider;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): using assume_role_arn %s",
        (void *)provider,
        aws_string_c_str(impl->assume_role_profile));

    impl->duration_seconds = options->duration_seconds;

    if (options->system_clock_fn != NULL) {
        impl->system_clock_fn = options->system_clock_fn;
    } else {
        impl->system_clock_fn = aws_sys_clock_get_ticks;
    }

    /* minimum for STS is 900 seconds*/
    if (impl->duration_seconds < aws_sts_assume_role_default_duration_secs) {
        impl->duration_seconds = aws_sts_assume_role_default_duration_secs;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): using credentials duration %" PRIu16,
        (void *)provider,
        impl->duration_seconds);

    impl->provider = options->creds_provider;
    aws_credentials_provider_acquire(impl->provider);

    aws_tls_connection_options_init_from_ctx(&impl->connection_options, impl->ctx);

    if (aws_tls_connection_options_set_server_name(&impl->connection_options, allocator, &s_host_header.value)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to create a tls connection options with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto cleanup_provider;
    }

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV6,
        .connect_timeout_ms = 3000,
    };

    struct aws_http_connection_manager_options connection_manager_options = {
        .bootstrap = options->bootstrap,
        .host = s_host_header.value,
        .initial_window_size = SIZE_MAX,
        .max_connections = 2,
        .port = 443,
        .socket_options = &socket_options,
        .tls_connection_options = &impl->connection_options,
    };

    impl->connection_manager =
        impl->function_table->aws_http_connection_manager_new(allocator, &connection_manager_options);

    if (!impl->connection_manager) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p): failed to create a connection manager with error %s",
            (void *)provider,
            aws_error_debug_str(aws_last_error()));
        goto cleanup_provider;
    }

    /*
     * Save the wrapped provider's shutdown callback and then swap it with our own.
     */
    impl->source_shutdown_options = impl->provider->shutdown_options;
    impl->provider->shutdown_options.shutdown_callback = s_on_credentials_provider_shutdown;
    impl->provider->shutdown_options.shutdown_user_data = provider;

    provider->shutdown_options = options->shutdown_options;

    return provider;

cleanup_provider:
    aws_credentials_provider_release(provider);

    return NULL;
}
