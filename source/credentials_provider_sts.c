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
#include <aws/auth/signer.h>
#include <aws/auth/signing_config.h>
#include <aws/auth/signable.h>
#include <aws/common/string.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/http/connection_manager.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>

#include <inttypes.h>
#include <aws/io/socket.h>
#include <aws/io/uri.h>

static struct aws_byte_cursor s_host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("host");
static struct aws_byte_cursor s_host_name_val = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("sts.amazonaws.com");
static struct aws_byte_cursor s_content_type = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("content-type");
static struct aws_byte_cursor s_content_type_val = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("application/x-www-form-urlencoded");
static struct aws_byte_cursor s_api_version = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("x-amz-api-version");
static struct aws_byte_cursor s_api_version_val = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("2011-06-15");
static struct aws_byte_cursor s_content_length = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("content-length");
static struct aws_byte_cursor s_method = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("POST");
static struct aws_byte_cursor s_path = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("/");
static struct aws_byte_cursor s_signing_region = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("us-east-1");
static struct aws_byte_cursor s_service_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("sts");
static struct aws_byte_cursor s_assume_role_root_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AssumeRoleResponse");
static struct aws_byte_cursor s_assume_role_result_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AssumeRoleResult");
static struct aws_byte_cursor s_assumed_role_user_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AssumedRoleUser");
static struct aws_byte_cursor s_assume_role_credentials_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Credentials");
static struct aws_byte_cursor s_assume_role_session_token_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("SessionToken");
static struct aws_byte_cursor s_assume_role_secret_key_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("SecretAccessKey");
static struct aws_byte_cursor s_assume_role_access_key_id_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("AccessKeyId");

struct aws_credentials_provider_sts_impl {
    struct aws_http_connection_manager *connection_manager;
    struct aws_signer *signer;
    struct aws_string *assume_role_profile;
    struct aws_string *role_session_name;
    uint16_t duration_seconds;
    struct aws_credentials_provider *provider;
    struct aws_tls_ctx *ctx;
    struct aws_tls_connection_options connection_options;
    bool owns_ctx;
};

struct sts_creds_provider_user_data {
    struct aws_credentials_provider *provider;
    aws_on_get_credentials_callback_fn *callback;
    struct aws_byte_buf payload_body;
    struct aws_input_stream *input_stream;
    struct aws_signable *signable;
    struct aws_signing_config_aws signing_config;
    struct aws_http_message *message;
    struct aws_byte_buf output_buf;
    void *user_data;
};

static int s_write_body_to_buffer(struct aws_credentials_provider *provider, struct aws_byte_buf *body) {
    struct aws_credentials_provider_sts_impl *provider_impl = provider->impl;

    struct aws_byte_cursor working_cur = aws_byte_cursor_from_c_str("Version=2011-06-15&Action=AssumeRole&RoleArn=");
    aws_byte_buf_append_dynamic(body, &working_cur);
    struct aws_byte_cursor role_cur = aws_byte_cursor_from_string(provider_impl->assume_role_profile);
    aws_byte_buf_append_encoding_uri_param(body, &role_cur);
    working_cur = aws_byte_cursor_from_c_str("&RoleSessionName=");
    aws_byte_buf_append_dynamic(body, &working_cur);
    struct aws_byte_cursor session_cur = aws_byte_cursor_from_string(provider_impl->role_session_name);
    aws_byte_buf_append_encoding_uri_param(body, &session_cur);
    working_cur = aws_byte_cursor_from_c_str("&DurationSeconds=");
    aws_byte_buf_append_dynamic(body, &working_cur);
    char duration_seconds[6];
    AWS_ZERO_ARRAY(duration_seconds);
    sprintf(duration_seconds, "%" PRIu16, provider_impl->duration_seconds);
    working_cur = aws_byte_cursor_from_c_str(duration_seconds);
    aws_byte_buf_append_dynamic(body, &working_cur);

    return AWS_OP_SUCCESS;
}

static int s_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;

    struct sts_creds_provider_user_data *provider_user_data = user_data;
    aws_byte_buf_append_dynamic(&provider_user_data->output_buf, data);
    return AWS_OP_SUCCESS;
}

static bool s_on_node_encountered_fn(struct aws_xml_parser *parser, struct aws_xml_node *node, void *user_data) {
    if (aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_root_name) ||
        aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_result_name) ||
        aws_byte_cursor_eq_ignore_case(&node->name, &s_assumed_role_user_name) ||
        aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_credentials_name)) {
        return aws_xml_node_traverse(parser, node, s_on_node_encountered_fn, user_data);
    }

    struct aws_credentials *credentials = user_data;
    struct aws_byte_cursor credential_data;
    AWS_ZERO_STRUCT(credential_data);
    if (aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_access_key_id_name)) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->access_key_id = aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);
    }

    if (aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_secret_key_name)) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->secret_access_key = aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);
    }

    if (aws_byte_cursor_eq_ignore_case(&node->name, &s_assume_role_session_token_name)) {
        aws_xml_node_as_body(parser, node, &credential_data);
        credentials->session_token = aws_string_new_from_array(credentials->allocator, credential_data.ptr, credential_data.len);
    }

    return true;
}

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    int http_response_code = 0;
    struct sts_creds_provider_user_data *provider_user_data = user_data;
    struct aws_credentials_provider_sts_impl *provider_impl = provider_user_data->provider->impl;

    aws_http_stream_get_incoming_response_status(stream, &http_response_code);

    if (!error_code && http_response_code == 200) {
        struct aws_xml_parser xml_parser;
        struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&provider_user_data->output_buf);

        aws_xml_parser_init(&xml_parser, provider_user_data->provider->allocator, &payload_cur);

        struct aws_credentials credentials;
        credentials.allocator = provider_user_data->provider->allocator;
        aws_xml_parser_parse(&xml_parser, s_on_node_encountered_fn, &credentials);

        provider_user_data->callback(&credentials, provider_user_data->user_data);
        aws_xml_parser_clean_up(&xml_parser);
    } else {

    }

    aws_http_connection_manager_release_connection(provider_impl->connection_manager, aws_http_stream_get_connection(stream));
    struct aws_credentials_provider *this_provider = provider_user_data->provider;
    aws_credentials_provider_release(this_provider);
    // release the rest.
}

static void s_on_connection_setup_fn(
        struct aws_http_connection *connection,
        int error_code,
        void *user_data) {
    struct sts_creds_provider_user_data *provider_user_data = user_data;
    struct aws_credentials_provider_sts_impl *provider_impl = provider_user_data->provider->impl;

    if (!error_code) {
        aws_byte_buf_init(&provider_user_data->output_buf, provider_impl->provider->allocator, 2048);

        struct aws_http_make_request_options options = {
                .manual_window_management = false,
                .user_data = user_data,
                .request = provider_user_data->message,
                .self_size = sizeof(struct aws_http_make_request_options),
                .on_response_headers = NULL,
                .on_response_header_block_done = NULL,
                .on_response_body = s_on_incoming_body_fn,
                .on_complete = s_on_stream_complete_fn,
        };

        aws_http_connection_make_request(connection, &options);


    }
}

void s_on_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {
    (void)result;
    (void)error_code;
    struct sts_creds_provider_user_data *provider_user_data = userdata;
    struct aws_credentials_provider_sts_impl *sts_impl = provider_user_data->provider->impl;
    aws_apply_signing_result_to_http_request(provider_user_data->message, provider_user_data->provider->allocator, result);
    aws_http_connection_manager_acquire_connection(sts_impl->connection_manager, s_on_connection_setup_fn, provider_user_data);
}

static int s_sts_get_creds(
        struct aws_credentials_provider *provider,
        aws_on_get_credentials_callback_fn callback,
        void *user_data) {

    struct aws_credentials_provider_sts_impl *sts_impl = provider->impl;
    struct sts_creds_provider_user_data *provider_user_data = aws_mem_calloc(provider->allocator, 1, sizeof(struct sts_creds_provider_user_data));
    provider_user_data->provider = provider;
    provider_user_data->callback = callback;
    provider_user_data->user_data = user_data;

    provider_user_data->message = aws_http_message_new_request(provider->allocator);
    struct aws_http_header host_header = {
            .name = s_host_name,
            .value = s_host_name_val,
    };

    aws_http_message_add_header(provider_user_data->message, host_header);

    struct aws_http_header content_type_header = {
            .name = s_content_type,
            .value = s_content_type_val,
    };

    aws_http_message_add_header(provider_user_data->message, content_type_header);

    struct aws_http_header api_version_header = {
            .name = s_api_version,
            .value = s_api_version_val,
    };

    aws_http_message_add_header(provider_user_data->message, api_version_header);

    aws_byte_buf_init(&provider_user_data->payload_body, provider->allocator, 2048);
    s_write_body_to_buffer(provider, &provider_user_data->payload_body);

    char content_length[21];
    AWS_ZERO_ARRAY(content_length);
    sprintf(content_length, "%" PRIu64, provider_user_data->payload_body.len);

    struct aws_http_header content_len_header = {
            .name = s_content_length,
            .value = aws_byte_cursor_from_c_str(content_length),
    };
    aws_http_message_add_header(provider_user_data->message, content_len_header);

    struct aws_byte_cursor payload_cur = aws_byte_cursor_from_buf(&provider_user_data->payload_body);
    provider_user_data->input_stream = aws_input_stream_new_from_cursor(provider_user_data->provider->allocator, &payload_cur);
    aws_http_message_set_body_stream(provider_user_data->message, provider_user_data->input_stream);

    aws_http_message_set_request_method(provider_user_data->message, s_method);
    aws_http_message_set_request_path(provider_user_data->message, s_path);

    if (sts_impl->signer) {
        provider_user_data->signable = aws_signable_new_http_request(provider->allocator, provider_user_data->message);
        provider_user_data->signing_config.algorithm = AWS_SIGNING_ALGORITHM_SIG_V4_HEADER;
        provider_user_data->signing_config.sign_body = true;
        provider_user_data->signing_config.config_type = AWS_SIGNING_CONFIG_AWS;
        provider_user_data->signing_config.credentials_provider = sts_impl->provider;
        aws_date_time_init_now(&provider_user_data->signing_config.date);
        provider_user_data->signing_config.region = s_signing_region;
        provider_user_data->signing_config.service = s_service_name;
        provider_user_data->signing_config.use_double_uri_encode = false;

        aws_signer_sign_request(sts_impl->signer, provider_user_data->signable, (struct aws_signing_config_base *)&provider_user_data->signing_config, s_on_signing_complete, provider_user_data);
    } else {
        aws_http_connection_manager_acquire_connection(sts_impl->connection_manager, s_on_connection_setup_fn, provider_user_data);
    }

    return AWS_OP_SUCCESS;
}

void s_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_sts_impl *sts_impl = provider->impl;

    aws_http_connection_manager_release(sts_impl->connection_manager);

    if (sts_impl->signer) {
        aws_signer_destroy(sts_impl->signer);
        aws_credentials_provider_release(sts_impl->provider);
    }

    aws_string_destroy(sts_impl->role_session_name);
    aws_string_destroy(sts_impl->assume_role_profile);

    if (sts_impl->owns_ctx) {
        aws_tls_ctx_destroy(sts_impl->ctx);
    }

    aws_tls_connection_options_clean_up(&sts_impl->connection_options);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_sts_vtable = {
        .get_credentials = s_sts_get_creds,
        .clean_up = s_clean_up,
        .shutdown = aws_credentials_provider_shutdown_nil,
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

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_sts_vtable, impl);

    if (options->tls_ctx) {
        impl->ctx = options->tls_ctx;
    } else {
        struct aws_tls_ctx_options tls_options;
        aws_tls_ctx_options_init_default_client(&tls_options, allocator);
        aws_tls_ctx_options_set_verify_peer(&tls_options, false);
        impl->ctx = aws_tls_client_ctx_new(allocator, &tls_options);
        aws_tls_ctx_options_clean_up(&tls_options);
    }

    if (!options->creds_provider && !options->tls_ctx) {
        //this is an error;
        return NULL;
    }

    impl->role_session_name = aws_string_new_from_array(allocator, options->session_name.ptr, options->session_name.len);
    impl->assume_role_profile = aws_string_new_from_array(allocator, options->role_arn.ptr, options->role_arn.len);
    impl->duration_seconds = 900;

    if (options->creds_provider) {
        aws_credentials_provider_acquire(options->creds_provider);
        impl->provider = options->creds_provider;
        impl->signer = aws_signer_new_aws(allocator);
    }

    aws_tls_connection_options_init_from_ctx(&impl->connection_options, impl->ctx);
    aws_tls_connection_options_set_server_name(&impl->connection_options, allocator, &s_host_name_val);

    struct aws_socket_options socket_options = {
            .type = AWS_SOCKET_STREAM,
            .domain = AWS_SOCKET_IPV6,
            .connect_timeout_ms = 3000,
    };

    struct aws_http_connection_manager_options connection_manager_options = {
            .bootstrap = options->bootstrap,
            .host = s_host_name_val,
            .initial_window_size = SIZE_MAX,
            .max_connections = 2,
            .port = 443,
            .socket_options = &socket_options,
            .tls_connection_options = &impl->connection_options,
    };

    impl->connection_manager = aws_http_connection_manager_new(allocator, &connection_manager_options);

    return provider;
}
