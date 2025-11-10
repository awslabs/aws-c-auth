/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/auth/credentials.h>
#include <inttypes.h>

#include <aws/auth/private/aws_http_credentials_provider.h>
#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/auth/private/login_token_utils.h>
#include <aws/common/environment.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

AWS_STATIC_STRING_FROM_LITERAL(s_login_service_host_prefix, "signin");
AWS_STATIC_STRING_FROM_LITERAL(s_login_service_name, "signin");
AWS_STATIC_STRING_FROM_LITERAL(s_login_service_env_name, "SIGNIN");

AWS_STATIC_STRING_FROM_LITERAL(s_login_session, "login_session");
AWS_STATIC_STRING_FROM_LITERAL(s_login_region, "region");
AWS_STATIC_STRING_FROM_LITERAL(s_login_cache_env_var, "AWS_LOGIN_CACHE_DIRECTORY");
AWS_STATIC_STRING_FROM_LITERAL(s_login_endpoint, "/v1/token");
AWS_STATIC_STRING_FROM_LITERAL(s_scheme_literal, "https://");

struct login_parameters {
    struct aws_allocator *allocator;
    struct aws_string *endpoint;
    struct aws_string *login_session;
    struct aws_string *login_region;
    struct aws_string *login_directory_override;
};

struct login_request_data {
    struct aws_login_token *token;
    struct aws_input_stream *body_stream;
    struct aws_byte_buf underlying_body;
};

static void s_parameters_destroy(void *parameters) {
    if (!parameters) {
        return;
    }
    struct login_parameters *login_parameters = parameters;
    aws_string_destroy(login_parameters->endpoint);
    aws_string_destroy(login_parameters->login_session);
    aws_string_destroy(login_parameters->login_region);
    aws_string_destroy(login_parameters->login_directory_override);
    aws_mem_release(login_parameters->allocator, login_parameters);
}

static struct login_parameters *s_parameters_new(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_login_options *options) {

    struct login_parameters *parameters = aws_mem_calloc(allocator, 1, sizeof(struct login_parameters));
    parameters->allocator = allocator;
    bool success = false;

    struct aws_profile_collection *config_profile_collection = NULL;
    struct aws_string *profile_name = NULL;

    profile_name = aws_get_profile_name(allocator, &options->profile_name_override);
    if (!profile_name) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: failed to resolve profile name");
        goto on_finish;
    }
    if (options->config_file_cached) {
        /* Use cached config file */
        config_profile_collection = aws_profile_collection_acquire(options->config_file_cached);
    } else {
        /* load config file */
        config_profile_collection =
            aws_load_profile_collection_from_config_file(allocator, options->config_file_name_override);
    }

    if (!config_profile_collection) {
        goto on_finish;
    }

    const struct aws_profile *profile = aws_profile_collection_get_profile(config_profile_collection, profile_name);
    if (!profile) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: failed to load \"%s\" profile", aws_string_c_str(profile_name));
        goto on_finish;
    }

    if (options->login_session.len > 0) {
        parameters->login_session = aws_string_new_from_cursor(allocator, &options->login_session);
    } else {
        const struct aws_profile_property *login_session = aws_profile_get_property(profile, s_login_session);
        if (login_session) {
            parameters->login_session =
                aws_string_new_from_string(allocator, aws_profile_property_get_value(login_session));
        }
    }

    if (!parameters->login_session) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: login_session is missing");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_SESSION_MISSING);
        goto on_finish;
    }

    if (options->login_region.len > 0) {
        parameters->login_region = aws_string_new_from_cursor(allocator, &options->login_region);
    } else {
        const struct aws_profile_property *login_region = aws_profile_get_property(profile, s_login_region);
        if (login_region) {
            parameters->login_region =
                aws_string_new_from_string(allocator, aws_profile_property_get_value(login_region));
        }
    }

    if (!parameters->login_region) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: region is missing");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_REGION_MISSING);
        goto on_finish;
    }

    if (options->login_cache_directory_override.len > 0) {
        parameters->login_directory_override =
            aws_string_new_from_cursor(allocator, &options->login_cache_directory_override);
    } else {
        if (aws_get_environment_value(allocator, s_login_cache_env_var, &parameters->login_directory_override)) {
            AWS_LOGF_TRACE(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: no override for cache dir found");
        }
    }

    const struct aws_byte_cursor suffix_override = aws_byte_cursor_from_c_str("aws.amazon.com");
    struct aws_string *region = aws_string_new_from_cursor(allocator, &options->login_region);

    /* determine endpoint */
    if (aws_credentials_provider_construct_endpoint(
            allocator,
            &parameters->endpoint,
            region,
            s_login_service_host_prefix,
            s_login_service_env_name,
            s_login_service_name,
            config_profile_collection,
            profile,
            &suffix_override,
            true)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to construct login endpoint");
        aws_string_destroy(region);
        goto on_finish;
    }
    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Successfully loaded all required parameters for login credentials provider.");
    aws_string_destroy(region);
    success = true;

on_finish:
    if (!success) {
        s_parameters_destroy(parameters);
        parameters = NULL;
    }
    aws_string_destroy(profile_name);
    aws_profile_collection_release(config_profile_collection);

    return parameters;
}

static int s_get_jwt_endpoint(
    struct aws_allocator *allocator,
    struct login_parameters *parameters,
    struct aws_byte_cursor *path_cursor,
    struct aws_byte_buf *endpoint_buf) {
    struct aws_byte_cursor scheme_cursor = aws_byte_cursor_from_string(s_scheme_literal);
    struct aws_byte_cursor endpoint_cursor = aws_byte_cursor_from_string(parameters->endpoint);
    if (aws_byte_buf_init_copy_from_cursor(endpoint_buf, allocator, scheme_cursor) ||
        aws_byte_buf_append_dynamic(endpoint_buf, &endpoint_cursor) ||
        aws_byte_buf_append_dynamic(endpoint_buf, path_cursor)) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

int s_login_create_request_fn(struct aws_http_query_context *http_query_context, void *user_data) {
    (void)user_data;
    bool success = false;
    struct aws_byte_buf dpop_header_value;
    AWS_ZERO_STRUCT(dpop_header_value);
    struct aws_byte_buf body_buf;
    AWS_ZERO_STRUCT(body_buf);
    struct aws_byte_buf endpoint_buf;
    AWS_ZERO_STRUCT(endpoint_buf);
    struct aws_byte_buf file_path_buf;
    AWS_ZERO_STRUCT(file_path_buf);

    struct login_parameters *parameters = http_query_context->parameters;
    struct aws_allocator *allocator = parameters->allocator;

    /*
     * load the token from disk and fail if it fails for any reason.
     */
    if (aws_login_token_construct_token_path(
            allocator, parameters->login_session, parameters->login_directory_override, &file_path_buf)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to load login token with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_finish;
    }

    struct aws_login_token *token = aws_login_token_new_from_file(allocator, &file_path_buf);
    if (!token) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to load login token with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        aws_mem_release(allocator, token);
        goto on_finish;
    }

    struct login_request_data *request_data = http_query_context->request_data;
    request_data->token = token;

    /* Set path and query */
    struct aws_byte_cursor path_cursor = aws_byte_cursor_from_string(s_login_endpoint);

    if (aws_byte_buf_init_copy_from_cursor(&http_query_context->path_and_query, allocator, path_cursor)) {
        goto on_finish;
    }

    /* Set content-type header */
    struct aws_http_header content_type_header = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Type"),
        .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("application/json"),
    };

    /* Set DPoP header */
    s_get_jwt_endpoint(allocator, parameters, &path_cursor, &endpoint_buf);
    struct aws_byte_cursor endpoint = aws_byte_cursor_from_buf(&endpoint_buf);

    if (aws_login_token_get_dpop_header(allocator, token, endpoint, &dpop_header_value)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to generate dpop header with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_finish;
    }

    struct aws_http_header dpop_header = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("DPoP"),
        .value = aws_byte_cursor_from_buf(&dpop_header_value),
    };

    /* Set body stream */
    if (aws_login_token_get_body(allocator, token, &body_buf)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to log in body with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_finish;
    }

    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&body_buf);
    struct aws_input_stream *body_stream = aws_input_stream_new_from_cursor(allocator, &body_cursor);
    aws_http_message_set_body_stream(http_query_context->request, body_stream);
    request_data->body_stream = body_stream;
    request_data->underlying_body = body_buf;

    /* Set content-length header */
    int64_t stream_length = 0;
    if (aws_input_stream_get_length(body_stream, &stream_length)) {
        AWS_FATAL_ASSERT(false);
    }
    char content_length_buffer[64] = "";
    snprintf(content_length_buffer, sizeof(content_length_buffer), "%" PRIu64, (uint64_t)stream_length);
    struct aws_byte_cursor content_length_cursor =
        aws_byte_cursor_from_array(content_length_buffer, strlen(content_length_buffer));
    struct aws_http_header cl_header = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
        .value = content_length_cursor,
    };
    if (aws_http_message_add_header(http_query_context->request, cl_header)) {
        AWS_FATAL_ASSERT(false);
    }

    /* Set Host header */
    struct aws_http_header host_header = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
        .value = aws_byte_cursor_from_string(parameters->endpoint),
    };

    /* Set all parameters on request */
    if (aws_http_message_add_header(http_query_context->request, content_type_header) ||
        aws_http_message_add_header(http_query_context->request, dpop_header) ||
        aws_http_message_add_header(http_query_context->request, host_header)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to add http header with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_finish;
    }

    if (aws_http_message_set_request_method(http_query_context->request, aws_http_method_post)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to set request method with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_finish;
    }

    if (aws_http_message_set_request_path(
            http_query_context->request, aws_byte_cursor_from_buf(&http_query_context->path_and_query))) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to set request path with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_finish;
    }

    success = true;
on_finish:
    aws_byte_buf_clean_up(&dpop_header_value);
    aws_byte_buf_clean_up(&endpoint_buf);
    aws_byte_buf_clean_up(&file_path_buf);
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static void s_login_finalize_credentials_fn(struct aws_http_query_context *http_query_context) {
    struct login_parameters *parameters = http_query_context->parameters;
    struct aws_credentials *credentials = NULL;
    struct aws_login_refresh_response *refresh_token = NULL;
    struct aws_byte_buf file_path_buf;
    AWS_ZERO_STRUCT(file_path_buf);

    /*
     * if the request is successful we want to parse the response, extract the refreshed parts and write back to
     * disk the changed parts.
     */
    if (http_query_context->error_code == AWS_ERROR_SUCCESS) {
        struct aws_byte_cursor payload = aws_byte_cursor_from_buf(&http_query_context->payload);
        refresh_token = aws_login_refresh_new_from_json_document(http_query_context->allocator, payload);
        if (!refresh_token) {
            AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: failed to parse refresh response");
            http_query_context->error_code = aws_last_error();
            goto on_finalize;
        }

        struct aws_byte_cursor access_key_id = aws_login_refresh_get_access_key_id(refresh_token);
        struct aws_byte_cursor secret_access_key = aws_login_refresh_get_secret_access_key(refresh_token);
        struct aws_byte_cursor session_token = aws_login_refresh_get_session_token(refresh_token);
        struct aws_date_time expires_at = aws_login_refresh_get_expires_at(refresh_token);
        struct aws_byte_cursor refresh_token_value = aws_login_refresh_get_refresh_token(refresh_token);

        struct login_request_data *request_data = http_query_context->request_data;
        struct aws_credentials_options creds_option = {
            .access_key_id_cursor = access_key_id,
            .secret_access_key_cursor = secret_access_key,
            .session_token_cursor = session_token,
            .account_id_cursor = aws_login_token_get_account_id(request_data->token),
            .expiration_timepoint_seconds = (uint64_t)aws_date_time_as_epoch_secs(&expires_at),
        };
        credentials = aws_credentials_new_with_options(http_query_context->allocator, &creds_option);

        aws_login_token_set_access_key_id(request_data->token, access_key_id);
        aws_login_token_set_secret_access_key(request_data->token, secret_access_key);
        aws_login_token_set_session_token(request_data->token, session_token);
        aws_login_token_set_expires_at(request_data->token, expires_at);
        aws_login_token_set_refresh_token(request_data->token, refresh_token_value);

        if (aws_login_token_construct_token_path(
                parameters->allocator,
                parameters->login_session,
                parameters->login_directory_override,
                &file_path_buf)) {
        }
        if (aws_login_token_write_token_file(request_data->token, http_query_context->allocator, &file_path_buf)) {
            AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: failed to write to token file");
        }
        aws_byte_buf_clean_up(&file_path_buf);
    }

on_finalize:
    /* pass the credentials back */
    http_query_context->original_callback(
        credentials, http_query_context->error_code, http_query_context->original_user_data);

    /* clean up */
    aws_login_refresh_destroy(refresh_token);
    aws_mem_release(http_query_context->allocator, refresh_token);
    aws_credentials_release(credentials);
}

static void s_login_request_data_create(struct aws_http_query_context *query_context) {
    struct login_request_data *login_request_data =
        aws_mem_calloc(query_context->allocator, 1, sizeof(struct login_request_data));
    query_context->request_data = login_request_data;
}

void s_login_request_data_reset(struct aws_http_query_context *query_context) {
    struct login_request_data *login_request_data = query_context->request_data;
    struct aws_allocator *allocator = query_context->allocator;
    if (login_request_data->token) {
        aws_login_token_destroy(login_request_data->token);
        aws_mem_release(allocator, login_request_data->token);
    }
    if (login_request_data->body_stream) {
        aws_input_stream_release(login_request_data->body_stream);
    }
    aws_byte_buf_clean_up(&login_request_data->underlying_body);
}

static struct aws_http_credentials_provider_request_vtable s_login_request_vtable = {
    .clean_up_parameters_fn = s_parameters_destroy,
    .finalize_credentials_fn = s_login_finalize_credentials_fn,
    .create_request_fn = s_login_create_request_fn,
    .create_request_data_fn = s_login_request_data_create,
    .reset_request_data_fn = s_login_request_data_reset,
};

struct aws_credentials_provider *aws_credentials_provider_new_login(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_login_options *options) {

    struct login_parameters *parameters = s_parameters_new(allocator, options);
    if (!parameters) {
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_SESSION_MISSING);
        return NULL;
    }

    struct aws_credentials_provider *provider = NULL;
    struct aws_http_credentials_provider_user_data *login_user_data = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &login_user_data,
        sizeof(struct aws_http_credentials_provider_user_data));

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*login_user_data);

    struct aws_credentials_provider_http_options http_options;
    AWS_ZERO_STRUCT(http_options);

    http_options.shutdown_options = options->shutdown_options;
    http_options.bootstrap = options->bootstrap;
    http_options.tls_ctx = options->tls_ctx;
    http_options.function_table = options->function_table;
    http_options.endpoint = aws_byte_cursor_from_string(parameters->endpoint);
    http_options.max_connections = 2;

    login_user_data->parameters = parameters;
    login_user_data->request_vtable = &s_login_request_vtable;

    if (aws_http_credentials_provider_init_base(allocator, provider, &http_options, login_user_data)) {
        goto on_error;
    }

    return provider;
on_error:
    aws_credentials_provider_destroy(provider);
    return NULL;
}
