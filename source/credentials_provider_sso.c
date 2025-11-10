/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/aws_http_credentials_provider.h>
#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/auth/private/sso_token_providers.h>
#include <aws/auth/private/sso_token_utils.h>

#include <aws/common/clock.h>
#include <aws/common/uri.h>
#include <aws/io/socket.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

AWS_STATIC_STRING_FROM_LITERAL(s_sso_service_host_prefix, "portal.sso");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_service_name, "sso");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_service_env_name, "SSO");

AWS_STATIC_STRING_FROM_LITERAL(s_sso_account_id, "sso_account_id");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_region, "sso_region");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_role_name, "sso_role_name");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_session, "sso_session");

struct sso_parameters {
    struct aws_allocator *allocator;
    struct aws_string *endpoint;
    struct aws_string *sso_account_id;
    struct aws_string *sso_role_name;
    struct aws_credentials_provider *token_provider;
};

struct sso_request_data {
    struct aws_string *token;
};

static void s_parameters_destroy(void *parameters) {
    if (!parameters) {
        return;
    }
    struct sso_parameters *sso_parameters = parameters;
    aws_string_destroy(sso_parameters->endpoint);
    aws_string_destroy(sso_parameters->sso_account_id);
    aws_string_destroy(sso_parameters->sso_role_name);
    aws_credentials_provider_release(sso_parameters->token_provider);
    aws_mem_release(sso_parameters->allocator, sso_parameters);
}

/**
 * Read the config file and construct profile or sso_session token provider based on sso_session property.
 *
 * If the profile contains sso_session property, a valid config example is as follow.
 * [profile sso-profile]
 *   sso_session = dev
 *   sso_account_id = 012345678901
 *   sso_role_name = SampleRole
 *
 * [sso-session dev]
 *   sso_region = us-east-1
 *   sso_start_url = https://d-abc123.awsapps.com/start
 *
 * If the profile does't contains sso_session, the legacy valid config example is as follow.
 * [profile sso-profile]
 *  sso_account_id = 012345678901
 *  sso_region = us-east-1
 *  sso_role_name = SampleRole
 *  sso_start_url = https://d-abc123.awsapps.com/start-beta
 */
static struct sso_parameters *s_parameters_new(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_sso_options *options) {

    struct sso_parameters *parameters = aws_mem_calloc(allocator, 1, sizeof(struct sso_parameters));
    parameters->allocator = allocator;

    struct aws_profile_collection *config_profile_collection = NULL;
    struct aws_string *profile_name = NULL;
    bool success = false;

    profile_name = aws_get_profile_name(allocator, &options->profile_name_override);
    if (!profile_name) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: failed to resolve profile name");
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
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: failed to load \"%s\" profile", aws_string_c_str(profile_name));
        goto on_finish;
    }

    const struct aws_profile_property *sso_account_id = aws_profile_get_property(profile, s_sso_account_id);
    const struct aws_profile_property *sso_role_name = aws_profile_get_property(profile, s_sso_role_name);
    const struct aws_profile_property *sso_region = NULL;

    if (!sso_account_id) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: sso_account_id is missing");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE);
        goto on_finish;
    }
    if (!sso_role_name) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: sso_role_name is missing");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE);
        goto on_finish;
    }

    const struct aws_profile_property *sso_session_property = aws_profile_get_property(profile, s_sso_session);
    /* create the appropriate token provider based on sso_session property is available or not */
    if (sso_session_property) {
        /* construct sso_session token provider */
        struct aws_token_provider_sso_session_options token_provider_options = {
            .config_file_name_override = options->config_file_name_override,
            .config_file_cached = config_profile_collection,
            .profile_name_override = options->profile_name_override,
            .bootstrap = options->bootstrap,
            .tls_ctx = options->tls_ctx,
            .system_clock_fn = options->system_clock_fn,
        };
        parameters->token_provider = aws_token_provider_new_sso_session(allocator, &token_provider_options);
        if (!parameters->token_provider) {
            AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: unable to create a sso token provider");
            aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE);
            goto on_finish;
        }
        sso_region = aws_profile_get_property(
            aws_profile_collection_get_section(
                config_profile_collection,
                AWS_PROFILE_SECTION_TYPE_SSO_SESSION,
                aws_profile_property_get_value(sso_session_property)),
            s_sso_region);
    } else {
        /* construct profile token provider */
        struct aws_token_provider_sso_profile_options token_provider_options = {
            .config_file_name_override = options->config_file_name_override,
            .config_file_cached = config_profile_collection,
            .profile_name_override = options->profile_name_override,
            .system_clock_fn = options->system_clock_fn,
        };

        parameters->token_provider = aws_token_provider_new_sso_profile(allocator, &token_provider_options);
        if (!parameters->token_provider) {
            AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: unable to create a profile token provider");
            aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE);
            goto on_finish;
        }
        sso_region = aws_profile_get_property(profile, s_sso_region);
    }

    if (!sso_region) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: sso_region is missing");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE);
        goto on_finish;
    }

    parameters->sso_account_id = aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_account_id));
    parameters->sso_role_name = aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_role_name));
    /* determine endpoint */
    if (aws_credentials_provider_construct_endpoint(
            allocator,
            &parameters->endpoint,
            aws_profile_property_get_value(sso_region),
            s_sso_service_host_prefix,
            s_sso_service_env_name,
            s_sso_service_name,
            config_profile_collection,
            profile,
            NULL,
            false)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to construct sso endpoint");
        goto on_finish;
    }
    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Successfully loaded all required parameters for sso credentials provider.");
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

/* Request headers. */
AWS_STATIC_STRING_FROM_LITERAL(s_sso_token_header, "x-amz-sso_bearer_token");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_user_agent_header, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_user_agent_header_value, "aws-sdk-crt/sso-credentials-provider");

static void s_on_get_token_callback(struct aws_credentials *credentials, int error_code, void *query_context) {
    struct aws_http_query_context *http_query_context = query_context;
    struct sso_parameters *parameters = http_query_context->parameters;

    if (error_code) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "id=%p: failed to acquire a token, error code %d(%s)",
            (void *)http_query_context->provider,
            error_code,
            aws_error_str(error_code));
        http_query_context->error_code = error_code;
        return;
    }

    struct aws_byte_cursor token = aws_credentials_get_token(credentials);
    AWS_LOGF_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): successfully acquired a token",
        (void *)http_query_context->provider);

    struct sso_request_data *sso_request_data = http_query_context->request_data;
    sso_request_data->token = aws_string_new_from_cursor(http_query_context->allocator, &token);

    struct aws_byte_cursor account_id_cursor = aws_byte_cursor_from_string(parameters->sso_account_id);
    struct aws_byte_cursor role_name_cursor = aws_byte_cursor_from_string(parameters->sso_role_name);
    struct aws_byte_cursor path_cursor = aws_byte_cursor_from_c_str("/federation/credentials?account_id=");
    struct aws_byte_cursor role_name_param_cursor = aws_byte_cursor_from_c_str("&role_name=");
    if (aws_byte_buf_init_copy_from_cursor(
            &http_query_context->path_and_query, http_query_context->provider->allocator, path_cursor) ||
        aws_byte_buf_append_encoding_uri_param(&http_query_context->path_and_query, &account_id_cursor) ||
        aws_byte_buf_append_dynamic(&http_query_context->path_and_query, &role_name_param_cursor) ||
        aws_byte_buf_append_encoding_uri_param(&http_query_context->path_and_query, &role_name_cursor)) {
        goto on_error;
    }

    struct aws_http_header host_header = {
        .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Host"),
        .value = aws_byte_cursor_from_string(parameters->endpoint),
    };

    if (aws_http_message_add_header(http_query_context->request, host_header)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to add http header with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    struct aws_http_header auth_header = {
        .name = aws_byte_cursor_from_string(s_sso_token_header),
        .value = aws_byte_cursor_from_string(sso_request_data->token),
    };
    struct aws_http_header user_agent_header = {
        .name = aws_byte_cursor_from_string(s_sso_user_agent_header),
        .value = aws_byte_cursor_from_string(s_sso_user_agent_header_value),
    };

    if (aws_http_message_add_header(http_query_context->request, auth_header) ||
        aws_http_message_add_header(http_query_context->request, user_agent_header)) {
        goto on_error;
    }

    if (aws_http_message_set_request_method(http_query_context->request, aws_http_method_get)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to set request method with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    if (aws_http_message_set_request_path(
            http_query_context->request, aws_byte_cursor_from_buf(&http_query_context->path_and_query))) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to set request path with error: %s",
            (void *)http_query_context->provider,
            aws_error_debug_str(aws_last_error()));
        goto on_error;
    }

    return;
on_error:
    http_query_context->error_code = aws_last_error();
}

static int s_sso_create_request_fn(struct aws_http_query_context *http_query_context, void *user_data) {
    struct sso_parameters *parameters = http_query_context->parameters;

    if (aws_credentials_provider_get_credentials(parameters->token_provider, s_on_get_token_callback, user_data)) {
        int last_error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "id=%p: failed to get a token, error code %d(%s)",
            (void *)http_query_context->provider,
            last_error_code,
            aws_error_str(last_error_code));

        http_query_context->error_code = last_error_code;
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static void s_sso_finalize_credentials_fn(struct aws_http_query_context *http_query_context) {
    struct sso_parameters *parameters = http_query_context->parameters;
    struct aws_credentials *credentials = NULL;
    struct aws_credentials *creds_with_accound_id = NULL;

    if (http_query_context->error_code == AWS_ERROR_SUCCESS) {
        /* parse credentials */
        struct aws_parse_credentials_from_json_doc_options parse_options = {
            .access_key_id_name = "accessKeyId",
            .secret_access_key_name = "secretAccessKey",
            .token_name = "sessionToken",
            .expiration_name = "expiration",
            .top_level_object_name = "roleCredentials",
            .token_required = true,
            .expiration_required = true,
            .expiration_format = AWS_PCEF_NUMBER_UNIX_EPOCH_MS,
        };

        credentials = aws_parse_credentials_from_json_document(
            http_query_context->allocator, aws_byte_cursor_from_buf(&http_query_context->payload), &parse_options);
    }

    if (!credentials) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) failed to query credentials",
            (void *)http_query_context->provider);

        if (http_query_context->error_code == AWS_ERROR_SUCCESS) {
            http_query_context->error_code = AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE;
        }
    } else {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) successfully queried credentials",
            (void *)http_query_context->provider);
        struct aws_credentials_options creds_option = {
            .access_key_id_cursor = aws_credentials_get_access_key_id(credentials),
            .secret_access_key_cursor = aws_credentials_get_secret_access_key(credentials),
            .session_token_cursor = aws_credentials_get_session_token(credentials),
            .account_id_cursor = aws_byte_cursor_from_string(parameters->sso_account_id),
            .expiration_timepoint_seconds = aws_credentials_get_expiration_timepoint_seconds(credentials),
        };

        creds_with_accound_id = aws_credentials_new_with_options(http_query_context->allocator, &creds_option);
    }

    /* pass the credentials back */
    http_query_context->original_callback(
        creds_with_accound_id, http_query_context->error_code, http_query_context->original_user_data);

    /* clean up */
    aws_credentials_release(credentials);
    aws_credentials_release(creds_with_accound_id);
}

static void s_sso_request_data_create(struct aws_http_query_context *query_context) {
    struct sso_request_data *request_data =
        aws_mem_acquire(query_context->allocator, sizeof(struct sso_request_data *));
    AWS_ZERO_STRUCT(*request_data);
    query_context->request_data = request_data;
}

static void s_sso_request_data_reset(struct aws_http_query_context *query_context) {
    struct sso_request_data *sso_request_data = query_context->request_data;
    if (sso_request_data->token) {
        aws_string_destroy_secure(sso_request_data->token);
        sso_request_data->token = NULL;
    }
}

static struct aws_http_credentials_provider_request_vtable s_sso_request_vtable = {
    .clean_up_parameters_fn = s_parameters_destroy,
    .finalize_credentials_fn = s_sso_finalize_credentials_fn,
    .create_request_fn = s_sso_create_request_fn,
    .create_request_data_fn = s_sso_request_data_create,
    .reset_request_data_fn = s_sso_request_data_reset,
};

struct aws_credentials_provider *aws_credentials_provider_new_sso(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_sso_options *options) {

    struct sso_parameters *parameters = s_parameters_new(allocator, options);
    if (!parameters) {
        return NULL;
    }

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_http_options *http_options = NULL;
    struct aws_http_credentials_provider_user_data *sso_user_data = NULL;

    aws_mem_acquire_many(
        allocator,
        3,
        &provider,
        sizeof(struct aws_credentials_provider),
        &http_options,
        sizeof(struct aws_credentials_provider_http_options),
        &sso_user_data,
        sizeof(struct aws_http_credentials_provider_user_data));

    AWS_ZERO_STRUCT(*http_options);
    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*sso_user_data);

    http_options->shutdown_options = options->shutdown_options;
    http_options->bootstrap = options->bootstrap;
    http_options->tls_ctx = options->tls_ctx;
    http_options->function_table = options->function_table;
    http_options->endpoint = aws_byte_cursor_from_string(parameters->endpoint);
    http_options->max_connections = 2;

    sso_user_data->parameters = parameters;
    sso_user_data->request_vtable = &s_sso_request_vtable;

    if (aws_http_credentials_provider_init_base(allocator, provider, http_options, sso_user_data)) {
        goto on_error;
    }

    return provider;
on_error:
    aws_credentials_provider_destroy(provider);
    return NULL;
}
