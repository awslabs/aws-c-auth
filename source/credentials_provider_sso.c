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
            profile)) {
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

static int s_sso_make_request_fn(struct aws_http_query_context *query_context) {
    struct sso_parameters *parameters = query_context->parameters;
    struct aws_byte_cursor account_id_cursor = aws_byte_cursor_from_string(query_context->account_id);
    struct aws_byte_cursor role_name_cursor = aws_byte_cursor_from_string(parameters->sso_role_name);
    struct aws_byte_cursor path_cursor = aws_byte_cursor_from_c_str("/federation/credentials?account_id=");
    struct aws_byte_cursor role_name_param_cursor = aws_byte_cursor_from_c_str("&role_name=");
    if (aws_byte_buf_init_copy_from_cursor(
            &query_context->path_and_query, query_context->provider->allocator, path_cursor) ||
        aws_byte_buf_append_encoding_uri_param(&query_context->path_and_query, &account_id_cursor) ||
        aws_byte_buf_append_dynamic(&query_context->path_and_query, &role_name_param_cursor) ||
        aws_byte_buf_append_encoding_uri_param(&query_context->path_and_query, &role_name_cursor)) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static struct aws_byte_cursor s_sso_credentials_get_token_fn(struct aws_credentials *credentials, void *user_data) {
    (void)user_data;
    return aws_credentials_get_token(credentials);
}

/* Request headers. */
AWS_STATIC_STRING_FROM_LITERAL(s_sso_token_header, "x-amz-sso_bearer_token");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_user_agent_header, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_user_agent_header_value, "aws-sdk-crt/sso-credentials-provider");

int s_sso_create_headers_fn(struct aws_http_query_context *query_context) {
    struct aws_http_header auth_header = {
        .name = aws_byte_cursor_from_string(s_sso_token_header),
        .value = aws_byte_cursor_from_string(query_context->token),
    };
    struct aws_http_header user_agent_header = {
        .name = aws_byte_cursor_from_string(s_sso_user_agent_header),
        .value = aws_byte_cursor_from_string(s_sso_user_agent_header_value),
    };

    if (aws_http_message_add_header(query_context->request, auth_header) ||
        aws_http_message_add_header(query_context->request, user_agent_header)) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

struct aws_credentials_provider *aws_credentials_provider_new_sso(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_sso_options *options) {

    struct sso_parameters *parameters = s_parameters_new(allocator, options);
    if (!parameters) {
        return NULL;
    }

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_http_options *http_options = NULL;
    struct aws_http_credentials_provider_request_vtable *sso_request_vtable = NULL;

    aws_mem_acquire_many(
        allocator,
        3,
        &provider,
        sizeof(struct aws_credentials_provider),
        &http_options,
        sizeof(struct aws_credentials_provider_http_options),
        &sso_request_vtable,
        sizeof(struct aws_http_credentials_provider_request_vtable));

    AWS_ZERO_STRUCT(*http_options);
    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*sso_request_vtable);

    http_options->shutdown_options = options->shutdown_options;
    http_options->bootstrap = options->bootstrap;
    http_options->tls_ctx = options->tls_ctx;
    http_options->function_table = options->function_table;
    http_options->endpoint = parameters->endpoint;
    http_options->token_provider = parameters->token_provider;
    http_options->account_id = parameters->sso_account_id;

    sso_request_vtable->credentials_get_token_fn = s_sso_credentials_get_token_fn;
    sso_request_vtable->create_headers_fn = s_sso_create_headers_fn;
    sso_request_vtable->make_request_fn = s_sso_make_request_fn;
    sso_request_vtable->clean_up_parameters_fn = s_parameters_destroy;
    sso_request_vtable->parameters = parameters;
    sso_request_vtable->error = AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE;

    if (aws_http_credentials_provider_init_base(allocator, provider, http_options, sso_request_vtable)) {
        goto on_error;
    }

    return provider;
on_error:
    aws_credentials_provider_destroy(provider);
    return NULL;
}
