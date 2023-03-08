/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/auth/private/sso_token_utils.h>
#include <aws/common/process.h>
#include <aws/common/string.h>
#include <aws/io/tls_channel_handler.h>
#ifdef _MSC_VER
/* allow non-constant declared initializers. */
#    pragma warning(disable : 4204)
#endif

/*
 * sso-session token provider implementation
 */
struct aws_token_provider_sso_session_impl {
    struct aws_string *sso_region;
    struct aws_string *sso_start_url;
    struct aws_string *token_file_path;
};

static int s_token_provider_sso_session_get_token_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_token_provider_sso_session_impl *impl = provider->impl;
    struct aws_sso_token *sso_token = NULL;
    struct aws_credentials *credentials = NULL;
    bool success = false;

    sso_token = aws_sso_token_new_from_file(provider->allocator, impl->token_file_path);
    if (!sso_token) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p) unable to read file.", (void *)provider);
        aws_raise_error(AWS_AUTH_SSO_TOKEN_INVALID);
        goto done;
    }

    /* TODO: Refresh token if it is within refresh window and refreshable */
    /* check token expiration. */
    struct aws_date_time now;
    aws_date_time_init_now(&now);
    if (aws_date_time_diff(&sso_token->expiration, &now) < 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "(id=%p) cached token is expired.", (void *)provider);
        aws_raise_error(AWS_AUTH_SSO_TOKEN_EXPIRED);
        goto done;
    }

    credentials = aws_credentials_new_token(
        provider->allocator,
        aws_byte_cursor_from_string(sso_token->token),
        aws_date_time_as_epoch_secs(&sso_token->expiration));
    if (!credentials) {
        goto done;
    }
    callback(credentials, AWS_OP_SUCCESS, user_data);
    success = true;

done:
    aws_sso_token_destroy(provider->allocator, sso_token);
    aws_credentials_release(credentials);
    if (!success) {
        callback(NULL, aws_last_error(), user_data);
    }
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static void s_token_provider_sso_session_destroy(struct aws_credentials_provider *provider) {
    struct aws_token_provider_sso_session_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_string_destroy(impl->sso_region);
    aws_string_destroy(impl->sso_start_url);
    aws_string_destroy(impl->token_file_path);

    aws_credentials_provider_invoke_shutdown_callback(provider);
    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_token_provider_sso_session_vtable = {
    .get_credentials = s_token_provider_sso_session_get_token_async,
    .destroy = s_token_provider_sso_session_destroy,
};

AWS_STRING_FROM_LITERAL(s_sso_session_name, "sso_session");
AWS_STRING_FROM_LITERAL(s_sso_region_name, "sso_region");
AWS_STRING_FROM_LITERAL(s_sso_start_url_name, "sso_start_url");

struct token_provider_sso_session_parameters {
    struct aws_string *sso_region;
    struct aws_string *sso_start_url;
    struct aws_string *token_path;
};

static int s_token_provider_sso_session_parameters_sso_session_init(
    struct aws_allocator *allocator,
    struct token_provider_sso_session_parameters *parameters,
    const struct aws_profile_collection *profile_collection,
    const struct aws_profile *profile,
    const struct aws_string *sso_session_name) {

    const struct aws_profile *session_profile =
        aws_profile_collection_get_section(profile_collection, sso_session_name, AWS_PROFILE_SECTION_TYPE_SSO_SESSION);
    if (!session_profile) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-session: token parser failed to find an sso-session");
        return aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
    }

    const struct aws_profile_property *sso_region_property =
        aws_profile_get_property(session_profile, s_sso_region_name);
    const struct aws_profile_property *sso_start_url_property =
        aws_profile_get_property(session_profile, s_sso_start_url_name);

    if (!sso_region_property) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-session: token parser failed to find sso_region in sso-session");
        return aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
    }

    if (!sso_start_url_property) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-session: token parser failed to find sso_start_url in sso-session");
        return aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
    }

    const struct aws_string *sso_region = aws_profile_property_get_value(sso_region_property);
    const struct aws_string *sso_start_url = aws_profile_property_get_value(sso_start_url_property);

    /* Verify sso_region & start_url are the same in profile section if they exist */
    const struct aws_profile_property *profile_sso_region_property =
        aws_profile_get_property(profile, s_sso_region_name);
    const struct aws_profile_property *profile_sso_start_url_property =
        aws_profile_get_property(profile, s_sso_start_url_name);

    if (profile_sso_region_property &&
        !aws_string_eq(sso_region, aws_profile_property_get_value(profile_sso_region_property))) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-session: profile & sso-session have different value for sso_region");
        return aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
    }

    if (profile_sso_start_url_property &&
        !aws_string_eq(sso_start_url, aws_profile_property_get_value(profile_sso_start_url_property))) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-session: profile & sso-session have different value for sso_start_url");
        return aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
    }

    parameters->sso_region = aws_string_new_from_string(allocator, sso_region);
    parameters->sso_start_url = aws_string_new_from_string(allocator, sso_start_url);
    parameters->token_path = aws_construct_token_path(allocator, sso_session_name);
    if (!parameters->token_path) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-session: token parser failed to construct token path in sso-session");
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static void s_token_provider_sso_session_parameters_destroy(
    struct aws_allocator *allocator,
    struct token_provider_sso_session_parameters *parameters) {

    aws_string_destroy(parameters->sso_region);
    aws_string_destroy(parameters->sso_start_url);
    aws_string_destroy(parameters->token_path);
    aws_mem_release(allocator, parameters);
}

static struct token_provider_sso_session_parameters *s_token_provider_sso_session_parameters_new(
    struct aws_allocator *allocator,
    struct aws_byte_cursor profile_name_override,
    struct aws_byte_cursor config_file_name_override) {
    struct aws_profile_collection *config_profiles = NULL;
    struct aws_string *config_file_path = NULL;
    struct aws_string *profile_name = NULL;
    bool success = false;

    struct token_provider_sso_session_parameters *parameters =
        aws_mem_calloc(allocator, 1, sizeof(struct token_provider_sso_session_parameters));
    config_file_path = aws_get_config_file_path(allocator, &config_file_name_override);

    if (!config_file_path) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-session: token provider failed resolve config file path");
        goto cleanup;
    }

    profile_name = aws_get_profile_name(allocator, &profile_name_override);
    if (!profile_name) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-session: token provider failed to resolve profile name");
        goto cleanup;
    }
    config_profiles = aws_profile_collection_new_from_file(allocator, config_file_path, AWS_PST_CONFIG);

    if (!config_profiles) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-session: token provider could not load or parse"
            " a config file.");
        goto cleanup;
    }

    const struct aws_profile *profile = aws_profile_collection_get_profile(config_profiles, profile_name);

    if (!profile) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-session: token provider could not load"
            " a profile at %s.",
            aws_string_c_str(profile_name));
        goto cleanup;
    }

    const struct aws_profile_property *sso_session_property = aws_profile_get_property(profile, s_sso_session_name);
    if (sso_session_property) {
        if (s_token_provider_sso_session_parameters_sso_session_init(
                allocator,
                parameters,
                config_profiles,
                profile,
                aws_profile_property_get_value(sso_session_property))) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "sso-session: token provider could not load a valid sso profile and session at %s",
                aws_string_c_str(profile_name));
            goto cleanup;
        }
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-session: token provider could not find an sso-session at profile %s",
            aws_string_c_str(profile_name));
        aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
        goto cleanup;
    }

    success = true;

cleanup:
    aws_string_destroy(config_file_path);
    aws_string_destroy(profile_name);
    aws_profile_collection_release(config_profiles);
    if (!success) {
        s_token_provider_sso_session_parameters_destroy(allocator, parameters);
        parameters = NULL;
    }
    return parameters;
}

struct aws_credentials_provider *aws_token_provider_new_sso_session(
    struct aws_allocator *allocator,
    const struct aws_token_provider_sso_session_options *options) {

    struct token_provider_sso_session_parameters *parameters = s_token_provider_sso_session_parameters_new(
        allocator, options->profile_name_override, options->config_file_name_override);
    if (!parameters) {
        return NULL;
    }
    struct aws_credentials_provider *provider = NULL;
    struct aws_token_provider_sso_session_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_token_provider_sso_session_impl));
    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);
    aws_credentials_provider_init_base(provider, allocator, &s_aws_token_provider_sso_session_vtable, impl);
    impl->sso_region = aws_string_new_from_string(allocator, parameters->sso_region);
    impl->sso_start_url = aws_string_new_from_string(allocator, parameters->sso_start_url);
    impl->token_file_path = aws_string_new_from_string(allocator, parameters->sso_start_url);
    provider->shutdown_options = options->shutdown_options;

    s_token_provider_sso_session_parameters_destroy(allocator, parameters);
    return provider;
}
