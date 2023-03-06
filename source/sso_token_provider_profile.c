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
 * sso-token profile provider implementation
 */
struct aws_token_provider_profile_impl {
    struct aws_string *sso_region;
    struct aws_string *sso_start_url;
    struct aws_string *token_file_path;
};

static int s_token_provider_profile_get_token_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {
    struct aws_token_provider_profile_impl *impl = provider->impl;

    struct aws_sso_token *sso_token = NULL;
    struct aws_credentials *credentials = NULL;

    sso_token = aws_sso_token_new_from_file(provider->allocator, impl->token_file_path);
    if (!sso_token) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-profile: unable to read file.");
        aws_raise_error(AWS_AUTH_SSO_TOKEN_INVALID);
        goto on_error;
    }

    /* check token expiration. */
    struct aws_date_time now;
    aws_date_time_init_now(&now);
    if (aws_date_time_diff(&sso_token->expiration, &now) < 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-profile: cached token is expired.");
        aws_raise_error(AWS_AUTH_SSO_TOKEN_INVALID);
        goto on_error;
    }

    credentials = aws_credentials_new_token(
        provider->allocator,
        aws_byte_cursor_from_string(sso_token->token),
        aws_date_time_as_epoch_secs(&sso_token->expiration));
    if (!credentials) {
        goto on_error;
    }

    callback(credentials, AWS_OP_SUCCESS, user_data);
    return AWS_OP_SUCCESS;

on_error:
    aws_sso_token_destroy(provider->allocator, sso_token);
    aws_credentials_release(credentials);
    // TODO: Should I check last error and set it to source failure?
    callback(credentials, aws_last_error(), user_data);
    return AWS_OP_ERR;
}

static void s_token_provider_profile_destroy(struct aws_credentials_provider *provider) {
    struct aws_token_provider_profile_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_string_destroy(impl->sso_region);
    aws_string_destroy(impl->sso_start_url);
    aws_string_destroy(impl->token_file_path);

    aws_credentials_provider_invoke_shutdown_callback(provider);
    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_token_provider_profile_vtable = {
    .get_credentials = s_token_provider_profile_get_token_async,
    .destroy = s_token_provider_profile_destroy,
};

AWS_STRING_FROM_LITERAL(s_profile_sso_region_name, "sso_region");
AWS_STRING_FROM_LITERAL(s_profile_sso_start_url_name, "sso_start_url");

struct token_provider_profile_parameters {
    struct aws_string *sso_region;
    struct aws_string *sso_start_url;
    struct aws_string *token_path;
};

static int s_token_provider_profile_parameters_init(
    struct aws_allocator *allocator,
    struct token_provider_profile_parameters *parameters,
    const struct aws_profile *profile) {
    const struct aws_profile_property *sso_region_property =
        aws_profile_get_property(profile, s_profile_sso_region_name);
    const struct aws_profile_property *sso_start_url_property =
        aws_profile_get_property(profile, s_profile_sso_start_url_name);

    if (!sso_region_property) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-profile: Profile token parser failed to find sso_region in profile");
        return aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
    }

    if (!sso_start_url_property) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-profile: Profile token parser failed to find sso_start_url in profile");
        return aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
    }

    parameters->sso_region = aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_region_property));
    parameters->sso_start_url =
        aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_start_url_property));
    parameters->token_path = construct_token_path(allocator, parameters->sso_start_url);
    if (!parameters->token_path) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-profile: Profile token parser failed to construct token path in profile");
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_token_provider_profile_parameters_destroy(
    struct aws_allocator *allocator,
    struct token_provider_profile_parameters *parameters) {

    aws_string_destroy(parameters->sso_region);
    aws_string_destroy(parameters->sso_start_url);
    aws_string_destroy(parameters->token_path);
    aws_mem_release(allocator, parameters);
}

static struct token_provider_profile_parameters *s_token_provider_profile_parameters_new(
    struct aws_allocator *allocator,
    struct aws_byte_cursor profile_name_override,
    struct aws_byte_cursor config_file_name_override) {
    struct aws_profile_collection *config_profiles = NULL;
    struct aws_string *config_file_path = NULL;
    struct aws_string *profile_name = NULL;
    bool success = false;

    struct token_provider_profile_parameters *parameters =
        aws_mem_calloc(allocator, 1, sizeof(struct token_provider_profile_parameters));
    config_file_path = aws_get_config_file_path(allocator, &config_file_name_override);

    if (!config_file_path) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-profile: Profile token parser failed resolve config file path");
        aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
        goto cleanup;
    }

    profile_name = aws_get_profile_name(allocator, &profile_name_override);
    if (!profile_name) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso-profile: Profile token parser failed to resolve profile name");
        aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
        goto cleanup;
    }
    config_profiles = aws_profile_collection_new_from_file(allocator, config_file_path, AWS_PST_CONFIG);

    if (!config_profiles) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-profile: Profile token parser could not load or parse"
            " a config file.");
        aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
        goto cleanup;
    }

    const struct aws_profile *profile = aws_profile_collection_get_profile(config_profiles, profile_name);

    if (!profile) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-profile: Profile token provider could not load"
            " a profile at %s.",
            aws_string_c_str(profile_name));
        aws_raise_error(AWS_AUTH_SSO_TOKEN_PROVIDER_SOURCE_FAILURE);
        goto cleanup;
    }

    if (s_token_provider_profile_parameters_init(allocator, parameters, profile)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "sso-profile: Profile token provider could not load a valid sso profile at %s",
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
        s_token_provider_profile_parameters_destroy(allocator, parameters);
        parameters = NULL;
    }
    return parameters;
}

struct aws_credentials_provider *aws_sso_token_provider_new_profile(
    struct aws_allocator *allocator,
    const struct aws_sso_token_provider_profile_options *options) {

    struct token_provider_profile_parameters *parameters = s_token_provider_profile_parameters_new(
        allocator, options->profile_name_override, options->config_file_name_override);
    if (!parameters) {
        return NULL;
    }
    struct aws_credentials_provider *provider = NULL;
    struct aws_token_provider_profile_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_token_provider_profile_impl));
    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);
    aws_credentials_provider_init_base(provider, allocator, &s_aws_token_provider_profile_vtable, impl);
    impl->sso_region = aws_string_new_from_string(allocator, parameters->sso_region);
    impl->sso_start_url = aws_string_new_from_string(allocator, parameters->sso_start_url);
    impl->token_file_path = aws_string_new_from_string(allocator, parameters->sso_start_url);
    provider->shutdown_options = options->shutdown_options;

    s_token_provider_profile_parameters_destroy(allocator, parameters);
    return provider;

    // on_error:
    //     aws_credentials_provider_destroy(provider);
    //     s_token_provider_profile_parameters_destroy(allocator, parameters);
    //     return NULL;
}
