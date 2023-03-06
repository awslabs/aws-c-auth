/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/date_time.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/common/xml_parser.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/file_utils.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/uri.h>
#include <inttypes.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#    pragma warning(disable : 4232)
#endif /* _MSC_VER */

static int s_construct_endpoint(
    struct aws_allocator *allocator,
    struct aws_byte_buf *endpoint,
    const struct aws_string *region) {
    // TODO: confirm logic
    if (!allocator || !endpoint || !region) {
        return AWS_ERROR_INVALID_ARGUMENT;
    }
    aws_byte_buf_clean_up(endpoint);
    struct aws_byte_cursor sso_prefix = aws_byte_cursor_from_c_str("portal.sso.");
    struct aws_byte_cursor region_cursor = aws_byte_cursor_from_string(region);
    struct aws_byte_cursor amazonaws_cursor = aws_byte_cursor_from_c_str(".amazonaws.com");
    struct aws_byte_cursor cn_cursor = aws_byte_cursor_from_c_str(".cn");

    if (aws_byte_buf_init_copy_from_cursor(endpoint, allocator, sso_prefix)) {
        goto on_error;
    }

    if (aws_byte_buf_append(endpoint, &region_cursor) || aws_byte_buf_append(endpoint, &amazonaws_cursor)) {
        goto on_error;
    }

    if (aws_string_eq_c_str_ignore_case(region, "cn-north-1") ||
        aws_string_eq_c_str_ignore_case(region, "cn-northwest-1")) {
        if (aws_byte_buf_append_dynamic(endpoint, &cn_cursor)) {
            goto on_error;
        }
    }
    return AWS_OP_SUCCESS;

on_error:
    aws_byte_buf_clean_up(endpoint);
    return AWS_OP_ERR;
}

AWS_STATIC_STRING_FROM_LITERAL(s_sso_account_id, "sso_account_id");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_region, "sso_region");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_role_name, "sso_role_name");
AWS_STATIC_STRING_FROM_LITERAL(s_sso_session, "sso_session");

struct sso_parameters {
    struct aws_allocator *allocator;
    struct aws_byte_buf endpoint;
    struct aws_string *sso_account_id;
    /* region is actually used to construct endpoint */
    struct aws_string *sso_role_name;
    struct aws_credentials_provider *token_provider;
};

static void s_parameters_destroy(struct sso_parameters *parameters) {
    if (!parameters) {
        return;
    }
    aws_byte_buf_clean_up(&parameters->endpoint);
    aws_string_destroy(parameters->sso_account_id);
    aws_string_destroy(parameters->sso_role_name);
    aws_credentials_provider_release(parameters->token_provider);
    aws_mem_release(parameters->allocator, parameters);
}

static struct sso_parameters *s_parameters_new(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_sso_options *options) {

    struct sso_parameters *parameters = aws_mem_calloc(allocator, 1, sizeof(struct sso_parameters));
    parameters->allocator = allocator;

    struct aws_profile_collection *config_profile = NULL;
    struct aws_string *profile_name = NULL;
    bool success = false;

    profile_name = aws_get_profile_name(allocator, &options->profile_name_override);
    if (!profile_name) {
        AWS_LOGF_DEBUG(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: failed to resolve profile name");
        goto on_finish;
    }

    config_profile = aws_load_config(allocator, options->config_file_name_override);
    if (!config_profile) {
        goto on_finish;
    }

    const struct aws_profile *profile = aws_profile_collection_get_profile(config_profile, profile_name);
    if (!profile) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: failed to load \"%s\" profile", aws_string_c_str(profile_name));
        goto on_finish;
    }

    const struct aws_profile_property *sso_account_id = aws_profile_get_property(profile, s_sso_account_id);
    const struct aws_profile_property *sso_role_name = aws_profile_get_property(profile, s_sso_role_name);
    const struct aws_profile_property *sso_region = aws_profile_get_property(profile, s_sso_region);

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
    if (!sso_region) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: sso_region is missing");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE);
        goto on_finish;
    }

    const struct aws_profile_property *sso_session_property = aws_profile_get_property(profile, s_sso_session);
    if (sso_session_property) {
        struct aws_sso_token_provider_sso_session_options token_provider_options;
        AWS_ZERO_STRUCT(options);
        token_provider_options.config_file_name_override = options->config_file_name_override;
        token_provider_options.profile_name_override = options->profile_name_override;

        parameters->token_provider = aws_sso_token_provider_new_sso_session(allocator, &token_provider_options);
        if (!parameters->token_provider) {
            AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: unable to create a sso token provider");
            aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE);
            goto on_finish;
        }
    } else {
        struct aws_sso_token_provider_profile_options token_provider_options;
        AWS_ZERO_STRUCT(options);
        token_provider_options.config_file_name_override = options->config_file_name_override;
        token_provider_options.profile_name_override = options->profile_name_override;

        parameters->token_provider = aws_sso_token_provider_new_profile(allocator, &token_provider_options);
        if (!parameters->token_provider) {
            AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "sso: unable to create a profile token provider");
            aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE);
            goto on_finish;
        }
    }

    parameters->sso_account_id = aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_account_id));
    parameters->sso_role_name = aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_role_name));
    /* determine endpoint */
    if (s_construct_endpoint(allocator, &parameters->endpoint, parameters->sso_region)) {
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
    aws_profile_collection_release(config_profile);

    return parameters;
}

struct aws_credentials_provider *aws_credentials_provider_new_sso(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_sso_options *options) {

    struct sso_parameters *parameters = s_parameters_new(allocator, options);
    if (!parameters) {
        return NULL;
    }

    //     struct aws_tls_connection_options tls_connection_options;
    //     AWS_ZERO_STRUCT(tls_connection_options);

    //     struct aws_credentials_provider *provider = NULL;
    //     struct aws_credentials_provider_sts_web_identity_impl *impl = NULL;

    //     aws_mem_acquire_many(
    //         allocator,
    //         2,
    //         &provider,
    //         sizeof(struct aws_credentials_provider),
    //         &impl,
    //         sizeof(struct aws_credentials_provider_sts_web_identity_impl));

    //     if (!provider) {
    //         goto on_error;
    //     }

    //     AWS_ZERO_STRUCT(*provider);
    //     AWS_ZERO_STRUCT(*impl);

    //     aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_sts_web_identity_vtable,
    //     impl);

    //     if (!options->tls_ctx) {
    //         AWS_LOGF_ERROR(
    //             AWS_LS_AUTH_CREDENTIALS_PROVIDER,
    //             "a TLS context must be provided to the STS web identity credentials provider");
    //         aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    //         return NULL;
    //     }

    //     aws_tls_connection_options_init_from_ctx(&tls_connection_options, options->tls_ctx);
    //     struct aws_byte_cursor host = aws_byte_cursor_from_buf(&parameters->endpoint);
    //     if (aws_tls_connection_options_set_server_name(&tls_connection_options, allocator, &host)) {
    //         AWS_LOGF_ERROR(
    //             AWS_LS_AUTH_CREDENTIALS_PROVIDER,
    //             "(id=%p): failed to create a tls connection options with error %s",
    //             (void *)provider,
    //             aws_error_str(aws_last_error()));
    //         goto on_error;
    //     }

    //     struct aws_socket_options socket_options;
    //     AWS_ZERO_STRUCT(socket_options);
    //     socket_options.type = AWS_SOCKET_STREAM;
    //     socket_options.domain = AWS_SOCKET_IPV4;
    //     socket_options.connect_timeout_ms = (uint32_t)aws_timestamp_convert(
    //         STS_WEB_IDENTITY_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);

    //     struct aws_http_connection_manager_options manager_options;
    //     AWS_ZERO_STRUCT(manager_options);
    //     manager_options.bootstrap = options->bootstrap;
    //     manager_options.initial_window_size = STS_WEB_IDENTITY_RESPONSE_SIZE_LIMIT;
    //     manager_options.socket_options = &socket_options;
    //     manager_options.host = host;
    //     manager_options.port = 443;
    //     manager_options.max_connections = 2;
    //     manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    //     manager_options.shutdown_complete_user_data = provider;
    //     manager_options.tls_connection_options = &tls_connection_options;

    //     impl->function_table = options->function_table;
    //     if (impl->function_table == NULL) {
    //         impl->function_table = g_aws_credentials_provider_http_function_table;
    //     }

    //     impl->connection_manager = impl->function_table->aws_http_connection_manager_new(allocator,
    //     &manager_options); if (impl->connection_manager == NULL) {
    //         goto on_error;
    //     }

    //     impl->role_arn = aws_string_new_from_array(allocator, parameters->role_arn.buffer, parameters->role_arn.len);
    //     if (impl->role_arn == NULL) {
    //         goto on_error;
    //     }

    //     impl->role_session_name =
    //         aws_string_new_from_array(allocator, parameters->role_session_name.buffer,
    //         parameters->role_session_name.len);
    //     if (impl->role_session_name == NULL) {
    //         goto on_error;
    //     }

    //     impl->token_file_path =
    //         aws_string_new_from_array(allocator, parameters->token_file_path.buffer,
    //         parameters->token_file_path.len);
    //     if (impl->token_file_path == NULL) {
    //         goto on_error;
    //     }

    //     provider->shutdown_options = options->shutdown_options;
    //     s_parameters_destroy(parameters);
    //     aws_tls_connection_options_clean_up(&tls_connection_options);
    //     return provider;

    // on_error:

    //     aws_credentials_provider_destroy(provider);
    //     s_parameters_destroy(parameters);
    //     aws_tls_connection_options_clean_up(&tls_connection_options);
    return NULL;
}
