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

#include <aws/common/clock.h>
#include <aws/common/environment.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>
#include <aws/io/uri.h>

#define DEFAULT_CREDENTIAL_PROVIDER_REFRESH_MS (15 * 60 * 1000)

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
/*
 * For designated initialization: .providers = providers,
 * of aws_credentials_provider_chain_options in function
 * aws_credentials_provider_new_chain_default
 */
#    pragma warning(disable : 4221)
#endif /* _MSC_VER */

/*
 * Credentials API implementations
 */

struct aws_credentials *aws_credentials_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token) {

    struct aws_byte_cursor access_key_id_cursor;
    AWS_ZERO_STRUCT(access_key_id_cursor);
    if (access_key_id) {
        access_key_id_cursor = aws_byte_cursor_from_string(access_key_id);
    }

    struct aws_byte_cursor secret_access_key_cursor;
    AWS_ZERO_STRUCT(secret_access_key_cursor);
    if (secret_access_key) {
        secret_access_key_cursor = aws_byte_cursor_from_string(secret_access_key);
    }

    struct aws_byte_cursor session_token_cursor;
    AWS_ZERO_STRUCT(session_token_cursor);
    if (session_token) {
        session_token_cursor = aws_byte_cursor_from_string(session_token);
    }

    return aws_credentials_new_from_cursors(
        allocator,
        access_key_id != NULL ? &access_key_id_cursor : NULL,
        secret_access_key != NULL ? &secret_access_key_cursor : NULL,
        session_token != NULL ? &session_token_cursor : NULL);
}

struct aws_credentials *aws_credentials_new_copy(struct aws_allocator *allocator, struct aws_credentials *credentials) {
    if (credentials != NULL) {
        struct aws_credentials *copy = aws_credentials_new(
            allocator, credentials->access_key_id, credentials->secret_access_key, credentials->session_token);

        copy->expiration_timepoint_seconds = credentials->expiration_timepoint_seconds;

        return copy;
    }

    return NULL;
}

struct aws_credentials *aws_credentials_new_from_cursors(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *access_key_id_cursor,
    const struct aws_byte_cursor *secret_access_key_cursor,
    const struct aws_byte_cursor *session_token_cursor) {

    struct aws_credentials *credentials = aws_mem_acquire(allocator, sizeof(struct aws_credentials));
    if (credentials == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*credentials);

    credentials->allocator = allocator;

    if (access_key_id_cursor != NULL) {
        credentials->access_key_id =
            aws_string_new_from_array(allocator, access_key_id_cursor->ptr, access_key_id_cursor->len);
        if (credentials->access_key_id == NULL) {
            goto error;
        }
    }

    if (secret_access_key_cursor != NULL) {
        credentials->secret_access_key =
            aws_string_new_from_array(allocator, secret_access_key_cursor->ptr, secret_access_key_cursor->len);
        if (credentials->secret_access_key == NULL) {
            goto error;
        }
    }

    if (session_token_cursor != NULL) {
        credentials->session_token =
            aws_string_new_from_array(allocator, session_token_cursor->ptr, session_token_cursor->len);
        if (credentials->session_token == NULL) {
            goto error;
        }
    }

    credentials->expiration_timepoint_seconds = UINT64_MAX;

    return credentials;

error:

    aws_credentials_destroy(credentials);

    return NULL;
}

void aws_credentials_destroy(struct aws_credentials *credentials) {
    if (credentials == NULL) {
        return;
    }

    if (credentials->access_key_id != NULL) {
        aws_string_destroy(credentials->access_key_id);
    }

    if (credentials->secret_access_key != NULL) {
        aws_string_destroy_secure(credentials->secret_access_key);
    }

    if (credentials->session_token != NULL) {
        aws_string_destroy(credentials->session_token);
    }

    aws_mem_release(credentials->allocator, credentials);
}

/*
 * global credentials provider APIs
 */

void aws_credentials_provider_destroy(struct aws_credentials_provider *provider) {
    if (provider != NULL) {
        provider->vtable->destroy(provider);
    }
}

void aws_credentials_provider_release(struct aws_credentials_provider *provider) {
    if (provider == NULL) {
        return;
    }

    size_t old_value = aws_atomic_fetch_sub(&provider->ref_count, 1);
    if (old_value == 1) {
        aws_credentials_provider_destroy(provider);
    }
}

void aws_credentials_provider_acquire(struct aws_credentials_provider *provider) {
    aws_atomic_fetch_add(&provider->ref_count, 1);
}

int aws_credentials_provider_get_credentials(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    AWS_ASSERT(provider->vtable->get_credentials);

    return provider->vtable->get_credentials(provider, callback, user_data);
}

AWS_STATIC_STRING_FROM_LITERAL(s_ecs_creds_env_relative_uri, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_creds_env_full_uri, "AWS_CONTAINER_CREDENTIALS_FULL_URI");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_creds_env_token, "AWS_CONTAINER_AUTHORIZATION_TOKEN");
AWS_STATIC_STRING_FROM_LITERAL(s_ecs_host, "169.254.170.2");
AWS_STATIC_STRING_FROM_LITERAL(s_ec2_creds_env_disable, "AWS_EC2_METADATA_DISABLED");

/**
 * ECS and IMDS credentials providers are mutually exclusive,
 * ECS has higher priority
 */
static struct aws_credentials_provider *s_aws_credentials_provider_new_ecs_or_imds(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_chain_default_options *options) {

    struct aws_credentials_provider *ecs_or_imds_provider = NULL;
    struct aws_string *ecs_relative_uri = NULL;
    struct aws_string *ecs_full_uri = NULL;
    struct aws_string *ec2_imds_disable = NULL;

    if (aws_get_environment_value(allocator, s_ecs_creds_env_relative_uri, &ecs_relative_uri) != AWS_OP_SUCCESS ||
        aws_get_environment_value(allocator, s_ecs_creds_env_full_uri, &ecs_full_uri) != AWS_OP_SUCCESS ||
        aws_get_environment_value(allocator, s_ec2_creds_env_disable, &ec2_imds_disable) != AWS_OP_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed reading envrionment variables during default credentials provider chain initialization.");
        goto clean_up;
    }
    if (ecs_relative_uri && ecs_relative_uri->len) {
        struct aws_credentials_provider_ecs_options ecs_options = {
            .bootstrap = options->bootstrap,
            .host = aws_byte_cursor_from_string(s_ecs_host),
            .path_and_query = aws_byte_cursor_from_string(ecs_relative_uri),
            .use_tls = false,
        };
        ecs_or_imds_provider = aws_credentials_provider_new_ecs(allocator, &ecs_options);

    } else if (ecs_full_uri && ecs_full_uri->len) {
        struct aws_uri uri;
        struct aws_byte_cursor uri_cstr = aws_byte_cursor_from_string(ecs_full_uri);
        if (AWS_OP_ERR == aws_uri_init_parse(&uri, allocator, &uri_cstr)) {
            goto clean_up;
        }

        struct aws_string *ecs_token = NULL;
        if (aws_get_environment_value(allocator, s_ecs_creds_env_token, &ecs_token) != AWS_OP_SUCCESS) {
            AWS_LOGF_WARN(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Failed reading ECS Token environment variable during ECS creds provider initialization.");
            goto clean_up;
        }

        struct aws_byte_cursor nullify_cursor;
        AWS_ZERO_STRUCT(nullify_cursor);

        struct aws_credentials_provider_ecs_options ecs_options = {
            .bootstrap = options->bootstrap,
            .host = uri.host_name,
            .path_and_query = uri.path_and_query,
            .use_tls = aws_byte_cursor_eq_c_str_ignore_case(&(uri.scheme), "HTTPS"),
            .auth_token = (ecs_token && ecs_token->len) ? aws_byte_cursor_from_string(ecs_token) : nullify_cursor,
        };

        ecs_or_imds_provider = aws_credentials_provider_new_ecs(allocator, &ecs_options);
        aws_string_destroy(ecs_token);

    } else if (ec2_imds_disable == NULL || aws_string_eq_c_str_ignore_case(ec2_imds_disable, "false")) {
        struct aws_credentials_provider_imds_options imds_options = {
            .bootstrap = options->bootstrap,
        };
        ecs_or_imds_provider = aws_credentials_provider_new_imds(allocator, &imds_options);
    }

clean_up:

    aws_string_destroy(ecs_relative_uri);
    aws_string_destroy(ecs_full_uri);
    aws_string_destroy(ec2_imds_disable);
    return ecs_or_imds_provider;
}

/*
 * Default provider chain implementation
 */
struct aws_credentials_provider *aws_credentials_provider_new_chain_default(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_chain_default_options *options) {

    struct aws_credentials_provider *environment_provider = NULL;
    struct aws_credentials_provider *profile_provider = NULL;
    struct aws_credentials_provider *ecs_or_imds_provider = NULL;
    struct aws_credentials_provider *chain_provider = NULL;
    struct aws_credentials_provider *cached_provider = NULL;

    struct aws_credentials_provider *providers[3];
    AWS_ZERO_ARRAY(providers);
    size_t index = 0;

    bool success = false;

    struct aws_credentials_provider_environment_options environment_options;
    AWS_ZERO_STRUCT(environment_options);
    environment_provider = aws_credentials_provider_new_environment(allocator, &environment_options);
    if (environment_provider == NULL) {
        goto on_ret;
    }

    providers[index++] = environment_provider;

    struct aws_credentials_provider_profile_options profile_options;
    AWS_ZERO_STRUCT(profile_options);
    profile_options.bootstrap = options->bootstrap;
    profile_provider = aws_credentials_provider_new_profile(allocator, &profile_options);
    if (profile_provider != NULL) {
        providers[index++] = profile_provider;
    }

    ecs_or_imds_provider = s_aws_credentials_provider_new_ecs_or_imds(allocator, options);
    if (ecs_or_imds_provider != NULL) {
        providers[index++] = ecs_or_imds_provider;
    }

    AWS_FATAL_ASSERT(index <= AWS_ARRAY_SIZE(providers));

    struct aws_credentials_provider_chain_options chain_options = {
        .provider_count = index,
        .providers = providers,
    };

    chain_provider = aws_credentials_provider_new_chain(allocator, &chain_options);
    if (chain_provider == NULL) {
        goto on_ret;
    }

    /*
     * Transfer ownership
     */
    aws_credentials_provider_release(environment_provider);
    aws_credentials_provider_release(profile_provider);
    aws_credentials_provider_release(ecs_or_imds_provider);

    struct aws_credentials_provider_cached_options cached_options = {
        .source = chain_provider,
        .refresh_time_in_milliseconds = DEFAULT_CREDENTIAL_PROVIDER_REFRESH_MS,
        .shutdown_options = options->shutdown_options,
    };

    cached_provider = aws_credentials_provider_new_cached(allocator, &cached_options);
    if (cached_provider == NULL) {
        goto on_ret;
    }

    /*
     * Transfer ownership
     */
    aws_credentials_provider_release(chain_provider);
    success = true;

on_ret:

    if (success) {
        return cached_provider;
    }
    /*
     * Have to be a bit more careful than normal with this clean up pattern since the chain/cache will
     * recursively destroy the other providers via ref release.
     *
     * Technically, the cached_provider can never be non-null here, but let's handle it anyways
     * in case someone does something weird in the future.
     */
    if (cached_provider) {
        aws_credentials_provider_release(cached_provider);
    } else if (chain_provider) {
        aws_credentials_provider_release(chain_provider);
    } else {
        aws_credentials_provider_release(ecs_or_imds_provider);
        aws_credentials_provider_release(profile_provider);
        aws_credentials_provider_release(environment_provider);
    }

    return NULL;
}
