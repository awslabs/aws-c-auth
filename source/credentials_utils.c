/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/external/cJSON.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/date_time.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>

void aws_credentials_query_init(
    struct aws_credentials_query *query,
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn *callback,
    void *user_data) {
    AWS_ZERO_STRUCT(*query);

    query->provider = provider;
    query->user_data = user_data;
    query->callback = callback;

    aws_credentials_provider_acquire(provider);
}

void aws_credentials_query_clean_up(struct aws_credentials_query *query) {
    if (query != NULL) {
        aws_credentials_provider_release(query->provider);
    }
}

void aws_credentials_provider_init_base(
    struct aws_credentials_provider *provider,
    struct aws_allocator *allocator,
    struct aws_credentials_provider_vtable *vtable,
    void *impl) {

    provider->allocator = allocator;
    provider->vtable = vtable;
    provider->impl = impl;

    aws_atomic_init_int(&provider->ref_count, 1);
}

void aws_credentials_provider_invoke_shutdown_callback(struct aws_credentials_provider *provider) {
    if (provider && provider->shutdown_options.shutdown_callback) {
        provider->shutdown_options.shutdown_callback(provider->shutdown_options.shutdown_user_data);
    }
}

struct aws_credentials *aws_parse_credentials_from_cjson_object(
    struct aws_allocator *allocator,
    struct cJSON *document_root,
    const struct aws_parse_credentials_from_json_doc_options *options) {

    AWS_FATAL_ASSERT(allocator);
    AWS_FATAL_ASSERT(document_root);
    AWS_FATAL_ASSERT(options);
    AWS_FATAL_ASSERT(options->access_key_id_name);
    AWS_FATAL_ASSERT(options->secrete_access_key_name);

    if (options->token_required) {
        AWS_FATAL_ASSERT(options->token_name);
    }

    if (options->expiration_required) {
        AWS_FATAL_ASSERT(options->expiration_name);
    }

    struct aws_credentials *credentials = NULL;
    cJSON *access_key_id = NULL;
    cJSON *secrete_access_key = NULL;
    cJSON *token = NULL;
    cJSON *creds_expiration = NULL;

    bool parse_error = true;

    /*
     * Pull out the credentials components
     */
    access_key_id = cJSON_GetObjectItem(document_root, options->access_key_id_name);
    if (!cJSON_IsString(access_key_id) || (access_key_id->valuestring == NULL)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse AccessKeyId from Json document.");
        goto done;
    }

    secrete_access_key = cJSON_GetObjectItem(document_root, options->secrete_access_key_name);
    if (!cJSON_IsString(secrete_access_key) || (secrete_access_key->valuestring == NULL)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse SecretAccessKey from Json document.");
        goto done;
    }

    if (options->token_name) {
        token = cJSON_GetObjectItem(document_root, options->token_name);
        if (!cJSON_IsString(token) || (token->valuestring == NULL)) {
            if (options->token_required) {
                AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Token from Json document.");
                goto done;
            }
        }
    }

    if (options->expiration_name) {
        creds_expiration = cJSON_GetObjectItem(document_root, options->expiration_name);
        if (!cJSON_IsString(creds_expiration) || (creds_expiration->valuestring == NULL)) {
            if (options->expiration_required) {
                AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Expiration from Json document.");
                goto done;
            }
        }
    }

    uint64_t expiration_timepoint_in_seconds = UINT64_MAX;
    if (creds_expiration) {
        struct aws_byte_cursor creds_expiration_cursor = aws_byte_cursor_from_c_str(creds_expiration->valuestring);
        if (options->expiration_required && creds_expiration_cursor.len == 0) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Parsed an unexpected credentials json document with empty expiration.")
            goto done;
        }
        if (creds_expiration_cursor.len != 0) {
            struct aws_date_time expiration;
            if (aws_date_time_init_from_str_cursor(&expiration, &creds_expiration_cursor, AWS_DATE_FORMAT_ISO_8601) ==
                AWS_OP_ERR) {
                if (options->expiration_required) {
                    AWS_LOGF_ERROR(
                        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                        "Expiration in Json document is not a valid ISO_8601 date string.");
                    goto done;
                } else {
                    AWS_LOGF_INFO(
                        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                        "Expiration in Json document is not a valid ISO_8601 date string.");
                }
            } else {
                expiration_timepoint_in_seconds = (uint64_t)aws_date_time_as_epoch_secs(&expiration);
            }
        }
    }

    /*
     * Build the credentials
     */
    struct aws_byte_cursor access_key_id_cursor = aws_byte_cursor_from_c_str(access_key_id->valuestring);
    struct aws_byte_cursor secret_access_key_cursor = aws_byte_cursor_from_c_str(secrete_access_key->valuestring);

    if (access_key_id_cursor.len == 0 || secret_access_key_cursor.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Parsed an unexpected credentials json document, either access key, secret key is empty.")
        goto done;
    }

    struct aws_byte_cursor session_token_cursor;
    AWS_ZERO_STRUCT(session_token_cursor);

    if (token) {
        session_token_cursor = aws_byte_cursor_from_c_str(token->valuestring);
        if (options->token_required && session_token_cursor.len == 0) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Parsed an unexpected credentials json document with empty token.")
            goto done;
        }
    }

    credentials = aws_credentials_new(
        allocator,
        access_key_id_cursor,
        secret_access_key_cursor,
        session_token_cursor,
        expiration_timepoint_in_seconds);

    if (credentials == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to allocate memory for credentials.");
        parse_error = false;
        goto done;
    }

done:

    if (parse_error) {
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
    }

    return credentials;
}

struct aws_credentials *aws_parse_credentials_from_json_document(
    struct aws_allocator *allocator,
    const char *document,
    const struct aws_parse_credentials_from_json_doc_options *options) {

    cJSON *document_root = cJSON_Parse(document);
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse document as Json document.");
        return NULL;
    }
    struct aws_credentials *credentials = aws_parse_credentials_from_cjson_object(allocator, document_root, options);
    cJSON_Delete(document_root);
    return credentials;
}
