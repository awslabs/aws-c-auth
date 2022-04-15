/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/credentials_utils.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>

#include <aws/common/date_time.h>
#include <aws/common/json.h>

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

struct aws_credentials *aws_parse_credentials_from_aws_json_object(
    struct aws_allocator *allocator,
    struct aws_json_value *document_root,
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
    struct aws_json_value *access_key_id = NULL;
    struct aws_json_value *secrete_access_key = NULL;
    struct aws_json_value *token = NULL;
    struct aws_json_value *creds_expiration = NULL;

    bool parse_error = true;

    /*
     * Pull out the credentials components
     */
    struct aws_byte_cursor access_key_id_cursor;
    fprintf(stdout, "\nAccess Key ID Name\n");
    access_key_id =
        aws_json_value_get_from_object(document_root, aws_byte_cursor_from_c_str((char *)options->access_key_id_name));
    if (!aws_json_value_is_string(access_key_id) ||
        aws_json_value_get_string(access_key_id, &access_key_id_cursor) == AWS_OP_ERR) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse AccessKeyId from Json document.");
        goto done;
    }

    struct aws_byte_cursor secrete_access_key_cursor;
    fprintf(stdout, "\nSecret Access Key Name\n");
    secrete_access_key = aws_json_value_get_from_object(
        document_root, aws_byte_cursor_from_c_str((char *)options->secrete_access_key_name));
    if (!aws_json_value_is_string(secrete_access_key) ||
        aws_json_value_get_string(secrete_access_key, &secrete_access_key_cursor) == AWS_OP_ERR) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse SecretAccessKey from Json document.");
        goto done;
    }

    struct aws_byte_cursor token_cursor;
    if (options->token_name) {
        fprintf(stdout, "\nToken Name\n");
        token = aws_json_value_get_from_object(document_root, aws_byte_cursor_from_c_str((char *)options->token_name));
        if (!aws_json_value_is_string(token) || aws_json_value_get_string(token, &token_cursor) == AWS_OP_ERR) {
            AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Token from Json document.");
            goto done;
        }
    }

    struct aws_byte_cursor creds_expiration_cursor;
    if (options->expiration_name) {
        fprintf(stdout, "\nExpiration Name\n");
        creds_expiration =
            aws_json_value_get_from_object(document_root, aws_byte_cursor_from_c_str((char *)options->expiration_name));
        if (!aws_json_value_is_string(creds_expiration) ||
            aws_json_value_get_string(creds_expiration, &creds_expiration_cursor) == AWS_OP_ERR) {
            if (options->expiration_required) {
                AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Expiration from Json document.");
                goto done;
            }
        }
    }

    uint64_t expiration_timepoint_in_seconds = UINT64_MAX;
    if (creds_expiration) {
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
    if (access_key_id_cursor.len == 0 || secrete_access_key_cursor.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Parsed an unexpected credentials json document, either access key, secret key is empty.")
        goto done;
    }

    struct aws_byte_cursor session_token_cursor;
    AWS_ZERO_STRUCT(session_token_cursor);

    if (token) {
        aws_json_value_get_string(token, &session_token_cursor);
        if (options->token_required && session_token_cursor.len == 0) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Parsed an unexpected credentials json document with empty token.")
            goto done;
        }
    }

    credentials = aws_credentials_new(
        allocator,
        access_key_id_cursor,
        secrete_access_key_cursor,
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

    struct aws_json_value *document_root =
        aws_json_value_new_from_string(allocator, aws_byte_cursor_from_c_str(document));
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse document as Json document.");
        return NULL;
    }
    struct aws_credentials *credentials = aws_parse_credentials_from_aws_json_object(allocator, document_root, options);
    aws_json_value_destroy(document_root);
    return credentials;
}
