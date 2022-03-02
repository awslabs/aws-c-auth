/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/credentials_utils.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>

#include <aws/common/json/json.h>

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

    struct aws_credentials *credentials = NULL;

    struct aws_json_parse_credentials_options parse_options;
    parse_options.access_key_id_name = options->access_key_id_name;
    parse_options.expiration_name = options->expiration_name;
    parse_options.expiration_required = options->expiration_required;
    parse_options.secrete_access_key_name = options->secrete_access_key_name;
    parse_options.token_name = options->token_name;
    parse_options.token_required = options->token_required;

    struct aws_json_parse_credentials_results parse_result =
        aws_json_parse_credentials_from_cjson(document_root, &parse_options);

    struct aws_byte_cursor access_key_id_cursor = aws_byte_cursor_from_c_str(parse_result.access_key_id);
    struct aws_byte_cursor secret_access_key_cursor = aws_byte_cursor_from_c_str(parse_result.secret_access_key);

    if (access_key_id_cursor.len == 0 || secret_access_key_cursor.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Parsed an unexpected credentials json document, either access key or secret key is empty.")
        goto done;
    }

    struct aws_byte_cursor session_token_cursor;
    AWS_ZERO_STRUCT(session_token_cursor);

    if (parse_result.token != NULL) {
        session_token_cursor = aws_byte_cursor_from_c_str(parse_result.token);
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
        parse_result.expiration_timepoint_in_seconds);

    if (credentials == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to allocate memory for credentials.");
        goto done;
    }

done:
    return credentials;
}

struct aws_credentials *aws_parse_credentials_from_json_document(
    struct aws_allocator *allocator,
    const char *document,
    const struct aws_parse_credentials_from_json_doc_options *options) {

    cJSON *document_root = aws_json_parse_cjson_from_string(document);
    if (document_root == NULL) {
        return NULL;
    }
    struct aws_credentials *credentials = aws_parse_credentials_from_cjson_object(allocator, document_root, options);
    aws_json_delete_cjson(document_root);
    return credentials;
}
