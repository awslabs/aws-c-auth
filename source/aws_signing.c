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

#include <aws/auth/private/aws_signing.h>

#include <aws/auth/credentials.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/cal/hash.h>
#include <aws/cal/hmac.h>
#include <aws/common/date_time.h>
#include <aws/common/encoding.h>
#include <aws/common/string.h>
#include <aws/io/stream.h>
#include <aws/io/uri.h>

#include <ctype.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

/*
 * A bunch of initial size values for various buffers used throughout the signing process
 *
 * We want them to be sufficient-but-not-wasting-significant-amounts-of-memory for "most"
 * requests.  The body read buffer is an exception since it will just be holding windows rather than
 * the entire thing.
 */
#define BODY_READ_BUFFER_SIZE 4096
#define CANONICAL_REQUEST_STARTING_SIZE 1024
#define STRING_TO_SIGN_STARTING_SIZE 256
#define SIGNED_HEADERS_STARTING_SIZE 256
#define CANONICAL_HEADER_BLOCK_STARTING_SIZE 1024
#define AUTHORIZATION_VALUE_STARTING_SIZE 512
#define PAYLOAD_HASH_STARTING_SIZE (AWS_SHA256_LEN * 2)
#define CREDENTIAL_SCOPE_STARTING_SIZE 128
#define ACCESS_CREDENTIAL_SCOPE_STARTING_SIZE 149
#define ENCODED_SIGNING_QUERY_PARAM_STARTING_SIZE 256
#define INITIAL_QUERY_FRAGMENT_COUNT 5
#define DEFAULT_PATH_COMPONENT_COUNT 10

AWS_STRING_FROM_LITERAL(g_aws_signing_content_header_name, "x-amz-content-sha256");
AWS_STRING_FROM_LITERAL(g_aws_signing_authorization_header_name, "Authorization");
AWS_STRING_FROM_LITERAL(g_aws_signing_authorization_query_param_name, "X-Amz-Signature");
AWS_STRING_FROM_LITERAL(g_aws_signing_algorithm_query_param_name, "X-Amz-Algorithm");
AWS_STRING_FROM_LITERAL(g_aws_signing_credential_query_param_name, "X-Amz-Credential");
AWS_STRING_FROM_LITERAL(g_aws_signing_date_name, "X-Amz-Date");
AWS_STRING_FROM_LITERAL(g_aws_signing_signed_headers_query_param_name, "X-Amz-SignedHeaders");
AWS_STRING_FROM_LITERAL(g_aws_signing_security_token_name, "X-Amz-Security-Token");

/* aws-related query param and header tables */
static struct aws_hash_table s_forbidden_headers;
static struct aws_hash_table s_forbidden_params;
static struct aws_hash_table s_skipped_headers;

static struct aws_byte_cursor s_amzn_trace_id_header_name;
static struct aws_byte_cursor s_user_agent_header_name;
static struct aws_byte_cursor s_connection_header_name;
static struct aws_byte_cursor s_sec_websocket_key_header_name;
static struct aws_byte_cursor s_sec_websocket_protocol_header_name;
static struct aws_byte_cursor s_sec_websocket_version_header_name;
static struct aws_byte_cursor s_upgrade_header_name;

static struct aws_byte_cursor s_amz_content_sha256_header_name;
static struct aws_byte_cursor s_amz_date_header_name;
static struct aws_byte_cursor s_authorization_header_name;

static struct aws_byte_cursor s_amz_signature_param_name;
static struct aws_byte_cursor s_amz_date_param_name;
static struct aws_byte_cursor s_amz_credential_param_name;
static struct aws_byte_cursor s_amz_algorithm_param_name;
static struct aws_byte_cursor s_amz_signed_headers_param_name;

/*
 * Build a set of library-static tables for quick lookup.
 *
 * Construction errors are considered fatal.
 */
int aws_signing_init_signing_tables(struct aws_allocator *allocator) {

    if (aws_hash_table_init(
            &s_skipped_headers,
            allocator,
            10,
            aws_hash_byte_cursor_ptr_ignore_case,
            (aws_hash_callback_eq_fn *)aws_byte_cursor_eq_ignore_case,
            NULL,
            NULL)) {
        return AWS_OP_ERR;
    }

    s_amzn_trace_id_header_name = aws_byte_cursor_from_c_str("x-amzn-trace-id");
    if (aws_hash_table_put(&s_skipped_headers, &s_amzn_trace_id_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_user_agent_header_name = aws_byte_cursor_from_c_str("UserAgent");
    if (aws_hash_table_put(&s_skipped_headers, &s_user_agent_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_connection_header_name = aws_byte_cursor_from_c_str("connection");
    if (aws_hash_table_put(&s_skipped_headers, &s_connection_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_sec_websocket_key_header_name = aws_byte_cursor_from_c_str("sec-websocket-key");
    if (aws_hash_table_put(&s_skipped_headers, &s_sec_websocket_key_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_sec_websocket_protocol_header_name = aws_byte_cursor_from_c_str("sec-websocket-protocol");
    if (aws_hash_table_put(&s_skipped_headers, &s_sec_websocket_protocol_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_sec_websocket_version_header_name = aws_byte_cursor_from_c_str("sec-websocket-version");
    if (aws_hash_table_put(&s_skipped_headers, &s_sec_websocket_version_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_upgrade_header_name = aws_byte_cursor_from_c_str("upgrade");
    if (aws_hash_table_put(&s_skipped_headers, &s_upgrade_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    if (aws_hash_table_init(
            &s_forbidden_headers,
            allocator,
            10,
            aws_hash_byte_cursor_ptr_ignore_case,
            (aws_hash_callback_eq_fn *)aws_byte_cursor_eq_ignore_case,
            NULL,
            NULL)) {
        return AWS_OP_ERR;
    }

    s_amz_content_sha256_header_name = aws_byte_cursor_from_string(g_aws_signing_content_header_name);
    if (aws_hash_table_put(&s_forbidden_headers, &s_amz_content_sha256_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_amz_date_header_name = aws_byte_cursor_from_string(g_aws_signing_date_name);
    if (aws_hash_table_put(&s_forbidden_headers, &s_amz_date_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_authorization_header_name = aws_byte_cursor_from_string(g_aws_signing_authorization_header_name);
    if (aws_hash_table_put(&s_forbidden_headers, &s_authorization_header_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    if (aws_hash_table_init(
            &s_forbidden_params,
            allocator,
            10,
            aws_hash_byte_cursor_ptr_ignore_case,
            (aws_hash_callback_eq_fn *)aws_byte_cursor_eq_ignore_case,
            NULL,
            NULL)) {
        return AWS_OP_ERR;
    }

    s_amz_signature_param_name = aws_byte_cursor_from_string(g_aws_signing_authorization_query_param_name);
    if (aws_hash_table_put(&s_forbidden_params, &s_amz_signature_param_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_amz_date_param_name = aws_byte_cursor_from_string(g_aws_signing_date_name);
    if (aws_hash_table_put(&s_forbidden_params, &s_amz_date_param_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_amz_credential_param_name = aws_byte_cursor_from_string(g_aws_signing_credential_query_param_name);
    if (aws_hash_table_put(&s_forbidden_params, &s_amz_credential_param_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_amz_algorithm_param_name = aws_byte_cursor_from_string(g_aws_signing_algorithm_query_param_name);
    if (aws_hash_table_put(&s_forbidden_params, &s_amz_algorithm_param_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    s_amz_signed_headers_param_name = aws_byte_cursor_from_string(g_aws_signing_signed_headers_query_param_name);
    if (aws_hash_table_put(&s_forbidden_params, &s_amz_signed_headers_param_name, NULL, NULL)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_signing_clean_up_signing_tables(void) {
    aws_hash_table_clean_up(&s_skipped_headers);
    aws_hash_table_clean_up(&s_forbidden_headers);
    aws_hash_table_clean_up(&s_forbidden_params);
}

/*
 * Signing algorithm helper functions
 */
AWS_STATIC_STRING_FROM_LITERAL(s_sigv4_algorithm, "AWS4-HMAC-SHA256");

static bool s_is_header_auth(enum aws_signing_algorithm algorithm) {
    return algorithm == AWS_SIGNING_ALGORITHM_SIG_V4_HEADER;
}

static bool s_is_query_param_auth(enum aws_signing_algorithm algorithm) {
    return algorithm == AWS_SIGNING_ALGORITHM_SIG_V4_QUERY_PARAM;
}

static int s_get_signing_algorithm_cursor(enum aws_signing_algorithm algorithm, struct aws_byte_cursor *cursor) {
    switch (algorithm) {
        case AWS_SIGNING_ALGORITHM_SIG_V4_HEADER:
        case AWS_SIGNING_ALGORITHM_SIG_V4_QUERY_PARAM:
            *cursor = aws_byte_cursor_from_string(s_sigv4_algorithm);
            break;

        default:
            return aws_raise_error(AWS_AUTH_SIGNING_UNSUPPORTED_ALGORITHM);
    }

    return AWS_OP_SUCCESS;
}

static int s_append_signing_algorithm(enum aws_signing_algorithm algorithm, struct aws_byte_buf *dest) {
    struct aws_byte_cursor algorithm_cursor;
    if (s_get_signing_algorithm_cursor(algorithm, &algorithm_cursor)) {
        return AWS_OP_ERR;
    }

    return aws_byte_buf_append_dynamic(dest, &algorithm_cursor);
}

/*
 * signing state management
 */
struct aws_signing_state_aws *aws_signing_state_new(
    struct aws_allocator *allocator,
    const struct aws_signing_config_aws *config,
    const struct aws_signable *signable,
    aws_signing_complete_fn *on_complete,
    void *userdata) {

    if (aws_validate_aws_signing_config_aws(config)) {
        return NULL;
    }

    struct aws_signing_state_aws *state = aws_mem_calloc(allocator, 1, sizeof(struct aws_signing_state_aws));
    if (!state) {
        return NULL;
    }

    state->allocator = allocator;

    /* Make our own copy of the signing config */
    state->config = *config;
    aws_credentials_provider_acquire(state->config.credentials_provider);

    if (aws_byte_buf_init(&state->region_service_buffer, allocator, config->region.len + config->service.len)) {
        goto on_error;
    }

    if (aws_byte_buf_append_and_update(&state->region_service_buffer, &state->config.region)) {
        goto on_error;
    }

    if (aws_byte_buf_append_and_update(&state->region_service_buffer, &state->config.service)) {
        goto on_error;
    }

    state->signable = signable;
    state->on_complete = on_complete;
    state->userdata = userdata;

    if (aws_signing_result_init(&state->result, allocator)) {
        goto on_error;
    }

    if (aws_byte_buf_init(&state->canonical_request, allocator, CANONICAL_REQUEST_STARTING_SIZE) ||
        aws_byte_buf_init(&state->string_to_sign, allocator, STRING_TO_SIGN_STARTING_SIZE) ||
        aws_byte_buf_init(&state->signed_headers, allocator, SIGNED_HEADERS_STARTING_SIZE) ||
        aws_byte_buf_init(&state->canonical_header_block, allocator, CANONICAL_HEADER_BLOCK_STARTING_SIZE) ||
        aws_byte_buf_init(&state->payload_hash, allocator, PAYLOAD_HASH_STARTING_SIZE) ||
        aws_byte_buf_init(&state->credential_scope, allocator, CREDENTIAL_SCOPE_STARTING_SIZE) ||
        aws_byte_buf_init(&state->access_credential_scope, allocator, ACCESS_CREDENTIAL_SCOPE_STARTING_SIZE) ||
        aws_byte_buf_init(&state->date, allocator, AWS_DATE_TIME_STR_MAX_LEN)) {

        goto on_error;
    }

    return state;

on_error:
    aws_signing_state_destroy(state);
    return NULL;
}

void aws_signing_state_destroy(struct aws_signing_state_aws *state) {
    aws_signing_result_clean_up(&state->result);

    aws_credentials_provider_release(state->config.credentials_provider);

    aws_byte_buf_clean_up(&state->region_service_buffer);

    aws_byte_buf_clean_up(&state->canonical_request);
    aws_byte_buf_clean_up(&state->string_to_sign);
    aws_byte_buf_clean_up(&state->signed_headers);
    aws_byte_buf_clean_up(&state->canonical_header_block);
    aws_byte_buf_clean_up(&state->payload_hash);
    aws_byte_buf_clean_up(&state->credential_scope);
    aws_byte_buf_clean_up(&state->access_credential_scope);
    aws_byte_buf_clean_up(&state->date);

    aws_mem_release(state->allocator, state);
}

/*
 * canonical request utility functions:
 *
 * various appends, conversion/encoding, etc...
 *
 */

static int s_append_character_to_byte_buf(struct aws_byte_buf *buffer, uint8_t value) {

#if defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(disable : 4221)
#endif /* _MSC_VER */

    /* msvc isn't a fan of this pointer-to-local assignment */
    struct aws_byte_cursor eq_cursor = {.len = 1, .ptr = &value};

#if defined(_MSC_VER)
#    pragma warning(pop)
#endif /* _MSC_VER */

    return aws_byte_buf_append_dynamic(buffer, &eq_cursor);
}

static int s_append_canonical_method(struct aws_signing_state_aws *state) {
    const struct aws_signable *signable = state->signable;
    struct aws_byte_buf *buffer = &state->canonical_request;

    struct aws_byte_cursor method_cursor;
    aws_signable_get_property(signable, g_aws_http_method_property_name, &method_cursor);

    if (aws_byte_buf_append_dynamic(buffer, &method_cursor)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(buffer, '\n')) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * A function that builds a normalized path (removes redundant '/' characters, '.' components, and properly pops off
 * components in response '..' components)
 *
 * We use a simple algorithm to do this:
 *
 * First split the path into components
 * Then, using a secondary stack of components, build the final path by pushing and popping (on '..') components
 * on the stack.  The final path is then the concatenation of the secondary stack.
 */
static int s_append_normalized_path(
    const struct aws_byte_cursor *raw_path,
    struct aws_allocator *allocator,
    struct aws_byte_buf *dest) {

    struct aws_array_list raw_split;
    AWS_ZERO_STRUCT(raw_split);

    struct aws_array_list normalized_split;
    AWS_ZERO_STRUCT(normalized_split);

    int result = AWS_OP_ERR;

    if (aws_array_list_init_dynamic(
            &raw_split, allocator, DEFAULT_PATH_COMPONENT_COUNT, sizeof(struct aws_byte_cursor))) {
        goto cleanup;
    }

    if (aws_byte_cursor_split_on_char(raw_path, '/', &raw_split)) {
        goto cleanup;
    }

    const size_t raw_split_count = aws_array_list_length(&raw_split);
    if (aws_array_list_init_dynamic(&normalized_split, allocator, raw_split_count, sizeof(struct aws_byte_cursor))) {
        goto cleanup;
    }

    /*
     * Iterate the raw split to build a list of path components that make up the
     * normalized path
     */
    for (size_t i = 0; i < raw_split_count; ++i) {
        struct aws_byte_cursor path_component;
        AWS_ZERO_STRUCT(path_component);
        if (aws_array_list_get_at(&raw_split, &path_component, i)) {
            goto cleanup;
        }

        if (path_component.len == 0 || (path_component.len == 1 && *path_component.ptr == '.')) {
            /* '.' and '' contribute nothing to a normalized path */
            continue;
        }

        if (path_component.len == 2 && *path_component.ptr == '.' && *(path_component.ptr + 1) == '.') {
            /* '..' causes us to remove the last valid path component */
            aws_array_list_pop_back(&normalized_split);
        } else {
            aws_array_list_push_back(&normalized_split, &path_component);
        }
    }

    /*
     * Special case preserve whether or not the path ended with a '/'
     */
    bool ends_with_slash = raw_path->len > 0 && raw_path->ptr[raw_path->len - 1] == '/';

    /*
     * Paths always start with a single '/'
     */
    if (s_append_character_to_byte_buf(dest, '/')) {
        goto cleanup;
    }

    /*
     * build the final normalized path from the normalized split by joining
     * the components together with '/'
     */
    const size_t normalized_split_count = aws_array_list_length(&normalized_split);
    for (size_t i = 0; i < normalized_split_count; ++i) {
        struct aws_byte_cursor normalized_path_component;
        AWS_ZERO_STRUCT(normalized_path_component);
        if (aws_array_list_get_at(&normalized_split, &normalized_path_component, i)) {
            goto cleanup;
        }

        if (aws_byte_buf_append_dynamic(dest, &normalized_path_component)) {
            goto cleanup;
        }

        if (i + 1 < normalized_split_count || ends_with_slash) {
            if (s_append_character_to_byte_buf(dest, '/')) {
                goto cleanup;
            }
        }
    }

    result = AWS_OP_SUCCESS;

cleanup:

    aws_array_list_clean_up(&raw_split);
    aws_array_list_clean_up(&normalized_split);

    return result;
}

static int s_append_canonical_path(const struct aws_uri *uri, struct aws_signing_state_aws *state) {
    const struct aws_signing_config_aws *config = &state->config;
    struct aws_byte_buf *canonical_request_buffer = &state->canonical_request;
    struct aws_allocator *allocator = state->allocator;
    int result = AWS_OP_ERR;

    /*
     * Put this at function global scope so that it gets cleaned up even though it's only used inside
     * a single branch.  Allows error handling and cleanup to follow the pattern established
     * throughout this file.
     */
    struct aws_byte_buf normalized_path;
    AWS_ZERO_STRUCT(normalized_path);

    /*
     * We assume the request's uri path has already been encoded once (in order to go out on the wire).
     * Some services do not decode the path before performing the sig v4 calculation, resulting in the
     * service actually performing sigv4 on a double-encoding of the path.  In order to match those
     * services, we must double encode in our calculation as well.
     */
    if (config->use_double_uri_encode) {
        struct aws_byte_cursor path_cursor;

        /*
         * We need to transform the the normalized path, so we can't just append it into the canonical
         * request.  Instead we append it into a temporary buffer and perform the transformation from
         * it.
         *
         * All this does is skip the temporary normalized path in the case where we don't need to
         * double encode.
         */
        if (config->should_normalize_uri_path) {
            if (aws_byte_buf_init(&normalized_path, state->allocator, uri->path.len)) {
                goto cleanup;
            }

            if (s_append_normalized_path(&uri->path, allocator, &normalized_path)) {
                goto cleanup;
            }

            path_cursor = aws_byte_cursor_from_buf(&normalized_path);
        } else {
            path_cursor = uri->path;
        }

        if (aws_byte_buf_append_encoding_uri_path(canonical_request_buffer, &path_cursor)) {
            goto cleanup;
        }
    } else {
        /*
         * If we don't need to perform any kind of transformation on the normalized path, just append it directly
         * into the canonical request buffer
         */
        if (config->should_normalize_uri_path &&
            s_append_normalized_path(&uri->path, allocator, canonical_request_buffer)) {
            goto cleanup;
        } else if (
            !config->should_normalize_uri_path && aws_byte_buf_append_dynamic(canonical_request_buffer, &uri->path)) {
            goto cleanup;
        }
    }

    if (s_append_character_to_byte_buf(canonical_request_buffer, '\n')) {
        goto cleanup;
    }

    result = AWS_OP_SUCCESS;

cleanup:

    aws_byte_buf_clean_up(&normalized_path);

    return result;
}

/*
 * Query params are compared first by name, then by value
 */
int s_canonical_query_param_comparator(const void *lhs, const void *rhs) {
    const struct aws_uri_param *left_param = lhs;
    const struct aws_uri_param *right_param = rhs;

    int key_compare = aws_byte_cursor_compare_lexical(&left_param->key, &right_param->key);
    if (key_compare != 0) {
        return key_compare;
    }

    return aws_byte_cursor_compare_lexical(&left_param->value, &right_param->value);
}

/*
 * We need to sort the headers in a stable fashion, but the default sorting methods available in the c library are not
 * guaranteed to be stable.  We can make the sort stable by instead sorting a wrapper object that includes the original
 * index of the wrapped object and using that index to break lexical ties.
 *
 * We sort a copy of the header (rather than pointers) so that we can easily inject secondary headers into
 * the canonical request.
 */
struct stable_header {
    struct aws_signable_property_list_pair header;
    size_t original_index;
};

int s_canonical_header_comparator(const void *lhs, const void *rhs) {
    const struct stable_header *left_header = lhs;
    const struct stable_header *right_header = rhs;

    int result = aws_byte_cursor_compare_lookup(
        &left_header->header.name, &right_header->header.name, aws_lookup_table_to_lower_get());
    if (result != 0) {
        return result;
    }

    /* they're the same header, use the original index to keep the sort stable */
    if (left_header->original_index < right_header->original_index) {
        return -1;
    }

    /* equality should never happen */
    AWS_ASSERT(left_header->original_index > right_header->original_index);

    return 1;
}

static int s_append_canonical_query_param(struct aws_uri_param *param, struct aws_byte_buf *buffer) {
    if (aws_byte_buf_append_encoding_uri_param(buffer, &param->key)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(buffer, '=')) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append_encoding_uri_param(buffer, &param->value)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_add_authorization_query_param_with_encoding(
    struct aws_signing_state_aws *state,
    struct aws_array_list *query_params,
    struct aws_uri_param *uri_param,
    struct aws_byte_buf *uri_encoded_buffer) {
    uri_encoded_buffer->len = 0;

    if (aws_byte_buf_append_encoding_uri_param(uri_encoded_buffer, &uri_param->value)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor encoded_algorithm_value = aws_byte_cursor_from_buf(uri_encoded_buffer);
    if (aws_signing_result_append_property_list(
            &state->result, g_aws_http_query_params_property_list_name, &uri_param->key, &encoded_algorithm_value) ||
        aws_array_list_push_back(query_params, uri_param)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * Checks the header against both an internal skip list as well as an optional user-supplied filter
 * function.  Only sign the header if both functions allow it.
 */
static bool s_should_sign_param(struct aws_signing_state_aws *state, struct aws_byte_cursor *name) {
    if (state->config.should_sign_param) {
        if (!state->config.should_sign_param(name, state->config.should_sign_param_ud)) {
            return false;
        }
    }

    struct aws_hash_element *element = NULL;
    if (aws_hash_table_find(&s_skipped_headers, name, &element) == AWS_OP_ERR || element != NULL) {
        return false;
    }

    return true;
}

/*
 * If the auth type was query param then this function adds all the required query params and values with the
 * exception of X-Amz-Signature (because we're still computing its value)
 */
static int s_add_authorization_query_params(struct aws_signing_state_aws *state, struct aws_array_list *query_params) {
    if (!s_is_query_param_auth(state->config.algorithm)) {
        return AWS_OP_SUCCESS;
    }

    int result = AWS_OP_ERR;

    struct aws_byte_buf uri_encoded_value;
    AWS_ZERO_STRUCT(uri_encoded_value);
    if (aws_byte_buf_init(&uri_encoded_value, state->allocator, ENCODED_SIGNING_QUERY_PARAM_STARTING_SIZE)) {
        goto done;
    }

    /* X-Amz-Algorithm */
    struct aws_uri_param algorithm_param = {.key =
                                                aws_byte_cursor_from_string(g_aws_signing_algorithm_query_param_name)};

    if (s_get_signing_algorithm_cursor(state->config.algorithm, &algorithm_param.value)) {
        goto done;
    }

    if (s_add_authorization_query_param_with_encoding(state, query_params, &algorithm_param, &uri_encoded_value)) {
        goto done;
    }

    /* X-Amz-Credential */
    struct aws_uri_param credential_param = {.key =
                                                 aws_byte_cursor_from_string(g_aws_signing_credential_query_param_name),
                                             .value = aws_byte_cursor_from_buf(&state->access_credential_scope)};

    if (s_add_authorization_query_param_with_encoding(state, query_params, &credential_param, &uri_encoded_value)) {
        goto done;
    }

    /* X-Amz-Date */
    struct aws_uri_param date_param = {.key = aws_byte_cursor_from_string(g_aws_signing_date_name),
                                       .value = aws_byte_cursor_from_buf(&state->date)};

    if (s_add_authorization_query_param_with_encoding(state, query_params, &date_param, &uri_encoded_value)) {
        goto done;
    }

    /* X-Amz-SignedHeaders */
    struct aws_uri_param signed_headers_param = {
        .key = aws_byte_cursor_from_string(g_aws_signing_signed_headers_query_param_name),
        .value = aws_byte_cursor_from_buf(&state->signed_headers)};

    if (s_add_authorization_query_param_with_encoding(state, query_params, &signed_headers_param, &uri_encoded_value)) {
        goto done;
    }

    /* X-Amz-Security-token */
    struct aws_byte_cursor security_token_name_cur = aws_byte_cursor_from_string(g_aws_signing_security_token_name);

    if (state->credentials->session_token && s_should_sign_param(state, &security_token_name_cur)) {
        struct aws_uri_param security_token_param = {
            .key = security_token_name_cur, .value = aws_byte_cursor_from_string(state->credentials->session_token)};

        if (s_add_authorization_query_param_with_encoding(
                state, query_params, &security_token_param, &uri_encoded_value)) {
            goto done;
        }
    }

    result = AWS_OP_SUCCESS;

done:

    aws_byte_buf_clean_up(&uri_encoded_value);

    return result;
}

static int s_validate_query_params(struct aws_array_list *params) {
    const size_t param_count = aws_array_list_length(params);
    for (size_t i = 0; i < param_count; ++i) {
        struct aws_uri_param param;
        AWS_ZERO_STRUCT(param);
        aws_array_list_get_at(params, &param, i);

        struct aws_hash_element *forbidden_element = NULL;
        aws_hash_table_find(&s_forbidden_params, &param.key, &forbidden_element);

        if (forbidden_element != NULL) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_SIGNING,
                "AWS authorization query param \"" PRInSTR "\" found in request while signing",
                AWS_BYTE_CURSOR_PRI(param.key));
            return aws_raise_error(AWS_AUTH_SIGNING_ILLEGAL_REQUEST_QUERY_PARAM);
        }
    }

    return AWS_OP_SUCCESS;
}

/*
 * Adds the full canonical query string to the canonical request:
 */
static int s_append_canonical_query_string(struct aws_uri *uri, struct aws_signing_state_aws *state) {
    struct aws_allocator *allocator = state->allocator;
    struct aws_byte_buf *canonical_request_buffer = &state->canonical_request;

    int result = AWS_OP_ERR;

    struct aws_array_list query_params;
    if (aws_array_list_init_dynamic(
            &query_params, allocator, INITIAL_QUERY_FRAGMENT_COUNT, sizeof(struct aws_uri_param))) {
        return result;
    }

    if (aws_uri_query_string_params(uri, &query_params)) {
        goto cleanup;
    }

    if (s_validate_query_params(&query_params)) {
        goto cleanup;
    }

    if (s_add_authorization_query_params(state, &query_params)) {
        goto cleanup;
    }

    const size_t param_count = aws_array_list_length(&query_params);

    /* lexical sort and append */
    qsort(query_params.data, param_count, sizeof(struct aws_uri_param), s_canonical_query_param_comparator);
    for (size_t i = 0; i < param_count; ++i) {
        struct aws_uri_param param;
        if (aws_array_list_get_at(&query_params, &param, i)) {
            goto cleanup;
        }

        if (s_append_canonical_query_param(&param, canonical_request_buffer)) {
            goto cleanup;
        }

        if (i + 1 < param_count) {
            if (s_append_character_to_byte_buf(canonical_request_buffer, '&')) {
                goto cleanup;
            }
        }
    }

    if (s_append_character_to_byte_buf(canonical_request_buffer, '\n')) {
        goto cleanup;
    }

    result = AWS_OP_SUCCESS;

cleanup:

    aws_array_list_clean_up(&query_params);

    return result;
}

/*
 * It is unclear from the spec (and not resolved by the tests) whether other forms of whitespace (\t \v) should be
 * included in the trimming done to headers
 */
static bool s_is_space(uint8_t value) {
    return isspace(value);
}

/*
 * Appends a single header key-value pair to the canonical request.  Multi-line and repeat headers make this more
 * complicated than you'd expect.
 *
 * We call this function on a sorted collection, so header repeats are guaranteed to be consecutive.
 *
 * In particular, there are two cases:
 *   (1) This is a header whose name hasn't been seen before, in which case we start a new line and append both name and
 * value. (2) This is a header we've previously seen, just append the value.
 *
 * The fact that we can't '\n' until we've moved to a new header name also complicates the logic.
 *
 * This function appends to a state buffer rather than the canonical request.  This allows us to calculate the signed
 * headers (so that it can go into the query param if needed) before the query params are put into the canonical
 * request.
 */
static int s_append_canonical_header(
    struct aws_signing_state_aws *state,
    struct aws_signable_property_list_pair *header,
    const struct aws_byte_cursor *last_seen_header_name) {
    struct aws_byte_buf *canonical_header_buffer = &state->canonical_header_block;
    struct aws_byte_buf *signed_headers_buffer = &state->signed_headers;
    const uint8_t *to_lower_table = aws_lookup_table_to_lower_get();
    bool prepend_comma = false;

    /*
     * Write to the signed_headers shared state for later use, copy
     * to canonical header buffer as well
     */
    if (last_seen_header_name == NULL ||
        aws_byte_cursor_compare_lookup(last_seen_header_name, &header->name, aws_lookup_table_to_lower_get()) != 0) {
        /*
         * The headers arrive in sorted order, so we know we've never seen this header before
         */
        if (last_seen_header_name) {
            /*
             * there's a previous header, add appropriate separator in both canonical header buffer
             * and signed headers buffer
             */
            if (s_append_character_to_byte_buf(canonical_header_buffer, '\n')) {
                return AWS_OP_ERR;
            }

            if (s_append_character_to_byte_buf(signed_headers_buffer, ';')) {
                return AWS_OP_ERR;
            }
        }

        /* add it to the signed headers buffer */
        if (aws_byte_buf_append_with_lookup(signed_headers_buffer, &header->name, to_lower_table)) {
            return AWS_OP_ERR;
        }

        /* add it to the canonical header buffer */
        if (aws_byte_buf_append_with_lookup(canonical_header_buffer, &header->name, to_lower_table)) {
            return AWS_OP_ERR;
        }

        if (s_append_character_to_byte_buf(canonical_header_buffer, ':')) {
            return AWS_OP_ERR;
        }
    } else {
        prepend_comma = true;
        /* we've seen this header before, add a comma before appending the first value */
    }

    /*
     * Handle multi-line headers by iterating a split against '\n' of the header's value
     */
    struct aws_byte_cursor line_split;
    AWS_ZERO_STRUCT(line_split);
    while (aws_byte_cursor_next_split(&header->value, '\n', &line_split)) {
        /*
         * This is the unsafe, non-append write of the header value where consecutive spaces
         * are squashed into a single one.  Since this can only shrink the value length and we've
         * already reserved enough to hold the value, we can do raw buffer writes safely without
         * worrying about capacity.
         */
        struct aws_byte_cursor trimmed_value = aws_byte_cursor_trim_pred(&line_split, s_is_space);
        if (trimmed_value.len == 0) {
            continue;
        }

        if (prepend_comma && s_append_character_to_byte_buf(canonical_header_buffer, ',')) {
            return AWS_OP_ERR;
        }

        /* raw, unsafe write loop */
        bool in_space = false;
        uint8_t *start_ptr = trimmed_value.ptr;
        uint8_t *end_ptr = trimmed_value.ptr + trimmed_value.len;
        uint8_t *dest_ptr = canonical_header_buffer->buffer + canonical_header_buffer->len;
        while (start_ptr < end_ptr) {
            uint8_t value = *start_ptr;
            bool is_space = value == ' ';

            if (!is_space || !in_space) {
                *dest_ptr++ = value;
                ++canonical_header_buffer->len;
            }

            in_space = is_space;

            ++start_ptr;
        }

        /* We wrote an actual value, so all subsequent values in this call must be pre-pended with a comma */
        prepend_comma = true;
    }

    return AWS_OP_SUCCESS;
}

/*
 * Builds the list of header name-value pairs to be added to the canonical request.  The list members are
 * actually the header wrapper structs that allow for stable sorting.
 *
 * Takes the original request headers, adds X-Amz-Date, and optionally, x-amz-content-sha256
 *
 * If we add filtering/exclusion support, this is where it would go
 */
static int s_build_canonical_stable_header_list(
    struct aws_signing_state_aws *state,
    struct aws_array_list *stable_header_list,
    size_t *out_required_capacity) {

    AWS_ASSERT(aws_array_list_length(stable_header_list) == 0);

    *out_required_capacity = 0;
    const struct aws_signable *signable = state->signable;

    /*
     * request headers
     */
    struct aws_array_list *signable_header_list = NULL;
    if (aws_signable_get_property_list(signable, g_aws_http_headers_property_list_name, &signable_header_list)) {
        return AWS_OP_ERR;
    }

    const size_t signable_header_count = aws_array_list_length(signable_header_list);
    for (size_t i = 0; i < signable_header_count; ++i) {
        struct stable_header header_wrapper;
        AWS_ZERO_STRUCT(header_wrapper);
        header_wrapper.original_index = i;

        if (aws_array_list_get_at(signable_header_list, &header_wrapper.header, i)) {
            return AWS_OP_ERR;
        }

        struct aws_byte_cursor *header_name_cursor = &header_wrapper.header.name;
        if (!s_should_sign_param(state, header_name_cursor)) {
            continue;
        }

        *out_required_capacity += header_wrapper.header.name.len + header_wrapper.header.value.len;

        if (aws_array_list_push_back(stable_header_list, &header_wrapper)) {
            return AWS_OP_ERR;
        }
    }

    size_t additional_header_index = signable_header_count;

    struct aws_byte_cursor security_token_cur = aws_byte_cursor_from_string(g_aws_signing_security_token_name);

    if (state->credentials->session_token && s_should_sign_param(state, &security_token_cur)) {
        /* X-Amz-Security-Token */
        struct stable_header session_token_header = {
            .original_index = additional_header_index++,
            .header =
                {
                    .name = security_token_cur,
                    .value = aws_byte_cursor_from_string(state->credentials->session_token),
                },
        };
        if (aws_array_list_push_back(stable_header_list, &session_token_header)) {
            return AWS_OP_ERR;
        }

        *out_required_capacity += g_aws_signing_security_token_name->len + state->credentials->session_token->len;
    }

    if (!s_is_query_param_auth(state->config.algorithm)) {
        /*
         * X-Amz-Date
         */
        struct stable_header date_header = {.original_index = additional_header_index++,
                                            .header = {.name = aws_byte_cursor_from_string(g_aws_signing_date_name),
                                                       .value = aws_byte_cursor_from_buf(&state->date)}};

        if (aws_array_list_push_back(stable_header_list, &date_header)) {
            return AWS_OP_ERR;
        }

        *out_required_capacity += g_aws_signing_date_name->len + state->date.len;
    }

    /*
     * x-amz-content-sha256 (optional)
     */
    if (state->config.body_signing_type >= AWS_BODY_SIGNING_ON) {
        struct stable_header content_hash_header = {
            .original_index = additional_header_index++,
            .header = {.name = aws_byte_cursor_from_string(g_aws_signing_content_header_name),
                       .value = aws_byte_cursor_from_buf(&state->payload_hash)}};

        if (aws_array_list_push_back(stable_header_list, &content_hash_header)) {
            return AWS_OP_ERR;
        }

        *out_required_capacity += g_aws_signing_content_header_name->len + state->payload_hash.len;
    }

    *out_required_capacity += aws_array_list_length(stable_header_list) * 2; /*  ':' + '\n' per header */

    return AWS_OP_SUCCESS;
}

static int s_validate_signable_header_list(struct aws_array_list *header_list) {
    const size_t header_count = aws_array_list_length(header_list);
    for (size_t i = 0; i < header_count; ++i) {
        struct aws_signable_property_list_pair header;
        AWS_ZERO_STRUCT(header);

        aws_array_list_get_at(header_list, &header, i);

        struct aws_hash_element *forbidden_element = NULL;
        aws_hash_table_find(&s_forbidden_headers, &header.name, &forbidden_element);

        if (forbidden_element != NULL) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_SIGNING,
                "AWS authorization header \"" PRInSTR "\" found in request while signing",
                AWS_BYTE_CURSOR_PRI(header.name));
            return aws_raise_error(AWS_AUTH_SIGNING_ILLEGAL_REQUEST_HEADER);
        }
    }

    return AWS_OP_SUCCESS;
}

/*
 * Top-level-ish function to write the canonical header set into a buffer as well as the signed header names
 * into a separate buffer.  We do this very early in the canonical request construction process so that the
 * query params processing has the signed header names available to it.
 */
static int s_build_canonical_headers(struct aws_signing_state_aws *state) {
    const struct aws_signable *signable = state->signable;
    struct aws_allocator *allocator = state->allocator;
    struct aws_byte_buf *header_buffer = &state->canonical_header_block;
    struct aws_byte_buf *signed_headers_buffer = &state->signed_headers;

    AWS_ASSERT(header_buffer->len == 0);
    AWS_ASSERT(signed_headers_buffer->len == 0);

    int result = AWS_OP_ERR;

    struct aws_array_list *signable_header_list = NULL;
    if (aws_signable_get_property_list(signable, g_aws_http_headers_property_list_name, &signable_header_list)) {
        return AWS_OP_ERR;
    }

    if (s_validate_signable_header_list(signable_header_list)) {
        return AWS_OP_ERR;
    }

    const size_t signable_header_count = aws_array_list_length(signable_header_list);
    size_t total_sign_headers_count = signable_header_count + 1; /* for X-Amz-Credentials */

    if (state->config.body_signing_type >= AWS_BODY_SIGNING_ON) {
        total_sign_headers_count += 1;
    }

    if (state->credentials->session_token) {
        total_sign_headers_count += 1; /* for X-Amz-Security-Token */
    }

    struct aws_array_list headers;
    if (aws_array_list_init_dynamic(&headers, allocator, total_sign_headers_count, sizeof(struct stable_header))) {
        return AWS_OP_ERR;
    }

    size_t header_buffer_reserve_size = 0;
    if (s_build_canonical_stable_header_list(state, &headers, &header_buffer_reserve_size)) {
        goto on_cleanup;
    }

    /*
     * Make sure there's enough room in the request buffer to hold a conservative overestimate of the room
     * needed for canonical headers.  There are places we'll be using an append function that does not resize.
     */
    if (aws_byte_buf_reserve(header_buffer, header_buffer_reserve_size)) {
        return AWS_OP_ERR;
    }

    const size_t header_count = aws_array_list_length(&headers);

    /* Sort the arraylist via lowercase header name and original position */
    qsort(headers.data, header_count, sizeof(struct stable_header), s_canonical_header_comparator);

    /* Iterate the sorted list, writing the canonical representation into the request */
    struct aws_byte_cursor *last_seen_header_name = NULL;
    for (size_t i = 0; i < header_count; ++i) {
        struct stable_header *wrapper = NULL;
        if (aws_array_list_get_at_ptr(&headers, (void **)&wrapper, i)) {
            goto on_cleanup;
        }

        if (s_append_canonical_header(state, &wrapper->header, last_seen_header_name)) {
            goto on_cleanup;
        }

        last_seen_header_name = &wrapper->header.name;
    }

    /* There's always at least one header entry (X-Amz-Date), end the last one */
    if (s_append_character_to_byte_buf(header_buffer, '\n')) {
        goto on_cleanup;
    }

    if (s_append_character_to_byte_buf(header_buffer, '\n')) {
        goto on_cleanup;
    }

    struct aws_byte_cursor signed_headers_cursor = aws_byte_cursor_from_buf(signed_headers_buffer);
    if (aws_byte_buf_append_dynamic(header_buffer, &signed_headers_cursor)) {
        goto on_cleanup;
    }

    if (s_append_character_to_byte_buf(header_buffer, '\n')) {
        goto on_cleanup;
    }

    result = AWS_OP_SUCCESS;

on_cleanup:

    aws_array_list_clean_up(&headers);

    return result;
}

/*
 * Computes the payload hash as hex digits.  We currently don't have a way
 * to rewind the stream, so the caller of the signing process will need to do
 * that manually.
 */
static int s_build_canonical_payload_hash(struct aws_signing_state_aws *state) {
    const struct aws_signable *signable = state->signable;
    struct aws_allocator *allocator = state->allocator;
    struct aws_byte_buf *payload_hash_buffer = &state->payload_hash;

    AWS_ASSERT(payload_hash_buffer->len == 0);

    struct aws_byte_buf digest_buffer = aws_byte_buf_from_c_str("UNSIGNED-PAYLOAD");
    struct aws_byte_buf body_buffer;
    AWS_ZERO_STRUCT(body_buffer);
    struct aws_hash *hash = NULL;

    int result = AWS_OP_ERR;
    if (state->config.body_signing_type != AWS_BODY_SIGNING_UNSIGNED_PAYLOAD) {
        hash = aws_sha256_new(allocator);
        AWS_ZERO_STRUCT(digest_buffer);

        if (hash == NULL) {
            return AWS_OP_ERR;
        }

        if (aws_byte_buf_init(&body_buffer, allocator, BODY_READ_BUFFER_SIZE) ||
            aws_byte_buf_init(&digest_buffer, allocator, AWS_SHA256_LEN)) {
            goto on_cleanup;
        }

        struct aws_input_stream *payload_stream = NULL;
        if (aws_signable_get_payload_stream(signable, &payload_stream)) {
            goto on_cleanup;
        }

        if (payload_stream != NULL && state->config.body_signing_type == AWS_BODY_SIGNING_ON) {
            if (aws_input_stream_seek(payload_stream, 0, AWS_SSB_BEGIN)) {
                goto on_cleanup;
            }

            struct aws_stream_status payload_status;
            AWS_ZERO_STRUCT(payload_status);

            while (!payload_status.is_end_of_stream) {
                /* reset the temporary body buffer; we can calculate the hash in window chunks */
                body_buffer.len = 0;
                aws_input_stream_read(payload_stream, &body_buffer);
                if (body_buffer.len > 0) {
                    struct aws_byte_cursor body_cursor = aws_byte_cursor_from_buf(&body_buffer);
                    aws_hash_update(hash, &body_cursor);
                }

                if (aws_input_stream_get_status(payload_stream, &payload_status)) {
                    goto on_cleanup;
                }
            }

            /* reset the input stream for sending */
            if (aws_input_stream_seek(payload_stream, 0, AWS_SSB_BEGIN)) {
                goto on_cleanup;
            }
        }

        if (aws_hash_finalize(hash, &digest_buffer, 0)) {
            goto on_cleanup;
        }
    }

    /*
     * cache the payload hash into the state
     */
    struct aws_byte_cursor digest_cursor = aws_byte_cursor_from_buf(&digest_buffer);
    if (state->config.body_signing_type != AWS_BODY_SIGNING_UNSIGNED_PAYLOAD) {
        if (aws_hex_encode_append_dynamic(&digest_cursor, payload_hash_buffer)) {
            goto on_cleanup;
        }
    } else {
        if (aws_byte_buf_append_dynamic(payload_hash_buffer, &digest_cursor)) {
            goto on_cleanup;
        }
    }

    result = AWS_OP_SUCCESS;

on_cleanup:

    aws_byte_buf_clean_up(&digest_buffer);
    aws_byte_buf_clean_up(&body_buffer);

    if (hash) {
        aws_hash_destroy(hash);
    }

    return result;
}

/*
 * Copies the previously-computed payload hash into the canonical request buffer
 */
static int s_append_canonical_payload_hash(struct aws_signing_state_aws *state) {
    struct aws_byte_buf *canonical_request_buffer = &state->canonical_request;
    struct aws_byte_buf *payload_hash_buffer = &state->payload_hash;

    /*
     * Copy the hex-encoded payload hash into the canonical request
     */
    struct aws_byte_cursor payload_hash_cursor = aws_byte_cursor_from_buf(payload_hash_buffer);
    if (aws_byte_buf_append_dynamic(canonical_request_buffer, &payload_hash_cursor)) {
        return AWS_OP_ERR;
    }

    /*
     * Add the payload hash header to the result if necessary
     */
    if (s_is_header_auth(state->config.algorithm)) {
        struct aws_byte_cursor hashed_body_header_name = aws_byte_cursor_from_string(g_aws_signing_content_header_name);
        if (aws_signing_result_append_property_list(
                &state->result,
                g_aws_http_headers_property_list_name,
                &hashed_body_header_name,
                &payload_hash_cursor)) {
            return AWS_OP_ERR;
        }
    }

    /* Sigv4 spec claims a newline should be included after the payload, but the implementation doesn't do this */

    return AWS_OP_SUCCESS;
}

AWS_STATIC_STRING_FROM_LITERAL(s_credential_scope_sigv4_terminator, "aws4_request");

static int s_append_credential_scope_terminator(enum aws_signing_algorithm algorithm, struct aws_byte_buf *dest) {
    struct aws_byte_cursor terminator_cursor;

    switch (algorithm) {
        case AWS_SIGNING_ALGORITHM_SIG_V4_HEADER:
        case AWS_SIGNING_ALGORITHM_SIG_V4_QUERY_PARAM:
            terminator_cursor = aws_byte_cursor_from_string(s_credential_scope_sigv4_terminator);
            break;

        default:
            return aws_raise_error(AWS_AUTH_SIGNING_UNSUPPORTED_ALGORITHM);
    }

    return aws_byte_buf_append_dynamic(dest, &terminator_cursor);
}

/*
 * Builds the credential scope string by appending a bunch of things together:
 *   Date, region, service, algorithm terminator
 */
static int s_build_credential_scope(struct aws_signing_state_aws *state) {
    AWS_ASSERT(state->credential_scope.len == 0);

    const struct aws_signing_config_aws *config = &state->config;
    struct aws_byte_buf *dest = &state->credential_scope;

    /*
     * date output uses the non-dynamic append, so make sure there's enough room first
     */
    if (aws_byte_buf_reserve_relative(dest, AWS_DATE_TIME_STR_MAX_LEN)) {
        return AWS_OP_ERR;
    }

    if (aws_date_time_to_utc_time_short_str(&config->date, AWS_DATE_FORMAT_ISO_8601_BASIC, dest)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(dest, '/')) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append_dynamic(dest, &config->region)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(dest, '/')) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append_dynamic(dest, &config->service)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(dest, '/')) {
        return AWS_OP_ERR;
    }

    if (s_append_credential_scope_terminator(state->config.algorithm, dest)) {
        return AWS_OP_ERR;
    }

    /* While we're at it, build the accesskey/credential scope string which is used during query param signing*/
    struct aws_byte_cursor access_key_cursor = aws_byte_cursor_from_string(state->credentials->access_key_id);
    if (aws_byte_buf_append_dynamic(&state->access_credential_scope, &access_key_cursor)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(&state->access_credential_scope, '/')) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor credential_scope_cursor = aws_byte_cursor_from_buf(&state->credential_scope);
    if (aws_byte_buf_append_dynamic(&state->access_credential_scope, &credential_scope_cursor)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * Builds a sigv4-signed canonical request
 */
static int s_build_canonical_request_sigv4(struct aws_signing_state_aws *state) {
    AWS_ASSERT(state->canonical_request.len == 0);

    int result = AWS_OP_ERR;

    struct aws_uri uri;
    AWS_ZERO_STRUCT(uri);

    struct aws_byte_cursor uri_cursor;
    if (aws_signable_get_property(state->signable, g_aws_http_uri_property_name, &uri_cursor)) {
        return AWS_OP_ERR;
    }

    if (aws_uri_init_parse(&uri, state->allocator, &uri_cursor)) {
        goto cleanup;
    }

    if (aws_date_time_to_utc_time_str(&state->config.date, AWS_DATE_FORMAT_ISO_8601_BASIC, &state->date)) {
        goto cleanup;
    }

    if (s_build_canonical_payload_hash(state)) {
        goto cleanup;
    }

    if (s_build_canonical_headers(state)) {
        goto cleanup;
    }

    if (s_build_credential_scope(state)) {
        goto cleanup;
    }

    if (s_append_canonical_method(state)) {
        goto cleanup;
    }

    if (s_append_canonical_path(&uri, state)) {
        goto cleanup;
    }

    if (s_append_canonical_query_string(&uri, state)) {
        goto cleanup;
    }

    struct aws_byte_cursor header_block_cursor = aws_byte_cursor_from_buf(&state->canonical_header_block);
    if (aws_byte_buf_append_dynamic(&state->canonical_request, &header_block_cursor)) {
        goto cleanup;
    }

    if (s_append_canonical_payload_hash(state)) {
        goto cleanup;
    }

    result = AWS_OP_SUCCESS;

cleanup:

    aws_uri_clean_up(&uri);

    return result;
}

/*
 * Top-level canonical request construction function.  Dispatches based on requested
 * signing algorithm.
 */
int aws_signing_build_canonical_request(struct aws_signing_state_aws *state) {
    switch (state->config.algorithm) {
        case AWS_SIGNING_ALGORITHM_SIG_V4_HEADER:
        case AWS_SIGNING_ALGORITHM_SIG_V4_QUERY_PARAM:
            return s_build_canonical_request_sigv4(state);

        default:
            return aws_raise_error(AWS_AUTH_SIGNING_UNSUPPORTED_ALGORITHM);
    }
}

/*
 * String-to-sign utility functions
 */

/*
 * Hashes the canonical request and appends its hex representation to the
 * string-to-sign buffer in the signing state.
 */
static int s_append_canonical_request_hash(struct aws_signing_state_aws *state) {
    struct aws_allocator *allocator = state->allocator;
    struct aws_byte_buf *dest = &state->string_to_sign;

    int result = AWS_OP_ERR;

    struct aws_byte_buf digest_buffer;
    AWS_ZERO_STRUCT(digest_buffer);

    if (aws_byte_buf_init(&digest_buffer, allocator, AWS_SHA256_LEN)) {
        goto cleanup;
    }

    struct aws_byte_cursor canonical_request_cursor = aws_byte_cursor_from_buf(&state->canonical_request);
    if (aws_sha256_compute(allocator, &canonical_request_cursor, &digest_buffer, 0)) {
        goto cleanup;
    }

    struct aws_byte_cursor digest_cursor = aws_byte_cursor_from_buf(&digest_buffer);
    if (aws_hex_encode_append_dynamic(&digest_cursor, dest)) {
        goto cleanup;
    }

    result = AWS_OP_SUCCESS;

cleanup:
    aws_byte_buf_clean_up(&digest_buffer);

    return result;
}

/*
 * Builds the string-to-sign buffer for the sigv4 signing process.
 */
static int s_build_string_to_sign_4(struct aws_signing_state_aws *state) {
    /* We must have a canonical request.  We must not have the credential scope or the string to sign */
    AWS_ASSERT(state->canonical_request.len > 0);
    AWS_ASSERT(state->string_to_sign.len == 0);

    struct aws_byte_buf *dest = &state->string_to_sign;

    if (s_append_signing_algorithm(state->config.algorithm, dest)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(dest, '\n')) {
        return AWS_OP_ERR;
    }

    /*  date_time output uses raw array writes, so ensure there's enough room beforehand */
    if (aws_byte_buf_reserve_relative(dest, AWS_DATE_TIME_STR_MAX_LEN)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor date_cursor = aws_byte_cursor_from_buf(&state->date);
    if (aws_byte_buf_append_dynamic(dest, &date_cursor)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(dest, '\n')) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor credential_scope_cursor = aws_byte_cursor_from_buf(&state->credential_scope);
    if (aws_byte_buf_append_dynamic(dest, &credential_scope_cursor)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(dest, '\n')) {
        return AWS_OP_ERR;
    }

    if (s_append_canonical_request_hash(state)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * Top-level function for computing the string-to-sign in an AWS signing process.
 */
int aws_signing_build_string_to_sign(struct aws_signing_state_aws *state) {
    switch (state->config.algorithm) {
        case AWS_SIGNING_ALGORITHM_SIG_V4_HEADER:
        case AWS_SIGNING_ALGORITHM_SIG_V4_QUERY_PARAM:
            return s_build_string_to_sign_4(state);

        default:
            return aws_raise_error(AWS_AUTH_SIGNING_UNSUPPORTED_ALGORITHM);
    }
}

/*
 * Signature calculation utility functions
 */

AWS_STATIC_STRING_FROM_LITERAL(s_secret_key_prefix, "AWS4");

/*
 * Computes the key to sign with as a function of the secret access key in the credentials and
 *  the components of the credential scope: date, region, service, algorithm terminator
 */
static int s_compute_sigv4_signing_key(struct aws_signing_state_aws *state, struct aws_byte_buf *dest) {
    /* dest should be empty */
    AWS_ASSERT(dest->len == 0);

    const struct aws_signing_config_aws *config = &state->config;
    struct aws_allocator *allocator = state->allocator;

    int result = AWS_OP_ERR;

    struct aws_byte_buf secret_key;
    AWS_ZERO_STRUCT(secret_key);

    struct aws_byte_buf output;
    AWS_ZERO_STRUCT(output);

    struct aws_byte_buf date_buf;
    AWS_ZERO_STRUCT(date_buf);

    if (aws_byte_buf_init(
            &secret_key, allocator, s_secret_key_prefix->len + state->credentials->secret_access_key->len) ||
        aws_byte_buf_init(&output, allocator, AWS_SHA256_LEN) ||
        aws_byte_buf_init(&date_buf, allocator, AWS_DATE_TIME_STR_MAX_LEN)) {
        goto cleanup;
    }

    /*
     * Prep Key
     */
    struct aws_byte_cursor prefix_cursor = aws_byte_cursor_from_string(s_secret_key_prefix);
    struct aws_byte_cursor key_cursor = aws_byte_cursor_from_string(state->credentials->secret_access_key);
    if (aws_byte_buf_append_dynamic(&secret_key, &prefix_cursor) ||
        aws_byte_buf_append_dynamic(&secret_key, &key_cursor)) {
        goto cleanup;
    }

    /*
     * Prep date
     */
    if (aws_date_time_to_utc_time_short_str(&config->date, AWS_DATE_FORMAT_ISO_8601_BASIC, &date_buf)) {
        goto cleanup;
    }

    struct aws_byte_cursor date_cursor = aws_byte_cursor_from_buf(&date_buf);
    struct aws_byte_cursor secret_key_cursor = aws_byte_cursor_from_buf(&secret_key);
    if (aws_sha256_hmac_compute(allocator, &secret_key_cursor, &date_cursor, &output, 0)) {
        goto cleanup;
    }

    struct aws_byte_cursor chained_key_cursor = aws_byte_cursor_from_buf(&output);
    output.len = 0; /* necessary evil part 1*/
    if (aws_sha256_hmac_compute(allocator, &chained_key_cursor, &config->region, &output, 0)) {
        goto cleanup;
    }

    chained_key_cursor = aws_byte_cursor_from_buf(&output);
    output.len = 0; /* necessary evil part 2 */
    if (aws_sha256_hmac_compute(allocator, &chained_key_cursor, &config->service, &output, 0)) {
        goto cleanup;
    }

    chained_key_cursor = aws_byte_cursor_from_buf(&output);
    struct aws_byte_cursor scope_terminator_cursor = aws_byte_cursor_from_string(s_credential_scope_sigv4_terminator);
    if (aws_sha256_hmac_compute(allocator, &chained_key_cursor, &scope_terminator_cursor, dest, 0)) {
        goto cleanup;
    }

    result = AWS_OP_SUCCESS;

cleanup:
    aws_byte_buf_clean_up_secure(&secret_key);
    aws_byte_buf_clean_up(&output);
    aws_byte_buf_clean_up(&date_buf);

    return result;
}

/*
 * Appends a hex-encoding of the final signature value from the sigv4 signing process to a buffer
 */
static int s_append_sigv4_signature_value(struct aws_signing_state_aws *state, struct aws_byte_buf *dest) {
    struct aws_allocator *allocator = state->allocator;

    int result = AWS_OP_ERR;

    struct aws_byte_buf key;
    AWS_ZERO_STRUCT(key);

    struct aws_byte_buf digest;
    AWS_ZERO_STRUCT(digest);

    if (aws_byte_buf_init(&key, allocator, AWS_SHA256_LEN) || aws_byte_buf_init(&digest, allocator, AWS_SHA256_LEN)) {
        goto cleanup;
    }

    if (s_compute_sigv4_signing_key(state, &key)) {
        goto cleanup;
    }

    struct aws_byte_cursor key_cursor = aws_byte_cursor_from_buf(&key);
    struct aws_byte_cursor string_to_sign_cursor = aws_byte_cursor_from_buf(&state->string_to_sign);
    if (aws_sha256_hmac_compute(allocator, &key_cursor, &string_to_sign_cursor, &digest, 0)) {
        goto cleanup;
    }

    struct aws_byte_cursor digest_cursor = aws_byte_cursor_from_buf(&digest);
    if (aws_hex_encode_append_dynamic(&digest_cursor, dest)) {
        goto cleanup;
    }

    result = AWS_OP_SUCCESS;

cleanup:

    aws_byte_buf_clean_up(&key);
    aws_byte_buf_clean_up(&digest);

    return result;
}

/*
 * Appends a final signature value to a buffer based on the requested signing algorithm
 */
int s_append_signature_value(struct aws_signing_state_aws *state, struct aws_byte_buf *dest) {
    switch (state->config.algorithm) {
        case AWS_SIGNING_ALGORITHM_SIG_V4_HEADER:
        case AWS_SIGNING_ALGORITHM_SIG_V4_QUERY_PARAM:
            return s_append_sigv4_signature_value(state, dest);

        default:
            return aws_raise_error(AWS_AUTH_SIGNING_UNSUPPORTED_ALGORITHM);
    }
}

/*
 * Adds the appropriate authorization header or query param to the signing result
 */
static int s_add_authorization_to_result(
    struct aws_signing_state_aws *state,
    struct aws_byte_buf *authorization_value) {
    struct aws_byte_cursor name;
    struct aws_byte_cursor value = aws_byte_cursor_from_buf(authorization_value);

    if (s_is_header_auth(state->config.algorithm)) {
        name = aws_byte_cursor_from_string(g_aws_signing_authorization_header_name);
        return aws_signing_result_append_property_list(
            &state->result, g_aws_http_headers_property_list_name, &name, &value);
    }

    if (s_is_query_param_auth(state->config.algorithm)) {
        name = aws_byte_cursor_from_string(g_aws_signing_authorization_query_param_name);
        return aws_signing_result_append_property_list(
            &state->result, g_aws_http_query_params_property_list_name, &name, &value);
    }

    return AWS_OP_ERR;
}

AWS_STATIC_STRING_FROM_LITERAL(s_credential_prefix, " Credential=");
AWS_STATIC_STRING_FROM_LITERAL(s_signed_headers_prefix, ", SignedHeaders=");
AWS_STATIC_STRING_FROM_LITERAL(s_signature_prefix, ", Signature=");

/*
 * The Authorization has a lot more than just the final signature value in it.  This function appends all those
 * other values together ala:
 *
 * "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date,
 * Signature="
 *
 * The final header value is this with the signature value appended to the end.
 */
static int s_append_authorization_header_preamble(struct aws_signing_state_aws *state, struct aws_byte_buf *dest) {
    if (s_append_signing_algorithm(state->config.algorithm, dest)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor credential_cursor = aws_byte_cursor_from_string(s_credential_prefix);
    if (aws_byte_buf_append_dynamic(dest, &credential_cursor)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor access_key_cursor = aws_byte_cursor_from_string(state->credentials->access_key_id);
    if (aws_byte_buf_append_dynamic(dest, &access_key_cursor)) {
        return AWS_OP_ERR;
    }

    if (s_append_character_to_byte_buf(dest, '/')) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor credential_scope_cursor = aws_byte_cursor_from_buf(&state->credential_scope);
    if (aws_byte_buf_append_dynamic(dest, &credential_scope_cursor)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor signed_headers_prefix_cursor = aws_byte_cursor_from_string(s_signed_headers_prefix);
    if (aws_byte_buf_append_dynamic(dest, &signed_headers_prefix_cursor)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor signed_headers_cursor = aws_byte_cursor_from_buf(&state->signed_headers);
    if (aws_byte_buf_append_dynamic(dest, &signed_headers_cursor)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor signature_prefix_cursor = aws_byte_cursor_from_string(s_signature_prefix);
    if (aws_byte_buf_append_dynamic(dest, &signature_prefix_cursor)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * Top-level function for constructing the final authorization header/query-param and adding it to the
 * signing result.
 */
int aws_signing_build_authorization_value(struct aws_signing_state_aws *state) {
    AWS_ASSERT(state->string_to_sign.len > 0);
    AWS_ASSERT(state->credential_scope.len > 0);

    int result = AWS_OP_ERR;
    struct aws_byte_buf uri_encoded_buf;
    AWS_ZERO_STRUCT(uri_encoded_buf);

    struct aws_byte_buf authorization_value;

    if (aws_byte_buf_init(&authorization_value, state->allocator, AUTHORIZATION_VALUE_STARTING_SIZE)) {
        goto cleanup;
    }

    if (s_is_header_auth(state->config.algorithm) &&
        s_append_authorization_header_preamble(state, &authorization_value)) {
        goto cleanup;
    }

    if (s_append_signature_value(state, &authorization_value)) {
        goto cleanup;
    }

    if (s_add_authorization_to_result(state, &authorization_value)) {
        goto cleanup;
    }

    /*
     * Add X-Amz-Date to the signing result
     */
    struct aws_byte_cursor date_header_name = aws_byte_cursor_from_string(g_aws_signing_date_name);
    struct aws_byte_cursor date_header_value = aws_byte_cursor_from_buf(&state->date);
    if (aws_signing_result_append_property_list(
            &state->result, g_aws_http_headers_property_list_name, &date_header_name, &date_header_value)) {
        return AWS_OP_ERR;
    }

    /*
     * Add Security token to the signing result if a session token was present.
     */
    if (state->credentials->session_token) {
        struct aws_byte_cursor session_token_name = aws_byte_cursor_from_string(g_aws_signing_security_token_name);
        struct aws_byte_cursor session_token = aws_byte_cursor_from_string(state->credentials->session_token);

        const struct aws_string *property_list_name = g_aws_http_headers_property_list_name;

        /* if we're doing query signing, the session token goes in the query string (uri encoded), not the headers */
        if (s_is_query_param_auth(state->config.algorithm)) {
            property_list_name = g_aws_http_query_params_property_list_name;

            if (aws_byte_buf_init(&uri_encoded_buf, state->allocator, session_token.len)) {
                goto cleanup;
            }

            /* uri encode it */
            if (aws_byte_buf_append_encoding_uri_param(&uri_encoded_buf, &session_token)) {
                aws_byte_buf_clean_up(&uri_encoded_buf);
                goto cleanup;
            }

            session_token = aws_byte_cursor_from_buf(&uri_encoded_buf);
        }

        if (aws_signing_result_append_property_list(
                &state->result, property_list_name, &session_token_name, &session_token)) {
            goto cleanup;
        }
    }

    AWS_LOGF_INFO(
        AWS_LS_AUTH_SIGNING,
        "(id=%p) Http request successfully built final authorization value via algorithm %s, with contents \"" PRInSTR
        "\"",
        (void *)state->signable,
        aws_signing_algorithm_to_string(state->config.algorithm),
        AWS_BYTE_BUF_PRI(authorization_value));

    result = AWS_OP_SUCCESS;

cleanup:
    aws_byte_buf_clean_up(&uri_encoded_buf);
    aws_byte_buf_clean_up(&authorization_value);

    return result;
}
