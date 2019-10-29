/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/testing/aws_test_harness.h>

#include <aws/auth/credentials.h>
#include <aws/auth/private/aws_signing.h>
#include <aws/auth/signable.h>
#include <aws/auth/signer.h>
#include <aws/common/string.h>
#include <aws/io/file_utils.h>
#include <aws/io/stream.h>
#include <aws/io/uri.h>

#include <ctype.h>

#include "test_signable.h"

struct sigv4_test_suite_contents {
    struct aws_allocator *allocator;
    struct aws_byte_buf request;
    struct aws_byte_buf expected_canonical_request;
    struct aws_byte_buf expected_string_to_sign;
    struct aws_byte_buf expected_signed_request;
    struct aws_byte_buf expected_auth_header;
    struct aws_input_stream *payload_stream;
    struct aws_array_list header_set;
};

static int s_load_test_suite_file(
    struct aws_allocator *allocator,
    const char *parent_folder,
    const char *test_name,
    const char *file_suffix,
    struct aws_byte_buf *file_contents) {
    char path[1024];
    snprintf(path, AWS_ARRAY_SIZE(path), "./%s/%s/%s.%s", parent_folder, test_name, test_name, file_suffix);

    return aws_byte_buf_init_from_file(file_contents, allocator, path);
}

static int s_sigv4_test_suite_contents_init_from_file_set(
    struct sigv4_test_suite_contents *contents,
    struct aws_allocator *allocator,
    const char *parent_folder,
    const char *test_name) {

    AWS_ZERO_STRUCT(*contents);
    contents->allocator = allocator;

    if (s_load_test_suite_file(allocator, parent_folder, test_name, "req", &contents->request) ||
        s_load_test_suite_file(allocator, parent_folder, test_name, "creq", &contents->expected_canonical_request) ||
        s_load_test_suite_file(allocator, parent_folder, test_name, "sts", &contents->expected_string_to_sign) ||
        s_load_test_suite_file(allocator, parent_folder, test_name, "sreq", &contents->expected_signed_request) ||
        s_load_test_suite_file(allocator, parent_folder, test_name, "authz", &contents->expected_auth_header)) {
        return AWS_OP_ERR;
    }

    if (aws_array_list_init_dynamic(
            &contents->header_set, allocator, 10, sizeof(struct aws_signable_property_list_pair))) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_sigv4_test_suite_contents_init_from_cursor(
    struct sigv4_test_suite_contents *contents,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *request_cursor,
    const struct aws_byte_cursor *expected_canonical_request_cursor) {

    AWS_ZERO_STRUCT(*contents);
    contents->allocator = allocator;

    if ((request_cursor && aws_byte_buf_init_copy_from_cursor(&contents->request, allocator, *request_cursor)) ||
        (expected_canonical_request_cursor &&
         aws_byte_buf_init_copy_from_cursor(
             &contents->expected_canonical_request, allocator, *expected_canonical_request_cursor))) {
        return AWS_OP_ERR;
    }

    if (aws_array_list_init_dynamic(
            &contents->header_set, allocator, 10, sizeof(struct aws_signable_property_list_pair))) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_sigv4_test_suite_contents_clean_up(struct sigv4_test_suite_contents *contents) {
    if (contents->allocator) {
        aws_byte_buf_clean_up(&contents->request);
        aws_byte_buf_clean_up(&contents->expected_canonical_request);
        aws_byte_buf_clean_up(&contents->expected_string_to_sign);
        aws_byte_buf_clean_up(&contents->expected_signed_request);
        aws_byte_buf_clean_up(&contents->expected_auth_header);

        aws_array_list_clean_up(&contents->header_set);

        aws_input_stream_destroy(contents->payload_stream);

        contents->allocator = NULL;
    }
}

AWS_STATIC_STRING_FROM_LITERAL(s_test_suite_service, "service");
AWS_STATIC_STRING_FROM_LITERAL(s_test_suite_region, "us-east-1");
AWS_STATIC_STRING_FROM_LITERAL(s_test_suite_access_key_id, "AKIDEXAMPLE");
AWS_STATIC_STRING_FROM_LITERAL(s_test_suite_secret_access_key, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
AWS_STATIC_STRING_FROM_LITERAL(
    s_test_suite_session_token,
    "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267");

AWS_STATIC_STRING_FROM_LITERAL(s_test_suite_date, "2015-08-30T12:36:00Z");

static int s_initialize_test_from_contents(
    struct aws_signable **signable,
    struct aws_signing_config_aws *config,
    struct aws_allocator *allocator,
    struct sigv4_test_suite_contents *contents) {

    struct aws_array_list request_lines;
    if (aws_array_list_init_dynamic(&request_lines, allocator, 10, sizeof(struct aws_byte_cursor))) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor request_cursor = aws_byte_cursor_from_buf(&contents->request);
    if (aws_byte_cursor_split_on_char(&request_cursor, '\n', &request_lines)) {
        return AWS_OP_ERR;
    }

    size_t line_count = aws_array_list_length(&request_lines);
    if (line_count == 0) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor first_line;
    AWS_ZERO_STRUCT(first_line);
    if (aws_array_list_get_at(&request_lines, &first_line, 0)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor method_cursor;
    AWS_ZERO_STRUCT(method_cursor);
    if (!aws_byte_cursor_next_split(&first_line, ' ', &method_cursor)) {
        return AWS_OP_ERR;
    }

    aws_byte_cursor_advance(&first_line, method_cursor.len + 1);

    /* not safe in general, but all test cases end in " HTTP/1.1" */
    struct aws_byte_cursor uri_cursor = first_line;
    uri_cursor.len -= 9;

    /* headers */
    size_t line_index = 1;
    for (; line_index < line_count; ++line_index) {
        struct aws_byte_cursor current_line;
        AWS_ZERO_STRUCT(current_line);
        if (aws_array_list_get_at(&request_lines, &current_line, line_index)) {
            return AWS_OP_ERR;
        }

        if (current_line.len == 0) {
            /* empty line = end of headers */
            break;
        }

        if (isspace(*current_line.ptr)) {
            /* multi-line header, append the entire line to the most recent header's value */
            size_t current_header_count = aws_array_list_length(&contents->header_set);
            AWS_FATAL_ASSERT(current_header_count > 0);

            struct aws_signable_property_list_pair *current_header;
            if (aws_array_list_get_at_ptr(&contents->header_set, (void **)&current_header, current_header_count - 1)) {
                return AWS_OP_ERR;
            }

            current_header->value.len = (current_line.ptr + current_line.len) - current_header->value.ptr;
        } else {
            /* new header, parse it and add to the header set */
            struct aws_signable_property_list_pair current_header;
            AWS_ZERO_STRUCT(current_header);
            if (!aws_byte_cursor_next_split(&current_line, ':', &current_header.name)) {
                return AWS_OP_ERR;
            }

            aws_byte_cursor_advance(&current_line, current_header.name.len + 1);
            current_header.value = current_line;

            struct aws_byte_cursor date_name_cursor = aws_byte_cursor_from_string(g_aws_signing_date_name);
            if (!aws_byte_cursor_eq_ignore_case(&current_header.name, &date_name_cursor)) {
                aws_array_list_push_back(&contents->header_set, &current_header);
            }
        }
    }

    /* body */
    struct aws_byte_cursor body_cursor;
    AWS_ZERO_STRUCT(body_cursor);
    if (line_index + 1 < line_count) {
        if (aws_array_list_get_at(&request_lines, &body_cursor, line_index + 1)) {
            return AWS_OP_ERR;
        }

        /* body length is the end of the whole request (pointer) minus the start of the body pointer */
        body_cursor.len = (contents->request.buffer + contents->request.len - body_cursor.ptr);
    }

    contents->payload_stream = aws_input_stream_new_from_cursor(allocator, &body_cursor);

    *signable = aws_signable_new_test(
        allocator,
        &method_cursor,
        &uri_cursor,
        (struct aws_signable_property_list_pair *)contents->header_set.data,
        aws_array_list_length(&contents->header_set),
        contents->payload_stream);

    config->config_type = AWS_SIGNING_CONFIG_AWS;
    config->algorithm = AWS_SIGNING_ALGORITHM_SIG_V4_HEADER;
    config->region = aws_byte_cursor_from_string(s_test_suite_region);
    config->service = aws_byte_cursor_from_string(s_test_suite_service);
    config->use_double_uri_encode = true;
    config->should_normalize_uri_path = true;
    config->sign_body = false;

    struct aws_byte_cursor date_cursor = aws_byte_cursor_from_string(s_test_suite_date);
    if (aws_date_time_init_from_str_cursor(&config->date, &date_cursor, AWS_DATE_FORMAT_ISO_8601)) {
        return AWS_OP_ERR;
    }

    aws_array_list_clean_up(&request_lines);

    return AWS_OP_SUCCESS;
}

static int s_initialize_test_from_file(
    struct aws_signable **signable,
    struct aws_signing_config_aws *config,
    struct aws_allocator *allocator,
    struct sigv4_test_suite_contents *contents,
    const char *test_name,
    const char *parent_folder) {

    if (s_sigv4_test_suite_contents_init_from_file_set(contents, allocator, parent_folder, test_name)) {
        return AWS_OP_ERR;
    }

    return s_initialize_test_from_contents(signable, config, allocator, contents);
}

static int s_initialize_test_from_cursor(
    struct aws_signable **signable,
    struct aws_signing_config_aws *config,
    struct aws_allocator *allocator,
    struct sigv4_test_suite_contents *contents,
    const struct aws_byte_cursor *request_cursor,
    const struct aws_byte_cursor *expected_canonical_request_cursor) {

    if (s_sigv4_test_suite_contents_init_from_cursor(
            contents, allocator, request_cursor, expected_canonical_request_cursor)) {
        return AWS_OP_ERR;
    }

    return s_initialize_test_from_contents(signable, config, allocator, contents);
}

struct aws_byte_cursor s_get_value_from_result(
    const struct aws_array_list *pair_list,
    const struct aws_byte_cursor *name) {
    struct aws_byte_cursor result;
    AWS_ZERO_STRUCT(result);

    size_t pair_count = aws_array_list_length(pair_list);
    for (size_t i = 0; i < pair_count; ++i) {
        struct aws_signing_result_property pair;
        AWS_ZERO_STRUCT(pair);
        if (aws_array_list_get_at(pair_list, &pair, i)) {
            continue;
        }

        if (pair.name == NULL) {
            continue;
        }

        struct aws_byte_cursor pair_name_cursor = aws_byte_cursor_from_string(pair.name);
        if (aws_byte_cursor_eq_ignore_case(&pair_name_cursor, name)) {
            result = aws_byte_cursor_from_string(pair.value);
            break;
        }
    }

    return result;
}

/*
 * For each sig v4 test case:
 *   (1) Validate the expected results (via the private API) at each stage of the signing process:
 *      (a) Canonical Request
 *      (b) String To Sign
 *      (c) Authorization Header
 *   (2) Validate the expected results of the signing process by the public API
 */
static int s_do_sigv4_test_suite_test(
    struct aws_allocator *allocator,
    const char *test_name,
    const char *parent_folder,
    struct aws_credentials *credentials) {

    /* Set up everything */
    aws_auth_library_init(allocator);

    struct sigv4_test_suite_contents test_contents;
    AWS_ZERO_STRUCT(test_contents);

    struct aws_signable *signable = NULL;

    struct aws_signing_config_aws config;
    AWS_ZERO_STRUCT(config);

    ASSERT_TRUE(
        s_initialize_test_from_file(&signable, &config, allocator, &test_contents, test_name, parent_folder) ==
        AWS_OP_SUCCESS);

    struct aws_signing_result result;
    ASSERT_TRUE(aws_signing_result_init(&result, allocator) == AWS_OP_SUCCESS);

    struct aws_signing_state_aws signing_state;
    ASSERT_TRUE(aws_signing_state_init(&signing_state, allocator, &config, signable, &result) == AWS_OP_SUCCESS);

    ASSERT_TRUE(credentials != NULL);

    config.credentials = credentials;

    /* 1a - validate canonical request */
    ASSERT_TRUE(aws_signing_build_canonical_request(&signing_state) == AWS_OP_SUCCESS);
    ASSERT_BIN_ARRAYS_EQUALS(
        test_contents.expected_canonical_request.buffer,
        test_contents.expected_canonical_request.len,
        signing_state.canonical_request.buffer,
        signing_state.canonical_request.len);

    /* 1b - validate string to sign */
    ASSERT_TRUE(aws_signing_build_string_to_sign(&signing_state) == AWS_OP_SUCCESS);
    ASSERT_BIN_ARRAYS_EQUALS(
        test_contents.expected_string_to_sign.buffer,
        test_contents.expected_string_to_sign.len,
        signing_state.string_to_sign.buffer,
        signing_state.string_to_sign.len);

    /* 1c - validate authorization value */
    ASSERT_TRUE(aws_signing_build_authorization_value(&signing_state) == AWS_OP_SUCCESS);

    struct aws_byte_cursor auth_header_name = aws_byte_cursor_from_string(g_aws_signing_authorization_header_name);

    struct aws_array_list *headers = NULL;
    ASSERT_TRUE(
        aws_signing_result_get_property_list(&result, g_aws_http_headers_property_list_name, &headers) ==
        AWS_OP_SUCCESS);

    struct aws_byte_cursor auth_header_value = s_get_value_from_result(headers, &auth_header_name);
    struct aws_byte_cursor expected_auth_header = aws_byte_cursor_from_buf(&test_contents.expected_auth_header);
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_auth_header.ptr, expected_auth_header.len, auth_header_value.ptr, auth_header_value.len);

    /* 2 - validate the public API */
    struct aws_signer *signer = aws_signer_new_aws(allocator);

    aws_signing_result_clean_up(&result);
    ASSERT_TRUE(aws_signing_result_init(&result, allocator) == AWS_OP_SUCCESS);

    ASSERT_TRUE(aws_signer_sign_request(signer, signable, (void *)&config, &result) == AWS_OP_SUCCESS);

    ASSERT_TRUE(
        aws_signing_result_get_property_list(&result, g_aws_http_headers_property_list_name, &headers) ==
        AWS_OP_SUCCESS);

    struct aws_byte_cursor auth_header_value2 = s_get_value_from_result(headers, &auth_header_name);
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_auth_header.ptr, expected_auth_header.len, auth_header_value2.ptr, auth_header_value2.len);

    /* 3 - sign via query param and check for expected query params.  We don't have an X-Amz-Signature value to check
     * though so just make sure it exists */
    aws_signing_result_clean_up(&result);
    ASSERT_TRUE(aws_signing_result_init(&result, allocator) == AWS_OP_SUCCESS);

    config.algorithm = AWS_SIGNING_ALGORITHM_SIG_V4_QUERY_PARAM;

    aws_signing_state_clean_up(&signing_state);
    ASSERT_TRUE(aws_signing_state_init(&signing_state, allocator, &config, signable, &result) == AWS_OP_SUCCESS);
    ASSERT_TRUE(aws_signing_build_canonical_request(&signing_state) == AWS_OP_SUCCESS);
    ASSERT_TRUE(aws_signing_build_string_to_sign(&signing_state) == AWS_OP_SUCCESS);
    ASSERT_TRUE(aws_signing_build_authorization_value(&signing_state) == AWS_OP_SUCCESS);

    ASSERT_TRUE(aws_signer_sign_request(signer, signable, (void *)&config, &result) == AWS_OP_SUCCESS);

    struct aws_array_list *params = NULL;
    ASSERT_TRUE(
        aws_signing_result_get_property_list(&result, g_aws_http_query_params_property_list_name, &params) ==
        AWS_OP_SUCCESS);

    ASSERT_TRUE(params != NULL);

    struct aws_byte_cursor algorithm_query_param_name =
        aws_byte_cursor_from_string(g_aws_signing_algorithm_query_param_name);
    struct aws_byte_cursor credential_query_param_name =
        aws_byte_cursor_from_string(g_aws_signing_credential_query_param_name);
    struct aws_byte_cursor signed_headers_query_param_name =
        aws_byte_cursor_from_string(g_aws_signing_signed_headers_query_param_name);
    struct aws_byte_cursor auth_query_param_name =
        aws_byte_cursor_from_string(g_aws_signing_authorization_query_param_name);

    struct aws_byte_cursor param_value;

    struct aws_byte_buf expected_value_uri_encoded;
    aws_byte_buf_init(&expected_value_uri_encoded, allocator, 256);

    /* This validation is fairly weak since we just check for equality against what was cached in the signing
     * state.  I'm not sure a redundant recalculation of the expected value for credential scope and signed headers
     * would have much value though.
     */
    param_value = s_get_value_from_result(params, &algorithm_query_param_name);
    struct aws_byte_cursor unencoded_algorithm_param_cursor = aws_byte_cursor_from_c_str("AWS4-HMAC-SHA256");
    aws_byte_buf_append_encoding_uri_param(&expected_value_uri_encoded, &unencoded_algorithm_param_cursor);
    struct aws_byte_cursor expected_algorithm = aws_byte_cursor_from_buf(&expected_value_uri_encoded);
    ASSERT_BIN_ARRAYS_EQUALS(expected_algorithm.ptr, expected_algorithm.len, param_value.ptr, param_value.len);

    param_value = s_get_value_from_result(params, &credential_query_param_name);
    struct aws_byte_cursor unencoded_credential_param_cursor =
        aws_byte_cursor_from_buf(&signing_state.access_credential_scope);
    expected_value_uri_encoded.len = 0;
    aws_byte_buf_append_encoding_uri_param(&expected_value_uri_encoded, &unencoded_credential_param_cursor);

    struct aws_byte_cursor expected_credential_param_value = aws_byte_cursor_from_buf(&expected_value_uri_encoded);
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_credential_param_value.ptr, expected_credential_param_value.len, param_value.ptr, param_value.len);

    param_value = s_get_value_from_result(params, &signed_headers_query_param_name);
    struct aws_byte_cursor unencoded_signed_headers_param_cursor =
        aws_byte_cursor_from_buf(&signing_state.signed_headers);
    expected_value_uri_encoded.len = 0;
    aws_byte_buf_append_encoding_uri_param(&expected_value_uri_encoded, &unencoded_signed_headers_param_cursor);
    struct aws_byte_cursor expected_signed_headers = aws_byte_cursor_from_buf(&expected_value_uri_encoded);
    ASSERT_BIN_ARRAYS_EQUALS(
        expected_signed_headers.ptr, expected_signed_headers.len, param_value.ptr, param_value.len);

    param_value = s_get_value_from_result(params, &auth_query_param_name);
    ASSERT_TRUE(param_value.len > 0); /* Is there are least something? */

    aws_byte_buf_clean_up(&expected_value_uri_encoded);
    aws_signing_state_clean_up(&signing_state);
    s_sigv4_test_suite_contents_clean_up(&test_contents);
    aws_signing_result_clean_up(&result);
    aws_signer_destroy(signer);
    aws_signable_destroy(signable);

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

#define DECLARE_SIGV4_TEST_SUITE_CASE(test_name, test_name_string)                                                     \
    static int s_sigv4_##test_name##_test(struct aws_allocator *allocator, void *ctx) {                                \
        (void)ctx;                                                                                                     \
        struct aws_credentials *credentials =                                                                          \
            aws_credentials_new(allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, NULL);          \
        int ret_val = s_do_sigv4_test_suite_test(allocator, test_name_string, ".", credentials);                       \
        aws_credentials_destroy(credentials);                                                                          \
        return ret_val;                                                                                                \
    }                                                                                                                  \
    AWS_TEST_CASE(sigv4_##test_name##_test, s_sigv4_##test_name##_test);

#define DECLARE_SIGV4_TEST_SUITE_CASE_WITH_SESSION_TOKEN(test_name, test_name_string)                                  \
    static int s_sigv4_##test_name##_test(struct aws_allocator *allocator, void *ctx) {                                \
        (void)ctx;                                                                                                     \
        struct aws_credentials *credentials = aws_credentials_new(                                                     \
            allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, s_test_suite_session_token);        \
        int ret_val = s_do_sigv4_test_suite_test(allocator, test_name_string, ".", credentials);                       \
        aws_credentials_destroy(credentials);                                                                          \
        return ret_val;                                                                                                \
    }                                                                                                                  \
    AWS_TEST_CASE(sigv4_##test_name##_test, s_sigv4_##test_name##_test);

#define DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(test_name, test_name_string, parent_folder)                               \
    static int s_sigv4_##test_name##_test(struct aws_allocator *allocator, void *ctx) {                                \
        (void)ctx;                                                                                                     \
        struct aws_credentials *credentials =                                                                          \
            aws_credentials_new(allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, NULL);          \
        int ret_val = s_do_sigv4_test_suite_test(allocator, test_name_string, parent_folder, credentials);             \
        aws_credentials_destroy(credentials);                                                                          \
        return ret_val;                                                                                                \
    }                                                                                                                  \
    AWS_TEST_CASE(sigv4_##test_name##_test, s_sigv4_##test_name##_test);

DECLARE_SIGV4_TEST_SUITE_CASE(get_header_key_duplicate, "get-header-key-duplicate");
DECLARE_SIGV4_TEST_SUITE_CASE(get_header_value_multiline, "get-header-value-multiline");
DECLARE_SIGV4_TEST_SUITE_CASE(get_header_value_order, "get-header-value-order");
DECLARE_SIGV4_TEST_SUITE_CASE(get_header_value_trim, "get-header-value-trim");
DECLARE_SIGV4_TEST_SUITE_CASE(get_unreserved, "get-unreserved");
DECLARE_SIGV4_TEST_SUITE_CASE(get_utf8, "get-utf8");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla, "get-vanilla");
DECLARE_SIGV4_TEST_SUITE_CASE_WITH_SESSION_TOKEN(get_vanilla_with_session_token, "get-vanilla-with-session-token");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_empty_query_key, "get-vanilla-empty-query-key");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_query, "get-vanilla-query");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_query_order_key_case, "get-vanilla-query-order-key-case");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_unreserved, "get-vanilla-query-unreserved");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_utf8_query, "get-vanilla-utf8-query");

DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_relative, "get-relative", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_relative_relative, "get-relative-relative", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_slash, "get-slash", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_slash_dot_slash, "get-slash-dot-slash", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_slash_pointless_dot, "get-slash-pointless-dot", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_slashes, "get-slashes", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_space, "get-space", "normalize-path");

DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(post_sts_header_after, "post-sts-header-after", "post-sts-token");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(post_sts_header_before, "post-sts-header-before", "post-sts-token");

DECLARE_SIGV4_TEST_SUITE_CASE(post_header_key_case, "post-header-key-case");
DECLARE_SIGV4_TEST_SUITE_CASE(post_header_key_sort, "post-header-key-sort");
DECLARE_SIGV4_TEST_SUITE_CASE(post_header_value_case, "post-header-value-case");
DECLARE_SIGV4_TEST_SUITE_CASE(post_vanilla, "post-vanilla");
DECLARE_SIGV4_TEST_SUITE_CASE(post_vanilla_empty_query_value, "post-vanilla-empty-query-value");
DECLARE_SIGV4_TEST_SUITE_CASE(post_vanilla_query, "post-vanilla-query");

DECLARE_SIGV4_TEST_SUITE_CASE(post_x_www_form_urlencoded, "post-x-www-form-urlencoded");
DECLARE_SIGV4_TEST_SUITE_CASE(post_x_www_form_urlencoded_parameters, "post-x-www-form-urlencoded-parameters");

static int s_do_header_skip_test(
    struct aws_allocator *allocator,
    aws_should_sign_header_fn *should_sign,
    const struct aws_string *request_contents,
    const struct aws_string *expected_canonical_request) {

    aws_auth_library_init(allocator);

    struct sigv4_test_suite_contents test_contents;
    AWS_ZERO_STRUCT(test_contents);

    struct aws_signable *signable = NULL;

    struct aws_signing_config_aws config;
    AWS_ZERO_STRUCT(config);

    struct aws_byte_cursor request_cursor = aws_byte_cursor_from_string(request_contents);
    struct aws_byte_cursor expected_canonical_request_cursor = aws_byte_cursor_from_string(expected_canonical_request);

    ASSERT_TRUE(
        s_initialize_test_from_cursor(
            &signable, &config, allocator, &test_contents, &request_cursor, &expected_canonical_request_cursor) ==
        AWS_OP_SUCCESS);

    config.should_sign_header = should_sign;

    struct aws_signing_result result;
    ASSERT_TRUE(aws_signing_result_init(&result, allocator) == AWS_OP_SUCCESS);

    struct aws_signing_state_aws signing_state;
    ASSERT_TRUE(aws_signing_state_init(&signing_state, allocator, &config, signable, &result) == AWS_OP_SUCCESS);

    struct aws_credentials *credentials =
        aws_credentials_new(allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, NULL);
    ASSERT_TRUE(credentials != NULL);

    config.credentials = credentials;

    ASSERT_TRUE(aws_signing_build_canonical_request(&signing_state) == AWS_OP_SUCCESS);

    ASSERT_BIN_ARRAYS_EQUALS(
        test_contents.expected_canonical_request.buffer,
        test_contents.expected_canonical_request.len,
        signing_state.canonical_request.buffer,
        signing_state.canonical_request.len);

    aws_signing_state_clean_up(&signing_state);
    s_sigv4_test_suite_contents_clean_up(&test_contents);
    aws_credentials_destroy(credentials);
    aws_signing_result_clean_up(&result);
    aws_signable_destroy(signable);

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_STATIC_STRING_FROM_LITERAL(
    s_skip_xray_header_request,
    "GET / HTTP/1.1\n"
    "Host:example.amazonaws.com\n"
    "x-amzn-trace-id:fsdbofdshfdsjkjhfs"
    "X-Amz-Date:20150830T123600Z");

AWS_STATIC_STRING_FROM_LITERAL(
    s_skip_xray_header_expected_canonical_request,
    "GET\n"
    "/\n"
    "\n"
    "host:example.amazonaws.com\n"
    "x-amz-date:20150830T123600Z\n"
    "\n"
    "host;x-amz-date\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

static int s_sigv4_skip_xray_header_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_header_skip_test(
        allocator, NULL, s_skip_xray_header_request, s_skip_xray_header_expected_canonical_request);
}
AWS_TEST_CASE(sigv4_skip_xray_header_test, s_sigv4_skip_xray_header_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_skip_user_agent_header_request,
    "GET / HTTP/1.1\n"
    "Useragent:c sdk v1.0\n"
    "Host:example.amazonaws.com\n"
    "X-Amz-Date:20150830T123600Z");

AWS_STATIC_STRING_FROM_LITERAL(
    s_skip_user_agent_header_expected_canonical_request,
    "GET\n"
    "/\n"
    "\n"
    "host:example.amazonaws.com\n"
    "x-amz-date:20150830T123600Z\n"
    "\n"
    "host;x-amz-date\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

static int s_sigv4_skip_user_agent_header_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_header_skip_test(
        allocator, NULL, s_skip_user_agent_header_request, s_skip_user_agent_header_expected_canonical_request);
}
AWS_TEST_CASE(sigv4_skip_user_agent_header_test, s_sigv4_skip_user_agent_header_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_skip_custom_header_request,
    "GET / HTTP/1.1\n"
    "MyHeader:Blahblah\n"
    "Host:example.amazonaws.com\n"
    "AnotherHeader:Oof\n"
    "X-Amz-Date:20150830T123600Z");

AWS_STATIC_STRING_FROM_LITERAL(
    s_skip_custom_header_expected_canonical_request,
    "GET\n"
    "/\n"
    "\n"
    "host:example.amazonaws.com\n"
    "x-amz-date:20150830T123600Z\n"
    "\n"
    "host;x-amz-date\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

static bool s_should_sign_header(const struct aws_byte_cursor *name) {
    struct aws_byte_cursor my_header_cursor = aws_byte_cursor_from_c_str("myheader");
    struct aws_byte_cursor another_header_cursor = aws_byte_cursor_from_c_str("anOtherHeader");

    if (aws_byte_cursor_eq_ignore_case(name, &my_header_cursor) ||
        aws_byte_cursor_eq_ignore_case(name, &another_header_cursor)) {
        return false;
    }

    return true;
}

static int s_sigv4_skip_custom_header_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_header_skip_test(
        allocator, s_should_sign_header, s_skip_custom_header_request, s_skip_custom_header_expected_canonical_request);
}
AWS_TEST_CASE(sigv4_skip_custom_header_test, s_sigv4_skip_custom_header_test);
