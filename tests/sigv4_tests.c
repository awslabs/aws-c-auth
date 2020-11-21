/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/auth/credentials.h>
#include <aws/auth/private/aws_signing.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/common/condition_variable.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/file_utils.h>
#include <aws/io/stream.h>
#include <aws/io/uri.h>

#include <ctype.h>

#include "credentials_provider_utils.h"
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
    s_test_suite_session_token_1,
    "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267");
AWS_STATIC_STRING_FROM_LITERAL(
    s_test_suite_session_token_2,
    "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHG"
    "BuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1N"
    "tBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHN"
    "VXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9"
    "FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==");
AWS_STATIC_STRING_FROM_LITERAL(s_empty_token, "");

AWS_STATIC_STRING_FROM_LITERAL(s_test_suite_date, "2015-08-30T12:36:00Z");

static int s_initialize_test_from_contents(
    struct aws_signable **signable,
    struct aws_signing_config_aws *config,
    struct aws_allocator *allocator,
    struct sigv4_test_suite_contents *contents,
    bool ignore_date_header,
    bool omit_session_token) {

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

        if (aws_isspace(*current_line.ptr)) {
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

            /* usually we ignore X-Amz-Date header from .req file, and pass value in manually */
            struct aws_byte_cursor date_name_cursor = aws_byte_cursor_from_string(g_aws_signing_date_name);
            if (aws_byte_cursor_eq_ignore_case(&current_header.name, &date_name_cursor) && ignore_date_header) {
                continue;
            }

            /* ignore X-Amz-Security-Token header from .req file, we pass value in manually */
            struct aws_byte_cursor session_token_name = aws_byte_cursor_from_string(g_aws_signing_security_token_name);
            if (aws_byte_cursor_eq_ignore_case(&current_header.name, &session_token_name)) {
                continue;
            }

            aws_array_list_push_back(&contents->header_set, &current_header);
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

        contents->payload_stream = aws_input_stream_new_from_cursor(allocator, &body_cursor);
    }

    *signable = aws_signable_new_test(
        allocator,
        &method_cursor,
        &uri_cursor,
        (struct aws_signable_property_list_pair *)contents->header_set.data,
        aws_array_list_length(&contents->header_set),
        contents->payload_stream);

    config->config_type = AWS_SIGNING_CONFIG_AWS;
    config->algorithm = AWS_SIGNING_ALGORITHM_V4;
    config->signature_type = AWS_ST_HTTP_REQUEST_HEADERS;
    config->region = aws_byte_cursor_from_string(s_test_suite_region);
    config->service = aws_byte_cursor_from_string(s_test_suite_service);
    config->flags.use_double_uri_encode = true;
    config->flags.should_normalize_uri_path = true;
    config->flags.omit_session_token = omit_session_token;
    config->signed_body_header = AWS_SBHT_NONE;

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
    const char *parent_folder,
    bool omit_session_token) {

    if (s_sigv4_test_suite_contents_init_from_file_set(contents, allocator, parent_folder, test_name)) {
        return AWS_OP_ERR;
    }

    return s_initialize_test_from_contents(signable, config, allocator, contents, true, omit_session_token);
}

static int s_initialize_test_from_cursor(
    struct aws_signable **signable,
    struct aws_signing_config_aws *config,
    struct aws_allocator *allocator,
    struct sigv4_test_suite_contents *contents,
    const struct aws_byte_cursor *request_cursor,
    const struct aws_byte_cursor *expected_canonical_request_cursor,
    bool skip_date_header) {

    if (s_sigv4_test_suite_contents_init_from_cursor(
            contents, allocator, request_cursor, expected_canonical_request_cursor)) {
        return AWS_OP_ERR;
    }

    return s_initialize_test_from_contents(signable, config, allocator, contents, skip_date_header, false);
}

struct sigv4_signer_waiter {
    struct aws_mutex lock;
    struct aws_condition_variable cv;

    bool done;

    struct aws_signing_result result;
};

void s_sigv4_signer_waiter_clean_up(struct sigv4_signer_waiter *waiter) {
    aws_mutex_clean_up(&waiter->lock);
    aws_condition_variable_clean_up(&waiter->cv);

    aws_signing_result_clean_up(&waiter->result);
}

int s_sigv4_signer_waiter_init(struct sigv4_signer_waiter *waiter) {

    if (aws_mutex_init(&waiter->lock)) {
        goto error;
    }

    if (aws_condition_variable_init(&waiter->cv)) {
        goto error;
    }

    waiter->done = false;
    return AWS_OP_SUCCESS;

error:
    s_sigv4_signer_waiter_clean_up(waiter);
    return AWS_OP_ERR;
}

bool s_sigv4_signer_waiter_cv_pred(void *userdata) {
    struct sigv4_signer_waiter *waiter = userdata;
    return waiter->done;
}

void s_sigv4_signer_wait(struct sigv4_signer_waiter *waiter) {
    aws_mutex_lock(&waiter->lock);
    if (!waiter->done) {
        aws_condition_variable_wait_pred(&waiter->cv, &waiter->lock, s_sigv4_signer_waiter_cv_pred, waiter);
    }
    aws_mutex_unlock(&waiter->lock);
}

void s_sigv4_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {

    AWS_FATAL_ASSERT(error_code == AWS_ERROR_SUCCESS);

    struct sigv4_signer_waiter *waiter = userdata;

    /* Swap the result into the waiter */
    waiter->result.allocator = result->allocator;
    waiter->result.properties = result->properties;
    waiter->result.property_lists = result->property_lists;

    /* Make sure the parent stack frame doesn't clean these up */
    AWS_ZERO_STRUCT(result->properties);
    AWS_ZERO_STRUCT(result->property_lists);

    /* Mark results complete */
    aws_mutex_lock(&waiter->lock);
    waiter->done = true;
    aws_condition_variable_notify_one(&waiter->cv);
    aws_mutex_unlock(&waiter->lock);
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
    struct aws_credentials *credentials,
    bool omit_session_token) {

    /* Set up everything */
    aws_auth_library_init(allocator);

    struct sigv4_test_suite_contents test_contents;
    AWS_ZERO_STRUCT(test_contents);

    struct aws_signable *signable = NULL;

    struct aws_signing_config_aws config;
    AWS_ZERO_STRUCT(config);

    ASSERT_SUCCESS(s_initialize_test_from_file(
        &signable, &config, allocator, &test_contents, test_name, parent_folder, omit_session_token));

    ASSERT_NOT_NULL(credentials);
    config.credentials = credentials;

    /* Get constants and expected values */
    struct aws_byte_cursor expected_auth_header = aws_byte_cursor_from_buf(&test_contents.expected_auth_header);

    {
        struct aws_signing_state_aws *signing_state = aws_signing_state_new(allocator, &config, signable, NULL, NULL);
        ASSERT_NOT_NULL(signing_state);

        struct aws_signing_result *result = &signing_state->result;

        /* 1a - validate canonical request */
        ASSERT_TRUE(aws_signing_build_canonical_request(signing_state) == AWS_OP_SUCCESS);
        ASSERT_BIN_ARRAYS_EQUALS(
            test_contents.expected_canonical_request.buffer,
            test_contents.expected_canonical_request.len,
            signing_state->canonical_request.buffer,
            signing_state->canonical_request.len);

        /* 1b - validate string to sign */
        ASSERT_TRUE(aws_signing_build_string_to_sign(signing_state) == AWS_OP_SUCCESS);
        ASSERT_BIN_ARRAYS_EQUALS(
            test_contents.expected_string_to_sign.buffer,
            test_contents.expected_string_to_sign.len,
            signing_state->string_to_sign.buffer,
            signing_state->string_to_sign.len);

        /* 1c - validate authorization value */
        ASSERT_TRUE(aws_signing_build_authorization_value(signing_state) == AWS_OP_SUCCESS);

        struct aws_string *auth_header_value = NULL;
        aws_signing_result_get_property_value_in_property_list(
            result, g_aws_http_headers_property_list_name, g_aws_signing_authorization_header_name, &auth_header_value);

        ASSERT_BIN_ARRAYS_EQUALS(
            expected_auth_header.ptr, expected_auth_header.len, auth_header_value->bytes, auth_header_value->len);

        struct aws_byte_cursor session_token = aws_credentials_get_session_token(credentials);
        if (session_token.len > 0) {
            struct aws_string *session_header_value = NULL;
            aws_signing_result_get_property_value_in_property_list(
                result,
                g_aws_http_headers_property_list_name,
                g_aws_signing_security_token_name,
                &session_header_value);
            struct aws_byte_cursor expected_session_header = session_token;

            ASSERT_BIN_ARRAYS_EQUALS(
                expected_session_header.ptr,
                expected_session_header.len,
                session_header_value->bytes,
                session_header_value->len);
        }

        aws_signing_state_destroy(signing_state);
    }

    /* 2 - validate the public API */
    {
        struct sigv4_signer_waiter waiter;
        ASSERT_SUCCESS(s_sigv4_signer_waiter_init(&waiter));

        ASSERT_SUCCESS(aws_sign_request_aws(allocator, signable, (void *)&config, s_sigv4_signing_complete, &waiter));

        s_sigv4_signer_wait(&waiter);

        struct aws_string *auth_header_value = NULL;
        aws_signing_result_get_property_value_in_property_list(
            &waiter.result,
            g_aws_http_headers_property_list_name,
            g_aws_signing_authorization_header_name,
            &auth_header_value);

        ASSERT_BIN_ARRAYS_EQUALS(
            expected_auth_header.ptr, expected_auth_header.len, auth_header_value->bytes, auth_header_value->len);

        s_sigv4_signer_waiter_clean_up(&waiter);
    }

    /* 3 - sign via query param and check for expected query params.  We don't have an X-Amz-Signature value to check
     * though so just make sure it exists */
    {
        config.signature_type = AWS_ST_HTTP_REQUEST_QUERY_PARAMS;

        struct aws_signing_state_aws *signing_state = aws_signing_state_new(allocator, &config, signable, NULL, NULL);
        ASSERT_NOT_NULL(signing_state);

        struct aws_signing_result *result = &signing_state->result;

        ASSERT_NOT_NULL(signing_state);
        ASSERT_SUCCESS(aws_signing_build_canonical_request(signing_state));
        ASSERT_SUCCESS(aws_signing_build_string_to_sign(signing_state));
        ASSERT_SUCCESS(aws_signing_build_authorization_value(signing_state));

        struct aws_string *param_value = NULL;
        struct aws_byte_buf expected_value_uri_encoded;
        aws_byte_buf_init(&expected_value_uri_encoded, allocator, 256);

        /* This validation is fairly weak since we just check for equality against what was cached in the signing
         * state.  I'm not sure a redundant recalculation of the expected value for credential scope and signed headers
         * would have much value though.
         */
        aws_signing_result_get_property_value_in_property_list(
            result, g_aws_http_query_params_property_list_name, g_aws_signing_algorithm_query_param_name, &param_value);
        struct aws_byte_cursor unencoded_algorithm_param_cursor = aws_byte_cursor_from_c_str("AWS4-HMAC-SHA256");
        aws_byte_buf_append_encoding_uri_param(&expected_value_uri_encoded, &unencoded_algorithm_param_cursor);
        struct aws_byte_cursor expected_algorithm = aws_byte_cursor_from_buf(&expected_value_uri_encoded);
        ASSERT_BIN_ARRAYS_EQUALS(expected_algorithm.ptr, expected_algorithm.len, param_value->bytes, param_value->len);

        aws_signing_result_get_property_value_in_property_list(
            result,
            g_aws_http_query_params_property_list_name,
            g_aws_signing_credential_query_param_name,
            &param_value);
        struct aws_byte_cursor unencoded_credential_param_cursor =
            aws_byte_cursor_from_buf(&signing_state->access_credential_scope);
        expected_value_uri_encoded.len = 0;
        aws_byte_buf_append_encoding_uri_param(&expected_value_uri_encoded, &unencoded_credential_param_cursor);

        struct aws_byte_cursor expected_credential_param_value = aws_byte_cursor_from_buf(&expected_value_uri_encoded);
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_credential_param_value.ptr,
            expected_credential_param_value.len,
            param_value->bytes,
            param_value->len);

        aws_signing_result_get_property_value_in_property_list(
            result,
            g_aws_http_query_params_property_list_name,
            g_aws_signing_signed_headers_query_param_name,
            &param_value);
        struct aws_byte_cursor unencoded_signed_headers_param_cursor =
            aws_byte_cursor_from_buf(&signing_state->signed_headers);
        expected_value_uri_encoded.len = 0;
        aws_byte_buf_append_encoding_uri_param(&expected_value_uri_encoded, &unencoded_signed_headers_param_cursor);
        struct aws_byte_cursor expected_signed_headers = aws_byte_cursor_from_buf(&expected_value_uri_encoded);
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_signed_headers.ptr, expected_signed_headers.len, param_value->bytes, param_value->len);

        aws_signing_result_get_property_value_in_property_list(
            result,
            g_aws_http_query_params_property_list_name,
            g_aws_signing_authorization_query_param_name,
            &param_value);
        ASSERT_TRUE(param_value->len > 0); /* Is there at least something? */

        aws_byte_buf_clean_up(&expected_value_uri_encoded);

        aws_signing_state_destroy(signing_state);
    }

    /* 4 - sign via pre-computed canonical request */
    {
        struct sigv4_signer_waiter waiter;
        ASSERT_SUCCESS(s_sigv4_signer_waiter_init(&waiter));

        struct aws_signable *cr_signable = aws_signable_new_canonical_request(
            allocator, aws_byte_cursor_from_buf(&test_contents.expected_canonical_request));

        config.signature_type = AWS_ST_CANONICAL_REQUEST_HEADERS;
        ASSERT_SUCCESS(
            aws_sign_request_aws(allocator, cr_signable, (void *)&config, s_sigv4_signing_complete, &waiter));

        s_sigv4_signer_wait(&waiter);

        struct aws_string *auth_header_value = NULL;
        aws_signing_result_get_property_value_in_property_list(
            &waiter.result,
            g_aws_http_headers_property_list_name,
            g_aws_signing_authorization_header_name,
            &auth_header_value);
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_auth_header.ptr, expected_auth_header.len, auth_header_value->bytes, auth_header_value->len);

        s_sigv4_signer_waiter_clean_up(&waiter);

        aws_signable_destroy(cr_signable);
    }

    aws_credentials_provider_release(config.credentials_provider);
    s_sigv4_test_suite_contents_clean_up(&test_contents);
    aws_signable_destroy(signable);

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

#define DECLARE_SIGV4_TEST_SUITE_CASE(test_name, test_name_string)                                                     \
    static int s_sigv4_##test_name##_test(struct aws_allocator *allocator, void *ctx) {                                \
        (void)ctx;                                                                                                     \
        struct aws_credentials *credentials = aws_credentials_new_from_string(                                         \
            allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, s_empty_token, UINT64_MAX);         \
        int ret_val = s_do_sigv4_test_suite_test(allocator, test_name_string, ".", credentials, false);                \
        aws_credentials_release(credentials);                                                                          \
        return ret_val;                                                                                                \
    }                                                                                                                  \
    AWS_TEST_CASE(sigv4_##test_name##_test, s_sigv4_##test_name##_test);

#define DECLARE_SIGV4_TEST_SUITE_CASE_WITH_SESSION_TOKEN(                                                              \
    test_name, test_name_string, session_token, omit_session_token)                                                    \
    static int s_sigv4_##test_name##_test(struct aws_allocator *allocator, void *ctx) {                                \
        (void)ctx;                                                                                                     \
        struct aws_credentials *credentials = aws_credentials_new_from_string(                                         \
            allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, session_token, UINT64_MAX);         \
        int ret_val = s_do_sigv4_test_suite_test(allocator, test_name_string, ".", credentials, omit_session_token);   \
        aws_credentials_release(credentials);                                                                          \
        return ret_val;                                                                                                \
    }                                                                                                                  \
    AWS_TEST_CASE(sigv4_##test_name##_test, s_sigv4_##test_name##_test);

#define DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(test_name, test_name_string, parent_folder)                               \
    static int s_sigv4_##test_name##_test(struct aws_allocator *allocator, void *ctx) {                                \
        (void)ctx;                                                                                                     \
        struct aws_credentials *credentials = aws_credentials_new_from_string(                                         \
            allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, s_empty_token, UINT64_MAX);         \
        int ret_val = s_do_sigv4_test_suite_test(allocator, test_name_string, parent_folder, credentials, false);      \
        aws_credentials_release(credentials);                                                                          \
        return ret_val;                                                                                                \
    }                                                                                                                  \
    AWS_TEST_CASE(sigv4_##test_name##_test, s_sigv4_##test_name##_test);

#define DECLARE_NESTED_SIGV4_TEST_SUITE_CASE_WITH_SESSION_TOKEN(                                                       \
    test_name, test_name_string, parent_folder, session_token, omit_session_token)                                     \
    static int s_sigv4_##test_name##_test(struct aws_allocator *allocator, void *ctx) {                                \
        (void)ctx;                                                                                                     \
        struct aws_credentials *credentials = aws_credentials_new_from_string(                                         \
            allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, session_token, UINT64_MAX);         \
        int ret_val =                                                                                                  \
            s_do_sigv4_test_suite_test(allocator, test_name_string, parent_folder, credentials, omit_session_token);   \
        aws_credentials_release(credentials);                                                                          \
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
DECLARE_SIGV4_TEST_SUITE_CASE_WITH_SESSION_TOKEN(
    get_vanilla_with_session_token,
    "get-vanilla-with-session-token",
    s_test_suite_session_token_1,
    false);
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_empty_query_key, "get-vanilla-empty-query-key");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_query, "get-vanilla-query");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_query_order_key_case, "get-vanilla-query-order-key-case");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_query_order_encoded, "get-vanilla-query-order-encoded");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_unreserved, "get-vanilla-query-unreserved");
DECLARE_SIGV4_TEST_SUITE_CASE(get_vanilla_utf8_query, "get-vanilla-utf8-query");

DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_relative, "get-relative", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_relative_relative, "get-relative-relative", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_slash, "get-slash", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_slash_dot_slash, "get-slash-dot-slash", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_slash_pointless_dot, "get-slash-pointless-dot", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_slashes, "get-slashes", "normalize-path");
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE(get_space, "get-space", "normalize-path");

DECLARE_NESTED_SIGV4_TEST_SUITE_CASE_WITH_SESSION_TOKEN(
    post_sts_header_after,
    "post-sts-header-after",
    "post-sts-token",
    s_test_suite_session_token_2,
    true);
DECLARE_NESTED_SIGV4_TEST_SUITE_CASE_WITH_SESSION_TOKEN(
    post_sts_header_before,
    "post-sts-header-before",
    "post-sts-token",
    s_test_suite_session_token_2,
    false);

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
            &signable, &config, allocator, &test_contents, &request_cursor, &expected_canonical_request_cursor, true) ==
        AWS_OP_SUCCESS);

    config.should_sign_header = should_sign;

    struct aws_credentials *credentials = aws_credentials_new_from_string(
        allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, NULL, UINT64_MAX);
    ASSERT_NOT_NULL(credentials);

    config.credentials = credentials;

    struct aws_signing_state_aws *signing_state = aws_signing_state_new(allocator, &config, signable, NULL, NULL);
    ASSERT_NOT_NULL(signing_state);

    ASSERT_SUCCESS(aws_signing_build_canonical_request(signing_state));

    ASSERT_BIN_ARRAYS_EQUALS(
        test_contents.expected_canonical_request.buffer,
        test_contents.expected_canonical_request.len,
        signing_state->canonical_request.buffer,
        signing_state->canonical_request.len);

    aws_credentials_provider_release(config.credentials_provider);

    aws_signing_state_destroy(signing_state);
    s_sigv4_test_suite_contents_clean_up(&test_contents);
    aws_credentials_release(credentials);
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
    "User-agent:c sdk v1.0\n"
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

static bool s_should_sign_header(const struct aws_byte_cursor *name, void *userdata) {
    (void)userdata;

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

static int s_do_forbidden_header_param_test(
    struct aws_allocator *allocator,
    const struct aws_string *request_contents,
    enum aws_auth_errors expected_error) {

    aws_auth_library_init(allocator);

    struct sigv4_test_suite_contents test_contents;
    AWS_ZERO_STRUCT(test_contents);

    struct aws_signable *signable = NULL;

    struct aws_signing_config_aws config;
    AWS_ZERO_STRUCT(config);

    struct aws_byte_cursor request_cursor = aws_byte_cursor_from_string(request_contents);

    ASSERT_TRUE(
        s_initialize_test_from_cursor(&signable, &config, allocator, &test_contents, &request_cursor, NULL, false) ==
        AWS_OP_SUCCESS);

    struct aws_credentials *credentials = aws_credentials_new_from_string(
        allocator, s_test_suite_access_key_id, s_test_suite_secret_access_key, NULL, UINT64_MAX);
    ASSERT_NOT_NULL(credentials);

    config.credentials = credentials;

    struct aws_signing_state_aws *signing_state = aws_signing_state_new(allocator, &config, signable, NULL, NULL);
    ASSERT_NOT_NULL(signing_state);

    ASSERT_FAILS(aws_signing_build_canonical_request(signing_state));
    ASSERT_TRUE(aws_last_error() == expected_error);

    aws_signing_state_destroy(signing_state);
    aws_credentials_provider_release(config.credentials_provider);
    s_sigv4_test_suite_contents_clean_up(&test_contents);
    aws_credentials_release(credentials);
    aws_signable_destroy(signable);

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_STATIC_STRING_FROM_LITERAL(
    s_amz_date_header_request,
    "GET / HTTP/1.1\n"
    "Host:example.amazonaws.com\n"
    "X-Amz-Date:20150830T123600Z");

static int s_sigv4_fail_date_header_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_forbidden_header_param_test(
        allocator, s_amz_date_header_request, AWS_AUTH_SIGNING_ILLEGAL_REQUEST_HEADER);
}
AWS_TEST_CASE(sigv4_fail_date_header_test, s_sigv4_fail_date_header_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_amz_content_sha256_header_request,
    "GET / HTTP/1.1\n"
    "Host:example.amazonaws.com\n"
    "x-amz-content-sha256:lieslieslies");

static int s_sigv4_fail_content_header_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_forbidden_header_param_test(
        allocator, s_amz_content_sha256_header_request, AWS_AUTH_SIGNING_ILLEGAL_REQUEST_HEADER);
}
AWS_TEST_CASE(sigv4_fail_content_header_test, s_sigv4_fail_content_header_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_authorization_header_request,
    "GET / HTTP/1.1\n"
    "Host:example.amazonaws.com\n"
    "Authorization:lieslieslies");

static int s_sigv4_fail_authorization_header_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_forbidden_header_param_test(
        allocator, s_authorization_header_request, AWS_AUTH_SIGNING_ILLEGAL_REQUEST_HEADER);
}
AWS_TEST_CASE(sigv4_fail_authorization_header_test, s_sigv4_fail_authorization_header_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_amz_signature_param_request,
    "GET /?X-Amz-Signature=Something HTTP/1.1\n"
    "Host:example.amazonaws.com\n");

static int s_sigv4_fail_signature_param_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_forbidden_header_param_test(
        allocator, s_amz_signature_param_request, AWS_AUTH_SIGNING_ILLEGAL_REQUEST_QUERY_PARAM);
}
AWS_TEST_CASE(sigv4_fail_signature_param_test, s_sigv4_fail_signature_param_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_amz_date_param_request,
    "GET /?X-Amz-Date=Tomorrow HTTP/1.1\n"
    "Host:example.amazonaws.com\n");

static int s_sigv4_fail_date_param_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_forbidden_header_param_test(
        allocator, s_amz_date_param_request, AWS_AUTH_SIGNING_ILLEGAL_REQUEST_QUERY_PARAM);
}
AWS_TEST_CASE(sigv4_fail_date_param_test, s_sigv4_fail_date_param_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_amz_credential_param_request,
    "GET /?X-Amz-Credential=TopSekrit HTTP/1.1\n"
    "Host:example.amazonaws.com\n");

static int s_sigv4_fail_credential_param_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_forbidden_header_param_test(
        allocator, s_amz_credential_param_request, AWS_AUTH_SIGNING_ILLEGAL_REQUEST_QUERY_PARAM);
}
AWS_TEST_CASE(sigv4_fail_credential_param_test, s_sigv4_fail_credential_param_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_amz_algorithm_param_request,
    "GET /?X-Amz-Algorithm=BubbleSort HTTP/1.1\n"
    "Host:example.amazonaws.com\n");

static int s_sigv4_fail_algorithm_param_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_forbidden_header_param_test(
        allocator, s_amz_algorithm_param_request, AWS_AUTH_SIGNING_ILLEGAL_REQUEST_QUERY_PARAM);
}
AWS_TEST_CASE(sigv4_fail_algorithm_param_test, s_sigv4_fail_algorithm_param_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_amz_signed_headers_param_request,
    "GET /?X-Amz-SignedHeaders=User-Agent HTTP/1.1\n"
    "Host:example.amazonaws.com\n");

static int s_sigv4_fail_signed_headers_param_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_do_forbidden_header_param_test(
        allocator, s_amz_signed_headers_param_request, AWS_AUTH_SIGNING_ILLEGAL_REQUEST_QUERY_PARAM);
}
AWS_TEST_CASE(sigv4_fail_signed_headers_param_test, s_sigv4_fail_signed_headers_param_test);

struct null_credentials_state {
    struct aws_signing_result *result;
    int error_code;
};

static void s_null_credentials_on_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {

    struct null_credentials_state *state = userdata;
    state->result = result;
    state->error_code = error_code;
}

static int s_signer_null_credentials_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct get_credentials_mock_result results = {
        .credentials = NULL,
        .error_code = AWS_AUTH_SIGNING_NO_CREDENTIALS,
    };

    struct aws_http_message *request = aws_http_message_new_request(allocator);
    struct aws_signable *signable = aws_signable_new_http_request(allocator, request);

    struct aws_signing_config_aws config = {
        .config_type = AWS_SIGNING_CONFIG_AWS,
        .algorithm = AWS_SIGNING_ALGORITHM_V4,
        .signature_type = AWS_ST_HTTP_REQUEST_HEADERS,
        .region = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("us-east-1"),
        .service = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("elasticdohickeyservice"),
    };
    config.credentials_provider = aws_credentials_provider_new_mock(allocator, &results, 1, NULL);
    aws_date_time_init_now(&config.date);

    struct null_credentials_state state;
    AWS_ZERO_STRUCT(state);

    ASSERT_SUCCESS(aws_sign_request_aws(
        allocator,
        signable,
        (struct aws_signing_config_base *)&config,
        s_null_credentials_on_signing_complete,
        &state));

    ASSERT_PTR_EQUALS(NULL, state.result);
    ASSERT_INT_EQUALS(AWS_AUTH_SIGNING_NO_CREDENTIALS, state.error_code);

    aws_credentials_provider_release(config.credentials_provider);
    aws_signable_destroy(signable);
    aws_http_message_release(request);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(signer_null_credentials_test, s_signer_null_credentials_test);
