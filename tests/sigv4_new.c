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
#include <aws/auth/external/cJSON.h>
#include <aws/auth/private/aws_signing.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/cal/ecc.h>
#include <aws/cal/hash.h>
#include <aws/common/condition_variable.h>
#include <aws/common/encoding.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/file_utils.h>
#include <aws/io/pki_utils.h>
#include <aws/io/stream.h>
#include <aws/io/uri.h>

#include <ctype.h>

#include "credentials_provider_utils.h"
#include "test_signable.h"

AWS_STATIC_STRING_FROM_LITERAL(s_ecc_key_filename, "key.pem");
AWS_STATIC_STRING_FROM_LITERAL(s_header_canonical_request_filename, "header-canonical-request.txt");
AWS_STATIC_STRING_FROM_LITERAL(s_header_string_to_sign_filename, "header-string-to-sign.txt");
AWS_STATIC_STRING_FROM_LITERAL(s_header_signed_request_filename, "header-signed-request.txt");
AWS_STATIC_STRING_FROM_LITERAL(s_query_canonical_request_filename, "query-canonical-request.txt");
AWS_STATIC_STRING_FROM_LITERAL(s_query_string_to_sign_filename, "query-string-to-sign.txt");
AWS_STATIC_STRING_FROM_LITERAL(s_query_signed_request_filename, "query-signed-request.txt");

static const struct aws_string *s_get_canonical_request_filename(enum aws_signing_request_transform transform) {
    switch (transform) {
        case AWS_SRT_HEADER:
            return s_header_canonical_request_filename;
        case AWS_SRT_QUERY_PARAM:
            return s_query_canonical_request_filename;

        default:
            return NULL;
    }
}

static const struct aws_string *s_get_string_to_sign_filename(enum aws_signing_request_transform transform) {
    switch (transform) {
        case AWS_SRT_HEADER:
            return s_header_string_to_sign_filename;
        case AWS_SRT_QUERY_PARAM:
            return s_query_string_to_sign_filename;

        default:
            return NULL;
    }
}

static const struct aws_string *s_get_signed_request_filename(enum aws_signing_request_transform transform) {
    switch (transform) {
        case AWS_SRT_HEADER:
            return s_header_signed_request_filename;
        case AWS_SRT_QUERY_PARAM:
            return s_query_signed_request_filename;

        default:
            return NULL;
    }
}

struct v4a_test_case_contents {
    struct aws_allocator *allocator;
    struct aws_byte_buf context;
    struct aws_byte_buf request;
    struct aws_byte_buf key;
    struct aws_byte_buf expected_canonical_request;
    struct aws_byte_buf expected_string_to_sign;
    struct aws_byte_buf sample_signed_request;
};

static int s_load_test_case_file(
    struct aws_allocator *allocator,
    const char *parent_folder,
    const char *test_name,
    const char *filename,
    struct aws_byte_buf *buffer) {
    char path[1024];
    snprintf(path, AWS_ARRAY_SIZE(path), "./%s/%s/%s", parent_folder, test_name, filename);
    return aws_byte_buf_init_from_file(buffer, allocator, path);
}

static int s_v4a_test_case_context_init_from_file_set(
    struct v4a_test_case_contents *contents,
    struct aws_allocator *allocator,
    const char *parent_folder,
    const char *test_name,
    enum aws_signing_request_transform transform,
    bool missing_optional_files_is_failure) {

    AWS_ZERO_STRUCT(*contents);
    contents->allocator = allocator;

    /* required files */
    if (s_load_test_case_file(allocator, parent_folder, test_name, "request.txt", &contents->request) ||
        s_load_test_case_file(allocator, parent_folder, test_name, "context.json", &contents->context)) {
        return AWS_OP_ERR;
    }

    /* optional while we're still debugging/generating */
    if (s_load_test_case_file(
            allocator, parent_folder, test_name, aws_string_c_str(s_ecc_key_filename), &contents->key) ||
        s_load_test_case_file(
            allocator,
            parent_folder,
            test_name,
            aws_string_c_str(s_get_canonical_request_filename(transform)),
            &contents->expected_canonical_request) ||
        s_load_test_case_file(
            allocator,
            parent_folder,
            test_name,
            aws_string_c_str(s_get_string_to_sign_filename(transform)),
            &contents->expected_string_to_sign)) {

        if (missing_optional_files_is_failure) {
            return AWS_OP_ERR;
        }
    }

    /* optional until generation is finished */
    s_load_test_case_file(
        allocator,
        parent_folder,
        test_name,
        aws_string_c_str(s_get_signed_request_filename(transform)),
        &contents->sample_signed_request);

    return AWS_OP_SUCCESS;
}

static void s_v4a_test_case_contents_clean_up(struct v4a_test_case_contents *contents) {
    if (contents->allocator) {
        aws_byte_buf_clean_up(&contents->request);
        aws_byte_buf_clean_up(&contents->context);
        aws_byte_buf_clean_up(&contents->key);
        aws_byte_buf_clean_up(&contents->expected_canonical_request);
        aws_byte_buf_clean_up(&contents->expected_string_to_sign);
        aws_byte_buf_clean_up(&contents->sample_signed_request);

        contents->allocator = NULL;
    }
}

struct v4a_test_context {
    struct aws_allocator *allocator;
    struct v4a_test_case_contents test_case_data;

    struct aws_string *region_config;
    struct aws_string *service;
    struct aws_string *timestamp;
    struct aws_credentials *credentials;
    bool should_normalize;
    struct aws_input_stream *payload_stream;
    struct aws_ecc_key_pair *ecc_key;

    struct aws_signable *signable;
    struct aws_signing_config_aws *config;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    bool done;

    struct aws_signing_state_aws *signing_state;
    struct aws_http_message *request;

    bool should_generate_test_case;
};

static void s_v4a_test_context_clean_up(struct v4a_test_context *context) {
    s_v4a_test_case_contents_clean_up(&context->test_case_data);

    aws_http_message_release(context->request);
    aws_input_stream_destroy(context->payload_stream);
    aws_ecc_key_pair_release(context->ecc_key);

    aws_string_destroy(context->region_config);
    aws_string_destroy(context->service);
    aws_string_destroy(context->timestamp);
    aws_credentials_release(context->credentials);

    aws_mutex_clean_up(&context->lock);
    aws_condition_variable_clean_up(&context->signal);

    aws_signing_state_destroy(context->signing_state);

    aws_mem_release(context->allocator, context->config);
    aws_signable_destroy(context->signable);
}

AWS_STATIC_STRING_FROM_LITERAL(s_empty_empty_string, "\0");
AWS_STATIC_STRING_FROM_LITERAL(s_credentials_name, "credentials");
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_name, "access_key_id");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_name, "secret_access_key");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_name, "token");
AWS_STATIC_STRING_FROM_LITERAL(s_region_name, "region");
AWS_STATIC_STRING_FROM_LITERAL(s_service_name, "service");
AWS_STATIC_STRING_FROM_LITERAL(s_timestamp_name, "timestamp");
AWS_STATIC_STRING_FROM_LITERAL(s_normalize_name, "normalize");

static int s_v4a_test_context_parse_context_file(struct v4a_test_context *context) {
    struct aws_byte_buf *document = &context->test_case_data.context;
    cJSON *document_root = NULL;
    int result = AWS_OP_ERR;

    struct aws_byte_cursor null_terminator_cursor = aws_byte_cursor_from_string(s_empty_empty_string);
    if (aws_byte_buf_append_dynamic(document, &null_terminator_cursor)) {
        goto done;
    }

    document_root = cJSON_Parse((const char *)document->buffer);
    if (document_root == NULL) {
        goto done;
    }

    cJSON *credentials_node = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_credentials_name));
    if (credentials_node != NULL) {
        /*
         * Pull out the three credentials components
         */
        cJSON *access_key_id =
            cJSON_GetObjectItemCaseSensitive(credentials_node, aws_string_c_str(s_access_key_id_name));
        cJSON *secret_access_key =
            cJSON_GetObjectItemCaseSensitive(credentials_node, aws_string_c_str(s_secret_access_key_name));
        cJSON *session_token =
            cJSON_GetObjectItemCaseSensitive(credentials_node, aws_string_c_str(s_session_token_name));

        if (!cJSON_IsString(access_key_id) || (access_key_id->valuestring == NULL) ||
            !cJSON_IsString(secret_access_key) || (secret_access_key->valuestring == NULL)) {
            goto done;
        }

        struct aws_byte_cursor access_key_id_cursor = aws_byte_cursor_from_c_str(access_key_id->valuestring);
        struct aws_byte_cursor secret_access_key_cursor = aws_byte_cursor_from_c_str(secret_access_key->valuestring);
        struct aws_byte_cursor session_token_cursor = {};

        if (cJSON_IsString(session_token) && session_token->valuestring != NULL) {
            session_token_cursor = aws_byte_cursor_from_c_str(session_token->valuestring);
        }

        context->credentials = aws_credentials_new(
            context->allocator, access_key_id_cursor, secret_access_key_cursor, session_token_cursor, UINT64_MAX);
    }

    cJSON *region_node = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_region_name));
    if (region_node == NULL || !cJSON_IsString(region_node) || (region_node->valuestring == NULL)) {
        goto done;
    }

    context->region_config = aws_string_new_from_c_str(context->allocator, region_node->valuestring);
    if (context->region_config == NULL) {
        goto done;
    }

    cJSON *service_node = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_service_name));
    if (service_node == NULL || !cJSON_IsString(service_node) || (service_node->valuestring == NULL)) {
        goto done;
    }

    context->service = aws_string_new_from_c_str(context->allocator, service_node->valuestring);
    if (context->service == NULL) {
        goto done;
    }

    cJSON *timestamp_node = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_timestamp_name));
    if (timestamp_node == NULL || !cJSON_IsString(timestamp_node) || (timestamp_node->valuestring == NULL)) {
        goto done;
    }

    context->timestamp = aws_string_new_from_c_str(context->allocator, timestamp_node->valuestring);
    if (context->timestamp == NULL) {
        goto done;
    }

    cJSON *normalize_node = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_normalize_name));
    if (normalize_node == NULL || !cJSON_IsBool(normalize_node)) {
        goto done;
    }

    context->should_normalize = cJSON_IsTrue(normalize_node);

    result = AWS_OP_SUCCESS;

done:

    if (document_root != NULL) {
        cJSON_Delete(document_root);
    }

    return result;
}

static int s_v4a_test_context_parse_request(
    struct v4a_test_context *context,
    struct aws_byte_buf *request_buffer,
    bool skip_date_header,
    struct aws_http_message **out_request,
    struct aws_input_stream **out_body_stream) {
    int result = AWS_OP_ERR;

    *out_request = NULL;
    *out_body_stream = NULL;

    struct aws_array_list request_lines;
    AWS_ZERO_STRUCT(request_lines);
    if (aws_array_list_init_dynamic(&request_lines, context->allocator, 10, sizeof(struct aws_byte_cursor))) {
        return AWS_OP_ERR;
    }

    struct aws_array_list header_set;
    AWS_ZERO_STRUCT(header_set);
    if (aws_array_list_init_dynamic(
            &header_set, context->allocator, 10, sizeof(struct aws_signable_property_list_pair))) {
        goto done;
    }

    struct aws_input_stream *body_stream = NULL;
    struct aws_http_message *request = aws_http_message_new_request(context->allocator);
    if (request == NULL) {
        goto done;
    }

    struct aws_byte_cursor request_cursor = aws_byte_cursor_from_buf(request_buffer);
    if (aws_byte_cursor_split_on_char(&request_cursor, '\n', &request_lines)) {
        goto done;
    }

    size_t line_count = aws_array_list_length(&request_lines);
    if (line_count == 0) {
        goto done;
    }

    struct aws_byte_cursor first_line;
    AWS_ZERO_STRUCT(first_line);
    if (aws_array_list_get_at(&request_lines, &first_line, 0)) {
        goto done;
    }

    struct aws_byte_cursor method_cursor;
    AWS_ZERO_STRUCT(method_cursor);
    if (!aws_byte_cursor_next_split(&first_line, ' ', &method_cursor)) {
        goto done;
    }

    aws_http_message_set_request_method(request, method_cursor);

    aws_byte_cursor_advance(&first_line, method_cursor.len + 1);

    /* not safe in general, but all test cases end in " HTTP/1.1" */
    struct aws_byte_cursor uri_cursor = first_line;
    uri_cursor.len -= 9;

    aws_http_message_set_request_path(request, uri_cursor);

    /* headers */
    size_t line_index = 1;
    for (; line_index < line_count; ++line_index) {
        struct aws_byte_cursor current_line;
        AWS_ZERO_STRUCT(current_line);
        if (aws_array_list_get_at(&request_lines, &current_line, line_index)) {
            goto done;
        }

        if (current_line.len == 0) {
            /* empty line = end of headers */
            break;
        }

        if (isspace(*current_line.ptr)) {
            /* multi-line header, append the entire line to the most recent header's value */
            size_t current_header_count = aws_array_list_length(&header_set);
            AWS_FATAL_ASSERT(current_header_count > 0);

            struct aws_signable_property_list_pair *current_header;
            if (aws_array_list_get_at_ptr(&header_set, (void **)&current_header, current_header_count - 1)) {
                goto done;
            }

            current_header->value.len = (current_line.ptr + current_line.len) - current_header->value.ptr;
        } else {
            /* new header, parse it and add to the header set */
            struct aws_signable_property_list_pair current_header;
            AWS_ZERO_STRUCT(current_header);
            if (!aws_byte_cursor_next_split(&current_line, ':', &current_header.name)) {
                goto done;
            }

            aws_byte_cursor_advance(&current_line, current_header.name.len + 1);
            current_header.value = current_line;

            struct aws_byte_cursor date_name_cursor = aws_byte_cursor_from_string(g_aws_signing_date_name);
            if (!aws_byte_cursor_eq_ignore_case(&current_header.name, &date_name_cursor) || !skip_date_header) {
                aws_array_list_push_back(&header_set, &current_header);
            }
        }
    }

    size_t header_count = aws_array_list_length(&header_set);
    for (size_t i = 0; i < header_count; ++i) {
        struct aws_signable_property_list_pair property_header;
        aws_array_list_get_at(&header_set, &property_header, i);

        struct aws_http_header header = {
            .name = property_header.name,
            .value = property_header.value,
        };

        aws_http_message_add_header(request, header);
    }

    /* body */
    struct aws_byte_cursor body_cursor;
    AWS_ZERO_STRUCT(body_cursor);
    if (line_index + 1 < line_count) {
        if (aws_array_list_get_at(&request_lines, &body_cursor, line_index + 1)) {
            goto done;
        }

        /* body length is the end of the whole request (pointer) minus the start of the body pointer */
        body_cursor.len = (request_cursor.ptr + request_cursor.len - body_cursor.ptr);

        body_stream = aws_input_stream_new_from_cursor(context->allocator, &body_cursor);
        if (body_stream == NULL) {
            goto done;
        }

        aws_http_message_set_body_stream(request, body_stream);
    }

    result = AWS_OP_SUCCESS;

done:

    aws_array_list_clean_up(&request_lines);
    aws_array_list_clean_up(&header_set);

    if (result == AWS_OP_ERR) {
        aws_http_message_release(request);
        aws_input_stream_destroy(body_stream);
    } else {
        *out_request = request;
        *out_body_stream = body_stream;
    }

    return result;
}

static int s_v4a_test_context_init_signing_config(
    struct v4a_test_context *context,
    enum aws_signing_request_transform transform) {

    context->signable = aws_signable_new_http_request(context->allocator, context->request);

    context->config = aws_mem_calloc(context->allocator, 1, sizeof(struct aws_signing_config_aws));
    if (context->config == NULL) {
        return AWS_OP_ERR;
    }

    context->config->config_type = AWS_SIGNING_CONFIG_AWS;
    context->config->algorithm = AWS_SIGNING_ALGORITHM_V4_ASYMMETRIC;
    context->config->transform = transform;
    context->config->region_config = aws_byte_cursor_from_string(context->region_config);
    context->config->service = aws_byte_cursor_from_string(context->service);
    context->config->use_double_uri_encode = true;
    context->config->should_normalize_uri_path = context->should_normalize;
    context->config->body_signing_type = AWS_BODY_SIGNING_OFF;
    context->config->credentials = context->credentials;

    struct aws_byte_cursor date_cursor = aws_byte_cursor_from_string(context->timestamp);
    if (aws_date_time_init_from_str_cursor(&context->config->date, &date_cursor, AWS_DATE_FORMAT_ISO_8601)) {
        return AWS_OP_ERR;
    }

    context->signing_state = aws_signing_state_new(context->allocator, context->config, context->signable, NULL, NULL);
    if (context->signing_state == NULL) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_v4a_test_context_parse_key(struct v4a_test_context *context) {
    if (context->test_case_data.key.len == 0) {
        return AWS_OP_SUCCESS;
    }

    size_t section_count = 0;
    struct aws_array_list key_sections;
    AWS_ZERO_STRUCT(key_sections);
    if (aws_array_list_init_dynamic(&key_sections, context->allocator, 1, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    int result = AWS_OP_ERR;
    struct aws_byte_cursor pem_cursor =
        aws_byte_cursor_from_array(context->test_case_data.key.buffer, context->test_case_data.key.len);
    if (aws_decode_pem_to_buffer_list(context->allocator, &pem_cursor, &key_sections)) {
        goto done;
    }

    ASSERT_TRUE(aws_array_list_length(&key_sections) == 1);
    struct aws_byte_buf *key_buffer = NULL;
    aws_array_list_get_at_ptr(&key_sections, (void **)&key_buffer, 0);

    struct aws_byte_cursor key_cursor = aws_byte_cursor_from_array(key_buffer->buffer, key_buffer->len);
    context->ecc_key = aws_ecc_key_pair_new_from_asn1(context->allocator, &key_cursor);
    if (context->ecc_key == NULL) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    section_count = aws_array_list_length(&key_sections);
    for (size_t i = 0; i < section_count; ++i) {
        struct aws_byte_buf *buffer = NULL;
        aws_array_list_get_at_ptr(&key_sections, (void **)&buffer, 0);

        aws_byte_buf_clean_up(buffer);
    }

    aws_array_list_clean_up(&key_sections);

    return result;
}

AWS_STATIC_STRING_FROM_LITERAL(s_generate_test_env_var_name, "GENERATE_TEST_CASES");

static int s_v4a_test_context_init(
    struct v4a_test_context *context,
    struct aws_allocator *allocator,
    const char *parent_folder,
    const char *test_name,
    enum aws_signing_request_transform transform) {

    AWS_ZERO_STRUCT(*context);
    context->allocator = allocator;

    struct aws_string *should_generate = NULL;
    ASSERT_SUCCESS(aws_get_environment_value(allocator, s_generate_test_env_var_name, &should_generate));

    context->should_generate_test_case = should_generate != NULL;
    aws_string_destroy(should_generate);

    if (s_v4a_test_case_context_init_from_file_set(
            &context->test_case_data,
            allocator,
            parent_folder,
            test_name,
            transform,
            !context->should_generate_test_case)) {
        return AWS_OP_ERR;
    }

    if (s_v4a_test_context_parse_context_file(context)) {
        return AWS_OP_ERR;
    }

    if (s_v4a_test_context_parse_request(
            context, &context->test_case_data.request, true, &context->request, &context->payload_stream)) {
        return AWS_OP_ERR;
    }

    if (s_v4a_test_context_init_signing_config(context, transform)) {
        return AWS_OP_ERR;
    }

    if (s_v4a_test_context_parse_key(context)) {
        return AWS_OP_ERR;
    }

    if (aws_mutex_init(&context->lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&context->signal)) {
        return AWS_OP_ERR;
    }

    context->done = false;

    return AWS_OP_SUCCESS;
}

bool s_is_signing_complete_predicate(void *userdata) {
    struct v4a_test_context *context = userdata;
    return context->done;
}

void s_wait_on_signing_complete(struct v4a_test_context *context) {
    aws_mutex_lock(&context->lock);
    if (!context->done) {
        aws_condition_variable_wait_pred(&context->signal, &context->lock, s_is_signing_complete_predicate, context);
    }
    aws_mutex_unlock(&context->lock);
}

static void s_on_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {

    AWS_FATAL_ASSERT(error_code == AWS_ERROR_SUCCESS);

    struct v4a_test_context *context = userdata;

    aws_apply_signing_result_to_http_request(context->request, context->allocator, result);

    /* Mark results complete */
    aws_mutex_lock(&context->lock);
    context->done = true;
    aws_condition_variable_notify_one(&context->signal);
    aws_mutex_unlock(&context->lock);
}

static struct aws_byte_cursor s_get_value_from_result(
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

#define DEFAULT_BUFFER_SIZE 1024
#define BASE64_CHARS_PER_LINE 80

static int s_write_key_to_test_case_file(
    struct v4a_test_context *test_context,
    struct aws_ecc_key_pair *ecc_key,
    const char *parent_folder,
    const char *test_name) {
    int result = AWS_OP_ERR;

    FILE *fp = NULL;
    struct aws_byte_buf der_key_buffer;
    AWS_ZERO_STRUCT(der_key_buffer);
    struct aws_byte_buf base64_buffer;
    AWS_ZERO_STRUCT(base64_buffer);

    if (aws_byte_buf_init(&der_key_buffer, test_context->allocator, DEFAULT_BUFFER_SIZE)) {
        goto done;
    }

    if (aws_ecc_key_pair_append_asn1_encoding(ecc_key, &der_key_buffer)) {
        goto done;
    }

    size_t base64_length = 0;
    if (aws_base64_compute_encoded_len(der_key_buffer.len, &base64_length)) {
        goto done;
    }

    if (aws_byte_buf_init(&base64_buffer, test_context->allocator, base64_length)) {
        goto done;
    }

    struct aws_byte_cursor der_cursor = aws_byte_cursor_from_array(der_key_buffer.buffer, der_key_buffer.len);
    if (aws_base64_encode(&der_cursor, &base64_buffer)) {
        goto done;
    }

    char path[1024];
    snprintf(path, AWS_ARRAY_SIZE(path), "./%s/%s/%s", parent_folder, test_name, aws_string_c_str(s_ecc_key_filename));

    fp = fopen(path, "w");
    if (fp == NULL) {
        goto done;
    }

    fprintf(fp, "-----BEGIN EC PRIVATE KEY-----\n");
    struct aws_byte_cursor base64_cursor = aws_byte_cursor_from_array(base64_buffer.buffer, base64_buffer.len);
    while (base64_cursor.len > 0) {
        size_t to_write = base64_cursor.len;
        if (to_write > BASE64_CHARS_PER_LINE) {
            to_write = BASE64_CHARS_PER_LINE;
        }

        struct aws_byte_cursor line_cursor = {.ptr = base64_cursor.ptr, .len = to_write};
        fprintf(fp, PRInSTR "\n", AWS_BYTE_CURSOR_PRI(line_cursor));

        aws_byte_cursor_advance(&base64_cursor, to_write);
    }

    fprintf(fp, "-----END EC PRIVATE KEY-----\n");

    result = AWS_OP_SUCCESS;

done:

    fclose(fp);

    aws_byte_buf_clean_up(&der_key_buffer);
    aws_byte_buf_clean_up(&base64_buffer);

    return result;
}

static int s_check_derived_ecc_key(struct v4a_test_context *test_context, struct aws_ecc_key_pair *derived_ecc_key) {
    struct aws_byte_cursor derived_pub_x;
    AWS_ZERO_STRUCT(derived_pub_x);
    struct aws_byte_cursor derived_pub_y;
    AWS_ZERO_STRUCT(derived_pub_y);
    struct aws_byte_cursor derived_private_d;
    AWS_ZERO_STRUCT(derived_private_d);

    aws_ecc_key_pair_get_public_key(derived_ecc_key, &derived_pub_x, &derived_pub_y);
    aws_ecc_key_pair_get_private_key(derived_ecc_key, &derived_private_d);

    struct aws_byte_cursor pub_x;
    AWS_ZERO_STRUCT(pub_x);
    struct aws_byte_cursor pub_y;
    AWS_ZERO_STRUCT(pub_y);
    struct aws_byte_cursor private_d;
    AWS_ZERO_STRUCT(private_d);

    aws_ecc_key_pair_get_public_key(test_context->ecc_key, &pub_x, &pub_y);
    aws_ecc_key_pair_get_private_key(test_context->ecc_key, &private_d);

    ASSERT_BIN_ARRAYS_EQUALS(derived_pub_x.ptr, derived_pub_x.len, pub_x.ptr, pub_x.len);
    ASSERT_BIN_ARRAYS_EQUALS(derived_pub_y.ptr, derived_pub_y.len, pub_y.ptr, pub_y.len);
    ASSERT_BIN_ARRAYS_EQUALS(derived_private_d.ptr, derived_private_d.len, private_d.ptr, private_d.len);

    return AWS_OP_SUCCESS;
}

static int s_write_test_file(
    const char *parent_folder,
    const char *test_name,
    const struct aws_string *filename,
    const struct aws_byte_buf *contents) {
    char path[1024];
    snprintf(path, AWS_ARRAY_SIZE(path), "./%s/%s/%s", parent_folder, test_name, aws_string_c_str(filename));

    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(contents->buffer, contents->len);
    fprintf(fp, PRInSTR, AWS_BYTE_CURSOR_PRI(cursor));

    fclose(fp);

    return AWS_OP_SUCCESS;
}

static int s_validate_authorization_value(
    struct v4a_test_context *test_context,
    struct aws_byte_cursor string_to_sign_cursor,
    struct aws_byte_cursor signature_value_cursor) {

    size_t binary_length = 0;
    if (aws_hex_compute_decoded_len(signature_value_cursor.len, &binary_length)) {
        return AWS_OP_ERR;
    }

    int result = AWS_OP_ERR;

    struct aws_byte_buf binary_signature;
    AWS_ZERO_STRUCT(binary_signature);

    struct aws_byte_buf sha256_digest;
    AWS_ZERO_STRUCT(sha256_digest);

    if (aws_byte_buf_init(&binary_signature, test_context->allocator, binary_length) ||
        aws_byte_buf_init(&sha256_digest, test_context->allocator, AWS_SHA256_LEN)) {
        goto done;
    }

    if (aws_hex_decode(&signature_value_cursor, &binary_signature)) {
        goto done;
    }

    if (aws_sha256_compute(test_context->allocator, &string_to_sign_cursor, &sha256_digest, 0)) {
        goto done;
    }

    struct aws_byte_cursor binary_signature_cursor =
        aws_byte_cursor_from_array(binary_signature.buffer, binary_signature.len);
    struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&sha256_digest);
    ASSERT_SUCCESS(aws_ecc_key_pair_verify_signature(test_context->ecc_key, &message_cursor, &binary_signature_cursor));

    result = AWS_OP_SUCCESS;

done:

    aws_byte_buf_clean_up(&binary_signature);
    aws_byte_buf_clean_up(&sha256_digest);

    return result;
}

static int s_validate_internal_header_authorization(struct v4a_test_context *test_context) {

    struct aws_signing_state_aws *signing_state = test_context->signing_state;
    struct aws_array_list *headers = NULL;
    ASSERT_TRUE(
        aws_signing_result_get_property_list(&signing_state->result, g_aws_http_headers_property_list_name, &headers) ==
        AWS_OP_SUCCESS);

    struct aws_byte_cursor auth_header_name = aws_byte_cursor_from_string(g_aws_signing_authorization_header_name);
    struct aws_byte_cursor auth_header_value = s_get_value_from_result(headers, &auth_header_name);
    ASSERT_TRUE(auth_header_value.len > 0);

    struct aws_byte_cursor signature_key_cursor = aws_byte_cursor_from_c_str("Signature=");
    struct aws_byte_cursor signature_value_cursor;
    AWS_ZERO_STRUCT(signature_value_cursor);
    ASSERT_SUCCESS(aws_byte_cursor_find_exact(&auth_header_value, &signature_key_cursor, &signature_value_cursor));
    aws_byte_cursor_advance(&signature_value_cursor, signature_key_cursor.len);

    ASSERT_TRUE(signature_value_cursor.len > 0);

    return s_validate_authorization_value(
        test_context, aws_byte_cursor_from_buf(&test_context->signing_state->string_to_sign), signature_value_cursor);
}

static int s_validate_internal_query_authorization(struct v4a_test_context *test_context) {

    struct aws_signing_state_aws *signing_state = test_context->signing_state;
    struct aws_array_list *params = NULL;
    ASSERT_SUCCESS(aws_signing_result_get_property_list(
        &signing_state->result, g_aws_http_query_params_property_list_name, &params));
    ASSERT_NOT_NULL(params);

    struct aws_byte_cursor auth_query_param_name =
        aws_byte_cursor_from_string(g_aws_signing_authorization_query_param_name);

    struct aws_byte_cursor signature_value_cursor = s_get_value_from_result(params, &auth_query_param_name);
    ASSERT_TRUE(signature_value_cursor.len > 0); /* Is there are least something? */

    return s_validate_authorization_value(
        test_context, aws_byte_cursor_from_buf(&test_context->signing_state->string_to_sign), signature_value_cursor);
}

static int s_validate_internal_authorization(struct v4a_test_context *test_context) {
    switch (test_context->config->transform) {
        case AWS_SRT_HEADER:
            return s_validate_internal_header_authorization(test_context);

        case AWS_SRT_QUERY_PARAM:
            return s_validate_internal_query_authorization(test_context);

        default:
            return AWS_OP_ERR;
    }
}

static int s_generate_test_case(
    struct v4a_test_context *test_context,
    const char *parent_folder,
    const char *test_name) {
    {
        struct aws_signing_state_aws *signing_state = test_context->signing_state;

        /* 1a - generate ecc key */
        if (test_context->credentials != NULL) {
            struct aws_ecc_key_pair *derived_ecc_key = aws_ecc_key_pair_new_ecdsa_p256_key_from_aws_credentials(
                test_context->allocator, test_context->credentials);
            ASSERT_NOT_NULL(derived_ecc_key);
            ASSERT_SUCCESS(aws_ecc_key_pair_derive_public_key(derived_ecc_key));

            ASSERT_SUCCESS(s_write_key_to_test_case_file(test_context, derived_ecc_key, parent_folder, test_name));
            aws_ecc_key_pair_release(test_context->ecc_key);
            test_context->ecc_key = derived_ecc_key;
        }

        signing_state->config.ecc_signing_key = test_context->ecc_key;
        aws_ecc_key_pair_acquire(signing_state->config.ecc_signing_key);

        /* 1b - generate canonical request */
        ASSERT_TRUE(aws_signing_build_canonical_request(signing_state) == AWS_OP_SUCCESS);
        ASSERT_SUCCESS(s_write_test_file(
            parent_folder,
            test_name,
            s_get_canonical_request_filename(test_context->config->transform),
            &signing_state->canonical_request));

        /* 1c- generate string to sign */
        ASSERT_TRUE(aws_signing_build_string_to_sign(signing_state) == AWS_OP_SUCCESS);
        ASSERT_SUCCESS(s_write_test_file(
            parent_folder,
            test_name,
            s_get_string_to_sign_filename(test_context->config->transform),
            &signing_state->string_to_sign));
    }

    return AWS_OP_SUCCESS;
}

static int s_check_test_case(struct v4a_test_context *test_context, const char *parent_folder, const char *test_name) {
    {
        struct aws_signing_state_aws *signing_state = test_context->signing_state;

        ASSERT_TRUE(test_context->ecc_key != NULL);

        /* 1a - validate ecc key if credentials present */
        if (test_context->credentials != NULL) {
            struct aws_ecc_key_pair *derived_ecc_key = aws_ecc_key_pair_new_ecdsa_p256_key_from_aws_credentials(
                test_context->allocator, test_context->credentials);
            ASSERT_NOT_NULL(derived_ecc_key);

            ASSERT_SUCCESS(aws_ecc_key_pair_derive_public_key(derived_ecc_key));

            ASSERT_SUCCESS(s_check_derived_ecc_key(test_context, derived_ecc_key));

            aws_ecc_key_pair_release(derived_ecc_key);
        }

        signing_state->config.ecc_signing_key = test_context->ecc_key;
        aws_ecc_key_pair_acquire(signing_state->config.ecc_signing_key);

        /* 1b -  validate canonical request */
        ASSERT_TRUE(aws_signing_build_canonical_request(signing_state) == AWS_OP_SUCCESS);
        ASSERT_BIN_ARRAYS_EQUALS(
            test_context->test_case_data.expected_canonical_request.buffer,
            test_context->test_case_data.expected_canonical_request.len,
            signing_state->canonical_request.buffer,
            signing_state->canonical_request.len);

        /* 1c- validate string to sign */
        ASSERT_TRUE(aws_signing_build_string_to_sign(signing_state) == AWS_OP_SUCCESS);
        ASSERT_BIN_ARRAYS_EQUALS(
            test_context->test_case_data.expected_string_to_sign.buffer,
            test_context->test_case_data.expected_string_to_sign.len,
            signing_state->string_to_sign.buffer,
            signing_state->string_to_sign.len);

        /* 1d - validate authorization value against itself */
        ASSERT_TRUE(aws_signing_build_authorization_value(signing_state) == AWS_OP_SUCCESS);
        ASSERT_SUCCESS(s_validate_internal_authorization(test_context));
    }

    return AWS_OP_SUCCESS;
}

static int s_do_sigv4a_test_internal(
    struct aws_allocator *allocator,
    const char *parent_folder,
    const char *test_name,
    enum aws_signing_request_transform transform,
    struct aws_byte_buf *out_string_to_sign) {

    struct v4a_test_context test_context;
    AWS_ZERO_STRUCT(test_context);

    ASSERT_SUCCESS(s_v4a_test_context_init(&test_context, allocator, parent_folder, test_name, transform));

    if (test_context.should_generate_test_case) {
        ASSERT_SUCCESS(s_generate_test_case(&test_context, parent_folder, test_name));
    } else {
        ASSERT_SUCCESS(s_check_test_case(&test_context, parent_folder, test_name));
    }

    struct aws_byte_cursor string_to_sign_cursor =
        aws_byte_cursor_from_buf(&test_context.signing_state->string_to_sign);
    aws_byte_buf_append_dynamic(out_string_to_sign, &string_to_sign_cursor);

    s_v4a_test_context_clean_up(&test_context);

    return AWS_OP_SUCCESS;
}

static int s_write_signed_request_to_file(
    struct v4a_test_context *test_context,
    const char *parent_folder,
    const char *test_name,
    const struct aws_string *filename) {
    char path[1024];
    snprintf(path, AWS_ARRAY_SIZE(path), "./%s/%s/%s", parent_folder, test_name, aws_string_c_str(filename));

    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor method_cursor;
    ASSERT_SUCCESS(aws_http_message_get_request_method(test_context->request, &method_cursor));

    struct aws_byte_cursor path_cursor;
    ASSERT_SUCCESS(aws_http_message_get_request_path(test_context->request, &path_cursor));

    fprintf(
        fp, PRInSTR " " PRInSTR " HTTP/1.1\n", AWS_BYTE_CURSOR_PRI(method_cursor), AWS_BYTE_CURSOR_PRI(path_cursor));
    size_t header_count = aws_http_message_get_header_count(test_context->request);
    for (size_t i = 0; i < header_count; ++i) {
        struct aws_http_header header;
        AWS_ZERO_STRUCT(header);
        ASSERT_SUCCESS(aws_http_message_get_header(test_context->request, &header, i));
        fprintf(fp, PRInSTR ":" PRInSTR "\n", AWS_BYTE_CURSOR_PRI(header.name), AWS_BYTE_CURSOR_PRI(header.value));
    }

    fprintf(fp, "\n");

    if (test_context->payload_stream) {
        int64_t stream_length = 0;
        ASSERT_SUCCESS(aws_input_stream_get_length(test_context->payload_stream, &stream_length));

        struct aws_byte_buf stream_buf;
        ASSERT_SUCCESS(aws_byte_buf_init(&stream_buf, test_context->allocator, (size_t)stream_length));

        ASSERT_SUCCESS(aws_input_stream_seek(test_context->payload_stream, 0, AWS_SSB_BEGIN));
        ASSERT_SUCCESS(aws_input_stream_read(test_context->payload_stream, &stream_buf));
        ASSERT_TRUE(stream_buf.len == (size_t)stream_length);

        fprintf(fp, PRInSTR, AWS_BYTE_BUF_PRI(stream_buf));

        aws_byte_buf_clean_up(&stream_buf);
    }

    fclose(fp);

    return AWS_OP_SUCCESS;
}

static int s_check_header_value(struct aws_http_message *request, struct aws_http_header *expected_header) {
    size_t header_count = aws_http_message_get_header_count(request);
    for (size_t i = 0; i < header_count; ++i) {
        struct aws_http_header header;
        AWS_ZERO_STRUCT(header);

        ASSERT_SUCCESS(aws_http_message_get_header(request, &header, i));

        if (aws_byte_cursor_eq_ignore_case(&header.name, &expected_header->name)) {
            if (aws_byte_cursor_eq(&header.value, &expected_header->value)) {
                aws_http_message_erase_header(request, i);
                return AWS_OP_SUCCESS;
            }
        }
    }

    ASSERT_TRUE(false);
}

static int s_check_query_authorization(
    struct v4a_test_context *test_context,
    struct aws_byte_cursor signed_path,
    struct aws_byte_cursor expected_path,
    struct aws_byte_buf *string_to_sign) {

    struct aws_uri signed_uri;
    ASSERT_SUCCESS(aws_uri_init_parse(&signed_uri, test_context->allocator, &signed_path));

    struct aws_uri expected_uri;
    ASSERT_SUCCESS(aws_uri_init_parse(&expected_uri, test_context->allocator, &expected_path));

    ASSERT_BIN_ARRAYS_EQUALS(signed_uri.path.ptr, signed_uri.path.len, expected_uri.path.ptr, expected_uri.path.len);

    struct aws_array_list signed_params;
    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&signed_params, test_context->allocator, 10, sizeof(struct aws_uri_param)));
    ASSERT_SUCCESS(aws_uri_query_string_params(&signed_uri, &signed_params));

    struct aws_array_list expected_params;
    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&expected_params, test_context->allocator, 10, sizeof(struct aws_uri_param)));
    ASSERT_SUCCESS(aws_uri_query_string_params(&expected_uri, &expected_params));

    ASSERT_TRUE(aws_array_list_length(&signed_params) == aws_array_list_length(&expected_params));

    struct aws_byte_cursor signature_cursor = aws_byte_cursor_from_string(g_aws_signing_authorization_query_param_name);

    size_t signed_param_count = aws_array_list_length(&signed_params);
    for (size_t i = 0; i < signed_param_count; ++i) {
        struct aws_uri_param signed_param;
        aws_array_list_get_at(&signed_params, &signed_param, i);

        if (aws_byte_cursor_eq_ignore_case(&signed_param.key, &signature_cursor)) {
            ASSERT_SUCCESS(s_validate_authorization_value(
                test_context, aws_byte_cursor_from_buf(string_to_sign), signed_param.value));
        } else {
            bool found = false;
            for (size_t j = 0; j < signed_param_count; ++j) {
                struct aws_uri_param expected_param;
                aws_array_list_get_at(&expected_params, &expected_param, j);
                if (aws_byte_cursor_eq_ignore_case(&signed_param.key, &expected_param.key)) {
                    ASSERT_TRUE(aws_byte_cursor_eq_ignore_case(&signed_param.value, &expected_param.value));
                    found = true;
                    break;
                }
            }

            ASSERT_TRUE(found);
        }
    }

    aws_uri_clean_up(&signed_uri);
    aws_uri_clean_up(&expected_uri);
    aws_array_list_clean_up(&signed_params);
    aws_array_list_clean_up(&expected_params);

    return AWS_OP_SUCCESS;
}

static int s_get_authorization_pair(
    const struct aws_byte_cursor *authorization_value,
    const struct aws_byte_cursor name,
    struct aws_byte_cursor value_end,
    struct aws_byte_cursor *value_out) {
    struct aws_byte_cursor value_start_cursor;
    AWS_ZERO_STRUCT(value_start_cursor);
    ASSERT_SUCCESS(aws_byte_cursor_find_exact(authorization_value, &name, &value_start_cursor));
    aws_byte_cursor_advance(&value_start_cursor, name.len);

    struct aws_byte_cursor value_end_cursor;
    AWS_ZERO_STRUCT(value_end_cursor);
    ASSERT_SUCCESS(aws_byte_cursor_find_exact(&value_start_cursor, &value_end, &value_end_cursor));

    *value_out = value_start_cursor;
    value_out->len = value_end_cursor.ptr - value_start_cursor.ptr;

    return AWS_OP_SUCCESS;
}

static int s_compare_authorization_pair(
    const struct aws_byte_cursor *signed_value,
    const struct aws_byte_cursor *expected_value,
    const struct aws_byte_cursor name) {
    struct aws_byte_cursor signed_pair_value;
    AWS_ZERO_STRUCT(signed_pair_value);
    ASSERT_SUCCESS(s_get_authorization_pair(signed_value, name, aws_byte_cursor_from_c_str(", "), &signed_pair_value));

    struct aws_byte_cursor expected_pair_value;
    AWS_ZERO_STRUCT(expected_pair_value);
    ASSERT_SUCCESS(
        s_get_authorization_pair(expected_value, name, aws_byte_cursor_from_c_str(", "), &expected_pair_value));

    ASSERT_BIN_ARRAYS_EQUALS(
        signed_pair_value.ptr, signed_pair_value.len, expected_pair_value.ptr, expected_pair_value.len);

    return AWS_OP_SUCCESS;
}

static int s_check_header_authorization(
    struct v4a_test_context *test_context,
    struct aws_http_header *header,
    struct aws_http_message *expected_request,
    struct aws_byte_buf *string_to_sign) {
    struct aws_byte_cursor signed_authorization_value = header->value;

    struct aws_byte_cursor expected_authorization_value;
    AWS_ZERO_STRUCT(expected_authorization_value);

    size_t expected_header_count = aws_http_message_get_header_count(expected_request);
    for (size_t i = 0; i < expected_header_count; ++i) {
        struct aws_http_header expected_header;
        AWS_ZERO_STRUCT(expected_header);

        if (aws_http_message_get_header(expected_request, &expected_header, i)) {
            continue;
        }

        if (aws_byte_cursor_eq_c_str_ignore_case(&expected_header.name, "Authorization")) {
            expected_authorization_value = expected_header.value;
            break;
        }
    }

    ASSERT_TRUE(expected_authorization_value.len > 0);

    struct aws_byte_cursor space_cursor = aws_byte_cursor_from_c_str(" ");

    struct aws_byte_cursor signed_space_cursor;
    AWS_ZERO_STRUCT(signed_space_cursor);
    ASSERT_SUCCESS(aws_byte_cursor_find_exact(&signed_authorization_value, &space_cursor, &signed_space_cursor));
    struct aws_byte_cursor signed_algorithm_cursor = {
        .ptr = signed_authorization_value.ptr,
        .len = signed_space_cursor.ptr - signed_authorization_value.ptr,
    };

    struct aws_byte_cursor expected_space_cursor;
    AWS_ZERO_STRUCT(expected_space_cursor);
    ASSERT_SUCCESS(aws_byte_cursor_find_exact(&expected_authorization_value, &space_cursor, &expected_space_cursor));
    struct aws_byte_cursor expected_algorithm_cursor = {
        .ptr = expected_authorization_value.ptr,
        .len = expected_space_cursor.ptr - expected_authorization_value.ptr,
    };

    ASSERT_BIN_ARRAYS_EQUALS(
        signed_algorithm_cursor.ptr,
        signed_algorithm_cursor.len,
        expected_algorithm_cursor.ptr,
        expected_algorithm_cursor.len);

    ASSERT_SUCCESS(s_compare_authorization_pair(
        &signed_authorization_value, &expected_authorization_value, aws_byte_cursor_from_c_str("Credential=")));
    ASSERT_SUCCESS(s_compare_authorization_pair(
        &signed_authorization_value, &expected_authorization_value, aws_byte_cursor_from_c_str("SignedHeaders=")));

    struct aws_byte_cursor signature_key_cursor = aws_byte_cursor_from_c_str("Signature=");

    struct aws_byte_cursor signed_signature_value;
    AWS_ZERO_STRUCT(signed_signature_value);
    ASSERT_SUCCESS(
        aws_byte_cursor_find_exact(&signed_authorization_value, &signature_key_cursor, &signed_signature_value));
    aws_byte_cursor_advance(&signed_signature_value, signature_key_cursor.len);
    ASSERT_SUCCESS(
        s_validate_authorization_value(test_context, aws_byte_cursor_from_buf(string_to_sign), signed_signature_value));

    struct aws_byte_cursor expected_signature_value;
    AWS_ZERO_STRUCT(expected_signature_value);
    ASSERT_SUCCESS(
        aws_byte_cursor_find_exact(&expected_authorization_value, &signature_key_cursor, &expected_signature_value));
    aws_byte_cursor_advance(&expected_signature_value, signature_key_cursor.len);
    ASSERT_SUCCESS(s_validate_authorization_value(
        test_context, aws_byte_cursor_from_buf(string_to_sign), expected_signature_value));

    return AWS_OP_SUCCESS;
}

static int s_check_signed_request(
    struct v4a_test_context *test_context,
    struct aws_byte_buf *expected_request_buffer,
    struct aws_byte_buf *string_to_sign) {

    struct aws_http_message *expected_request = NULL;
    struct aws_input_stream *body_stream = NULL;

    ASSERT_SUCCESS(s_v4a_test_context_parse_request(
        test_context, expected_request_buffer, false, &expected_request, &body_stream));
    ASSERT_NOT_NULL(expected_request);

    /* method */
    struct aws_byte_cursor signed_method;
    AWS_ZERO_STRUCT(signed_method);
    aws_http_message_get_request_method(test_context->request, &signed_method);

    struct aws_byte_cursor expected_method;
    AWS_ZERO_STRUCT(expected_method);
    aws_http_message_get_request_method(expected_request, &expected_method);

    ASSERT_BIN_ARRAYS_EQUALS(expected_method.ptr, expected_method.len, signed_method.ptr, signed_method.len);

    /* path + query string */
    struct aws_byte_cursor signed_path;
    AWS_ZERO_STRUCT(signed_path);
    aws_http_message_get_request_path(test_context->request, &signed_path);

    struct aws_byte_cursor expected_path;
    AWS_ZERO_STRUCT(expected_path);
    aws_http_message_get_request_path(expected_request, &expected_path);

    if (test_context->config->transform == AWS_SRT_QUERY_PARAM) {
        ASSERT_SUCCESS(s_check_query_authorization(test_context, signed_path, expected_path, string_to_sign));
    } else {
        ASSERT_BIN_ARRAYS_EQUALS(expected_path.ptr, expected_path.len, signed_path.ptr, signed_path.len);
    }

    /* headers */
    size_t signed_header_count = aws_http_message_get_header_count(test_context->request);
    size_t expected_header_count = aws_http_message_get_header_count(expected_request);
    ASSERT_TRUE(signed_header_count == expected_header_count);

    for (size_t i = 0; i < signed_header_count; ++i) {
        struct aws_http_header header;
        AWS_ZERO_STRUCT(header);

        if (aws_http_message_get_header(test_context->request, &header, i)) {
            continue;
        }

        if (test_context->config->transform == AWS_SRT_HEADER &&
            aws_byte_cursor_eq_c_str_ignore_case(&header.name, "Authorization")) {
            ASSERT_SUCCESS(s_check_header_authorization(test_context, &header, expected_request, string_to_sign));
        } else {
            ASSERT_SUCCESS(s_check_header_value(expected_request, &header));
        }
    }

    aws_http_message_release(expected_request);
    aws_input_stream_destroy(body_stream);

    return AWS_OP_SUCCESS;
}

static int s_do_sigv4a_test_signing(
    struct aws_allocator *allocator,
    const char *parent_folder,
    const char *test_name,
    enum aws_signing_request_transform transform) {

    struct aws_byte_buf string_to_sign;
    if (aws_byte_buf_init(&string_to_sign, allocator, 1024)) {
        return AWS_OP_ERR;
    }

    ASSERT_SUCCESS(s_do_sigv4a_test_internal(allocator, parent_folder, test_name, transform, &string_to_sign));

    struct v4a_test_context test_context;
    AWS_ZERO_STRUCT(test_context);

    ASSERT_SUCCESS(s_v4a_test_context_init(&test_context, allocator, parent_folder, test_name, transform));

    ASSERT_SUCCESS(aws_sign_request_aws(
        allocator, test_context.signable, (void *)test_context.config, s_on_signing_complete, &test_context));

    s_wait_on_signing_complete(&test_context);

    if (test_context.should_generate_test_case) {
        ASSERT_SUCCESS(s_write_signed_request_to_file(
            &test_context, parent_folder, test_name, s_get_signed_request_filename(transform)));
    } else {
        ASSERT_SUCCESS(
            s_check_signed_request(&test_context, &test_context.test_case_data.sample_signed_request, &string_to_sign));
    }

    s_v4a_test_context_clean_up(&test_context);

    aws_byte_buf_clean_up(&string_to_sign);

    return AWS_OP_SUCCESS;
}

static int s_do_sigv4a_test_case(struct aws_allocator *allocator, const char *test_name, const char *parent_folder) {

    /* Set up everything */
    aws_auth_library_init(allocator);

    ASSERT_SUCCESS(s_do_sigv4a_test_signing(allocator, parent_folder, test_name, AWS_SRT_HEADER));
    ASSERT_SUCCESS(s_do_sigv4a_test_signing(allocator, parent_folder, test_name, AWS_SRT_QUERY_PARAM));

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

#define DECLARE_SIGV4A_TEST_SUITE_CASE(test_name, test_name_string)                                                    \
    static int s_sigv4a_##test_name##_test(struct aws_allocator *allocator, void *ctx) {                               \
        (void)ctx;                                                                                                     \
        return s_do_sigv4a_test_case(allocator, test_name_string, "./v4a");                                            \
    }                                                                                                                  \
    AWS_TEST_CASE(sigv4a_##test_name##_test, s_sigv4a_##test_name##_test);

DECLARE_SIGV4A_TEST_SUITE_CASE(get_header_key_duplicate, "get-header-key-duplicate");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_header_value_multiline, "get-header-value-multiline");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_header_value_order, "get-header-value-order");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_header_value_trim, "get-header-value-trim");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_unreserved, "get-unreserved");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_utf8, "get-utf8");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_vanilla, "get-vanilla");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_vanilla_empty_query_key, "get-vanilla-empty-query-key");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_vanilla_query, "get-vanilla-query");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_vanilla_query_order_key_case, "get-vanilla-query-order-key-case");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_vanilla_unreserved, "get-vanilla-query-unreserved");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_vanilla_utf8_query, "get-vanilla-utf8-query");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_header_key_case, "post-header-key-case");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_header_key_sort, "post-header-key-sort");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_header_value_case, "post-header-value-case");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_vanilla, "post-vanilla");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_vanilla_empty_query_value, "post-vanilla-empty-query-value");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_vanilla_query, "post-vanilla-query");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_x_www_form_urlencoded, "post-x-www-form-urlencoded");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_x_www_form_urlencoded_parameters, "post-x-www-form-urlencoded-parameters");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_vanilla_with_session_token, "get-vanilla-with-session-token");

DECLARE_SIGV4A_TEST_SUITE_CASE(post_sts_header_after, "post-sts-header-after");
DECLARE_SIGV4A_TEST_SUITE_CASE(post_sts_header_before, "post-sts-header-before");

DECLARE_SIGV4A_TEST_SUITE_CASE(get_relative_normalized, "get-relative-normalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_relative_unnormalized, "get-relative-unnormalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_relative_relative_normalized, "get-relative-relative-normalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_relative_relative_unnormalized, "get-relative-relative-unnormalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_slash_normalized, "get-slash-normalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_slash_unnormalized, "get-slash-unnormalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_slash_dot_slash_normalized, "get-slash-dot-slash-normalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_slash_dot_slash_unnormalized, "get-slash-dot-slash-unnormalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_slash_pointless_dot_normalized, "get-slash-pointless-dot-normalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_slash_pointless_dot_unnormalized, "get-slash-pointless-dot-unnormalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_slashes_normalized, "get-slashes-normalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_slashes_unnormalized, "get-slashes-unnormalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_space_normalized, "get-space-normalized");
DECLARE_SIGV4A_TEST_SUITE_CASE(get_space_unnormalized, "get-space-unnormalized");
