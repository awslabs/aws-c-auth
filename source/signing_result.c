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

#include <aws/auth/signing_result.h>

#include <aws/common/byte_buf.h>
#include <aws/common/string.h>

#define INITIAL_SIGNING_RESULT_HEADERS_SIZE 10
#define INITIAL_SIGNING_RESULT_QUERY_PARAMS_SIZE 10

static void s_aws_signing_result_name_value_pair_clean_up(struct aws_signing_result_name_value_pair *pair) {
    aws_string_destroy(pair->name);
    aws_string_destroy(pair->value);
}

int aws_signing_result_init(struct aws_signing_result *result, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*result);

    result->allocator = allocator;
    if (aws_array_list_init_dynamic(
            &result->headers,
            allocator,
            INITIAL_SIGNING_RESULT_HEADERS_SIZE,
            sizeof(struct aws_signing_result_name_value_pair)) ||
        aws_array_list_init_dynamic(
            &result->query_params,
            allocator,
            INITIAL_SIGNING_RESULT_QUERY_PARAMS_SIZE,
            sizeof(struct aws_signing_result_name_value_pair))) {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:

    aws_signing_result_clean_up(result);

    return AWS_OP_ERR;
}

void aws_signing_result_clean_up(struct aws_signing_result *result) {

    size_t header_count = aws_array_list_length(&result->headers);
    for (size_t i = 0; i < header_count; ++i) {
        struct aws_signing_result_name_value_pair header;
        if (aws_array_list_get_at(&result->headers, &header, i)) {
            continue;
        }

        s_aws_signing_result_name_value_pair_clean_up(&header);
    }

    size_t query_param_count = aws_array_list_length(&result->query_params);
    for (size_t i = 0; i < query_param_count; ++i) {
        struct aws_signing_result_name_value_pair query_param;
        if (aws_array_list_get_at(&result->query_params, &query_param, i)) {
            continue;
        }

        s_aws_signing_result_name_value_pair_clean_up(&query_param);
    }

    aws_array_list_clean_up(&result->headers);
    aws_array_list_clean_up(&result->query_params);
}

int s_aws_signing_result_add_pair(
    struct aws_array_list *pair_list,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *name,
    struct aws_byte_cursor *value) {
    struct aws_signing_result_name_value_pair pair;
    AWS_ZERO_STRUCT(pair);

    pair.name = aws_string_new_from_array(allocator, name->ptr, name->len);
    pair.value = aws_string_new_from_array(allocator, value->ptr, value->len);
    if (pair.name == NULL || pair.value == NULL) {
        goto on_error;
    }

    if (aws_array_list_push_back(pair_list, &pair)) {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:

    s_aws_signing_result_name_value_pair_clean_up(&pair);

    return AWS_OP_ERR;
}

int aws_signing_result_add_header(
    struct aws_signing_result *result,
    struct aws_byte_cursor *name,
    struct aws_byte_cursor *value) {
    return s_aws_signing_result_add_pair(&result->headers, result->allocator, name, value);
}

int aws_signing_result_add_query_param(
    struct aws_signing_result *result,
    struct aws_byte_cursor *name,
    struct aws_byte_cursor *value) {
    return s_aws_signing_result_add_pair(&result->query_params, result->allocator, name, value);
}
