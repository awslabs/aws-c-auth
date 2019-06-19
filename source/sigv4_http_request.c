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

#include <aws/auth/private/sigv4_http_request.h>

#include <aws/auth/signable.h>
#include <aws/auth/signing_result.h>
#include <aws/io/uri.h>

int aws_sign_http_request_identity(struct aws_http_request_options *input_request,
                                   struct aws_http_request_options **output_request,
                                   aws_http_request_options_destroy_fn **request_cleanup)
{
    *request_cleanup = NULL;
    *output_request = input_request;

    return AWS_OP_SUCCESS;
}

static void s_destroy_signed_request_clone(struct aws_allocator *allocator, struct aws_http_request_options *request) {
    if (request == NULL) {
        return;
    }

    if (request->method.ptr) {
        aws_mem_release(allocator, request->method.ptr);
    }

    if (request->uri.ptr) {
        aws_mem_release(allocator, request->uri.ptr);
    }

    for (size_t i = 0; i < request->num_headers; ++i) {
        const struct aws_http_header *header = &request->header_array[i];
        if (header->name.ptr) {
            aws_mem_release(allocator, header->name.ptr);
        }
        if (header->value.ptr) {
            aws_mem_release(allocator, header->value.ptr);
        }
    }

    if (request->header_array) {
        aws_mem_release(allocator, (struct aws_http_header *) request->header_array);
    }
}

static int s_clone_byte_cursor(struct aws_allocator *allocator, struct aws_byte_cursor *source, struct aws_byte_cursor *dest) {
    if (source->len == 0) {
        return AWS_OP_SUCCESS;
    }

    uint8_t *raw_data = aws_mem_acquire(allocator, source->len);
    if (raw_data == NULL) {
        return AWS_OP_ERR;
    }

    memcpy(raw_data, source->ptr, source->len);
    dest->ptr = raw_data;
    dest->len = source->len;

    return AWS_OP_SUCCESS;
}

static int s_clone_request_uri(struct aws_allocator *allocator, struct aws_byte_cursor *source_uri, struct aws_http_request_options *dest_request, struct aws_signing_result *result) {

    /* first let's see if we need to do anything at all */
    struct aws_array_list *result_param_list = NULL;
    if (aws_signing_result_get_property_list(result, g_aws_http_query_params_property_list_name, &result_param_list)) {
        return AWS_OP_ERR;
    }

    size_t signed_query_param_count = 0;
    if (result_param_list != NULL) {
        signed_query_param_count = aws_array_list_length(result_param_list);
    }

    struct aws_uri old_uri;
    AWS_ZERO_STRUCT(old_uri);

    struct aws_uri new_uri;
    AWS_ZERO_STRUCT(new_uri);

    struct aws_uri_builder_options new_uri_builder;
    AWS_ZERO_STRUCT(new_uri_builder);

    struct aws_array_list query_params;
    AWS_ZERO_STRUCT(query_params);

    /* start with the old uri and parse it */
    if (aws_uri_init_parse(&old_uri, allocator, source_uri)) {
        goto error;
    }

    /* pull out the query params */
    if (aws_array_list_init_dynamic(&query_params, allocator, 10, sizeof(struct aws_uri_param))) {
        goto error;
    }

    if (aws_uri_query_string_params(&old_uri, &query_params)) {
        goto error;
    }

    /* initialize a builder for the new uri matching the old uri */
    new_uri_builder.host_name = old_uri.host_name;
    new_uri_builder.path = old_uri.path;
    new_uri_builder.port = old_uri.port;
    new_uri_builder.scheme = old_uri.scheme;
    new_uri_builder.query_params = &query_params;

    /* and now add any signing query params */
    for (size_t i = 0; i < signed_query_param_count; ++i) {
        struct aws_signable_property_list_pair source_param;
        if (aws_array_list_get_at(result_param_list, &source_param, i)) {
            goto error;
        }

        struct aws_uri_param signed_param;
        signed_param.key = source_param.name;
        signed_param.value = source_param.value;

        aws_array_list_push_back(&query_params, &signed_param);
    }

    /* create the new uri */
    if (aws_uri_init_from_builder_options(&new_uri, allocator, &new_uri_builder)) {
        goto error;
    }

    /* copy the full string */
    struct aws_byte_cursor new_uri_cursor = aws_byte_cursor_from_buf(&new_uri.uri_str);
    if (s_clone_byte_cursor(allocator, &new_uri_cursor, &dest_request->uri)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:

    aws_array_list_clean_up(&query_params);

    aws_uri_clean_up(&new_uri);
    aws_uri_clean_up(&old_uri);

    return AWS_OP_ERR;
}

static struct aws_http_request_options *s_build_signed_request(struct aws_allocator *allocator, struct aws_http_request_options *request, struct aws_signing_result *result) {
    struct aws_http_request_options *request_copy = aws_mem_calloc(allocator, 1, sizeof(struct aws_http_request_options));
    if (request_copy == NULL) {
        return NULL;
    }

    /* method */
    if (s_clone_byte_cursor(allocator, &request->method, &request_copy->method)) {
        goto error;
    }

    /* uri/query params */
    if (s_clone_request_uri(allocator, &request->uri, request_copy, result)) {
        goto error;
    }

    /* headers */
    struct aws_array_list *result_header_list = NULL;
    if (aws_signing_result_get_property_list(result, g_aws_http_headers_property_list_name, &result_header_list)) {
        goto error;
    }

    size_t signing_header_count = 0;
    if (result_header_list != NULL) {
        signing_header_count = aws_array_list_length(result_header_list);
    }

    size_t copy_header_count = request->num_headers + signing_header_count;
    request_copy->header_array = aws_mem_calloc(allocator, copy_header_count, sizeof(struct aws_http_header));
    if (request_copy->header_array == NULL) {
        goto error;
    }

    request_copy->num_headers = copy_header_count;
    for (size_t i = 0; i < request->num_headers; ++i) {
        struct aws_http_header *source_header = (struct aws_http_header *)&request->header_array[i];
        struct aws_http_header *dest_header = (struct aws_http_header *)&request_copy->header_array[i];
        if (s_clone_byte_cursor(allocator, &source_header->name, &dest_header->name)) {
            goto error;
        }

        if (s_clone_byte_cursor(allocator, &source_header->value, &dest_header->value)) {
            goto error;
        }
    }

    for (size_t i = 0; i < signing_header_count; ++i) {
        struct aws_signable_property_list_pair source_header;
        if (aws_array_list_get_at(result_header_list, &source_header, i)) {
            goto error;
        }
        struct aws_http_header *dest_header = (struct aws_http_header *)&request_copy->header_array[i + request->num_headers];

        if (s_clone_byte_cursor(allocator, &source_header.name, &dest_header->name)) {
            goto error;
        }

        if (s_clone_byte_cursor(allocator, &source_header.value, &dest_header->value)) {
            goto error;
        }
    }

    request_copy->self_size = request->self_size;
    request_copy->client_connection = request->client_connection;
    request_copy->user_data = request->user_data;
    request_copy->stream_outgoing_body = request->stream_outgoing_body;
    request_copy->on_response_headers = request->on_response_headers;
    request_copy->on_response_header_block_done = request->on_response_header_block_done;
    request_copy->on_response_body = request->on_response_body;
    request_copy->on_complete = request->on_complete;

    return request_copy;

error:

    s_destroy_signed_request_clone(allocator, request_copy);

    return NULL;
}

int aws_sign_http_request_sigv4(struct aws_allocator *allocator,
        struct aws_http_request_options *input_request,
                                struct aws_http_request_options **output_request,
                                aws_http_request_options_destroy_fn **request_cleanup)
{
    *request_cleanup = NULL;
    *output_request = input_request;

    return AWS_OP_SUCCESS;
}
