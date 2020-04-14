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

#include <aws/common/string.h>
#include <aws/auth/private/credentials_utils.h>

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

    aws_atomic_store_int(&provider->ref_count, 1);
}

void aws_credentials_provider_invoke_shutdown_callback(struct aws_credentials_provider *provider) {
    if (provider && provider->shutdown_options.shutdown_callback) {
        provider->shutdown_options.shutdown_callback(provider->shutdown_options.shutdown_user_data);
    }
}

static struct aws_byte_cursor s_dot_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(".");
static struct aws_byte_cursor s_amazonaws_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(".amazonaws.com");
static struct aws_byte_cursor s_cn_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(".cn");

int aws_credentials_provider_construct_endpoint(
    struct aws_allocator *allocator,
    struct aws_byte_buf *endpoint,
    const struct aws_string *region, 
    const struct aws_string *service_name) {

    aws_byte_buf_clean_up(endpoint);

    if (!allocator || !endpoint || !region || !service_name) {
        return AWS_ERROR_INVALID_ARGUMENT;
    }

    struct aws_byte_cursor service_cursor = aws_byte_cursor_from_string(service_name);
    if (aws_byte_buf_init_copy_from_cursor(endpoint, allocator, service_cursor)) {
        goto on_finish;
    }

    if (aws_byte_buf_init_copy_from_cursor(endpoint, allocator, s_dot_cursor)) {
        goto on_finish;
    }

    struct aws_byte_cursor region_cursor;
    region_cursor = aws_byte_cursor_from_array(region->bytes, region->len);
    if (aws_byte_buf_append_dynamic(endpoint, &region_cursor)) {
        goto on_finish;
    }

    if (aws_byte_buf_append_dynamic(endpoint, &s_amazonaws_cursor)) {
        goto on_finish;
    }

    if (aws_string_eq_c_str_ignore_case(region, "cn-north-1") ||
        aws_string_eq_c_str_ignore_case(region, "cn-northwest-1")) {
        if (aws_byte_buf_append_dynamic(endpoint, &s_cn_cursor)) {
            goto on_finish;
        }
    }
    return AWS_OP_SUCCESS;

on_finish:
    aws_byte_buf_clean_up(endpoint);
    return AWS_OP_ERR;
}
