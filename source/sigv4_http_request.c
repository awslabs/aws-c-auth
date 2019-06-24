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

#include <aws/auth/credentials.h>
#include <aws/auth/signable.h>
#include <aws/auth/signer.h>
#include <aws/auth/signing_result.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/uri.h>

int aws_sign_http_request_identity(
    struct aws_http_request *request,
    struct aws_allocator *allocator,
    const struct aws_hash_table *context) {
    (void)request;
    (void)allocator;
    (void)context;

    return AWS_OP_SUCCESS;
}

static int s_build_request_uri(
    struct aws_allocator *allocator,
    struct aws_http_request *request,
    struct aws_signing_result *signing_result) {

    /* first let's see if we need to do anything at all */
    struct aws_array_list *result_param_list = NULL;
    if (aws_signing_result_get_property_list(
            signing_result, g_aws_http_query_params_property_list_name, &result_param_list)) {
        return AWS_OP_SUCCESS;
    }

    int result = AWS_OP_ERR;

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

    struct aws_byte_cursor old_path;
    aws_http_request_get_path(request, &old_path);

    /* start with the old uri and parse it */
    if (aws_uri_init_parse(&old_uri, allocator, &old_path)) {
        goto done;
    }

    /* pull out the query params */
    if (aws_array_list_init_dynamic(&query_params, allocator, 10, sizeof(struct aws_uri_param))) {
        goto done;
    }

    if (aws_uri_query_string_params(&old_uri, &query_params)) {
        goto done;
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
            goto done;
        }

        struct aws_uri_param signed_param;
        signed_param.key = source_param.name;
        signed_param.value = source_param.value;

        aws_array_list_push_back(&query_params, &signed_param);
    }

    /* create the new uri */
    if (aws_uri_init_from_builder_options(&new_uri, allocator, &new_uri_builder)) {
        goto done;
    }

    /* copy the full string */
    struct aws_byte_cursor new_uri_cursor = aws_byte_cursor_from_buf(&new_uri.uri_str);
    if (aws_http_request_set_path(request, new_uri_cursor)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_array_list_clean_up(&query_params);

    aws_uri_clean_up(&new_uri);
    aws_uri_clean_up(&old_uri);

    return result;
}

static int s_apply_signing_result_to_request(
    struct aws_http_request *request,
    struct aws_allocator *allocator,
    struct aws_signing_result *result) {

    /* uri/query params */
    if (s_build_request_uri(allocator, request, result)) {
        return AWS_OP_ERR;
    }

    /* headers */
    struct aws_array_list *result_header_list = NULL;
    if (aws_signing_result_get_property_list(result, g_aws_http_headers_property_list_name, &result_header_list)) {
        return AWS_OP_ERR;
    }

    size_t signing_header_count = 0;
    if (result_header_list != NULL) {
        signing_header_count = aws_array_list_length(result_header_list);
    }

    for (size_t i = 0; i < signing_header_count; ++i) {
        struct aws_signing_result_property source_header;
        if (aws_array_list_get_at(result_header_list, &source_header, i)) {
            return AWS_OP_ERR;
        }

        struct aws_http_header dest_header = {.name = aws_byte_cursor_from_string(source_header.name),
                                              .value = aws_byte_cursor_from_string(source_header.value)};
        aws_http_request_add_header(request, dest_header);
    }

    return AWS_OP_SUCCESS;
}

struct aws_signable_http_request_impl {
    struct aws_http_request *request;
    struct aws_array_list headers;
};

static int s_aws_signable_http_request_get_property(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_byte_cursor *out_value) {

    struct aws_signable_http_request_impl *impl = signable->impl;

    AWS_ZERO_STRUCT(*out_value);

    if (aws_string_eq(name, g_aws_http_uri_property_name)) {
        aws_http_request_get_path(impl->request, out_value);
    } else if (aws_string_eq(name, g_aws_http_method_property_name)) {
        aws_http_request_get_method(impl->request, out_value);
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_signable_http_request_get_property_list(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_array_list **out_list) {

    struct aws_signable_http_request_impl *impl = signable->impl;

    *out_list = NULL;

    if (aws_string_eq(name, g_aws_http_headers_property_list_name)) {
        *out_list = &impl->headers;
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_signable_http_request_get_payload_stream(
    const struct aws_signable *signable,
    struct aws_input_stream **out_input_stream) {
    struct aws_signable_http_request_impl *impl = signable->impl;
    *out_input_stream = aws_http_request_get_body_stream(impl->request);

    return AWS_OP_SUCCESS;
}

static void s_aws_signable_http_request_clean_up(struct aws_signable *signable) {
    if (signable == NULL) {
        return;
    }

    struct aws_signable_http_request_impl *impl = signable->impl;
    if (impl != NULL) {
        aws_mem_release(signable->allocator, impl);
    }
}

static struct aws_signable_vtable s_signable_http_request_vtable = {
    .get_property = s_aws_signable_http_request_get_property,
    .get_property_list = s_aws_signable_http_request_get_property_list,
    .get_payload_stream = s_aws_signable_http_request_get_payload_stream,
    .clean_up = s_aws_signable_http_request_clean_up};

struct aws_signable *aws_signable_new_http_request(struct aws_allocator *allocator, struct aws_http_request *request) {

    struct aws_signable *signable = aws_mem_acquire(allocator, sizeof(struct aws_signable));
    if (signable == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*signable);
    signable->allocator = allocator;
    signable->vtable = &s_signable_http_request_vtable;

    struct aws_signable_http_request_impl *impl =
        aws_mem_acquire(allocator, sizeof(struct aws_signable_http_request_impl));
    if (impl == NULL) {
        goto on_error;
    }

    AWS_ZERO_STRUCT(*impl);
    signable->impl = impl;

    size_t header_count = aws_http_request_get_header_count(request);
    if (aws_array_list_init_dynamic(
            &impl->headers, allocator, header_count, sizeof(struct aws_signable_property_list_pair))) {
        goto on_error;
    }

    for (size_t i = 0; i < header_count; ++i) {
        struct aws_http_header header;
        aws_http_request_get_header(request, &header, i);

        struct aws_signable_property_list_pair property = {.name = header.name, .value = header.value};
        aws_array_list_push_back(&impl->headers, &property);
    }

    impl->request = request;

    return signable;

on_error:

    aws_signable_destroy(signable);

    return NULL;
}

struct aws_credentials_waiter {
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    struct aws_credentials *credentials;
    bool done;
};

static int s_aws_credentials_waiter_init(struct aws_credentials_waiter *waiter) {
    if (aws_mutex_init(&waiter->lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&waiter->signal)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_aws_credentials_waiter_clean_up(struct aws_credentials_waiter *waiter) {
    aws_mutex_clean_up(&waiter->lock);
    aws_condition_variable_clean_up(&waiter->signal);
    aws_credentials_destroy(waiter->credentials);
}

void s_get_credentials_callback(struct aws_credentials *credentials, void *user_data) {
    struct aws_credentials_waiter *waiter = user_data;
    aws_mutex_lock(&waiter->lock);
    waiter->done = true;
    waiter->credentials = aws_credentials_new_copy(credentials->allocator, credentials);
    aws_condition_variable_notify_one(&waiter->signal);
    aws_mutex_unlock(&waiter->lock);
}

bool s_wait_predicate(void *user_data) {
    struct aws_credentials_waiter *waiter = user_data;

    return waiter->done;
}

void s_aws_credentials_waiter_wait_on_credentials(struct aws_credentials_waiter *waiter) {
    aws_mutex_lock(&waiter->lock);
    if (!waiter->done) {
        aws_condition_variable_wait_pred(&waiter->signal, &waiter->lock, s_wait_predicate, waiter);
    }
    aws_mutex_unlock(&waiter->lock);
}

AWS_STATIC_STRING_FROM_LITERAL(s_region_key, "region");
AWS_STATIC_STRING_FROM_LITERAL(s_service_key, "service");

int aws_sign_http_request_sigv4(
    struct aws_http_request *request,
    struct aws_allocator *allocator,
    const struct aws_hash_table *context) {
    int result = AWS_OP_ERR;

    struct aws_signing_result signing_result;
    AWS_ZERO_STRUCT(signing_result);

    struct aws_signing_config_aws config;
    AWS_ZERO_STRUCT(config);

    struct aws_credentials_waiter credentials_waiter;
    AWS_ZERO_STRUCT(credentials_waiter);

    struct aws_signable *signable = NULL;
    struct aws_signer *signer = NULL;
    struct aws_credentials_provider *provider = NULL;

    aws_auth_library_init(allocator);

    signable = aws_signable_new_http_request(allocator, request);
    if (signable == NULL) {
        goto done;
    }

    signer = aws_signer_new_aws(allocator);
    if (signer == NULL) {
        goto done;
    }

    if (aws_signing_result_init(&signing_result, allocator)) {
        goto done;
    }

    struct aws_credentials_provider_profile_options provider_options;
    AWS_ZERO_STRUCT(provider_options);

    provider = aws_credentials_provider_new_profile(allocator, &provider_options);
    if (provider == NULL) {
        goto done;
    }

    if (s_aws_credentials_waiter_init(&credentials_waiter)) {
        goto done;
    }

    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, &credentials_waiter);
    s_aws_credentials_waiter_wait_on_credentials(&credentials_waiter);

    struct aws_hash_element *region_element = NULL;
    if (aws_hash_table_find(context, s_region_key, &region_element)) {
        goto done;
    }
    struct aws_string *region = region_element->value;

    struct aws_hash_element *service_element = NULL;
    if (aws_hash_table_find(context, s_service_key, &service_element)) {
        goto done;
    }
    struct aws_string *service = service_element->value;

    config.credentials = credentials_waiter.credentials;
    config.config_type = AWS_SIGNING_CONFIG_AWS;
    config.algorithm = AWS_SIGNING_ALGORITHM_SIG_V4_HEADER;
    config.region = aws_byte_cursor_from_c_str((const char *)region->bytes);
    config.service = aws_byte_cursor_from_c_str((const char *)service->bytes);
    config.use_double_uri_encode = true;
    config.should_normalize_uri_path = true;
    config.sign_body = false;

    aws_date_time_init_now(&config.date);

    if (aws_signer_sign_request(signer, signable, (void *)&config, &signing_result)) {
        goto done;
    }

    s_apply_signing_result_to_request(request, allocator, &signing_result);

    result = AWS_OP_SUCCESS;

done:

    s_aws_credentials_waiter_clean_up(&credentials_waiter);
    aws_credentials_provider_release(provider);
    aws_signer_destroy(signer);
    aws_signable_destroy(signable);

    aws_signing_result_clean_up(&signing_result);

    return result;
}
