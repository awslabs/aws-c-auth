/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/sigv4_http_request.h>

#include <aws/auth/credentials.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/auth/signing_result.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/uri.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

#define DEFAULT_QUERY_PARAM_COUNT 10

/*
 * Uses the signing result to rebuild the request's URI.  If the signing was not done via
 * query params, then this ends up doing nothing.
 */
static int s_build_request_uri(
    struct aws_allocator *allocator,
    struct aws_http_message *request,
    const struct aws_signing_result *signing_result) {

    /* first let's see if we need to do anything at all */
    struct aws_array_list *result_param_list = NULL;
    if (aws_signing_result_get_property_list(
            signing_result, g_aws_http_query_params_property_list_name, &result_param_list) ||
        result_param_list == NULL) {
        return AWS_OP_SUCCESS;
    }

    /*
     * There are query params to apply.  Use the following algorithm:
     *
     * (1) Take the old uri and parse it into a URI structure
     * (2) Make a new URI builder and add the old URI's components to it
     * (3) Add the signing query params to the builder
     * (4) Use the builder to make a new URI
     */
    int result = AWS_OP_ERR;
    size_t signed_query_param_count = aws_array_list_length(result_param_list);

    struct aws_uri old_uri;
    AWS_ZERO_STRUCT(old_uri);

    struct aws_uri new_uri;
    AWS_ZERO_STRUCT(new_uri);

    struct aws_uri_builder_options new_uri_builder;
    AWS_ZERO_STRUCT(new_uri_builder);

    struct aws_array_list query_params;
    AWS_ZERO_STRUCT(query_params);

    struct aws_byte_cursor old_path;
    aws_http_message_get_request_path(request, &old_path);

    /* start with the old uri and parse it */
    if (aws_uri_init_parse(&old_uri, allocator, &old_path)) {
        goto done;
    }

    /* pull out the old query params */
    if (aws_array_list_init_dynamic(
            &query_params, allocator, DEFAULT_QUERY_PARAM_COUNT, sizeof(struct aws_uri_param))) {
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
        struct aws_signing_result_property source_param;
        if (aws_array_list_get_at(result_param_list, &source_param, i)) {
            goto done;
        }

        struct aws_uri_param signed_param;
        signed_param.key = aws_byte_cursor_from_string(source_param.name);
        signed_param.value = aws_byte_cursor_from_string(source_param.value);

        aws_array_list_push_back(&query_params, &signed_param);
    }

    /* create the new uri */
    if (aws_uri_init_from_builder_options(&new_uri, allocator, &new_uri_builder)) {
        goto done;
    }

    /* copy the full string */
    struct aws_byte_cursor new_uri_cursor = aws_byte_cursor_from_buf(&new_uri.uri_str);
    if (aws_http_message_set_request_path(request, new_uri_cursor)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_array_list_clean_up(&query_params);

    aws_uri_clean_up(&new_uri);
    aws_uri_clean_up(&old_uri);

    return result;
}

/*
 * Takes a mutable http request and adds all the additional query params and/or headers generated by the
 * signing process.
 */
int aws_apply_signing_result_to_http_request(
    struct aws_http_message *request,
    struct aws_allocator *allocator,
    const struct aws_signing_result *result) {

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
        AWS_ZERO_STRUCT(source_header);

        if (aws_array_list_get_at(result_header_list, &source_header, i)) {
            return AWS_OP_ERR;
        }

        if (source_header.name == NULL || source_header.value == NULL) {
            return AWS_OP_ERR;
        }

        struct aws_http_header dest_header = {.name = aws_byte_cursor_from_string(source_header.name),
                                              .value = aws_byte_cursor_from_string(source_header.value)};
        aws_http_message_add_header(request, dest_header);
    }

    return AWS_OP_SUCCESS;
}

/*
 * This is a simple aws_signable wrapper implementation for the aws_http_message struct
 */
struct aws_signable_http_request_impl {
    struct aws_http_message *request;
    struct aws_array_list headers;
};

static int s_aws_signable_http_request_get_property(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_byte_cursor *out_value) {

    struct aws_signable_http_request_impl *impl = signable->impl;

    AWS_ZERO_STRUCT(*out_value);

    /*
     * uri and method can be queried directly from the wrapper request
     */
    if (aws_string_eq(name, g_aws_http_uri_property_name)) {
        aws_http_message_get_request_path(impl->request, out_value);
    } else if (aws_string_eq(name, g_aws_http_method_property_name)) {
        aws_http_message_get_request_method(impl->request, out_value);
    } else {
        return AWS_OP_ERR;
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
    } else {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_signable_http_request_get_payload_stream(
    const struct aws_signable *signable,
    struct aws_input_stream **out_input_stream) {

    struct aws_signable_http_request_impl *impl = signable->impl;
    *out_input_stream = aws_http_message_get_body_stream(impl->request);

    return AWS_OP_SUCCESS;
}

static void s_aws_signable_http_request_destroy(struct aws_signable *signable) {
    if (signable == NULL) {
        return;
    }

    struct aws_signable_http_request_impl *impl = signable->impl;
    if (impl == NULL) {
        return;
    }

    aws_array_list_clean_up(&impl->headers);
    aws_mem_release(signable->allocator, signable);
}

static struct aws_signable_vtable s_signable_http_request_vtable = {
    .get_property = s_aws_signable_http_request_get_property,
    .get_property_list = s_aws_signable_http_request_get_property_list,
    .get_payload_stream = s_aws_signable_http_request_get_payload_stream,
    .destroy = s_aws_signable_http_request_destroy,
};

struct aws_signable *aws_signable_new_http_request(struct aws_allocator *allocator, struct aws_http_message *request) {

    struct aws_signable *signable = NULL;
    struct aws_signable_http_request_impl *impl = NULL;
    aws_mem_acquire_many(
        allocator, 2, &signable, sizeof(struct aws_signable), &impl, sizeof(struct aws_signable_http_request_impl));

    if (signable == NULL || impl == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*signable);
    AWS_ZERO_STRUCT(*impl);

    signable->allocator = allocator;
    signable->vtable = &s_signable_http_request_vtable;
    signable->impl = impl;

    /*
     * Copy the headers since they're not different types
     */
    size_t header_count = aws_http_message_get_header_count(request);
    if (aws_array_list_init_dynamic(
            &impl->headers, allocator, header_count, sizeof(struct aws_signable_property_list_pair))) {
        goto on_error;
    }

    for (size_t i = 0; i < header_count; ++i) {
        struct aws_http_header header;
        aws_http_message_get_header(request, &header, i);

        struct aws_signable_property_list_pair property = {.name = header.name, .value = header.value};
        aws_array_list_push_back(&impl->headers, &property);
    }

    impl->request = request;

    return signable;

on_error:

    aws_signable_destroy(signable);

    return NULL;
}

/*
 * Utility struct/API to let us wait on credentials resolution
 */
struct aws_signing_waiter {
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    bool done;

    struct aws_allocator *allocator;
    struct aws_http_message *request;
    int error_code;
};

static int s_aws_signing_waiter_init(
    struct aws_signing_waiter *waiter,
    struct aws_allocator *allocator,
    struct aws_http_message *request) {

    waiter->allocator = allocator;
    waiter->request = request;
    waiter->error_code = AWS_ERROR_SUCCESS;

    if (aws_mutex_init(&waiter->lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&waiter->signal)) {
        aws_mutex_clean_up(&waiter->lock);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_aws_signing_waiter_clean_up(struct aws_signing_waiter *waiter) {
    aws_mutex_clean_up(&waiter->lock);
    aws_condition_variable_clean_up(&waiter->signal);
}

void s_sign_callback(struct aws_signing_result *result, int error_code, void *user_data) {
    struct aws_signing_waiter *waiter = user_data;
    aws_mutex_lock(&waiter->lock);

    waiter->error_code = error_code;

    if (result) {
        aws_apply_signing_result_to_http_request(waiter->request, waiter->allocator, result);
    }

    waiter->done = true;
    aws_condition_variable_notify_one(&waiter->signal);
    aws_mutex_unlock(&waiter->lock);
}

bool s_wait_predicate(void *user_data) {
    struct aws_signing_waiter *waiter = user_data;

    return waiter->done;
}

void s_aws_signing_waiter_wait_on_credentials(struct aws_signing_waiter *waiter) {
    aws_mutex_lock(&waiter->lock);
    if (!waiter->done) {
        aws_condition_variable_wait_pred(&waiter->signal, &waiter->lock, s_wait_predicate, waiter);
    }
    aws_mutex_unlock(&waiter->lock);
}

AWS_STATIC_STRING_FROM_LITERAL(s_region_key, "region");
AWS_STATIC_STRING_FROM_LITERAL(s_service_key, "service");

int aws_sign_http_request_sigv4(struct aws_http_message *request, struct aws_allocator *allocator, void *user_data) {
    int result = AWS_OP_ERR;
    const struct aws_hash_table *context = user_data;

    struct aws_signing_result signing_result;
    AWS_ZERO_STRUCT(signing_result);

    struct aws_signing_config_aws config;
    AWS_ZERO_STRUCT(config);

    struct aws_signing_waiter signing_waiter;
    AWS_ZERO_STRUCT(signing_waiter);

    struct aws_credentials_provider_profile_options provider_options;
    AWS_ZERO_STRUCT(provider_options);

    struct aws_signable *signable = NULL;
    struct aws_credentials_provider *provider = NULL;

    aws_auth_library_init(allocator);

    /*
     * Initialize signable wrapper, signer, credentials provider
     */
    signable = aws_signable_new_http_request(allocator, request);
    if (signable == NULL) {
        goto done;
    }

    if (aws_signing_result_init(&signing_result, allocator)) {
        goto done;
    }

    provider = aws_credentials_provider_new_profile(allocator, &provider_options);
    if (provider == NULL) {
        goto done;
    }

    /*
     * Initialize credentials waiter and wait for credentials resolution
     */
    if (s_aws_signing_waiter_init(&signing_waiter, allocator, request)) {
        goto done;
    }

    /*
     * Pull out required context key-value pairs: region and service
     * We may add more context keys for signing algorithm and uri flags later
     */
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

    /*
     * configure the signing request
     */
    config.credentials_provider = provider;
    config.config_type = AWS_SIGNING_CONFIG_AWS;
    config.algorithm = AWS_SIGNING_ALGORITHM_V4;
    config.signature_type = AWS_ST_HTTP_REQUEST_HEADERS;
    config.region = aws_byte_cursor_from_string(region);
    config.service = aws_byte_cursor_from_string(service);
    config.flags.use_double_uri_encode = true;
    config.flags.should_normalize_uri_path = true;
    config.signed_body_value = AWS_SBVT_EMPTY;

    aws_date_time_init_now(&config.date);

    /*
     * Perform the signing process and apply the result to the request
     */
    if (aws_sign_request_aws(
            allocator, signable, (struct aws_signing_config_base *)&config, s_sign_callback, &config)) {
        goto done;
    }

    s_aws_signing_waiter_wait_on_credentials(&signing_waiter);

    if (signing_waiter.error_code) {
        result = aws_raise_error(signing_waiter.error_code);
    } else {
        result = AWS_OP_SUCCESS;
    }

done:

    s_aws_signing_waiter_clean_up(&signing_waiter);
    aws_credentials_provider_release(provider);
    aws_signable_destroy(signable);

    aws_signing_result_clean_up(&signing_result);

    return result;
}

/*
 * This is a simple aws_signable wrapper implementation for an s3 chunk
 */
struct aws_signable_chunk_impl {
    struct aws_input_stream *chunk_data;
    struct aws_string *previous_signature;
};

static int s_aws_signable_chunk_get_property(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_byte_cursor *out_value) {

    struct aws_signable_chunk_impl *impl = signable->impl;

    AWS_ZERO_STRUCT(*out_value);

    /*
     * uri and method can be queried directly from the wrapper request
     */
    if (aws_string_eq(name, g_aws_previous_signature_property_name)) {
        *out_value = aws_byte_cursor_from_string(impl->previous_signature);
    } else {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_signable_chunk_get_property_list(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_array_list **out_list) {
    (void)signable;
    (void)name;
    (void)out_list;

    return AWS_OP_ERR;
}

static int s_aws_signable_chunk_get_payload_stream(
    const struct aws_signable *signable,
    struct aws_input_stream **out_input_stream) {

    struct aws_signable_chunk_impl *impl = signable->impl;
    *out_input_stream = impl->chunk_data;

    return AWS_OP_SUCCESS;
}

static void s_aws_signable_chunk_destroy(struct aws_signable *signable) {
    if (signable == NULL) {
        return;
    }

    struct aws_signable_chunk_impl *impl = signable->impl;
    if (impl == NULL) {
        return;
    }

    aws_string_destroy(impl->previous_signature);

    aws_mem_release(signable->allocator, signable);
}

static struct aws_signable_vtable s_signable_chunk_vtable = {
    .get_property = s_aws_signable_chunk_get_property,
    .get_property_list = s_aws_signable_chunk_get_property_list,
    .get_payload_stream = s_aws_signable_chunk_get_payload_stream,
    .destroy = s_aws_signable_chunk_destroy,
};

struct aws_signable *aws_signable_new_chunk(
    struct aws_allocator *allocator,
    struct aws_input_stream *chunk_data,
    struct aws_byte_cursor previous_signature) {

    struct aws_signable *signable = NULL;
    struct aws_signable_chunk_impl *impl = NULL;
    aws_mem_acquire_many(
        allocator, 2, &signable, sizeof(struct aws_signable), &impl, sizeof(struct aws_signable_chunk_impl));

    if (signable == NULL || impl == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*signable);
    AWS_ZERO_STRUCT(*impl);

    signable->allocator = allocator;
    signable->vtable = &s_signable_chunk_vtable;
    signable->impl = impl;

    impl->chunk_data = chunk_data;
    impl->previous_signature = aws_string_new_from_array(allocator, previous_signature.ptr, previous_signature.len);
    if (impl->previous_signature == NULL) {
        goto on_error;
    }

    return signable;

on_error:

    aws_signable_destroy(signable);

    return NULL;
}
