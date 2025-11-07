/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_HTTP_CREDENTIALS_PROVIDER_H
#define AWS_HTTP_CREDENTIALS_PROVIDER_H

#include <aws/auth/credentials.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>

AWS_PUSH_SANE_WARNING_LEVEL

/**
 * Configuration needed to create a underlying http client.
 */
struct aws_credentials_provider_http_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    /*
     * Required.
     * Connection bootstrap to use for any network connections
     * made while sourcing credentials.
     */
    struct aws_client_bootstrap *bootstrap;

    /*
     * Required.
     * Client TLS context to use when querying a http based provider.
     */
    struct aws_tls_ctx *tls_ctx;

    /*
     * Required
     * Maximum number of connections the underlying manager is
     * allowed to contain.
     */
    size_t max_connections;

    /*
     * Optional.
     * Endpoint override for service endpoint. Leave null
     * to use default endpoint.
     */
    struct aws_byte_cursor endpoint;

    /*
     * Optional
     * Retry strategy override. Leave null
     * to use default retry strategy.
     */
    struct aws_retry_strategy *retry_strategy;

    /* For mocking the http layer in tests, leave NULL otherwise */
    const struct aws_auth_http_system_vtable *function_table;
};

/**
 * aws_htttp_query_context - context for each outstanding http query.
 */
struct aws_http_query_context {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_credentials_provider *provider;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;

    /* mutable */
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_byte_buf payload;
    struct aws_retry_token *retry_token;
    struct aws_byte_buf path_and_query;

    int status_code;
    int error_code;

    // implementation-specific data and errors
    void *parameters;
    void *request_data;
};

typedef int(create_request_fn)(struct aws_http_query_context *query_context, void *user_data);
typedef void(finalize_credentials_fn)(struct aws_http_query_context *query_context);
typedef void(clean_up_parameters_fn)(void *parameters);
typedef void(create_request_data_fn)(struct aws_http_query_context *query_context);
typedef void(reset_request_data_fn)(struct aws_http_query_context *query_context);

/**
 * Implementation specific userdata for the http provider.
 */
struct aws_http_credentials_provider_user_data {
    /*
     * owning pointer to implementation specific data. i.e. values that
     * could be used during request creation.
     */
    void *parameters;

    /*
     * implementation specific callbacks for creating and cleaning up
     * the underlying http request,
     */
    struct aws_http_credentials_provider_request_vtable *request_vtable;
};

/**
 * A table to hold implementation specific values for
 * an http credentials provider.
 */
struct aws_http_credentials_provider_request_vtable {
    /*
     * Creates the request to be sent via the underlying http client.
     */
    create_request_fn *create_request_fn;

    /*
     * Creates credentials options. This is used to create the
     * credentials that are returned to the user
     */
    finalize_credentials_fn *finalize_credentials_fn;

    /*
     * cleans up the parameters that are provided to the implemetatnion.
     */
    clean_up_parameters_fn *clean_up_parameters_fn;

    /*
     * implementation specific data that is created each request.
     */
    create_request_data_fn *create_request_data_fn;

    /*
     * implementation specific data that is destroyed each request.
     */
    reset_request_data_fn *reset_request_data_fn;
};

AWS_EXTERN_C_BEGIN

/**
 * Initializes a underlying http based credentials provider.
 *
 * @param allocator memory allocator to use
 * @param provider allocated instance of provider that will be initialized with
 * a http based credentials fetching implementation.
 * @param options standard http options.
 * @param user_data implementation specific branching for http based providers
 * such as hot to create requests.
 * @return error code if encountered.
 */
AWS_AUTH_API
int aws_http_credentials_provider_init_base(
    struct aws_allocator *allocator,
    struct aws_credentials_provider *provider,
    struct aws_credentials_provider_http_options *options,
    struct aws_http_credentials_provider_user_data *user_data);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_HTTP_CREDENTIALS_PROVIDER_H */
