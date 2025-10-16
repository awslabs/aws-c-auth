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
     * Connection bootstrap to use for any network connections
     * made while sourcing credentials.
     * Required.
     */
    struct aws_client_bootstrap *bootstrap;

    /*
     * Client TLS context to use when querying a http based provider.
     * Required.
     */
    struct aws_tls_ctx *tls_ctx;

    /*
     * Endpoint override for service endpoint. Leave null
     * to use default endpoint.
     */
    struct aws_string *endpoint;

    /*
     * account id associated with the credentials.
     */
    struct aws_string *account_id;

    /*
     * credentials provider that will be used a token in the underlying call.
     */
    struct aws_credentials_provider *token_provider;

    /*
     * Retry strategy override. If null default will be used.
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
    struct aws_string *account_id;
    struct aws_string *token;

    int status_code;
    int error_code;
    // implementation-specific parameters and errors
    void *parameters;
    enum aws_auth_errors error;
};

typedef int(make_request_fn)(struct aws_http_query_context *query_context);
typedef int(create_headers_fn)(struct aws_http_query_context *query_context);
typedef struct aws_byte_cursor(credentials_get_token_fn)(struct aws_credentials *credentials, void *user_data);
typedef void(clean_up_parameters_fn)(void *parameters);

/**
 * A table to hold implementation specific values for
 * an http credentials provider.
 */
struct aws_http_credentials_provider_request_vtable {
    /*
     * Creates the request to be sent via the underlying http client.
     */
    make_request_fn *make_request_fn;
    /*
     * Creates the headers that are send alongside
     * the request to the underlying http client/
     */
    create_headers_fn *create_headers_fn;
    /*
     * Fetches the authentication token to be used alongside the requst.
     */
    credentials_get_token_fn *credentials_get_token_fn;
    /*
     * cleans up the parameters that are provided to the implemetatnion.
     */
    clean_up_parameters_fn *clean_up_parameters_fn;
    /*
     * owning pointer to implementation specific data. i.e.e values that
     * could be used during request creation.
     */
    void *parameters;

    /*
     * error that will be emitted when a credentials call fails.
     */
    enum aws_auth_errors error;
};

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
/**
 * Initializes a underlying http based credentials provider.
 *
 * @param allocator memory allocator to use
 * @param provider allocated instance of provider that will be initialized with
 * a http based credentials fetching implementation.
 * @param options standard http options.
 * @param request_vtable implementation specific branching for http based providers
 * such as hot to create requests.
 * @return error code if encountered.
 */
int aws_http_credentials_provider_init_base(
    struct aws_allocator *allocator,
    struct aws_credentials_provider *provider,
    struct aws_credentials_provider_http_options *options,
    struct aws_http_credentials_provider_request_vtable *request_vtable);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_HTTP_CREDENTIALS_PROVIDER_H */
