#ifndef AWS_AUTH_CREDENTIALS_PRIVATE_H
#define AWS_AUTH_CREDENTIALS_PRIVATE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/auth.h>
#include <aws/auth/credentials.h>
#include <aws/auth/external/cJSON.h>
#include <aws/http/connection_manager.h>

struct aws_http_connection;
struct aws_http_connection_manager;
struct aws_http_make_request_options;
struct aws_http_stream;

/*
 * Internal struct tracking an asynchronous credentials query.
 * Used by both the cached provider and the test mocks.
 *
 */
struct aws_credentials_query {
    struct aws_linked_list_node node;
    struct aws_credentials_provider *provider;
    aws_on_get_credentials_callback_fn *callback;
    void *user_data;
};

typedef struct aws_http_connection_manager *(aws_http_connection_manager_new_fn)(
    struct aws_allocator *allocator,
    struct aws_http_connection_manager_options *options);
typedef void(aws_http_connection_manager_release_fn)(struct aws_http_connection_manager *manager);
typedef void(aws_http_connection_manager_acquire_connection_fn)(
    struct aws_http_connection_manager *manager,
    aws_http_connection_manager_on_connection_setup_fn *callback,
    void *user_data);
typedef int(aws_http_connection_manager_release_connection_fn)(
    struct aws_http_connection_manager *manager,
    struct aws_http_connection *connection);
typedef struct aws_http_stream *(aws_http_connection_make_request_fn)(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);
typedef int(aws_http_stream_activate_fn)(struct aws_http_stream *stream);
typedef struct aws_http_connection *(aws_http_stream_get_connection_fn)(const struct aws_http_stream *stream);

typedef int(aws_http_stream_get_incoming_response_status_fn)(const struct aws_http_stream *stream, int *out_status);
typedef void(aws_http_stream_release_fn)(struct aws_http_stream *stream);
typedef void(aws_http_connection_close_fn)(struct aws_http_connection *connection);

/*
 * Table of all downstream http functions used by the credentials providers that make http calls. Allows for simple
 * mocking.
 */
struct aws_auth_http_system_vtable {
    aws_http_connection_manager_new_fn *aws_http_connection_manager_new;
    aws_http_connection_manager_release_fn *aws_http_connection_manager_release;

    aws_http_connection_manager_acquire_connection_fn *aws_http_connection_manager_acquire_connection;
    aws_http_connection_manager_release_connection_fn *aws_http_connection_manager_release_connection;

    aws_http_connection_make_request_fn *aws_http_connection_make_request;
    aws_http_stream_activate_fn *aws_http_stream_activate;
    aws_http_stream_get_connection_fn *aws_http_stream_get_connection;
    aws_http_stream_get_incoming_response_status_fn *aws_http_stream_get_incoming_response_status;
    aws_http_stream_release_fn *aws_http_stream_release;

    aws_http_connection_close_fn *aws_http_connection_close;
};

AWS_EXTERN_C_BEGIN

/*
 * Misc. credentials-related APIs
 */

AWS_AUTH_API
void aws_credentials_query_init(
    struct aws_credentials_query *query,
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn *callback,
    void *user_data);

AWS_AUTH_API
void aws_credentials_query_clean_up(struct aws_credentials_query *query);

AWS_AUTH_API
void aws_credentials_provider_init_base(
    struct aws_credentials_provider *provider,
    struct aws_allocator *allocator,
    struct aws_credentials_provider_vtable *vtable,
    void *impl);

AWS_AUTH_API
void aws_credentials_provider_destroy(struct aws_credentials_provider *provider);

AWS_AUTH_API
void aws_credentials_provider_invoke_shutdown_callback(struct aws_credentials_provider *provider);

struct aws_parse_credentials_from_json_doc_options {
    const char *access_key_id_name;
    const char *secrete_access_key_name;
    const char *token_name;
    const char *expiration_name;
    bool token_required;
    bool expiration_required;
};

/**
 * This API is used internally to parse credentials from json document.
 * It _ONLY_ parses the first level of json structure. json document like
 * this will produce a valid credentials:
 {
    "accessKeyId" : "...",
    "secretAccessKey" : "...",
    "Token" : "...",
    "expiration" : "2019-05-29T00:21:43Z"
 }
 * but json document like this won't:
 {
    "credentials": {
        "accessKeyId" : "...",
        "secretAccessKey" : "...",
        "sessionToken" : "...",
        "expiration" : "2019-05-29T00:21:43Z"
    }
 }
 * In general, the keys' names of credentials in json document are:
 * "AccessKeyId", "SecretAccessKey", "Token" and "Expiration",
 * but there are cases services use different keys like "sessionToken".
 * A valid credentials must have "access key" and "secrete access key".
 * For some services, token and expiration are not required.
 * So in this API, the keys are provided by callers and this API will
 * performe a case insensitive search.
 */
AWS_AUTH_API
struct aws_credentials *aws_parse_credentials_from_cjson_object(
    struct aws_allocator *allocator,
    struct cJSON *document_root,
    const struct aws_parse_credentials_from_json_doc_options *options);

/**
 * This API is similar to aws_parse_credentials_from_cjson_object,
 * except it accpets a char buffer json document as it's input.
 */
AWS_AUTH_API
struct aws_credentials *aws_parse_credentials_from_json_document(
    struct aws_allocator *allocator,
    const char *json_document,
    const struct aws_parse_credentials_from_json_doc_options *options);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_CREDENTIALS_PRIVATE_H */
