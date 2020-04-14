#ifndef AWS_AUTH_CREDENTIALS_PRIVATE_H
#define AWS_AUTH_CREDENTIALS_PRIVATE_H

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

#include <aws/auth/auth.h>

#include <aws/auth/credentials.h>

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
struct aws_credentials_provider_system_vtable {
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

AWS_EXTERN_C_END

#endif /* AWS_AUTH_CREDENTIALS_PRIVATE_H */
