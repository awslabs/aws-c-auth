#ifndef AWS_AUTH_EC2_METADATA_CLIENT_H
#define AWS_AUTH_EC2_METADATA_CLIENT_H

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/auth/private/credentials_utils.h>
#include <aws/http/connection_manager.h>
#include <aws/io/retry_strategy.h>

/*
 * EC2 IMDS_V1 takes one http request to get resource, while IMDS_V2 takes one more token (Http PUT) request
 * to get secure token used in following request.
 */
enum aws_imds_client_versions {
    /* defaults to try IMDS_V2, if IMDS_V2 is not available (on some old instances), fall back to IMDS_V1 */
    IMDS_CLIENT_V2,
    IMDS_CLIENT_V1,
};

struct aws_imds_client_system_vtable {
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

typedef void(aws_imds_client_shutdown_completed_fn)(void *user_data);

struct aws_imds_client_shutdown_options {
    aws_imds_client_shutdown_completed_fn *shutdown_callback;
    void *shutdown_user_data;
};

struct aws_imds_client_options {
    struct aws_imds_client_shutdown_options shutdown_options;
    struct aws_client_bootstrap *bootstrap;
    struct aws_retry_strategy *retry_strategy;
    /* If not set, this value will be false, means use IMDS_V2 */
    enum aws_imds_client_versions imds_version;
    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_imds_client_system_vtable *function_table;
};

typedef void(aws_imds_client_on_get_resource_callback_fn)(struct aws_byte_cursor resource, void *user_data);

AWS_EXTERN_C_BEGIN

/**
 * AWS EC2 Metadata Client is used to retrieve AWS EC2 Instance Metadata info.
 */
AWS_AUTH_API
struct aws_imds_client;

AWS_AUTH_API
struct aws_imds_client *aws_imds_client_new(
    struct aws_allocator *allocator,
    const struct aws_imds_client_options *options);

AWS_AUTH_API
void aws_imds_client_release(struct aws_imds_client *client);

AWS_AUTH_API
int aws_ec2_metadata_client_get_resource_async(
    struct aws_imds_client *client,
    struct aws_byte_cursor resource_path,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_CREDENTIALS_H */
