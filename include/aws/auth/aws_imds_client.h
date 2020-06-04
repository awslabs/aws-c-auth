#ifndef AWS_AUTH_IMDS_CLIENT_H
#define AWS_AUTH_IMDS_CLIENT_H

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
#include <aws/common/array_list.h>
#include <aws/common/date_time.h>
#include <aws/http/connection_manager.h>
#include <aws/io/retry_strategy.h>

/*
 * EC2 IMDS_V1 takes one http request to get resource, while IMDS_V2 takes one more token (Http PUT) request
 * to get secure token used in following request.
 */
enum aws_imds_protocol_version {
    /* defaults to try IMDS_PROTOCOL_V2, if IMDS_PROTOCOL_V2 is not available (on some old instances), fall back to
       IMDS_PROTOCOL_V1 */
    IMDS_PROTOCOL_V2,
    IMDS_PROTOCOL_V1,
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
    /* Defaults to IMDS_PROTOCOL_V2 */
    enum aws_imds_protocol_version imds_version;
    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_imds_client_system_vtable *function_table;
};

typedef void(
    aws_imds_client_on_get_resource_callback_fn)(const struct aws_byte_buf *resource, int error_code, void *user_data);

AWS_EXTERN_C_BEGIN

/**
 * AWS EC2 Metadata Client is used to retrieve AWS EC2 Instance Metadata info.
 */
struct aws_imds_client;

AWS_AUTH_API
struct aws_imds_client *aws_imds_client_new(
    struct aws_allocator *allocator,
    const struct aws_imds_client_options *options);

AWS_AUTH_API
void aws_imds_client_acquire(struct aws_imds_client *client);

AWS_AUTH_API
void aws_imds_client_release(struct aws_imds_client *client);

AWS_AUTH_API
int aws_imds_client_get_resource_async(
    struct aws_imds_client *client,
    struct aws_byte_cursor resource_path,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

/**
 * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html
 */
struct aws_imds_iam_profile {
    struct aws_date_time last_updated;
    struct aws_byte_cursor instance_profile_arn;
    struct aws_byte_cursor instance_profile_id;
};

/**
 * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
 */
struct aws_imds_instance_info {
    /* an array of aws_byte_cursor */
    struct aws_array_list marketplace_product_codes;
    struct aws_byte_cursor availability_zone;
    struct aws_byte_cursor private_ip;
    struct aws_byte_cursor version;
    struct aws_byte_cursor instance_id;
    /* an array of aws_byte_cursor */
    struct aws_array_list billing_products;
    struct aws_byte_cursor instance_type;
    struct aws_byte_cursor account_id;
    struct aws_byte_cursor image_id;
    struct aws_date_time pending_time;
    struct aws_byte_cursor architecture;
    struct aws_byte_cursor kernel_id;
    struct aws_byte_cursor ramdisk_id;
    struct aws_byte_cursor region;
};

/* the item typed stored in array is pointer to aws_byte_cursor */
typedef void(
    aws_imds_client_on_get_array_callback_fn)(const struct aws_array_list *array, int error_code, void *user_data);

typedef void(aws_imds_client_on_get_credentials_callback_fn)(
    const struct aws_credentials *credentials,
    int error_code,
    void *user_data);

typedef void(aws_imds_client_on_get_iam_profile_callback_fn)(
    const struct aws_imds_iam_profile *iam_profile_info,
    int error_code,
    void *user_data);

typedef void(aws_imds_client_on_get_instance_info_callback_fn)(
    const struct aws_imds_instance_info *instance_info,
    int error_code,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_ami_id(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_ami_launch_index(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_ami_manifest_path(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_ancestor_ami_ids(
    struct aws_imds_client *client,
    aws_imds_client_on_get_array_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_instance_action(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_instance_id(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_instance_type(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_mac_address(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_private_ip_address(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_availability_zone(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_product_codes(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_public_key(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_ramdisk_id(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_reservation_id(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_security_groups(
    struct aws_imds_client *client,
    aws_imds_client_on_get_array_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_block_device_mapping(
    struct aws_imds_client *client,
    aws_imds_client_on_get_array_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_attached_iam_role(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_credentials(
    struct aws_imds_client *client,
    struct aws_byte_cursor iam_role_name,
    aws_imds_client_on_get_credentials_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_iam_profile(
    struct aws_imds_client *client,
    aws_imds_client_on_get_iam_profile_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_user_data(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_instance_signature(
    struct aws_imds_client *client,
    aws_imds_client_on_get_resource_callback_fn callback,
    void *user_data);

AWS_AUTH_API
int aws_imds_client_get_instance_info(
    struct aws_imds_client *client,
    aws_imds_client_on_get_instance_info_callback_fn callback,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_IMDS_CLIENT_H */
