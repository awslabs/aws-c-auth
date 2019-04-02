#ifndef AWS_AUTH_CREDENTIALS_PROVIDER_MOCK_H
#define AWS_AUTH_CREDENTIALS_PROVIDER_MOCK_H

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

#include <aws/auth/private/aws_profile.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>

struct aws_credentials;
struct aws_credentials_provider;
struct aws_string;

/*
 * test helper struct to correctly wait on credentials callbacks
 */
struct aws_get_credentials_test_callback_result {
    struct aws_mutex sync;
    struct aws_condition_variable signal;
    struct aws_credentials *credentials;
    int count;
    int required_count;
};

void aws_get_credentials_test_callback_result_init(
    struct aws_get_credentials_test_callback_result *result,
    int required_count);
void aws_get_credentials_test_callback_result_clean_up(struct aws_get_credentials_test_callback_result *result);

void aws_wait_on_credentials_callback(struct aws_get_credentials_test_callback_result *result);

void aws_test_get_credentials_async_callback(struct aws_credentials *credentials, void *user_data);

struct get_credentials_mock_result {
    int error_code;
    struct aws_credentials *credentials;
};

/*
 * Mock credentials provider, synchronous
 */
struct aws_credentials_provider *aws_credentials_provider_new_mock(
    struct aws_allocator *allocator,
    struct get_credentials_mock_result *results,
    size_t result_count);

/*
 * Credentials provider that puts a mock provider in a background thread and uses signalling to control callback
 * invocation.  Useful to properly test query queuing during expiration
 */

struct aws_credentials_provider_mock_async_controller {
    struct aws_mutex sync;
    struct aws_condition_variable signal;
    bool should_fire_callback;
    bool should_quit;
};

void aws_credentials_provider_mock_async_controller_init(
    struct aws_credentials_provider_mock_async_controller *controller);
void aws_credentials_provider_mock_async_controller_clean_up(
    struct aws_credentials_provider_mock_async_controller *controller);

struct aws_credentials_provider *aws_credentials_provider_new_mock_async(
    struct aws_allocator *allocator,
    struct get_credentials_mock_result *results,
    size_t result_count,
    struct aws_credentials_provider_mock_async_controller *controller);

/*
 * Simple global clock mock
 */
int mock_aws_get_time(uint64_t *current_time);
void mock_aws_set_time(uint64_t current_time);

/*
 * Credentials provider that always returns NULL.  Useful for chain tests.
 */
struct aws_credentials_provider *aws_credentials_provider_new_null(struct aws_allocator *allocator);

#endif /* AWS_AUTH_CREDENTIALS_PROVIDER_MOCK_H */
