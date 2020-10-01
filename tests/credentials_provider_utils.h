#ifndef AWS_AUTH_CREDENTIALS_PROVIDER_MOCK_H
#define AWS_AUTH_CREDENTIALS_PROVIDER_MOCK_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/aws_profile.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>

struct aws_credentials;
struct aws_credentials_provider;
struct aws_credentials_provider_shutdown_options;
struct aws_event_loop_group;
struct aws_string;

/*
 * This file contains a number of helper functions and data structures
 * that let us verify async behavior within the credentials provider.
 *
 * It includes multiple provider mocks (one synchronous, one background-thread
 * based and externally controllable), a synchronizing controller that uses
 * concurrency primitives to ensure we can perform operations at troublesome
 * time points (freeze the cached background query so that we can queue up
 * multiple pending queries, for example), and misc supporting functions like
 * time function mocks.
 */

/*
 * test helper struct to correctly wait on async credentials callbacks
 */
struct aws_get_credentials_test_callback_result {
    struct aws_mutex sync;
    struct aws_condition_variable signal;
    struct aws_credentials *credentials;
    int count;
    int required_count;
    int last_error;
};

void aws_get_credentials_test_callback_result_init(
    struct aws_get_credentials_test_callback_result *result,
    int required_count);
void aws_get_credentials_test_callback_result_clean_up(struct aws_get_credentials_test_callback_result *result);

void aws_wait_on_credentials_callback(struct aws_get_credentials_test_callback_result *result);

void aws_test_get_credentials_async_callback(struct aws_credentials *credentials, int error_code, void *user_data);

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
    size_t result_count,
    struct aws_credentials_provider_shutdown_options *shutdown_options);

struct aws_credentials_provider *aws_credentials_provider_new_mock_async(
    struct aws_allocator *allocator,
    struct get_credentials_mock_result *results,
    size_t result_count,
    struct aws_event_loop_group *elg,
    struct aws_credentials_provider_shutdown_options *shutdown_options);

/* If any pending queries, deliver the next mock-result to all of them from another thread.
 * If no pending queries, nothing happens. */
void aws_credentials_provider_mock_async_fire_callbacks(struct aws_credentials_provider *provider);

/*
 * Simple global clock mocks
 */
int mock_aws_get_system_time(uint64_t *current_time);
void mock_aws_set_system_time(uint64_t current_time);

int mock_aws_get_high_res_time(uint64_t *current_time);
void mock_aws_set_high_res_time(uint64_t current_time);

/*
 * Credentials provider that always returns NULL.  Useful for chain tests.
 */
struct aws_credentials_provider *aws_credentials_provider_new_null(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_shutdown_options *shutdown_options);

#endif /* AWS_AUTH_CREDENTIALS_PROVIDER_MOCK_H */
