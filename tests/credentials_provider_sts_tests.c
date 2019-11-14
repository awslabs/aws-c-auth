/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/testing/aws_test_harness.h>
#include <aws/auth/credentials.h>
#include <aws/io/event_loop.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/common/condition_variable.h>

struct credentials_cb_data {
    struct aws_condition_variable cvar;
    struct aws_mutex mutex;
};

static void s_on_credentials_callback_fn(struct aws_credentials *credentials, void *user_data) {
    struct credentials_cb_data *cb_data = user_data;

    aws_condition_variable_notify_one(&cb_data->cvar);
}

static int s_credentials_provider_sts_default_tls_options(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);

    struct aws_event_loop_group el_group;
    aws_event_loop_group_default_init(&el_group, allocator, 0);

    struct aws_host_resolver resolver;
    aws_host_resolver_init_default(&resolver, allocator, 10, &el_group);

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &el_group, &resolver, NULL);

    struct aws_credentials_provider_chain_default_options default_options = {
            .bootstrap = bootstrap,
    };

    struct aws_credentials_provider_sts_options options = {
            .creds_provider = aws_credentials_provider_new_chain_default(allocator, &default_options),
            .bootstrap = bootstrap,
            .role_arn = aws_byte_cursor_from_c_str("arn:aws:iam::123124136734:role/assume_admin_role_testing"),
            .session_name = aws_byte_cursor_from_c_str("test_session"),
            .duration_seconds = 0,
    };

    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &options);

    struct credentials_cb_data cb_data = {
            .cvar = AWS_CONDITION_VARIABLE_INIT,
            .mutex = AWS_MUTEX_INIT,
    };

    aws_mutex_lock(&cb_data.mutex);
    aws_credentials_provider_get_credentials(sts_provider, s_on_credentials_callback_fn, &cb_data);

    aws_condition_variable_wait(&cb_data.cvar, &cb_data.mutex);
    aws_credentials_provider_get_credentials(sts_provider, s_on_credentials_callback_fn, &cb_data);
    aws_condition_variable_wait(&cb_data.cvar, &cb_data.mutex);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(credentials_provider_sts_default_tls_options, s_credentials_provider_sts_default_tls_options)