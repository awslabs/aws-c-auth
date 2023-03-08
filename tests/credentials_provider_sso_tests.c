/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include "shared_credentials_test_definitions.h"
#include <aws/auth/credentials.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/date_time.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>

static bool s_has_tester_received_credentials_callback(void *user_data) {
    (void)user_data;

    return false;
}
static void s_get_credentials_callback(struct aws_credentials *credentials, int error_code, void *user_data) {
    (void)user_data;
    (void)credentials;
    printf("get credentials callback, %d", error_code);
}

static int s_credentials_provider_sso_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);
    struct aws_credentials_provider_sso_options options;
    AWS_ZERO_STRUCT(options);
    options.profile_name_override = aws_byte_cursor_from_c_str("AdministratorAccess-069542832437");

    struct aws_tls_ctx_options tls_options;
    aws_tls_ctx_options_init_default_client(&tls_options, allocator);
    options.tls_ctx = aws_tls_client_ctx_new(allocator, &tls_options);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 0, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 8,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = el_group,
        .host_resolver = resolver,
    };
    options.bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    aws_credentials_provider_get_credentials(provider, s_get_credentials_callback, NULL);
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    if (aws_mutex_init(&lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&signal)) {
        return AWS_OP_ERR;
    }

    aws_condition_variable_wait_pred(&signal, &lock, s_has_tester_received_credentials_callback, NULL);

    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_new_destroy, s_credentials_provider_sso_new_destroy);
