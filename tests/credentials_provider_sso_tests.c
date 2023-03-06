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
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>

static int s_credentials_provider_sso_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_sso_token_provider_sso_session_options options;
    AWS_ZERO_STRUCT(options);
    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    return 0;
}
AWS_TEST_CASE(credentials_provider_sso_new_destroy, s_credentials_provider_sso_new_destroy);
