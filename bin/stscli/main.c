/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/auth/credentials.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* Disable warnings about fopen() being insecure */
#    pragma warning(disable : 4204) /* Declared initializers */
#    pragma warning(disable : 4221) /* Local var in declared initializer */
#endif

#ifdef WIN32
// Windows does not need specific imports
#else
#    include <stdio.h>
#endif

struct app_ctx {
    struct aws_allocator *allocator;
    struct aws_mutex lock;
    struct aws_condition_variable signal;

    bool fetch_completed;
    struct aws_credentials *credentials;
};

static void s_get_credentials_callback(struct aws_credentials *credentials, int error_code, void *user_data) {
    (void)error_code;

    struct app_ctx *context = user_data;

    aws_mutex_lock(&context->lock);

    context->credentials = credentials;
    context->fetch_completed = true;
    aws_credentials_acquire(credentials);

    aws_mutex_unlock(&context->lock);
    aws_condition_variable_notify_one(&context->signal);
}

static bool s_received_credentials_callback(void *user_data) {
    struct app_ctx *context = user_data;

    return context->fetch_completed;
}

static void s_aws_wait_for_credentials_result(struct app_ctx *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(
        &context->signal, &context->lock, s_received_credentials_callback, context);
    aws_mutex_unlock(&context->lock);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage:\n");
        printf("  stscli [rolearn] [session-name]\n");
        return -1;
    }
    struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_STACKS, 15);

    aws_auth_library_init(allocator);

    struct app_ctx app_ctx;
    AWS_ZERO_STRUCT(app_ctx);
    app_ctx.allocator = allocator;
    app_ctx.signal = (struct aws_condition_variable)AWS_CONDITION_VARIABLE_INIT;
    aws_mutex_init(&app_ctx.lock);

    struct aws_event_loop_group *elg = aws_event_loop_group_new_default(allocator, 0, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = elg,
        .max_entries = 8,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = elg,
        .host_resolver = resolver,
    };
    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_tls_ctx_options tls_options;
    AWS_ZERO_STRUCT(tls_options);
    aws_tls_ctx_options_init_default_client(&tls_options, allocator);
    struct aws_tls_ctx *tls_ctx = aws_tls_client_ctx_new(allocator, &tls_options);

    aws_tls_ctx_options_clean_up(&tls_options);

    struct aws_credentials_provider_chain_default_options default_options = {
        .bootstrap = bootstrap,
        .tls_ctx = tls_ctx,
    };
    struct aws_credentials_provider *default_provider = aws_credentials_provider_new_chain_default(allocator, &default_options);

    struct aws_credentials_provider_sts_options sts_options = {
        .creds_provider = default_provider,
        .bootstrap = bootstrap,
        .tls_ctx = tls_ctx,
        .role_arn = aws_byte_cursor_from_c_str(argv[1]),
        .session_name = aws_byte_cursor_from_c_str(argv[2]),
        .duration_seconds = 3600,
    };
    struct aws_credentials_provider *sts_provider = aws_credentials_provider_new_sts(allocator, &sts_options);

    aws_credentials_provider_get_credentials(sts_provider, s_get_credentials_callback, &app_ctx);

    s_aws_wait_for_credentials_result(&app_ctx);

    aws_credentials_provider_release(sts_provider);
    aws_credentials_provider_release(default_provider);

    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(elg);

    if (tls_ctx) {
        aws_tls_ctx_release(tls_ctx);
    }

    aws_thread_join_all_managed();

    aws_auth_library_clean_up();

    return 0;
}
