/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/auth/credentials.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/environment.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/tls_channel_handler.h>

#include <credentials_provider_utils.h>

#include "shared_credentials_test_definitions.h"

struct sso_session_profile_example {
    const char *name;
    struct aws_byte_cursor text;
};

static int s_sso_token_provider_profile_invalid_profile_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct sso_session_profile_example invalid_profile_examples[] = {
        {
            .name = "No config",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(
                "[profile default]\naws_access_key_id=fake_access_key\naws_secret_access_key=fake_secret_key\n"),
        },
        {
            .name = "No sso_start_url",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[profile "
                                                          "default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_region=us-east-1\n"),
        },
        {
            .name = "only sso_session",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[profile "
                                                          "default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_session=dev\n[sso-session "
                                                          "dev]\nsso_start_url=url\nsso_region=us-east-1"),
        },
    };

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_token_provider_sso_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(invalid_profile_examples); ++i) {
        printf("invalid example [%zu]: %s\n", i, invalid_profile_examples[i].name);
        struct aws_string *config_contents = aws_string_new_from_cursor(allocator, &invalid_profile_examples[i].text);
        ASSERT_SUCCESS(aws_create_profile_file(config_file_str, config_contents));
        ASSERT_NULL(aws_token_provider_new_sso_profile(allocator, &options));
        aws_string_destroy(config_contents);
    }

    aws_string_destroy(config_file_str);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sso_token_provider_profile_invalid_profile_test, s_sso_token_provider_profile_invalid_profile_test);

static int s_sso_token_provider_profile_valid_profile_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    static struct sso_session_profile_example s_valid_profile_examples[] = {
        {
            .name = "profile",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_region=us-east-"
                                                          "1\nsso_start_url=url"),
        },
        {
            .name = "with sso_session",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(
                "[default]\naws_access_key_id=fake_access_key\naws_secret_"
                "access_key=fake_secret_key\nsso_region=us-east-1\nsso_start_url=url\nsso_"
                "session=dev\n[sso-session dev]\nsso_region=us-east-"
                "1\nsso_start_url=url2"),
        },
    };

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_token_provider_sso_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_valid_profile_examples); ++i) {
        printf("valid example [%zu]: %s\n", i, s_valid_profile_examples[i].name);
        struct aws_string *config_contents = aws_string_new_from_cursor(allocator, &s_valid_profile_examples[i].text);
        ASSERT_SUCCESS(aws_create_profile_file(config_file_str, config_contents));
        struct aws_credentials_provider *provider = aws_token_provider_new_sso_profile(allocator, &options);
        ASSERT_NOT_NULL(provider);
        aws_credentials_provider_release(provider);
        aws_string_destroy(config_contents);
    }

    aws_string_destroy(config_file_str);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sso_token_provider_profile_valid_profile_test, s_sso_token_provider_profile_valid_profile_test);

static struct aws_mock_token_provider_sso_tester {
    struct aws_tls_ctx *tls_ctx;
    struct aws_event_loop_group *el_group;
    struct aws_host_resolver *resolver;
    struct aws_client_bootstrap *bootstrap;

    struct aws_mutex lock;
    struct aws_condition_variable signal;
    struct aws_credentials *credentials;
    bool has_received_credentials_callback;
    bool has_received_shutdown_callback;
    int error_code;

} s_tester;

static int s_aws_mock_token_provider_sso_tester_init(struct aws_allocator *allocator) {
    aws_auth_library_init(allocator);

    AWS_ZERO_STRUCT(s_tester);

    struct aws_tls_ctx_options tls_ctx_options;
    aws_tls_ctx_options_init_default_client(&tls_ctx_options, allocator);
    s_tester.tls_ctx = aws_tls_client_ctx_new(allocator, &tls_ctx_options);
    ASSERT_NOT_NULL(s_tester.tls_ctx);

    s_tester.el_group = aws_event_loop_group_new_default(allocator, 0, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = s_tester.el_group,
        .max_entries = 8,
    };
    s_tester.resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = s_tester.el_group,
        .host_resolver = s_tester.resolver,
    };
    s_tester.bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    return AWS_OP_SUCCESS;
}

void s_aws_mock_token_provider_sso_tester_cleanup(void) {
    aws_tls_ctx_release(s_tester.tls_ctx);
    aws_client_bootstrap_release(s_tester.bootstrap);
    aws_host_resolver_release(s_tester.resolver);
    aws_event_loop_group_release(s_tester.el_group);

    aws_condition_variable_clean_up(&s_tester.signal);
    aws_mutex_clean_up(&s_tester.lock);
    aws_credentials_release(s_tester.credentials);
    aws_auth_library_clean_up();
}

static int s_sso_token_provider_sso_session_invalid_config_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_aws_mock_token_provider_sso_tester_init(allocator);
    const struct sso_session_profile_example invalid_config_examples[] = {
        {
            .name = "no sso-session",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_region=us-east-"
                                                          "1\nsso_start_url=url"),
        },
        {
            .name = "sso_session with different profile region",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(
                "[profile "
                "default]\naws_access_key_id=fake_access_key\naws_secret_"
                "access_key=fake_secret_key\nsso_session=dev\nsso_region=us-west-"
                "1\nsso_start_url=url\n[sso-session dev]\nsso_region=us-east-1\nsso_start_url=url"),
        },
        {
            .name = "sso_session with different profile start url",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(
                "[profile "
                "default]\naws_access_key_id=fake_access_key\naws_secret_"
                "access_key=fake_secret_key\nsso_session=dev\nsso_region=us-east-"
                "1\nsso_start_url=url\n[sso-session dev]\nsso_region=us-east-1\nsso_start_url=url2"),
        },
        {
            .name = "different sso_session name",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(
                "[default]\naws_access_key_id=fake_access_key\naws_secret_"
                "access_key=fake_secret_key\nsso_region=us-east-1\nsso_start_url=url\nsso_"
                "session=dev\n[sso-session dev2]\nsso_region=us-east-"
                "1\nsso_start_url=url"),
        },
    };

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_token_provider_sso_session_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
        .tls_ctx = s_tester.tls_ctx,
        .bootstrap = s_tester.bootstrap,
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(invalid_config_examples); ++i) {
        printf("invalid example [%zu]: %s\n", i, invalid_config_examples[i].name);
        struct aws_string *config_contents = aws_string_new_from_cursor(allocator, &invalid_config_examples[i].text);
        ASSERT_SUCCESS(aws_create_profile_file(config_file_str, config_contents));
        ASSERT_NULL(aws_token_provider_new_sso_session(allocator, &options));
        aws_string_destroy(config_contents);
    }

    aws_string_destroy(config_file_str);
    s_aws_mock_token_provider_sso_tester_cleanup();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sso_token_provider_sso_session_invalid_config_test, s_sso_token_provider_sso_session_invalid_config_test);

static int s_sso_token_provider_sso_session_valid_config_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_aws_mock_token_provider_sso_tester_init(allocator);

    static struct sso_session_profile_example s_valid_profile_examples[] = {
        {
            .name = "sso-session",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_"
                                                          "session=dev\n[sso-session dev]\nsso_region=us-east-"
                                                          "1\nsso_start_url=url"),
        },
        {
            .name = "with sso_region",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_region=us-east-1\nsso_"
                                                          "session=dev\n[sso-session dev]\nsso_region=us-east-"
                                                          "1\nsso_start_url=url"),
        },
        {
            .name = "with sso_start_url",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_start_url=url\nsso_"
                                                          "session=dev\n[sso-session dev]\nsso_region=us-east-"
                                                          "1\nsso_start_url=url"),
        },
        {
            .name = "with profile",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(
                "[default]\naws_access_key_id=fake_access_key\naws_secret_"
                "access_key=fake_secret_key\nsso_region=us-east-1\nsso_start_url=url\nsso_"
                "session=dev\n[sso-session dev]\nsso_region=us-east-"
                "1\nsso_start_url=url"),
        },
    };

    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_token_provider_sso_session_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
        .tls_ctx = s_tester.tls_ctx,
        .bootstrap = s_tester.bootstrap,
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_valid_profile_examples); ++i) {
        printf("valid example [%zu]: %s\n", i, s_valid_profile_examples[i].name);
        struct aws_string *config_contents = aws_string_new_from_cursor(allocator, &s_valid_profile_examples[i].text);
        ASSERT_SUCCESS(aws_create_profile_file(config_file_str, config_contents));
        struct aws_credentials_provider *provider = aws_token_provider_new_sso_session(allocator, &options);
        ASSERT_NOT_NULL(provider);
        aws_credentials_provider_release(provider);
        aws_string_destroy(config_contents);
    }

    aws_string_destroy(config_file_str);
    s_aws_mock_token_provider_sso_tester_cleanup();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sso_token_provider_sso_session_valid_config_test, s_sso_token_provider_sso_session_valid_config_test);
