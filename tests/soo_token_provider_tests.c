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

#include <credentials_provider_utils.h>

#include "shared_credentials_test_definitions.h"

struct sso_session_profile_example {
    const char *name;
    struct aws_byte_cursor text;
};

static int s_sso_token_provider_profile_invalid_profile_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    static struct sso_session_profile_example s_invalid_profile_examples[] = {
        {
            .name = "No config",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(
                "[profile default]\naws_access_key_id=fake_access_key\naws_secret_access_key=fake_secret_key\n"),
        },
        {
            .name = "No sso-region",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[profile "
                                                          "default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_start_url=url\n"),
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

    aws_unset_environment_value(s_default_profile_env_variable_name);
    aws_unset_environment_value(s_default_config_path_env_variable_name);
    aws_unset_environment_value(s_default_credentials_path_env_variable_name);
    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_sso_token_provider_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_invalid_profile_examples); ++i) {
        printf("invalid example [%zu]: %s\n", i, s_invalid_profile_examples[i].name);
        struct aws_string *config_contents = aws_string_new_from_cursor(allocator, &s_invalid_profile_examples[i].text);
        ASSERT_SUCCESS(aws_create_profile_file(config_file_str, config_contents));
        ASSERT_NULL(aws_sso_token_provider_new_profile(allocator, &options));
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
                "1\nsso_start_url=url"),
        },
    };

    aws_unset_environment_value(s_default_profile_env_variable_name);
    aws_unset_environment_value(s_default_config_path_env_variable_name);
    aws_unset_environment_value(s_default_credentials_path_env_variable_name);
    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_sso_token_provider_profile_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
        .profile_name_override = NULL,
        .shutdown_options = NULL,
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_valid_profile_examples); ++i) {
        printf("valid example [%zu]: %s\n", i, s_valid_profile_examples[i].name);
        struct aws_string *config_contents = aws_string_new_from_cursor(allocator, &s_valid_profile_examples[i].text);
        ASSERT_SUCCESS(aws_create_profile_file(config_file_str, config_contents));
        struct aws_credentials_provider *provider = aws_sso_token_provider_new_profile(allocator, &options);
        ASSERT_NOT_NULL(provider);
        aws_credentials_provider_release(provider);
        aws_string_destroy(config_contents);
    }

    aws_string_destroy(config_file_str);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sso_token_provider_profile_valid_profile_test, s_sso_token_provider_profile_valid_profile_test);

static int s_sso_token_provider_sso_session_invalid_profile_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    static struct sso_session_profile_example s_invalid_profile_examples[] = {
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

    aws_unset_environment_value(s_default_profile_env_variable_name);
    aws_unset_environment_value(s_default_config_path_env_variable_name);
    aws_unset_environment_value(s_default_credentials_path_env_variable_name);
    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_sso_token_provider_sso_session_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_invalid_profile_examples); ++i) {
        printf("invalid example [%zu]: %s\n", i, s_invalid_profile_examples[i].name);
        struct aws_string *config_contents = aws_string_new_from_cursor(allocator, &s_invalid_profile_examples[i].text);
        ASSERT_SUCCESS(aws_create_profile_file(config_file_str, config_contents));
        ASSERT_NULL(aws_sso_token_provider_new_sso_session(allocator, &options));
        aws_string_destroy(config_contents);
    }

    aws_string_destroy(config_file_str);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    sso_token_provider_sso_session_invalid_profile_test,
    s_sso_token_provider_sso_session_invalid_profile_test);

static int s_sso_token_provider_sso_session_valid_profile_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    static struct sso_session_profile_example s_valid_profile_examples[] = {
        {
            .name = "sso-session",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_"
                                                          "session=dev\n[sso-session dev]\nsso_region=us-east-"
                                                          "1\nsso_start_url=url"),
        },
        {
            .name = "with nsso_region",
            .text = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("[default]\naws_access_key_id=fake_access_key\naws_secret_"
                                                          "access_key=fake_secret_key\nsso_region=us-east-1\nsso_"
                                                          "session=dev\n[sso-session dev]\nsso_region=us-east-"
                                                          "1\nsso_start_url=url"),
        },
        {
            .name = "with nsso_start_url",
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

    aws_unset_environment_value(s_default_profile_env_variable_name);
    aws_unset_environment_value(s_default_config_path_env_variable_name);
    aws_unset_environment_value(s_default_credentials_path_env_variable_name);
    struct aws_string *config_file_str = aws_create_process_unique_file_name(allocator);
    struct aws_sso_token_provider_sso_session_options options = {
        .config_file_name_override = aws_byte_cursor_from_string(config_file_str),
        .profile_name_override = NULL,
        .shutdown_options = NULL,
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_valid_profile_examples); ++i) {
        printf("valid example [%zu]: %s\n", i, s_valid_profile_examples[i].name);
        struct aws_string *config_contents = aws_string_new_from_cursor(allocator, &s_valid_profile_examples[i].text);
        ASSERT_SUCCESS(aws_create_profile_file(config_file_str, config_contents));
        struct aws_credentials_provider *provider = aws_sso_token_provider_new_sso_session(allocator, &options);
        ASSERT_NOT_NULL(provider);
        aws_credentials_provider_release(provider);
        aws_string_destroy(config_contents);
    }

    aws_string_destroy(config_file_str);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sso_token_provider_sso_session_valid_profile_test, s_sso_token_provider_sso_session_valid_profile_test);
