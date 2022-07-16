/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include "shared_credentials_test_definitions.h"
#include <aws/auth/credentials.h>
#include <aws/auth/private/aws_profile.h>
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

static struct aws_mock_sso_tester {
    struct aws_tls_ctx *tls_ctx;

    struct aws_mutex lock;
    struct aws_condition_variable signal;

    struct aws_event_loop_group *el_group;
    struct aws_client_bootstrap *bootstrap;

    bool has_received_shutdown_callback;

    int attempts;
    int response_code;
    int error_code;
} s_tester;

static void s_on_shutdown_complete(void *user_data) {
    (void)user_data;

    aws_mutex_lock(&s_tester.lock);
    s_tester.has_received_shutdown_callback = true;
    aws_mutex_unlock(&s_tester.lock);

    aws_condition_variable_notify_one(&s_tester.signal);
}

static bool s_has_tester_received_shutdown_callback(void *user_data) {
    (void)user_data;

    return s_tester.has_received_shutdown_callback;
}

static void s_aws_wait_for_provider_shutdown_callback(void) {
    aws_mutex_lock(&s_tester.lock);
    aws_condition_variable_wait_pred(&s_tester.signal, &s_tester.lock, s_has_tester_received_shutdown_callback, NULL);
    aws_mutex_unlock(&s_tester.lock);
}

/**
 * Create the directory components of @path:
 * - if @path ends in a path separator, create every directory component;
 * - else, stop at the last path separator (parent directory of @path).
 */
static int s_create_directory_components(
        struct aws_allocator *allocator,
        const struct aws_string *path) {
    const char local_platform_separator = aws_get_platform_directory_separator();

    /* Create directory components and ensure use of platform separator at the same time. */
    for (size_t i = 0; i < path->len; ++i) {
        if (aws_is_any_directory_separator((char)path->bytes[i])) {
            ((char *)path->bytes)[i] = local_platform_separator;

            struct aws_string *segment = aws_string_new_from_array(allocator, path->bytes, i);
            int rc = aws_directory_create(segment);
            aws_string_destroy(segment);

            if (rc != AWS_OP_SUCCESS) {
                return rc;
            }
        }
    }
    return AWS_OP_SUCCESS;
}

/**
 * Point AWS_CONFIG_FILE to a local profile created from @config_contents.
 * Set AWS_PROFILE to the "foo" profile (should exist in @config_contents).
 */
static int s_sso_provider_init_config_profile(
        struct aws_allocator *allocator,
        const struct aws_string *config_contents) {
    AWS_STATIC_STRING_FROM_LITERAL(s_sso_foo_profile, "foo");
    struct aws_string *config_file_path_str = aws_create_process_unique_file_name(allocator);
    ASSERT_NOT_NULL(config_file_path_str);

    ASSERT_SUCCESS(aws_create_profile_file(config_file_path_str, config_contents));

    ASSERT_SUCCESS(aws_set_environment_value(s_default_config_path_env_variable_name, config_file_path_str));
    ASSERT_SUCCESS(aws_set_environment_value(s_default_profile_env_variable_name, s_sso_foo_profile));

    aws_string_destroy(config_file_path_str);
    return AWS_OP_SUCCESS;
}

/**
 * Return the value of the sso_start_url for the given $AWS_PROFILE in $AWS_CONFIG_FILE.
 * This is used to construct access token paths from dynamically loaded profiles.
 */
static struct aws_string *s_sso_extract_start_url_from_profile(struct aws_allocator *allocator) {
    AWS_STRING_FROM_LITERAL(s_sso_start_url, "sso_start_url");
    struct aws_string *result_sso_start_url = NULL;
    struct aws_profile_collection *config_profile = NULL;
    struct aws_string *config_file_path = NULL;
    struct aws_string *profile_name = NULL;

    config_file_path = aws_get_config_file_path(allocator, NULL);
    if (!config_file_path) {
        goto error;
    }

    profile_name = aws_get_profile_name(allocator, NULL);
    if (!profile_name) {
        goto error;
    }

    config_profile = aws_profile_collection_new_from_file(allocator, config_file_path, AWS_PST_CONFIG);
    if (!config_profile) {
        goto error;
    }

    const struct aws_profile *profile = aws_profile_collection_get_profile(config_profile, profile_name);
    if (!profile) {
        goto error;
    }

    const struct aws_profile_property *sso_start_url = aws_profile_get_property(profile, s_sso_start_url);
    if (!sso_start_url) {
        goto error;
    }

    result_sso_start_url = aws_string_new_from_string(allocator, aws_profile_property_get_value(sso_start_url));

error:
    aws_profile_collection_destroy(config_profile);
    aws_string_destroy(config_file_path);
    aws_string_destroy(profile_name);

    return result_sso_start_url;
}

static int s_aws_sso_tester_init(struct aws_allocator *allocator) {
    aws_auth_library_init(allocator);

    struct aws_tls_ctx_options tls_options;
    aws_tls_ctx_options_init_default_client(&tls_options, allocator);
    s_tester.tls_ctx = aws_tls_client_ctx_new(allocator, &tls_options);
    ASSERT_NOT_NULL(s_tester.tls_ctx);

    if (aws_mutex_init(&s_tester.lock)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&s_tester.signal)) {
        return AWS_OP_ERR;
    }

    /* Event loop is needed since SSO uses a retry strategy. */
    s_tester.el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = s_tester.el_group,
        .user_data = NULL,
        .host_resolution_config = NULL,
        .host_resolver = NULL,
        .on_shutdown_complete = NULL,
    };
    s_tester.bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(s_tester.bootstrap);

    return AWS_OP_SUCCESS;
}

static void s_aws_sso_tester_cleanup(void) {
    aws_event_loop_group_release(s_tester.el_group);
    aws_client_bootstrap_release(s_tester.bootstrap);
    aws_tls_ctx_release(s_tester.tls_ctx);
    aws_condition_variable_clean_up(&s_tester.signal);
    aws_mutex_clean_up(&s_tester.lock);
    aws_auth_library_clean_up();
}

/*
 * sso_access_token_path tests.
 */
extern struct aws_string *sso_access_token_path(struct aws_allocator *allocator, const struct aws_string *sso_start_url);

static int s_credentials_provider_sso_access_token_path_not_null(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_string *url_str = aws_string_new_from_c_str(allocator, "https://some.url/start");
    struct aws_string *empty_str = aws_string_new_from_c_str(allocator, "");

    aws_auth_library_init(allocator);

    struct aws_string *token_path = sso_access_token_path(allocator, url_str);
    ASSERT_NOT_NULL(token_path);
    aws_string_destroy(token_path);

    token_path = sso_access_token_path(allocator, empty_str);
    ASSERT_NOT_NULL(token_path);
    aws_string_destroy(token_path);

    aws_string_destroy(url_str);
    aws_string_destroy(empty_str);

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    credentials_provider_sso_access_token_path_not_null,
    s_credentials_provider_sso_access_token_path_not_null);

/* Table-driven test for sha1 sums of given (SSO Start) URLs. */
static int s_credentials_provider_sso_access_token_path_sha1(struct aws_allocator *allocator, void *ctx) {
    const struct {
        const char *url;
        const char *sha1_sum;
    } sha1_sums[] = {
        { "https://www.google.com", "ef7efc9839c3ee036f023e9635bc3b056d6ee2db" },
        { "https://www.amazon.com/", "b7bccaa77123d0c319a96ef4bce9b8fb817a0619" },
        { "https://aws.amazon.com", "87f8a6e65508244be74d473a01f9287f009ab21b" },
        { "https://aws.amazon.com/", "bcf19c5764665c6db5bd1069e983a29edc433e65" },
        { "https://aws.amazon.com/console/", "f302445b142e6456ee7219099e2f48de7bb646e7" },
    };

    aws_auth_library_init(allocator);

    for (int i = 0; i < sizeof(sha1_sums)/sizeof(sha1_sums[0]); i++) {
        struct aws_string *url_str = aws_string_new_from_c_str(allocator, sha1_sums[i].url);
        struct aws_string *token_path = sso_access_token_path(allocator, url_str);
        struct aws_byte_cursor sha1_cursor = aws_byte_cursor_from_c_str(sha1_sums[i].sha1_sum);
        struct aws_byte_cursor token_cursor = aws_byte_cursor_from_string(token_path);
        struct aws_byte_cursor find_cursor = {0};

        ASSERT_SUCCESS(aws_byte_cursor_find_exact(&token_cursor, &sha1_cursor, &find_cursor));

        aws_string_destroy(url_str);
        aws_string_destroy(token_path);
    }

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    credentials_provider_sso_access_token_path_sha1,
    s_credentials_provider_sso_access_token_path_sha1);

/* Environment variable content to redirect $HOME to "here". */
AWS_STATIC_STRING_FROM_LITERAL(s_home_env_var, "HOME");
AWS_STATIC_STRING_FROM_LITERAL(s_home_here, ".");

static int s_credentials_provider_sso_provider_profile_file_missing(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    s_aws_sso_tester_init(allocator);

    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    struct aws_credentials_provider_profile_options options = {0};

    options.tls_ctx = s_tester.tls_ctx;

    /* Redirect $HOME to a place that has no .aws/config file. */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_here));

    ASSERT_PTR_EQUALS(NULL, aws_credentials_provider_new_sso(allocator, &options));

    /* Clean up */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);

    s_aws_sso_tester_cleanup();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
        credentials_provider_sso_provider_profile_file_missing,
        s_credentials_provider_sso_provider_profile_file_missing);

AWS_STATIC_STRING_FROM_LITERAL(
    sso_test_profile_contents,
    "[profile default]\n"
    "sso_start_url = https://sso-default.awsapps.com/start\n"
    "sso_region = us-east-1\n"
    "sso_account_id = 270484358888\n"
    "sso_role_name = Tester\n"
    "region = us-east-1\n"
    "output = json\n"
    "[profile foo]\n"
    "sso_start_url = https://sso-foo.awsapps.com/start\n"
    "sso_region = us-west-2\n"
    "sso_account_id = 270484358888\n"
    "sso_role_name = Tester\n"
    "region = us-west-2\n"
    "output = json\n"
);

static int s_credentials_provider_sso_provider_access_token_file_missing(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_credentials_provider_profile_options options = {0};

    s_aws_sso_tester_init(allocator);

    options.tls_ctx = s_tester.tls_ctx;

    /* Redirect $HOME to the testing directory without creating the access token file .aws/sso/cache/<sha1>.json. */
    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_here));

    /* Remove stale cache directory. */
    struct aws_string *fake_cache_dir = aws_string_new_from_c_str(allocator, ".aws/sso/cache");
    ASSERT_SUCCESS(aws_directory_delete(fake_cache_dir, /* recursive = */ true));
    aws_string_destroy(fake_cache_dir);

    ASSERT_SUCCESS(s_sso_provider_init_config_profile(allocator, sso_test_profile_contents));

    ASSERT_PTR_EQUALS(NULL, aws_credentials_provider_new_sso(allocator, &options));

    /* Clean up */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);

    s_aws_sso_tester_cleanup();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    credentials_provider_sso_provider_access_token_file_missing,
    s_credentials_provider_sso_provider_access_token_file_missing);

static int s_credentials_provider_sso_provider_access_token_expired(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_credentials_provider_profile_options options = {0};
    AWS_STATIC_STRING_FROM_LITERAL(
        sso_expired_access_token,
        "{\
          \"startUrl\": \"https://sso-foo.awsapps.com/start\",\
          \"region\": \"us-west-2\",\
          \"accessToken\": \"FakeAccessTokenContent\",\
          \"expiresAt\": \"2022-06-03T05:53:48Z\"\
        }\n"
    );
    s_aws_sso_tester_init(allocator);

    options.tls_ctx = s_tester.tls_ctx;

    ASSERT_SUCCESS(s_sso_provider_init_config_profile(allocator, sso_test_profile_contents));

    /* Redirect $HOME to the testing directory, to create the $HOME/.aws/sso/cache/<sha1>.json there. */
    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_here));

    /* Create access token file. */
    struct aws_string *start_url = s_sso_extract_start_url_from_profile(allocator);
    ASSERT_NOT_NULL(start_url);

    struct aws_string *token_path = sso_access_token_path(allocator, start_url);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(s_create_directory_components(allocator, token_path));
    ASSERT_SUCCESS(aws_create_profile_file(token_path, sso_expired_access_token));

    ASSERT_PTR_EQUALS(NULL, aws_credentials_provider_new_sso(allocator, &options));

    /* Clean up */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);
    aws_string_destroy(start_url);
    aws_string_destroy(token_path);

    s_aws_sso_tester_cleanup();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    credentials_provider_sso_provider_access_token_expired,
    s_credentials_provider_sso_provider_access_token_expired);

static int s_credentials_provider_sso_new_destroy_from_config(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    AWS_STATIC_STRING_FROM_LITERAL(
        sso_eternal_access_token,
        "{\
          \"startUrl\": \"https://sso-foo.awsapps.com/start\",\
          \"region\": \"us-west-2\",\
          \"accessToken\": \"FakeAccessTokenContent\",\
          \"expiresAt\": \"2099-12-31T23:59:59Z\"\
        }\n"
    );
    s_aws_sso_tester_init(allocator);

    ASSERT_SUCCESS(s_sso_provider_init_config_profile(allocator, sso_test_profile_contents));

    /* Redirect $HOME to the testing directory, to create the $HOME/.aws/sso/cache/<sha1>.json there. */
    struct aws_string *actual_home = aws_string_new_from_c_str(allocator, getenv("HOME"));
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, s_home_here));

    /* Create access token file. */
    struct aws_string *start_url = s_sso_extract_start_url_from_profile(allocator);
    ASSERT_NOT_NULL(start_url);

    struct aws_string *token_path = sso_access_token_path(allocator, start_url);
    ASSERT_NOT_NULL(token_path);

    ASSERT_SUCCESS(s_create_directory_components(allocator, token_path));
    ASSERT_SUCCESS(aws_create_profile_file(token_path, sso_eternal_access_token));

    struct aws_credentials_provider_profile_options options = {
        .bootstrap = s_tester.bootstrap,
        .tls_ctx = s_tester.tls_ctx,
        .shutdown_options =
            {
                .shutdown_callback = s_on_shutdown_complete,
                .shutdown_user_data = NULL,
            },
    };

    struct aws_credentials_provider *provider = aws_credentials_provider_new_sso(allocator, &options);
    aws_credentials_provider_release(provider);

    s_aws_wait_for_provider_shutdown_callback();

    /* Clean up */
    ASSERT_SUCCESS(aws_set_environment_value(s_home_env_var, actual_home));
    aws_string_destroy(actual_home);
    aws_string_destroy(start_url);
    aws_string_destroy(token_path);

    s_aws_sso_tester_cleanup();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    credentials_provider_sso_new_destroy_from_config,
    s_credentials_provider_sso_new_destroy_from_config);
