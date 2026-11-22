/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/credentials_utils.h>
#include <aws/auth/private/sts_utils.h>
#include <aws/common/environment.h>
#include <aws/sdkutils/aws_profile.h>
#include <aws/testing/aws_test_harness.h>

static int s_credentials_utils_construct_endpoint_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *service_name = aws_string_new_from_c_str(allocator, "sts");
    struct aws_string *endpoint;
    struct aws_string *region;

    region = aws_string_new_from_c_str(allocator, "us-east-2");
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS("sts.us-east-2.amazonaws.com", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "cn-northwest-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS("sts.cn-northwest-1.amazonaws.com.cn", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "eusc-de-east-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS("sts.eusc-de-east-1.amazonaws.eu", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-iso-east-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS("sts.us-iso-east-1.c2s.ic.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-isob-east-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS("sts.us-isob-east-1.sc2s.sgov.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "eu-isoe-west-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS("sts.eu-isoe-west-1.cloud.adc-e.uk", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-isof-south-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS("sts.us-isof-south-1.csp.hci.ic.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    aws_string_destroy(service_name);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(credentials_utils_construct_endpoint_test, s_credentials_utils_construct_endpoint_test);

static int s_credentials_utils_endpoint_override_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *region = aws_string_new_from_c_str(allocator, "us-east-2");
    struct aws_string *service_name = aws_string_new_from_c_str(allocator, "sts");
    struct aws_string *service_name_env = aws_string_new_from_c_str(allocator, "STS");
    struct aws_string *endpoint = NULL;

    /* test service-specific endpoint override */
    struct aws_string *endpoint_override_env = aws_string_new_from_c_str(allocator, "AWS_ENDPOINT_URL_STS");
    struct aws_string *endpoint_override = aws_string_new_from_c_str(allocator, "test.endpoint.override.com");
    aws_set_environment_value(endpoint_override_env, endpoint_override);
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name_env, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS(aws_string_c_str(endpoint_override), aws_string_c_str(endpoint));
    aws_unset_environment_value(endpoint_override_env);
    aws_string_destroy(endpoint_override);
    aws_string_destroy(endpoint_override_env);
    aws_string_destroy(endpoint);

    /* test global endpoint override */
    struct aws_string *endpoint_override_env_global = aws_string_new_from_c_str(allocator, "AWS_ENDPOINT_URL");
    endpoint_override = aws_string_new_from_c_str(allocator, "global.endpoint.override.com");
    aws_set_environment_value(endpoint_override_env_global, endpoint_override);
    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator, &endpoint, region, service_name, service_name_env, service_name, NULL, NULL, NULL, false));
    ASSERT_STR_EQUALS(aws_string_c_str(endpoint_override), aws_string_c_str(endpoint));
    aws_unset_environment_value(endpoint_override_env_global);
    aws_string_destroy(endpoint_override);
    aws_string_destroy(endpoint_override_env_global);
    aws_string_destroy(endpoint);

    /* test service-specific config endpoint override */
    struct aws_byte_cursor service_override_config_contents =
        aws_byte_cursor_from_c_str("[profile test-profile]\n"
                                   "test = 123\n"
                                   "services = test-services\n"
                                   "[services test-services]\n"
                                   "sts =\n"
                                   "    endpoint_url = test.sts.endpoint.com\n"
                                   "[sso-session session]\n");
    struct aws_byte_buf config_file;
    AWS_ZERO_STRUCT(config_file);
    aws_byte_buf_init_copy_from_cursor(&config_file, allocator, service_override_config_contents);
    struct aws_profile_collection *profile_collection =
        aws_profile_collection_new_from_buffer(allocator, &config_file, AWS_PST_CONFIG);
    struct aws_string *profile_name = aws_string_new_from_c_str(allocator, "test-profile");
    const struct aws_profile *profile = aws_profile_collection_get_profile(profile_collection, profile_name);

    struct aws_string *expected_endpoint = aws_string_new_from_c_str(allocator, "test.sts.endpoint.com");

    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator,
        &endpoint,
        region,
        service_name,
        service_name,
        service_name,
        profile_collection,
        profile,
        NULL,
        false));
    ASSERT_STR_EQUALS(aws_string_c_str(expected_endpoint), aws_string_c_str(endpoint));
    aws_string_destroy(expected_endpoint);
    aws_byte_buf_clean_up(&config_file);
    aws_profile_collection_release(profile_collection);
    aws_string_destroy(endpoint);
    aws_string_destroy(profile_name);
    /* test global config endpoint override */
    struct aws_byte_cursor global_override_config_contents =
        aws_byte_cursor_from_c_str("[profile test-profile]\n"
                                   "test = 123\n"
                                   "endpoint_url = global.sts.endpoint.com\n");
    AWS_ZERO_STRUCT(config_file);
    aws_byte_buf_init_copy_from_cursor(&config_file, allocator, global_override_config_contents);
    profile_collection = aws_profile_collection_new_from_buffer(allocator, &config_file, AWS_PST_CONFIG);
    profile_name = aws_string_new_from_c_str(allocator, "test-profile");
    profile = aws_profile_collection_get_profile(profile_collection, profile_name);
    expected_endpoint = aws_string_new_from_c_str(allocator, "global.sts.endpoint.com");

    ASSERT_SUCCESS(aws_credentials_provider_construct_endpoint(
        allocator,
        &endpoint,
        region,
        service_name,
        service_name,
        service_name,
        profile_collection,
        profile,
        NULL,
        false));
    ASSERT_STR_EQUALS(aws_string_c_str(expected_endpoint), aws_string_c_str(endpoint));
    aws_string_destroy(expected_endpoint);
    aws_byte_buf_clean_up(&config_file);
    aws_profile_collection_release(profile_collection);
    aws_string_destroy(endpoint);
    aws_string_destroy(profile_name);

    aws_string_destroy(region);
    aws_string_destroy(service_name);
    aws_string_destroy(service_name_env);
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(credentials_utils_endpoint_override_test, s_credentials_utils_endpoint_override_test);

static int s_credentials_utils_parse_account_id_from_arn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(
        aws_parse_account_id_from_arn(aws_byte_cursor_from_c_str("::::123456789012::")), "123456789012");
    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(
        aws_parse_account_id_from_arn(aws_byte_cursor_from_c_str("arn:a:b:c:123456789012::")), "123456789012");
    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(aws_parse_account_id_from_arn(aws_byte_cursor_from_c_str("::::::")), "");
    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(aws_parse_account_id_from_arn(aws_byte_cursor_from_c_str("invalid-arn")), "");
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(credentials_utils_parse_account_id_from_arn, s_credentials_utils_parse_account_id_from_arn);

/* Reads <Code> from <ErrorResponse><Error> and from a bare <Error> root */
static int s_sts_utils_parse_error_code_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor code;

    struct aws_byte_cursor error_response = aws_byte_cursor_from_c_str(
        "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error><Type>Sender</Type>"
        "<Code>AccessDenied</Code><Message>denied</Message></Error><RequestId>id</RequestId></ErrorResponse>");
    ASSERT_SUCCESS(aws_credentials_provider_parse_sts_error_code(allocator, error_response, &code));
    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(code, "AccessDenied");

    struct aws_byte_cursor bare_error =
        aws_byte_cursor_from_c_str("<Error><Code>IDPCommunicationError</Code><Message>XXX</Message></Error>");
    ASSERT_SUCCESS(aws_credentials_provider_parse_sts_error_code(allocator, bare_error, &code));
    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(code, "IDPCommunicationError");

    struct aws_byte_cursor no_code =
        aws_byte_cursor_from_c_str("<ErrorResponse><Error><Message>no code</Message></Error></ErrorResponse>");
    ASSERT_SUCCESS(aws_credentials_provider_parse_sts_error_code(allocator, no_code, &code));
    ASSERT_UINT_EQUALS(0, code.len);

    struct aws_byte_cursor not_xml = aws_byte_cursor_from_c_str("not xml");
    ASSERT_FAILS(aws_credentials_provider_parse_sts_error_code(allocator, not_xml, &code));
    ASSERT_UINT_EQUALS(0, code.len);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(sts_utils_parse_error_code_test, s_sts_utils_parse_error_code_test);

/* Web identity retries only ExpiredToken, ExpiredTokenException and IDPCommunicationError */
static int s_sts_utils_retryable_web_identity_error_code_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    ASSERT_TRUE(
        aws_credentials_provider_is_retryable_sts_web_identity_error_code(aws_byte_cursor_from_c_str("ExpiredToken")));
    ASSERT_TRUE(aws_credentials_provider_is_retryable_sts_web_identity_error_code(
        aws_byte_cursor_from_c_str("ExpiredTokenException")));
    ASSERT_TRUE(aws_credentials_provider_is_retryable_sts_web_identity_error_code(
        aws_byte_cursor_from_c_str("IDPCommunicationError")));
    ASSERT_FALSE(aws_credentials_provider_is_retryable_sts_web_identity_error_code(
        aws_byte_cursor_from_c_str("InvalidIdentityToken")));
    ASSERT_FALSE(
        aws_credentials_provider_is_retryable_sts_web_identity_error_code(aws_byte_cursor_from_c_str("AccessDenied")));
    ASSERT_FALSE(aws_credentials_provider_is_retryable_sts_web_identity_error_code(aws_byte_cursor_from_c_str("")));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(sts_utils_retryable_web_identity_error_code_test, s_sts_utils_retryable_web_identity_error_code_test);

/* Non-recoverable STS codes are exactly the six the SEP lists */
static int s_sts_utils_non_recoverable_error_code_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    const char *non_recoverable[] = {
        "AccessDenied",
        "IDPRejectedClaim",
        "InvalidIdentityToken",
        "MalformedPolicyDocument",
        "PackedPolicyTooLarge",
        "RegionDisabledException",
    };
    for (size_t i = 0; i < AWS_ARRAY_SIZE(non_recoverable); ++i) {
        ASSERT_TRUE(
            aws_credentials_provider_is_non_recoverable_sts_error_code(aws_byte_cursor_from_c_str(non_recoverable[i])));
    }

    const char *recoverable[] = {"ExpiredToken", "IDPCommunicationError", "Throttling", "InternalFailure", ""};
    for (size_t i = 0; i < AWS_ARRAY_SIZE(recoverable); ++i) {
        ASSERT_FALSE(
            aws_credentials_provider_is_non_recoverable_sts_error_code(aws_byte_cursor_from_c_str(recoverable[i])));
    }

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(sts_utils_non_recoverable_error_code_test, s_sts_utils_non_recoverable_error_code_test);

/* The refresh cache treats only the SSO, Login and STS non-recoverable codes as non-recoverable */
static int s_credentials_utils_is_non_recoverable_error_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_auth_library_init(allocator);

    int non_recoverable[] = {
        AWS_AUTH_SSO_TOKEN_EXPIRED,
        AWS_AUTH_SSO_TOKEN_INVALID,
        AWS_AUTH_CREDENTIALS_PROVIDER_SSO_UNAUTHORIZED,
        AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_FAILED_TO_CREATE_TOKEN,
        AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_ACCESS_DENIED,
        AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_VALIDATION_FAILED,
        AWS_AUTH_CREDENTIALS_PROVIDER_STS_NON_RECOVERABLE,
    };
    for (size_t i = 0; i < AWS_ARRAY_SIZE(non_recoverable); ++i) {
        ASSERT_TRUE(aws_credentials_provider_is_non_recoverable_error(non_recoverable[i]));
    }

    int recoverable[] = {
        AWS_ERROR_SUCCESS,
        AWS_ERROR_UNKNOWN,
        AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_TOKEN_EXPIRED,
        AWS_AUTH_CREDENTIALS_PROVIDER_IMDS_SOURCE_FAILURE,
        AWS_AUTH_CREDENTIALS_PROVIDER_STS_SOURCE_FAILURE,
        AWS_AUTH_CREDENTIALS_PROVIDER_SSO_SOURCE_FAILURE,
        AWS_AUTH_SIGNING_NO_CREDENTIALS,
    };
    for (size_t i = 0; i < AWS_ARRAY_SIZE(recoverable); ++i) {
        ASSERT_FALSE(aws_credentials_provider_is_non_recoverable_error(recoverable[i]));
    }

    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(credentials_utils_is_non_recoverable_error_test, s_credentials_utils_is_non_recoverable_error_test);
