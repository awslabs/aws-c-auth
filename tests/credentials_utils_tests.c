/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/credentials_utils.h>
#include <aws/testing/aws_test_harness.h>
#include <aws/common/environment.h>

static int s_credentials_utils_construct_endpoint_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *service_name = aws_string_new_from_c_str(allocator, "sts");
    struct aws_string *service_name_env = aws_string_new_from_c_str(allocator, "STS");
    struct aws_string *endpoint;
    struct aws_string *region;

    region = aws_string_new_from_c_str(allocator, "us-east-2");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL));
    ASSERT_STR_EQUALS("sts.us-east-2.amazonaws.com", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "cn-northwest-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL));
    ASSERT_STR_EQUALS("sts.cn-northwest-1.amazonaws.com.cn", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-iso-east-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL));
    ASSERT_STR_EQUALS("sts.us-iso-east-1.c2s.ic.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-isob-east-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL));
    ASSERT_STR_EQUALS("sts.us-isob-east-1.sc2s.sgov.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "eu-isoe-west-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL));
    ASSERT_STR_EQUALS("sts.eu-isoe-west-1.cloud.adc-e.uk", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-isof-south-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(
        allocator, &endpoint, region, service_name, service_name, service_name, NULL, NULL));
    ASSERT_STR_EQUALS("sts.us-isof-south-1.csp.hci.ic.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-east-2");
    struct aws_string *endpoint_override_env = aws_string_new_from_c_str(allocator, "AWS_ENDPOINT_URL_STS");
    struct aws_string *endpoint_override = aws_string_new_from_c_str(allocator, "test.endpoint.override.com");
    aws_set_environment_value(endpoint_override_env, endpoint_override);
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(
        allocator, &endpoint, region, service_name, service_name_env, service_name, NULL, NULL));
    ASSERT_STR_EQUALS(aws_string_c_str(endpoint_override), aws_string_c_str(endpoint));
    aws_unset_environment_value(endpoint_override_env);
    aws_string_destroy(endpoint_override);
    aws_string_destroy(endpoint_override_env);
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    aws_string_destroy(service_name);
    aws_string_destroy(service_name_env);

    return 0;
}

AWS_TEST_CASE(credentials_utils_construct_endpoint_test, s_credentials_utils_construct_endpoint_test);
