/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/credentials_utils.h>
#include <aws/testing/aws_test_harness.h>

static int s_credentials_utils_construct_endpoint_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *service_name = aws_string_new_from_c_str(allocator, "sts");

    struct aws_string *endpoint;
    struct aws_string *region;

    region = aws_string_new_from_c_str(allocator, "us-east-2");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(allocator, &endpoint, region, service_name));
    ASSERT_STR_EQUALS("sts.us-east-2.amazonaws.com", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "cn-northwest-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(allocator, &endpoint, region, service_name));
    ASSERT_STR_EQUALS("sts.cn-northwest-1.amazonaws.com.cn", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-iso-east-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(allocator, &endpoint, region, service_name));
    ASSERT_STR_EQUALS("sts.us-iso-east-1.c2s.ic.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-isob-east-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(allocator, &endpoint, region, service_name));
    ASSERT_STR_EQUALS("sts.us-isob-east-1.sc2s.sgov.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "eu-isoe-west-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(allocator, &endpoint, region, service_name));
    ASSERT_STR_EQUALS("sts.eu-isoe-west-1.cloud.adc-e.uk", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    region = aws_string_new_from_c_str(allocator, "us-isof-south-1");
    ASSERT_SUCCESS(aws_credentials_provider_construct_regional_endpoint(allocator, &endpoint, region, service_name));
    ASSERT_STR_EQUALS("sts.us-isof-south-1.csp.hci.ic.gov", aws_string_c_str(endpoint));
    aws_string_destroy(endpoint);
    aws_string_destroy(region);

    aws_string_destroy(service_name);

    return 0;
}

AWS_TEST_CASE(credentials_utils_construct_endpoint_test, s_credentials_utils_construct_endpoint_test);
