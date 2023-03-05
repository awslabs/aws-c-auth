/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include "shared_credentials_test_definitions.h"
#include <aws/auth/private/sso_token_utils.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>

static int s_parse_token_location_url_test(struct aws_allocator *allocator, void *ctx) {
    struct aws_string *start_url = aws_string_new_from_c_str(allocator, "https://d-92671207e4.awsapps.com/start");
    struct aws_string *token_path = construct_token_path(allocator, start_url);
    struct aws_string *expected_token_path =
        aws_string_new_from_c_str(allocator, "13f9d35043871d073ab260e020f0ffde092cb14b.json");

    // TODO: mock home
    ASSERT_TRUE(aws_string_eq(token_path, expected_token_path));

    aws_string_destroy(start_url);
    aws_string_destroy(token_path);
    aws_string_destroy(expected_token_path);
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(parse_token_location_url_test, s_parse_token_location_url_test);

static int s_parse_token_location_session_test(struct aws_allocator *allocator, void *ctx) {
    struct aws_string *session = aws_string_new_from_c_str(allocator, "admin");
    struct aws_string *token_path = construct_token_path(allocator, session);
    struct aws_string *expected_token_path =
        aws_string_new_from_c_str(allocator, "d033e22ae348aeb5660fc2140aec35850c4da997.json");
    // TODO: mock home
    ASSERT_TRUE(aws_string_eq(token_path, expected_token_path));

    aws_string_destroy(session);
    aws_string_destroy(token_path);
    aws_string_destroy(expected_token_path);
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(parse_token_location_session_test, s_parse_token_location_session_test);

AWS_STATIC_STRING_FROM_LITERAL(
    s_valid_token_json,
    "{\"accessToken\": \"string\",\"expiresAt\": \"2019-11-14T04:05:45Z\",\"refreshToken\": \"string\",\"clientId\": "
    "\"ABCDEFG323242423121312312312312312\",\"clientSecret\": \"ABCDE123\",\"registrationExpiresAt\": "
    "\"2022-03-06T19:53:17Z\",\"region\": \"us-west-2\",\"startUrl\": \"https://d-abc123.awsapps.com/start\"}");
static int s_parse_sso_token_valid(struct aws_allocator *allocator, void *ctx) {

    aws_auth_library_init(allocator);

    struct aws_string *file_path = aws_create_process_unique_file_name(allocator);
    ASSERT_TRUE(aws_create_profile_file(file_path, s_valid_token_json) == AWS_OP_SUCCESS);
    struct aws_sso_token *token = aws_sso_token_new_from_file(allocator, file_path);
    ASSERT_TRUE(aws_string_eq_c_str(token->token, "string"));
    ASSERT_INT_EQUALS(aws_date_time_as_epoch_secs(&token->expiration), 1573704345);
    aws_string_destroy(file_path);
    aws_sso_token_destroy(allocator, token);
    aws_auth_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(parse_sso_token_valid, s_parse_sso_token_valid);
