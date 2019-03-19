/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/auth/credentials.h>

#include <aws/common/string.h>

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_test_value, "My Access Key");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_test_value, "SekritKey");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_test_value,
                               "Some Session Token");

static int s_credentials_create_destroy_test(struct aws_allocator *allocator,
                                             void *ctx) {
  (void)ctx;

  struct aws_credentials *credentials = aws_credentials_new(
      allocator, s_access_key_id_test_value, s_secret_access_key_test_value,
      s_session_token_test_value);

  ASSERT_TRUE(aws_string_compare(credentials->access_key_id,
                                 s_access_key_id_test_value) == 0);
  ASSERT_TRUE(aws_string_compare(credentials->secret_access_key,
                                 s_secret_access_key_test_value) == 0);
  ASSERT_TRUE(aws_string_compare(credentials->session_token,
                                 s_session_token_test_value) == 0);

  aws_credentials_destroy(credentials);

  return 0;
}

AWS_TEST_CASE(credentials_create_destroy_test,
              s_credentials_create_destroy_test);

static int s_credentials_copy_test(struct aws_allocator *allocator, void *ctx) {
  (void)ctx;

  struct aws_credentials *source = aws_credentials_new(
      allocator, s_access_key_id_test_value, s_secret_access_key_test_value,
      s_session_token_test_value);

  struct aws_credentials *credentials =
      aws_credentials_new_copy(allocator, source);

  // Verify string equality and pointer inequality
  ASSERT_TRUE(aws_string_compare(credentials->access_key_id,
                                 s_access_key_id_test_value) == 0);
  ASSERT_TRUE(credentials->access_key_id != source->access_key_id);

  ASSERT_TRUE(aws_string_compare(credentials->secret_access_key,
                                 s_secret_access_key_test_value) == 0);
  ASSERT_TRUE(credentials->secret_access_key != source->secret_access_key);

  ASSERT_TRUE(aws_string_compare(credentials->session_token,
                                 s_session_token_test_value) == 0);
  ASSERT_TRUE(credentials->session_token != source->session_token);

  aws_credentials_destroy(credentials);
  aws_credentials_destroy(source);

  return 0;
}

AWS_TEST_CASE(credentials_copy_test, s_credentials_copy_test);
