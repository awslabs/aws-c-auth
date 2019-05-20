#ifndef AWS_AUTH_TEST_SIGNABLE_H
#define AWS_AUTH_TEST_SIGNABLE_H

/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/auth/auth.h>

struct aws_byte_cursor;
struct aws_input_stream;
struct aws_signable;
struct aws_signable_property_list_pair;

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
struct aws_signable *aws_signable_new_test(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *method,
    struct aws_byte_cursor *uri,
    struct aws_signable_property_list_pair *headers,
    size_t header_count,
    struct aws_input_stream *body_stream);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_TEST_SIGNABLE_H */
