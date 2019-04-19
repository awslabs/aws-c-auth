#ifndef AWS_AUTH_SIGNING_RESULT_H
#define AWS_AUTH_SIGNING_RESULT_H

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

#include <aws/common/array_list.h>

struct aws_byte_cursor;
struct aws_string;

struct aws_signing_result_name_value_pair {
    struct aws_string *name;
    struct aws_string *value;
};

/*
 * A structure for tracking all the signer-requested changes to an http request needed to build
 * a properly-signed http request.
 */
struct aws_signing_result {
    struct aws_allocator *allocator;
    struct aws_array_list headers;
    struct aws_array_list query_params;
};

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
int aws_signing_result_init(struct aws_signing_result *result, struct aws_allocator *allocator);

AWS_AUTH_API
void aws_signing_result_clean_up(struct aws_signing_result *result);

AWS_AUTH_API
int aws_signing_result_add_header(
    struct aws_signing_result *result,
    struct aws_byte_cursor *name,
    struct aws_byte_cursor *value);

AWS_AUTH_API
int aws_signing_result_add_query_param(
    struct aws_signing_result *result,
    struct aws_byte_cursor *name,
    struct aws_byte_cursor *value);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNING_RESULT_H */
