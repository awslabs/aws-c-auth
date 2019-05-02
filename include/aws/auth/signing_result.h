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

#include <aws/common/hash_table.h>

struct aws_array_list;
struct aws_byte_cursor;
struct aws_string;

struct aws_signing_result_property {
    struct aws_string *name;
    struct aws_string *value;
};

/*
 * A structure for tracking all the signer-requested changes to a signable.  Interpreting
 * these changes is signing-algorithm specific.
 */
struct aws_signing_result {
    struct aws_allocator *allocator;
    struct aws_hash_table properties;
    struct aws_hash_table property_lists;
};

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
int aws_signing_result_init(struct aws_signing_result *result, struct aws_allocator *allocator);

AWS_AUTH_API
void aws_signing_result_clean_up(struct aws_signing_result *result);

AWS_AUTH_API
int aws_signing_result_set_property(
    struct aws_signing_result *result,
    const struct aws_string *property_name,
    const struct aws_byte_cursor *property_value);

AWS_AUTH_API
int aws_signing_result_get_property(
    struct aws_signing_result *result,
    const struct aws_string *property_name,
    struct aws_string **out_property_value);

AWS_AUTH_API
int aws_signing_result_append_property_list(
    struct aws_signing_result *result,
    const struct aws_string *list_name,
    const struct aws_byte_cursor *property_name,
    const struct aws_byte_cursor *property_value);

AWS_AUTH_API
int aws_signing_result_get_property_list(
    struct aws_signing_result *result,
    const struct aws_string *list_name,
    struct aws_array_list **out_list);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNING_RESULT_H */
