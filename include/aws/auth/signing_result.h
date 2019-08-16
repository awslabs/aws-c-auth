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
struct aws_http_message;
struct aws_string;

struct aws_signing_result_property {
    struct aws_string *name;
    struct aws_string *value;
};

/*
 * A structure for tracking all the signer-requested changes to a signable.  Interpreting
 * these changes is signing-algorithm specific.
 *
 * A signing result consists of
 *
 *   (1) Properties - A set of key-value pairs
 *   (2) Property Lists - A set of named key-value pair lists
 *
 * The hope is that these two generic structures are enough to model the changes required
 * by any generic message-signing algorithm.
 *
 * Note that the key-value pairs of a signing_result are different types (but same intent) as
 * the key-value pairs in the signable interface.  This is because the signing result stands alone
 * and owns its own copies of all values, whereas a signable can wrap an existing object and thus
 * use non-owning references (like byte cursors) if appropriate to its implementation.
 */
struct aws_signing_result {
    struct aws_allocator *allocator;
    struct aws_hash_table properties;
    struct aws_hash_table property_lists;
};

AWS_EXTERN_C_BEGIN

/**
 * Initialize a signing result to its starting state
 */
AWS_AUTH_API
int aws_signing_result_init(struct aws_signing_result *result, struct aws_allocator *allocator);

/**
 * Clean up all resources held by the signing result
 */
AWS_AUTH_API
void aws_signing_result_clean_up(struct aws_signing_result *result);

/**
 * Sets the value of a property on a signing result
 */
AWS_AUTH_API
int aws_signing_result_set_property(
    struct aws_signing_result *result,
    const struct aws_string *property_name,
    const struct aws_byte_cursor *property_value);

/**
 * Gets the value of a property on a signing result
 */
AWS_AUTH_API
int aws_signing_result_get_property(
    struct aws_signing_result *result,
    const struct aws_string *property_name,
    struct aws_string **out_property_value);

/**
 * Adds a key-value pair to a named property list.  If the named list does not yet exist, it will be created as
 * an empty list before the pair is added.  No uniqueness checks are made against existing pairs.
 */
AWS_AUTH_API
int aws_signing_result_append_property_list(
    struct aws_signing_result *result,
    const struct aws_string *list_name,
    const struct aws_byte_cursor *property_name,
    const struct aws_byte_cursor *property_value);

/**
 * Gets a named property list on the signing result.  If the list does not exist, *out_list will be set to null
 */
AWS_AUTH_API
int aws_signing_result_get_property_list(
    struct aws_signing_result *result,
    const struct aws_string *list_name,
    struct aws_array_list **out_list);

/*
 * Specific implementation that applies a signing result to a mutable http request
 */
AWS_AUTH_API
int aws_apply_signing_result_to_http_request(
    struct aws_http_message *request,
    struct aws_allocator *allocator,
    struct aws_signing_result *result);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNING_RESULT_H */
