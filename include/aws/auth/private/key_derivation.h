#ifndef AWS_AUTH_KEY_DERIVATION_H
#define AWS_AUTH_KEY_DERIVATION_H

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

struct aws_byte_buf;

/*
 * Some utility functions used while deriving an ecc key from aws credentials.
 *
 * The functions operate on the raw bytes of a buffer, treating them as a (base 255) big-endian
 * integer.  Both functions are constant-time.
 */
AWS_EXTERN_C_BEGIN

/**
 * Compares two byte buffers lexically.  The buffers must be of equal size.  Lexical comparison from front-to-back
 * corresponds to arithmetic comparison when the byte sequences are considered to be big-endian large integers.
 * The comparison result (-1 for <, 0 for ==, 1 for >) is an output parameter.
 *
 * @return AWS_OP_SUCCESS or AWS_OP_ERR
 *
 * This is a constant-time operation.
 */
AWS_AUTH_API
int aws_be_bytes_compare(
    const struct aws_byte_buf *raw_be_bigint_lhs,
    const struct aws_byte_buf *raw_be_bigint_rhs,
    int *comparison_result);

/**
 * Adds one to a big integer represented as a sequence of bytes (in big-endian order).
 *
 * This is a constant-time operation.
 */
AWS_AUTH_API
void aws_be_bytes_add_one(struct aws_byte_buf *raw_be_bigint);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_KEY_DERIVATION_H */
