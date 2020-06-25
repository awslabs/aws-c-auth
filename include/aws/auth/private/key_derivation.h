#ifndef AWS_AUTH_KEY_DERIVATION_H
#define AWS_AUTH_KEY_DERIVATION_H

/*
 * Copyright 2010-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

AWS_EXTERN_C_BEGIN

/*
 * Some utility functions used while deriving an ecc key from aws credentials.
 *
 * The functions operate on the raw bytes of a buffer, treating them as a (base 255) big-endian
 * integer.
 */

/**
 * Compares two byte buffers lexically.  The buffers must be of equal size.  Lexical comparison from front-to-back
 * corresponds to arithmetic comparison when the byte sequences are considered to be big-endian large integers.
 * The output parameter comparison_result is set to:
 *   -1 if lhs_raw_be_bigint < rhs_raw_be_bigint
 *    0 if lhs_raw_be_bigint == rhs_raw_be_bigint
 *    1 if lhs_raw_be_bigint > rhs_raw_be_bigint
 *
 * @return AWS_OP_SUCCESS or AWS_OP_ERR
 *
 * This is a constant-time operation.
 */
AWS_AUTH_API
int aws_be_bytes_compare_constant_time(
    const struct aws_byte_buf *lhs_raw_be_bigint,
    const struct aws_byte_buf *rhs_raw_be_bigint,
    int *comparison_result);

/**
 * Adds one to a big integer represented as a sequence of bytes (in big-endian order).  A maximal (unsigned) value
 * will roll over to 0.
 *
 * This is a constant-time operation.
 */
AWS_AUTH_API
void aws_be_bytes_add_one_constant_time(struct aws_byte_buf *raw_be_bigint);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_KEY_DERIVATION_H */
