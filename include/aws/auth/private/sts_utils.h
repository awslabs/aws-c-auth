#ifndef AWS_AUTH_STS_UTILS_PRIVATE_H
#define AWS_AUTH_STS_UTILS_PRIVATE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/auth.h>
#include <aws/common/byte_buf.h>

AWS_EXTERN_C_BEGIN

/*
 * Reads the <Code> of an STS error response (<ErrorResponse><Error><Code> or <Error><Code>).
 * out_error_code points into error_document, and is empty if there is no <Code>.
 */
AWS_AUTH_API
int aws_sts_parse_error_code(
    struct aws_allocator *allocator,
    struct aws_byte_cursor error_document,
    struct aws_byte_cursor *out_error_code);

/*
 * Returns true if an STS error code means retrying will not succeed.
 */
AWS_AUTH_API
bool aws_sts_is_non_recoverable_error_code(struct aws_byte_cursor error_code);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_STS_UTILS_PRIVATE_H */
