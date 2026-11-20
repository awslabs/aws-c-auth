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
 * Reads the <Code> element of an STS error response, rooted at <ErrorResponse><Error> or <Error>.
 * out_error_code points into error_document and is empty when there is no <Code>.
 */
AWS_AUTH_API
int aws_credentials_provider_parse_sts_error_code(
    struct aws_allocator *allocator,
    struct aws_byte_cursor error_document,
    struct aws_byte_cursor *out_error_code);

/*
 * Returns true if an AssumeRoleWithWebIdentity error code (the <Code> element) should be retried within the attempt.
 */
AWS_AUTH_API
bool aws_credentials_provider_is_retryable_sts_web_identity_error_code(struct aws_byte_cursor error_code);

/*
 * Returns true if an STS error response code (the <Code> element) means retrying will not succeed.
 */
AWS_AUTH_API
bool aws_credentials_provider_is_non_recoverable_sts_error_code(struct aws_byte_cursor error_code);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_STS_UTILS_PRIVATE_H */
