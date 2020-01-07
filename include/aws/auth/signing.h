#ifndef AWS_AUTH_SIGNER_H
#define AWS_AUTH_SIGNER_H

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

#include <aws/auth/signing_config.h>
#include <aws/auth/signing_result.h>

struct aws_signable;

/**
 * Gets called by the signing function when the signing is complete.
 *
 * Note that result will be destroyed after this function returns, so either copy it,
 * or do all necessary adjustments inside the callback.
 */
typedef void(aws_signing_complete_fn)(struct aws_signing_result *result, int error_code, void *userdata);

AWS_EXTERN_C_BEGIN

/*
 * Takes an http request and a per-signer-type configuration struct and computes the changes to the request necessary
 * for compliance with the signer's signing algorithm.
 *
 * This signing function currently supports only the sigv4 algorithm.
 *
 * When using this signing function to sign AWS http requests:
 *
 *   (1) Do not add the following headers to requests before signing:
 *      x-amz-content-sha256,
 *      X-Amz-Date,
 *      Authorization
 *
 *   (2) Do not add the following query params to requests before signing:
 *      X-Amz-Signature,
 *      X-Amz-Date,
 *      X-Amz-Credential,
 *      X-Amz-Algorithm,
 *      X-Amz-SignedHeaders
 *
 * In all cases, the signing result will tell exactly what header and/or query params to add to the request
 * to become a fully-signed AWS http request.
 *
 * These restrictions can be relaxed, if necessary, in the future.
 */
AWS_AUTH_API
int aws_sign_request_aws(
    struct aws_allocator *allocator,
    const struct aws_signable *signable,
    const struct aws_signing_config_base *base_config,
    aws_signing_complete_fn *on_complete,
    void *userdata);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNER_H */
