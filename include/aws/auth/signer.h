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
struct aws_signer;

typedef int(aws_signer_sign_request_fn)(
    struct aws_signer *signer,
    const struct aws_signable *signable,
    const struct aws_signing_config_base *base_config,
    struct aws_signing_result *result);
typedef void(aws_signer_clean_up_fn)(struct aws_signer *signer);

struct aws_signer_vtable {
    aws_signer_sign_request_fn *sign_request;
    aws_signer_clean_up_fn *clean_up;
};

/*
 * An object that can take an http request and return a set of changes to the request (header/query param) necessary
 * for the request to be authorized, according to an associated signing process.
 */
struct aws_signer {
    struct aws_allocator *allocator;
    struct aws_signer_vtable *vtable;
    void *impl;
};

AWS_EXTERN_C_BEGIN

/*
 * Destroys all resources associated with a signer
 */
AWS_AUTH_API
void aws_signer_destroy(struct aws_signer *signer);

/*
 * Takes an http request and a per-signer-type configuration struct and computes the changes to the request necessary
 * for compliance with the signer's signing algorithm.
 */
AWS_AUTH_API
int aws_signer_sign_request(
    struct aws_signer *signer,
    const struct aws_signable *signable,
    const struct aws_signing_config_base *base_config,
    struct aws_signing_result *result);

/*
 * Creates a new signer that performs AWS http request signing.  Requires an instance of
 * the aws_signing_config_aws struct when signing.
 *
 * This signer currently supports only the sigv4 algorithm.
 *
 * When using this signer to sign AWS http requests:
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
 * These restrictions can be relaxed, if necessary, in the future, but they don't unreasonable and
 * relaxing them adds non-trivial complexity.
 */
AWS_AUTH_API
struct aws_signer *aws_signer_new_aws(struct aws_allocator *allocator);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNER_H */
