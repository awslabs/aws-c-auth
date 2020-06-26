#ifndef AWS_AUTH_SIGNER_H
#define AWS_AUTH_SIGNER_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/auth.h>

#include <aws/auth/signing_config.h>

struct aws_signable;
struct aws_signing_result;

/**
 * Gets called by the signing function when the signing is complete.
 *
 * Note that result will be destroyed after this function returns, so either copy it,
 * or do all necessary adjustments inside the callback.
 *
 * When performing event or chunk signing, you will need to copy out the signature value in order
 * to correctly configure the signable that wraps the event or chunk you want signed next.  The signature is
 * found in the "signature" property on the signing result.  This value must be added as the
 * "previous-signature" property on the next signable.
 */
typedef void(aws_signing_complete_fn)(struct aws_signing_result *result, int error_code, void *userdata);

AWS_EXTERN_C_BEGIN

/*
 * Takes a signable object and a configuration struct and computes the changes to the signable necessary
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
 * The signing result will tell exactly what header and/or query params to add to the request
 * to become a fully-signed AWS http request.
 *
 *
 * When using this signing function to sign chunks:
 *
 *   (1) The signable should be a wrapper around the chunk's input stream
 *   (2) The most-recently-computed signature value (original request or most recent chunk) must be the
 *       "previous-signature" property on the signable.
 *
 * The signing result will include the chunk's signature as the "signature" property.
 *
 *
 * When using this function to sign events:
 *
 *   (1) The signable should be a wrapper around the event's payloads and headers.  TBD: forbid :date and calculate
 *       it based on the config's date value?
 *   (2) The most-recently-computed signature value (original request or most recent chunk) must be the
 *       "previous-signature" property on the signable.
 *
 * The signing result will include the chunk's signature as the "signature" property, where it should be added
 * to the event as the value of the ":chunk-signature" header.
 *
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
