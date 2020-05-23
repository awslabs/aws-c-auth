#ifndef AWS_AUTH_SIGNING_CONFIG_H
#define AWS_AUTH_SIGNING_CONFIG_H

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

#include <aws/common/byte_buf.h>
#include <aws/common/date_time.h>

struct aws_credentials;

typedef bool(aws_should_sign_param_fn)(const struct aws_byte_cursor *name, void *userdata);

/*
 * A primitive RTTI indicator for signing configuration structs
 *
 * There must be one entry per config structure type and it's a fatal error
 * to put the wrong value in the "config_type" member of your config structure.
 */
enum aws_signing_config_type { AWS_SIGNING_CONFIG_AWS = 1 };

/*
 * All signing configuration structs must match this by having
 * the config_type member as the first member.
 */
struct aws_signing_config_base {
    enum aws_signing_config_type config_type;
};

/*
 * What version of the AWS signing process should we use.
 */
enum aws_signing_algorithm {
    AWS_SIGNING_ALGORITHM_V4,
};

/*
 * How should the signing process transform the request.
 */
enum aws_signing_request_transform {
    AWS_SRT_HEADER,
    AWS_SRT_QUERY_PARAM,
};

enum aws_signed_body_value_type {
    AWS_SBVT_EMPTY,
    AWS_SBVT_REQUEST,
    AWS_SBVT_UNSIGNED_PAYLOAD,
    AWS_SBVT_STREAMING_AWS4_HMAC_SHA256_PAYLOAD,
};

enum aws_signed_body_header_type {
    AWS_SBHT_NONE,
    AWS_SBHT_X_AMZ_CONTENT_SHA256,
};

/*
 * A configuration structure for use in AWS-related signing.  Currently covers sigv4 only, but is not required to.
 */
struct aws_signing_config_aws {

    /*
     * What kind of config structure is this?
     */
    enum aws_signing_config_type config_type;

    /*
     * What signing algorithm to use.
     */
    enum aws_signing_algorithm algorithm;

    /*
     * What kind of signing transform should be applied to the request.
     */
    enum aws_signing_request_transform transform;

    /*
     * The region to sign against
     */
    struct aws_byte_cursor region;

    /*
     * name of service to sign a request for
     */
    struct aws_byte_cursor service;

    /*
     * Raw date to use during the signing process.
     */
    struct aws_date_time date;

    /*
     * Optional function to control which parameters (header or query) are a part of the canonical request.
     * Skipping auth-required params
     * will result in an unusable signature.  Headers injected by the signing process are not skippable.
     *
     * This function does not override the internal check function (x-amzn-trace-id, user-agent), but rather
     * supplements it.  In particular, a header will get signed if and only if it returns true to both
     * the internal check (skips x-amzn-trace-id, user-agent) and this function (if defined).
     */
    aws_should_sign_param_fn *should_sign_param;
    void *should_sign_param_ud;

    /*
     * We assume the uri will be encoded once in preparation for transmission.  Certain services
     * do not decode before checking signature, requiring us to actually double-encode the uri in the canonical request
     * in order to pass a signature check.
     */
    bool use_double_uri_encode;

    /*
     * Controls whether or not the uri paths should be normalized when building the canonical request
     */
    bool should_normalize_uri_path;

    /*
     * Controls what should be hashed as "the body" when creating the canonical request:
     *  AWS_SBVT_EMPTY - the hash of the empty string should be used
     *  AWS_SBVT_REQUEST - the hash of the request payload should be used
     *  AWS_SBVT_UNSIGNED_PAYLOAD - the hash of 'UNSIGNED-PAYLOAD' should be used
     *  AWS_SBVT_STREAMING_AWS4_HMAC_SHA256_PAYLOAD - the hash of 'STREAMING_AWS4_HMAC_SHA256_PAYLOAD' should be used
     */
    enum aws_signed_body_value_type signed_body_type;

    /*
     * Controls what body hash header, if any, should be added to the canonical request and the signed request:
     *   AWS_SBHT_NONE - no body hash header should be added
     *   AWS_SBHT_X_AMZ_CONTENT_SHA256 - the body hash should be added in the X-Amz-Content-Sha256 header
     */
    enum aws_signed_body_header_type signed_body_header;

    /*
     * Signing key control:
     *
     *   (1) If "credentials" is valid, use it
     *   (2) Else if "credentials_provider" is valid, query credentials from the provider and use the result
     *   (3) Else fail
     *
     */

    /*
     * AWS Credentials to sign with.
     */
    struct aws_credentials *credentials;

    /*
     * AWS credentials provider to fetch credentials from.
     */
    struct aws_credentials_provider *credentials_provider;

    /*
     * If non-zero and the signing transform is query param, then signing will add X-Amz-Expires to the query
     * string, equal to the value specified here.  If this value is zero or if header signing is being used then
     * this parameter has no effect.
     */
    uint64_t expiration_in_seconds;
};

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
const char *aws_signing_algorithm_to_string(enum aws_signing_algorithm algorithm);

AWS_AUTH_API
int aws_validate_aws_signing_config_aws(const struct aws_signing_config_aws *config);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNING_CONFIG_H */
