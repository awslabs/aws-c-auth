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
 * What signing algorithm to use.  Independent of signing config type as some
 * algorithms may share a common configuration struct.
 */
enum aws_signing_algorithm {
    AWS_SIGNING_ALGORITHM_SIG_V4_HEADER,
    AWS_SIGNING_ALGORITHM_SIG_V4_QUERY_PARAM,
    AWS_SIGNING_ALGORITHM_COUNT
};

enum aws_body_signing_config_type {
    AWS_BODY_SIGNING_OFF,
    AWS_BODY_SIGNING_ON,
    AWS_BODY_SIGNING_UNSIGNED_PAYLOAD,
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
     * What signing process do we want to invoke
     */
    enum aws_signing_algorithm algorithm;

    /*
     * AWS credentials provider to fetch signing credentials with
     */
    struct aws_credentials_provider *credentials_provider;

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
     * If AWS_BODY_SIGNING_ON adds the x-amz-content-sha256 header (with sha256 hash of the payload) to the canonical
     * request. If AWS_BODY_SIGNING_UNSIGNED_PAYLOAD, "UNSIGNED-PAYLOAD" is used for the x-amz-content-sha256 header,
     * otherwise no paylod signing will take place.
     */
    enum aws_body_signing_config_type body_signing_type;
};

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
const char *aws_signing_algorithm_to_string(enum aws_signing_algorithm algorithm);

AWS_AUTH_API
int aws_validate_aws_signing_config_aws(const struct aws_signing_config_aws *config);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNING_CONFIG_H */
