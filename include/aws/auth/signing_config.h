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
 * Indicates whether authorization should be header-based or query-param-based.
 */
enum aws_signing_auth_type { AWS_SIGN_AUTH_HEADER, AWS_SIGN_AUTH_QUERY_PARAM };

/*
 * What signing algorithm to use.  Independent of signing config type as some
 * algorithms may share a common configuration struct.
 */
enum aws_signing_algorithm { AWS_SIGNING_ALGORITHM_SIG_V4, AWS_SIGNING_ALGORITHM_COUNT };

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
     * AWS credentials to sign with
     */
    struct aws_credentials *credentials;

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
     * We assume the uri has already been encoded once in preparation for transmission.  Certain services
     * do not decode before checking signature, requiring us to actually double-encode the uri in the canonical request
     * in order to pass a signature check.
     */
    bool use_double_uri_encode;

    /*
     * If true adds the x-amz-content-sha256 header (with appropriate value) to the canonical request, otherwise does
     * nothing
     */
    bool sign_body;

    /*
     * Controls whether the signing result contains request header or query-param auth changes
     */
    enum aws_signing_auth_type auth_type;
};

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
const char *aws_signing_algorithm_to_string(enum aws_signing_algorithm algorithm);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNING_CONFIG_H */
