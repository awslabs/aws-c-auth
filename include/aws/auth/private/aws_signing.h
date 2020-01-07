#ifndef AWS_AUTH_SIGNING_SIGV4_H
#define AWS_AUTH_SIGNING_SIGV4_H

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
#include <aws/auth/signing.h>

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>

struct aws_signable;
struct aws_signing_config_aws;
struct aws_signing_result;

/*
 * Private signing API
 *
 * Technically this could be folded directly into signing.c but it's useful to be able
 * to call the individual stages of the signing process for testing.
 */

/*
 * A structure that contains all the state related to signing a request for AWS.  We pass
 * this around rather than a million parameters.
 */
struct aws_signing_state_aws {
    struct aws_allocator *allocator;

    const struct aws_signable *signable;
    aws_signing_complete_fn *on_complete;
    void *userdata;

    struct aws_signing_config_aws config;
    struct aws_byte_buf region_service_buffer;

    struct aws_signing_result result;
    struct aws_credentials *credentials;

    /* persistent, constructed values that are either/or
     *  (1) consumed by later stages of the signing process,
     *  (2) used in multiple places
     */
    struct aws_byte_buf canonical_request;
    struct aws_byte_buf string_to_sign;
    struct aws_byte_buf signed_headers;
    struct aws_byte_buf canonical_header_block;
    struct aws_byte_buf payload_hash;
    struct aws_byte_buf credential_scope;
    struct aws_byte_buf access_credential_scope;
    struct aws_byte_buf date;
};

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
struct aws_signing_state_aws *aws_signing_state_new(
    struct aws_allocator *allocator,
    const struct aws_signing_config_aws *config,
    const struct aws_signable *signable,
    aws_signing_complete_fn *on_complete,
    void *userdata);

AWS_AUTH_API
void aws_signing_state_destroy(struct aws_signing_state_aws *state);

/*
 * A set of functions that together performs the AWS signing process based
 * on the algorithm requested in the shared config.
 *
 * These must be called (presumably by the signer) in sequential order:
 *
 *   (1) aws_signing_build_canonical_request
 *   (2) aws_signing_build_string_to_sign
 *   (3) aws_signing_build_authorization_value
 */

AWS_AUTH_API
int aws_signing_build_canonical_request(struct aws_signing_state_aws *state);

AWS_AUTH_API
int aws_signing_build_string_to_sign(struct aws_signing_state_aws *state);

AWS_AUTH_API
int aws_signing_build_authorization_value(struct aws_signing_state_aws *state);

/*
 * Named constants particular to the sigv4 signing algorithm.  Can be moved to a public header
 * as needed.
 */
AWS_AUTH_API extern const struct aws_string *g_aws_signing_content_header_name;
AWS_AUTH_API extern const struct aws_string *g_aws_signing_algorithm_query_param_name;
AWS_AUTH_API extern const struct aws_string *g_aws_signing_credential_query_param_name;
AWS_AUTH_API extern const struct aws_string *g_aws_signing_date_name;
AWS_AUTH_API extern const struct aws_string *g_aws_signing_signed_headers_query_param_name;
AWS_AUTH_API extern const struct aws_string *g_aws_signing_authorization_header_name;
AWS_AUTH_API extern const struct aws_string *g_aws_signing_authorization_query_param_name;
AWS_AUTH_API extern const struct aws_string *g_aws_signing_security_token_name;

/**
 * Initializes the internal table of headers that should not be signed
 */
AWS_AUTH_API
int aws_signing_init_signing_tables(struct aws_allocator *allocator);

/**
 * Cleans up the internal table of headers that should not be signed
 */
AWS_AUTH_API
void aws_signing_clean_up_signing_tables(void);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNING_SIGV4_H */
