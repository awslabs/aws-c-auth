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

#include <aws/auth/signing.h>

#include <aws/auth/credentials.h>
#include <aws/auth/private/aws_signing.h>
#include <aws/io/uri.h>

/*
 * Aws signing implementation
 */

aws_on_get_credentials_callback_fn s_aws_signing_on_get_credentials;

int aws_sign_request_aws(
    struct aws_allocator *allocator,
    const struct aws_signable *signable,
    const struct aws_signing_config_base *base_config,
    aws_signing_complete_fn *on_complete,
    void *userdata) {

    AWS_PRECONDITION(base_config);

    if (base_config->config_type != AWS_SIGNING_CONFIG_AWS) {
        return aws_raise_error(AWS_AUTH_SIGNING_MISMATCHED_CONFIGURATION);
    }

    const struct aws_signing_config_aws *config = (void *)base_config;

    struct aws_signing_state_aws *signing_state =
        aws_signing_state_new(allocator, config, signable, on_complete, userdata);
    if (!signing_state) {
        return AWS_OP_ERR;
    }

    if (aws_credentials_provider_get_credentials(
            config->credentials_provider, s_aws_signing_on_get_credentials, signing_state)) {
        goto cleanup;
    }

    return AWS_OP_SUCCESS;

cleanup:
    aws_signing_state_destroy(signing_state);
    return AWS_OP_ERR;
}

void s_aws_signing_on_get_credentials(struct aws_credentials *credentials, void *user_data) {
    struct aws_signing_state_aws *state = user_data;

    struct aws_signing_result *result = NULL;
    int error_code = AWS_ERROR_SUCCESS;

    if (!credentials) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_SIGNING, "(id=%p) Credentials Provider provided no credentials", (void *)state->signable);

        error_code = AWS_AUTH_SIGNING_NO_CREDENTIALS;
        goto cleanup;
    }

    state->credentials = credentials;

    if (aws_signing_build_canonical_request(state)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_SIGNING,
            "(id=%p) Http request failed to build canonical request via algorithm %s",
            (void *)state->signable,
            aws_signing_algorithm_to_string(state->config.algorithm));
        error_code = aws_last_error();
        goto cleanup;
    }

    AWS_LOGF_INFO(
        AWS_LS_AUTH_SIGNING,
        "(id=%p) Http request successfully built canonical request for algorithm %s, with contents \"" PRInSTR "\"",
        (void *)state->signable,
        aws_signing_algorithm_to_string(state->config.algorithm),
        AWS_BYTE_BUF_PRI(state->canonical_request));

    if (aws_signing_build_string_to_sign(state)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_SIGNING,
            "(id=%p) Http request failed to build string-to-sign via algorithm %s",
            (void *)state->signable,
            aws_signing_algorithm_to_string(state->config.algorithm));
        error_code = aws_last_error();
        goto cleanup;
    }

    AWS_LOGF_INFO(
        AWS_LS_AUTH_SIGNING,
        "(id=%p) Http request successfully built string-to-sign via algorithm %s, with contents \"" PRInSTR "\"",
        (void *)state->signable,
        aws_signing_algorithm_to_string(state->config.algorithm),
        AWS_BYTE_BUF_PRI(state->string_to_sign));

    if (aws_signing_build_authorization_value(state)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_SIGNING,
            "(id=%p) Http request failed to build final authorization value via algorithm %s",
            (void *)state->signable,
            aws_signing_algorithm_to_string(state->config.algorithm));
        error_code = aws_last_error();
        goto cleanup;
    }

    result = &state->result;

cleanup:

    state->on_complete(result, error_code, state->userdata);
    aws_signing_state_destroy(state);
}
