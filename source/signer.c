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

#include <aws/auth/signer.h>

#include <aws/auth/private/aws_signing.h>
#include <aws/io/uri.h>

void aws_signer_destroy(struct aws_signer *signer) {
    if (signer == NULL) {
        return;
    }

    AWS_ASSERT(signer->vtable->clean_up);
    signer->vtable->clean_up(signer);

    aws_mem_release(signer->allocator, signer);
}

int aws_signer_sign_request(
    struct aws_signer *signer,
    const struct aws_signable *signable,
    const struct aws_signing_config_base *base_config,
    struct aws_signing_result *result) {
    AWS_ASSERT(signer && signable);
    AWS_ASSERT(signer->vtable && signer->vtable->sign_request);

    return signer->vtable->sign_request(signer, signable, base_config, result);
}

/*
 * Aws signing implementation
 */

static int s_aws_signer_aws_sign_request(
    struct aws_signer *signer,
    const struct aws_signable *signable,
    const struct aws_signing_config_base *base_config,
    struct aws_signing_result *result) {
    if (base_config->config_type != AWS_SIGNING_CONFIG_AWS) {
        return aws_raise_error(AWS_AUTH_SIGNING_MISMATCHED_CONFIGURATION);
    }

    int signing_result = AWS_OP_ERR;

    const struct aws_signing_config_aws *config = (void *)base_config;

    struct aws_signing_state_aws signing_state;
    AWS_ZERO_STRUCT(signing_state);

    if (aws_signing_state_init(&signing_state, signer->allocator, config, signable, result)) {
        goto cleanup;
    }

    if (aws_signing_build_canonical_request(&signing_state)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_SIGNING,
            "(id=%p) Http request failed to build canonical request via algorithm %s",
            (void *)signable,
            aws_signing_algorithm_to_string(config->algorithm));
        goto cleanup;
    }

    AWS_LOGF_INFO(
        AWS_LS_AUTH_SIGNING,
        "(id=%p) Http request successfully built canonical request for algorithm %s, with contents \"" PRInSTR "\"",
        (void *)signable,
        aws_signing_algorithm_to_string(config->algorithm),
        AWS_BYTE_BUF_PRI(signing_state.canonical_request));

    if (aws_signing_build_string_to_sign(&signing_state)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_SIGNING,
            "(id=%p) Http request failed to build string-to-sign via algorithm %s",
            (void *)signable,
            aws_signing_algorithm_to_string(config->algorithm));
        goto cleanup;
    }

    AWS_LOGF_INFO(
        AWS_LS_AUTH_SIGNING,
        "(id=%p) Http request successfully built string-to-sign via algorithm %s, with contents \"" PRInSTR "\"",
        (void *)signable,
        aws_signing_algorithm_to_string(config->algorithm),
        AWS_BYTE_BUF_PRI(signing_state.string_to_sign));

    if (aws_signing_build_authorization_value(&signing_state)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_SIGNING,
            "(id=%p) Http request failed to build final authorization value via algorithm %s",
            (void *)signable,
            aws_signing_algorithm_to_string(config->algorithm));
        goto cleanup;
    }

    signing_result = AWS_OP_SUCCESS;

cleanup:

    aws_signing_state_clean_up(&signing_state);

    return signing_result;
}

static void s_aws_signer_aws_clean_up(struct aws_signer *signer) {
    (void)signer;
}

static struct aws_signer_vtable s_aws_signer_aws_vtable = {.sign_request = s_aws_signer_aws_sign_request,
                                                           .clean_up = s_aws_signer_aws_clean_up};

struct aws_signer *aws_signer_new_aws(struct aws_allocator *allocator) {
    struct aws_signer *signer = aws_mem_acquire(allocator, sizeof(struct aws_signer));
    if (signer == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*signer);

    signer->allocator = allocator;
    signer->vtable = &s_aws_signer_aws_vtable;
    signer->impl = NULL;

    return signer;
}
