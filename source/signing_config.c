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

#include <aws/auth/signing_config.h>

static const char *s_algorithm_names[AWS_SIGNING_ALGORITHM_COUNT] = {"Aws SigV4"};

const char *aws_signing_algorithm_to_string(enum aws_signing_algorithm algorithm) {
    if (algorithm < AWS_SIGNING_ALGORITHM_COUNT) {
        return s_algorithm_names[algorithm];
    }

    return "Unknown";
}

int aws_validate_aws_signing_config_aws(const struct aws_signing_config_aws *config) {
    if (config == NULL) {
        return aws_raise_error(AWS_AUTH_SIGNING_INVALID_CONFIGURATION);
    }

    if (config->region.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_SIGNING, "(id=%p) Signing config is missing a region identifier", (void *)config);
        return aws_raise_error(AWS_AUTH_SIGNING_INVALID_CONFIGURATION);
    }

    if (config->service.len == 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_SIGNING, "(id=%p) Signing config is missing a service identifier", (void *)config);
        return aws_raise_error(AWS_AUTH_SIGNING_INVALID_CONFIGURATION);
    }

    if (config->credentials_provider == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_SIGNING,
            "(id=%p) Signing config is missing a credentials provider or credentials",
            (void *)config);
        return aws_raise_error(AWS_AUTH_SIGNING_INVALID_CONFIGURATION);
    }

    return AWS_OP_SUCCESS;
}
