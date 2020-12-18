/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/credentials_utils.h>
#include <aws/common/environment.h>
#include <aws/common/string.h>

struct aws_credentials_provider *aws_credentials_provider_new_vtable(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_vtable_options *options) {
    struct aws_credentials_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_credentials_provider));
    if (provider == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);

    aws_credentials_provider_init_base(provider, allocator, &options->provider_vtable, NULL);

    provider->shutdown_options = options->shutdown_options;

    return provider;
}
