/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/identity.h>

struct aws_identity_provider_credentials_provider_impl {
    struct aws_credentials_provider *credentials_provider;
};

static void s_on_credentials_provider_get_credentials(
    struct aws_credentials *credentials,
    int error_code,
    void *user_data) {}

static int s_identity_provider_get_identity_cp(
    struct aws_identity_provider *provider,
    aws_on_get_identity_callback_fn callback,
    void *user_data) {}

static void s_identity_provider_credentials_provider_destroy(struct aws_identity_provider *provider) {}

static struct aws_identity_provider_vtable s_aws_identity_provider_credential_provider_vtable = {
    .get_identity = s_identity_provider_get_identity_cp,
    .destroy = s_identity_provider_credentials_provider_destroy,
};

struct aws_identity_provider *aws_identity_provider_new_credentials_provider(
    struct aws_allocator *allocator,
    struct aws_credentials_provider *credentials_provider) {
    struct aws_identity_provider *provider = aws_mem_acquire(allocator, sizeof(struct aws_identity_provider));
    provider->allocator = allocator;

    return NULL;
}
