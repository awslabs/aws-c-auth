/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>
#include <aws/auth/identity.h>
#include <aws/common/macros.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>

struct aws_identity_base {
    enum aws_identity_type identity_type;

    struct aws_allocator *allocator;

    struct aws_ref_count ref_count;

    /* Optional */
    uint64_t expiration_timepoint_secs;
};
struct aws_identity_credentials {
    struct aws_identity_base identity_base;

    struct aws_credentials *credentials;
};
struct aws_identity_token {
    struct aws_identity_base identity_base;

    struct aws_string *token;
};

static void s_identity_destroy(struct aws_identity_base *base) {
    AWS_PRECONDITION(base);

    switch (base->identity_type) {
        case IDENTITY_AWS_CREDENTIALS: {
            struct aws_identity_credentials *cred_identity =
                AWS_CONTAINER_OF(base, struct aws_identity_credentials, identity_base);
            aws_credentials_release(cred_identity->credentials);
            aws_mem_release(base->allocator, cred_identity);
            /* code */
            break;
        }

        case IDENTITY_TOKEN: {
            struct aws_identity_token *token_identity =
                AWS_CONTAINER_OF(base, struct aws_identity_token, identity_base);
            aws_string_destroy(token_identity->token);
            aws_mem_release(base->allocator, token_identity);
            /* code */
            break;
        }
        default:
            break;
    }
}

struct aws_identity_base *aws_identity_new_credentials(
    struct aws_allocator *allocator,
    struct aws_credentials *credentials,
    uint64_t expiration_timepoint_secs) {
    struct aws_identity_credentials *cred_identity =
        aws_mem_acquire(allocator, sizeof(struct aws_identity_credentials));
    struct aws_identity_base *base = &cred_identity->identity_base;
    base->identity_type = IDENTITY_AWS_CREDENTIALS;
    base->allocator = allocator;
    base->expiration_timepoint_secs = expiration_timepoint_secs;

    aws_credentials_acquire(credentials);
    cred_identity->credentials = credentials;
    aws_ref_count_init(&base->ref_count, &base, (aws_simple_completion_callback *)s_identity_destroy);
}

struct aws_identity_base *aws_identity_new_token(
    struct aws_allocator *allocator,
    struct aws_byte_cursor token,
    uint64_t expiration_timepoint_secs) {
    struct aws_identity_token *token_identity = aws_mem_acquire(allocator, sizeof(struct aws_identity_token));

    struct aws_identity_base *base = &token_identity->identity_base;
    base->identity_type = IDENTITY_TOKEN;
    base->allocator = allocator;
    base->expiration_timepoint_secs = expiration_timepoint_secs;

    token_identity->token = aws_string_new_from_cursor(allocator, &token);
    aws_ref_count_init(&base->ref_count, &base, (aws_simple_completion_callback *)s_identity_destroy);
}

enum aws_identity_type aws_identity_get_type(const struct aws_identity_base *identity_base) {
    AWS_PRECONDITION(identity_base);
    return identity_base->identity_type;
}
struct aws_identity_base *aws_identity_acquire(struct aws_identity_base *identity_base) {
    if (identity_base) {
        aws_ref_count_acquire(&identity_base->ref_count);
    }
    return identity_base;
}
struct aws_identity_base *aws_identity_release(struct aws_identity_base *identity_base) {
    if (identity_base) {
        aws_ref_count_release(&identity_base->ref_count);
    }
    return NULL;
}

/* Return null if failed */
const struct aws_credentials *aws_identity_credentials_get_credentials(const struct aws_identity_base *identity_base);
/* Return null if failed. aws_string* or byte_cursor? */
const struct aws_string *aws_identity_token_get_token(const struct aws_identity_base *identity_base);

/******************************************* Identity provider **********************************************/

struct aws_identity_provider_credentials_provider_impl {
    struct aws_credentials_provider *credentials_provider;
};

static void s_on_credentials_provider_get_credentials(
    struct aws_credentials *credentials,
    int error_code,
    void *user_data);

static int s_identity_provider_get_identity_cp(
    struct aws_identity_provider *provider,
    aws_on_get_identity_callback_fn callback,
    void *user_data);

static void s_identity_provider_credentials_provider_destroy(struct aws_identity_provider *provider);

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
