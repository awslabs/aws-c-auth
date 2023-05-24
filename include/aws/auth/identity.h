#ifndef AWS_AUTH_IDENTITY_H
#define AWS_AUTH_IDENTITY_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/auth.h>
#include <aws/auth/credentials.h>
#include <aws/common/date_time.h>

enum aws_identity_type {
    AWS_CREDENTIALS_IDENTITY,
    TOKEN_IDENTITY,
    ANONYMOUS_IDENTITY,
};

/*************************************** Private, move to .c later ***************************************/
struct aws_identity_base {
    enum aws_identity_type identity_type;

    struct aws_allocator *allocator;

    struct aws_atomic_var ref_count;

    /* Optional */
    struct aws_date_time *expiration;
};
struct aws_identity_credentials {
    struct aws_identity_base identity_base;
    struct aws_credentials *credentials;
};
struct aws_identity_token {
    struct aws_identity_base identity_base;
    struct aws_string *token;
};

/*************************************** END Private ***************************************/

struct aws_identity_base *aws_identity_new_credentials(
    struct aws_allocator *allocator,
    struct aws_credentials *credentials);
struct aws_identity_base *aws_identity_new_token(struct aws_allocator *allocator, struct aws_byte_cursor token);

enum aws_identity_type aws_identity_get_type(struct aws_identity_base *identity_base);
struct aws_identity_base *aws_identity_acquire(struct aws_identity_base *identity_base);
struct aws_identity_base *aws_identity_release(struct aws_identity_base *identity_base);

/************   Identity provider    ****************/

struct aws_identity_provider;

typedef void(aws_on_get_identity_callback_fn)(struct aws_identity_base *identity, int error_code, void *user_data);

typedef int(aws_identity_provider_get_identity_fn)(
    struct aws_identity_provider *provider,
    aws_on_get_identity_callback_fn callback,
    void *user_data);
typedef void(aws_identity_provider_destroy_fn)(struct aws_identity_provider *provider);

struct aws_identity_provider_vtable {
    aws_identity_provider_get_identity_fn *get_identity;
    aws_identity_provider_destroy_fn *destroy;
};

typedef void(aws_identity_provider_shutdown_completed_fn)(void *user_data);

struct aws_identity_provider_shutdown_options {
    aws_identity_provider_shutdown_completed_fn *shutdown_callback;
    void *shutdown_user_data;
};

struct aws_identity_provider {
    enum aws_identity_type identity_type;
    struct aws_identity_provider_vtable *vtable;
    struct aws_allocator *allocator;
    struct aws_identity_provider_shutdown_options shutdown_options;
    void *impl;
    struct aws_atomic_var ref_count;
};

AWS_EXTERN_C_BEGIN
AWS_AUTH_API
struct aws_identity_provider *aws_identity_provider_new_credentials_provider(
    struct aws_allocator *allocator,
    struct aws_credentials_provider *credentials_provider);

void aws_identity_provider_init_with_credentials_provider(
    struct aws_identity_provider *identity_provider,
    struct aws_credentials_provider *credentials_provider);

AWS_AUTH_API
int aws_identity_provider_get_identity(
    struct aws_identity_provider *provider,
    aws_on_get_identity_callback_fn callback,
    void *user_data);

AWS_EXTERN_C_END
#endif /* AWS_AUTH_IDENTITY_H */
