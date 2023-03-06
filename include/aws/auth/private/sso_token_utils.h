#ifndef AWS_AUTH_TOKEN_PRIVATE_H
#define AWS_AUTH_TOKEN_PRIVATE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/auth.h>
#include <aws/auth/credentials.h>
#include <aws/common/date_time.h>

struct aws_sso_token {
    struct aws_string *token;
    struct aws_date_time expiration;
};

AWS_EXTERN_C_BEGIN

/* Construct token path which ~/.aws/sso/cache/<hex encoded sha1 of input>.json */
AWS_AUTH_API
struct aws_string *aws_construct_token_path(struct aws_allocator *allocator, const struct aws_string *input);

AWS_AUTH_API
void aws_sso_token_destroy(struct aws_allocator *allocator, struct aws_sso_token *token);

AWS_AUTH_API
struct aws_sso_token *aws_sso_token_new_from_file(struct aws_allocator *allocator, const struct aws_string *file_path);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_CREDENTIALS_PRIVATE_H */
