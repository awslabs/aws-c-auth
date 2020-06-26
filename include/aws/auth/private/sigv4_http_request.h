#ifndef AWS_AUTH_SIGV4_HTTP_REQUEST_H
#define AWS_AUTH_SIGV4_HTTP_REQUEST_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/auth.h>

struct aws_http_message;

AWS_EXTERN_C_BEGIN

/*
 * An http request transformation that performs AWS sigv4 signing
 */
AWS_AUTH_API
int aws_sign_http_request_sigv4(struct aws_http_message *request, struct aws_allocator *allocator, void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGV4_HTTP_REQUEST_H */
