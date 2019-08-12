#ifndef AWS_AUTH_SIGV4_HTTP_REQUEST_H
#define AWS_AUTH_SIGV4_HTTP_REQUEST_H

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

struct aws_http_message;

AWS_EXTERN_C_BEGIN

/*
 * An http request transformation that performs AWS sigv4 signing
 */
AWS_AUTH_API
int aws_sign_http_request_sigv4(struct aws_http_message *request, struct aws_allocator *allocator, void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGV4_HTTP_REQUEST_H */
