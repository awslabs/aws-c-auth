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

#include <aws/http/request_response.h>

struct aws_http_request_options;
struct aws_input_stream;

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
int aws_sign_http_request_identity(
    struct aws_allocator *allocator,
    struct aws_http_request_options *input_request,
    struct aws_input_stream *payload_stream,
    const char *signing_region,
    const char *signing_service,
    struct aws_http_request_options **output_request,
    aws_http_request_options_destroy_fn **request_cleanup);

AWS_AUTH_API
int aws_sign_http_request_sigv4(
    struct aws_allocator *allocator,
    struct aws_http_request_options *input_request,
    struct aws_input_stream *payload_stream,
    const char *signing_region,
    const char *signing_service,
    struct aws_http_request_options **output_request,
    aws_http_request_options_destroy_fn **request_cleanup);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGV4_HTTP_REQUEST_H */
