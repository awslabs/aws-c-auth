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

#include <aws/auth/signable_constants.h>

#include <aws/common/string.h>

AWS_STATIC_STRING_FROM_LITERAL(s_aws_http_headers_property_list_name, "headers");
AWS_STATIC_STRING_FROM_LITERAL(s_aws_http_query_params_property_list_name, "params");
AWS_STATIC_STRING_FROM_LITERAL(s_aws_http_method_property_name, "method");
AWS_STATIC_STRING_FROM_LITERAL(s_aws_http_uri_property_name, "uri");

static struct aws_signable_http_constants s_http_constants = {
    .headers_property_list_name = (struct aws_string *)(&s_aws_http_headers_property_list_name_s),
    .query_params_property_list_name = (struct aws_string *)(&s_aws_http_query_params_property_list_name_s),
    .method_property_name = (struct aws_string *)(&s_aws_http_method_property_name_s),
    .uri_property_name = (struct aws_string *)(&s_aws_http_uri_property_name_s)};

AWS_AUTH_API
const struct aws_signable_http_constants *aws_get_http_signable_constants(void) {
    (void)s_aws_http_headers_property_list_name;
    (void)s_aws_http_query_params_property_list_name;
    (void)s_aws_http_method_property_name;
    (void)s_aws_http_uri_property_name;

    return &s_http_constants;
}
