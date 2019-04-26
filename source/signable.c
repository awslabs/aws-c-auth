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

#include <aws/auth/signable.h>

#include <aws/common/string.h>

void aws_signable_destroy(struct aws_signable *signable) {
    if (signable == NULL) {
        return;
    }

    if (signable->vtable != NULL) {
        assert(signable->vtable->clean_up);

        signable->vtable->clean_up(signable);
    }

    aws_mem_release(signable->allocator, signable);
}

AWS_STRING_FROM_LITERAL(g_aws_http_headers_property_list_name, "headers");
AWS_STRING_FROM_LITERAL(g_aws_http_query_params_property_list_name, "params");
AWS_STRING_FROM_LITERAL(g_aws_http_method_property_name, "method");
AWS_STRING_FROM_LITERAL(g_aws_http_uri_property_name, "uri");
