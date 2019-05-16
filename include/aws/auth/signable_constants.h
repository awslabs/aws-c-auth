#ifndef AWS_AUTH_SIGNABLE_CONSTANTS_H
#define AWS_AUTH_SIGNABLE_CONSTANTS_H

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

struct aws_string;

struct aws_signable_http_constants {

    /**
     * Name of the property list that wraps the headers of an http request
     */
    const struct aws_string *headers_property_list_name;

    /**
     * Name of the property list that wraps the query params of an http request.  Only used by signing_result.
     * For input to a http signing algorithm, query params are assumed to be part of the uri.
     */
    const struct aws_string *query_params_property_list_name;

    /**
     * Name of the property that holds the method of an http request
     */
    const struct aws_string *method_property_name;

    /**
     * Name of the property that holds the URI of an http request
     */
    const struct aws_string *uri_property_name;
};

AWS_AUTH_API
const struct aws_signable_http_constants *aws_get_http_signable_constants(void);

#endif /* AWS_AUTH_SIGNABLE_CONSTANTS_H */
