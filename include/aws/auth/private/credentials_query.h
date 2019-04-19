#ifndef AWS_AUTH_CREDENTIALS_PRIVATE_H
#define AWS_AUTH_CREDENTIALS_PRIVATE_H

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

#include <aws/auth/credentials.h>

/*
 * Internal struct tracking an asynchronous credentials query.
 * Used by both the cached provider and the test mocks.
 *
 */
struct aws_credentials_query {
    struct aws_linked_list_node node;
    struct aws_credentials_provider *provider;
    aws_on_get_credentials_callback_fn *callback;
    void *user_data;
};

AWS_EXTERN_C_BEGIN

/*
 * Credentials query APIs
 */

AWS_AUTH_API
void aws_credentials_query_init(
    struct aws_credentials_query *query,
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn *callback,
    void *user_data);

AWS_AUTH_API
void aws_credentials_query_clean_up(struct aws_credentials_query *query);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_CREDENTIALS_PRIVATE_H */
