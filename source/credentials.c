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

#include <aws/auth/credentials.h>

#include <aws/common/string.h>

struct aws_credentials *aws_credentials_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token) {

    struct aws_credentials *credentials =
        (struct aws_credentials *)(aws_mem_acquire(allocator, sizeof(struct aws_credentials)));
    if (credentials == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*credentials);

    credentials->allocator = allocator;

    if (access_key_id != NULL) {
        credentials->access_key_id = aws_string_new_from_string(allocator, access_key_id);
    }

    if (secret_access_key != NULL) {
        credentials->secret_access_key = aws_string_new_from_string(allocator, secret_access_key);
    }

    if (session_token != NULL) {
        credentials->session_token = aws_string_new_from_string(allocator, session_token);
    }

    return credentials;
}

struct aws_credentials *aws_credentials_new_copy(struct aws_allocator *allocator, struct aws_credentials *credentials) {
    return aws_credentials_new(
        allocator, credentials->access_key_id, credentials->secret_access_key, credentials->session_token);
}

void aws_credentials_destroy(struct aws_credentials *credentials) {

    if (credentials->access_key_id != NULL) {
        aws_string_destroy(credentials->access_key_id);
    }

    if (credentials->secret_access_key != NULL) {
        aws_string_destroy(credentials->secret_access_key);
    }

    if (credentials->session_token != NULL) {
        aws_string_destroy(credentials->session_token);
    }

    aws_mem_release(credentials->allocator, credentials);
}
