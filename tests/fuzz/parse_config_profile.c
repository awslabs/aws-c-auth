/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/auth/private/aws_profile.h>

#include <aws/common/byte_buf.h>

#include <assert.h>

/* NOLINTNEXTLINE(readability-identifier-naming) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    struct aws_allocator *allocator = aws_default_allocator();

    struct aws_byte_buf buffer;
    buffer.allocator = NULL;
    buffer.buffer = (uint8_t *)data;
    buffer.capacity = size;
    buffer.len = size;

    struct aws_profile_collection *profile_set =
        aws_profile_collection_new_from_buffer(allocator, &buffer, AWS_PST_CONFIG);
    aws_profile_collection_destroy(profile_set);

    return 0;
}
