#ifndef AWS_AUTH_AUTH_H
#define AWS_AUTH_AUTH_H

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

#include <aws/auth/exports.h>

#include <aws/io/logging.h>

#define AWS_C_AUTH_PACKAGE_ID 6

enum aws_auth_errors {
    AWS_AUTH_PROFILE_PARSE_RECOVERABLE_ERROR = AWS_ERROR_ENUM_BEGIN_RANGE(AWS_C_AUTH_PACKAGE_ID),
    AWS_AUTH_PROFILE_PARSE_FATAL_ERROR,
    AWS_AUTH_SIGNING_UNSUPPORTED_ALGORITHM,
    AWS_AUTH_SIGNING_MISMATCHED_CONFIGURATION,
    AWS_AUTH_SIGNING_NO_CREDENTIALS,
    AWS_AUTH_SIGNING_ILLEGAL_REQUEST_QUERY_PARAM,
    AWS_AUTH_SIGNING_ILLEGAL_REQUEST_HEADER,
    AWS_AUTH_SIGNING_INVALID_CONFIGURATION,
    AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE,

    AWS_AUTH_ERROR_END_RANGE = AWS_ERROR_ENUM_END_RANGE(AWS_C_AUTH_PACKAGE_ID)
};

enum aws_auth_log_subject {
    AWS_LS_AUTH_GENERAL = AWS_LOG_SUBJECT_BEGIN_RANGE(AWS_C_AUTH_PACKAGE_ID),
    AWS_LS_AUTH_PROFILE,
    AWS_LS_AUTH_CREDENTIALS_PROVIDER,
    AWS_LS_AUTH_SIGNING,

    AWS_LS_AUTH_LAST = AWS_LOG_SUBJECT_END_RANGE(AWS_C_AUTH_PACKAGE_ID)
};

AWS_EXTERN_C_BEGIN

/**
 * Initializes internal datastructures used by aws-c-auth.
 * Must be called before using any functionality in aws-c-auth.
 */
AWS_AUTH_API
void aws_auth_library_init(struct aws_allocator *allocator);

/**
 * Clean up internal datastructures used by aws-c-auth.
 * Must not be called until application is done using functionality in aws-c-auth.
 */
AWS_AUTH_API
void aws_auth_library_clean_up(void);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_AUTH_H */
