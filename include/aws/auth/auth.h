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

enum aws_auth_errors {
    AWS_AUTH_PROFILE_PARSE_RECOVERABLE_ERROR = 0x1800,
    AWS_AUTH_PROFILE_PARSE_FATAL_ERROR,

    AWS_AUTH_ERROR_END_RANGE = 0x1BFF
};

enum aws_auth_log_subject {
    AWS_LS_AUTH_GENERAL = 0x1800,
    AWS_LS_AUTH_PROFILE,
    AWS_LS_AUTH_CREDENTIALS_PROVIDER,

    AWS_LS_AUTH_LAST = (AWS_LS_AUTH_GENERAL + AWS_LOG_SUBJECT_SPACE_SIZE - 1)
};

AWS_EXTERN_C_BEGIN

/**
 * Loads error strings for this library so that aws_last_error_str etc... will
 * return useful debug strings.
 */
AWS_AUTH_API
void aws_auth_load_error_strings(void);

/**
 * Loads log subject info strings for this library.
 */
AWS_AUTH_API
void aws_auth_load_log_subject_strings(void);

AWS_EXTERN_C_END


#endif /* AWS_AUTH_AUTH_H */
