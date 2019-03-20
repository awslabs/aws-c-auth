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
#include <aws/auth/auth.h>

#include <aws/common/error.h>

#define AWS_DEFINE_ERROR_INFO_AUTH(CODE, STR) AWS_DEFINE_ERROR_INFO(CODE, STR, "aws-c-auth")

/* clang-format off */
static struct aws_error_info s_errors[] = {
    AWS_DEFINE_ERROR_INFO_AUTH(
        AWS_AUTH_PROFILE_PARSE_RECOVERABLE_ERROR,
        "Recoverable error while parsing an aws profile file"),
    AWS_DEFINE_ERROR_INFO_AUTH(
        AWS_AUTH_PROFILE_PARSE_FATAL_ERROR,
        "Fatal error while parsing an aws profile file"),
};
/* clang-format on */

static struct aws_error_info_list s_error_list = {
    .error_list = s_errors,
    .count = sizeof(s_errors) / sizeof(struct aws_error_info),
};

static bool s_error_strings_loaded = false;

void aws_auth_load_error_strings(void) {
    if (!s_error_strings_loaded) {
        s_error_strings_loaded = true;
        aws_register_error_info(&s_error_list);
    }
}

static struct aws_log_subject_info s_auth_log_subject_infos[] = {
    DEFINE_LOG_SUBJECT_INFO(
        AWS_LS_AUTH_GENERAL,
        "AuthGeneral",
        "Subject for aws-c-auth logging that defies categorization."),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_AUTH_PROFILE, "AuthProfile", "Subject for config profile related logging."),
    DEFINE_LOG_SUBJECT_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "AuthCredentialsProvider",
        "Subject for credentials provider related logging."),
};

static struct aws_log_subject_info_list s_auth_log_subject_list = {
    .subject_list = s_auth_log_subject_infos,
    .count = AWS_ARRAY_SIZE(s_auth_log_subject_infos),
};

static bool s_log_subject_strings_loaded = false;

void aws_auth_load_log_subject_strings(void) {
    if (!s_log_subject_strings_loaded) {
        s_log_subject_strings_loaded = true;
        aws_register_log_subject_info_list(&s_auth_log_subject_list);
    }
}
