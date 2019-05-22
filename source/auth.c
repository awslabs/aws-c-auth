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

#include <aws/auth/private/aws_signing.h>
#include <aws/auth/private/cJSON.h>

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
    AWS_DEFINE_ERROR_INFO_AUTH(
        AWS_AUTH_SIGNING_UNSUPPORTED_ALGORITHM,
        "Attempt to sign an http request with an unusupported version of the AWS signing protocol"),
    AWS_DEFINE_ERROR_INFO_AUTH(
        AWS_AUTH_SIGNING_MISMATCHED_CONFIGURATION,
        "Attempt to sign an http request with a signing configuration unrecognized by the invoked signer"),
};
/* clang-format on */

static struct aws_error_info_list s_error_list = {
    .error_list = s_errors,
    .count = sizeof(s_errors) / sizeof(struct aws_error_info),
};

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
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_AUTH_SIGNING, "AuthSigning", "Subject for AWS request signing logging."),
};

static struct aws_log_subject_info_list s_auth_log_subject_list = {
    .subject_list = s_auth_log_subject_infos,
    .count = AWS_ARRAY_SIZE(s_auth_log_subject_infos),
};

static void *s_cJSONAlloc(size_t sz) {
    return aws_mem_acquire(aws_default_allocator(), sz);
}

static void s_cJSONFree(void *ptr) {
    aws_mem_release(aws_default_allocator(), ptr);
}

static bool s_library_initialized = false;

void aws_auth_library_init(struct aws_allocator *allocator) {
    (void)allocator;
    if (s_library_initialized) {
        return;
    }
    s_library_initialized = true;

    aws_register_error_info(&s_error_list);
    aws_register_log_subject_info_list(&s_auth_log_subject_list);

    AWS_FATAL_ASSERT(aws_signing_init_skipped_headers(allocator) == AWS_OP_SUCCESS);

    struct cJSON_Hooks allocation_hooks = {
        .malloc_fn = s_cJSONAlloc,
        .free_fn = s_cJSONFree
    };
    cJSON_InitHooks(&allocation_hooks);
}

void aws_auth_library_clean_up(void) {
    aws_signing_clean_up_skipped_headers();

    s_library_initialized = false;
}
