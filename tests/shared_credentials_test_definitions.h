#ifndef SHARED_CREDENTIALS_TEST_DEFINITIONS_H
#define SHARED_CREDENTIALS_TEST_DEFINITIONS_H
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

#include <aws/common/string.h>
#include <aws/io/file_utils.h>

#include <errno.h>

#ifdef _MSC_VER
/* fopen, fprintf etc... */
#    pragma warning( push )
#    pragma warning(disable : 4996)
#endif

AWS_STATIC_STRING_FROM_LITERAL(s_config_file_name, "./.config_test");
AWS_STATIC_STRING_FROM_LITERAL(s_credentials_file_name, "./.credentials_test");
AWS_STATIC_STRING_FROM_LITERAL(s_default_profile_env_variable_name, "AWS_PROFILE");
AWS_STATIC_STRING_FROM_LITERAL(s_default_config_path_env_variable_name, "AWS_CONFIG_FILE");
AWS_STATIC_STRING_FROM_LITERAL(s_default_credentials_path_env_variable_name, "AWS_SHARED_CREDENTIALS_FILE");
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_env_var, "AWS_ACCESS_KEY_ID");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_env_var, "AWS_SECRET_ACCESS_KEY");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_env_var, "AWS_SESSION_TOKEN");

static int aws_create_profile_file(const struct aws_string *file_name, const struct aws_string *file_contents) {
    (void)s_session_token_env_var;

    FILE *fp = fopen(aws_string_c_str(file_name), "w");
    if (fp == NULL) {
        return aws_translate_and_raise_io_error(errno);
    }

    int result = fprintf(fp, "%s", aws_string_c_str(file_contents));
    fclose(fp);

    if (result < 0) {
        return aws_translate_and_raise_io_error(errno);
    }

    return AWS_OP_SUCCESS;
}

#ifdef _MSC_VER
#    pragma warning( pop )
#endif

#endif /* SHARED_CREDENTIALS_TEST_DEFINITIONS_H */
