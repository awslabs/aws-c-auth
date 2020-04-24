/*
 * Copyright 2010-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/auth/external/cJSON.h>
#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/date_time.h>
#include <aws/common/environment.h>
#include <aws/common/process.h>
#include <aws/common/string.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

struct aws_credentials_provider_process_impl {
    struct aws_string *command;
};

AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_name, "AccessKeyId");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_name, "SecretAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_name, "Token");
AWS_STATIC_STRING_FROM_LITERAL(s_creds_expiration_name, "Expiration");

static struct aws_credentials *s_parse_credentials_from_json_document(
    struct aws_allocator *allocator,
    struct aws_byte_buf *document) {

    struct aws_credentials *credentials = NULL;
    cJSON *document_root = NULL;
    bool success = false;
    bool parse_error = true;

    document_root = cJSON_Parse((const char *)document->buffer);
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse process output as Json document.");
        goto done;
    }

    /*
     * Pull out the three credentials components
     */
    cJSON *access_key_id = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_access_key_id_name));
    if (!cJSON_IsString(access_key_id) || (access_key_id->valuestring == NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse AccessKeyId from process output Json document.");
        goto done;
    }

    cJSON *secret_access_key =
        cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_secret_access_key_name));
    if (!cJSON_IsString(secret_access_key) || (secret_access_key->valuestring == NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse SecretAccessKey from process output Json document.");
        goto done;
    }

    cJSON *session_token = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_session_token_name));
    if (!cJSON_IsString(session_token) || (session_token->valuestring == NULL)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Token from process output Json document.");
        goto done;
    }

    cJSON *creds_expiration =
        cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_creds_expiration_name));
    if (!cJSON_IsString(creds_expiration) || (creds_expiration->valuestring == NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Expiration from process output Json document.");
        goto done;
    }

    /*
     * Build the credentials
     */
    struct aws_byte_cursor access_key_id_cursor = aws_byte_cursor_from_c_str(access_key_id->valuestring);
    struct aws_byte_cursor secret_access_key_cursor = aws_byte_cursor_from_c_str(secret_access_key->valuestring);
    struct aws_byte_cursor session_token_cursor = aws_byte_cursor_from_c_str(session_token->valuestring);
    struct aws_byte_cursor creds_expiration_cursor = aws_byte_cursor_from_c_str(creds_expiration->valuestring);

    if (access_key_id_cursor.len == 0 || secret_access_key_cursor.len == 0 || session_token_cursor.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Process credentials provider received unexpected output,"
            " either access key, secret key or token is empty.")
        goto done;
    }

    credentials = aws_credentials_new_from_cursors(
        allocator, &access_key_id_cursor, &secret_access_key_cursor, &session_token_cursor);

    if (credentials == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Process credentials provider failed to allocate memory for credentials.");
        parse_error = false;
        goto done;
    }

    if (creds_expiration_cursor.len != 0) {
        struct aws_date_time expiration;
        if (aws_date_time_init_from_str_cursor(&expiration, &creds_expiration_cursor, AWS_DATE_FORMAT_ISO_8601) ==
            AWS_OP_ERR) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Expiration in command output Json data is not a valid ISO_8601 date string.");
            aws_credentials_destroy(credentials);
            credentials = NULL;
            goto done;
        }
        credentials->expiration_timepoint_seconds = (uint64_t)aws_date_time_as_epoch_secs(&expiration);
    }
    success = true;
done:
    if (!success && parse_error) {
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
    }

    if (document_root != NULL) {
        cJSON_Delete(document_root);
    }

    return credentials;
}

static int s_get_credentials_from_process(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_process_impl *impl = provider->impl;
    struct aws_credentials *credentials = NULL;
    struct aws_run_command_options options = {.command = aws_string_c_str(impl->command)};
    struct aws_run_command_result result;
    int ret = AWS_OP_ERR;
    if (aws_run_command_result_init(provider->allocator, &result)) {
        goto on_finish;
    }

    if (aws_run_command(provider->allocator, &options, &result) || result.ret_code || !result.std_out) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Failed to source credentials from running process credentials provider with command: %s, err:%s",
            (void *)provider,
            aws_string_c_str(impl->command),
            aws_error_str(aws_last_error()));
        goto on_finish;
    }

    struct aws_byte_buf doc_buf = aws_byte_buf_from_array(result.std_out->bytes, result.std_out->len);
    credentials = s_parse_credentials_from_json_document(provider->allocator, &doc_buf);
    if (!credentials) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Process credentials provider failed to parse credentials from command output (output is not "
            "logged in case sensitive information).",
            (void *)provider);
        goto on_finish;
    }

    AWS_LOGF_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Process credentials provider successfully sourced credentials.",
        (void *)provider);
    ret = AWS_OP_SUCCESS;

on_finish:
    callback(credentials, user_data);
    aws_run_command_result_cleanup(&result);
    aws_credentials_destroy(credentials);
    return ret;
}

static void s_credentials_provider_process_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_process_impl *impl = provider->impl;
    if (impl) {
        aws_string_destroy_secure(impl->command);
    }
    aws_credentials_provider_invoke_shutdown_callback(provider);
    aws_mem_release(provider->allocator, provider);
}

AWS_STATIC_STRING_FROM_LITERAL(s_credentials_process, "credential_process");
static struct aws_byte_cursor s_default_profile_name_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("default");

static struct aws_profile_collection *s_load_profile(struct aws_allocator *allocator) {

    struct aws_profile_collection *config_profiles = NULL;
    struct aws_string *config_file_path = NULL;

    config_file_path = aws_get_config_file_path(allocator, NULL);
    if (!config_file_path) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to resolve config file path during process credentials provider initialization: %s",
            aws_error_str(aws_last_error()));
        goto on_error;
    }

    config_profiles = aws_profile_collection_new_from_file(allocator, config_file_path, AWS_PST_CONFIG);
    if (config_profiles != NULL) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Successfully built config profile collection from file at (%s)",
            aws_string_c_str(config_file_path));
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to build config profile collection from file at (%s) : %s",
            aws_string_c_str(config_file_path),
            aws_error_str(aws_last_error()));
        goto on_error;
    }

    aws_string_destroy(config_file_path);
    return config_profiles;

on_error:
    aws_string_destroy(config_file_path);
    aws_profile_collection_destroy(config_profiles);
    return NULL;
}

static void s_check_or_get_with_profile_config(
    struct aws_allocator *allocator,
    struct aws_profile *profile,
    struct aws_string **target,
    const struct aws_string *config_key) {

    if (!allocator || !profile || !config_key) {
        return;
    }
    if ((!(*target) || !(*target)->len)) {
        if (*target) {
            aws_string_destroy(*target);
        }
        struct aws_profile_property *property = aws_profile_get_property(profile, config_key);
        if (property) {
            *target = aws_string_new_from_string(allocator, property->value);
        }
    }
}

static struct aws_string *s_get_command(struct aws_allocator *allocator, const struct aws_string *profile_to_use) {

    bool success = false;
    struct aws_string *command = NULL;
    struct aws_profile_collection *config_profile = NULL;
    struct aws_string *profile_name = NULL;
    struct aws_profile *profile = NULL;

    config_profile = s_load_profile(allocator);
    if (!profile_to_use || !profile_to_use->len) {
        profile_name = aws_get_profile_name(allocator, &s_default_profile_name_cursor);
    } else {
        profile_name = aws_string_new_from_string(allocator, profile_to_use);
    }
    if (config_profile && profile_name) {
        profile = aws_profile_collection_get_profile(config_profile, profile_name);
    }

    if (!profile) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to resolve config profile during process credentials provider initialization.");
        goto on_finish;

    } else {
        s_check_or_get_with_profile_config(allocator, profile, &command, s_credentials_process);
    }

    if (!command || !command->len) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "Failed to resolve credentials_process command during process credentials provider initialization.")
        goto on_finish;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "Successfully loaded credentials_process command for process credentials provider.")
    success = true;

on_finish:
    aws_string_destroy(profile_name);
    aws_profile_collection_destroy(config_profile);
    if (!success) {
        aws_string_destroy(command);
    }
    return command;
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_process_vtable = {
    .get_credentials = s_get_credentials_from_process,
    .destroy = s_credentials_provider_process_destroy,
};

static struct aws_byte_cursor s_stderr_redirect_to_stdout = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(" 2>&1");

struct aws_credentials_provider *aws_credentials_provider_new_process(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_process_options *options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_process_impl *impl = NULL;
    struct aws_string *command = NULL;
    struct aws_byte_buf command_with_stderr_redirected;
    AWS_ZERO_STRUCT(command_with_stderr_redirected);

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_process_impl));

    if (!provider) {
        goto on_error;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    command = s_get_command(allocator, options->profile_to_use);
    if (!command) {
        goto on_error;
    }

    struct aws_byte_cursor command_cursor = aws_byte_cursor_from_string(command);
    if (aws_byte_buf_init_copy_from_cursor(&command_with_stderr_redirected, allocator, command_cursor)) {
        goto on_error;
    }
    if (aws_byte_buf_append_dynamic(&command_with_stderr_redirected, &s_stderr_redirect_to_stdout)) {
        goto on_error;
    }
    impl->command =
        aws_string_new_from_array(allocator, command_with_stderr_redirected.buffer, command_with_stderr_redirected.len);

    if (!impl->command) {
        goto on_error;
    }

    aws_string_destroy_secure(command);
    aws_byte_buf_clean_up_secure(&command_with_stderr_redirected);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_process_vtable, impl);
    provider->shutdown_options = options->shutdown_options;
    AWS_LOGF_TRACE(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p): Successfully initializing a process credentials provider.",
        (void *)provider);

    return provider;

on_error:
    aws_string_destroy(command);
    aws_byte_buf_clean_up(&command_with_stderr_redirected);
    aws_mem_release(allocator, provider);
    return NULL;
}
