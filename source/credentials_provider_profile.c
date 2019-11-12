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

#include <aws/auth/private/aws_profile.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/string.h>
#include <aws/io/tls_channel_handler.h>

/*
 * Profile provider implementation
 */

struct aws_credentials_provider_profile_file_impl {
    struct aws_string *config_file_path;
    struct aws_string *credentials_file_path;
    struct aws_string *profile_name;
};

static int s_profile_file_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_profile_file_impl *impl = provider->impl;
    struct aws_credentials *credentials = NULL;

    /*
     * Parse config file, if it exists
     */
    struct aws_profile_collection *config_profiles =
        aws_profile_collection_new_from_file(provider->allocator, impl->config_file_path, AWS_PST_CONFIG);

    if (config_profiles != NULL) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider successfully built config profile collection from file at (%s)",
            (void *)provider,
            aws_string_c_str(impl->config_file_path));
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed to build config profile collection from file at (%s)",
            (void *)provider,
            aws_string_c_str(impl->config_file_path));
    }

    /*
     * Parse credentials file, if it exists
     */
    struct aws_profile_collection *credentials_profiles =
        aws_profile_collection_new_from_file(provider->allocator, impl->credentials_file_path, AWS_PST_CREDENTIALS);

    if (credentials_profiles != NULL) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider successfully built credentials profile collection from file at (%s)",
            (void *)provider,
            aws_string_c_str(impl->credentials_file_path));
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed to build credentials profile collection from file at (%s)",
            (void *)provider,
            aws_string_c_str(impl->credentials_file_path));
    }

    /*
     * Merge the (up to) two sources into a single unified profile
     */
    struct aws_profile_collection *merged_profiles =
        aws_profile_collection_new_from_merge(provider->allocator, config_profiles, credentials_profiles);
    if (merged_profiles != NULL) {
        struct aws_profile *profile = aws_profile_collection_get_profile(merged_profiles, impl->profile_name);
        if (profile != NULL) {
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Profile credentials provider attempting to pull credentials from profile \"%s\"",
                (void *)provider,
                aws_string_c_str(impl->profile_name));
            credentials = aws_credentials_new_from_profile(provider->allocator, profile);
        } else {
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Profile credentials provider could not find a profile named \"%s\"",
                (void *)provider,
                aws_string_c_str(impl->profile_name));
        }
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed to merge config and credentials profile collections",
            (void *)provider);
    }

    callback(credentials, user_data);

    /*
     * clean up
     */
    aws_credentials_destroy(credentials);
    aws_profile_collection_destroy(merged_profiles);
    aws_profile_collection_destroy(config_profiles);
    aws_profile_collection_destroy(credentials_profiles);

    return AWS_OP_SUCCESS;
}

static void s_profile_file_credentials_provider_clean_up(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_profile_file_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_string_destroy(impl->config_file_path);
    aws_string_destroy(impl->credentials_file_path);
    aws_string_destroy(impl->profile_name);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_profile_file_vtable = {
    .get_credentials = s_profile_file_credentials_provider_get_credentials_async,
    .clean_up = s_profile_file_credentials_provider_clean_up,
    .shutdown = aws_credentials_provider_shutdown_nil};

struct aws_credentials_provider *aws_credentials_provider_new_profile(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_profile_options *options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_profile_file_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_profile_file_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_profile_file_vtable, impl);

    impl->credentials_file_path = aws_get_credentials_file_path(allocator, &options->credentials_file_name_override);
    if (impl->credentials_file_path == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed resolve credentials file path",
            (void *)provider);
        goto on_error;
    }

    impl->config_file_path = aws_get_config_file_path(allocator, &options->config_file_name_override);
    if (impl->config_file_path == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed resolve config file path",
            (void *)provider);
        goto on_error;
    }

    impl->profile_name = aws_get_profile_name(allocator, &options->profile_name_override);
    if (impl->profile_name == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Profile credentials provider failed to resolve profile name",
            (void *)provider);
        goto on_error;
    }

    return provider;

on_error:
    aws_credentials_provider_destroy(provider);

    return NULL;
}
