
#ifndef AWS_AUTH_CREDENTIALS_H
#define AWS_AUTH_CREDENTIALS_H

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

#include <aws/common/array_list.h>
#include <aws/io/io.h>

struct aws_string;

struct aws_credentials {
    struct aws_allocator *allocator;
    struct aws_string *access_key_id;
    struct aws_string *secret_access_key;
    struct aws_string *session_token;
};

struct aws_credentials_provider;

typedef void(aws_on_get_credentials_callback_fn)(struct aws_credentials *credentials, void *user_data);

typedef int(aws_credentials_provider_get_credentials_fn)(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data);
typedef void(aws_credentials_provider_clean_up_fn)(struct aws_credentials_provider *provider);

struct aws_credentials_provider_vtable {
    aws_credentials_provider_get_credentials_fn *get_credentials;
    aws_credentials_provider_clean_up_fn *clean_up;
};

struct aws_credentials_provider {
    struct aws_credentials_provider_vtable *vtable;
    struct aws_allocator *allocator;
    void *impl;
};

struct aws_credentials_query {
    struct aws_credentials_provider *provider;
    aws_on_get_credentials_callback_fn *callback;
    void *user_data;
};

struct aws_credentials_provider_profile_options {
    const struct aws_string *profile_name_override;
    const struct aws_string *config_file_name_override;
    const struct aws_string *credentials_file_name_override;
};

struct aws_credentials_provider_cached_options {
    struct aws_credentials_provider *source;
    uint64_t refresh_time_in_milliseconds;
    aws_io_clock_fn *clock_fn;
};

struct aws_credentials_provider_chain_options {
    struct aws_credentials_provider **providers;
    size_t provider_count;
};

AWS_EXTERN_C_BEGIN

/*
 * Credentials APIs
 */

AWS_AUTH_API
struct aws_credentials *aws_credentials_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token);

AWS_AUTH_API
struct aws_credentials *aws_credentials_new_copy(struct aws_allocator *allocator, struct aws_credentials *credentials);

AWS_AUTH_API
void aws_credentials_destroy(struct aws_credentials *credentials);

/*
 * Credentials provider APIs
 */

AWS_AUTH_API
void aws_credentials_provider_destroy(struct aws_credentials_provider *provider);

AWS_AUTH_API
int aws_credentials_provider_get_credentials(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data);

/*
 * Credentials provider variant creation
 */

/*
 * A simple provider that just returns a fixed set of credentials
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_static_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token);

/*
 * A provider that returns credentials sourced from the environment variables:
 *
 * AWS_ACCESS_KEY_ID
 * AWS_SECRET_ACCESS_KEY
 * AWS_SESSION_TOKEN
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_environment(struct aws_allocator *allocator);

/*
 * A provider that functions as a caching decorating of another provider.
 *
 * For example, the default chain is implemented as:
 *
 * CachedProvider -> ProviderChain(EnvironmentProvider -> ProfileProvider -> ECS/EC2IMD etc...)
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_cached(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_cached_options *options);

/*
 * A provider that sources credentials from key-value profiles loaded from the aws credentials
 * file ("~/.aws/credentials" by default) and the aws config file ("~/.aws/config" by
 * default)
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_profile(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_profile_options *options);

/*
 * A provider that sources credentials from an ordered sequence of providers, with the overall result
 * being from the first provider to return a valid set of credentials
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_chain(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_chain_options *options);

/*
 * Creates the default provider chain used by most AWS SDKs.
 *
 * Generally:
 *
 * (1) Environment
 * (2) Profile
 * (3) (conditional, off by default) ECS
 * (4) (conditional, on by default) EC2 Instance Metadata
 *
 * Support for environmental control of the default provider chain is not yet
 * implemented.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_chain_default(struct aws_allocator *allocator);

AWS_EXTERN_C_END

#endif // AWS_AUTH_CREDENTIALS_PROVIDER_H
