
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

typedef void (on_aws_get_credentials_callback_fn)(struct aws_credentials *credentials, void *user_data);

typedef int (get_credentials_async_fn)(struct aws_credentials_provider *provider, on_aws_get_credentials_callback_fn callback, void *user_data);
typedef void (aws_credentials_provider_cleanup_fn)(struct aws_credentials_provider *provider);

struct aws_credentials_provider_vtable {
    get_credentials_async_fn *get_credentials_async;
    aws_credentials_provider_cleanup_fn *cleanup;
};

struct aws_credentials_provider {
    struct aws_credentials_provider_vtable *vtable;
    struct aws_allocator *allocator;
    void *impl;
};

struct aws_credentials_query {
    struct aws_credentials_provider *provider;
    on_aws_get_credentials_callback_fn *callback;
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
    struct aws_array_list providers;
};

AWS_EXTERN_C_BEGIN

/*
 * Credentials APIs
 */

/*
 * Does this need to be externally visible?
 */
AWS_AUTH_API
struct aws_credentials *aws_credentials_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token
);

AWS_AUTH_API
struct aws_credentials *aws_credentials_new_copy(struct aws_allocator *allocator, struct aws_credentials *credentials);

AWS_AUTH_API
void aws_credentials_destroy(struct aws_credentials* credentials);

/*
 * Credentials provider APIs
 */
AWS_AUTH_API
void aws_credentials_provider_destroy(struct aws_credentials_provider* provider);

AWS_AUTH_API
int aws_credentials_provider_get_credentials_async(struct aws_credentials_provider *provider, on_aws_get_credentials_callback_fn callback, void *user_data);

/*
 * Credentials provider variant creation
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_static_new(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token
);

AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_environment_new(struct aws_allocator *allocator);

AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_cached_new(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_cached_options *options
);

AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_profile_new(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_profile_options *options
);

AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_chain_new(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_chain_options *options
);

AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_chain_default_new(
    struct aws_allocator *allocator
);

AWS_EXTERN_C_END

#endif //AWS_AUTH_CREDENTIALS_PROVIDER_H
