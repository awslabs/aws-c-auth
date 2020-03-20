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
#include <aws/common/atomics.h>
#include <aws/common/linked_list.h>
#include <aws/io/io.h>

struct aws_client_bootstrap;
struct aws_credentials_provider_system_vtable;
struct aws_string;

extern const uint16_t aws_sts_assume_role_default_duration_secs;

/*
 * A structure that wraps the public/private data needed to sign an authenticated AWS request
 */
struct aws_credentials {
    struct aws_allocator *allocator;
    struct aws_string *access_key_id;
    struct aws_string *secret_access_key;
    struct aws_string *session_token;

    /*
     * A timepoint, in seconds since epoch, at which the credentials should no longer be used because they
     * will have expired.
     *
     *
     * The primary purpose of this value is to allow providers to communicate to the caching provider any
     * additional constraints on how the sourced credentials should be used (STS).  After refreshing the cached
     * credentials, the caching provider uses the following calculation to determine the next requery time:
     *
     *   next_requery_time = now + cached_expiration_config;
     *   if (cached_creds->expiration_timepoint_seconds < next_requery_time) {
     *       next_requery_time = cached_creds->expiration_timepoint_seconds;
     *
     *  The cached provider may, at its discretion, use a smaller requery time to avoid edge-case scenarios where
     *  credential expiration becomes a race condition.
     *
     * The following leaf providers always set this value to UINT64_MAX (indefinite):
     *    static
     *    environment
     *    imds
     *    profile_config*
     *
     *  * - profile_config may invoke sts which will use a non-max value
     *
     *  The following leaf providers set this value to a sensible timepoint:
     *    sts - value is based on current time + options->duration_seconds
     *
     */
    uint64_t expiration_timepoint_seconds;
};

struct aws_credentials_provider;

typedef void(aws_on_get_credentials_callback_fn)(struct aws_credentials *credentials, void *user_data);

typedef int(aws_credentials_provider_get_credentials_fn)(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data);
typedef void(aws_credentials_provider_destroy_fn)(struct aws_credentials_provider *provider);

struct aws_credentials_provider_vtable {
    aws_credentials_provider_get_credentials_fn *get_credentials;
    aws_credentials_provider_destroy_fn *destroy;
};

typedef void(aws_credentials_provider_shutdown_completed_fn)(void *user_data);

/*
 * All credentials providers support an optional shutdown callback that
 * gets invoked, with appropriate user data, when the resources used by the provider
 * are no longer in use.  For example, the imds provider uses this to
 * signal when it is no longer using the client bootstrap used in its
 * internal connection manager.
 */
struct aws_credentials_provider_shutdown_options {
    aws_credentials_provider_shutdown_completed_fn *shutdown_callback;
    void *shutdown_user_data;
};

/*
 * An interface for a variety of different methods for sourcing credentials.
 * Ref-counted.  Thread-safe.
 */
struct aws_credentials_provider {
    struct aws_credentials_provider_vtable *vtable;
    struct aws_allocator *allocator;
    struct aws_credentials_provider_shutdown_options shutdown_options;
    void *impl;
    struct aws_atomic_var ref_count;
};

/*
 * Config structs for creating all the different credentials providers
 */

struct aws_credentials_provider_static_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_byte_cursor access_key_id;
    struct aws_byte_cursor secret_access_key;
    struct aws_byte_cursor session_token;
};

struct aws_credentials_provider_environment_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
};

struct aws_credentials_provider_profile_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_byte_cursor profile_name_override;
    struct aws_byte_cursor config_file_name_override;
    struct aws_byte_cursor credentials_file_name_override;
    struct aws_client_bootstrap *bootstrap;

    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_credentials_provider_system_vtable *function_table;
};

struct aws_credentials_provider_cached_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_credentials_provider *source;
    uint64_t refresh_time_in_milliseconds;

    /* For mocking, leave NULL otherwise */
    aws_io_clock_fn *high_res_clock_fn;
    aws_io_clock_fn *system_clock_fn;
};

struct aws_credentials_provider_chain_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_credentials_provider **providers;
    size_t provider_count;
};

/*
 * IMDS_V1 takes two http requests to get IMDS credentials.
 * Prior to these two requests, IMDS_V2 takes one more token (Http PUT) request
 * to get secure token used in following requests.
 */
enum aws_credentials_provider_imds_versions {
    // defaults to use IMDS_V2
    IMDS_V2,
    IMDS_V1
};

struct aws_credentials_provider_imds_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_client_bootstrap *bootstrap;
    /* If not set, this value will be false, means use IMDS_V2 */
    enum aws_credentials_provider_imds_versions imds_version;
    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_credentials_provider_system_vtable *function_table;
};

/*
 * ECS creds provider can be used to access creds via either
 * relative uri to a fixed endpoint http://169.254.170.2,
 * or via a full uri specified by environment variables:
 * AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
 * AWS_CONTAINER_CREDENTIALS_FULL_URI
 * AWS_CONTAINER_AUTHORIZATION_TOKEN
 * If both relative uri and absolute uri are set, relative uri
 * has higher priority. Token is used in auth header but only for
 * absolute uri.
 * While above information is used in request only, endpoint info
 * is needed when creating ecs provider to initiate the connection
 * manager, more specifically, host and http scheme (tls or not)
 * from endpoint are needed.
 */
struct aws_credentials_provider_ecs_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_client_bootstrap *bootstrap;

    struct aws_byte_cursor host;
    struct aws_byte_cursor path_and_query;
    struct aws_byte_cursor auth_token;
    /* it is also used to determine the port: 443 or 80 */
    bool use_tls;

    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_credentials_provider_system_vtable *function_table;
};

struct aws_credentials_provider_sts_options {
    struct aws_client_bootstrap *bootstrap;
    struct aws_tls_ctx *tls_ctx;
    struct aws_credentials_provider *creds_provider;
    struct aws_byte_cursor role_arn;
    struct aws_byte_cursor session_name;
    uint16_t duration_seconds;
    struct aws_credentials_provider_shutdown_options shutdown_options;

    /* For mocking, leave NULL otherwise */
    struct aws_credentials_provider_system_vtable *function_table;
    aws_io_clock_fn *system_clock_fn;
};

struct aws_credentials_provider_chain_default_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_client_bootstrap *bootstrap;
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
struct aws_credentials *aws_credentials_new_from_cursors(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *access_key_id_cursor,
    const struct aws_byte_cursor *secret_access_key_cursor,
    const struct aws_byte_cursor *session_token_cursor);

AWS_AUTH_API
void aws_credentials_destroy(struct aws_credentials *credentials);

/*
 * Credentials provider APIs
 */

/*
 * Release a reference to a credentials provider
 */
AWS_AUTH_API
void aws_credentials_provider_release(struct aws_credentials_provider *provider);

/*
 * Add a reference to a credentials provider
 */
AWS_AUTH_API
void aws_credentials_provider_acquire(struct aws_credentials_provider *provider);

/*
 * Async function for retrieving credentials from a provider
 */
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
struct aws_credentials_provider *aws_credentials_provider_new_static(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_static_options *options);

/*
 * A provider that returns credentials sourced from the environment variables:
 *
 * AWS_ACCESS_KEY_ID
 * AWS_SECRET_ACCESS_KEY
 * AWS_SESSION_TOKEN
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_environment(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_environment_options *options);

/*
 * A provider that functions as a caching decorating of another provider.
 *
 * For example, the default chain is implemented as:
 *
 * CachedProvider -> ProviderChain(EnvironmentProvider -> ProfileProvider -> ECS/EC2IMD etc...)
 *
 * A reference is taken on the target provider
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_cached(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_cached_options *options);

/*
 * A provider that sources credentials from key-value profiles loaded from the aws credentials
 * file ("~/.aws/credentials" by default) and the aws config file ("~/.aws/config" by
 * default)
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_profile(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_profile_options *options);

/*
 * A provider assumes an IAM role via. STS AssumeRole() API. This provider will fetch new credentials
 * upon each call to aws_credentials_provider_get_credentials(). If you very likely don't want this behavior,
 * prefer aws_credentials_provider_new_sts_cached() instead.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_sts(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_sts_options *options);

/*
 * A provider that sources credentials from an ordered sequence of providers, with the overall result
 * being from the first provider to return a valid set of credentials
 *
 * References are taken on all supplied providers
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_chain(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_chain_options *options);

/*
 * A provider that sources credentials from the ec2 instance metadata service
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_imds(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_imds_options *options);

/*
 * A provider that sources credentials from the ecs role credentials service
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_ecs(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_ecs_options *options);

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
struct aws_credentials_provider *aws_credentials_provider_new_chain_default(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_chain_default_options *options);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_CREDENTIALS_H */
