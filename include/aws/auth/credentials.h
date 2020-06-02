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

struct aws_credentials;
struct aws_credentials_provider;

typedef void(aws_on_get_credentials_callback_fn)(struct aws_credentials *credentials, int error_code, void *user_data);

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
    /* defaults to use IMDS_V2 */
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

/**
 * The x509 credentials provider sources temporary credentials from AWS IoT Core using TLS mutual authentication.
 * See details: https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html
 * An end to end demo with detailed steps can be found here:
 * https://aws.amazon.com/blogs/security/how-to-eliminate-the-need-for-hardcoded-aws-credentials-in-devices-by-using-the-aws-iot-credentials-provider/
 */
struct aws_credentials_provider_x509_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_client_bootstrap *bootstrap;

    /* TLS connection options that have been initialized with your x509 certificate and private key */
    const struct aws_tls_connection_options *tls_connection_options;

    /* IoT thing name you registered with AWS IOT for your device, it will be used in http request header */
    struct aws_byte_cursor thing_name;

    /* Iot role alias you created with AWS IoT for your IAM role, it will be used in http request path */
    struct aws_byte_cursor role_alias;

    /**
     * AWS account specific endpoint that can be acquired using AWS CLI following instructions from the giving demo
     * example: c2sakl5huz0afv.credentials.iot.us-east-1.amazonaws.com
     */
    struct aws_byte_cursor endpoint;

    /**
     * (Optional) proxy configuration for the http request that fetches credentials
     */
    const struct aws_http_proxy_options *proxy_options;

    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_credentials_provider_system_vtable *function_table;
};

/**
 * Sts with web identity credentials provider sources a set of temporary security credentials for users who have been
 * authenticated in a mobile or web application with a web identity provider.
 * Example providers include Amazon Cognito, Login with Amazon, Facebook, Google, or any OpenID Connect-compatible
 * identity provider like Elastic Kubernetes Service
 * https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
 * The required parameters used in the request (region, roleArn, sessionName, tokenFilePath) are automatically resolved
 * by SDK from envrionment variables or config file.
 ---------------------------------------------------------------------------------
 | Parameter           | Environment Variable Name    | Config File Property Name |
 ----------------------------------------------------------------------------------
 | region              | AWS_DEFAULT_REGION           | region                    |
 | role_arn            | AWS_ROLE_ARN                 | role_arn                  |
 | role_session_name   | AWS_ROLE_SESSION_NAME        | role_session_name         |
 | token_file_path     | AWS_WEB_IDENTITY_TOKEN_FILE  | web_identity_token_file   |
 |--------------------------------------------------------------------------------|
 */
struct aws_credentials_provider_sts_web_identity_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_client_bootstrap *bootstrap;

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

/**
 * The process credentials provider sources credentials from running a command or process.
 * The command to run is sourced from a profile in the AWS config file, using the standard
 * profile selection rules. The profile key the command is read from is "credential_process."
 * E.g.:
 *  [default]
 *  credential_process=/opt/amazon/bin/my-credential-fetcher --argsA=abc
 * On successfully running the command, the output should be a json data with the following
 * format:
 * {
    "Version": 1,
    "AccessKeyId": "accesskey",
    "SecretAccessKey": "secretAccessKey"
    "SessionToken": "....",
    "Expiration": "2019-05-29T00:21:43Z"
   }
 * Version here identifies the command output format version.
 * This provider is not part of the default provider chain.
 */
struct aws_credentials_provider_process_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    /**
     * In which profile name to look for credential_process,
     * if not provided, we will try environment variable: AWS_PROFILE.
     */
    struct aws_byte_cursor profile_to_use;
};

struct aws_credentials_provider_chain_default_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_client_bootstrap *bootstrap;
};

AWS_EXTERN_C_BEGIN

/*
 * Credentials APIs
 *
 * expiration_timepoint_seconds is the timepoint, in seconds since epoch, that the credentials will no longer
 * be valid.  For credentials that do not expire, use UINT64_MAX.
 */

AWS_AUTH_API
struct aws_credentials *aws_credentials_new(
    struct aws_allocator *allocator,
    struct aws_byte_cursor access_key_id_cursor,
    struct aws_byte_cursor secret_access_key_cursor,
    struct aws_byte_cursor session_token_cursor,
    uint64_t expiration_timepoint_seconds);

AWS_AUTH_API
struct aws_credentials *aws_credentials_new_from_string(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token,
    uint64_t expiration_timepoint_seconds);

AWS_AUTH_API
void aws_credentials_acquire(struct aws_credentials *credentials);

AWS_AUTH_API
void aws_credentials_release(struct aws_credentials *credentials);

AWS_AUTH_API
struct aws_byte_cursor aws_credentials_get_access_key_id(const struct aws_credentials *credentials);

AWS_AUTH_API
struct aws_byte_cursor aws_credentials_get_secret_access_key(const struct aws_credentials *credentials);

AWS_AUTH_API
struct aws_byte_cursor aws_credentials_get_session_token(const struct aws_credentials *credentials);

AWS_AUTH_API
uint64_t aws_credentials_get_expiration_timepoint_seconds(const struct aws_credentials *credentials);

AWS_AUTH_API
struct aws_ecc_key_pair *aws_credentials_get_ecc_key_pair(const struct aws_credentials *credentials);

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
 * A provider that sources credentials from IoT Core
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_x509(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_x509_options *options);

/*
 * A provider that sources credentials from STS using AssumeRoleWithWebIdentity
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_sts_web_identity(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_sts_web_identity_options *options);

/*
 * A provider that sources credentials from running an external command or process
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_process(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_process_options *options);

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

AWS_AUTH_API
struct aws_credentials *aws_credentials_new_ecc(
    struct aws_allocator *allocator,
    struct aws_byte_cursor access_key_id,
    struct aws_ecc_key_pair *ecc_key,
    struct aws_byte_cursor session_token,
    uint64_t expiration_timepoint_in_seconds);

/*
 * Takes a pair of AWS credentials and performs the sigv4a key expansion algorithm to generate a unique
 * ecc P256 key pair based on the credentials.  The ecc key is written to the buffer in DER format.
 *
 * Sigv4a signing takes the raw DER-encoded ecc key as an optional parameter in signing (if not present,
 * key expansion will be done for the caller before signing).
 */
AWS_AUTH_API
struct aws_credentials *aws_credentials_new_ecc_from_aws_credentials(
    struct aws_allocator *allocator,
    struct aws_credentials *credentials);

AWS_AUTH_API
struct aws_ecc_key_pair *aws_ecc_key_pair_new_ecdsa_p256_key_from_aws_credentials(
    struct aws_allocator *allocator,
    struct aws_credentials *credentials);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_CREDENTIALS_H */
