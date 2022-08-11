#ifndef AWS_AUTH_CREDENTIALS_H
#define AWS_AUTH_CREDENTIALS_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/auth.h>
#include <aws/common/array_list.h>
#include <aws/common/atomics.h>
#include <aws/common/linked_list.h>
#include <aws/io/io.h>

struct aws_client_bootstrap;
struct aws_auth_http_system_vtable;
struct aws_string;
struct aws_credentials;
struct aws_credentials_provider;

extern const uint16_t aws_sts_assume_role_default_duration_secs;

/*
 * Signature for the credentials sourcing callback
 */
typedef void(aws_on_get_credentials_callback_fn)(struct aws_credentials *credentials, int error_code, void *user_data);

typedef int(aws_credentials_provider_get_credentials_fn)(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data);
typedef void(aws_credentials_provider_destroy_fn)(struct aws_credentials_provider *provider);

/*
 * Common function table that all credentials provider implementations must support
 */
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

/**
 * A baseclass for credentials providers.  A credentials provider is an object that has an asynchronous
 * query function for retrieving AWS credentials.
 *
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

/**
 * Configuration options for a provider that returns a fixed set of credentials
 */
struct aws_credentials_provider_static_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
    struct aws_byte_cursor access_key_id;
    struct aws_byte_cursor secret_access_key;
    struct aws_byte_cursor session_token;
};

/**
 * Configuration options for a provider that returns credentials based on environment variable values
 */
struct aws_credentials_provider_environment_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;
};

/**
 * Configuration options for a provider that sources credentials from the aws profile and credentials files
 * (by default ~/.aws/profile and ~/.aws/credentials)
 */
struct aws_credentials_provider_profile_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;

    /*
     * Override of what profile to use to source credentials from ('default' by default)
     */
    struct aws_byte_cursor profile_name_override;

    /*
     * Override path to the profile config file (~/.aws/config by default)
     */
    struct aws_byte_cursor config_file_name_override;

    /*
     * Override path to the profile credentials file (~/.aws/credentials by default)
     */
    struct aws_byte_cursor credentials_file_name_override;

    /*
     * Bootstrap to use for any network connections made while sourcing credentials (for example,
     * a profile that uses assume-role will need to hit STS)
     */
    struct aws_client_bootstrap *bootstrap;

    /*
     * Client TLS context to use for any secure network connections made while sourcing credentials
     * (for example, a profile that uses assume-role will need to hit STS).
     *
     * If a TLS context is needed, and you did not pass one in, it will be created automatically.
     * However, you are encouraged to pass in a shared one since these are expensive objects.
     * If using BYO_CRYPTO, you must provide the TLS context since it cannot be created automatically.
     */
    struct aws_tls_ctx *tls_ctx;

    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_auth_http_system_vtable *function_table;
};

/**
 * Configuration options for a provider that functions as a caching decorator.  Credentials sourced through this
 * provider will be cached within it until their expiration time.  When the cached credentials expire, new
 * credentials will be fetched when next queried.
 */
struct aws_credentials_provider_cached_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;

    /*
     * The provider to cache credentials query results from
     */
    struct aws_credentials_provider *source;

    /*
     * An optional expiration time period for sourced credentials.  For a given set of cached credentials,
     * the refresh time period will be the minimum of this time and any expiration timestamp on the credentials
     * themselves.
     */
    uint64_t refresh_time_in_milliseconds;

    /* For mocking, leave NULL otherwise */
    aws_io_clock_fn *high_res_clock_fn;
    aws_io_clock_fn *system_clock_fn;
};

/**
 * Configuration options for a provider that queries, in order, a list of providers.  This provider uses the
 * first set of credentials successfully queried.  Providers are queried one at a time; a provider is not queried
 * until the preceding provider has failed to source credentials.
 */
struct aws_credentials_provider_chain_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;

    /*
     * Pointer to an array of credentials providers to use
     */
    struct aws_credentials_provider **providers;

    /*
     * Number of elements in the array of credentials providers
     */
    size_t provider_count;
};

/*
 * EC2 IMDS_V1 takes one http request to get resource, while IMDS_V2 takes one more token (Http PUT) request
 * to get secure token used in following request.
 */
enum aws_imds_protocol_version {
    /**
     * Defaults to IMDS_PROTOCOL_V2. It can be set to either one and IMDS Client
     * will figure out (by looking at response code) which protocol an instance
     * is using. But a more clear setting will reduce unnecessary network request.
     */
    IMDS_PROTOCOL_V2,
    IMDS_PROTOCOL_V1,
};

/**
 * Configuration options for the provider that sources credentials from ec2 instance metadata
 */
struct aws_credentials_provider_imds_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;

    /*
     * Connection bootstrap to use for any network connections made while sourcing credentials
     */
    struct aws_client_bootstrap *bootstrap;

    /*
     * Which version of the imds query protocol to use.
     */
    enum aws_imds_protocol_version imds_version;

    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_auth_http_system_vtable *function_table;
};

/*
 * Configuration options for the provider that sources credentials from ECS container metadata
 *
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

    /*
     * Connection bootstrap to use for any network connections made while sourcing credentials
     */
    struct aws_client_bootstrap *bootstrap;

    /*
     * Host to query credentials from
     */
    struct aws_byte_cursor host;

    /*
     * Http path and query string for the credentials query
     */
    struct aws_byte_cursor path_and_query;

    /*
     * Authorization token to include in the credentials query
     */
    struct aws_byte_cursor auth_token;

    /*
     * Client TLS context to use when making query.
     * If set, port 443 is used. If NULL, port 80 is used.
     */
    struct aws_tls_ctx *tls_ctx;

    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_auth_http_system_vtable *function_table;

    /*
     * Port to query credentials from.  If zero, 80/443 will be used based on whether or not tls is enabled.
     */
    uint16_t port;
};

/**
 * Configuration options for the X509 credentials provider
 *
 * The x509 credentials provider sources temporary credentials from AWS IoT Core using TLS mutual authentication.
 * See details: https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html
 * An end to end demo with detailed steps can be found here:
 * https://aws.amazon.com/blogs/security/how-to-eliminate-the-need-for-hardcoded-aws-credentials-in-devices-by-using-the-aws-iot-credentials-provider/
 */
struct aws_credentials_provider_x509_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;

    /*
     * Connection bootstrap to use for any network connections made while sourcing credentials
     */
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
     *
     * This a different endpoint than the IoT data mqtt broker endpoint.
     */
    struct aws_byte_cursor endpoint;

    /**
     * (Optional) Http proxy configuration for the http request that fetches credentials
     */
    const struct aws_http_proxy_options *proxy_options;

    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_auth_http_system_vtable *function_table;
};

/**
 * Configuration options for the STS web identity provider
 *
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

    /*
     * Connection bootstrap to use for any network connections made while sourcing credentials
     */
    struct aws_client_bootstrap *bootstrap;

    /*
     * Client TLS context to use when querying STS web identity provider.
     * Required.
     */
    struct aws_tls_ctx *tls_ctx;

    /* For mocking the http layer in tests, leave NULL otherwise */
    struct aws_auth_http_system_vtable *function_table;
};

/**
 * Configuration options for the STS credentials provider
 */
struct aws_credentials_provider_sts_options {
    /*
     * Connection bootstrap to use for any network connections made while sourcing credentials
     */
    struct aws_client_bootstrap *bootstrap;

    /*
     * Client TLS context to use when querying STS.
     * Required.
     */
    struct aws_tls_ctx *tls_ctx;

    /*
     * Credentials provider to be used to sign the requests made to STS to fetch credentials.
     */
    struct aws_credentials_provider *creds_provider;

    /*
     * Arn of the role to assume by fetching credentials for
     */
    struct aws_byte_cursor role_arn;

    /*
     * Assumed role session identifier to be associated with the sourced credentials
     */
    struct aws_byte_cursor session_name;

    /*
     * How long sourced credentials should remain valid for, in seconds.  900 is the minimum allowed value.
     */
    uint16_t duration_seconds;

    struct aws_credentials_provider_shutdown_options shutdown_options;

    /* For mocking, leave NULL otherwise */
    struct aws_auth_http_system_vtable *function_table;
    aws_io_clock_fn *system_clock_fn;
};

/**
 *
 * Configuration options for the process credentials provider
 *
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

/**
 * Configuration options for the default credentials provider chain.
 */
struct aws_credentials_provider_chain_default_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;

    /*
     * Connection bootstrap to use for any network connections made while sourcing credentials
     */
    struct aws_client_bootstrap *bootstrap;

    /*
     * Client TLS context to use for any secure network connections made while sourcing credentials.
     *
     * If not provided the default chain will construct a new one, but these
     * are expensive objects so you are encouraged to pass in a shared one.
     *
     * Must be provided if using BYO_CRYPTO.
     */
    struct aws_tls_ctx *tls_ctx;
};

typedef int(aws_credentials_provider_delegate_get_credentials_fn)(
    void *delegate_user_data,
    aws_on_get_credentials_callback_fn callback,
    void *callback_user_data);

/**
 * Configuration options for the delegate credentials provider.
 */
struct aws_credentials_provider_delegate_options {
    struct aws_credentials_provider_shutdown_options shutdown_options;

    /**
     * Delegated get_credentials() callback.
     */
    aws_credentials_provider_delegate_get_credentials_fn *get_credentials;

    /**
     * User data for delegated callbacks.
     */
    void *delegate_user_data;
};

AWS_EXTERN_C_BEGIN

/*
 * Credentials APIs
 *
 * expiration_timepoint_seconds is the timepoint, in seconds since epoch, that the credentials will no longer
 * be valid.  For credentials that do not expire, use UINT64_MAX.
 */

/**
 * Creates a new set of aws credentials
 *
 * @param allocator memory allocator to use
 * @param access_key_id_cursor value for the aws access key id field
 * @param secret_access_key_cursor value for the secret access key field
 * @param session_token_cursor (optional) security token associated with the credentials
 * @param expiration_timepoint_seconds timepoint, in seconds since epoch, that the credentials will no longer
 * be valid past.  For credentials that do not expire, use UINT64_MAX
 *
 * @return a valid credentials object, or NULL
 */
AWS_AUTH_API
struct aws_credentials *aws_credentials_new(
    struct aws_allocator *allocator,
    struct aws_byte_cursor access_key_id_cursor,
    struct aws_byte_cursor secret_access_key_cursor,
    struct aws_byte_cursor session_token_cursor,
    uint64_t expiration_timepoint_seconds);

/**
 * Creates a new set of AWS anonymous credentials
 *
 * @param allocator memory allocator to use
 * @param expiration_timepoint_seconds timepoint, in seconds since epoch, that the credentials will no longer
 * be valid past.  For credentials that do not expire, use UINT64_MAX
 *
 * @return a valid credentials object, or NULL
 */
AWS_AUTH_API
struct aws_credentials *aws_credentials_new_anonymous(
    struct aws_allocator *allocator,
    uint64_t expiration_timepoint_seconds);

/**
 * Creates a new set of AWS credentials
 *
 * @param allocator memory allocator to use
 * @param access_key_id  value for the aws access key id field
 * @param secret_access_key value for the secret access key field
 * @param session_token (optional) security token associated with the credentials
 * @param expiration_timepoint_seconds timepoint, in seconds since epoch, that the credentials will no longer
 * be valid past.  For credentials that do not expire, use UINT64_MAX
 *
 * @return a valid credentials object, or NULL
 */
AWS_AUTH_API
struct aws_credentials *aws_credentials_new_from_string(
    struct aws_allocator *allocator,
    const struct aws_string *access_key_id,
    const struct aws_string *secret_access_key,
    const struct aws_string *session_token,
    uint64_t expiration_timepoint_seconds);

/**
 * Add a reference to some credentials
 *
 * @param credentials credentials to increment the ref count on
 */
AWS_AUTH_API
void aws_credentials_acquire(const struct aws_credentials *credentials);

/**
 * Remove a reference to some credentials
 *
 * @param credentials credentials to decrement the ref count on
 */
AWS_AUTH_API
void aws_credentials_release(const struct aws_credentials *credentials);

/**
 * Get the AWS access key id from a set of credentials
 *
 * @param credentials credentials to get the access key id from
 * @return a byte cursor to the access key id
 */
AWS_AUTH_API
struct aws_byte_cursor aws_credentials_get_access_key_id(const struct aws_credentials *credentials);

/**
 * Get the AWS secret access key from a set of credentials
 *
 * @param credentials credentials to get the secret access key from
 * @return a byte cursor to the secret access key
 */
AWS_AUTH_API
struct aws_byte_cursor aws_credentials_get_secret_access_key(const struct aws_credentials *credentials);

/**
 * Get the AWS session token from a set of credentials
 *
 * @param credentials credentials to get the session token from
 * @return a byte cursor to the session token or an empty byte cursor if there is no session token
 */
AWS_AUTH_API
struct aws_byte_cursor aws_credentials_get_session_token(const struct aws_credentials *credentials);

/**
 * Get the expiration timepoint (in seconds since epoch) associated with a set of credentials
 *
 * @param credentials credentials to get the expiration timepoint for
 * @return the time, in seconds since epoch, the credentials will expire; UINT64_MAX for credentials
 * without a specific expiration time
 */
AWS_AUTH_API
uint64_t aws_credentials_get_expiration_timepoint_seconds(const struct aws_credentials *credentials);

/**
 * Get the elliptic curve key associated with this set of credentials
 * @param credentials credentials to get the the elliptic curve key for
 * @return the elliptic curve key associated with the credentials, or NULL if no key is associated with
 * these credentials
 */
AWS_AUTH_API
struct aws_ecc_key_pair *aws_credentials_get_ecc_key_pair(const struct aws_credentials *credentials);

/**
 * Check if the credentials are anonymous or not
 * @param credentials credentials to check
 *
 * @return true if the credentials are anonymous; false otherwise.
 */
AWS_AUTH_API
bool aws_credentials_is_anonymous(const struct aws_credentials *credentials);

/*
 * Credentials provider APIs
 */

/**
 * Release a reference to a credentials provider
 *
 * @param provider provider to increment the ref count on
 */
AWS_AUTH_API
void aws_credentials_provider_release(struct aws_credentials_provider *provider);

/*
 * Add a reference to a credentials provider
 *
 * @param provider provider to decrement the ref count on
 */
AWS_AUTH_API
void aws_credentials_provider_acquire(struct aws_credentials_provider *provider);

/*
 * Async function for retrieving credentials from a provider
 *
 * @param provider credentials provider to source from
 * @param callback completion callback to invoke when the fetch has completed or failed
 * @param user_data user data to pass to the completion callback
 *
 * @return AWS_OP_SUCCESS if the fetch was successfully started, AWS_OP_ERR otherwise.  The completion
 * callback will only be invoked if-and-only-if the return value was AWS_OP_SUCCESS.
 *
 */
AWS_AUTH_API
int aws_credentials_provider_get_credentials(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data);

/*
 * Credentials provider variant creation
 */

/**
 * Creates a simple provider that just returns a fixed set of credentials
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_static(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_static_options *options);

/**
 * Creates a simple anonymous credentials provider
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param shutdown_options an optional shutdown callback that gets
 * invoked when the resources used by the provider are no longer in use.
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_anonymous(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_shutdown_options *shutdown_options);

/**
 * Creates a provider that returns credentials sourced from the environment variables:
 *
 * AWS_ACCESS_KEY_ID
 * AWS_SECRET_ACCESS_KEY
 * AWS_SESSION_TOKEN
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_environment(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_environment_options *options);

/**
 * Creates a provider that functions as a caching decorating of another provider.
 *
 * For example, the default chain is implemented as:
 *
 * CachedProvider -> ProviderChain(EnvironmentProvider -> ProfileProvider -> ECS/EC2IMD etc...)
 *
 * A reference is taken on the target provider
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_cached(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_cached_options *options);

/**
 * Creates a provider that sources credentials from key-value profiles loaded from the aws credentials
 * file ("~/.aws/credentials" by default) and the aws config file ("~/.aws/config" by
 * default)
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_profile(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_profile_options *options);

/**
 * Creates a provider that assumes an IAM role via. STS AssumeRole() API. This provider will fetch new credentials
 * upon each call to aws_credentials_provider_get_credentials().
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_sts(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_sts_options *options);

/**
 * Creates a provider that sources credentials from an ordered sequence of providers, with the overall result
 * being from the first provider to return a valid set of credentials
 *
 * References are taken on all supplied providers
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_chain(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_chain_options *options);

/**
 * Creates a provider that sources credentials from the ec2 instance metadata service
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_imds(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_imds_options *options);

/**
 * Creates a provider that sources credentials from the ecs role credentials service
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_ecs(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_ecs_options *options);

/**
 * Creates a provider that sources credentials from IoT Core
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_x509(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_x509_options *options);

/**
 * Creates a provider that sources credentials from STS using AssumeRoleWithWebIdentity
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_sts_web_identity(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_sts_web_identity_options *options);

/*
 * Creates a provider that sources credentials from running an external command or process
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_process(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_process_options *options);

/**
 * Create a credentials provider depends on provided vtable to fetch the credentials.
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
 */
AWS_AUTH_API
struct aws_credentials_provider *aws_credentials_provider_new_delegate(
    struct aws_allocator *allocator,
    struct aws_credentials_provider_delegate_options *options);

/**
 * Creates the default provider chain used by most AWS SDKs.
 *
 * Generally:
 *
 * (1) Environment
 * (2) Profile
 * (3) STS web identity
 * (4) (conditional, off by default) ECS
 * (5) (conditional, on by default) EC2 Instance Metadata
 *
 * Support for environmental control of the default provider chain is not yet
 * implemented.
 *
 * @param allocator memory allocator to use for all memory allocation
 * @param options provider-specific configuration options
 *
 * @return the newly-constructed credentials provider, or NULL if an error occurred.
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
    const struct aws_credentials *credentials);

AWS_AUTH_API
struct aws_ecc_key_pair *aws_ecc_key_pair_new_ecdsa_p256_key_from_aws_credentials(
    struct aws_allocator *allocator,
    const struct aws_credentials *credentials);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_CREDENTIALS_H */
