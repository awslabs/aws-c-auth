/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_AUTH_TOKEN_PRIVATE_H
#define AWS_AUTH_TOKEN_PRIVATE_H

#include <aws/auth/auth.h>
#include <aws/common/date_time.h>

/*
 * A login token provided by the the aws login command in the aws cli that is stored to disk. This token has valid sigv4
 * credentials alongside additional fields that can be used to refresh the credentials when the expire. owns a pointer
 * to serialized_token that all byte cursors point to. an owned token needs to be destroyed with aws_login_token_destroy
 * when leaving scope.
 */
struct aws_login_token;

/*
 * A refresh response retuned by the aws sign in service when the operation CreateOAuth2Token is called successfully.
 * This response will contain valid AWS sigv4 credentials alongside a refresh token that can be used in further calls
 * to the service to refresh the credentials again. Owns a pointer to serialized_token that all byte cursors point to.
 * an owned token needs to be destroyed with aws_login_token_destroy when leaving scope.
 */
struct aws_login_refresh_response;

AWS_EXTERN_C_BEGIN

/*
 * Creates a login token file from a cached file.
 */
AWS_AUTH_API
struct aws_login_token *aws_login_token_new_from_file(struct aws_allocator *allocator, struct aws_byte_buf *file_path);

/*
 * Getter for account Id.
 */
AWS_AUTH_API
struct aws_byte_cursor aws_login_token_get_account_id(struct aws_login_token *token);

/*
 * Setter for access key id.
 */
AWS_AUTH_API
void aws_login_token_set_access_key_id(struct aws_login_token *token, struct aws_byte_cursor value);

/*
 * Setter for secret access key.
 */
AWS_AUTH_API
void aws_login_token_set_secret_access_key(struct aws_login_token *token, struct aws_byte_cursor value);

/*
 * Setter for session token.
 */
AWS_AUTH_API
void aws_login_token_set_session_token(struct aws_login_token *token, struct aws_byte_cursor value);

/*
 * Setter for expires at.
 */
AWS_AUTH_API
void aws_login_token_set_expires_at(struct aws_login_token *token, struct aws_date_time value);

/*
 * Setter for refresh token
 */
AWS_AUTH_API
void aws_login_token_set_refresh_token(struct aws_login_token *token, struct aws_byte_cursor value);

/*
 * Creates a login token from a byte cursor to json document.
 */
AWS_AUTH_API
struct aws_login_token *aws_login_token_new_from_json_document(
    struct aws_allocator *allocator,
    struct aws_byte_cursor payload_cursor);

/*
 * Writes a login token to a filepath.
 */
AWS_AUTH_API
int aws_login_token_write_token_file(
    const struct aws_login_token *token,
    struct aws_allocator *allocator,
    const struct aws_byte_buf *file_path);

/*
 * Constructs a DPoP (Demonstrating Proof of Possession) header. This is sent as a header to the sign in service to
 * authenticate the refresh token that we send.
 */
AWS_AUTH_API
int aws_login_token_get_dpop_header(
    struct aws_allocator *allocator,
    const struct aws_login_token *token,
    struct aws_byte_cursor host,
    struct aws_byte_buf *header_value);

/*
 * Constructs a path to a login cached credential i.e.
 *
 * ~/.aws/login/cache/${SHA_256_OF_LOGIN_SESSION}.json
 */
AWS_AUTH_API
int aws_login_token_construct_token_path(
    struct aws_allocator *allocator,
    const struct aws_string *input,
    const struct aws_string *directory_override,
    struct aws_byte_buf *login_token_path_buf);

/*
 * Constructs the payload body that we are sending to the sign in service.
 */
AWS_AUTH_API
int aws_login_token_get_body(
    struct aws_allocator *allocator,
    const struct aws_login_token *token,
    struct aws_byte_buf *body_buf);

/*
 * Destroys a login token.
 */
AWS_AUTH_API
struct aws_login_token *aws_login_token_destroy(struct aws_login_token *token);

/*
 * Creates a refresh token from a byte cursor to json document.
 */
AWS_AUTH_API
struct aws_login_refresh_response *aws_login_refresh_new_from_json_document(
    struct aws_allocator *allocator,
    struct aws_byte_cursor payload_cursor);

/*
 * Getter for access key id.
 */
AWS_AUTH_API
struct aws_byte_cursor aws_login_refresh_get_access_key_id(struct aws_login_refresh_response *token);

/*
 * Getter for secret access key id.
 */
AWS_AUTH_API
struct aws_byte_cursor aws_login_refresh_get_secret_access_key(struct aws_login_refresh_response *token);

/*
 * Getter for session token.
 */
AWS_AUTH_API
struct aws_byte_cursor aws_login_refresh_get_session_token(struct aws_login_refresh_response *token);

/*
 * Getter for expires at.
 */
AWS_AUTH_API
struct aws_date_time aws_login_refresh_get_expires_at(struct aws_login_refresh_response *token);

/*
 * Getter for refresh token.
 */
AWS_AUTH_API
struct aws_byte_cursor aws_login_refresh_get_refresh_token(struct aws_login_refresh_response *token);

/*
 * Destroys a refresh response.
 */
AWS_AUTH_API
struct aws_login_refresh_response *aws_login_refresh_destroy(struct aws_login_refresh_response *token);

AWS_EXTERN_C_END

#endif // AWS_AUTH_TOKEN_PRIVATE_H
