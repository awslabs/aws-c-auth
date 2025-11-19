/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/auth/credentials.h>
#include <aws/auth/private/login_token_utils.h>
#include <aws/cal/ecc.h>
#include <aws/cal/hash.h>
#include <aws/common/encoding.h>
#include <aws/common/file.h>
#include <aws/common/json.h>
#include <aws/common/uuid.h>
#include <aws/io/pem.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4232)
#endif /* _MSC_VER */

static int TOKEN_BUFFER_SIZE = 2500;

/* Token JSON keys*/
AWS_STATIC_STRING_FROM_LITERAL(s_login_access_token_key, "accessToken");
AWS_STATIC_STRING_FROM_LITERAL(s_login_access_key_id_key, "accessKeyId");
AWS_STATIC_STRING_FROM_LITERAL(s_login_secret_access_key, "secretAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_login_session_token_key, "sessionToken");
AWS_STATIC_STRING_FROM_LITERAL(s_login_expires_at_key, "expiresAt");
AWS_STATIC_STRING_FROM_LITERAL(s_login_expires_in_key, "expiresIn");
AWS_STATIC_STRING_FROM_LITERAL(s_login_account_id_key, "accountId");
AWS_STATIC_STRING_FROM_LITERAL(s_login_token_type_key, "tokenType");
AWS_STATIC_STRING_FROM_LITERAL(s_login_refresh_token_key, "refreshToken");
AWS_STATIC_STRING_FROM_LITERAL(s_login_id_token_key, "idToken");
AWS_STATIC_STRING_FROM_LITERAL(s_login_client_id_key, "clientId");
AWS_STATIC_STRING_FROM_LITERAL(s_login_dpop_key, "dpopKey");
AWS_STATIC_STRING_FROM_LITERAL(s_login_grant_type_key, "grantType");
AWS_STATIC_STRING_FROM_LITERAL(s_login_grant_type_value, "refresh_token");

/* JWT JSON keys*/
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_typ_key, "typ");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_alg_key, "alg");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_kty_key, "kty");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_x_nums_key, "x");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_y_nums_key, "y");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_crv_key, "crv");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_jti_key, "jti");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_htm_key, "htm");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_htu_key, "htu");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_iat_key, "iat");

/* JWT static JSON values*/
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_typ_value, "dpop+jwt");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_alg_value, "ES256");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_kty_value, "EC");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_crv_value, "P-256");
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_header_htm_value, "POST");

/* Static values during JWT creations */
AWS_STATIC_STRING_FROM_LITERAL(s_jwt_message_delim, ".");

struct aws_login_token {
    struct aws_json_value *serialized_token;
    struct aws_byte_cursor access_key_id;
    struct aws_byte_cursor secret_access_key;
    struct aws_byte_cursor session_token;
    struct aws_byte_cursor account_id;
    struct aws_date_time expires_at;
    struct aws_byte_cursor token_type;
    struct aws_byte_cursor refresh_token;
    struct aws_byte_cursor id_token;
    struct aws_byte_cursor client_id;
    struct aws_byte_cursor dpop_key;
};

struct aws_login_refresh_response {
    struct aws_json_value *serialized_token;
    struct aws_byte_cursor access_key_id;
    struct aws_byte_cursor secret_access_key;
    struct aws_byte_cursor session_token;
    struct aws_date_time expires_at;
    struct aws_byte_cursor refresh_token;
};

struct aws_byte_cursor aws_login_token_get_account_id(struct aws_login_token *token) {
    return token->account_id;
}

void aws_login_token_set_access_key_id(struct aws_login_token *token, struct aws_byte_cursor value) {
    token->access_key_id = value;
}

void aws_login_token_set_secret_access_key(struct aws_login_token *token, struct aws_byte_cursor value) {
    token->secret_access_key = value;
}

void aws_login_token_set_session_token(struct aws_login_token *token, struct aws_byte_cursor value) {
    token->session_token = value;
}

void aws_login_token_set_expires_at(struct aws_login_token *token, struct aws_date_time value) {
    token->expires_at = value;
}

void aws_login_token_set_refresh_token(struct aws_login_token *token, struct aws_byte_cursor value) {
    token->refresh_token = value;
}

struct aws_login_token *aws_login_token_destroy(struct aws_login_token *login_token) {
    if (login_token == NULL) {
        return login_token;
    }
    aws_json_value_destroy(login_token->serialized_token);
    return login_token;
}
struct aws_byte_cursor aws_login_refresh_get_access_key_id(struct aws_login_refresh_response *token) {
    return token->access_key_id;
}

struct aws_byte_cursor aws_login_refresh_get_secret_access_key(struct aws_login_refresh_response *token) {
    return token->secret_access_key;
}

struct aws_byte_cursor aws_login_refresh_get_session_token(struct aws_login_refresh_response *token) {
    return token->session_token;
}

struct aws_date_time aws_login_refresh_get_expires_at(struct aws_login_refresh_response *token) {
    return token->expires_at;
}

struct aws_byte_cursor aws_login_refresh_get_refresh_token(struct aws_login_refresh_response *token) {
    return token->refresh_token;
}

struct aws_login_refresh_response *aws_login_refresh_destroy(struct aws_login_refresh_response *refresh_token) {
    if (refresh_token == NULL) {
        return refresh_token;
    }
    aws_json_value_destroy(refresh_token->serialized_token);
    return refresh_token;
}

int aws_login_token_construct_token_path(
    struct aws_allocator *allocator,
    const struct aws_string *input,
    const struct aws_string *directory_override,
    struct aws_byte_buf *login_token_path_buf) {
    bool success = false;
    AWS_PRECONDITION(input);

    struct aws_string *home_directory = aws_get_home_directory(allocator);
    if (!home_directory) {
        goto on_error;
    }

    struct aws_byte_buf sha256_buf;
    AWS_ZERO_STRUCT(sha256_buf);

    if (directory_override) {
        struct aws_byte_cursor override_dir = aws_byte_cursor_from_string(directory_override);
        if (aws_byte_buf_init_copy_from_cursor(login_token_path_buf, allocator, override_dir)) {
            goto on_error;
        }
    } else {
        /* append home directory */
        struct aws_byte_cursor home_dir_cursor = aws_byte_cursor_from_string(home_directory);
        if (aws_byte_buf_init_copy_from_cursor(login_token_path_buf, allocator, home_dir_cursor)) {
            goto on_error;
        }

        /* append login cache directory */
        struct aws_byte_cursor login_cache_dir_cursor = aws_byte_cursor_from_c_str("/.aws/login/cache/");
        if (aws_byte_buf_append_dynamic(login_token_path_buf, &login_cache_dir_cursor)) {
            goto on_error;
        }
    }

    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_string(input);
    struct aws_byte_cursor json_cursor = aws_byte_cursor_from_c_str(".json");

    /* append hex encoded sha256 of input */
    if (aws_byte_buf_init(&sha256_buf, allocator, AWS_SHA256_LEN) ||
        aws_sha256_compute(allocator, &input_cursor, &sha256_buf, 0)) {
        goto on_error;
    }
    struct aws_byte_cursor sha256_cursor = aws_byte_cursor_from_buf(&sha256_buf);
    if (aws_hex_encode_append_dynamic(&sha256_cursor, login_token_path_buf)) {
        goto on_error;
    }

    /* append .json */
    if (aws_byte_buf_append_dynamic(login_token_path_buf, &json_cursor)) {
        goto on_error;
    }

    /* use platform-specific directory separator. */
    aws_normalize_directory_separator(login_token_path_buf);

    AWS_LOGF_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "successfully constructed token path: " PRInSTR,
        AWS_BYTE_BUF_PRI(*login_token_path_buf));
    success = true;
    goto on_finish;
on_error:
    aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_FAILED_TO_CREATE_TOKEN_PATH);
on_finish:
    aws_byte_buf_clean_up(&sha256_buf);
    aws_string_destroy(home_directory);
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

struct aws_login_token *aws_login_token_new_from_file(struct aws_allocator *allocator, struct aws_byte_buf *file_path) {
    AWS_PRECONDITION(allocator);
    struct aws_login_token *token = NULL;
    struct aws_byte_buf file_contents_buf;
    AWS_ZERO_STRUCT(file_contents_buf);
    struct aws_string *file_path_str = aws_string_new_from_buf(allocator, file_path);
    if (aws_byte_buf_init_from_file(&file_contents_buf, allocator, aws_string_c_str(file_path_str))) {
        goto on_finish;
    }

    struct aws_byte_cursor document_cursor = aws_byte_cursor_from_buf(&file_contents_buf);
    token = aws_login_token_new_from_json_document(allocator, document_cursor);
on_finish:
    aws_string_destroy(file_path_str);
    aws_byte_buf_clean_up_secure(&file_contents_buf);
    return token;
}

typedef bool(validate_json_object_fn)(struct aws_json_value *value);
typedef int(fetch_json_object_fn)(struct aws_json_value *value, void *raw_value);

static int s_set_json_on_token(
    struct aws_json_value *json_parent,
    struct aws_byte_cursor json_value,
    validate_json_object_fn *validate_fn,
    fetch_json_object_fn *fetch_fn,
    void *json_raw_value) {
    struct aws_json_value *json_node = aws_json_value_get_from_object(json_parent, json_value);
    if (!validate_fn(json_node) || fetch_fn(json_node, json_raw_value)) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static bool s_is_string_json_value(struct aws_json_value *value) {
    return aws_json_value_is_string(value);
}

static int s_get_string_json_value(struct aws_json_value *value, void *out_value) {
    struct aws_byte_cursor *out_cursor = out_value;
    return aws_json_value_get_string(value, out_cursor);
}

static int s_get_date_from_string_value(struct aws_json_value *value, void *out_value) {
    struct aws_date_time *expiration = out_value;
    struct aws_byte_cursor expires_at_cursor;
    aws_json_value_get_string(value, &expires_at_cursor);
    if (aws_date_time_init_from_str_cursor(expiration, &expires_at_cursor, AWS_DATE_FORMAT_ISO_8601)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "login token: expiresAt '" PRInSTR "' is not a valid ISO-8601 date string",
            AWS_BYTE_CURSOR_PRI(expires_at_cursor));
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static bool s_is_number_json_value(struct aws_json_value *value) {
    return aws_json_value_is_number(value);
}

/*
 * AWS sign in returns "expires in" instead of a time stamp. we need to calculate the data time when the expiration
 * will actually occur.
 */
static int s_get_expiration_from_expires_in(struct aws_json_value *value, void *out_value) {
    bool success = false;
    struct aws_date_time *date_time = out_value;

    double number = 0;
    if (aws_json_value_get_number(value, &number)) {
        goto on_finish;
    }

    struct aws_date_time now;
    aws_date_time_init_now(&now);
    double expiration_seconds = aws_date_time_as_epoch_secs(&now) + number;
    aws_date_time_init_epoch_secs(date_time, expiration_seconds);
    success = true;
on_finish:
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

struct aws_login_token *aws_login_token_new_from_json_document(
    struct aws_allocator *allocator,
    struct aws_byte_cursor document_cursor) {
    AWS_PRECONDITION(allocator);
    bool success = false;

    struct aws_login_token *token = aws_mem_acquire(allocator, sizeof(struct aws_login_token));
    struct aws_json_value *document_root = NULL;

    document_root = aws_json_value_new_from_string(allocator, document_cursor);
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to parse login token");
        goto on_error;
    }

    struct aws_json_value *access_token =
        aws_json_value_get_from_object(document_root, aws_byte_cursor_from_string(s_login_access_token_key));
    if (!aws_json_value_is_object(access_token)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to parse accessToken");
        goto on_error;
    }

    if (s_set_json_on_token(
            access_token,
            aws_byte_cursor_from_string(s_login_access_key_id_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->access_key_id) ||
        s_set_json_on_token(
            access_token,
            aws_byte_cursor_from_string(s_login_secret_access_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->secret_access_key) ||
        s_set_json_on_token(
            access_token,
            aws_byte_cursor_from_string(s_login_session_token_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->session_token) ||
        s_set_json_on_token(
            access_token,
            aws_byte_cursor_from_string(s_login_expires_at_key),
            s_is_string_json_value,
            s_get_date_from_string_value,
            &token->expires_at) ||
        s_set_json_on_token(
            access_token,
            aws_byte_cursor_from_string(s_login_account_id_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->account_id) ||
        s_set_json_on_token(
            document_root,
            aws_byte_cursor_from_string(s_login_token_type_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->token_type) ||
        s_set_json_on_token(
            document_root,
            aws_byte_cursor_from_string(s_login_refresh_token_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->refresh_token) ||
        s_set_json_on_token(
            document_root,
            aws_byte_cursor_from_string(s_login_id_token_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->id_token) ||
        s_set_json_on_token(
            document_root,
            aws_byte_cursor_from_string(s_login_client_id_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->client_id) ||
        s_set_json_on_token(
            document_root,
            aws_byte_cursor_from_string(s_login_dpop_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &token->dpop_key)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to parse login token");
        goto on_error;
    }

    // check that the token has not expired yet
    struct aws_date_time now;
    aws_date_time_init_now(&now);
    if (aws_date_time_as_millis(&token->expires_at) < aws_date_time_as_millis(&now)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: token is already expired");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_TOKEN_EXPIRED);
        goto on_finish;
        ;
    }

    token->serialized_token = document_root;
    success = true;
    goto on_finish;
on_error:
    aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_FAILED_TO_CREATE_TOKEN);
on_finish:
    if (!success) {
        aws_mem_release(allocator, token);
        token = NULL;
        aws_json_value_destroy(document_root);
    }
    return token;
}

struct aws_login_refresh_response *aws_login_refresh_new_from_json_document(
    struct aws_allocator *allocator,
    struct aws_byte_cursor payload_cursor) {
    bool success = false;
    struct aws_login_refresh_response *refresh_token =
        aws_mem_acquire(allocator, sizeof(struct aws_login_refresh_response));
    struct aws_json_value *document_root = NULL;

    document_root = aws_json_value_new_from_string(allocator, payload_cursor);
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to parse login token");
        goto on_error;
    }

    struct aws_json_value *access_token =
        aws_json_value_get_from_object(document_root, aws_byte_cursor_from_string(s_login_access_token_key));
    if (!aws_json_value_is_object(access_token)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to parse accessToken");
        goto on_error;
    }

    if (s_set_json_on_token(
            access_token,
            aws_byte_cursor_from_string(s_login_access_key_id_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &refresh_token->access_key_id) ||
        s_set_json_on_token(
            access_token,
            aws_byte_cursor_from_string(s_login_secret_access_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &refresh_token->secret_access_key) ||
        s_set_json_on_token(
            access_token,
            aws_byte_cursor_from_string(s_login_session_token_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &refresh_token->session_token) ||
        s_set_json_on_token(
            document_root,
            aws_byte_cursor_from_string(s_login_expires_in_key),
            s_is_number_json_value,
            s_get_expiration_from_expires_in,
            &refresh_token->expires_at) ||
        s_set_json_on_token(
            document_root,
            aws_byte_cursor_from_string(s_login_refresh_token_key),
            s_is_string_json_value,
            s_get_string_json_value,
            &refresh_token->refresh_token)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: failed to parse refresh token");
        goto on_error;
    }

    refresh_token->serialized_token = document_root;
    success = true;
    goto on_finish;
on_error:
    aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_FAILED_TO_CREATE_REFRESH_TOKEN);
on_finish:
    if (!success) {
        aws_mem_release(allocator, refresh_token);
        refresh_token = NULL;
        aws_json_value_destroy(document_root);
    }
    return refresh_token;
}

typedef int(new_node_fn)(struct aws_allocator *allocator, struct aws_json_value **node, const void *value);
typedef int(add_node_to_parent_fn)(struct aws_json_value *parent, const char *key, struct aws_json_value *node);

static int s_write_to_json_node(
    struct aws_allocator *allocator,
    struct aws_json_value *node,
    new_node_fn *new_node_fn,
    add_node_to_parent_fn *add_node_to_parent_fn,
    const char *key,
    const void *value) {
    bool success = false;
    struct aws_json_value *new_node = NULL;
    if (new_node_fn(allocator, &new_node, value)) {
        goto on_finish;
    }

    if (add_node_to_parent_fn(node, key, new_node)) {
        aws_json_value_destroy(new_node);
    }
    success = true;
on_finish:
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int s_new_string_from_cursor_json_value(
    struct aws_allocator *allocator,
    struct aws_json_value **node,
    const void *value) {
    const struct aws_byte_cursor *string_value = value;
    *node = aws_json_value_new_string(allocator, *string_value);
    return *node ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int s_new_string_json_value(struct aws_allocator *allocator, struct aws_json_value **node, const void *value) {
    const struct aws_string *string_value = value;
    *node = aws_json_value_new_string(allocator, aws_byte_cursor_from_string(string_value));
    return *node ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int s_new_number_json_value(struct aws_allocator *allocator, struct aws_json_value **node, const void *value) {
    const double *number_value = value;
    *node = aws_json_value_new_number(allocator, *number_value);
    return *node ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int s_add_json_value_to_parent(struct aws_json_value *parent, const char *key, struct aws_json_value *node) {
    if (aws_json_value_add_to_object(parent, aws_byte_cursor_from_c_str(key), node)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login: failed to add string json value to parent");
        aws_json_value_destroy(node);
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static int s_new_string_json_value_from_date_time(
    struct aws_allocator *allocator,
    struct aws_json_value **node,
    const void *value) {
    const struct aws_date_time *date_time = value;
    struct aws_byte_buf expires_buf;
    AWS_ZERO_STRUCT(expires_buf);
    if (aws_byte_buf_init(&expires_buf, allocator, AWS_DATE_TIME_STR_MAX_LEN)) {
        goto on_finish;
    }

    if (aws_date_time_to_utc_time_str(date_time, AWS_DATE_FORMAT_ISO_8601, &expires_buf)) {
        goto on_finish;
    }
    *node = aws_json_value_new_string(allocator, aws_byte_cursor_from_buf(&expires_buf));
on_finish:
    aws_byte_buf_clean_up_secure(&expires_buf);
    return *node ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

int aws_login_token_write_token_file(
    const struct aws_login_token *token,
    struct aws_allocator *allocator,
    const struct aws_byte_buf *file_path) {
    bool success = false;
    struct aws_byte_buf output_buffer;
    AWS_ZERO_STRUCT(output_buffer);
    struct aws_json_value *login_json = NULL;
    struct aws_json_value *access_token = NULL;

    struct aws_string *mode = aws_string_new_from_c_str(allocator, "wb");
    struct aws_string *file_path_string = aws_string_new_from_buf(allocator, file_path);

    FILE *cache_file = aws_fopen_safe(file_path_string, mode);
    if (!cache_file) {
        goto on_error;
    }

    access_token = aws_json_value_new_object(allocator);

    if (s_write_to_json_node(
            allocator,
            access_token,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_access_key_id_key),
            &token->access_key_id) ||
        s_write_to_json_node(
            allocator,
            access_token,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_secret_access_key),
            &token->secret_access_key) ||
        s_write_to_json_node(
            allocator,
            access_token,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_session_token_key),
            &token->session_token) ||
        s_write_to_json_node(
            allocator,
            access_token,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_account_id_key),
            &token->account_id) ||
        s_write_to_json_node(
            allocator,
            access_token,
            s_new_string_json_value_from_date_time,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_expires_at_key),
            &token->expires_at)) {
        aws_json_value_destroy(access_token);
        goto on_error;
    }

    login_json = aws_json_value_new_object(allocator);

    if (aws_json_value_add_to_object(login_json, aws_byte_cursor_from_string(s_login_access_token_key), access_token) ||
        s_write_to_json_node(
            allocator,
            login_json,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_token_type_key),
            &token->token_type) ||
        s_write_to_json_node(
            allocator,
            login_json,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_refresh_token_key),
            &token->refresh_token) ||
        s_write_to_json_node(
            allocator,
            login_json,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_id_token_key),
            &token->id_token) ||
        s_write_to_json_node(
            allocator,
            login_json,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_client_id_key),
            &token->client_id) ||
        s_write_to_json_node(
            allocator,
            login_json,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_dpop_key),
            &token->dpop_key)) {
        aws_json_value_destroy(login_json);
        aws_json_value_destroy(access_token);
        goto on_error;
    }

    if (aws_byte_buf_init(&output_buffer, allocator, TOKEN_BUFFER_SIZE) ||
        aws_byte_buf_append_json_string_formatted(login_json, &output_buffer)) {
        aws_byte_buf_clean_up_secure(&output_buffer);
        goto on_error;
    }

    int chars_written = fprintf(cache_file, PRInSTR, AWS_BYTE_BUF_PRI(output_buffer));
    if (chars_written < 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to write to cache file");
        goto on_error;
    }

    if (fflush(cache_file) != 0) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to flush cache file");
        goto on_error;
    }

    success = true;
    goto on_finish;
on_error:
    aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_FAILED_TO_WRITE_TOKEN);
on_finish:
    aws_byte_buf_clean_up_secure(&output_buffer);
    if (success) {
        aws_json_value_destroy(login_json);
    }
    if (cache_file) {
        fclose(cache_file);
    }
    aws_string_destroy(mode);
    aws_string_destroy(file_path_string);
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

typedef void(calculate_size_fn)(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output);
typedef int(encode_fn)(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output);

void s_base_64_url_length(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output) {
    struct aws_byte_cursor *input_cursor = input;
    size_t encoded_length;
    aws_base64_url_compute_encoded_len(input_cursor->len, &encoded_length);
    aws_byte_buf_init(output, allocator, encoded_length);
}

static int s_encode_base64_url(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output) {
    (void)allocator;
    struct aws_byte_cursor *input_cursor = input;
    return aws_base64_url_encode(input_cursor, output);
}

static void s_sha256_length(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output) {
    (void)input;
    aws_byte_buf_init(output, allocator, AWS_SHA256_LEN);
}

static int s_sha256_encode(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output) {
    struct aws_byte_cursor *input_cursor = input;
    return aws_sha256_compute(allocator, input_cursor, output, 0);
}

struct ecc_sign_input {
    struct aws_byte_cursor *message;
    struct aws_ecc_key_pair *private_key;
};

static void s_ecc_signature_length(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output) {
    struct ecc_sign_input *ecc_input = input;
    size_t signature_length = aws_ecc_key_pair_signature_length(ecc_input->private_key);
    aws_byte_buf_init(output, allocator, signature_length);
}

static int s_ecc_sign(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output) {
    (void)allocator;
    struct ecc_sign_input *ecc_input = input;
    return aws_ecc_key_pair_sign_message(ecc_input->private_key, ecc_input->message, output);
}

struct private_key_rs_pair {
    struct aws_byte_cursor *r;
    struct aws_byte_cursor *s;
};

static void s_rs_buff(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output) {
    struct private_key_rs_pair *private_key_rs_pair = input;
    aws_byte_buf_init(output, allocator, private_key_rs_pair->r->len + private_key_rs_pair->s->len);
}

static int s_rs_combine(struct aws_allocator *allocator, void *input, struct aws_byte_buf *output) {
    (void)allocator;
    struct private_key_rs_pair *private_key_rs_pair = input;
    if (aws_byte_buf_append_dynamic(output, private_key_rs_pair->r) ||
        aws_byte_buf_append_dynamic(output, private_key_rs_pair->s)) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static int s_encode_buff(
    struct aws_allocator *allocator,
    void *input,
    struct aws_byte_buf *output,
    calculate_size_fn *size_fn,
    encode_fn encode_fn) {

    size_fn(allocator, input, output);
    if (encode_fn(allocator, input, output)) {
        aws_byte_buf_clean_up_secure(output);
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to encode buffer");
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

static struct aws_ecc_key_pair *s_get_ecc_key_pair(
    struct aws_allocator *allocator,
    struct aws_byte_cursor private_token_cursor) {
    struct aws_ecc_key_pair *private_key = NULL;

    struct aws_array_list pem_objects;
    AWS_ZERO_STRUCT(pem_objects);
    if (aws_pem_objects_init_from_file_contents(&pem_objects, allocator, private_token_cursor)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to initialize pem objects");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_INVALID_PEM);
        goto on_finish;
    }

    size_t pem_objects_length = aws_array_list_length(&pem_objects);
    if (pem_objects_length != 1) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: pem object should only have one entry");
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_INVALID_PEM);
        goto on_finish;
    }

    for (size_t i = 0; i < pem_objects_length; ++i) {
        struct aws_pem_object pem_object;
        AWS_ZERO_STRUCT(pem_object);
        aws_array_list_get_at(&pem_objects, &pem_object, i);
        if (pem_object.type == AWS_PEM_TYPE_EC_PRIVATE) {
            struct aws_byte_cursor private_key_cursor = aws_byte_cursor_from_buf(&pem_object.data);
            private_key = aws_ecc_key_pair_new_from_asn1(allocator, &private_key_cursor);
        }
    }

    if (!private_key) {
        aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_INVALID_PEM);
    }
on_finish:
    aws_pem_objects_clean_up(&pem_objects);
    return private_key;
}

static int build_header(
    struct aws_allocator *allocator,
    struct aws_ecc_key_pair *private_key,
    struct aws_byte_buf *header_buf) {

    struct aws_json_value *header = NULL;
    struct aws_json_value *jwk = NULL;

    struct aws_byte_cursor x_cursor = aws_byte_cursor_from_buf(&private_key->pub_x);
    struct aws_byte_buf x_byte_buf;
    AWS_ZERO_STRUCT(x_byte_buf);

    struct aws_byte_cursor y_cursor = aws_byte_cursor_from_buf(&private_key->pub_y);
    struct aws_byte_buf y_byte_buf;
    AWS_ZERO_STRUCT(y_byte_buf);

    if (s_encode_buff(allocator, &x_cursor, &x_byte_buf, s_base_64_url_length, s_encode_base64_url) ||
        s_encode_buff(allocator, &y_cursor, &y_byte_buf, s_base_64_url_length, s_encode_base64_url)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to build dpop header");
        goto on_finish;
    }

    struct aws_byte_cursor x_encoded_cursor = aws_byte_cursor_from_buf(&x_byte_buf);
    struct aws_byte_cursor y_encoded_cursor = aws_byte_cursor_from_buf(&y_byte_buf);

    header = aws_json_value_new_object(allocator);
    jwk = aws_json_value_new_object(allocator);
    if (!header || !jwk || aws_json_value_add_to_object(header, aws_byte_cursor_from_c_str("jwk"), jwk) ||
        s_write_to_json_node(
            allocator,
            header,
            s_new_string_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_typ_key),
            s_jwt_header_typ_value) ||
        s_write_to_json_node(
            allocator,
            header,
            s_new_string_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_alg_key),
            s_jwt_header_alg_value) ||
        s_write_to_json_node(
            allocator,
            jwk,
            s_new_string_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_kty_key),
            s_jwt_header_kty_value) ||
        s_write_to_json_node(
            allocator,
            jwk,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_x_nums_key),
            &x_encoded_cursor) ||
        s_write_to_json_node(
            allocator,
            jwk,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_y_nums_key),
            &y_encoded_cursor) ||
        s_write_to_json_node(
            allocator,
            jwk,
            s_new_string_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_crv_key),
            s_jwt_header_crv_value)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to build dpop header");
        goto on_finish;
    }

    aws_byte_buf_init(header_buf, allocator, TOKEN_BUFFER_SIZE);
    aws_byte_buf_append_json_string(header, header_buf);
on_finish:
    aws_byte_buf_clean_up(&x_byte_buf);
    aws_byte_buf_clean_up(&y_byte_buf);
    if (header) {
        aws_json_value_destroy(header);
    }
    return AWS_OP_SUCCESS;
}

static int build_payload(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *host,
    struct aws_byte_buf *payload_buf) {
    bool success = false;
    struct aws_json_value *payload = NULL;

    struct aws_uuid jwk_id;
    AWS_ZERO_STRUCT(jwk_id);
    aws_uuid_init(&jwk_id);
    struct aws_byte_buf jwk_id_buf;
    AWS_ZERO_STRUCT(jwk_id_buf);
    aws_byte_buf_init(&jwk_id_buf, allocator, AWS_UUID_STR_LEN);
    aws_uuid_to_str(&jwk_id, &jwk_id_buf);
    struct aws_byte_cursor jwk_id_cursor = aws_byte_cursor_from_buf(&jwk_id_buf);

    struct aws_date_time dt;
    AWS_ZERO_STRUCT(dt);
    aws_date_time_init_now(&dt);
    double iat_seconds = (int)aws_date_time_as_epoch_secs(&dt);

    payload = aws_json_value_new_object(allocator);
    if (!payload ||
        s_write_to_json_node(
            allocator,
            payload,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_jti_key),
            &jwk_id_cursor) ||
        s_write_to_json_node(
            allocator,
            payload,
            s_new_string_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_htm_key),
            s_jwt_header_htm_value) ||
        s_write_to_json_node(
            allocator,
            payload,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_htu_key),
            host) ||
        s_write_to_json_node(
            allocator,
            payload,
            s_new_number_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_jwt_header_iat_key),
            &iat_seconds)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to build dpop header");
        goto on_finish;
    }

    aws_byte_buf_init(payload_buf, allocator, TOKEN_BUFFER_SIZE);
    aws_byte_buf_append_json_string(payload, payload_buf);
    success = true;
on_finish:
    aws_byte_buf_clean_up(&jwk_id_buf);
    if (payload) {
        aws_json_value_destroy(payload);
    }
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int get_message(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *header_cursor,
    struct aws_byte_cursor *payload_cursor,
    struct aws_byte_buf *message) {
    bool success = false;

    struct aws_byte_buf header_encoded_byte_buf;
    struct aws_byte_buf payload_encoded_byte_buf;
    if (s_encode_buff(allocator, header_cursor, &header_encoded_byte_buf, s_base_64_url_length, s_encode_base64_url) ||
        s_encode_buff(
            allocator, payload_cursor, &payload_encoded_byte_buf, s_base_64_url_length, s_encode_base64_url)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to create message");
        goto on_finish;
    }

    struct aws_byte_cursor period_delim = aws_byte_cursor_from_string(s_jwt_message_delim);
    struct aws_byte_cursor payload_encoded_cursor = aws_byte_cursor_from_buf(&payload_encoded_byte_buf);
    if (aws_byte_buf_init_copy_from_cursor(message, allocator, aws_byte_cursor_from_buf(&header_encoded_byte_buf)) ||
        aws_byte_buf_append_dynamic(message, &period_delim) ||
        aws_byte_buf_append_dynamic(message, &payload_encoded_cursor)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to create message");
        goto on_finish;
    }

    success = true;
on_finish:
    aws_byte_buf_clean_up_secure(&header_encoded_byte_buf);
    aws_byte_buf_clean_up_secure(&payload_encoded_byte_buf);
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int sign_message(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *message_cursor,
    struct aws_ecc_key_pair *private_key,
    struct aws_byte_buf *signature_encoded) {
    bool success = false;

    struct aws_byte_buf message_sha256;
    AWS_ZERO_STRUCT(message_sha256);
    if (s_encode_buff(allocator, message_cursor, &message_sha256, s_sha256_length, s_sha256_encode)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed calculate SHA256 Digest");
        goto on_finish;
    }

    struct aws_byte_cursor message_sha256_cursor = aws_byte_cursor_from_buf(&message_sha256);
    struct ecc_sign_input ecc_input = {.message = &message_sha256_cursor, .private_key = private_key};
    struct aws_byte_buf signature;
    AWS_ZERO_STRUCT(signature);
    if (s_encode_buff(allocator, &ecc_input, &signature, s_ecc_signature_length, s_ecc_sign)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed sign digest");
        goto on_finish;
    }

    struct aws_byte_cursor signature_cursor = aws_byte_cursor_from_buf(&signature);
    struct aws_byte_cursor r;
    struct aws_byte_cursor s;
    AWS_ZERO_STRUCT(r);
    AWS_ZERO_STRUCT(s);
    if (aws_ecc_decode_signature_der_to_raw(allocator, signature_cursor, &r, &s)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to decode signature");
        goto on_finish;
    }

    struct private_key_rs_pair private_key_rs_pair = {.r = &r, .s = &s};
    struct aws_byte_buf rs_combination;
    AWS_ZERO_STRUCT(rs_combination);
    if (s_encode_buff(allocator, &private_key_rs_pair, &rs_combination, s_rs_buff, s_rs_combine)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed combine r and s numbers");
        goto on_finish;
    }

    struct aws_byte_cursor rs_combination_cursor = aws_byte_cursor_from_buf(&rs_combination);
    s_encode_buff(allocator, &rs_combination_cursor, signature_encoded, s_base_64_url_length, s_encode_base64_url);

    success = true;
on_finish:
    aws_byte_buf_clean_up_secure(&message_sha256);
    aws_byte_buf_clean_up_secure(&signature);
    aws_byte_buf_clean_up_secure(&rs_combination);
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

int aws_login_token_get_dpop_header(
    struct aws_allocator *allocator,
    const struct aws_login_token *token,
    struct aws_byte_cursor host,
    struct aws_byte_buf *header_value) {
    bool success = false;

    struct aws_byte_cursor private_token_cursor = token->dpop_key;
    struct aws_ecc_key_pair *private_key = NULL;
    struct aws_byte_buf header_buf;
    struct aws_byte_buf payload_buf;
    struct aws_byte_buf message;
    struct aws_byte_buf signature;
    AWS_ZERO_STRUCT(header_buf);
    AWS_ZERO_STRUCT(payload_buf);
    AWS_ZERO_STRUCT(message);
    AWS_ZERO_STRUCT(signature);

    private_key = s_get_ecc_key_pair(allocator, private_token_cursor);
    if (!private_key) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to initialize ecc key pair");
        goto on_error;
    }

    if (build_header(allocator, private_key, &header_buf) || build_payload(allocator, &host, &payload_buf)) {
        goto on_error;
        ;
    }

    struct aws_byte_cursor header_cursor = aws_byte_cursor_from_buf(&header_buf);
    struct aws_byte_cursor payload_cursor = aws_byte_cursor_from_buf(&payload_buf);
    get_message(allocator, &header_cursor, &payload_cursor, &message);

    struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message);
    sign_message(allocator, &message_cursor, private_key, &signature);

    struct aws_byte_cursor period_delim = aws_byte_cursor_from_string(s_jwt_message_delim);
    struct aws_byte_cursor signature_encoded_cursor = aws_byte_cursor_from_buf(&signature);
    aws_byte_buf_init_copy_from_cursor(header_value, allocator, aws_byte_cursor_from_buf(&message));
    aws_byte_buf_append_dynamic(header_value, &period_delim);
    aws_byte_buf_append_dynamic(header_value, &signature_encoded_cursor);

    success = true;
    goto on_finish;
on_error:
    aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_FAILED_TO_CREATE_DPOP_HEADER);
on_finish:
    if (private_key) {
        aws_ecc_key_pair_release(private_key);
    }
    aws_byte_buf_clean_up_secure(&header_buf);
    aws_byte_buf_clean_up_secure(&payload_buf);
    aws_byte_buf_clean_up_secure(&message);
    aws_byte_buf_clean_up_secure(&signature);

    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

int aws_login_token_get_body(
    struct aws_allocator *allocator,
    const struct aws_login_token *token,
    struct aws_byte_buf *body_buf) {
    bool success = false;
    struct aws_json_value *body = aws_json_value_new_object(allocator);

    if (s_write_to_json_node(
            allocator,
            body,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_client_id_key),
            &token->client_id) ||
        s_write_to_json_node(
            allocator,
            body,
            s_new_string_from_cursor_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_refresh_token_key),
            &token->refresh_token) ||
        s_write_to_json_node(
            allocator,
            body,
            s_new_string_json_value,
            s_add_json_value_to_parent,
            aws_string_c_str(s_login_grant_type_key),
            s_login_grant_type_value)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "login token: failed to build body");
        goto on_error;
    }

    aws_byte_buf_init(body_buf, allocator, TOKEN_BUFFER_SIZE);
    aws_byte_buf_append_json_string(body, body_buf);
    success = true;
    goto on_finish;
on_error:
    aws_raise_error(AWS_AUTH_CREDENTIALS_PROVIDER_LOGIN_FAILED_TO_CREATE_REQUEST_BODY);
on_finish:
    aws_json_value_destroy(body);
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}
