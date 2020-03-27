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

#include <aws/auth/external/cJSON.h>
#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/date_time.h>
#include <aws/common/string.h>
#include <aws/http/connection.h>
#include <aws/http/connection_manager.h>
#include <aws/http/request_response.h>
#include <aws/http/status_code.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <ctype.h>

#if defined(_MSC_VER)
#    pragma warning(disable : 4204)
#endif /* _MSC_VER */

/* instance role credentials body response is currently ~ 1300 characters + name length */
#define IMDS_RESPONSE_SIZE_INITIAL 2048
#define IMDS_RESPONSE_TOKEN_SIZE_INITIAL 64
#define IMDS_RESPONSE_SIZE_LIMIT 10000
#define IMDS_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS 2
#define IMDS_MAX_RETRIES 4

struct aws_credentials_provider_imds_impl {
    struct aws_http_connection_manager *connection_manager;
    struct aws_credentials_provider_system_vtable *function_table;
    /* will be set to true by default, means using IMDS V2 */
    bool token_required;
};

static struct aws_credentials_provider_system_vtable s_default_function_table = {
    .aws_http_connection_manager_new = aws_http_connection_manager_new,
    .aws_http_connection_manager_release = aws_http_connection_manager_release,
    .aws_http_connection_manager_acquire_connection = aws_http_connection_manager_acquire_connection,
    .aws_http_connection_manager_release_connection = aws_http_connection_manager_release_connection,
    .aws_http_connection_make_request = aws_http_connection_make_request,
    .aws_http_stream_activate = aws_http_stream_activate,
    .aws_http_stream_get_connection = aws_http_stream_get_connection,
    .aws_http_stream_get_incoming_response_status = aws_http_stream_get_incoming_response_status,
    .aws_http_stream_release = aws_http_stream_release,
    .aws_http_connection_close = aws_http_connection_close,
};

static void s_imds_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data);

/*
 * This tracks which request we're on.
 */
enum aws_imds_query_state {
    AWS_IMDS_QS_TOKEN_REQ,
    AWS_IMDS_QS_TOKEN_RESP,
    AWS_IMDS_QS_ROLE_NAME_REQ,
    AWS_IMDS_QS_ROLE_NAME_RESP,
    AWS_IMDS_QS_ROLE_CREDENTIALS_REQ,
    AWS_IMDS_QS_ROLE_CREDENTIALS_RESP,
    AWS_IMDS_QS_COMPLETE,
    AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK,
    AWS_IMDS_QS_UNRECOVERABLE_ERROR
};

/*
 * Tracking structure for each outstanding async query to an imds provider
 */
struct aws_credentials_provider_imds_user_data {
    /* immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_credentials_provider *imds_provider;
    aws_on_get_credentials_callback_fn *original_callback;
    void *original_user_data;

    /* mutable */
    enum aws_imds_query_state query_state;
    struct aws_http_connection *connection;
    struct aws_http_message *request;
    struct aws_byte_buf current_result;
    struct aws_byte_buf token_result;
    struct aws_byte_cursor token;
    struct aws_byte_buf creds_uri;
    struct aws_credentials *credentials;
    /*
     * initial value is copy of impl->token_required,
     * will be adapted according to response.
     */
    bool token_required;
    uint8_t retry_count;
    int status_code;
};

static void s_aws_credentials_provider_imds_user_data_destroy(
    struct aws_credentials_provider_imds_user_data *user_data) {
    if (user_data == NULL) {
        return;
    }
    struct aws_credentials_provider_imds_impl *impl = user_data->imds_provider->impl;

    if (user_data->connection) {
        impl->function_table->aws_http_connection_manager_release_connection(
            impl->connection_manager, user_data->connection);
    }

    if (user_data->credentials) {
        aws_credentials_destroy(user_data->credentials);
        user_data->credentials = NULL;
    }

    aws_byte_buf_clean_up(&user_data->creds_uri);
    aws_byte_buf_clean_up(&user_data->current_result);
    aws_byte_buf_clean_up(&user_data->token_result);

    if (user_data->request) {
        aws_http_message_destroy(user_data->request);
    }
    aws_credentials_provider_release(user_data->imds_provider);
    aws_mem_release(user_data->allocator, user_data);
}

static struct aws_credentials_provider_imds_user_data *s_aws_credentials_provider_imds_user_data_new(
    struct aws_credentials_provider *imds_provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_imds_user_data *wrapped_user_data =
        aws_mem_calloc(imds_provider->allocator, 1, sizeof(struct aws_credentials_provider_imds_user_data));
    if (wrapped_user_data == NULL) {
        goto on_error;
    }

    wrapped_user_data->allocator = imds_provider->allocator;
    wrapped_user_data->imds_provider = imds_provider;
    aws_credentials_provider_acquire(imds_provider);
    wrapped_user_data->original_user_data = user_data;
    wrapped_user_data->original_callback = callback;

    if (aws_byte_buf_init(&wrapped_user_data->current_result, imds_provider->allocator, IMDS_RESPONSE_SIZE_INITIAL)) {
        goto on_error;
    }

    if (aws_byte_buf_init(
            &wrapped_user_data->token_result, imds_provider->allocator, IMDS_RESPONSE_TOKEN_SIZE_INITIAL)) {
        goto on_error;
    }
    struct aws_credentials_provider_imds_impl *impl = imds_provider->impl;
    wrapped_user_data->token_required = impl->token_required;

    if (impl->token_required) {
        wrapped_user_data->query_state = AWS_IMDS_QS_TOKEN_REQ;
    } else {
        wrapped_user_data->query_state = AWS_IMDS_QS_ROLE_NAME_REQ;
    }

    return wrapped_user_data;

on_error:

    s_aws_credentials_provider_imds_user_data_destroy(wrapped_user_data);

    return NULL;
}

static void s_aws_credentials_provider_imds_user_data_reset_scratch_data(
    struct aws_credentials_provider_imds_user_data *imds_user_data) {
    imds_user_data->current_result.len = 0;
    imds_user_data->status_code = 0;

    if (imds_user_data->request) {
        aws_http_message_destroy(imds_user_data->request);
        imds_user_data->request = NULL;
    }
}

AWS_STATIC_STRING_FROM_LITERAL(s_empty_string, "\0");
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_name, "AccessKeyId");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_name, "SecretAccessKey");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_name, "Token");
AWS_STATIC_STRING_FROM_LITERAL(s_creds_expiration_name, "Expiration");

static int s_imds_on_incoming_body_fn(
    struct aws_http_stream *stream,
    const struct aws_byte_cursor *data,
    void *user_data) {

    (void)stream;
    (void)data;

    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;
    struct aws_credentials_provider_imds_impl *impl = imds_user_data->imds_provider->impl;

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) IMDS credentials provider received %zu response bytes",
        (void *)imds_user_data->imds_provider,
        data->len);

    if (data->len + imds_user_data->current_result.len > IMDS_RESPONSE_SIZE_LIMIT) {
        impl->function_table->aws_http_connection_close(imds_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) IMDS credentials provider query response exceeded maximum allowed length",
            (void *)imds_user_data->imds_provider);

        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append_dynamic(&imds_user_data->current_result, data)) {
        impl->function_table->aws_http_connection_close(imds_user_data->connection);
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) IMDS credentials provider query error appending response",
            (void *)imds_user_data->imds_provider);

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_imds_on_incoming_headers_fn(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {

    (void)header_array;
    (void)num_headers;

    if (header_block != AWS_HTTP_HEADER_BLOCK_MAIN) {
        return AWS_OP_SUCCESS;
    }

    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;
    if (header_block == AWS_HTTP_HEADER_BLOCK_MAIN) {
        if (imds_user_data->status_code == 0) {
            struct aws_credentials_provider_imds_impl *impl = imds_user_data->imds_provider->impl;
            if (impl->function_table->aws_http_stream_get_incoming_response_status(
                    stream, &imds_user_data->status_code)) {

                AWS_LOGF_ERROR(
                    AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                    "(id=%p) IMDS credentials provider failed to get http status code",
                    (void *)imds_user_data->imds_provider);

                return AWS_OP_ERR;
            }
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) IMDS credentials provider query received http status code %d",
                (void *)imds_user_data->imds_provider,
                imds_user_data->status_code);
        }
    }

    return AWS_OP_SUCCESS;
}

static bool s_isspace(uint8_t c) {
    return isspace((int)c) != 0;
}

static void s_imds_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data);

AWS_STATIC_STRING_FROM_LITERAL(s_imds_metadata_resource_path, "/latest/meta-data/iam/security-credentials/");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_accept_header, "Accept");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_accept_header_value, "*/*");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_host, "169.254.169.254");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_user_agent_header, "User-Agent");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_user_agent_header_value, "aws-sdk-crt/imds-credentials-provider");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_h1_0_keep_alive_header, "Connection");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_h1_0_keep_alive_header_value, "keep-alive");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_token_resource_path, "/latest/api/token");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_token_ttl_header, "x-aws-ec2-metadata-token-ttl-seconds");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_token_header, "x-aws-ec2-metadata-token");
AWS_STATIC_STRING_FROM_LITERAL(s_imds_token_ttl_default_value, "21600");

static int s_make_imds_http_query(
    struct aws_credentials_provider_imds_user_data *imds_user_data,
    const struct aws_byte_cursor *verb,
    const struct aws_byte_cursor *uri,
    const struct aws_http_header *headers,
    size_t header_count) {
    AWS_FATAL_ASSERT(imds_user_data->connection);

    struct aws_http_stream *stream = NULL;
    struct aws_http_message *request = aws_http_message_new_request(imds_user_data->allocator);
    struct aws_credentials_provider_imds_impl *impl = imds_user_data->imds_provider->impl;

    if (request == NULL) {
        return AWS_OP_ERR;
    }

    if (headers && aws_http_message_add_header_array(request, headers, header_count)) {
        goto on_error;
    }

    struct aws_http_header accept_header = {
        .name = aws_byte_cursor_from_string(s_imds_accept_header),
        .value = aws_byte_cursor_from_string(s_imds_accept_header_value),
    };
    if (aws_http_message_add_header(request, accept_header)) {
        goto on_error;
    }

    struct aws_http_header user_agent_header = {
        .name = aws_byte_cursor_from_string(s_imds_user_agent_header),
        .value = aws_byte_cursor_from_string(s_imds_user_agent_header_value),
    };
    if (aws_http_message_add_header(request, user_agent_header)) {
        goto on_error;
    }

    struct aws_http_header keep_alive_header = {
        .name = aws_byte_cursor_from_string(s_imds_h1_0_keep_alive_header),
        .value = aws_byte_cursor_from_string(s_imds_h1_0_keep_alive_header_value),
    };
    if (aws_http_message_add_header(request, keep_alive_header)) {
        goto on_error;
    }

    if (aws_http_message_set_request_method(request, *verb)) {
        goto on_error;
    }

    if (aws_http_message_set_request_path(request, *uri)) {
        goto on_error;
    }

    imds_user_data->request = request;

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .on_response_headers = s_imds_on_incoming_headers_fn,
        .on_response_header_block_done = NULL,
        .on_response_body = s_imds_on_incoming_body_fn,
        .on_complete = s_imds_on_stream_complete_fn,
        .user_data = imds_user_data,
        .request = request,
    };

    stream = impl->function_table->aws_http_connection_make_request(imds_user_data->connection, &request_options);

    if (!stream) {
        goto on_error;
    }

    if (impl->function_table->aws_http_stream_activate(stream)) {
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    impl->function_table->aws_http_stream_release(stream);
    aws_http_message_destroy(request);

    return AWS_OP_ERR;
}

typedef void(imds_state_fn)(struct aws_credentials_provider_imds_user_data *);

/* Make an http request to put a ttl and hopefully get a token back. */
static void s_imds_query_token(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_PRECONDITION(imds_user_data->query_state == AWS_IMDS_QS_TOKEN_REQ);

    struct aws_byte_cursor uri = aws_byte_cursor_from_string(s_imds_token_resource_path);

    struct aws_http_header token_ttl_header = {
        .name = aws_byte_cursor_from_string(s_imds_token_ttl_header),
        .value = aws_byte_cursor_from_string(s_imds_token_ttl_default_value),
    };

    struct aws_http_header headers[] = {
        token_ttl_header,
    };

    struct aws_byte_cursor verb = aws_byte_cursor_from_c_str("PUT");

    imds_user_data->query_state = AWS_IMDS_QS_TOKEN_RESP;

    if (s_make_imds_http_query(imds_user_data, &verb, &uri, headers, AWS_ARRAY_SIZE(headers))) {
        imds_user_data->query_state = AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK;
    }
}

/*
 * Process the http response from the token put.
 */
static void s_imds_on_token_response(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_PRECONDITION(imds_user_data->query_state == AWS_IMDS_QS_TOKEN_RESP);

    /* Gets 400 means token is required but the request itself failed. */
    if (imds_user_data->status_code == AWS_HTTP_STATUS_CODE_400_BAD_REQUEST) {
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        return;
    }

    /*
     * Other than that, if meets any error, then token is not required,
     * we should fall back to insecure request. Otherwise, we should use
     * token in following requests.
     */
    if (imds_user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK || imds_user_data->current_result.len == 0) {
        imds_user_data->token_required = false;
    } else {
        imds_user_data->token = aws_byte_cursor_from_buf(&(imds_user_data->current_result));
        aws_byte_cursor_trim_pred(&(imds_user_data->token), s_isspace);
        if (imds_user_data->token.len == 0) {
            imds_user_data->token_required = false;
        } else {
            aws_byte_buf_reset(&imds_user_data->token_result, true /*zero contents*/);
            if (aws_byte_buf_append_and_update(&imds_user_data->token_result, &imds_user_data->token)) {
                imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
                return;
            }
        }
    }
    s_aws_credentials_provider_imds_user_data_reset_scratch_data(imds_user_data);
    /* No matter token acquire succeeded or not, moving forward to next step. */
    imds_user_data->query_state = AWS_IMDS_QS_ROLE_NAME_REQ;
}

/*
 * Make the http request to fetch the role name.
 */
static void s_imds_query_instance_role_name(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_PRECONDITION(imds_user_data->query_state == AWS_IMDS_QS_ROLE_NAME_REQ);

    struct aws_http_header token_header = {
        .name = aws_byte_cursor_from_string(s_imds_token_header),
        .value = imds_user_data->token,
    };

    struct aws_http_header headers[] = {
        token_header,
    };

    size_t headers_count = 0;
    struct aws_http_header *headers_array_ptr = NULL;

    if (imds_user_data->token_required) {
        headers_count = 1;
        headers_array_ptr = headers;
    }

    struct aws_byte_cursor uri = aws_byte_cursor_from_string(s_imds_metadata_resource_path);
    struct aws_byte_cursor verb = aws_byte_cursor_from_c_str("GET");

    imds_user_data->query_state = AWS_IMDS_QS_ROLE_NAME_RESP;

    if (s_make_imds_http_query(imds_user_data, &verb, &uri, headers_array_ptr, headers_count)) {
        imds_user_data->query_state = AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK;
        return;
    }
}

/*
 * Process the http response for fetching the role name for the ec2 instance.
 */
static void s_imds_process_instance_role_response(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_PRECONDITION(imds_user_data->query_state == AWS_IMDS_QS_ROLE_NAME_RESP);

    /* In this case we fallback to the secure imds flow. */
    if (imds_user_data->status_code == AWS_HTTP_STATUS_CODE_401_UNAUTHORIZED) {
        s_aws_credentials_provider_imds_user_data_reset_scratch_data(imds_user_data);
        imds_user_data->token_required = true;
        imds_user_data->query_state = AWS_IMDS_QS_TOKEN_REQ;
        return;
    }

    /*
     * At this step, on anything other than a 200, nullify the
     * response and treat as an error
     */
    if (imds_user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK) {
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        return;
    }
    /*
     * Take the result of the base query, which should be the name of the instance role
     */
    if (imds_user_data->current_result.len == 0) {
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        return;
    }

    /*
     * Append the role name to the base uri to get the final uri
     */
    if (aws_byte_buf_init(
            &imds_user_data->creds_uri,
            imds_user_data->allocator,
            s_imds_metadata_resource_path->len + imds_user_data->current_result.len)) {
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        return;
    }

    struct aws_byte_cursor imds_path = aws_byte_cursor_from_string(s_imds_metadata_resource_path);
    if (aws_byte_buf_append(&imds_user_data->creds_uri, &imds_path)) {
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        return;
    }

    struct aws_byte_cursor role_name = aws_byte_cursor_from_buf(&imds_user_data->current_result);
    if (aws_byte_buf_append(&imds_user_data->creds_uri, &role_name)) {
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        return;
    }

    /* "Clear" the result */
    s_aws_credentials_provider_imds_user_data_reset_scratch_data(imds_user_data);
    imds_user_data->query_state = AWS_IMDS_QS_ROLE_CREDENTIALS_REQ;
}

/*
 * Make a request to attempt to fetch the credentials.
 */
static void s_imds_query_instance_role_credentials_req(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_PRECONDITION(imds_user_data->query_state == AWS_IMDS_QS_ROLE_CREDENTIALS_REQ);

    AWS_FATAL_ASSERT(imds_user_data->connection);
    AWS_FATAL_ASSERT(imds_user_data->creds_uri.buffer);

    struct aws_http_header token_header = {
        .name = aws_byte_cursor_from_string(s_imds_token_header),
        .value = imds_user_data->token,
    };

    struct aws_http_header headers[] = {
        token_header,
    };

    size_t headers_count = 0;
    struct aws_http_header *headers_array_ptr = NULL;

    if (imds_user_data->token_required) {
        headers_count = 1;
        headers_array_ptr = headers;
    }

    struct aws_byte_cursor verb = aws_byte_cursor_from_c_str("GET");
    struct aws_byte_cursor uri = aws_byte_cursor_from_buf(&imds_user_data->creds_uri);

    imds_user_data->query_state = AWS_IMDS_QS_ROLE_CREDENTIALS_RESP;

    if (s_make_imds_http_query(imds_user_data, &verb, &uri, headers_array_ptr, headers_count)) {
        imds_user_data->query_state = AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK;
    }
}

/*
 * Process the http response from the get credentials for role response.
 *
 * In general, the IMDS document looks something like:

{
  "Code" : "Success",
  "LastUpdated" : "2019-05-28T18:03:09Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "...",
  "SecretAccessKey" : "...",
  "Token" : "...",
  "Expiration" : "2019-05-29T00:21:43Z"
}

 */
static void s_imds_query_instance_role_credentials_response(
    struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_PRECONDITION(imds_user_data->query_state == AWS_IMDS_QS_ROLE_CREDENTIALS_RESP);

    cJSON *document_root = NULL;

    if (imds_user_data->status_code != AWS_HTTP_STATUS_CODE_200_OK) {
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        goto done;
    }

    struct aws_byte_cursor null_terminator_cursor = aws_byte_cursor_from_string(s_empty_string);
    if (aws_byte_buf_append_dynamic(&imds_user_data->current_result, &null_terminator_cursor)) {
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
        goto done;
    }

    document_root = cJSON_Parse((const char *)imds_user_data->current_result.buffer);
    if (document_root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse IMDS response as JSON document.");
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
        goto done;
    }

    /*
     * Pull out the three credentials components
     */
    cJSON *access_key_id = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_access_key_id_name));
    if (!cJSON_IsString(access_key_id) || (access_key_id->valuestring == NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse AccessKeyId from IMDS response JSON document.");
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
        goto done;
    }

    cJSON *secret_access_key =
        cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_secret_access_key_name));
    if (!cJSON_IsString(secret_access_key) || (secret_access_key->valuestring == NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse SecretAccessKey from IMDS response JSON document.");
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
        goto done;
    }

    cJSON *session_token = cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_session_token_name));
    if (!cJSON_IsString(session_token) || (session_token->valuestring == NULL)) {
        AWS_LOGF_ERROR(AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Token from IMDS response JSON document.");
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
        goto done;
    }

    cJSON *creds_expiration =
        cJSON_GetObjectItemCaseSensitive(document_root, aws_string_c_str(s_creds_expiration_name));
    if (!cJSON_IsString(creds_expiration) || (creds_expiration->valuestring == NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "Failed to parse Expiration from IMDS response JSON document.");
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
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
            "IMDS credentials provider received unexpected credentials response,"
            " either access key, secret key or token is empty.");
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
        goto done;
    }

    imds_user_data->credentials = aws_credentials_new_from_cursors(
        imds_user_data->allocator, &access_key_id_cursor, &secret_access_key_cursor, &session_token_cursor);

    if (imds_user_data->credentials == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER, "IMDS credentials provider failed to allocate memory for credentials.");
        imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        goto done;
    }

    if (creds_expiration_cursor.len != 0) {
        struct aws_date_time expiration;
        if (aws_date_time_init_from_str_cursor(&expiration, &creds_expiration_cursor, AWS_DATE_FORMAT_ISO_8601) ==
            AWS_OP_ERR) {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "Expiration in IMDS response JSON document is not a valid ISO_8601 date string.");
            aws_credentials_destroy(imds_user_data->credentials);
            imds_user_data->credentials = NULL;
            imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
            aws_raise_error(AWS_AUTH_PROVIDER_PARSER_UNEXPECTED_RESPONSE);
            goto done;
        }
        imds_user_data->credentials->expiration_timepoint_seconds = (uint64_t)aws_date_time_as_epoch_secs(&expiration);
        imds_user_data->query_state = AWS_IMDS_QS_COMPLETE;
    }

done:
    if (document_root != NULL) {
        cJSON_Delete(document_root);
    }

    s_aws_credentials_provider_imds_user_data_reset_scratch_data(imds_user_data);
}

static void s_imds_query_complete(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_PRECONDITION(imds_user_data->query_state == AWS_IMDS_QS_COMPLETE);

    imds_user_data->original_callback(imds_user_data->credentials, imds_user_data->original_user_data);
    AWS_LOGF_INFO(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) IMDS credentials provider successfully queried instance role credentials",
        (void *)imds_user_data->imds_provider);
}

static void s_imds_query_error(struct aws_credentials_provider_imds_user_data *imds_user_data) {
    AWS_PRECONDITION(
        imds_user_data->query_state == AWS_IMDS_QS_UNRECOVERABLE_ERROR ||
        imds_user_data->query_state == AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK);

    imds_user_data->original_callback(NULL, imds_user_data->original_user_data);
    AWS_LOGF_WARN(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) IMDS credentials provider failed to query instance role credentials",
        (void *)imds_user_data->imds_provider);
}

/* Okay, some explanation on this state machine. There are two drivers.
 *
 * Upon receiving a connection from the connection manager, we drive the machine. This should always be in a
 * request state (we assert this) request states are even numbers.
 *
 * Upon receiving a response from the http request, we drive the machine. This should always be in a response state.
 *
 * Each state is responsible for crafting it's own http requests AND processing the meaning of it's own response.
 *
 * For your convenience, the functions in this table are in order above.
 */
static imds_state_fn *s_query_state_machine[] = {
    [AWS_IMDS_QS_TOKEN_REQ] = s_imds_query_token,
    [AWS_IMDS_QS_TOKEN_RESP] = s_imds_on_token_response,
    [AWS_IMDS_QS_ROLE_NAME_REQ] = s_imds_query_instance_role_name,
    [AWS_IMDS_QS_ROLE_NAME_RESP] = s_imds_process_instance_role_response,
    [AWS_IMDS_QS_ROLE_CREDENTIALS_REQ] = s_imds_query_instance_role_credentials_req,
    [AWS_IMDS_QS_ROLE_CREDENTIALS_RESP] = s_imds_query_instance_role_credentials_response,
    [AWS_IMDS_QS_COMPLETE] = s_imds_query_complete,
    [AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK] = s_imds_query_error,
    [AWS_IMDS_QS_UNRECOVERABLE_ERROR] = s_imds_query_error,
};

static inline bool s_imds_state_machine_is_terminal_state(struct aws_credentials_provider_imds_user_data *user_data) {
    return user_data->query_state >= AWS_IMDS_QS_COMPLETE && user_data->query_state <= AWS_IMDS_QS_UNRECOVERABLE_ERROR;
}

static inline bool s_imds_state_machine_is_request_state(struct aws_credentials_provider_imds_user_data *user_data) {
    return !s_imds_state_machine_is_terminal_state(user_data) && !(user_data->query_state & 0x01);
}

static inline void s_imds_state_machine_roll_back_to_request_state(
    struct aws_credentials_provider_imds_user_data *user_data) {
    AWS_FATAL_ASSERT(
        !s_imds_state_machine_is_terminal_state(user_data) &&
        "State machine can't be rolled back from a terminal state.");
    user_data->query_state -= 1;
    /* request states are evenly numbered. */
    AWS_FATAL_ASSERT(s_imds_state_machine_is_request_state(user_data) && "Can only rollback to a request state.");
}

static void s_imds_on_acquire_connection(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;

    AWS_FATAL_ASSERT(
        s_imds_state_machine_is_request_state(user_data) && "Invalid query state, we should be in a request state.")
    imds_user_data->connection = connection;

    if (connection == NULL) {
        AWS_LOGF_WARN(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "id=%p: Instance metadata provider failed to acquire a connection, error code %d(%s)",
            (void *)imds_user_data->imds_provider,
            error_code,
            aws_error_str(error_code));

        imds_user_data->query_state = AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK;
    } else {
        s_query_state_machine[imds_user_data->query_state](imds_user_data);
    }

    /* there's no universe where we should have moved to COMPLETE, but an error could have occurred. */
    if (imds_user_data->query_state == AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK) {
        s_query_state_machine[AWS_IMDS_QS_QUERY_NEVER_CLEARED_STACK](imds_user_data);
        s_aws_credentials_provider_imds_user_data_destroy(imds_user_data);
    }
}

static void s_imds_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    struct aws_credentials_provider_imds_user_data *imds_user_data = user_data;

    aws_http_message_destroy(imds_user_data->request);
    imds_user_data->request = NULL;

    struct aws_credentials_provider_imds_impl *impl = imds_user_data->imds_provider->impl;

    struct aws_http_connection *connection = impl->function_table->aws_http_stream_get_connection(stream);
    impl->function_table->aws_http_stream_release(stream);
    impl->function_table->aws_http_connection_manager_release_connection(impl->connection_manager, connection);

    /* try again, just drop the state from the response to the request state by subtracting one.
     * Don't run the state machine in this callback in this case, let the acquire connection callback handle it.
     * Note these are connection level errors, not http level. Since we obviously connected, it's likely
     * we're on EC2, plus we have max retries so it's likely safer to just retry everything.*/
    if (error_code) {
        if (imds_user_data->retry_count++ < IMDS_MAX_RETRIES) {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "id=%p: Connection was closed, retrying the last request on a new connection.",
                (void *)imds_user_data->imds_provider);
            /* roll back to the last request we made, and let it retry. */
            s_imds_state_machine_roll_back_to_request_state(imds_user_data);
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "id=%p: Connection was closed, retries have been exhausted.",
                (void *)imds_user_data->imds_provider);
            /* roll back to the last request we made, and let it retry. */
            imds_user_data->query_state = AWS_IMDS_QS_UNRECOVERABLE_ERROR;
        }
    } else {
        s_query_state_machine[imds_user_data->query_state](imds_user_data);
    }

    /* if there's more work to do, acquire a connection, and run the machine again. */
    if (!s_imds_state_machine_is_terminal_state(imds_user_data)) {
        impl->function_table->aws_http_connection_manager_acquire_connection(
            impl->connection_manager, s_imds_on_acquire_connection, user_data);
    } else {
        /* terminal state, invoke the terminal state and cleanup. */
        s_query_state_machine[imds_user_data->query_state](imds_user_data);
        s_aws_credentials_provider_imds_user_data_destroy(imds_user_data);
    }
}

static int s_credentials_provider_imds_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_imds_impl *impl = provider->impl;

    struct aws_credentials_provider_imds_user_data *wrapped_user_data =
        s_aws_credentials_provider_imds_user_data_new(provider, callback, user_data);
    if (wrapped_user_data == NULL) {
        goto error;
    }

    impl->function_table->aws_http_connection_manager_acquire_connection(
        impl->connection_manager, s_imds_on_acquire_connection, wrapped_user_data);

    return AWS_OP_SUCCESS;

error:

    s_aws_credentials_provider_imds_user_data_destroy(wrapped_user_data);

    return AWS_OP_ERR;
}

static void s_credentials_provider_imds_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_imds_impl *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    impl->function_table->aws_http_connection_manager_release(impl->connection_manager);

    /* freeing the provider takes place in the shutdown callback below */
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_imds_vtable = {
    .get_credentials = s_credentials_provider_imds_get_credentials_async,
    .destroy = s_credentials_provider_imds_destroy,
};

static void s_on_connection_manager_shutdown(void *user_data) {
    struct aws_credentials_provider *provider = user_data;

    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_mem_release(provider->allocator, provider);
}

struct aws_credentials_provider *aws_credentials_provider_new_imds(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_imds_options *options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_imds_impl *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_imds_impl));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_imds_vtable, impl);

    struct aws_socket_options socket_options;
    AWS_ZERO_STRUCT(socket_options);
    socket_options.type = AWS_SOCKET_STREAM;
    socket_options.domain = AWS_SOCKET_IPV4;
    socket_options.connect_timeout_ms = (uint32_t)aws_timestamp_convert(
        IMDS_CONNECT_TIMEOUT_DEFAULT_IN_SECONDS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);

    struct aws_http_connection_manager_options manager_options;
    AWS_ZERO_STRUCT(manager_options);
    manager_options.bootstrap = options->bootstrap;
    manager_options.initial_window_size = IMDS_RESPONSE_SIZE_LIMIT;
    manager_options.socket_options = &socket_options;
    manager_options.tls_connection_options = NULL;
    manager_options.host = aws_byte_cursor_from_string(s_imds_host);
    manager_options.port = 80;
    manager_options.max_connections = 2;
    manager_options.shutdown_complete_callback = s_on_connection_manager_shutdown;
    manager_options.shutdown_complete_user_data = provider;

    impl->function_table = options->function_table;
    if (impl->function_table == NULL) {
        impl->function_table = &s_default_function_table;
    }
    impl->token_required = options->imds_version == IMDS_V1 ? false : true;
    impl->connection_manager = impl->function_table->aws_http_connection_manager_new(allocator, &manager_options);
    if (impl->connection_manager == NULL) {
        goto on_error;
    }

    provider->shutdown_options = options->shutdown_options;

    return provider;

on_error:

    aws_credentials_provider_destroy(provider);

    return NULL;
}
