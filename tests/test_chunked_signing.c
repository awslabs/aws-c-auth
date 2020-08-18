/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/auth/credentials.h>
#include <aws/auth/private/aws_signing.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/auth/signing_config.h>
#include <aws/auth/signing_result.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/stream.h>

/*
 * The chunked signing test is built using the complete chunked signing example in the s3 docs:
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
 *
 */

AWS_STATIC_STRING_FROM_LITERAL(s_chunked_access_key_id, "AKIAIOSFODNN7EXAMPLE");
AWS_STATIC_STRING_FROM_LITERAL(s_chunked_secret_access_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
AWS_STATIC_STRING_FROM_LITERAL(s_chunked_test_region, "us-east-1");
AWS_STATIC_STRING_FROM_LITERAL(s_chunked_test_service, "s3");
AWS_STATIC_STRING_FROM_LITERAL(s_chunked_test_date, "Fri, 24 May 2013 00:00:00 GMT");

static struct aws_http_header s_host_header = {
    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("host"),
    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("s3.amazonaws.com"),
};

static struct aws_http_header s_storage_class_header = {
    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("x-amz-storage-class"),
    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("REDUCED_REDUNDANCY"),
};

static struct aws_http_header s_content_encoding_header = {
    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Encoding"),
    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("aws-chunked"),
};

static struct aws_http_header s_decoded_length_header = {
    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("x-amz-decoded-content-length"),
    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("66560"),
};

static struct aws_http_header s_content_length_header = {
    .name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("Content-Length"),
    .value = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("66824"),
};

AWS_STATIC_STRING_FROM_LITERAL(s_chunked_test_path, "/examplebucket/chunkObject.txt");

static struct aws_http_message *s_build_chunked_test_request(struct aws_allocator *allocator) {
    struct aws_http_message *request = aws_http_message_new_request(allocator);

    aws_http_message_add_header(request, s_host_header);
    aws_http_message_add_header(request, s_storage_class_header);
    aws_http_message_add_header(request, s_content_encoding_header);
    aws_http_message_add_header(request, s_decoded_length_header);
    aws_http_message_add_header(request, s_content_length_header);
    aws_http_message_set_request_method(request, aws_http_method_put);
    aws_http_message_set_request_path(request, aws_byte_cursor_from_string(s_chunked_test_path));

    return request;
}

static int s_initialize_request_signing_config(
    struct aws_signing_config_aws *config,
    struct aws_credentials *credentials) {
    config->config_type = AWS_SIGNING_CONFIG_AWS;
    config->algorithm = AWS_SIGNING_ALGORITHM_V4;
    config->signature_type = AWS_ST_HTTP_REQUEST_HEADERS;
    config->region = aws_byte_cursor_from_string(s_chunked_test_region);
    config->service = aws_byte_cursor_from_string(s_chunked_test_service);

    struct aws_byte_cursor chunked_test_date_cursor = aws_byte_cursor_from_string(s_chunked_test_date);
    if (aws_date_time_init_from_str_cursor(&config->date, &chunked_test_date_cursor, AWS_DATE_FORMAT_RFC822)) {
        return AWS_OP_ERR;
    }

    config->flags.use_double_uri_encode = false;
    config->flags.should_normalize_uri_path = true;
    config->signed_body_value = g_aws_signed_body_value_streaming_aws4_hmac_sha256_payload;
    config->signed_body_header = AWS_SBHT_X_AMZ_CONTENT_SHA256;
    config->credentials = credentials;

    return AWS_OP_SUCCESS;
}

static int s_initialize_chunk_signing_config(
    struct aws_signing_config_aws *config,
    struct aws_credentials *credentials) {
    config->config_type = AWS_SIGNING_CONFIG_AWS;
    config->algorithm = AWS_SIGNING_ALGORITHM_V4;
    config->signature_type = AWS_ST_HTTP_REQUEST_CHUNK;
    config->region = aws_byte_cursor_from_string(s_chunked_test_region);
    config->service = aws_byte_cursor_from_string(s_chunked_test_service);

    struct aws_byte_cursor chunked_test_date_cursor = aws_byte_cursor_from_string(s_chunked_test_date);
    if (aws_date_time_init_from_str_cursor(&config->date, &chunked_test_date_cursor, AWS_DATE_FORMAT_RFC822)) {
        return AWS_OP_ERR;
    }

    config->flags.use_double_uri_encode = false;
    config->flags.should_normalize_uri_path = true;
    config->signed_body_header = AWS_SBHT_NONE;
    config->credentials = credentials;

    return AWS_OP_SUCCESS;
}

struct chunked_signing_tester {
    struct aws_credentials *credentials;
    struct aws_http_message *request;
    struct aws_signable *request_signable;
    struct aws_signing_config_aws request_signing_config;
    struct aws_signing_config_aws chunk_signing_config;
    struct aws_byte_buf chunk1;
    struct aws_byte_buf chunk2;
    struct aws_input_stream *chunk1_stream;
    struct aws_input_stream *chunk2_stream;

    struct aws_byte_buf request_authorization_header;
    struct aws_byte_buf last_signature;
};

#define CHUNK1_SIZE 65536
#define CHUNK2_SIZE 1024

static int s_chunked_signing_tester_init(struct aws_allocator *allocator, struct chunked_signing_tester *tester) {
    tester->credentials = aws_credentials_new_from_string(
        allocator, s_chunked_access_key_id, s_chunked_secret_access_key, NULL, UINT64_MAX);
    tester->request = s_build_chunked_test_request(allocator);
    tester->request_signable = aws_signable_new_http_request(allocator, tester->request);

    AWS_ZERO_STRUCT(tester->request_signing_config);
    ASSERT_SUCCESS(s_initialize_request_signing_config(&tester->request_signing_config, tester->credentials));
    ASSERT_SUCCESS(s_initialize_chunk_signing_config(&tester->chunk_signing_config, tester->credentials));

    ASSERT_SUCCESS(aws_byte_buf_init(&tester->request_authorization_header, allocator, 512));
    ASSERT_SUCCESS(aws_byte_buf_init(&tester->last_signature, allocator, 128));

    struct aws_byte_cursor a_cursor = aws_byte_cursor_from_c_str("a");
    ASSERT_SUCCESS(aws_byte_buf_init(&tester->chunk1, allocator, CHUNK1_SIZE));
    for (size_t i = 0; i < CHUNK1_SIZE; ++i) {
        aws_byte_buf_append_dynamic(&tester->chunk1, &a_cursor);
    }

    ASSERT_SUCCESS(aws_byte_buf_init(&tester->chunk2, allocator, 1024));
    for (size_t i = 0; i < CHUNK2_SIZE; ++i) {
        aws_byte_buf_append_dynamic(&tester->chunk2, &a_cursor);
    }

    struct aws_byte_cursor chunk1_cursor = aws_byte_cursor_from_buf(&tester->chunk1);
    tester->chunk1_stream = aws_input_stream_new_from_cursor(allocator, &chunk1_cursor);

    struct aws_byte_cursor chunk2_cursor = aws_byte_cursor_from_buf(&tester->chunk2);
    tester->chunk2_stream = aws_input_stream_new_from_cursor(allocator, &chunk2_cursor);

    return AWS_OP_SUCCESS;
}

static void s_chunked_signing_tester_cleanup(struct chunked_signing_tester *tester) {
    aws_signable_destroy(tester->request_signable);
    aws_http_message_release(tester->request);
    aws_credentials_release(tester->credentials);
    aws_byte_buf_clean_up(&tester->request_authorization_header);
    aws_byte_buf_clean_up(&tester->last_signature);
    aws_byte_buf_clean_up(&tester->chunk1);
    aws_byte_buf_clean_up(&tester->chunk2);
    aws_input_stream_destroy(tester->chunk1_stream);
    aws_input_stream_destroy(tester->chunk2_stream);
}

static void s_on_request_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {
    (void)error_code;

    struct chunked_signing_tester *tester = userdata;

    struct aws_array_list *headers = NULL;
    aws_signing_result_get_property_list(result, g_aws_http_headers_property_list_name, &headers);

    struct aws_byte_cursor auth_header_name = aws_byte_cursor_from_string(g_aws_signing_authorization_header_name);
    struct aws_byte_cursor auth_header_value;
    AWS_ZERO_STRUCT(auth_header_value);
    for (size_t i = 0; i < aws_array_list_length(headers); ++i) {
        struct aws_signing_result_property pair;
        AWS_ZERO_STRUCT(pair);
        if (aws_array_list_get_at(headers, &pair, i)) {
            continue;
        }

        if (pair.name == NULL) {
            continue;
        }

        struct aws_byte_cursor pair_name_cursor = aws_byte_cursor_from_string(pair.name);
        if (aws_byte_cursor_eq_ignore_case(&pair_name_cursor, &auth_header_name)) {
            auth_header_value = aws_byte_cursor_from_string(pair.value);
            break;
        }
    }
    aws_byte_buf_append_dynamic(&tester->request_authorization_header, &auth_header_value);

    struct aws_string *signature = NULL;
    aws_signing_result_get_property(result, g_aws_signature_property_name, &signature);

    struct aws_byte_cursor signature_cursor = aws_byte_cursor_from_string(signature);
    aws_byte_buf_append_dynamic(&tester->last_signature, &signature_cursor);
}

static void s_on_chunk_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {
    (void)error_code;

    struct chunked_signing_tester *tester = userdata;

    tester->last_signature.len = 0;

    struct aws_string *signature = NULL;
    aws_signing_result_get_property(result, g_aws_signature_property_name, &signature);

    struct aws_byte_cursor signature_cursor = aws_byte_cursor_from_string(signature);
    aws_byte_buf_append_dynamic(&tester->last_signature, &signature_cursor);
}

/* There is an error in the s3 docs where they list the authorization header value: it is missing a space between
 * the ',' and 'SignedHeaders=' as well as a space between the ',' and 'Signature='
 */
AWS_STATIC_STRING_FROM_LITERAL(
    s_expected_request_authorization_header,
    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
    "SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-"
    "amz-storage-class, Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9");
AWS_STATIC_STRING_FROM_LITERAL(
    s_expected_request_signature,
    "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9");
AWS_STATIC_STRING_FROM_LITERAL(
    s_expected_first_chunk_signature,
    "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648");
AWS_STATIC_STRING_FROM_LITERAL(
    s_expected_second_chunk_signature,
    "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497");
AWS_STATIC_STRING_FROM_LITERAL(
    s_expected_final_chunk_signature,
    "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9");

static int s_sigv4_chunked_signing_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_auth_library_init(allocator);

    struct chunked_signing_tester tester;
    AWS_ZERO_STRUCT(tester);
    ASSERT_SUCCESS(s_chunked_signing_tester_init(allocator, &tester));

    /* Sign the base request and check the signature and authorization header */
    ASSERT_SUCCESS(aws_sign_request_aws(
        allocator,
        tester.request_signable,
        (void *)&tester.request_signing_config,
        s_on_request_signing_complete,
        &tester));

    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_request_authorization_header->bytes,
        s_expected_request_authorization_header->len,
        tester.request_authorization_header.buffer,
        tester.request_authorization_header.len);
    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_request_signature->bytes,
        s_expected_request_signature->len,
        tester.last_signature.buffer,
        tester.last_signature.len);

    /* Make and sign the first chunk */
    struct aws_signable *first_chunk_signable =
        aws_signable_new_chunk(allocator, tester.chunk1_stream, aws_byte_cursor_from_buf(&tester.last_signature));
    ASSERT_SUCCESS(aws_sign_request_aws(
        allocator, first_chunk_signable, (void *)&tester.chunk_signing_config, s_on_chunk_signing_complete, &tester));
    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_first_chunk_signature->bytes,
        s_expected_first_chunk_signature->len,
        tester.last_signature.buffer,
        tester.last_signature.len);
    aws_signable_destroy(first_chunk_signable);

    /* Make and sign the second chunk */
    struct aws_signable *second_chunk_signable =
        aws_signable_new_chunk(allocator, tester.chunk2_stream, aws_byte_cursor_from_buf(&tester.last_signature));
    ASSERT_SUCCESS(aws_sign_request_aws(
        allocator, second_chunk_signable, (void *)&tester.chunk_signing_config, s_on_chunk_signing_complete, &tester));
    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_second_chunk_signature->bytes,
        s_expected_second_chunk_signature->len,
        tester.last_signature.buffer,
        tester.last_signature.len);
    aws_signable_destroy(second_chunk_signable);

    /* Make and sign the final, empty chunk */
    struct aws_signable *final_chunk_signable =
        aws_signable_new_chunk(allocator, NULL, aws_byte_cursor_from_buf(&tester.last_signature));
    ASSERT_SUCCESS(aws_sign_request_aws(
        allocator, final_chunk_signable, (void *)&tester.chunk_signing_config, s_on_chunk_signing_complete, &tester));
    ASSERT_BIN_ARRAYS_EQUALS(
        s_expected_final_chunk_signature->bytes,
        s_expected_final_chunk_signature->len,
        tester.last_signature.buffer,
        tester.last_signature.len);
    aws_signable_destroy(final_chunk_signable);

    s_chunked_signing_tester_cleanup(&tester);

    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(sigv4_chunked_signing_test, s_sigv4_chunked_signing_test);
