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

#include <aws/auth/private/key_derivation.h>

#include <aws/auth/credentials.h>
#include <aws/auth/private/aws_signing.h>
#include <aws/cal/ecc.h>
#include <aws/cal/hash.h>
#include <aws/cal/hmac.h>
#include <aws/common/byte_buf.h>
#include <aws/common/string.h>

#define SIGV4A_FIXED_INPUT_SIZE_OVERESTIMATE 256
#define SECRET_BUFFER_LENGTH_OVERESTIMATE 64
#define NUM_KEY_BITS 256

/*
 * Not really in the spec but it's what the server implementation did and the probability that this value ever
 * gets reached is absurdly low.
 */
#define MAX_KEY_DERIVATION_COUNTER_VALUE 254

/*
 * These values are defined as 0x01 and 0x0100 in the spec, but the service-side key derivation library makes
 * these 32 bits, so we match that here.
 */
AWS_STATIC_STRING_FROM_LITERAL(s_1_as_four_bytes_be, "\x00\x00\x00\x01");
AWS_STATIC_STRING_FROM_LITERAL(s_256_as_four_bytes_be, "\x00\x00\x01\x00");

AWS_STRING_FROM_LITERAL(g_signature_type_sigv4a_http_request, "AWS4-ECDSA-P256-SHA256");

static int s_aws_build_fixed_input_buffer(
    struct aws_byte_buf *fixed_input,
    struct aws_credentials *credentials,
    uint8_t counter) {

    if (counter == 0 || counter > MAX_KEY_DERIVATION_COUNTER_VALUE) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (!aws_byte_buf_is_valid(fixed_input)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    aws_byte_buf_reset(fixed_input, false);

    /*
     * A placeholder value that's not actually part of the fixed input string in the spec, but is always this value
     * and is always the first byte of the hmac-ed string.
     */
    struct aws_byte_cursor one_cursor = aws_byte_cursor_from_string(s_1_as_four_bytes_be);
    if (aws_byte_buf_append_dynamic(fixed_input, &one_cursor)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor sigv4a_algorithm_cursor = aws_byte_cursor_from_string(g_signature_type_sigv4a_http_request);
    if (aws_byte_buf_append(fixed_input, &sigv4a_algorithm_cursor)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append_byte_dynamic(fixed_input, 0)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor access_key_cursor = aws_credentials_get_access_key_id(credentials);
    if (aws_byte_buf_append(fixed_input, &access_key_cursor)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_append_byte_dynamic(fixed_input, counter)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor encoded_bit_length_cursor = aws_byte_cursor_from_string(s_256_as_four_bytes_be);
    if (aws_byte_buf_append_dynamic(fixed_input, &encoded_bit_length_cursor)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * A pair of constant-time arithmetic functions that operate on raw bytes as if they were unbounded integers in
 * a big-endian base 255 format.
 */

/*
 * In the following function gt and eq are updated in little "blocks".  After each block update, the variables will be
 * in one of the following states:
 *
 *  (1) gt is 0, eq is 1, and from an ordering perspective, lhs == rhs, as checked "so far"
 *  (2) gt is 1, eq is 0, (lhs > rhs)
 *  (3) gt is 0, eq is 0, (lhs < rhs)
 *
 *  States (2) and (3) are terminal states that cannot be exited since eq is 0 and is the and-wise mask of all
 *  subsequent gt updates.  Similarly, once eq is zero it cannot ever become non-zero.
 *
 *  Intuitively these ideas match the standard way of comparing magnitude equality by considering digit count and
 *  digits from most significant to least significant.
 *
 *  Let l and r be the the two digits that we are
 *  comparing between lhs and rhs.  Assume l and r are both non-negative and can each be represented
 *  by an int32:
 *
 *  gt is maintained by the following bit trick:
 *
 *      l > r <=>
 *      (r - l) < 0 <=>
 *      (r - l) as an int32 has the high bit set <=>
 *      ((r - l) >> 31) & 0x01 == 1
 *
 *  eq is maintained by the following bit trick:
 *
 *      l == r <=>
 *      l ^ r == 0 <=>
 *      (l ^ r) - 1 == -1 <=>
 *      (((l ^ r) - 1) >> 31) & 0x01 == 1   // only true if l and r are < (1U << 31)
 *
 *      I found this last step confusing and a little uncomfortable.  Everywhere else we naturally think of l and
 *      r as arbitrary, but here there's a bound as to under what conditions that last equivalence holds.
 *
 */

/**
 * Compares two large unsigned integers in a raw byte format.
 * The two operands *must* be the same size (simplifies the problem significantly)
 * Returns -1, 0, 1 for less-than, equal, or greater-than respectively.
 */
int aws_be_bytes_compare(
    const struct aws_byte_buf *raw_be_bigint_lhs,
    const struct aws_byte_buf *raw_be_bigint_rhs,
    int *comparison_result) {
    /*
     * We only need to support comparing byte sequences of the same length here
     */
    size_t lhs_len = raw_be_bigint_lhs->len;
    if (lhs_len != raw_be_bigint_rhs->len) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    volatile uint8_t gt = 0;
    volatile uint8_t eq = 1;

    const uint8_t *raw_lhs_bytes = raw_be_bigint_lhs->buffer;
    const uint8_t *raw_rhs_bytes = raw_be_bigint_rhs->buffer;
    for (size_t i = 0; i < lhs_len; ++i) {
        volatile int32_t lhs_digit = (int32_t)raw_lhs_bytes[i];
        volatile int32_t rhs_digit = (int32_t)raw_rhs_bytes[i];

        /*
         * For each digit, check for a state (1) => (2) ie lhs > rhs, or (1) => (3) ie lhs < rhs transition
         * based on comparing the two digits in constant time using the ideas explained in the giant comment
         * block above this function.
         */
        gt |= ((rhs_digit - lhs_digit) >> 31) & eq;
        eq &= (((lhs_digit ^ rhs_digit) - 1) >> 31) & 0x01;
    }

    *comparison_result = gt + gt + eq - 1;

    return AWS_OP_SUCCESS;
}

/**
 * Adds one to a large unsigned integer represented by a sequence of bytes.
 */
void aws_be_bytes_add_one(struct aws_byte_buf *raw_be_bigint) {
    size_t byte_count = raw_be_bigint->len;

    volatile uint32_t carry = 1;
    uint8_t *raw_bytes = raw_be_bigint->buffer;

    for (size_t i = 0; i < byte_count; ++i) {
        size_t index = byte_count - i - 1;

        volatile uint32_t current_digit = raw_bytes[index];
        current_digit += carry;

        volatile uint8_t final_digit = (current_digit & 0xFF);
        carry = (current_digit >> 8) & 0x01;

        raw_bytes[index] = final_digit;
    }
}

/* clang-format off */

/* In the spec, this is N-1 */
static uint8_t s_n_minus_1[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
};

/* clang-format on */

enum aws_key_derivation_result {
    AKDR_SUCCESS,
    AKDR_NEXT_COUNTER,
    AKDR_FAILURE,
};

static enum aws_key_derivation_result s_aws_derive_ecc_private_key(
    struct aws_byte_buf *private_key_value,
    struct aws_byte_buf *k0) {
    AWS_FATAL_ASSERT(k0->len == NUM_KEY_BITS / 8);

    aws_byte_buf_reset(private_key_value, false);

    struct aws_byte_buf s_n_minus_1_buf = {
        .allocator = NULL,
        .buffer = s_n_minus_1,
        .capacity = AWS_ARRAY_SIZE(s_n_minus_1),
        .len = AWS_ARRAY_SIZE(s_n_minus_1),
    };

    int comparison_result = 0;
    if (aws_be_bytes_compare(k0, &s_n_minus_1_buf, &comparison_result)) {
        return AKDR_FAILURE;
    }

    if (comparison_result >= 0) {
        return AKDR_NEXT_COUNTER;
    }

    struct aws_byte_cursor k0_cursor = aws_byte_cursor_from_buf(k0);
    if (aws_byte_buf_append(private_key_value, &k0_cursor)) {
        return AKDR_FAILURE;
    }

    aws_be_bytes_add_one(private_key_value);

    return AKDR_SUCCESS;
}

static int s_init_secret_buf(
    struct aws_byte_buf *secret_buf,
    struct aws_allocator *allocator,
    struct aws_credentials *credentials) {
    if (aws_byte_buf_init(secret_buf, allocator, SECRET_BUFFER_LENGTH_OVERESTIMATE)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor prefix_cursor = aws_byte_cursor_from_c_str("AWS4A");
    if (aws_byte_buf_append_dynamic(secret_buf, &prefix_cursor)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor secret_access_key_cursor = aws_credentials_get_secret_access_key(credentials);
    if (aws_byte_buf_append_dynamic(secret_buf, &secret_access_key_cursor)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_ecdsa_p256_key_from_aws_credentials(
    struct aws_allocator *allocator,
    struct aws_credentials *credentials) {

    if (allocator == NULL || credentials == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_ecc_key_pair *ecc_key_pair = NULL;

    struct aws_byte_buf fixed_input;
    AWS_ZERO_STRUCT(fixed_input);

    struct aws_byte_buf fixed_input_hash_digest;
    AWS_ZERO_STRUCT(fixed_input_hash_digest);

    struct aws_byte_buf private_key_buf;
    AWS_ZERO_STRUCT(private_key_buf);

    struct aws_byte_buf secret_buf;
    AWS_ZERO_STRUCT(secret_buf);

    if (aws_byte_buf_init(&fixed_input, allocator, SIGV4A_FIXED_INPUT_SIZE_OVERESTIMATE)) {
        goto done;
    }

    if (aws_byte_buf_init(&fixed_input_hash_digest, allocator, AWS_SHA256_LEN)) {
        goto done;
    }

    size_t key_length = aws_ecc_key_coordinate_byte_size_from_curve_name(AWS_CAL_ECDSA_P256);
    AWS_FATAL_ASSERT(key_length * 8 == NUM_KEY_BITS);
    if (aws_byte_buf_init(&private_key_buf, allocator, key_length)) {
        goto done;
    }

    if (s_init_secret_buf(&secret_buf, allocator, credentials)) {
        goto done;
    }
    struct aws_byte_cursor secret_cursor = aws_byte_cursor_from_buf(&secret_buf);

    uint32_t counter = 1;
    enum aws_key_derivation_result result = AKDR_NEXT_COUNTER;
    while (result == AKDR_NEXT_COUNTER && counter <= MAX_KEY_DERIVATION_COUNTER_VALUE) {
        if (s_aws_build_fixed_input_buffer(&fixed_input, credentials, counter++)) {
            break;
        }

        aws_byte_buf_reset(&fixed_input_hash_digest, true);

        struct aws_byte_cursor fixed_input_cursor = aws_byte_cursor_from_buf(&fixed_input);
        if (aws_sha256_hmac_compute(allocator, &secret_cursor, &fixed_input_cursor, &fixed_input_hash_digest, 0)) {
            break;
        }

        result = s_aws_derive_ecc_private_key(&private_key_buf, &fixed_input_hash_digest);
    }

    if (result == AKDR_SUCCESS) {
        struct aws_byte_cursor private_key_cursor = aws_byte_cursor_from_buf(&private_key_buf);
        ecc_key_pair = aws_ecc_key_pair_new_from_private_key(allocator, AWS_CAL_ECDSA_P256, &private_key_cursor);
    }

done:

    aws_byte_buf_clean_up_secure(&secret_buf);
    aws_byte_buf_clean_up(&private_key_buf);
    aws_byte_buf_clean_up(&fixed_input_hash_digest);
    aws_byte_buf_clean_up(&fixed_input);

    return ecc_key_pair;
}
