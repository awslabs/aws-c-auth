/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/sts_utils.h>

#include <aws/common/xml_parser.h>

/* STS error codes that retrying will not fix, from the Credential Refresh SEP */
static const char *s_non_recoverable_sts_error_codes[] = {
    "AccessDenied",
    "IDPRejectedClaim",
    "InvalidIdentityToken",
    "MalformedPolicyDocument",
    "PackedPolicyTooLarge",
    "RegionDisabledException",
};

static int s_on_error_child(struct aws_xml_node *node, void *user_data) {
    struct aws_byte_cursor *out_error_code = user_data;

    struct aws_byte_cursor node_name = aws_xml_node_get_name(node);
    if (aws_byte_cursor_eq_c_str_ignore_case(&node_name, "Code")) {
        return aws_xml_node_as_body(node, out_error_code);
    }

    return AWS_OP_SUCCESS;
}

/* AssumeRole wraps <Error> in <ErrorResponse>, AssumeRoleWithWebIdentity may not */
static int s_on_error_node(struct aws_xml_node *node, void *user_data) {
    struct aws_byte_cursor node_name = aws_xml_node_get_name(node);
    if (aws_byte_cursor_eq_c_str_ignore_case(&node_name, "ErrorResponse")) {
        return aws_xml_node_traverse(node, s_on_error_node, user_data);
    }
    if (aws_byte_cursor_eq_c_str_ignore_case(&node_name, "Error")) {
        return aws_xml_node_traverse(node, s_on_error_child, user_data);
    }

    return AWS_OP_SUCCESS;
}

int aws_sts_parse_error_code(
    struct aws_allocator *allocator,
    struct aws_byte_cursor error_document,
    struct aws_byte_cursor *out_error_code) {

    AWS_ZERO_STRUCT(*out_error_code);

    struct aws_xml_parser_options options = {
        .doc = error_document,
        .on_root_encountered = s_on_error_node,
        .user_data = out_error_code,
    };

    return aws_xml_parse(allocator, &options);
}

bool aws_sts_is_non_recoverable_error_code(struct aws_byte_cursor error_code) {
    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_non_recoverable_sts_error_codes); ++i) {
        if (aws_byte_cursor_eq_c_str_ignore_case(&error_code, s_non_recoverable_sts_error_codes[i])) {
            return true;
        }
    }

    return false;
}
