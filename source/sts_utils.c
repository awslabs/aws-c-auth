/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/private/sts_utils.h>

#include <aws/common/xml_parser.h>

/* STS (AWS Query protocol) error response, also accepting <Error> as the root:
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
    <Error>
        <Type>Sender</Type>
        <Code>AccessDenied</Code>
        <Message>...</Message>
    </Error>
    <RequestId>...</RequestId>
</ErrorResponse>
 * Error codes: https://docs.aws.amazon.com/STS/latest/APIReference/CommonErrors.html
 * Ref:
https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-xml-api-responses.html#sqs-api-error-response-structure
 */
static int s_sts_error_xml_on_Error_child(struct aws_xml_node *node, void *user_data) {
    struct aws_byte_cursor *sts_error_code = user_data;
    struct aws_byte_cursor node_name = aws_xml_node_get_name(node);
    if (aws_byte_cursor_eq_c_str_ignore_case(&node_name, "Code")) {
        return aws_xml_node_as_body(node, sts_error_code);
    }
    return AWS_OP_SUCCESS;
}

static int s_sts_error_xml_on_ErrorResponse_child(struct aws_xml_node *node, void *user_data) {
    struct aws_byte_cursor node_name = aws_xml_node_get_name(node);
    if (aws_byte_cursor_eq_c_str_ignore_case(&node_name, "Error")) {
        return aws_xml_node_traverse(node, s_sts_error_xml_on_Error_child, user_data);
    }
    return AWS_OP_SUCCESS;
}

static int s_sts_error_xml_on_root(struct aws_xml_node *node, void *user_data) {
    struct aws_byte_cursor node_name = aws_xml_node_get_name(node);
    if (aws_byte_cursor_eq_c_str_ignore_case(&node_name, "ErrorResponse")) {
        return aws_xml_node_traverse(node, s_sts_error_xml_on_ErrorResponse_child, user_data);
    }
    if (aws_byte_cursor_eq_c_str_ignore_case(&node_name, "Error")) {
        return aws_xml_node_traverse(node, s_sts_error_xml_on_Error_child, user_data);
    }
    return AWS_OP_SUCCESS;
}

int aws_credentials_provider_parse_sts_error_code(
    struct aws_allocator *allocator,
    struct aws_byte_cursor error_document,
    struct aws_byte_cursor *out_error_code) {

    AWS_ZERO_STRUCT(*out_error_code);

    struct aws_xml_parser_options options = {
        .doc = error_document,
        .on_root_encountered = s_sts_error_xml_on_root,
        .user_data = out_error_code,
    };
    return aws_xml_parse(allocator, &options);
}

bool aws_credentials_provider_is_retryable_sts_web_identity_error_code(struct aws_byte_cursor error_code) {
    static const char *s_retryable_sts_web_identity_error_codes[] = {
        "ExpiredToken",
        "IDPCommunicationError",
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_retryable_sts_web_identity_error_codes); ++i) {
        if (aws_byte_cursor_eq_c_str_ignore_case(&error_code, s_retryable_sts_web_identity_error_codes[i])) {
            return true;
        }
    }

    return false;
}

bool aws_credentials_provider_is_non_recoverable_sts_error_code(struct aws_byte_cursor error_code) {
    static const char *s_non_recoverable_sts_error_codes[] = {
        "AccessDenied",
        "IDPRejectedClaim",
        "InvalidIdentityToken",
        "MalformedPolicyDocument",
        "PackedPolicyTooLarge",
        "RegionDisabledException",
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_non_recoverable_sts_error_codes); ++i) {
        if (aws_byte_cursor_eq_c_str_ignore_case(&error_code, s_non_recoverable_sts_error_codes[i])) {
            return true;
        }
    }

    return false;
}
