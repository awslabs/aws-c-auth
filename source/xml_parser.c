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

#include <aws/auth/private/xml_parser.h>

#include <aws/common/array_list.h>

int aws_xml_parser_init(struct aws_xml_parser *parser, struct aws_allocator *allocator, struct aws_byte_cursor *doc) {
    parser->allocator = allocator;
    parser->doc = *doc;
    return AWS_OP_SUCCESS;
}

void aws_xml_parser_clean_up(struct aws_xml_parser *parser) {
    AWS_ZERO_STRUCT(parser);
}

int aws_xml_parser_parse(struct aws_xml_parser *parser, aws_xml_parser_on_node_encountered_fn *on_node_encountered, void *user_data) {
    if (*parser->doc.ptr != '<') {
        return aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
    }

    aws_byte_cursor_advance(&parser->doc, 1);

    /* nobody cares about the preamble */
    uint8_t *location = memchr(parser->doc.ptr, '>', parser->doc.len);

    if (!location) {
        return aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
    }

    size_t advance = location - parser->doc.ptr;
    aws_byte_cursor_advance(&parser->doc, advance);

    uint8_t *next_location = memchr(parser->doc.ptr, '<', parser->doc.len);

    if (!next_location) {
        return AWS_OP_SUCCESS;
    }

    aws_byte_cursor_advance(&parser->doc, next_location - parser->doc.ptr);
    uint8_t *end_location = memchr(parser->doc.ptr, '>', parser->doc.len);

    if (!end_location) {
        return aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
    }

    size_t node_name_len = end_location - next_location;
    aws_byte_cursor_advance(&parser->doc, end_location - parser->doc.ptr + 1);
    struct aws_xml_node root_node = {
            .doc_at_body = parser->doc,
            .name = aws_byte_cursor_from_array(next_location + 1, node_name_len - 1),
    };

    on_node_encountered(parser, &root_node, user_data);
    return AWS_OP_SUCCESS;
}

int s_advance_to_closing_tag(struct aws_xml_parser *parser, struct aws_xml_node *node, struct aws_byte_cursor *out_body) {
    uint8_t name_close[260] = {0};

    struct aws_byte_buf cmp_buf = aws_byte_buf_from_empty_array(name_close, sizeof(name_close));

    size_t closing_name_len = node->name.len + 4;

    if (closing_name_len > node->doc_at_body.len) {
        return aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
    }

    if (sizeof(name_close) < node->name.len) {
        return aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
    }

    struct aws_byte_cursor open_bracket = aws_byte_cursor_from_c_str("</");
    struct aws_byte_cursor close_bracket = aws_byte_cursor_from_c_str(">");
    struct aws_byte_cursor null_term = aws_byte_cursor_from_array("\0", 1);

    aws_byte_buf_append(&cmp_buf, &open_bracket);
    aws_byte_buf_append(&cmp_buf, &node->name);
    aws_byte_buf_append(&cmp_buf, &close_bracket);
    aws_byte_buf_append(&cmp_buf, &null_term);

    uint8_t *end_tag_location = (uint8_t *)strstr((const char *)node->doc_at_body.ptr, (const char *)cmp_buf.buffer);

    if (!end_tag_location) {
        return aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
    }

    size_t len = end_tag_location - node->doc_at_body.ptr;
    aws_byte_cursor_advance(&parser->doc, len + cmp_buf.len);

    if (out_body) {
        *out_body = aws_byte_cursor_from_array(node->doc_at_body.ptr, len);
    }
    return AWS_OP_SUCCESS;
}

int aws_xml_node_as_body(struct aws_xml_parser *parser, struct aws_xml_node *node, struct aws_byte_cursor *out_body) {
    return s_advance_to_closing_tag(parser, node, out_body);
}

int aws_xml_node_traverse(struct aws_xml_parser *parser, struct aws_xml_node *node, aws_xml_parser_on_node_encountered_fn *on_node_encountered, void *user_data) {
    uint8_t *next_location = memchr(parser->doc.ptr, '<', parser->doc.len);

    if (!next_location) {
        return aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
    }

    uint8_t *end_location = memchr(parser->doc.ptr, '>', parser->doc.len);

    if (!end_location) {
        return aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
    }

    size_t node_name_len = end_location - next_location;
    aws_byte_cursor_advance(&parser->doc, end_location - parser->doc.ptr + 1);
    struct aws_xml_node next_node = {
            .doc_at_body = parser->doc,
            .name = aws_byte_cursor_from_array(next_location + 1, node_name_len - 1),
    };

    on_node_encountered(parser, &next_node, user_data);
    return s_advance_to_closing_tag(parser, node, NULL);
}


