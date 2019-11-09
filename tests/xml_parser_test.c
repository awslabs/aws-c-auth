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

#include <aws/testing/aws_test_harness.h>
#include <aws/auth/private/xml_parser.h>

const char root_with_text[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><rootNode>TestBody</rootNode>";

struct root_with_text_capture {
    struct aws_byte_cursor capture;
    struct aws_byte_cursor node_name;
    int error;
};

bool s_root_with_text_root_node(struct aws_xml_parser *parser, struct aws_xml_node *node, void *user_data) {
    struct root_with_text_capture *capture = user_data;
    capture->error = aws_xml_node_as_body(parser, node, &capture->capture);
    capture->node_name = node->name;

    return true;
}

static int s_xml_parser_root_with_text_test(struct aws_allocator *allocator, void *ctx) {

    struct aws_byte_cursor test_doc = aws_byte_cursor_from_array(root_with_text, sizeof(root_with_text));
    struct aws_xml_parser parser;

    ASSERT_SUCCESS(aws_xml_parser_init(&parser, allocator, &test_doc));

    struct root_with_text_capture capture;
    AWS_ZERO_STRUCT(capture);

    ASSERT_SUCCESS(aws_xml_parser_parse(&parser, s_root_with_text_root_node, &capture));

    const char expected_name[] = "rootNode";
    const char expected_value[] = "TestBody";

    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, capture.error);
    ASSERT_BIN_ARRAYS_EQUALS(expected_name, sizeof(expected_name) - 1, capture.node_name.ptr, capture.node_name.len);
    ASSERT_BIN_ARRAYS_EQUALS(expected_value, sizeof(expected_value) - 1, capture.capture.ptr, capture.capture.len);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(xml_parser_root_with_text, s_xml_parser_root_with_text_test)

const char child_with_text[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><rootNode><child1>TestBody</child1></rootNode>";

struct child_text_capture {
    struct aws_byte_cursor capture;
    struct aws_byte_cursor node_name;
    int error;
};

bool s_child_with_text_root_node(struct aws_xml_parser *parser, struct aws_xml_node *node, void *user_data) {
    struct child_text_capture *capture = user_data;
    capture->error |= aws_xml_node_as_body(parser, node, &capture->capture);
    capture->node_name = node->name;

    return true;
}

bool s_root_with_child(struct aws_xml_parser *parser, struct aws_xml_node *node, void *user_data) {
    struct child_text_capture *capture = user_data;
    capture->error |= aws_xml_node_traverse(parser, node, s_child_with_text_root_node, user_data);
    return true;
}

static int s_xml_parser_child_with_text_test(struct aws_allocator *allocator, void *ctx) {

    struct aws_byte_cursor test_doc = aws_byte_cursor_from_array(child_with_text, sizeof(child_with_text));
    struct aws_xml_parser parser;

    ASSERT_SUCCESS(aws_xml_parser_init(&parser, allocator, &test_doc));

    struct root_with_text_capture capture;
    AWS_ZERO_STRUCT(capture);

    ASSERT_SUCCESS(aws_xml_parser_parse(&parser, s_root_with_child, &capture));

    const char expected_name[] = "child1";
    const char expected_value[] = "TestBody";

    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, capture.error);
    ASSERT_BIN_ARRAYS_EQUALS(expected_name, sizeof(expected_name) - 1, capture.node_name.ptr, capture.node_name.len);
    ASSERT_BIN_ARRAYS_EQUALS(expected_value, sizeof(expected_value) - 1, capture.capture.ptr, capture.capture.len);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(xml_parser_child_with_text, s_xml_parser_child_with_text_test)