#ifndef AWS_AUTH_XML_PARSER
#define AWS_AUTH_XML_PARSER

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

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>

struct aws_xml_attribute {
    struct aws_byte_cursor name;
    struct aws_byte_cursor value;
};

struct aws_xml_node {
    struct aws_byte_cursor name;
    struct aws_array_list attributes;
    struct aws_byte_cursor doc_at_body;
};

struct aws_xml_parser;
typedef bool(
    aws_xml_parser_on_node_encountered_fn)(struct aws_xml_parser *parser, struct aws_xml_node *node, void *user_data);

struct aws_xml_parser {
    struct aws_allocator *allocator;
    struct aws_byte_cursor doc;
    struct aws_array_list cb_stack;
    struct aws_xml_attribute attributes[10];
    struct aws_byte_cursor split_scratch[22];
};

int aws_xml_parser_init(struct aws_xml_parser *parser, struct aws_allocator *allocator, struct aws_byte_cursor *doc);
void aws_xml_parser_clean_up(struct aws_xml_parser *parser);

int aws_xml_parser_parse(
    struct aws_xml_parser *parser,
    aws_xml_parser_on_node_encountered_fn *on_node_encountered,
    void *user_data);
int aws_xml_node_as_body(struct aws_xml_parser *parser, struct aws_xml_node *node, struct aws_byte_cursor *out_body);
int aws_xml_node_traverse(
    struct aws_xml_parser *parser,
    struct aws_xml_node *node,
    aws_xml_parser_on_node_encountered_fn *on_node_encountered,
    void *user_data);

#endif /* AWS_AUTH_XML_PARSER */
