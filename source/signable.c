/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/signable.h>

#include <aws/common/string.h>

void aws_signable_destroy(struct aws_signable *signable) {
    if (signable == NULL) {
        return;
    }

    if (signable->vtable != NULL) {
        signable->vtable->destroy(signable);
    }
}

int aws_signable_get_property(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_byte_cursor *out_value) {

    AWS_ASSERT(signable && signable->vtable && signable->vtable->get_property);

    return signable->vtable->get_property(signable, name, out_value);
}

int aws_signable_get_property_list(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_array_list **out_property_list) {

    AWS_ASSERT(signable && signable->vtable && signable->vtable->get_property_list);

    return signable->vtable->get_property_list(signable, name, out_property_list);
}

int aws_signable_get_payload_stream(const struct aws_signable *signable, struct aws_input_stream **out_input_stream) {

    AWS_ASSERT(signable && signable->vtable && signable->vtable->get_payload_stream);

    return signable->vtable->get_payload_stream(signable, out_input_stream);
}

AWS_STRING_FROM_LITERAL(g_aws_http_headers_property_list_name, "headers");
AWS_STRING_FROM_LITERAL(g_aws_http_query_params_property_list_name, "params");
AWS_STRING_FROM_LITERAL(g_aws_http_method_property_name, "method");
AWS_STRING_FROM_LITERAL(g_aws_http_uri_property_name, "uri");
AWS_STRING_FROM_LITERAL(g_aws_signature_property_name, "signature");
AWS_STRING_FROM_LITERAL(g_aws_previous_signature_property_name, "previous-signature");
