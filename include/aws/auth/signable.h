#ifndef AWS_AUTH_SIGNABLE_H
#define AWS_AUTH_SIGNABLE_H

#include <aws/auth/auth.h>

struct aws_input_stream;
struct aws_signable;
struct aws_string;

/*
 * While not referenced directly in this file, this is the structure expected to be in the property lists
 */
struct aws_signable_property_list_pair {
    struct aws_byte_cursor name;
    struct aws_byte_cursor value;
};

typedef int(aws_signable_get_property_fn)(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_byte_cursor *out_value);

typedef int(aws_signable_get_property_list_fn)(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_array_list **out_list);

typedef int(aws_signable_get_payload_stream_fn)(
    const struct aws_signable *signable,
    struct aws_input_stream **out_input_stream);

typedef void(aws_signable_clean_up_fn)(struct aws_signable *signable);

struct aws_signable_vtable {
    aws_signable_get_property_fn *get_property;
    aws_signable_get_property_list_fn *get_property_list;
    aws_signable_get_payload_stream_fn *get_payload_stream;
    aws_signable_clean_up_fn *clean_up;
};

struct aws_signable {
    struct aws_allocator *allocator;
    void *impl;
    struct aws_signable_vtable *vtable;
};

AWS_EXTERN_C_BEGIN

AWS_AUTH_API
void aws_signable_destroy(struct aws_signable *signable);

AWS_AUTH_API
int aws_signable_get_property(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_byte_cursor *out_value);

AWS_AUTH_API
int aws_signable_get_property_list(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_array_list **out_property_list);

AWS_AUTH_API
int aws_signable_get_payload_stream(const struct aws_signable *signable, struct aws_input_stream **input_stream);

AWS_AUTH_API extern const struct aws_string *g_aws_http_headers_property_list_name;
AWS_AUTH_API extern const struct aws_string *g_aws_http_query_params_property_list_name;
AWS_AUTH_API extern const struct aws_string *g_aws_http_method_property_name;
AWS_AUTH_API extern const struct aws_string *g_aws_http_uri_property_name;

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNABLE_H */
