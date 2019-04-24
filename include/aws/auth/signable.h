#ifndef AWS_AUTH_SIGNABLE_H
#define AWS_AUTH_SIGNABLE_H

#include <aws/auth/auth.h>

struct aws_signable;
struct aws_input_stream;
struct aws_http_request_options;

/*
 * While not referenced directly in this file, this is the structure expected to be in the metadata lists
 */
struct aws_signable_metadata_list_pair {
    struct aws_byte_cursor name;
    struct aws_byte_cursor value;
};

typedef int (aws_signable_get_metadata_fn)(struct aws_signable *signable, const struct aws_byte_cursor *name, struct aws_byte_cursor *out_value);
typedef int (aws_signable_get_metadata_list_fn)(struct aws_signable *signable, const struct aws_byte_cursor *name, struct aws_array_list **out_list);
typedef int (aws_signable_get_payload_stream_fn)(struct aws_signable *signable, struct aws_input_stream **out_input_stream);
typedef void (aws_signable_clean_up_fn)(struct aws_signable *signable);

struct aws_signable_vtable {
    aws_signable_get_metadata_fn *get_metadata;
    aws_signable_get_metadata_list_fn *get_metadata_list;
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

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNABLE_H */
