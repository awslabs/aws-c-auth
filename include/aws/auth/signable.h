#ifndef AWS_AUTH_SIGNABLE_H
#define AWS_AUTH_SIGNABLE_H

#include <aws/auth/auth.h>

struct aws_http_message;
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

/**
 * Signable is a generic interface for any kind of object that can be cryptographically signed.
 *
 * Like signing_result, the signable interface presents
 *
 *   (1) Properties - A set of key-value pairs
 *   (2) Property Lists - A set of named key-value pair lists
 *
 * as well as
 *
 *   (3) A message payload modeled as a stream
 *
 * When creating a signable "subclass" the query interface should map to retrieving
 * the properties of the underlying object needed by signing algorithms that can operate on it.
 *
 * As an example, if a signable implementation wrapped an http request, you would query
 * request elements like method and uri from the property interface, headers would be queried
 * via the property list interface, and the request body would map to the payload stream.
 *
 * String constants that map to agreed on keys for particular signable types
 * ("METHOD", "URI", "HEADERS", etc...) are exposed in appropriate header files.
 */
struct aws_signable {
    struct aws_allocator *allocator;
    void *impl;
    struct aws_signable_vtable *vtable;
};

AWS_EXTERN_C_BEGIN

/**
 * Cleans up and frees all resources associated with a signable instance
 */
AWS_AUTH_API
void aws_signable_destroy(struct aws_signable *signable);

/**
 * Retrieves a property (key-value pair) from a signable.  Global property name constants are
 * included below.
 */
AWS_AUTH_API
int aws_signable_get_property(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_byte_cursor *out_value);

/**
 * Retrieves a named property list (list of key-value pairs) from a signable.  Global property list name
 * constants are included below.
 */
AWS_AUTH_API
int aws_signable_get_property_list(
    const struct aws_signable *signable,
    const struct aws_string *name,
    struct aws_array_list **out_property_list);

/**
 * Retrieves the signable's message payload as a stream.
 */
AWS_AUTH_API
int aws_signable_get_payload_stream(const struct aws_signable *signable, struct aws_input_stream **input_stream);

/*
 * Some global property and property-list name constants
 */

/**
 * Name of the property list that wraps the headers of an http request
 */
AWS_AUTH_API extern const struct aws_string *g_aws_http_headers_property_list_name;

/**
 * Name of the property list that wraps the query params of an http request.  Only used by signing_result.
 * For input to a http signing algorithm, query params are assumed to be part of the uri.
 */
AWS_AUTH_API extern const struct aws_string *g_aws_http_query_params_property_list_name;

/**
 * Name of the property that holds the method of an http request
 */
AWS_AUTH_API extern const struct aws_string *g_aws_http_method_property_name;

/**
 * Name of the property that holds the URI of an http request
 */
AWS_AUTH_API extern const struct aws_string *g_aws_http_uri_property_name;

/*
 * Common signable implementations
 */

AWS_AUTH_API
struct aws_signable *aws_signable_new_http_request(struct aws_allocator *allocator, struct aws_http_message *request);

AWS_EXTERN_C_END

#endif /* AWS_AUTH_SIGNABLE_H */
