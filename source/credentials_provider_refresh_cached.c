/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/*
 * Refresh cache, used by aws_credentials_provider_new_cached for refreshable sources. It keeps credentials after a
 * failed refresh, backs off between failed refreshes, caches non-recoverable errors briefly and supports invalidate.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/device_random.h>
#include <aws/common/math.h>
#include <aws/common/mutex.h>

#include <inttypes.h>

/* Advisory refresh window, chosen from the lifetime of the credentials when they arrive */
/* No provider has its own earlier schedule, so IMDS uses these too: 60 min for its 6 h credentials */
#define REFRESH_ADVISORY_SHORT_LIFETIME_SECS (20 * 60)
#define REFRESH_ADVISORY_MEDIUM_LIFETIME_SECS (90 * 60)
#define REFRESH_ADVISORY_SHORT_WINDOW_SECS (5 * 60)
#define REFRESH_ADVISORY_MEDIUM_WINDOW_SECS (15 * 60)
#define REFRESH_ADVISORY_LONG_WINDOW_SECS (60 * 60)

/* Mandatory refresh window: every request waits for a refresh this close to expiration */
#define REFRESH_MANDATORY_WINDOW_SECS 60

/* Backoff after a failed refresh: uniform(min, max(floor, min(remaining / 2, cap))) */
#define REFRESH_BACKOFF_MIN_SECS 60
#define REFRESH_BACKOFF_UPPER_FLOOR_SECS 90
#define REFRESH_BACKOFF_UPPER_CAP_SECS 600

/* How long a non-recoverable error is returned without calling the source */
#define NON_RECOVERABLE_ERROR_CACHE_MIN_SECS 1
#define NON_RECOVERABLE_ERROR_CACHE_MAX_SECS 5

struct aws_credentials_provider_refresh_cached {
    struct aws_credentials_provider *source;
    aws_io_clock_fn *high_res_clock_fn;
    aws_io_clock_fn *system_clock_fn;

    struct aws_mutex lock;

    /* Everything below is guarded by lock */
    struct aws_credentials *cached_credentials;

    /* System time in ns. Our own copy, so invalidate can change it without touching the shared credentials. */
    uint64_t expiration_ns;

    /* Fixed for the cached credentials until a successful refresh */
    uint64_t advisory_window_ns;

    /* High-res time in ns before which the source is not called. 0 when not rate-limited. */
    uint64_t next_refresh_allowed_ns;

    int cached_error_code;
    uint64_t cached_error_expires_ns;

    /* Set by invalidate, cleared when new credentials are cached */
    bool invalidated;

    bool refresh_in_flight;
    struct aws_linked_list pending_queries;
};

static uint64_t s_uniform_random_ns(uint64_t min_ns, uint64_t max_ns) {
    uint64_t random_value = 0;
    if (max_ns <= min_ns || aws_device_random_u64(&random_value)) {
        return min_ns;
    }

    uint64_t range_ns = aws_add_u64_saturating(aws_sub_u64_saturating(max_ns, min_ns), 1);
    return aws_add_u64_saturating(min_ns, random_value % range_ns);
}

static uint64_t s_get_expiration_ns(const struct aws_credentials *credentials) {
    /* No expiration (UINT64_MAX) stays UINT64_MAX */
    return aws_timestamp_convert(
        aws_credentials_get_expiration_timepoint_seconds(credentials), AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
}

static uint64_t s_advisory_window_ns(uint64_t lifetime_ns) {
    uint64_t window_secs = REFRESH_ADVISORY_LONG_WINDOW_SECS;
    if (lifetime_ns <=
        aws_timestamp_convert(REFRESH_ADVISORY_SHORT_LIFETIME_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL)) {
        window_secs = REFRESH_ADVISORY_SHORT_WINDOW_SECS;
    } else if (
        lifetime_ns <
        aws_timestamp_convert(REFRESH_ADVISORY_MEDIUM_LIFETIME_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL)) {
        window_secs = REFRESH_ADVISORY_MEDIUM_WINDOW_SECS;
    }

    return aws_timestamp_convert(window_secs, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
}

/* True once the cached credentials are in the advisory window, the mandatory window or expired */
static bool s_refresh_needed(const struct aws_credentials_provider_refresh_cached *impl, uint64_t system_now_ns) {
    return aws_sub_u64_saturating(impl->expiration_ns, system_now_ns) < impl->advisory_window_ns;
}

/* True while the backoff after a failed refresh has not elapsed */
static bool s_refresh_rate_limited(const struct aws_credentials_provider_refresh_cached *impl, uint64_t now_ns) {
    return impl->next_refresh_allowed_ns != 0 && now_ns < impl->next_refresh_allowed_ns;
}

/* True once the cached credentials are in the mandatory window or expired */
static bool s_mandatory_refresh_needed(
    const struct aws_credentials_provider_refresh_cached *impl,
    uint64_t system_now_ns) {
    uint64_t mandatory_window_ns =
        aws_timestamp_convert(REFRESH_MANDATORY_WINDOW_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    return aws_sub_u64_saturating(impl->expiration_ns, system_now_ns) < mandatory_window_ns;
}

/* True while a non-recoverable error is still cached */
static bool s_non_recoverable_error_cached(
    const struct aws_credentials_provider_refresh_cached *impl,
    uint64_t now_ns) {
    return impl->cached_error_code != AWS_ERROR_SUCCESS && now_ns < impl->cached_error_expires_ns;
}

static uint64_t s_refresh_backoff_ns(
    const struct aws_credentials_provider_refresh_cached *impl,
    uint64_t system_now_ns) {

    uint64_t remaining_ns = aws_sub_u64_saturating(impl->expiration_ns, system_now_ns);
    uint64_t min_ns = aws_timestamp_convert(REFRESH_BACKOFF_MIN_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    uint64_t floor_ns =
        aws_timestamp_convert(REFRESH_BACKOFF_UPPER_FLOOR_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    uint64_t cap_ns =
        aws_timestamp_convert(REFRESH_BACKOFF_UPPER_CAP_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

    uint64_t upper_ns = aws_max_u64(floor_ns, aws_min_u64(remaining_ns / 2, cap_ns));
    return s_uniform_random_ns(min_ns, upper_ns);
}

static void s_cache_credentials(
    struct aws_credentials_provider *provider,
    struct aws_credentials *credentials,
    uint64_t system_now_ns) {

    struct aws_credentials_provider_refresh_cached *impl = provider->impl;

    aws_credentials_acquire(credentials);
    aws_credentials_release(impl->cached_credentials);
    impl->cached_credentials = credentials;

    impl->expiration_ns = s_get_expiration_ns(credentials);
    impl->advisory_window_ns = s_advisory_window_ns(aws_sub_u64_saturating(impl->expiration_ns, system_now_ns));
    impl->next_refresh_allowed_ns = 0;
    impl->cached_error_code = AWS_ERROR_SUCCESS;
    impl->cached_error_expires_ns = 0;
    impl->invalidated = false;

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Refresh cached credentials provider cached new credentials, expiration %" PRIu64
        " ns, advisory refresh window %" PRIu64 " ns",
        (void *)provider,
        impl->expiration_ns,
        impl->advisory_window_ns);
}

static void s_apply_refresh_backoff(
    struct aws_credentials_provider *provider,
    const char *reason,
    uint64_t system_now_ns,
    uint64_t now_ns) {

    struct aws_credentials_provider_refresh_cached *impl = provider->impl;

    uint64_t backoff_ns = s_refresh_backoff_ns(impl, system_now_ns);
    impl->next_refresh_allowed_ns = aws_add_u64_saturating(now_ns, backoff_ns);

    AWS_LOGF_WARN(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Credential refresh failed: %s. The SDK will continue using cached credentials. A refresh of these "
        "credentials will be attempted again after %" PRIu64 " seconds.",
        (void *)provider,
        reason,
        aws_timestamp_convert(backoff_ns, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_SECS, NULL));
}

static void s_cache_non_recoverable_error(struct aws_credentials_provider *provider, int error_code, uint64_t now_ns) {
    struct aws_credentials_provider_refresh_cached *impl = provider->impl;

    uint64_t cache_duration_ns = s_uniform_random_ns(
        aws_timestamp_convert(NON_RECOVERABLE_ERROR_CACHE_MIN_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL),
        aws_timestamp_convert(NON_RECOVERABLE_ERROR_CACHE_MAX_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));
    impl->cached_error_code = error_code;
    impl->cached_error_expires_ns = aws_add_u64_saturating(now_ns, cache_duration_ns);

    AWS_LOGF_ERROR(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Credential source returned non-recoverable error %d(%s), caching it for %" PRIu64 " ms",
        (void *)provider,
        error_code,
        aws_error_str(error_code),
        aws_timestamp_convert(cache_duration_ns, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_MILLIS, NULL));
}

static bool s_has_same_access_key_id(const struct aws_credentials *a, const struct aws_credentials *b) {
    struct aws_byte_cursor a_access_key_id = aws_credentials_get_access_key_id(a);
    struct aws_byte_cursor b_access_key_id = aws_credentials_get_access_key_id(b);
    return a_access_key_id.len > 0 && aws_byte_cursor_eq(&a_access_key_id, &b_access_key_id);
}

/* Handles the answer of one source call; every waiting request gets the same result */
static void s_on_credential_source_result(struct aws_credentials *credentials, int error_code, void *user_data) {
    struct aws_credentials_provider *provider = user_data;
    struct aws_credentials_provider_refresh_cached *impl = provider->impl;

    uint64_t system_now_ns = 0;
    impl->system_clock_fn(&system_now_ns);
    uint64_t now_ns = 0;
    impl->high_res_clock_fn(&now_ns);

    if (credentials == NULL && error_code == AWS_ERROR_SUCCESS) {
        error_code = AWS_ERROR_UNKNOWN;
    }

    struct aws_credentials *result_credentials = NULL;
    int result_error_code = AWS_ERROR_SUCCESS;

    struct aws_linked_list pending_queries;
    aws_linked_list_init(&pending_queries);

    aws_mutex_lock(&impl->lock);

    aws_linked_list_swap_contents(&pending_queries, &impl->pending_queries);
    impl->refresh_in_flight = false;

    if (credentials != NULL) {
        bool cached_new_credentials = false;
        if (impl->cached_credentials == NULL) {
            /* Initial fetch: cache the credentials even if they are already expired */
            s_cache_credentials(provider, credentials, system_now_ns);
            cached_new_credentials = true;
        } else if (aws_sub_u64_saturating(s_get_expiration_ns(credentials), system_now_ns) == 0) {
            s_apply_refresh_backoff(
                provider, "the credential source returned expired credentials", system_now_ns, now_ns);
        } else if (impl->invalidated && s_has_same_access_key_id(impl->cached_credentials, credentials)) {
            s_apply_refresh_backoff(
                provider, "the credential source returned the rejected credentials", system_now_ns, now_ns);
        } else {
            s_cache_credentials(provider, credentials, system_now_ns);
            cached_new_credentials = true;
        }

        /* Credentials already inside their refresh window would make every request refresh again, so wait one
         * backoff first, ending no later than the mandatory window. Credentials already in the mandatory window or
         * expired get no wait, so the next request takes the mandatory refresh */
        if (cached_new_credentials && !s_mandatory_refresh_needed(impl, system_now_ns) &&
            s_refresh_needed(impl, system_now_ns)) {
            uint64_t mandatory_window_ns =
                aws_timestamp_convert(REFRESH_MANDATORY_WINDOW_SECS, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
            uint64_t until_mandatory_ns =
                aws_sub_u64_saturating(aws_sub_u64_saturating(impl->expiration_ns, system_now_ns), mandatory_window_ns);
            uint64_t backoff_ns = aws_min_u64(s_refresh_backoff_ns(impl, system_now_ns), until_mandatory_ns);
            impl->next_refresh_allowed_ns = aws_add_u64_saturating(now_ns, backoff_ns);
            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Credential source returned credentials already inside their refresh window; the next "
                "refresh is attempted after %" PRIu64 " seconds.",
                (void *)provider,
                aws_timestamp_convert(backoff_ns, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_SECS, NULL));
        }

        result_credentials = impl->cached_credentials;
        aws_credentials_acquire(result_credentials);

    } else if (aws_credentials_provider_is_non_recoverable_error(error_code)) {
        /* No backoff: the error is returned even if the cached credentials are still valid */
        s_cache_non_recoverable_error(provider, error_code, now_ns);
        result_error_code = error_code;

    } else if (impl->cached_credentials != NULL) {
        s_apply_refresh_backoff(provider, aws_error_str(error_code), system_now_ns, now_ns);
        result_credentials = impl->cached_credentials;
        aws_credentials_acquire(result_credentials);

    } else {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Refresh cached credentials provider failed the initial fetch with error %d(%s)",
            (void *)provider,
            error_code,
            aws_error_str(error_code));
        /* Return the source error; a chain or signing reports it as no credentials */
        result_error_code = error_code;
    }

    aws_mutex_unlock(&impl->lock);

    aws_credentials_query_list_notify_and_clean_up(
        &pending_queries, provider->allocator, result_credentials, result_error_code);
    aws_credentials_release(result_credentials);

    /* Taken in s_call_credential_source */
    aws_credentials_provider_release(provider);
}

static void s_call_credential_source(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_refresh_cached *impl = provider->impl;

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Refresh cached credentials provider calling its credential source",
        (void *)provider);

    /* Keeps the cache alive until the source answers */
    aws_credentials_provider_acquire(provider);

    if (aws_credentials_provider_get_credentials(impl->source, s_on_credential_source_result, provider)) {
        s_on_credential_source_result(NULL, aws_last_error(), provider);
    }
}

static int s_refresh_cached_get_credentials(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_refresh_cached *impl = provider->impl;

    uint64_t system_now_ns = 0;
    impl->system_clock_fn(&system_now_ns);
    uint64_t now_ns = 0;
    impl->high_res_clock_fn(&now_ns);

    struct aws_credentials *credentials = NULL;
    int error_code = AWS_ERROR_SUCCESS;
    bool wait_for_refresh = false;
    bool call_source = false;

    aws_mutex_lock(&impl->lock);

    if (impl->cached_credentials == NULL) {
        /* State 1: no credentials. Wait for the initial fetch unless a non-recoverable error is cached. */
        if (s_non_recoverable_error_cached(impl, now_ns)) {
            error_code = impl->cached_error_code;
        } else {
            wait_for_refresh = true;
        }

    } else if (!s_refresh_needed(impl, system_now_ns) || s_refresh_rate_limited(impl, now_ns)) {
        /* State 2, or backing off after a failed refresh */
        credentials = impl->cached_credentials;
        aws_credentials_acquire(credentials);

    } else if (!s_mandatory_refresh_needed(impl, system_now_ns)) {
        /* State 3: advisory refresh. Others get the cached credentials while a refresh is in flight. */
        if (impl->refresh_in_flight) {
            credentials = impl->cached_credentials;
            aws_credentials_acquire(credentials);
        } else if (s_non_recoverable_error_cached(impl, now_ns)) {
            error_code = impl->cached_error_code;
        } else {
            wait_for_refresh = true;
        }

    } else {
        /* States 4 and 5: mandatory refresh or expired. Every request waits for one refresh. */
        if (!impl->refresh_in_flight && s_non_recoverable_error_cached(impl, now_ns)) {
            error_code = impl->cached_error_code;
        } else {
            wait_for_refresh = true;
        }
    }

    if (wait_for_refresh) {
        struct aws_credentials_query *query =
            aws_mem_calloc(provider->allocator, 1, sizeof(struct aws_credentials_query));
        aws_credentials_query_init(query, provider, callback, user_data);
        aws_linked_list_push_back(&impl->pending_queries, &query->node);

        if (!impl->refresh_in_flight) {
            impl->refresh_in_flight = true;
            call_source = true;
        }
    }

    aws_mutex_unlock(&impl->lock);

    if (call_source) {
        s_call_credential_source(provider);
    } else if (!wait_for_refresh) {
        callback(credentials, error_code, user_data);
        aws_credentials_release(credentials);
    }

    return AWS_OP_SUCCESS;
}

static int s_refresh_cached_invalidate(
    struct aws_credentials_provider *provider,
    const struct aws_credentials *rejected_credentials) {

    struct aws_credentials_provider_refresh_cached *impl = provider->impl;

    uint64_t system_now_ns = 0;
    impl->system_clock_fn(&system_now_ns);

    aws_mutex_lock(&impl->lock);

    /* A refresh in flight will replace the credentials anyway */
    if (impl->refresh_in_flight || impl->cached_credentials == NULL) {
        aws_mutex_unlock(&impl->lock);
        return AWS_OP_SUCCESS;
    }

    if (s_has_same_access_key_id(impl->cached_credentials, rejected_credentials)) {
        /* The backoff and the cached credentials are kept; the next request takes the mandatory path */
        impl->expiration_ns = system_now_ns;
        impl->invalidated = true;
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Refresh cached credentials provider invalidated credentials rejected by a service",
            (void *)provider);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Refresh cached credentials provider ignored invalidate for credentials it no longer holds",
            (void *)provider);
    }

    aws_mutex_unlock(&impl->lock);

    return AWS_OP_SUCCESS;
}

static void s_refresh_cached_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_refresh_cached *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_credentials_provider_release(impl->source);

    aws_credentials_provider_invoke_shutdown_callback(provider);

    aws_credentials_release(impl->cached_credentials);

    aws_mutex_clean_up(&impl->lock);

    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_refresh_cached_vtable = {
    .get_credentials = s_refresh_cached_get_credentials,
    .destroy = s_refresh_cached_destroy,
    .invalidate = s_refresh_cached_invalidate,
};

struct aws_credentials_provider *aws_credentials_provider_new_refresh_cached(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_cached_options *options) {

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_refresh_cached *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_refresh_cached));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    aws_credentials_provider_init_base(provider, allocator, &s_aws_credentials_provider_refresh_cached_vtable, impl);

    if (aws_mutex_init(&impl->lock)) {
        aws_mem_release(allocator, provider);
        return NULL;
    }

    aws_linked_list_init(&impl->pending_queries);

    impl->source = aws_credentials_provider_acquire(options->source);
    impl->high_res_clock_fn =
        options->high_res_clock_fn != NULL ? options->high_res_clock_fn : &aws_high_res_clock_get_ticks;
    impl->system_clock_fn = options->system_clock_fn != NULL ? options->system_clock_fn : &aws_sys_clock_get_ticks;

    provider->shutdown_options = options->shutdown_options;

    if (options->refresh_time_in_milliseconds > 0) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Refresh cached credentials provider ignores refresh time of %" PRIu64
            " ms; refresh timing follows the credentials' expiration",
            (void *)provider,
            options->refresh_time_in_milliseconds);
    }

    return provider;
}

bool aws_credentials_provider_is_refresh_cached(const struct aws_credentials_provider *provider) {
    return provider->vtable == &s_aws_credentials_provider_refresh_cached_vtable;
}
