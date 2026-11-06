/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>

#include <aws/auth/private/credentials_utils.h>
#include <aws/common/clock.h>
#include <aws/common/device_random.h>
#include <aws/common/math.h>
#include <aws/common/mutex.h>
#include <aws/common/time.h>

#include <inttypes.h>

/*

 ToDo: credentials expiration environment overrides

AWS_STATIC_STRING_FROM_LITERAL(s_credential_expiration_env_var, "AWS_CREDENTIAL_EXPIRATION");

*/

#define REFRESH_CREDENTIALS_EARLY_DURATION_SECONDS 60 * 5 /* 5 minutes */

/* Values used by the new credential refresh strategy */
#define MANDATORY_REFRESH_WINDOW_SECS 60
#define REFRESH_BACKOFF_MIN_SECS 60
#define REFRESH_BACKOFF_FLOOR_SECS 90
#define REFRESH_BACKOFF_CAP_SECS 600
#define NON_RECOVERABLE_ERROR_CACHE_MIN_MS 1000
#define NON_RECOVERABLE_ERROR_CACHE_MAX_MS 5000

struct aws_credentials_provider_cached {
    struct aws_credentials_provider *source;
    struct aws_credentials *cached_credentials;
    struct aws_mutex lock;
    uint64_t refresh_interval_in_ns;
    uint64_t next_refresh_time;
    aws_io_clock_fn *high_res_clock_fn;
    aws_io_clock_fn *system_clock_fn;
    struct aws_linked_list pending_queries;

    /* State used only by the new credential refresh strategy, all high_res nanoseconds */
    uint64_t expiration_ns;         /* UINT64_MAX = no expiration */
    uint64_t advisory_window_ns;    /* fixed per credential set */
    uint64_t next_paced_refresh_ns; /* existing refresh_time_in_milliseconds schedule */
    uint64_t backoff_until_ns;      /* 0 = not rate limited */
    int cached_error_code;          /* 0 = no cached non-recoverable error */
    uint64_t cached_error_until_ns;
    bool refresh_in_flight;
};

static void s_aws_credentials_query_list_notify_and_clean_up(
    struct aws_linked_list *query_list,
    struct aws_allocator *allocator,
    struct aws_credentials *credentials,
    int error_code) {

    while (!aws_linked_list_empty(query_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(query_list);
        struct aws_credentials_query *query = AWS_CONTAINER_OF(node, struct aws_credentials_query, node);
        query->callback(credentials, error_code, query->user_data);
        aws_credentials_query_clean_up(query);
        aws_mem_release(allocator, query);
    }
}

static void s_swap_cached_credentials(
    struct aws_credentials_provider *provider,
    struct aws_credentials *new_credentials) {
    struct aws_credentials_provider_cached *cached_provider = provider->impl;

    aws_credentials_release(cached_provider->cached_credentials);
    cached_provider->cached_credentials = new_credentials;
    if (cached_provider->cached_credentials != NULL) {
        aws_credentials_acquire(cached_provider->cached_credentials);

        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider successfully sourced credentials on refresh",
            (void *)provider);
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider was unable to source credentials on refresh",
            (void *)provider);
    }
}

static void s_cached_credentials_provider_get_credentials_async_callback(
    struct aws_credentials *credentials,
    int error_code,
    void *user_data) {

    struct aws_credentials_provider *provider = user_data;
    struct aws_credentials_provider_cached *impl = provider->impl;

    aws_mutex_lock(&impl->lock);

    /*
     * Move pending queries so that we can do notifications outside the lock
     */
    struct aws_linked_list pending_queries;
    aws_linked_list_init(&pending_queries);

    aws_linked_list_swap_contents(&pending_queries, &impl->pending_queries);

    uint64_t next_refresh_time_in_ns = UINT64_MAX;

    uint64_t high_res_now = 0;
    if (!impl->high_res_clock_fn(&high_res_now)) {
        if (impl->refresh_interval_in_ns > 0) {
            next_refresh_time_in_ns = high_res_now + impl->refresh_interval_in_ns;
        }

        uint64_t credentials_expiration_timepoint_seconds = UINT64_MAX;
        if (credentials != NULL) {
            credentials_expiration_timepoint_seconds = aws_credentials_get_expiration_timepoint_seconds(credentials);
        }

        /*
         * If the sourced credentials have an explicit expiration time, we should always use that time
         * rather than the much cruder, mechanical refresh setting on the caching wrapper.
         */
        if (credentials_expiration_timepoint_seconds < UINT64_MAX) {
            uint64_t system_now = 0;
            if (!impl->system_clock_fn(&system_now)) {

                uint64_t system_now_seconds =
                    aws_timestamp_convert(system_now, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_SECS, NULL);
                if (credentials_expiration_timepoint_seconds >=
                    system_now_seconds + REFRESH_CREDENTIALS_EARLY_DURATION_SECONDS) {
                    next_refresh_time_in_ns = high_res_now;
                    next_refresh_time_in_ns += aws_timestamp_convert(
                        credentials_expiration_timepoint_seconds - system_now_seconds -
                            REFRESH_CREDENTIALS_EARLY_DURATION_SECONDS,
                        AWS_TIMESTAMP_SECS,
                        AWS_TIMESTAMP_NANOS,
                        NULL);
                } else {
                    next_refresh_time_in_ns = high_res_now;
                }
            }
        }
    }

    impl->next_refresh_time = next_refresh_time_in_ns;

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Cached credentials provider next refresh time set to %" PRIu64,
        (void *)provider,
        impl->next_refresh_time);

    s_swap_cached_credentials(provider, credentials);

    aws_mutex_unlock(&impl->lock);

    AWS_LOGF_DEBUG(
        AWS_LS_AUTH_CREDENTIALS_PROVIDER,
        "(id=%p) Cached credentials provider notifying pending queries of new credentials",
        (void *)provider);

    s_aws_credentials_query_list_notify_and_clean_up(&pending_queries, provider->allocator, credentials, error_code);
}

static int s_cached_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_cached *impl = provider->impl;

    uint64_t current_time = 0;
    impl->high_res_clock_fn(&current_time);

    bool should_submit_query = false;
    bool perform_callback = false;
    struct aws_credentials *credentials = NULL;

    aws_mutex_lock(&impl->lock);

    if (impl->cached_credentials != NULL && current_time < impl->next_refresh_time) {
        perform_callback = true;
        credentials = impl->cached_credentials;
        aws_credentials_acquire(credentials);
    } else {
        struct aws_credentials_query *query =
            aws_mem_acquire(provider->allocator, sizeof(struct aws_credentials_query));
        if (query != NULL) {
            aws_credentials_query_init(query, provider, callback, user_data);
            should_submit_query = aws_linked_list_empty(&impl->pending_queries);
            aws_linked_list_push_back(&impl->pending_queries, &query->node);
        } else {
            perform_callback = true;
        }
    }

    aws_mutex_unlock(&impl->lock);

    if (should_submit_query) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider has expired credentials.  Requerying.",
            (void *)provider);

        aws_credentials_provider_get_credentials(
            impl->source, s_cached_credentials_provider_get_credentials_async_callback, provider);

    } else if (!perform_callback) {
        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider has expired credentials.  Waiting on existing query.",
            (void *)provider);
    }

    if (perform_callback) {
        if (credentials != NULL) {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Cached credentials provider successfully sourced from cache",
                (void *)provider);
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Cached credentials provider failed to source credentials while skipping requery",
                (void *)provider);
        }
        callback(credentials, (credentials != NULL) ? AWS_ERROR_SUCCESS : aws_last_error(), user_data);
        aws_credentials_release(credentials);
    }

    return AWS_OP_SUCCESS;
}

/*
 * New credential refresh strategy.
 */

static uint64_t s_secs_to_ns(uint64_t secs) {
    return aws_timestamp_convert(secs, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
}

static uint64_t s_millis_to_ns(uint64_t millis) {
    return aws_timestamp_convert(millis, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
}

static uint64_t s_ns_to_secs(uint64_t ns) {
    return aws_timestamp_convert(ns, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_SECS, NULL);
}

/* Uniform random value in [low_ns, high_ns] */
static uint64_t s_uniform_ns(uint64_t low_ns, uint64_t high_ns) {
    if (high_ns <= low_ns) {
        return low_ns;
    }

    uint64_t random_value = 0;
    aws_device_random_u64(&random_value);
    return low_ns + (random_value % (high_ns - low_ns + 1));
}

/* Converts the credentials' epoch expiration to a high_res deadline, once, when they arrive */
static uint64_t s_get_expiration_deadline_ns(
    struct aws_credentials_provider *provider,
    const struct aws_credentials *credentials,
    uint64_t high_res_now) {

    struct aws_credentials_provider_cached *impl = provider->impl;

    uint64_t expiration_secs = aws_credentials_get_expiration_timepoint_seconds(credentials);
    if (expiration_secs == UINT64_MAX) {
        return UINT64_MAX;
    }

    uint64_t system_now = 0;
    if (impl->system_clock_fn(&system_now)) {
        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider failed to read the system clock, ignoring credentials expiration",
            (void *)provider);
        return UINT64_MAX;
    }

    uint64_t system_now_secs = s_ns_to_secs(system_now);
    if (expiration_secs <= system_now_secs) {
        return high_res_now;
    }

    return aws_add_u64_saturating(high_res_now, s_secs_to_ns(expiration_secs - system_now_secs));
}

/* Advisory refresh window: lifetime <= 20 min -> 5 min, < 90 min -> 15 min, otherwise 60 min */
static uint64_t s_get_advisory_window_ns(uint64_t lifetime_ns) {
    if (lifetime_ns <= s_secs_to_ns(20 * 60)) {
        return s_secs_to_ns(5 * 60);
    }
    if (lifetime_ns < s_secs_to_ns(90 * 60)) {
        return s_secs_to_ns(15 * 60);
    }
    return s_secs_to_ns(60 * 60);
}

/* Refresh backoff: uniform(60 s, max(90 s, min(remaining / 2, 600 s))) */
static uint64_t s_get_backoff_ns(const struct aws_credentials_provider_cached *impl, uint64_t now) {
    uint64_t remaining_ns = aws_sub_u64_saturating(impl->expiration_ns, now);
    uint64_t upper_ns = aws_min_u64(remaining_ns / 2, s_secs_to_ns(REFRESH_BACKOFF_CAP_SECS));
    upper_ns = aws_max_u64(upper_ns, s_secs_to_ns(REFRESH_BACKOFF_FLOOR_SECS));
    return s_uniform_ns(s_secs_to_ns(REFRESH_BACKOFF_MIN_SECS), upper_ns);
}

/* Refresh is due at the earlier of the paced schedule and the start of the advisory window */
static bool s_is_refresh_needed(const struct aws_credentials_provider_cached *impl, uint64_t now) {
    if (now >= impl->next_paced_refresh_ns) {
        return true;
    }
    if (impl->expiration_ns == UINT64_MAX) {
        return false;
    }

    uint64_t advisory_start_ns = aws_sub_u64_saturating(impl->expiration_ns, impl->advisory_window_ns);
    return now >= advisory_start_ns;
}

/* A previous refresh failed and the backoff has not elapsed. backoff_until_ns is 0 when not rate limited. */
static bool s_is_refresh_rate_limited(const struct aws_credentials_provider_cached *impl, uint64_t now) {
    return now < impl->backoff_until_ns;
}

static bool s_is_mandatory_refresh_needed(const struct aws_credentials_provider_cached *impl, uint64_t now) {
    if (impl->expiration_ns == UINT64_MAX) {
        return false;
    }
    return aws_add_u64_saturating(now, s_secs_to_ns(MANDATORY_REFRESH_WINDOW_SECS)) >= impl->expiration_ns;
}

static void s_new_strategy_cached_credentials_provider_source_callback(
    struct aws_credentials *credentials,
    int error_code,
    void *user_data) {

    struct aws_credentials_provider *provider = user_data;
    struct aws_credentials_provider_cached *impl = provider->impl;

    if (credentials == NULL && error_code == AWS_ERROR_SUCCESS) {
        error_code = AWS_ERROR_UNKNOWN;
    }

    uint64_t now = 0;
    impl->high_res_clock_fn(&now);

    struct aws_linked_list pending_queries;
    aws_linked_list_init(&pending_queries);

    struct aws_credentials *result_credentials = NULL;
    int result_error_code = AWS_ERROR_SUCCESS;

    aws_mutex_lock(&impl->lock);

    /* Move pending queries so that we can do notifications outside the lock */
    aws_linked_list_swap_contents(&pending_queries, &impl->pending_queries);
    impl->refresh_in_flight = false;

    bool is_initial_fetch = impl->cached_credentials == NULL;
    uint64_t deadline_ns = (credentials != NULL) ? s_get_expiration_deadline_ns(provider, credentials, now) : 0;

    if (credentials != NULL && (is_initial_fetch || deadline_ns > now)) {
        /* Success. The initial fetch accepts credentials even if they are already expired. */
        s_swap_cached_credentials(provider, credentials);
        impl->expiration_ns = deadline_ns;
        impl->advisory_window_ns = (deadline_ns == UINT64_MAX) ? 0 : s_get_advisory_window_ns(deadline_ns - now);
        impl->next_paced_refresh_ns =
            (impl->refresh_interval_in_ns > 0) ? aws_add_u64_saturating(now, impl->refresh_interval_in_ns) : UINT64_MAX;
        impl->backoff_until_ns = 0;
        impl->cached_error_code = 0;
        result_credentials = credentials;

        AWS_LOGF_DEBUG(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider expiration set to %" PRIu64 ", advisory window %" PRIu64
            " seconds, next paced refresh %" PRIu64,
            (void *)provider,
            impl->expiration_ns,
            s_ns_to_secs(impl->advisory_window_ns),
            impl->next_paced_refresh_ns);

    } else if (credentials == NULL && aws_credentials_provider_is_non_recoverable_error(error_code)) {
        /* Non-recoverable: raise it, cache it for 1 to 5 s, no backoff, keep any cached credentials */
        impl->cached_error_code = error_code;
        uint64_t error_cache_ns = s_uniform_ns(
            s_millis_to_ns(NON_RECOVERABLE_ERROR_CACHE_MIN_MS), s_millis_to_ns(NON_RECOVERABLE_ERROR_CACHE_MAX_MS));
        impl->cached_error_until_ns = aws_add_u64_saturating(now, error_cache_ns);
        result_error_code = error_code;

        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Credential refresh failed with a non-recoverable error: %s",
            (void *)provider,
            aws_error_debug_str(error_code));

    } else if (is_initial_fetch) {
        /* Recoverable initial fetch failure: nothing cached, no backoff */
        result_error_code = AWS_AUTH_SIGNING_NO_CREDENTIALS;

        AWS_LOGF_ERROR(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider failed to source credentials with error %d(%s)",
            (void *)provider,
            error_code,
            aws_error_debug_str(error_code));

    } else {
        /* Recoverable refresh failure, or expired credentials on refresh: keep cached credentials, back off */
        uint64_t backoff_ns = s_get_backoff_ns(impl, now);
        impl->backoff_until_ns = aws_add_u64_saturating(now, backoff_ns);
        result_credentials = impl->cached_credentials;

        const char *failure_reason = (credentials != NULL) ? "the credentials source returned expired credentials"
                                                           : aws_error_debug_str(error_code);
        AWS_LOGF_WARN(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Credential refresh failed: %s. The SDK will continue using cached credentials. A refresh of "
            "these credentials will be attempted again after %" PRIu64 " seconds.",
            (void *)provider,
            failure_reason,
            s_ns_to_secs(backoff_ns));
    }

    /* Hold the result across the unlock, NULL is a no-op */
    aws_credentials_acquire(result_credentials);

    aws_mutex_unlock(&impl->lock);

    s_aws_credentials_query_list_notify_and_clean_up(
        &pending_queries, provider->allocator, result_credentials, result_error_code);

    aws_credentials_release(result_credentials);
}

/* What get_credentials does for one caller, decided under impl->lock */
enum aws_cached_refresh_outcome {
    AWS_CACHED_REFRESH_RETURN_CACHED,
    AWS_CACHED_REFRESH_RETURN_ERROR,
    AWS_CACHED_REFRESH_WAIT,
};

struct aws_cached_refresh_request {
    struct aws_credentials_provider *provider;
    aws_on_get_credentials_callback_fn *callback;
    void *user_data;
    uint64_t now;
    int error_code;          /* set for AWS_CACHED_REFRESH_RETURN_ERROR */
    bool should_call_source; /* this caller starts the refresh */
};

static bool s_is_error_cached(const struct aws_credentials_provider_cached *impl, uint64_t now) {
    return impl->cached_error_code != 0 && now < impl->cached_error_until_ns;
}

/* Queues the caller on the single in-flight refresh, starting it if none is in flight */
static enum aws_cached_refresh_outcome s_wait_on_refresh(struct aws_cached_refresh_request *request) {
    struct aws_credentials_provider *provider = request->provider;
    struct aws_credentials_provider_cached *impl = provider->impl;

    struct aws_credentials_query *query = aws_mem_acquire(provider->allocator, sizeof(struct aws_credentials_query));
    aws_credentials_query_init(query, provider, request->callback, request->user_data);
    /* every caller waits here */
    aws_linked_list_push_back(&impl->pending_queries, &query->node);

    /* only the first caller gets the lock */
    if (!impl->refresh_in_flight) {
        impl->refresh_in_flight = true;
        request->should_call_source = true;
    }

    return AWS_CACHED_REFRESH_WAIT;
}

/* State 1: no credentials yet. Callers block, and concurrent callers reuse one fetch. */
static enum aws_cached_refresh_outcome s_fetch_initial_credentials(struct aws_cached_refresh_request *request) {
    struct aws_credentials_provider_cached *impl = request->provider->impl;

    if (s_is_error_cached(impl, request->now)) {
        /* previous attempt returned a non-recoverable error that is still cached. Raise it without calling the source
         */
        request->error_code = impl->cached_error_code;
        return AWS_CACHED_REFRESH_RETURN_ERROR;
    }

    /* Acquire lock */
    return s_wait_on_refresh(request);
}

/* State 3: advisory refresh. If a refresh is already in flight, return the cached credentials without waiting. */
static enum aws_cached_refresh_outcome s_attempt_advisory_refresh(struct aws_cached_refresh_request *request) {
    struct aws_credentials_provider_cached *impl = request->provider->impl;

    if (impl->refresh_in_flight) {
        return AWS_CACHED_REFRESH_RETURN_CACHED;
    }

    if (s_is_error_cached(impl, request->now)) {
        request->error_code = impl->cached_error_code;
        return AWS_CACHED_REFRESH_RETURN_ERROR;
    }

    return s_wait_on_refresh(request);
}

/* States 4 and 5: mandatory refresh or expired. Callers block, and concurrent callers reuse one refresh. */
static enum aws_cached_refresh_outcome s_attempt_mandatory_refresh(struct aws_cached_refresh_request *request) {
    struct aws_credentials_provider_cached *impl = request->provider->impl;

    if (impl->refresh_in_flight) {
        return s_wait_on_refresh(request);
    }

    if (s_is_error_cached(impl, request->now)) {
        request->error_code = impl->cached_error_code;
        return AWS_CACHED_REFRESH_RETURN_ERROR;
    }

    return s_wait_on_refresh(request);
}

static int s_new_strategy_cached_credentials_provider_get_credentials_async(
    struct aws_credentials_provider *provider,
    aws_on_get_credentials_callback_fn callback,
    void *user_data) {

    struct aws_credentials_provider_cached *impl = provider->impl;

    struct aws_cached_refresh_request request = {
        .provider = provider,
        .callback = callback,
        .user_data = user_data,
        .error_code = AWS_ERROR_SUCCESS,
        .should_call_source = false,
    };
    impl->high_res_clock_fn(&request.now);

    struct aws_credentials *credentials = NULL;
    enum aws_cached_refresh_outcome outcome = AWS_CACHED_REFRESH_RETURN_CACHED;

    /* Guards the cached state only. It is never held while the source is called. */
    aws_mutex_lock(&impl->lock);

    if (impl->cached_credentials == NULL) {
        outcome = s_fetch_initial_credentials(&request);
    } else if (!s_is_refresh_needed(impl, request.now)) {
        /**
         * State 2: valid credentials, no refresh needed
         * Return cached credentials.
         */
        outcome = AWS_CACHED_REFRESH_RETURN_CACHED;
    } else if (s_is_refresh_rate_limited(impl, request.now)) {
        /* Backoff gate: return cached credentials without calling the source */
        outcome = AWS_CACHED_REFRESH_RETURN_CACHED;
    } else if (!s_is_mandatory_refresh_needed(impl, request.now)) {
        outcome = s_attempt_advisory_refresh(&request);
    } else {
        outcome = s_attempt_mandatory_refresh(&request);
    }

    if (outcome == AWS_CACHED_REFRESH_RETURN_CACHED) {
        credentials = impl->cached_credentials;
        aws_credentials_acquire(credentials);
    }

    aws_mutex_unlock(&impl->lock);

    if (request.should_call_source) {
        AWS_LOGF_INFO(
            AWS_LS_AUTH_CREDENTIALS_PROVIDER,
            "(id=%p) Cached credentials provider refreshing credentials",
            (void *)provider);

        if (aws_credentials_provider_get_credentials(
                impl->source, s_new_strategy_cached_credentials_provider_source_callback, provider)) {
            /* The source failed synchronously and will not invoke the callback */
            s_new_strategy_cached_credentials_provider_source_callback(NULL, aws_last_error(), provider);
        }
    }

    if (outcome != AWS_CACHED_REFRESH_WAIT) {
        callback(credentials, request.error_code, user_data);
        aws_credentials_release(credentials);
    }

    return AWS_OP_SUCCESS;
}

/* Marks the cached credentials for a mandatory refresh if they are the ones a service rejected */
static int s_new_strategy_cached_credentials_provider_invalidate(
    struct aws_credentials_provider *provider,
    const struct aws_credentials *rejected_credentials) {

    struct aws_credentials_provider_cached *impl = provider->impl;

    if (rejected_credentials == NULL) {
        return AWS_OP_SUCCESS;
    }

    uint64_t now = 0;
    impl->high_res_clock_fn(&now);

    aws_mutex_lock(&impl->lock);

    /* A refresh in flight will replace the credentials, nothing to do */
    if (!impl->refresh_in_flight && impl->cached_credentials != NULL) {
        struct aws_byte_cursor cached_id = aws_credentials_get_access_key_id(impl->cached_credentials);
        struct aws_byte_cursor rejected_id = aws_credentials_get_access_key_id(rejected_credentials);

        /* Only invalidate if the cache still holds the identity that signed the rejected request. Token and
         * anonymous credentials have no access key ID, so they never match. */
        if (cached_id.len > 0 && aws_byte_cursor_eq(&cached_id, &rejected_id)) {
            /* Next get_credentials takes the mandatory path. Cached credentials and backoff are kept. */
            impl->expiration_ns = now;

            AWS_LOGF_INFO(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Cached credentials provider invalidated credentials rejected by a service",
                (void *)provider);
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_AUTH_CREDENTIALS_PROVIDER,
                "(id=%p) Cached credentials provider ignored a stale invalidate",
                (void *)provider);
        }
    }

    aws_mutex_unlock(&impl->lock);

    return AWS_OP_SUCCESS;
}

static void s_cached_credentials_provider_destroy(struct aws_credentials_provider *provider) {
    struct aws_credentials_provider_cached *impl = provider->impl;
    if (impl == NULL) {
        return;
    }

    aws_credentials_provider_release(impl->source);

    /* Invoke our own shutdown callback */
    aws_credentials_provider_invoke_shutdown_callback(provider);

    if (impl->cached_credentials != NULL) {
        aws_credentials_release(impl->cached_credentials);
    }

    aws_mutex_clean_up(&impl->lock);

    aws_mem_release(provider->allocator, provider);
}

static struct aws_credentials_provider_vtable s_aws_credentials_provider_cached_vtable = {
    .get_credentials = s_cached_credentials_provider_get_credentials_async,
    .destroy = s_cached_credentials_provider_destroy,
};

static struct aws_credentials_provider_vtable s_aws_credentials_provider_cached_new_strategy_vtable = {
    .get_credentials = s_new_strategy_cached_credentials_provider_get_credentials_async,
    .destroy = s_cached_credentials_provider_destroy,
    .invalidate = s_new_strategy_cached_credentials_provider_invalidate,
};

struct aws_credentials_provider *aws_credentials_provider_new_cached(
    struct aws_allocator *allocator,
    const struct aws_credentials_provider_cached_options *options) {

    AWS_ASSERT(options->source != NULL);

    struct aws_credentials_provider *provider = NULL;
    struct aws_credentials_provider_cached *impl = NULL;

    aws_mem_acquire_many(
        allocator,
        2,
        &provider,
        sizeof(struct aws_credentials_provider),
        &impl,
        sizeof(struct aws_credentials_provider_cached));

    if (!provider) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*provider);
    AWS_ZERO_STRUCT(*impl);

    /* The refresh strategy is fixed here, before any refresh */
    struct aws_credentials_provider_vtable *vtable = &s_aws_credentials_provider_cached_vtable;
    if (options->enable_new_cred_refresh_strategy) {
        vtable = &s_aws_credentials_provider_cached_new_strategy_vtable;
    }

    aws_credentials_provider_init_base(provider, allocator, vtable, impl);

    if (aws_mutex_init(&impl->lock)) {
        goto on_error;
    }

    aws_linked_list_init(&impl->pending_queries);

    impl->source = options->source;
    aws_credentials_provider_acquire(impl->source);

    if (options->refresh_time_in_milliseconds > 0) {
        impl->refresh_interval_in_ns = aws_timestamp_convert(
            options->refresh_time_in_milliseconds, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    } else {
        /*
         * TODO: query AWS_CREDENTIAL_EXPIRATION for a refresh override
         *
         * This must be an ISO 8601 time interval which we don't have a parser for yet (one could be cobbled
         * together from the existing timestamp parser).  Does not seem important enough to get bogged down in atm.
         * Punting for now.
         */
        impl->refresh_interval_in_ns = 0;
    }

    if (options->high_res_clock_fn != NULL) {
        impl->high_res_clock_fn = options->high_res_clock_fn;
    } else {
        impl->high_res_clock_fn = &aws_high_res_clock_get_ticks;
    }

    if (options->system_clock_fn != NULL) {
        impl->system_clock_fn = options->system_clock_fn;
    } else {
        impl->system_clock_fn = &aws_sys_clock_get_ticks;
    }

    provider->shutdown_options = options->shutdown_options;

    return provider;

on_error:

    aws_credentials_provider_destroy(provider);

    return NULL;
}
