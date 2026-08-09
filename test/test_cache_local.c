/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2017-2026 ZmartZone Holding BV
 * All rights reserved.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

/*
 * oidc_cache_local is a pure-APR leaf utility (no request_rec, no Apache symbols), so this test
 * deliberately does NOT use the heavy oidc_test fixture: it runs a minimal APR-only fixture and
 * its own srunner, which also keeps its link free of the Apache stubs.
 */

#include "util/cache_local.h"

/* for the old-libcheck assertion shims only; the oidc_test fixture is not used here */
#include "check_util.h"

#include <apr_pools.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static apr_pool_t *pool = NULL;

static void test_cache_local_setup(void) {
	apr_pool_create(&pool, NULL);
}

static void test_cache_local_teardown(void) {
	apr_pool_destroy(pool);
	pool = NULL;
}

/* a counting free callback over malloc'd int values, so libcheck+valgrind verify the free path */
static int _free_count = 0;

static void test_free_value(void *value) {
	_free_count++;
	free(value);
}

static int *mkval(int n) {
	int *p = (int *)malloc(sizeof(int));
	*p = n;
	return p;
}

/*
 * The cache exposes exactly two ways in and out - get_use() and set_build() - because a value read
 * out of an evicting cache is only safe to touch under the lock. These shims give the tests the
 * plain get/set they want on top of those two. Handing the stored pointer back out past the lock is
 * sound here and only here: the suite is single-threaded, so nothing can evict underneath it.
 */
static void test_copy_out(void *value, void *baton) {
	*(void **)baton = value;
}

static void *test_get(oidc_cache_local_t *cache, const char *key) {
	void *value = NULL;
	oidc_cache_local_get_use(cache, key, NULL, NULL, test_copy_out, &value);
	return value;
}

static void *test_build_baton(apr_pool_t *pool, const char *key, void *baton) {
	return baton;
}

/* stores `value` (NULL drops the entry, freeing what was there); returns FALSE when it was not
 * stored, in which case `value` is still the caller's to free */
static apr_byte_t test_set(oidc_cache_local_t *cache, const char *key, void *value) {
	return oidc_cache_local_set_build(cache, key, NULL, NULL, test_build_baton, value);
}

/*
 * resident set size of this process, or 0 when it cannot be determined (non-Linux, /proc not
 * mounted). APR pool allocations are invisible to the C library's own accounting - the allocator
 * mmaps its blocks - so this is the portable-enough way to observe that a cache is not retaining
 * memory it should have reclaimed.
 */
static apr_size_t oidc_test_resident_bytes(void) {
	unsigned long size = 0, resident = 0;
	FILE *f = fopen("/proc/self/statm", "r");
	if (f == NULL)
		return 0;
	if (fscanf(f, "%lu %lu", &size, &resident) != 2)
		resident = 0;
	fclose(f);
	return (apr_size_t)resident * (apr_size_t)getpagesize();
}

/* a compute callback that counts invocations (via the baton) and returns a cache-pool value */
static void *test_compute(apr_pool_t *pool, const char *key, void *baton) {
	int *count = (int *)baton;
	if (count != NULL)
		(*count)++;
	int *p = (int *)apr_palloc(pool, sizeof(int));
	*p = (int)strlen(key);
	return p;
}

START_TEST(test_cache_local_basic_set_get) {

	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "basic", 8, 0, NULL, NULL, NULL);
	ck_assert_ptr_nonnull(cache);

	int a = 1, b = 2;
	test_set(cache, "a", &a);
	test_set(cache, "b", &b);

	ck_assert_ptr_eq(test_get(cache, "a"), &a);
	ck_assert_ptr_eq(test_get(cache, "b"), &b);
	ck_assert_ptr_null(test_get(cache, "missing"));
}
END_TEST

START_TEST(test_cache_local_overwrite_frees_old) {

	_free_count = 0;
	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "ovr", 8, 0, test_free_value, NULL, NULL);

	int *v1 = mkval(1);
	int *v2 = mkval(2);
	test_set(cache, "k", v1);
	test_set(cache, "k", v2);

	/* the old value must have been freed, the new one stored, and the entry count unchanged */
	ck_assert_int_eq(_free_count, 1);
	ck_assert_ptr_eq(test_get(cache, "k"), v2);

	/* free the survivor so valgrind stays clean (no cleanup will run before teardown here) */
	test_set(cache, "k", NULL);
}
END_TEST

/* an entry that is a pure function of its key never goes stale; see oidc_authz_pcre_cache_get() */
static int test_always_fresh(void *value, const void *ctx) {
	return 1;
}

/*
 * the memoize idiom every caller now uses: look up, and on a miss build under the write lock and
 * look up again. Passing an always-fresh validator is what makes a concurrent second builder hand
 * back the first one's entry rather than free and rebuild it.
 */
START_TEST(test_cache_local_miss_then_build_then_hit) {

	int compute_count = 0;

	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "memo", 8, 0, NULL, NULL, NULL);

	ck_assert_ptr_null(test_get(cache, "hello"));
	ck_assert(oidc_cache_local_set_build(cache, "hello", test_always_fresh, NULL, test_compute, &compute_count) ==
		  TRUE);
	void *first = test_get(cache, "hello");
	ck_assert_ptr_nonnull(first);
	ck_assert_int_eq(*(int *)first, 5);
	ck_assert_int_eq(compute_count, 1);

	/* the entry is never stale, so a second build is a no-op that keeps the first one's value */
	ck_assert(oidc_cache_local_set_build(cache, "hello", test_always_fresh, NULL, test_compute, &compute_count) ==
		  TRUE);
	ck_assert_ptr_eq(test_get(cache, "hello"), first);
	ck_assert_int_eq(compute_count, 1);
}
END_TEST

START_TEST(test_cache_local_bound_stops_when_full) {

	int compute_count = 0;

	/* evict_on_full = 0: once full, new keys are not cached and build is not called for them */
	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "bound", 2, 0, NULL, NULL, NULL);

	ck_assert(oidc_cache_local_set_build(cache, "a", NULL, NULL, test_compute, &compute_count) == TRUE);
	ck_assert(oidc_cache_local_set_build(cache, "b", NULL, NULL, test_compute, &compute_count) == TRUE);
	ck_assert_int_eq(compute_count, 2);

	/* full: c is neither built nor cached */
	ck_assert(oidc_cache_local_set_build(cache, "c", NULL, NULL, test_compute, &compute_count) == FALSE);
	ck_assert_int_eq(compute_count, 2);

	/* the earlier entries are still served */
	ck_assert_ptr_nonnull(test_get(cache, "a"));
	ck_assert_ptr_nonnull(test_get(cache, "b"));
	ck_assert_ptr_null(test_get(cache, "c"));
}
END_TEST

START_TEST(test_cache_local_bound_evicts_one_when_full) {

	_free_count = 0;

	/* evict_on_full = 1: inserting past the bound evicts a single (LRU) entry, not the whole cache */
	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "lru", 2, 1, test_free_value, NULL, NULL);

	test_set(cache, "a", mkval(1));
	test_set(cache, "b", mkval(2));
	ck_assert_int_eq(_free_count, 0);

	/* the third insert evicts exactly one entry (not both) and stores c */
	test_set(cache, "c", mkval(3));
	ck_assert_int_eq(_free_count, 1);
	ck_assert_ptr_nonnull(test_get(cache, "c"));
	/* exactly one of the two originals survives alongside c (which one is the LRU tie-break) */
	int survivors = (test_get(cache, "a") != NULL) + (test_get(cache, "b") != NULL);
	ck_assert_int_eq(survivors, 1);

	/* the remaining values are freed by the cache's pool cleanup at teardown */
}
END_TEST

/* a counting warn callback, to verify the "cache full, evicting hot entries" hook + its rate limit */
static int _warn_count = 0;

static void test_warn(void *log_ctx, const char *name, int max_entries) {
	_warn_count++;
}

START_TEST(test_cache_local_warns_on_young_eviction) {

	_free_count = 0;
	_warn_count = 0;

	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "warn", 2, 1, test_free_value, test_warn, NULL);

	test_set(cache, "a", mkval(1));
	test_set(cache, "b", mkval(2));
	ck_assert_int_eq(_warn_count, 0);

	/* overflow evicts a just-inserted (young) entry, so the warn hook fires once */
	test_set(cache, "c", mkval(3));
	ck_assert_int_eq(_warn_count, 1);

	/* a further overflow within the rate-limit window is suppressed */
	test_set(cache, "d", mkval(4));
	ck_assert_int_eq(_warn_count, 1);
}
END_TEST

START_TEST(test_cache_local_cleanup_frees_values) {
	apr_pool_t *parent = pool;
	apr_pool_t *child = NULL;
	apr_pool_create(&child, parent);
	_free_count = 0;

	oidc_cache_local_t *cache = oidc_cache_local_create(child, "cln", 8, 0, test_free_value, NULL, NULL);
	test_set(cache, "a", mkval(1));
	test_set(cache, "b", mkval(2));
	test_set(cache, "c", mkval(3));
	ck_assert_int_eq(_free_count, 0);

	/* destroying the pool runs the cache cleanup, which frees every stored value */
	apr_pool_destroy(child);
	ck_assert_int_eq(_free_count, 3);
}
END_TEST

START_TEST(test_cache_local_null_safe) {

	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "nul", 8, 0, NULL, NULL, NULL);
	int v = 1;

	/* a NULL cache is tolerated everywhere */
	ck_assert_ptr_null(test_get(NULL, "k"));
	ck_assert(test_set(NULL, "k", &v) == FALSE);
	oidc_cache_local_clear(NULL);

	/* a NULL key is tolerated too */
	ck_assert_ptr_null(test_get(cache, NULL));
	ck_assert(test_set(cache, NULL, &v) == FALSE);
}
END_TEST

/* ---- get_use / set_build / clear: the validated-entry primitives ---- */

/* a small validated entry: `stamp` is the freshness token, `payload` the value handed out */
typedef struct test_entry_t {
	int stamp;
	int payload;
} test_entry_t;

struct test_build_ctx {
	int stamp;
	int payload;
};

static void *test_build(apr_pool_t *pool, const char *key, void *baton) {
	const struct test_build_ctx *ctx = (const struct test_build_ctx *)baton;
	test_entry_t *e = (test_entry_t *)malloc(sizeof(test_entry_t));
	e->stamp = ctx->stamp;
	e->payload = ctx->payload;
	return e;
}

static int test_validate(void *value, const void *ctx) {
	return ((test_entry_t *)value)->stamp == *(const int *)ctx;
}

static void test_use(void *value, void *baton) {
	*(int *)baton = ((test_entry_t *)value)->payload;
}

START_TEST(test_cache_local_get_use_set_build) {
	_free_count = 0;
	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "gusb", 8, 1, test_free_value, NULL, NULL);

	/* build stores a fresh entry; get_use validates it fresh and hands out the payload */
	struct test_build_ctx b1 = {.stamp = 1, .payload = 100};
	ck_assert(oidc_cache_local_set_build(cache, "k", NULL, NULL, test_build, &b1) == TRUE);

	int want = 1, out = -1;
	ck_assert(oidc_cache_local_get_use(cache, "k", test_validate, &want, test_use, &out) == TRUE);
	ck_assert_int_eq(out, 100);

	/* a stale freshness token misses and leaves the caller's value untouched */
	int stale = 2;
	out = -1;
	ck_assert(oidc_cache_local_get_use(cache, "k", test_validate, &stale, test_use, &out) == FALSE);
	ck_assert_int_eq(out, -1);

	/* rebuilding the key frees the old entry and stores the new one */
	struct test_build_ctx b2 = {.stamp = 2, .payload = 200};
	oidc_cache_local_set_build(cache, "k", NULL, NULL, test_build, &b2);
	ck_assert_int_eq(_free_count, 1);
	out = -1;
	ck_assert(oidc_cache_local_get_use(cache, "k", test_validate, &stale, test_use, &out) == TRUE);
	ck_assert_int_eq(out, 200);

	/* clear evicts everything, freeing the survivor */
	oidc_cache_local_clear(cache);
	ck_assert_int_eq(_free_count, 2);
	ck_assert(oidc_cache_local_get_use(cache, "k", test_validate, &want, test_use, &out) == FALSE);

	/* the primitives tolerate a NULL cache */
	ck_assert(oidc_cache_local_get_use(NULL, "k", test_validate, &want, test_use, &out) == FALSE);
	ck_assert(oidc_cache_local_set_build(NULL, "k", NULL, NULL, test_build, &b1) == FALSE);
	oidc_cache_local_clear(NULL);
}
END_TEST

/*
 * the write-lock re-check: several callers can find the same entry stale at the same moment and
 * queue on the write lock, but by the time the later ones get in the first has already rebuilt it.
 * With a freshness test supplied they must hand back what is there rather than free and rebuild -
 * for the jwks cache a redundant rebuild permanently retires another key set.
 */
START_TEST(test_cache_local_set_build_rechecks_under_lock) {
	_free_count = 0;
	oidc_cache_local_t *cache = oidc_cache_local_create(pool, "recheck", 8, 1, test_free_value, NULL, NULL);

	struct test_build_ctx b1 = {.stamp = 1, .payload = 100};
	ck_assert(oidc_cache_local_set_build(cache, "k", NULL, NULL, test_build, &b1) == TRUE);

	/* the loser of the race: its freshness token matches what is stored, so nothing is freed and
	 * nothing is rebuilt - the entry the winner built stays in place, as the read-back below shows */
	int fresh = 1;
	struct test_build_ctx b2 = {.stamp = 1, .payload = 200};
	ck_assert(oidc_cache_local_set_build(cache, "k", test_validate, &fresh, test_build, &b2) == TRUE);
	ck_assert_int_eq(_free_count, 0);

	int want = 1, out = -1;
	ck_assert(oidc_cache_local_get_use(cache, "k", test_validate, &want, test_use, &out) == TRUE);
	ck_assert_int_eq(out, 100); /* the winner's payload, not the skipped rebuild's 200 */

	/* a genuinely stale entry is still replaced, and its old value still freed */
	int stale = 2;
	struct test_build_ctx b3 = {.stamp = 2, .payload = 300};
	ck_assert(oidc_cache_local_set_build(cache, "k", test_validate, &stale, test_build, &b3) == TRUE);
	ck_assert_int_eq(_free_count, 1);
	out = -1;
	ck_assert(oidc_cache_local_get_use(cache, "k", test_validate, &stale, test_use, &out) == TRUE);
	ck_assert_int_eq(out, 300);

	oidc_cache_local_clear(cache);
}
END_TEST

/* an entry that owns a private subpool, as the session/appinfo/jwks caches do: free_value must
 * destroy that subpool, and the cache's PRE-cleanup must run free_value while those child subpools
 * (of the cache pool) are still valid */
typedef struct test_pooled_entry_t {
	apr_pool_t *pool;
	int payload;
} test_pooled_entry_t;

static void test_pooled_free(void *value) {
	test_pooled_entry_t *e = (test_pooled_entry_t *)value;
	_free_count++;
	apr_pool_destroy(e->pool);
}

static void *test_pooled_build(apr_pool_t *pool, const char *key, void *baton) {
	apr_pool_t *sub = NULL;
	test_pooled_entry_t *e = NULL;
	if (apr_pool_create(&sub, pool) != APR_SUCCESS)
		return NULL;
	e = (test_pooled_entry_t *)apr_pcalloc(sub, sizeof(test_pooled_entry_t));
	e->pool = sub;
	e->payload = *(int *)baton;
	return e;
}

START_TEST(test_cache_local_subpool_entries_freed_on_cleanup) {
	apr_pool_t *child = NULL;
	int v = 42;
	apr_pool_create(&child, pool);
	_free_count = 0;

	oidc_cache_local_t *cache = oidc_cache_local_create(child, "pooled", 8, 1, test_pooled_free, NULL, NULL);
	ck_assert(oidc_cache_local_set_build(cache, "a", NULL, NULL, test_pooled_build, &v) == TRUE);
	ck_assert(oidc_cache_local_set_build(cache, "b", NULL, NULL, test_pooled_build, &v) == TRUE);

	/* overwriting an entry destroys its old subpool via free_value */
	oidc_cache_local_set_build(cache, "a", NULL, NULL, test_pooled_build, &v);
	ck_assert_int_eq(_free_count, 1);

	/* destroying the owning pool destroys each remaining entry's subpool via free_value - as a
	 * PRE-cleanup, before those child subpools are auto-destroyed (valgrind confirms no double free) */
	apr_pool_destroy(child);
	ck_assert_int_eq(_free_count, 3);
}
END_TEST

/*
 * the teardown ordering the jwks cache depends on (see oidc_proto_jwks_cache_retired_cleanup): a
 * free_value that cannot actually free - because in-flight requests still hold the value - instead
 * hands it to a module-level list drained at teardown, and that list points into the cache's OWN
 * pool. The cleanup draining it must therefore run after the cache has retired every entry but
 * still before the cache pool is destroyed, which makes it a PRE-cleanup registered before
 * oidc_cache_local_create: APR runs pre-cleanups in reverse registration order and destroys child
 * pools only after all of them, so a regular cleanup would drain the list into freed memory.
 *
 * The trace records retire ('F'), drain ('D') and cache-pool-destroyed ('P'); a regular cleanup
 * yields "FPD".
 */
static char _order_trace[8];
static apr_size_t _order_len = 0;

static void test_order_mark(char c) {
	if (_order_len < sizeof(_order_trace) - 1)
		_order_trace[_order_len++] = c;
}

/* registered from the build callback on the cache's own pool: fires when that pool goes away */
static apr_status_t test_order_cache_pool_gone(void *data) {
	test_order_mark('P');
	return APR_SUCCESS;
}

/* retire rather than free, as the jwks cache does: the value stays allocated in the cache pool */
static void test_order_free(void *value) {
	test_order_mark('F');
}

static apr_status_t test_order_drain(void *data) {
	test_order_mark('D');
	return APR_SUCCESS;
}

static void *test_order_build(apr_pool_t *pool, const char *key, void *baton) {
	/* `pool` is the cache's own pool - the one a retired pointer would be left dangling into */
	apr_pool_cleanup_register(pool, NULL, test_order_cache_pool_gone, apr_pool_cleanup_null);
	return apr_pcalloc(pool, sizeof(int));
}

START_TEST(test_cache_local_retired_drain_runs_before_pool_destroy) {
	apr_pool_t *child = NULL;
	apr_pool_create(&child, pool);
	_order_len = 0;
	memset(_order_trace, 0, sizeof(_order_trace));

	/* registered first, so the cache's own pre-cleanup - registered below - runs before it */
	apr_pool_pre_cleanup_register(child, NULL, test_order_drain);

	oidc_cache_local_t *cache = oidc_cache_local_create(child, "order", 8, 1, test_order_free, NULL, NULL);
	ck_assert_ptr_nonnull(cache);
	ck_assert(oidc_cache_local_set_build(cache, "k", NULL, NULL, test_order_build, NULL) == TRUE);

	apr_pool_destroy(child);

	ck_assert_str_eq(_order_trace, "FDP");
}
END_TEST

/*
 * churn far more distinct keys through a small, bounded cache than it can hold, so the internal
 * compaction (which re-interns the surviving keys and nodes into a fresh pool and drops the old one)
 * runs many times over. Everything the cache promises must survive that: the bound, exact free_value
 * accounting, and the identity of the entries carried across a rebuild.
 */
START_TEST(test_cache_local_survives_compaction) {
	const int max_entries = 8;
	/* well past the 4 x max_entries compaction threshold, so it fires repeatedly */
	const int churn = 400;
	char key[32];

	_free_count = 0;
	oidc_cache_local_t *cache =
	    oidc_cache_local_create(pool, "compact", max_entries, 1, test_free_value, NULL, NULL);
	ck_assert_ptr_nonnull(cache);

	for (int i = 0; i < churn; i++) {
		snprintf(key, sizeof(key), "key-%06d", i);
		test_set(cache, key, mkval(i));
	}

	/* the bound held: everything but max_entries values was evicted and freed exactly once */
	ck_assert_int_eq(_free_count, churn - max_entries);

	/*
	 * exactly max_entries entries survive, and every survivor still maps to its own value - which
	 * is precisely what a compaction has to preserve when it re-interns keys and nodes into a new
	 * pool. Deliberately NOT asserting *which* keys survive: eviction picks the oldest access
	 * stamp, apr_time_now() has microsecond resolution, and inserts that land within the same
	 * microsecond tie - the victim among tied entries is then hash-order dependent (the same
	 * reason test_cache_local_bound_evicts_one_when_full only counts survivors).
	 */
	int present = 0;
	for (int i = 0; i < churn; i++) {
		snprintf(key, sizeof(key), "key-%06d", i);
		const int *v = (const int *)test_get(cache, key);
		if (v == NULL)
			continue;
		present++;
		/* a rebuild must never re-pair a key with another entry's value */
		ck_assert_int_eq(*v, i);
	}
	ck_assert_int_eq(present, max_entries);

	/* drop the survivors so valgrind sees a clean slate */
	oidc_cache_local_clear(cache);
	ck_assert_int_eq(_free_count, churn);
}
END_TEST

/*
 * the regression test for the growth this compaction exists to stop: a bounded cache whose key space
 * churns used to retain the interned key and node of every entry ever inserted for the life of the
 * cache pool, because APR pools cannot release individual allocations. With multi-KB keys - which is
 * what OIDCSessionType client-cookie produced before the session key was hashed - that ran to
 * hundreds of MB. Retention must now be a high-water mark, not a function of the insert count.
 */
START_TEST(test_cache_local_churn_does_not_grow_without_bound) {
	const int max_entries = 64;
	const int key_len = 3072;
	char *key = apr_pcalloc(pool, key_len + 1);
	apr_size_t before = 0, after = 0;

	memset(key, 'k', key_len);

	oidc_cache_local_t *cache =
	    oidc_cache_local_create(pool, "growth", max_entries, 1, test_free_value, NULL, NULL);
	ck_assert_ptr_nonnull(cache);

	/* fill to capacity first, so the comparison below measures churn rather than the steady state */
	for (int i = 0; i < max_entries; i++) {
		snprintf(key, 24, "warm-%018d", i);
		key[23] = 'k';
		test_set(cache, key, mkval(i));
	}

	before = oidc_test_resident_bytes();
	if (before == 0)
		return; /* no way to observe process memory here; nothing to assert */

	/* every insert is a brand-new multi-KB key, i.e. the worst case for key interning */
	for (int i = 0; i < 20000; i++) {
		snprintf(key, 24, "sess-%018d", i);
		key[23] = 'k';
		test_set(cache, key, mkval(i));
	}

	after = oidc_test_resident_bytes();

	/*
	 * unbounded retention would be ~key_len per insert, i.e. upwards of 60 MB here; the bound is
	 * roughly the compaction threshold (4 x max_entries) times the key size, well under 1 MB. Assert
	 * against a threshold an order of magnitude above the bound but an order below linear growth, so
	 * the test is immune to allocator and page-granularity noise.
	 */
	ck_assert_msg(after - before < 8 * 1024 * 1024,
		      "process memory grew by %lu bytes over 20000 inserts into a cache bounded at %d entries; "
		      "the interned keys/nodes of evicted entries are not being reclaimed",
		      (unsigned long)(after - before), max_entries);

	oidc_cache_local_clear(cache);
}
END_TEST

int main(void) {
	int failed = 0;

	apr_initialize();

	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, test_cache_local_setup, test_cache_local_teardown);
	tcase_add_test(core, test_cache_local_basic_set_get);
	tcase_add_test(core, test_cache_local_overwrite_frees_old);
	tcase_add_test(core, test_cache_local_miss_then_build_then_hit);
	tcase_add_test(core, test_cache_local_bound_stops_when_full);
	tcase_add_test(core, test_cache_local_bound_evicts_one_when_full);
	tcase_add_test(core, test_cache_local_warns_on_young_eviction);
	tcase_add_test(core, test_cache_local_cleanup_frees_values);
	tcase_add_test(core, test_cache_local_null_safe);
	tcase_add_test(core, test_cache_local_get_use_set_build);
	tcase_add_test(core, test_cache_local_set_build_rechecks_under_lock);
	tcase_add_test(core, test_cache_local_subpool_entries_freed_on_cleanup);
	tcase_add_test(core, test_cache_local_retired_drain_runs_before_pool_destroy);
	tcase_add_test(core, test_cache_local_survives_compaction);
	tcase_add_test(core, test_cache_local_churn_does_not_grow_without_bound);

	Suite *s = suite_create("cache_local");
	suite_add_tcase(s, core);

	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_ENV);
	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	apr_terminate();

	return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
