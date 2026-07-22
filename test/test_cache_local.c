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

#include <apr_pools.h>
#include <check.h>
#include <stdlib.h>
#include <string.h>

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

	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, pool, "basic", 8, 0, NULL);
	ck_assert_ptr_nonnull(cache);

	int a = 1, b = 2;
	oidc_cache_local_set(cache, "a", &a);
	oidc_cache_local_set(cache, "b", &b);

	ck_assert_ptr_eq(oidc_cache_local_get(cache, "a"), &a);
	ck_assert_ptr_eq(oidc_cache_local_get(cache, "b"), &b);
	ck_assert_ptr_null(oidc_cache_local_get(cache, "missing"));
}
END_TEST

START_TEST(test_cache_local_overwrite_frees_old) {

	_free_count = 0;
	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, pool, "ovr", 8, 0, test_free_value);

	int *v1 = mkval(1);
	int *v2 = mkval(2);
	oidc_cache_local_set(cache, "k", v1);
	oidc_cache_local_set(cache, "k", v2);

	/* the old value must have been freed, the new one stored, and the entry count unchanged */
	ck_assert_int_eq(_free_count, 1);
	ck_assert_ptr_eq(oidc_cache_local_get(cache, "k"), v2);

	/* free the survivor so valgrind stays clean (no cleanup will run before teardown here) */
	oidc_cache_local_set(cache, "k", NULL);
}
END_TEST

START_TEST(test_cache_local_get_or_compute_memoizes) {

	int compute_count = 0;

	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, pool, "goc", 8, 0, NULL);

	void *first = oidc_cache_local_get_or_compute(cache, "hello", test_compute, &compute_count);
	ck_assert_ptr_nonnull(first);
	ck_assert_int_eq(*(int *)first, 5);
	ck_assert_int_eq(compute_count, 1);

	/* a second lookup returns the same cached object without recomputing */
	void *second = oidc_cache_local_get_or_compute(cache, "hello", test_compute, &compute_count);
	ck_assert_ptr_eq(second, first);
	ck_assert_int_eq(compute_count, 1);

	/* a plain get also sees it */
	ck_assert_ptr_eq(oidc_cache_local_get(cache, "hello"), first);
}
END_TEST

START_TEST(test_cache_local_bound_stops_when_full) {

	int compute_count = 0;

	/* reset_on_full = 0: once full, new keys are not cached and compute is not called for them */
	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, pool, "bound", 2, 0, NULL);

	ck_assert_ptr_nonnull(oidc_cache_local_get_or_compute(cache, "a", test_compute, &compute_count));
	ck_assert_ptr_nonnull(oidc_cache_local_get_or_compute(cache, "b", test_compute, &compute_count));
	ck_assert_int_eq(compute_count, 2);

	/* full: c is neither computed nor cached */
	ck_assert_ptr_null(oidc_cache_local_get_or_compute(cache, "c", test_compute, &compute_count));
	ck_assert_int_eq(compute_count, 2);

	/* the earlier entries are still served */
	ck_assert_ptr_nonnull(oidc_cache_local_get(cache, "a"));
	ck_assert_ptr_nonnull(oidc_cache_local_get(cache, "b"));
	ck_assert_ptr_null(oidc_cache_local_get(cache, "c"));
}
END_TEST

START_TEST(test_cache_local_bound_resets_when_full) {

	_free_count = 0;

	/* reset_on_full = 1: inserting past the bound clears the cache (freeing all) then inserts */
	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, pool, "reset", 2, 1, test_free_value);

	oidc_cache_local_set(cache, "a", mkval(1));
	oidc_cache_local_set(cache, "b", mkval(2));
	ck_assert_int_eq(_free_count, 0);

	/* the third insert resets (frees a and b) and stores c */
	oidc_cache_local_set(cache, "c", mkval(3));
	ck_assert_int_eq(_free_count, 2);
	ck_assert_ptr_null(oidc_cache_local_get(cache, "a"));
	ck_assert_ptr_null(oidc_cache_local_get(cache, "b"));
	ck_assert_ptr_nonnull(oidc_cache_local_get(cache, "c"));

	/* release the survivor */
	oidc_cache_local_set(cache, "c", NULL);
}
END_TEST

START_TEST(test_cache_local_cleanup_frees_values) {
	apr_pool_t *parent = pool;
	apr_pool_t *child = NULL;
	apr_pool_create(&child, parent);
	_free_count = 0;

	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, child, "cln", 8, 0, test_free_value);
	oidc_cache_local_set(cache, "a", mkval(1));
	oidc_cache_local_set(cache, "b", mkval(2));
	oidc_cache_local_set(cache, "c", mkval(3));
	ck_assert_int_eq(_free_count, 0);

	/* destroying the pool runs the cache cleanup, which frees every stored value */
	apr_pool_destroy(child);
	ck_assert_int_eq(_free_count, 3);
}
END_TEST

START_TEST(test_cache_local_null_safe) {

	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, pool, "nul", 8, 0, NULL);
	int v = 1;

	/* a NULL cache is tolerated everywhere */
	ck_assert_ptr_null(oidc_cache_local_get(NULL, "k"));
	oidc_cache_local_set(NULL, "k", &v);
	ck_assert_ptr_null(oidc_cache_local_get_or_compute(NULL, "k", test_compute, NULL));

	/* a NULL key is tolerated too */
	ck_assert_ptr_null(oidc_cache_local_get(cache, NULL));
	oidc_cache_local_set(cache, NULL, &v);
	ck_assert_ptr_null(oidc_cache_local_get_or_compute(cache, NULL, test_compute, NULL));
}
END_TEST

/* file-scope owner so the pool cleanup can reset it after the owning pool is destroyed */
static oidc_cache_local_t *_owned_cache = NULL;

START_TEST(test_cache_local_owner_reset_on_pool_cleanup) {
	apr_pool_t *parent = pool;
	apr_pool_t *first = NULL, *second = NULL;
	apr_pool_create(&first, parent);

	_owned_cache = NULL;
	oidc_cache_local_t *c1 = oidc_cache_local_create(&_owned_cache, first, "owned", 8, 0, NULL);
	ck_assert_ptr_nonnull(c1);
	ck_assert_ptr_eq(_owned_cache, c1);

	/* create with the same owner is idempotent */
	ck_assert_ptr_eq(oidc_cache_local_create(&_owned_cache, first, "owned", 8, 0, NULL), c1);

	/* destroying the owning pool resets the owner pointer, so a stale cache is never used */
	apr_pool_destroy(first);
	ck_assert_ptr_null(_owned_cache);

	/* a reload (new pool) re-creates the cache and re-tracks the owner (NB: the new cache may
	 * reuse the freed address of c1, so identity is verified via the owner pointer and a live
	 * round-trip, not pointer inequality) */
	(void)c1;
	apr_pool_create(&second, parent);
	oidc_cache_local_t *c2 = oidc_cache_local_create(&_owned_cache, second, "owned", 8, 0, NULL);
	ck_assert_ptr_nonnull(c2);
	ck_assert_ptr_eq(_owned_cache, c2);
	int v = 7;
	oidc_cache_local_set(c2, "k", &v);
	ck_assert_ptr_eq(oidc_cache_local_get(c2, "k"), &v);

	apr_pool_destroy(second);
	ck_assert_ptr_null(_owned_cache);
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

static int test_validate(void *value, void *ctx) {
	return ((test_entry_t *)value)->stamp == *(int *)ctx;
}

static void test_use(void *value, void *baton) {
	*(int *)baton = ((test_entry_t *)value)->payload;
}

START_TEST(test_cache_local_get_use_set_build) {
	_free_count = 0;
	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, pool, "gusb", 8, 1, test_free_value);

	/* build stores a fresh entry; get_use validates it fresh and hands out the payload */
	struct test_build_ctx b1 = {.stamp = 1, .payload = 100};
	ck_assert_ptr_nonnull(oidc_cache_local_set_build(cache, "k", test_build, &b1));

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
	oidc_cache_local_set_build(cache, "k", test_build, &b2);
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
	ck_assert_ptr_null(oidc_cache_local_set_build(NULL, "k", test_build, &b1));
	oidc_cache_local_clear(NULL);
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

	oidc_cache_local_t *cache = oidc_cache_local_create(NULL, child, "pooled", 8, 1, test_pooled_free);
	ck_assert_ptr_nonnull(oidc_cache_local_set_build(cache, "a", test_pooled_build, &v));
	ck_assert_ptr_nonnull(oidc_cache_local_set_build(cache, "b", test_pooled_build, &v));

	/* overwriting an entry destroys its old subpool via free_value */
	oidc_cache_local_set_build(cache, "a", test_pooled_build, &v);
	ck_assert_int_eq(_free_count, 1);

	/* destroying the owning pool destroys each remaining entry's subpool via free_value - as a
	 * PRE-cleanup, before those child subpools are auto-destroyed (valgrind confirms no double free) */
	apr_pool_destroy(child);
	ck_assert_int_eq(_free_count, 3);
}
END_TEST

int main(void) {
	int failed = 0;

	apr_initialize();

	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, test_cache_local_setup, test_cache_local_teardown);
	tcase_add_test(core, test_cache_local_basic_set_get);
	tcase_add_test(core, test_cache_local_overwrite_frees_old);
	tcase_add_test(core, test_cache_local_get_or_compute_memoizes);
	tcase_add_test(core, test_cache_local_bound_stops_when_full);
	tcase_add_test(core, test_cache_local_bound_resets_when_full);
	tcase_add_test(core, test_cache_local_cleanup_frees_values);
	tcase_add_test(core, test_cache_local_null_safe);
	tcase_add_test(core, test_cache_local_owner_reset_on_pool_cleanup);
	tcase_add_test(core, test_cache_local_get_use_set_build);
	tcase_add_test(core, test_cache_local_subpool_entries_freed_on_cleanup);

	Suite *s = suite_create("cache_local");
	suite_add_tcase(s, core);

	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_ENV);
	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	apr_terminate();

	return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
