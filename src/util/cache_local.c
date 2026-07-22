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

#include "util/cache_local.h"

#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_thread_rwlock.h>

struct oidc_cache_local_t {
	apr_pool_t *pool;
	apr_hash_t *hash;
#if APR_HAS_THREADS
	apr_thread_rwlock_t *rwlock;
#endif
	const char *name;
	int max_entries;
	int reset_on_full;
	oidc_cache_local_free_fn free_value;
	oidc_cache_local_t **owner;
};

static void oidc_cache_local_rdlock(oidc_cache_local_t *cache) {
#if APR_HAS_THREADS
	apr_thread_rwlock_rdlock(cache->rwlock);
#endif
}

static void oidc_cache_local_wrlock(oidc_cache_local_t *cache) {
#if APR_HAS_THREADS
	apr_thread_rwlock_wrlock(cache->rwlock);
#endif
}

static void oidc_cache_local_unlock(oidc_cache_local_t *cache) {
#if APR_HAS_THREADS
	apr_thread_rwlock_unlock(cache->rwlock);
#endif
}

/* free every stored value and empty the hash; must be called with the write lock held (or at
 * teardown, when the process is single-threaded); the pstrdup'd keys are reclaimed at pool cleanup */
static void oidc_cache_local_clear_unlocked(oidc_cache_local_t *cache) {
	if (cache->free_value != NULL) {
		void *val = NULL;
		for (apr_hash_index_t *hi = apr_hash_first(NULL, cache->hash); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, &val);
			cache->free_value(val);
		}
	}
	apr_hash_clear(cache->hash);
}

static apr_status_t oidc_cache_local_cleanup(void *data) {
	oidc_cache_local_t *cache = (oidc_cache_local_t *)data;
	/* free the values while the hash is still valid (this cleanup is registered on the cache's
	 * own pool, so it runs before that pool's memory is released) */
	oidc_cache_local_clear_unlocked(cache);
	/* reset the owner's pointer so a subsequent (config-reload) create re-creates the cache in
	 * the new pool instead of dereferencing this freed one */
	if (cache->owner != NULL)
		*(cache->owner) = NULL;
	return APR_SUCCESS;
}

oidc_cache_local_t *oidc_cache_local_create(oidc_cache_local_t **owner, apr_pool_t *pool, const char *name,
					    int max_entries, int reset_on_full, oidc_cache_local_free_fn free_value) {
	/* idempotent when an owner pointer is tracked: a second create is a no-op */
	if ((owner != NULL) && (*owner != NULL))
		return *owner;

	oidc_cache_local_t *cache = apr_pcalloc(pool, sizeof(oidc_cache_local_t));
	cache->pool = pool;
	cache->name = apr_pstrdup(pool, (name != NULL) ? name : "cache");
	cache->max_entries = (max_entries > 0) ? max_entries : 1;
	cache->reset_on_full = reset_on_full;
	cache->free_value = free_value;
	cache->owner = owner;

#if APR_HAS_THREADS
	if (apr_thread_rwlock_create(&cache->rwlock, pool) != APR_SUCCESS)
		return NULL;
#endif

	cache->hash = apr_hash_make(pool);
	/* a PRE-cleanup so free_value runs while the hash - and any per-entry subpools a caller nests
	 * inside its values (children of this pool) - are still valid; a regular cleanup would run only
	 * after those child subpools had already been destroyed (children go before regular cleanups) */
	apr_pool_pre_cleanup_register(pool, cache, oidc_cache_local_cleanup);

	if (owner != NULL)
		*owner = cache;

	return cache;
}

void oidc_cache_local_clear(oidc_cache_local_t *cache) {
	if (cache == NULL)
		return;
	oidc_cache_local_wrlock(cache);
	oidc_cache_local_clear_unlocked(cache);
	oidc_cache_local_unlock(cache);
}

void *oidc_cache_local_get(oidc_cache_local_t *cache, const char *key) {
	void *value = NULL;
	if ((cache == NULL) || (key == NULL))
		return NULL;
	oidc_cache_local_rdlock(cache);
	value = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	oidc_cache_local_unlock(cache);
	return value;
}

/* insert value under key, assuming key is absent; must hold the write lock. Returns TRUE when
 * stored, FALSE when the cache is full and does not reset (caller then owns the value). */
static apr_byte_t oidc_cache_local_insert_unlocked(oidc_cache_local_t *cache, const char *key, void *value) {
	if (apr_hash_count(cache->hash) >= cache->max_entries) {
		if (cache->reset_on_full == 0)
			return FALSE;
		oidc_cache_local_clear_unlocked(cache);
	}
	apr_hash_set(cache->hash, apr_pstrdup(cache->pool, key), APR_HASH_KEY_STRING, value);
	return TRUE;
}

void oidc_cache_local_set(oidc_cache_local_t *cache, const char *key, void *value) {
	apr_byte_t stored = FALSE;

	if ((cache == NULL) || (key == NULL))
		return;

	oidc_cache_local_wrlock(cache);
	void *existing = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if (existing != NULL) {
		/* overwrite: release the old value and update in place (apr_hash keeps the interned key) */
		if (cache->free_value != NULL)
			cache->free_value(existing);
		apr_hash_set(cache->hash, key, APR_HASH_KEY_STRING, value);
		stored = TRUE;
	} else {
		stored = oidc_cache_local_insert_unlocked(cache, key, value);
	}
	oidc_cache_local_unlock(cache);

	/* ownership was transferred to us; if we could not store it, release it */
	if ((stored == FALSE) && (cache->free_value != NULL))
		cache->free_value(value);
}

void *oidc_cache_local_get_or_compute(oidc_cache_local_t *cache, const char *key, oidc_cache_local_compute_fn compute,
				      void *baton) {
	void *value = NULL;

	if ((cache == NULL) || (key == NULL) || (compute == NULL))
		return NULL;

	oidc_cache_local_rdlock(cache);
	value = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	oidc_cache_local_unlock(cache);
	if (value != NULL)
		return value;

	oidc_cache_local_wrlock(cache);
	/* re-check under the write lock: another thread may have inserted the key meanwhile */
	value = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if (value == NULL) {
		if ((apr_hash_count(cache->hash) >= cache->max_entries) && (cache->reset_on_full != 0))
			oidc_cache_local_clear_unlocked(cache);
		if (apr_hash_count(cache->hash) < cache->max_entries) {
			/* compute (and any process-lifetime allocation) happens under the write lock,
			 * since the cache pool is not thread-safe */
			value = compute(cache->pool, key, baton);
			if (value != NULL)
				apr_hash_set(cache->hash, apr_pstrdup(cache->pool, key), APR_HASH_KEY_STRING, value);
		}
	}
	oidc_cache_local_unlock(cache);

	return value;
}

apr_byte_t oidc_cache_local_get_use(oidc_cache_local_t *cache, const char *key, oidc_cache_local_validate_fn validate,
				    const void *vctx, oidc_cache_local_use_fn use, void *ubaton) {
	apr_byte_t rv = FALSE;

	if ((cache == NULL) || (key == NULL) || (use == NULL))
		return FALSE;

	oidc_cache_local_rdlock(cache);
	void *value = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if ((value != NULL) && ((validate == NULL) || (validate(value, vctx) != 0))) {
		use(value, ubaton);
		rv = TRUE;
	}
	oidc_cache_local_unlock(cache);

	return rv;
}

void *oidc_cache_local_set_build(oidc_cache_local_t *cache, const char *key, oidc_cache_local_compute_fn build,
				 void *baton) {
	void *value = NULL;

	if ((cache == NULL) || (key == NULL) || (build == NULL))
		return NULL;

	oidc_cache_local_wrlock(cache);
	void *existing = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if (existing != NULL) {
		/* replace a (typically stale) entry: free the old value, then build and store the new
		 * one under the interned key (or delete the entry when the rebuild yields nothing) */
		if (cache->free_value != NULL)
			cache->free_value(existing);
		value = build(cache->pool, key, baton);
		apr_hash_set(cache->hash, key, APR_HASH_KEY_STRING, value);
	} else {
		if ((apr_hash_count(cache->hash) >= cache->max_entries) && (cache->reset_on_full != 0))
			oidc_cache_local_clear_unlocked(cache);
		if (apr_hash_count(cache->hash) < cache->max_entries) {
			value = build(cache->pool, key, baton);
			if (value != NULL)
				apr_hash_set(cache->hash, apr_pstrdup(cache->pool, key), APR_HASH_KEY_STRING, value);
		}
	}
	oidc_cache_local_unlock(cache);

	return value;
}
