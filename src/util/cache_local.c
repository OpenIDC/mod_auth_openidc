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
#include <apr_time.h>

/* an entry accessed within this window of its eviction means the cache is too small for the working
 * set (we are throwing out entries that are still hot) - a signal worth warning the operator about */
#define OIDC_CACHE_LOCAL_YOUNG_EVICT_SEC 60
/* rate-limit the "cache full" warning to at most one per this window, to avoid log spam under churn */
#define OIDC_CACHE_LOCAL_WARN_INTERVAL_SEC 300

/* a stored value plus its last-access time; the hash maps interned keys to these nodes so eviction
 * can pick the least-recently-used one instead of clearing the whole cache */
typedef struct oidc_cache_local_node_t {
	void *value;
	apr_time_t access;
} oidc_cache_local_node_t;

struct oidc_cache_local_t {
	apr_pool_t *pool;
	apr_hash_t *hash;
#if APR_HAS_THREADS
	apr_thread_rwlock_t *rwlock;
#endif
	const char *name;
	int max_entries;
	int evict_on_full;
	oidc_cache_local_free_fn free_value;
	oidc_cache_local_t **owner;
	oidc_cache_local_log_fn log_full;
	void *log_ctx;
	apr_time_t last_warn;
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

/*
 * refresh an entry's last-access stamp for the LRU ordering, but only when it has drifted by a
 * second or more, so hot entries read by many threads are not written on every lookup. The write
 * happens under the read lock and so races with concurrent readers doing the same, but the race is
 * benign: it is an aligned 64-bit store (never torn on the platforms we target) and the value only
 * drives which entry is evicted first, never correctness.
 */
static void oidc_cache_local_touch(oidc_cache_local_node_t *node) {
	const apr_time_t now = apr_time_now();
	if ((now - node->access) >= apr_time_from_sec(1))
		node->access = now;
}

/* wrap value in a freshly-stamped node and insert it under a private copy of key; hold the write lock */
static void oidc_cache_local_insert(oidc_cache_local_t *cache, const char *key, void *value) {
	oidc_cache_local_node_t *node = apr_palloc(cache->pool, sizeof(oidc_cache_local_node_t));
	node->value = value;
	node->access = apr_time_now();
	apr_hash_set(cache->hash, apr_pstrdup(cache->pool, key), APR_HASH_KEY_STRING, node);
}

/* evict the least-recently-used entry; must hold the write lock. In-flight holders of a refcounted/
 * copied value are unaffected (they keep their own reference). Warns - rate-limited - when the victim
 * was accessed recently, i.e. the cache is too small for the load and is discarding still-hot entries. */
static void oidc_cache_local_evict_lru_unlocked(oidc_cache_local_t *cache) {
	oidc_cache_local_node_t *victim = NULL;
	const void *victim_key = NULL;
	apr_ssize_t victim_klen = 0;
	void *val = NULL;
	const void *key = NULL;
	apr_ssize_t klen = 0;

	for (apr_hash_index_t *hi = apr_hash_first(NULL, cache->hash); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, &key, &klen, &val);
		oidc_cache_local_node_t *node = val;
		if ((victim == NULL) || (node->access < victim->access)) {
			victim = node;
			victim_key = key;
			victim_klen = klen;
		}
	}
	if (victim == NULL)
		return;

	apr_hash_set(cache->hash, victim_key, victim_klen, NULL);

	if (cache->log_full != NULL) {
		const apr_time_t now = apr_time_now();
		if (((now - victim->access) < apr_time_from_sec(OIDC_CACHE_LOCAL_YOUNG_EVICT_SEC)) &&
		    ((now - cache->last_warn) > apr_time_from_sec(OIDC_CACHE_LOCAL_WARN_INTERVAL_SEC))) {
			cache->last_warn = now;
			cache->log_full(cache->log_ctx, cache->name, cache->max_entries);
		}
	}

	if (cache->free_value != NULL)
		cache->free_value(victim->value);
}

/* ensure there is room for one more entry; must hold the write lock. Returns FALSE only when the
 * cache is full and configured to stop rather than evict (borrowed values handed out by reference). */
static apr_byte_t oidc_cache_local_make_room_unlocked(oidc_cache_local_t *cache) {
	/* max_entries is clamped to >= 1 at create time, so the cast to the unsigned return type of
	 * apr_hash_count() is safe */
	if (apr_hash_count(cache->hash) < (unsigned int)cache->max_entries)
		return TRUE;
	if (cache->evict_on_full == 0)
		return FALSE;
	oidc_cache_local_evict_lru_unlocked(cache);
	return TRUE;
}

/* free every stored value and empty the hash; must be called with the write lock held (or at
 * teardown, when the process is single-threaded); the nodes and pstrdup'd keys are reclaimed at
 * pool cleanup */
static void oidc_cache_local_clear_unlocked(oidc_cache_local_t *cache) {
	if (cache->free_value != NULL) {
		void *val = NULL;
		for (apr_hash_index_t *hi = apr_hash_first(NULL, cache->hash); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, &val);
			cache->free_value(((oidc_cache_local_node_t *)val)->value);
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
					    int max_entries, int evict_on_full, oidc_cache_local_free_fn free_value,
					    oidc_cache_local_log_fn log_full, void *log_ctx) {
	/* idempotent when an owner pointer is tracked: a second create is a no-op */
	if ((owner != NULL) && (*owner != NULL))
		return *owner;

	oidc_cache_local_t *cache = apr_pcalloc(pool, sizeof(oidc_cache_local_t));
	cache->pool = pool;
	cache->name = apr_pstrdup(pool, (name != NULL) ? name : "cache");
	cache->max_entries = (max_entries > 0) ? max_entries : 1;
	cache->evict_on_full = evict_on_full;
	cache->free_value = free_value;
	cache->owner = owner;
	cache->log_full = log_full;
	cache->log_ctx = log_ctx;

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
	oidc_cache_local_node_t *node = NULL;
	void *value = NULL;
	if ((cache == NULL) || (key == NULL))
		return NULL;
	oidc_cache_local_rdlock(cache);
	node = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if (node != NULL) {
		oidc_cache_local_touch(node);
		value = node->value;
	}
	oidc_cache_local_unlock(cache);
	return value;
}

void oidc_cache_local_set(oidc_cache_local_t *cache, const char *key, void *value) {
	apr_byte_t stored = FALSE;
	oidc_cache_local_node_t *existing = NULL;

	if ((cache == NULL) || (key == NULL))
		return;

	oidc_cache_local_wrlock(cache);
	existing = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if (existing != NULL) {
		/* overwrite: release the old value and update in place (apr_hash keeps the interned key) */
		if (cache->free_value != NULL)
			cache->free_value(existing->value);
		existing->value = value;
		existing->access = apr_time_now();
		stored = TRUE;
	} else if (oidc_cache_local_make_room_unlocked(cache) == TRUE) {
		oidc_cache_local_insert(cache, key, value);
		stored = TRUE;
	}
	oidc_cache_local_unlock(cache);

	/* ownership was transferred to us; if we could not store it, release it */
	if ((stored == FALSE) && (cache->free_value != NULL))
		cache->free_value(value);
}

void *oidc_cache_local_get_or_compute(oidc_cache_local_t *cache, const char *key, oidc_cache_local_compute_fn compute,
				      void *baton) {
	oidc_cache_local_node_t *node = NULL;
	void *value = NULL;

	if ((cache == NULL) || (key == NULL) || (compute == NULL))
		return NULL;

	oidc_cache_local_rdlock(cache);
	node = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if (node != NULL) {
		oidc_cache_local_touch(node);
		value = node->value;
	}
	oidc_cache_local_unlock(cache);
	if (value != NULL)
		return value;

	oidc_cache_local_wrlock(cache);
	/* re-check under the write lock: another thread may have inserted the key meanwhile */
	node = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if (node != NULL) {
		value = node->value;
	} else if (oidc_cache_local_make_room_unlocked(cache) == TRUE) {
		/* compute (and any process-lifetime allocation) happens under the write lock,
		 * since the cache pool is not thread-safe */
		value = compute(cache->pool, key, baton);
		if (value != NULL)
			oidc_cache_local_insert(cache, key, value);
	}
	oidc_cache_local_unlock(cache);

	return value;
}

apr_byte_t oidc_cache_local_get_use(oidc_cache_local_t *cache, const char *key, oidc_cache_local_validate_fn validate,
				    const void *vctx, oidc_cache_local_use_fn use, void *ubaton) {
	oidc_cache_local_node_t *node = NULL;
	apr_byte_t rv = FALSE;

	if ((cache == NULL) || (key == NULL) || (use == NULL))
		return FALSE;

	oidc_cache_local_rdlock(cache);
	node = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if ((node != NULL) && ((validate == NULL) || (validate(node->value, vctx) != 0))) {
		use(node->value, ubaton);
		oidc_cache_local_touch(node);
		rv = TRUE;
	}
	oidc_cache_local_unlock(cache);

	return rv;
}

void *oidc_cache_local_set_build(oidc_cache_local_t *cache, const char *key, oidc_cache_local_compute_fn build,
				 void *baton) {
	oidc_cache_local_node_t *existing = NULL;
	void *value = NULL;

	if ((cache == NULL) || (key == NULL) || (build == NULL))
		return NULL;

	oidc_cache_local_wrlock(cache);
	existing = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if (existing != NULL) {
		/* replace a (typically stale) entry: free the old value, then build and store the new one
		 * in place under the interned key (or drop the entry when the rebuild yields nothing) */
		if (cache->free_value != NULL)
			cache->free_value(existing->value);
		value = build(cache->pool, key, baton);
		if (value != NULL) {
			existing->value = value;
			existing->access = apr_time_now();
		} else {
			apr_hash_set(cache->hash, key, APR_HASH_KEY_STRING, NULL);
		}
	} else if (oidc_cache_local_make_room_unlocked(cache) == TRUE) {
		value = build(cache->pool, key, baton);
		if (value != NULL)
			oidc_cache_local_insert(cache, key, value);
	}
	oidc_cache_local_unlock(cache);

	return value;
}
