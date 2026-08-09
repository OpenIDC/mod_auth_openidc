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

#include <apr_atomic.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_thread_rwlock.h>
#include <apr_time.h>

/* an entry accessed within this window of its eviction means the cache is too small for the working
 * set (we are throwing out entries that are still hot) - a signal worth warning the operator about */
#define OIDC_CACHE_LOCAL_YOUNG_EVICT_SEC 60
/* rate-limit the "cache full" warning to at most one per this window, to avoid log spam under churn */
#define OIDC_CACHE_LOCAL_WARN_INTERVAL_SEC 300
/* compact once this many times `max_entries` entries have been evicted; see oidc_cache_local_compact_unlocked.
 * The factor trades the (O(max_entries), amortized well under one copy per insert) rebuild against the peak
 * amount of superseded key/node memory held between two rebuilds */
#define OIDC_CACHE_LOCAL_COMPACT_FACTOR 4

/* a stored value plus its last-access time; the hash maps interned keys to these nodes so eviction
 * can pick the least-recently-used one instead of clearing the whole cache.
 *
 * The stamp is in whole seconds, which is all the LRU ordering ever resolved anyway (see
 * oidc_cache_local_touch), and 32 bits wide so it can be read and written through apr_atomic_*:
 * touch() runs under the READ lock, where concurrent readers stamp the same node. */
typedef struct oidc_cache_local_node_t {
	void *value;
	apr_uint32_t access;
} oidc_cache_local_node_t;

/* seconds, in the same arbitrary epoch for every node; only differences are ever used */
static apr_uint32_t oidc_cache_local_now_sec(void) {
	return (apr_uint32_t)apr_time_sec(apr_time_now());
}

struct oidc_cache_local_t {
	/* the caller's (process/worker lifetime) pool; values built by the callbacks are allocated here */
	apr_pool_t *pool;
	/* private subpool holding only the hash, its interned keys and the nodes, so all of it can be
	 * reclaimed wholesale by oidc_cache_local_compact_unlocked */
	apr_pool_t *kpool;
	apr_hash_t *hash;
#if APR_HAS_THREADS
	apr_thread_rwlock_t *rwlock;
#endif
	const char *name;
	int max_entries;
	int evict_on_full;
	/* evictions since the last compaction, and the count at which to compact (derived once at
	 * create time so the multiplication cannot overflow at runtime) */
	apr_uint32_t evictions;
	apr_uint32_t compact_at;
	/* seconds, as the nodes' stamps are; only touched under the write lock */
	oidc_cache_local_free_fn free_value;
	oidc_cache_local_log_fn log_full;
	void *log_ctx;
	apr_uint32_t last_warn;
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
 * refresh an entry's last-access stamp for the LRU ordering, but only when it has actually moved on,
 * so hot entries read by many threads are not written on every lookup. This runs under the READ
 * lock, so concurrent readers stamp the same node; the store is atomic and the value only decides
 * which entry is evicted first, never correctness.
 */
static void oidc_cache_local_touch(oidc_cache_local_node_t *node) {
	const apr_uint32_t now = oidc_cache_local_now_sec();
	if (apr_atomic_read32(&node->access) != now)
		apr_atomic_set32(&node->access, now);
}

/* wrap value in a freshly-stamped node and insert it under a private copy of key; hold the write lock */
static void oidc_cache_local_insert(oidc_cache_local_t *cache, const char *key, void *value) {
	oidc_cache_local_node_t *node = apr_palloc(cache->kpool, sizeof(oidc_cache_local_node_t));
	node->value = value;
	node->access = oidc_cache_local_now_sec();
	apr_hash_set(cache->hash, apr_pstrdup(cache->kpool, key), APR_HASH_KEY_STRING, node);
}

/*
 * rebuild the hash, its interned keys and its nodes in a fresh subpool and drop the old one; must hold
 * the write lock.
 *
 * APR pools cannot release individual allocations, so the key copy and the node of every entry ever
 * inserted stay allocated until the pool itself goes away. A *bounded* cache whose key space churns -
 * session ids, and in client-cookie mode the multi-KB cookie itself - would therefore grow the
 * process-lifetime pool without bound even though the entry count never moves. Re-interning the live
 * entries into a new pool and destroying the old one returns everything the evicted entries left behind.
 *
 * Only keys and nodes move; values are owned by the caller (and freed through free_value), so they are
 * carried over by pointer and no consumer of a borrowed value is affected.
 */
static void oidc_cache_local_compact_unlocked(oidc_cache_local_t *cache) {
	apr_pool_t *kpool = NULL;
	apr_hash_t *hash = NULL;
	const void *key = NULL;
	apr_ssize_t klen = 0;
	void *val = NULL;

	if (apr_pool_create(&kpool, cache->pool) != APR_SUCCESS)
		/* out of memory: keep the current pool, we just do not reclaim anything this round */
		return;

	hash = apr_hash_make(kpool);
	for (apr_hash_index_t *hi = apr_hash_first(NULL, cache->hash); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, &key, &klen, &val);
		const oidc_cache_local_node_t *old = val;
		oidc_cache_local_node_t *node = apr_palloc(kpool, sizeof(oidc_cache_local_node_t));
		node->value = old->value;
		node->access = old->access;
		/* klen excludes the terminator that APR_HASH_KEY_STRING interning implies */
		apr_hash_set(hash, apr_pmemdup(kpool, key, klen + 1), klen, node);
	}

	apr_pool_destroy(cache->kpool);
	cache->kpool = kpool;
	cache->hash = hash;
	cache->evictions = 0;
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
		if ((victim == NULL) || (apr_atomic_read32(&node->access) < apr_atomic_read32(&victim->access))) {
			victim = node;
			victim_key = key;
			victim_klen = klen;
		}
	}
	if (victim == NULL)
		return;

	apr_hash_set(cache->hash, victim_key, victim_klen, NULL);

	if (cache->log_full != NULL) {
		const apr_uint32_t now = oidc_cache_local_now_sec();
		if (((now - apr_atomic_read32(&victim->access)) < OIDC_CACHE_LOCAL_YOUNG_EVICT_SEC) &&
		    ((now - cache->last_warn) > OIDC_CACHE_LOCAL_WARN_INTERVAL_SEC)) {
			cache->last_warn = now;
			cache->log_full(cache->log_ctx, cache->name, cache->max_entries);
		}
	}

	if (cache->free_value != NULL)
		cache->free_value(victim->value);

	cache->evictions++;
}

/* an entry left the hash: its interned key and node stay allocated until the next rebuild, so count
 * it and rebuild once enough have accumulated. Must hold the write lock. */
static void oidc_cache_local_account_removal_unlocked(oidc_cache_local_t *cache) {
	if (cache->evictions >= cache->compact_at)
		oidc_cache_local_compact_unlocked(cache);
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
	/* reclaim what the evicted entries left interned once enough of them have accumulated */
	oidc_cache_local_account_removal_unlocked(cache);
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
	return APR_SUCCESS;
}

oidc_cache_local_t *oidc_cache_local_create(apr_pool_t *pool, const char *name, int max_entries, int evict_on_full,
					    oidc_cache_local_free_fn free_value, oidc_cache_local_log_fn log_full,
					    void *log_ctx) {
	oidc_cache_local_t *cache = apr_pcalloc(pool, sizeof(oidc_cache_local_t));
	apr_uint64_t compact_at = 0;

	/*
	 * everything this cache allocates after creation hangs off a private subpool, not off the
	 * caller's pool directly. All five caches are created in the same (post-config) pool and each
	 * serializes only on its OWN rwlock, so allocating values straight from that shared pool let
	 * two threads in two different caches into it at once - and an apr pool is not thread-safe:
	 * they would bump the same first_avail, or mutate the same child list when a nested subpool
	 * is created. With a pool per cache, that cache's write lock is a sufficient guard again.
	 *
	 * The caller's pool is still touched here at creation time, which is single-threaded, and the
	 * PRE-cleanup below is still registered on it so free_value runs before this subpool - its
	 * child - is destroyed.
	 */
	if (apr_pool_create(&cache->pool, pool) != APR_SUCCESS)
		return NULL;
	cache->name = apr_pstrdup(pool, (name != NULL) ? name : "cache");
	cache->max_entries = (max_entries > 0) ? max_entries : 1;
	cache->evict_on_full = evict_on_full;
	cache->free_value = free_value;
	cache->log_full = log_full;
	cache->log_ctx = log_ctx;

	compact_at = (apr_uint64_t)cache->max_entries * OIDC_CACHE_LOCAL_COMPACT_FACTOR;
	cache->compact_at = (compact_at > APR_UINT32_MAX) ? APR_UINT32_MAX : (apr_uint32_t)compact_at;

#if APR_HAS_THREADS
	if (apr_thread_rwlock_create(&cache->rwlock, pool) != APR_SUCCESS) {
		apr_pool_destroy(cache->pool);
		return NULL;
	}
#endif

	/* the hash, its interned keys and the nodes live in a subpool of their own so compaction can
	 * return the memory of superseded entries; see oidc_cache_local_compact_unlocked */
	if (apr_pool_create(&cache->kpool, cache->pool) != APR_SUCCESS) {
		apr_pool_destroy(cache->pool);
		return NULL;
	}
	cache->hash = apr_hash_make(cache->kpool);
	/* a PRE-cleanup so free_value runs while the hash - and any per-entry subpools a caller nests
	 * inside its values (children of this pool) - are still valid; a regular cleanup would run only
	 * after those child subpools had already been destroyed (children go before regular cleanups) */
	apr_pool_pre_cleanup_register(pool, cache, oidc_cache_local_cleanup);

	return cache;
}

void oidc_cache_local_clear(oidc_cache_local_t *cache) {
	if (cache == NULL)
		return;
	oidc_cache_local_wrlock(cache);
	oidc_cache_local_clear_unlocked(cache);
	/* the hash is empty now, so this copies nothing and simply returns everything the cleared
	 * entries had interned - a purge would otherwise retain it all until process exit */
	oidc_cache_local_compact_unlocked(cache);
	oidc_cache_local_unlock(cache);
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

apr_byte_t oidc_cache_local_set_build(oidc_cache_local_t *cache, const char *key, oidc_cache_local_validate_fn validate,
				      const void *vctx, oidc_cache_local_compute_fn build, void *baton) {
	oidc_cache_local_node_t *existing = NULL;
	void *value = NULL;

	if ((cache == NULL) || (key == NULL) || (build == NULL))
		return FALSE;

	oidc_cache_local_wrlock(cache);
	existing = apr_hash_get(cache->hash, key, APR_HASH_KEY_STRING);
	if ((existing != NULL) && (validate != NULL) && (validate(existing->value, vctx) != 0)) {
		/*
		 * re-check under the write lock: a caller arrives here having found the entry stale
		 * (or absent) on the read path, and several of them can find that at the same moment
		 * and queue on this lock. Only the first needs to rebuild - for the rest the entry is
		 * fresh again by the time they get in.
		 *
		 * Without it they each free the entry the winner just built and build it again. For a
		 * cache whose entries are pure functions of their key that is merely wasted work; for
		 * the authz-pcre cache it is a use-after-free, since the freed compiled program may
		 * already have been aliased into a running request.
		 */
		value = existing->value;
		oidc_cache_local_touch(existing);
	} else if (existing != NULL) {
		/* replace a (typically stale) entry: free the old value, then build and store the new one
		 * in place under the interned key (or drop the entry when the rebuild yields nothing) */
		if (cache->free_value != NULL)
			cache->free_value(existing->value);
		value = build(cache->pool, key, baton);
		if (value != NULL) {
			existing->value = value;
			existing->access = oidc_cache_local_now_sec();
		} else {
			/* the rebuild declined, so the entry goes; it leaves an interned key and a node
			 * behind exactly as an eviction does, and is counted the same way */
			apr_hash_set(cache->hash, key, APR_HASH_KEY_STRING, NULL);
			cache->evictions++;
			oidc_cache_local_account_removal_unlocked(cache);
		}
	} else if (oidc_cache_local_make_room_unlocked(cache) == TRUE) {
		value = build(cache->pool, key, baton);
		if (value != NULL)
			oidc_cache_local_insert(cache, key, value);
	}
	oidc_cache_local_unlock(cache);

	/* deliberately not the value itself: it is owned by the cache and, on a cache that evicts,
	 * another thread may free it the moment the lock above is released */
	return (value != NULL) ? TRUE : FALSE;
}
