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

#ifndef _MOD_AUTH_OPENIDC_UTIL_CACHE_LOCAL_H_
#define _MOD_AUTH_OPENIDC_UTIL_CACHE_LOCAL_H_

#include <apr.h>
#include <apr_pools.h>

/*
 * A process-local, thread-safe, bounded string-keyed cache of in-memory derived objects.
 *
 * This is the "process-local derived-object cache" tier, distinct from the pluggable, serialized
 * oidc_cache backend (cache/): it holds parsed/compiled objects that cannot be serialized into
 * shm/redis/memcache (compiled regexes, parsed JSON, cjose keys, ...) and memoizes them for the
 * lifetime of the worker process. It centralizes the concurrency, bounding and teardown discipline
 * that would otherwise be re-implemented per cache (rwlock, write-lock-only pool allocation,
 * cleanup ordering, reload-safe owner-pointer reset).
 *
 * Values are owned by the cache; `free_value` (if given) is called for each value when it is
 * evicted or when the cache is torn down at pool cleanup. The cache never copies values.
 */
typedef struct oidc_cache_local_t oidc_cache_local_t;

/* release a stored value at eviction/teardown; may be NULL when values live in the cache pool */
typedef void (*oidc_cache_local_free_fn)(void *value);

/*
 * compute/build the value for a key, allocating anything process-lifetime from `pool` (the
 * cache's own pool); called with the write lock held. Return NULL to not cache the key.
 */
typedef void *(*oidc_cache_local_compute_fn)(apr_pool_t *pool, const char *key, void *baton);

/* return non-zero when the stored value is still fresh for `ctx` (e.g. an mtime+size or raw-string
 * check); used to invalidate stale entries on lookup */
typedef int (*oidc_cache_local_validate_fn)(void *value, void *ctx);

/* use the (validated) stored value while the read lock is held - e.g. take a reference to it or copy
 * it out into `baton` - so it cannot be evicted/freed between the lookup and the caller using it */
typedef void (*oidc_cache_local_use_fn)(void *value, void *baton);

/*
 * create a cache in `pool` (process/worker lifetime). `max_entries` bounds it; on overflow either
 * the whole cache is reset (`reset_on_full` != 0 — safe only when values are refcounted/copied so
 * in-flight holders are unaffected) or new keys are simply not cached (`reset_on_full` == 0 — use
 * this when consumers borrow the stored value, e.g. compiled programs handed out by reference).
 *
 * `owner`, when non-NULL, is the address of the caller's cache pointer: `*owner` is set to the new
 * cache and reset to NULL at pool cleanup, so a config reload (new pool) re-creates the cache
 * instead of dereferencing a freed one; passing the same `owner` again is idempotent. Tests that
 * manage the cache on the stack pass NULL and use the return value.
 *
 * Returns the cache, or NULL on allocation failure (callers then operate without a cache; all
 * functions below tolerate a NULL cache).
 */
oidc_cache_local_t *oidc_cache_local_create(oidc_cache_local_t **owner, apr_pool_t *pool, const char *name,
					    int max_entries, int reset_on_full, oidc_cache_local_free_fn free_value);

/* evict every entry (calling `free_value` for each) without tearing the cache down, e.g. to force a
 * full refresh; safe to call concurrently with lookups/stores (takes the write lock) */
void oidc_cache_local_clear(oidc_cache_local_t *cache);

/* look up `key`; returns the stored value or NULL (read-locked) */
void *oidc_cache_local_get(oidc_cache_local_t *cache, const char *key);

/* store `value` under `key`, taking ownership of `value`; replaces (and frees) any existing value.
 * When the cache is full and does not reset, `value` is not stored and is freed via `free_value`. */
void oidc_cache_local_set(oidc_cache_local_t *cache, const char *key, void *value);

/*
 * return the value cached for `key`; on a miss, compute it under the write lock (with a re-check),
 * store and return it. Returns NULL when the cache is full and does not reset, or when `compute`
 * returns NULL. The returned value is owned by the cache; do not free it.
 */
void *oidc_cache_local_get_or_compute(oidc_cache_local_t *cache, const char *key, oidc_cache_local_compute_fn compute,
				      void *baton);

/*
 * look up `key`; when it is present and fresh (validate is NULL or validate(value, vctx) is
 * non-zero), invoke use(value, ubaton) while the read lock is held and return TRUE; otherwise
 * return FALSE. Running `use` under the lock lets the caller safely take a reference to or copy the
 * value before any concurrent reset could free it. A stale entry is left in place for set_build to
 * replace.
 */
apr_byte_t oidc_cache_local_get_use(oidc_cache_local_t *cache, const char *key, oidc_cache_local_validate_fn validate,
				    void *vctx, oidc_cache_local_use_fn use, void *ubaton);

/*
 * store the entry for `key` produced by `build` (called under the write lock so the cache pool is
 * used single-threaded), replacing and freeing any existing entry; honors the bound the same way as
 * set/get_or_compute. Returns the stored value, or NULL when `build` returns NULL. Use this after
 * the (expensive) work of producing the value has been done outside the lock, paired with
 * get_use for the fast lookup path.
 */
void *oidc_cache_local_set_build(oidc_cache_local_t *cache, const char *key, oidc_cache_local_compute_fn build,
				 void *baton);

#endif // _MOD_AUTH_OPENIDC_UTIL_CACHE_LOCAL_H_
