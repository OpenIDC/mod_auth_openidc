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
 * cleanup ordering, teardown).
 *
 * Values are owned by the cache; `free_value` (if given) is called for each value when it is
 * evicted or when the cache is torn down at pool cleanup. The cache never copies values.
 *
 * There are exactly two ways in and out - oidc_cache_local_get_use() and oidc_cache_local_set_build()
 * - and both run the caller's callback with the lock held. Nothing hands a stored pointer back past
 * the lock, because on a cache that evicts, another thread may free it the moment the lock drops.
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
typedef int (*oidc_cache_local_validate_fn)(void *value, const void *ctx);

/* use the (validated) stored value while the read lock is held - e.g. take a reference to it or copy
 * it out into `baton` - so it cannot be evicted/freed between the lookup and the caller using it */
typedef void (*oidc_cache_local_use_fn)(void *value, void *baton);

/* called (rate-limited) when a full cache evicts a still-recently-used entry, i.e. it is too small
 * for the load; `log_ctx` is the opaque context passed to create. Kept as a callback so this module
 * stays free of any server/logging dependency (and its unit test needs no Apache stubs). */
typedef void (*oidc_cache_local_log_fn)(void *log_ctx, const char *name, int max_entries);

/*
 * create a cache in `pool` (process/worker lifetime). `max_entries` bounds it; on overflow either
 * the least-recently-used entry is evicted (`evict_on_full` != 0 — safe only when values are
 * refcounted/copied so in-flight holders are unaffected) or new keys are simply not cached
 * (`evict_on_full` == 0 — use this when consumers borrow the stored value, e.g. compiled programs
 * handed out by reference).
 *
 * `log_full`, when non-NULL, is invoked (rate-limited) with `log_ctx` whenever an eviction discards
 * an entry that was accessed recently, so an operator can be warned the cache is undersized for the
 * concurrency; pass NULL to stay silent.
 *
 * Returns the cache, or NULL on allocation failure (callers then operate without a cache; all
 * functions below tolerate a NULL cache). Callers keep it in a static and simply assign it again on
 * a config reload: post-config runs against a fresh pool, and the cache built on the previous one
 * went away with it - no request can be looking at either in between.
 */
oidc_cache_local_t *oidc_cache_local_create(apr_pool_t *pool, const char *name, int max_entries, int evict_on_full,
					    oidc_cache_local_free_fn free_value, oidc_cache_local_log_fn log_full,
					    void *log_ctx);

/* evict every entry (calling `free_value` for each) without tearing the cache down, e.g. to force a
 * full refresh; safe to call concurrently with lookups/stores (takes the write lock) */
void oidc_cache_local_clear(oidc_cache_local_t *cache);

/*
 * look up `key`; when it is present and fresh (validate is NULL or validate(value, vctx) is
 * non-zero), invoke use(value, ubaton) while the read lock is held and return TRUE; otherwise
 * return FALSE. Running `use` under the lock lets the caller safely take a reference to or copy the
 * value before any concurrent reset could free it. A stale entry is left in place for set_build to
 * replace.
 */
apr_byte_t oidc_cache_local_get_use(oidc_cache_local_t *cache, const char *key, oidc_cache_local_validate_fn validate,
				    const void *vctx, oidc_cache_local_use_fn use, void *ubaton);

/*
 * store the entry for `key` produced by `build` (called under the write lock so the cache pool is
 * used single-threaded), replacing and freeing any existing entry; honors the bound the same way as
 * set_build's own bound. Returns TRUE when `key` holds a value on return, FALSE when `build` declined
 * (returned NULL) or the cache was full and does not evict. Use this after the (expensive) work of
 * producing the value has been done outside the lock, paired with get_use for the fast lookup path.
 *
 * It deliberately does not return the value: that would be a borrowed pointer handed out after the
 * lock is released, and this is the primitive the evicting caches use, so another thread could free
 * it before the caller ever looked at it. Read the value back with get_use if you need it.
 *
 * `validate` re-checks under the write lock: when an entry is
 * already present and validate(value, vctx) is non-zero, it is fresh again - another thread rebuilt
 * it while this one waited for the lock - and it is returned untouched instead of being freed and
 * rebuilt. Pass the same validate/vctx used with get_use. Passing NULL keeps the unconditional
 * replace, which is only right for a cache whose entries have no freshness test.
 */
apr_byte_t oidc_cache_local_set_build(oidc_cache_local_t *cache, const char *key, oidc_cache_local_validate_fn validate,
				      const void *vctx, oidc_cache_local_compute_fn build, void *baton);

#endif // _MOD_AUTH_OPENIDC_UTIL_CACHE_LOCAL_H_
