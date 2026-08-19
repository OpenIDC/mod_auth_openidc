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
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * bounded shared-memory cache with hash lookup and exact LRU eviction
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "cache/shm.h"
#include "cache/cache.h"
#include "cfg/cache.h"
#include "cfg/cfg_int.h"
#include <apr_general.h>
#include <apr_shm.h>
#include <stdint.h>

/* size of key in cached key/value pairs */
#define OIDC_CACHE_SHM_KEY_MAX OIDC_CACHE_KEY_SIZE_MAX

#define OIDC_CACHE_SHM_PRESSURE_WARN_INTERVAL apr_time_from_sec(60)
/* Reject accidental configurations large enough to monopolize a host even on 64-bit platforms. */
#define OIDC_CACHE_SHM_SEGMENT_SIZE_MAX ((apr_uint64_t)16 * 1024 * 1024 * 1024)

typedef struct oidc_cache_cfg_shm_t {
	apr_shm_t *shm;
	oidc_cache_mutex_t *mutex;
	apr_byte_t mutex_ready;
	apr_byte_t is_parent;
} oidc_cache_cfg_shm_t;

/*
 * Layout: header | buckets | slots. Links use 1-based indexes because processes may map the segment
 * at different addresses. One cross-process mutex protects the buckets, slots and free list.
 */
typedef struct oidc_cache_shm_header_t {
	/* number of (fixed size) cache entry slots */
	apr_uint32_t nslots;
	/* number of hash buckets; a power of two >= nslots */
	apr_uint32_t nbuckets;
	/* configured size of one slot, including the entry struct itself */
	apr_uint32_t entry_size;
	/* per-segment SipHash key, initialized before workers fork */
	apr_uint64_t hash_key[2];
	/* fields below are serialized by the cache mutex */
	apr_uint32_t free_head;
	apr_time_t last_pressure_warning;
} oidc_cache_shm_header_t;

/* represents one (fixed size) cache entry, cq. name/value string pair */
typedef __attribute__((aligned(64))) struct oidc_cache_shm_entry_t {

	/* name of the cache entry */
	char section_key[OIDC_CACHE_SHM_KEY_MAX];
	/* last read or write access timestamp */
	apr_time_t access;
	/* expiry timestamp */
	apr_time_t expires;
	/* 1-based index of the next entry in the bucket chain or free list, 0 = none */
	apr_uint32_t next;
	/* value of the cache entry */
	char value[];
} oidc_cache_shm_entry_t;

static apr_uint32_t *oidc_cache_shm_buckets(oidc_cache_shm_header_t *hdr) {
	return (apr_uint32_t *)((uint8_t *)hdr + APR_ALIGN(sizeof(oidc_cache_shm_header_t), 64));
}

static oidc_cache_shm_entry_t *oidc_cache_shm_slot(oidc_cache_shm_header_t *hdr, apr_uint32_t idx) {
	uint8_t *slots =
	    (uint8_t *)oidc_cache_shm_buckets(hdr) + APR_ALIGN((apr_size_t)hdr->nbuckets * sizeof(apr_uint32_t), 64);
	return (oidc_cache_shm_entry_t *)(slots + (apr_size_t)(idx - 1) * hdr->entry_size);
}

/*
 * Align the layout base to match oidc_cache_shm_entry_t; APR does not guarantee raw alignment.
 * The anonymous segment is fork-inherited at the same base, so every worker selects the same
 * offset. Segment sizing includes space for this adjustment.
 */
static oidc_cache_shm_header_t *oidc_cache_shm_base(const oidc_cache_cfg_shm_t *context) {
	return (oidc_cache_shm_header_t *)APR_ALIGN((uintptr_t)apr_shm_baseaddr_get(context->shm), 64);
}

apr_byte_t oidc_cache_shm_segment_size(int size_max, int entry_size_max, apr_uint32_t nbuckets, apr_size_t *result) {
	/* Calculate in 64 bits first: apr_size_t is only 32 bits on supported 32-bit APR builds. */
	const apr_uint64_t header_size = ((apr_uint64_t)sizeof(oidc_cache_shm_header_t) + 63) & ~63ULL;
	const apr_uint64_t bucket_size = ((apr_uint64_t)nbuckets * sizeof(apr_uint32_t) + 63) & ~63ULL;
	const apr_uint64_t slot_size = ((apr_uint64_t)entry_size_max + 63) & ~63ULL;
	const apr_uint64_t slots_size = slot_size * (apr_uint64_t)size_max;
	const apr_uint64_t total = 64 + header_size + bucket_size + slots_size;

	if ((result == NULL) || (size_max <= 0) || (entry_size_max <= 0) || (nbuckets == 0) ||
	    (slots_size / slot_size != (apr_uint64_t)size_max) || (total < slots_size) ||
	    (total > (apr_uint64_t)SIZE_MAX) || (total > OIDC_CACHE_SHM_SEGMENT_SIZE_MAX))
		return FALSE;

	*result = (apr_size_t)total;
	return TRUE;
}

static apr_uint64_t oidc_cache_shm_rotate_left(apr_uint64_t v, unsigned int n) {
	return (v << n) | (v >> (64 - n));
}

static apr_uint64_t oidc_cache_shm_load64_le(const unsigned char *p) {
	return (apr_uint64_t)p[0] | ((apr_uint64_t)p[1] << 8) | ((apr_uint64_t)p[2] << 16) |
	       ((apr_uint64_t)p[3] << 24) | ((apr_uint64_t)p[4] << 32) | ((apr_uint64_t)p[5] << 40) |
	       ((apr_uint64_t)p[6] << 48) | ((apr_uint64_t)p[7] << 56);
}

#define OIDC_CACHE_SHM_SIPROUND(v0, v1, v2, v3)                                                                        \
	do {                                                                                                           \
		(v0) += (v1);                                                                                          \
		(v1) = oidc_cache_shm_rotate_left((v1), 13);                                                           \
		(v1) ^= (v0);                                                                                          \
		(v0) = oidc_cache_shm_rotate_left((v0), 32);                                                           \
		(v2) += (v3);                                                                                          \
		(v3) = oidc_cache_shm_rotate_left((v3), 16);                                                           \
		(v3) ^= (v2);                                                                                          \
		(v0) += (v3);                                                                                          \
		(v3) = oidc_cache_shm_rotate_left((v3), 21);                                                           \
		(v3) ^= (v0);                                                                                          \
		(v2) += (v1);                                                                                          \
		(v1) = oidc_cache_shm_rotate_left((v1), 17);                                                           \
		(v1) ^= (v2);                                                                                          \
		(v2) = oidc_cache_shm_rotate_left((v2), 32);                                                           \
	} while (0)

/* SipHash-2-4 prevents predictable bucket flooding while remaining cheap for short cache keys. */
apr_uint64_t oidc_cache_shm_siphash(const unsigned char *data, apr_size_t len, const apr_uint64_t key[2]) {
	const unsigned char *p = data;
	const unsigned char *end = p + (len & ~(apr_size_t)7);
	apr_uint64_t v0 = 0x736f6d6570736575ULL ^ key[0];
	apr_uint64_t v1 = 0x646f72616e646f6dULL ^ key[1];
	apr_uint64_t v2 = 0x6c7967656e657261ULL ^ key[0];
	apr_uint64_t v3 = 0x7465646279746573ULL ^ key[1];
	apr_uint64_t tail = (apr_uint64_t)len << 56;

	while (p != end) {
		const apr_uint64_t m = oidc_cache_shm_load64_le(p);
		v3 ^= m;
		OIDC_CACHE_SHM_SIPROUND(v0, v1, v2, v3);
		OIDC_CACHE_SHM_SIPROUND(v0, v1, v2, v3);
		v0 ^= m;
		p += 8;
	}
	for (apr_size_t i = 0; i < (len & 7); i++)
		tail |= (apr_uint64_t)p[i] << (8 * i);

	v3 ^= tail;
	OIDC_CACHE_SHM_SIPROUND(v0, v1, v2, v3);
	OIDC_CACHE_SHM_SIPROUND(v0, v1, v2, v3);
	v0 ^= tail;
	v2 ^= 0xff;
	for (int i = 0; i < 4; i++)
		OIDC_CACHE_SHM_SIPROUND(v0, v1, v2, v3);
	return v0 ^ v1 ^ v2 ^ v3;
}

static apr_uint64_t oidc_cache_shm_hash(const char *s, const apr_uint64_t key[2]) {
	return oidc_cache_shm_siphash((const unsigned char *)s, _oidc_strlen(s), key);
}

apr_ssize_t oidc_cache_shm_value_size_max(int entry_size_max) {
	return (apr_ssize_t)entry_size_max - (apr_ssize_t)sizeof(oidc_cache_shm_entry_t);
}

#undef OIDC_CACHE_SHM_SIPROUND

/* Put an already-unlinked slot on the free list; the cache mutex must be held. */
static void oidc_cache_shm_slot_free(oidc_cache_shm_header_t *hdr, oidc_cache_shm_entry_t *t, apr_uint32_t idx) {
	t->section_key[0] = '\0';
	t->access = 0;
	t->next = hdr->free_head;
	hdr->free_head = idx;
}

static apr_byte_t oidc_cache_shm_validate_buckets(request_rec *r, oidc_cache_shm_header_t *hdr, apr_byte_t *visited,
						  const char **error) {
	for (apr_uint32_t bucket_idx = 0; bucket_idx < hdr->nbuckets; bucket_idx++) {
		for (apr_uint32_t idx = oidc_cache_shm_buckets(hdr)[bucket_idx]; idx != 0;
		     idx = oidc_cache_shm_slot(hdr, idx)->next) {
			if ((idx > hdr->nslots) || (visited[idx] != 0)) {
				*error = apr_psprintf(r->pool, "invalid or repeated occupied slot %u", idx);
				return FALSE;
			}
			const oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
			const apr_uint32_t expected_bucket =
			    (apr_uint32_t)oidc_cache_shm_hash(t->section_key, hdr->hash_key) & (hdr->nbuckets - 1);
			if ((t->section_key[0] == '\0') || (expected_bucket != bucket_idx)) {
				*error = apr_psprintf(r->pool, "slot %u is linked from the wrong bucket", idx);
				return FALSE;
			}
			visited[idx] = 1;
		}
	}
	return TRUE;
}

static apr_byte_t oidc_cache_shm_validate_free_list(request_rec *r, oidc_cache_shm_header_t *hdr, apr_byte_t *visited,
						    const char **error) {
	for (apr_uint32_t idx = hdr->free_head; idx != 0; idx = oidc_cache_shm_slot(hdr, idx)->next) {
		if ((idx > hdr->nslots) || (visited[idx] != 0) ||
		    (oidc_cache_shm_slot(hdr, idx)->section_key[0] != '\0')) {
			*error = apr_psprintf(r->pool, "invalid or repeated free slot %u", idx);
			return FALSE;
		}
		visited[idx] = 1;
	}
	return TRUE;
}

static apr_byte_t oidc_cache_shm_validate_ownership(request_rec *r, const oidc_cache_shm_header_t *hdr,
						    const apr_byte_t *visited, const char **error) {
	for (apr_uint32_t idx = 1; idx <= hdr->nslots; idx++) {
		if (visited[idx] == 0) {
			*error = apr_psprintf(r->pool, "orphaned slot %u", idx);
			return FALSE;
		}
	}
	return TRUE;
}

/* Validate bucket/free-list ownership; used by stress tests and available for diagnostics. */
apr_byte_t oidc_cache_shm_validate(request_rec *r, const char **error) {
	if (error == NULL)
		return FALSE;

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	const oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *)cfg->cache.cfg;
	oidc_cache_shm_header_t *hdr = oidc_cache_shm_base(context);
	apr_byte_t valid = TRUE;
	*error = NULL;

	if (oidc_cache_mutex_lock(r->pool, r->server, context->mutex) == FALSE)
		return FALSE;
	apr_byte_t *visited = apr_pcalloc(r->pool, (apr_size_t)hdr->nslots + 1);
	valid = oidc_cache_shm_validate_buckets(r, hdr, visited, error) &&
		oidc_cache_shm_validate_free_list(r, hdr, visited, error) &&
		oidc_cache_shm_validate_ownership(r, hdr, visited, error);
	if (oidc_cache_mutex_unlock(r->pool, r->server, context->mutex) == FALSE)
		valid = FALSE;
	return valid;
}

/* create the cache context */
static void *oidc_cache_shm_cfg_create(apr_pool_t *pool) {
	oidc_cache_cfg_shm_t *context = apr_pcalloc(pool, sizeof(oidc_cache_cfg_shm_t));
	context->shm = NULL;
	context->mutex = oidc_cache_mutex_create(pool, TRUE);
	context->is_parent = TRUE;
	return context;
}

/*
 * initialized the shared memory block in the parent process
 */
static int oidc_cache_shm_post_config(apr_pool_t *pool, server_rec *s) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(s->module_config, &auth_openidc_module);
	const int size_max = oidc_cfg_cache_shm_size_max_get(cfg);
	const int entry_size_max = oidc_cfg_cache_shm_entry_size_max_get(cfg);

	if (cfg->cache.cfg != NULL)
		return OK;
	oidc_cache_cfg_shm_t *context = oidc_cache_shm_cfg_create(pool);
	cfg->cache.cfg = context;

	/* a power-of-two number of hash buckets >= the number of slots */
	apr_uint32_t nbuckets = 1;
	while ((nbuckets < (apr_uint32_t)size_max) && (nbuckets <= UINT32_MAX / 2))
		nbuckets <<= 1;
	if (nbuckets < (apr_uint32_t)size_max) {
		oidc_serror(s, "could not size the shared memory hash bucket array");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	apr_size_t segment_size = 0;
	if (oidc_cache_shm_segment_size(size_max, entry_size_max, nbuckets, &segment_size) == FALSE) {
		oidc_serror(s,
			    "requested shared memory cache is too large; reduce " OIDCCacheShmMax
			    " or " OIDCCacheShmEntrySizeMax " (maximum segment size is %" APR_UINT64_T_FMT " bytes)",
			    OIDC_CACHE_SHM_SEGMENT_SIZE_MAX);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* create the shared memory segment */
	apr_status_t rv = apr_shm_create(&context->shm, segment_size, NULL, pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "apr_shm_create failed to create shared memory segment");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* initialize the header, the (empty) hash buckets and the free list holding all slots */
	oidc_cache_shm_header_t *hdr = oidc_cache_shm_base(context);
	hdr->nslots = (apr_uint32_t)size_max;
	hdr->nbuckets = nbuckets;
	/* round the slot stride up to the entry's 64-byte alignment (see oidc_cache_shm_segment_size) */
	hdr->entry_size = (apr_uint32_t)APR_ALIGN((apr_size_t)entry_size_max, 64);
	if (apr_generate_random_bytes((unsigned char *)hdr->hash_key, sizeof(hdr->hash_key)) != APR_SUCCESS) {
		oidc_serror(s, "apr_generate_random_bytes failed to seed the shared memory cache hash");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	hdr->last_pressure_warning = 0;
	_oidc_memset(oidc_cache_shm_buckets(hdr), 0, (apr_size_t)nbuckets * sizeof(apr_uint32_t));
	for (apr_uint32_t i = 1; i <= hdr->nslots; i++) {
		oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, i);
		t->section_key[0] = '\0';
		t->access = 0;
		t->next = i < hdr->nslots ? i + 1 : 0;
	}
	hdr->free_head = 1;

	if (oidc_cache_mutex_post_config(pool, s, context->mutex, "shm") == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;
	context->mutex_ready = TRUE;

	oidc_sdebug(s,
		    "initialized shared memory with a cache size (# entries) of: %d, a max (single) entry size of: %d, "
		    "and a segment size of: %" APR_SIZE_T_FMT,
		    size_max, entry_size_max, segment_size);

	oidc_slog(s, APLOG_TRACE1, "create: %pp (shm=%pp,s=%pp, p=%d)", context, context ? context->shm : 0, s,
		  context ? context->is_parent : -1);

	return OK;
}

/*
 * initialize the shared memory segment in a child process
 */
static int oidc_cache_shm_child_init(apr_pool_t *p, server_rec *s) {
	oidc_cfg_t *cfg = ap_get_module_config(s->module_config, &auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *)cfg->cache.cfg;

	oidc_slog(s, APLOG_TRACE1, "init: %pp (shm=%pp,s=%pp, p=%d)", context, context ? context->shm : 0, s,
		  context ? context->is_parent : -1);

	if (context->is_parent == FALSE)
		return APR_SUCCESS;
	context->is_parent = FALSE;

	return oidc_cache_mutex_child_init(p, s, context->mutex);
}

/*
 * assemble single key name based on section/key input
 */
static char *oidc_cache_shm_get_key(request_rec *r, const char *section, const char *key) {

	char *section_key = oidc_cache_section_key(r->pool, section, key);

	/* check that the passed in key is valid */
	const apr_size_t section_key_len = _oidc_strlen(section_key);
	if (section_key_len >= OIDC_CACHE_SHM_KEY_MAX) {
		oidc_error(r, "could not construct cache key since key size is too large (%d >= %d) (%s)",
			   (int)section_key_len, OIDC_CACHE_SHM_KEY_MAX, section_key);
		return NULL;
	}

	return section_key;
}

static apr_uint32_t oidc_cache_shm_find(oidc_cache_shm_header_t *hdr, const apr_uint32_t *bucket,
					const char *section_key, apr_uint32_t *prev) {
	*prev = 0;
	for (apr_uint32_t idx = *bucket; idx != 0; idx = oidc_cache_shm_slot(hdr, idx)->next) {
		if (_oidc_strcmp(oidc_cache_shm_slot(hdr, idx)->section_key, section_key) == 0)
			return idx;
		*prev = idx;
	}
	return 0;
}

/*
 * get a value from the shared memory cache
 */
static apr_byte_t oidc_cache_shm_get(request_rec *r, const char *section, const char *key, char **value) {

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	const oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *)cfg->cache.cfg;

	const char *section_key = oidc_cache_shm_get_key(r, section, key);
	if (section_key == NULL)
		return FALSE;

	*value = NULL;
	oidc_cache_shm_header_t *hdr = oidc_cache_shm_base(context);
	const apr_uint64_t hash = oidc_cache_shm_hash(section_key, hdr->hash_key);
	const apr_uint32_t bucket_idx = (apr_uint32_t)hash & (hdr->nbuckets - 1);

	if (oidc_cache_mutex_lock(r->pool, r->server, context->mutex) == FALSE)
		return FALSE;

	apr_uint32_t *bucket = &oidc_cache_shm_buckets(hdr)[bucket_idx];
	const apr_time_t current_time = apr_time_now();
	apr_uint32_t prev = 0;
	apr_uint32_t idx = oidc_cache_shm_find(hdr, bucket, section_key, &prev);
	if (idx != 0) {
		oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
		if (t->expires > current_time) {
			t->access = current_time;
			/* The copy must finish while the mutex prevents a concurrent replacement. */
			*value = apr_pstrdup(r->pool, t->value);
		} else {
			if (prev != 0)
				oidc_cache_shm_slot(hdr, prev)->next = t->next;
			else
				*bucket = t->next;
			oidc_cache_shm_slot_free(hdr, t, idx);
		}
	}
	return oidc_cache_mutex_unlock(r->pool, r->server, context->mutex);
}

/*
 * unlink the specified slot from the bucket chain it is on; must be called with the mutex held
 */
static apr_byte_t oidc_cache_shm_unlink(oidc_cache_shm_header_t *hdr, apr_uint32_t idx) {
	const oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
	const apr_uint64_t hash = oidc_cache_shm_hash(t->section_key, hdr->hash_key);
	apr_uint32_t *bucket = &oidc_cache_shm_buckets(hdr)[(apr_uint32_t)hash & (hdr->nbuckets - 1)];
	apr_uint32_t prev = 0;
	for (apr_uint32_t i = *bucket; i != 0; i = oidc_cache_shm_slot(hdr, i)->next) {
		if (i == idx) {
			if (prev != 0)
				oidc_cache_shm_slot(hdr, prev)->next = t->next;
			else
				*bucket = t->next;
			return TRUE;
		}
		prev = i;
	}
	return FALSE;
}

/* The cache mutex is held: reclaim an expired entry, otherwise use exact LRU. */
static apr_uint32_t oidc_cache_shm_evict(oidc_cache_shm_header_t *hdr, apr_time_t current_time,
					 apr_time_t *pressure_age) {
	apr_uint32_t expired_victim = 0;
	apr_uint32_t lru_victim = 0;
	apr_time_t oldest = 0;
	*pressure_age = -1;
	for (apr_uint32_t idx = 1; idx <= hdr->nslots; idx++) {
		const oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
		if (t->section_key[0] == '\0')
			continue;
		if ((expired_victim == 0) && (t->expires <= current_time))
			expired_victim = idx;
		if ((lru_victim == 0) || (t->access < oldest)) {
			lru_victim = idx;
			oldest = t->access;
		}
	}

	const apr_uint32_t victim = expired_victim != 0 ? expired_victim : lru_victim;
	if (victim == 0)
		return 0;

	if (expired_victim == 0) {
		const apr_time_t access = oidc_cache_shm_slot(hdr, victim)->access;
		const apr_time_t age = current_time >= access ? (current_time - access) / 1000000 : 0;
		if ((age < 3600) &&
		    ((hdr->last_pressure_warning == 0) || (current_time < hdr->last_pressure_warning) ||
		     (current_time - hdr->last_pressure_warning >= OIDC_CACHE_SHM_PRESSURE_WARN_INTERVAL))) {
			hdr->last_pressure_warning = current_time;
			*pressure_age = age;
		}
	}

	if (oidc_cache_shm_unlink(hdr, victim) == FALSE)
		return 0;

	return victim;
}

static void oidc_cache_shm_entry_update(oidc_cache_shm_header_t *hdr, apr_uint32_t idx, const char *value,
					apr_time_t expiry, apr_time_t access) {
	oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
	_oidc_strcpy(t->value, value);
	t->expires = expiry;
	t->access = access;
}

static void oidc_cache_shm_entry_insert(oidc_cache_shm_header_t *hdr, apr_uint32_t *bucket, apr_uint32_t idx,
					const char *section_key, const char *value, apr_time_t expiry,
					apr_time_t access) {
	oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
	t->next = *bucket;
	*bucket = idx;
	_oidc_strncpy(t->section_key, section_key, OIDC_CACHE_SHM_KEY_MAX - 1);
	t->section_key[OIDC_CACHE_SHM_KEY_MAX - 1] = '\0';
	oidc_cache_shm_entry_update(hdr, idx, value, expiry, access);
}

static void oidc_cache_shm_warn_pressure(request_rec *r, const oidc_cfg_t *cfg, apr_time_t pressure_age) {
	if (pressure_age < 0)
		return;
	oidc_warn(r,
		  "dropping least-recently-used entry with age = %" APR_TIME_T_FMT
		  "s, which is less than one hour; consider increasing the shared memory caching space "
		  "(which is %d now) with the (global) " OIDCCacheShmMax " setting.",
		  pressure_age, oidc_cfg_cache_shm_size_max_get(cfg));
}

/*
 * store a value in the shared memory cache
 */
static apr_byte_t oidc_cache_shm_set(request_rec *r, const char *section, const char *key, const char *value,
				     apr_time_t expiry) {

	const oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	const oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *)cfg->cache.cfg;
	const int entry_size_max = oidc_cfg_cache_shm_entry_size_max_get(cfg);

	const char *section_key = oidc_cache_shm_get_key(r, section, key);
	if (section_key == NULL)
		return FALSE;

	/* Use signed subtraction so an undersized slot cannot wrap into a large value limit. */
	const apr_ssize_t value_size_max = oidc_cache_shm_value_size_max(entry_size_max);
	const apr_ssize_t value_size = value != NULL ? (apr_ssize_t)_oidc_strlen(value) : 0;

	/* check that the passed in value is valid; reject at ">=" rather than ">" so the NUL terminator
	 * written by the _oidc_strcpy below always fits within the entry, independent of struct padding */
	if ((value != NULL) && ((value_size_max <= 0) || (value_size >= value_size_max))) {
		oidc_error(r,
			   "could not store value since value size is too large (%ld >= %ld); consider "
			   "increasing " OIDCCacheShmEntrySizeMax "",
			   (long)value_size, (long)value_size_max);
		return FALSE;
	}

	oidc_cache_shm_header_t *hdr = oidc_cache_shm_base(context);
	const apr_uint64_t hash = oidc_cache_shm_hash(section_key, hdr->hash_key);
	const apr_uint32_t bucket_idx = (apr_uint32_t)hash & (hdr->nbuckets - 1);
	apr_uint32_t *bucket = &oidc_cache_shm_buckets(hdr)[bucket_idx];
	if (oidc_cache_mutex_lock(r->pool, r->server, context->mutex) == FALSE)
		return FALSE;

	apr_uint32_t prev = 0;
	apr_uint32_t idx = oidc_cache_shm_find(hdr, bucket, section_key, &prev);
	if (value == NULL) {
		if (idx != 0) {
			oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
			if (prev != 0)
				oidc_cache_shm_slot(hdr, prev)->next = t->next;
			else
				*bucket = t->next;
			oidc_cache_shm_slot_free(hdr, t, idx);
		}
		return oidc_cache_mutex_unlock(r->pool, r->server, context->mutex);
	}

	const apr_time_t current_time = apr_time_now();
	apr_time_t pressure_age = -1;
	if (idx != 0) {
		oidc_cache_shm_entry_update(hdr, idx, value, expiry, current_time);
	} else {
		if (hdr->free_head != 0) {
			idx = hdr->free_head;
			hdr->free_head = oidc_cache_shm_slot(hdr, idx)->next;
		} else {
			idx = oidc_cache_shm_evict(hdr, current_time, &pressure_age);
		}
		if (idx != 0)
			oidc_cache_shm_entry_insert(hdr, bucket, idx, section_key, value, expiry, current_time);
	}

	const apr_byte_t unlocked = oidc_cache_mutex_unlock(r->pool, r->server, context->mutex);
	if (idx == 0) {
		oidc_error(r, "could not obtain a cache slot");
		return FALSE;
	}
	if (unlocked == FALSE)
		return FALSE;
	oidc_cache_shm_warn_pressure(r, cfg, pressure_age);
	return TRUE;
}

static apr_status_t oidc_cache_shm_destroy_segment(apr_pool_t *pool, server_rec *s, oidc_cache_cfg_shm_t *context) {
	apr_byte_t locked = FALSE;
	if (context->mutex_ready == TRUE) {
		locked = oidc_cache_mutex_lock(pool, s, context->mutex);
		if (locked == FALSE)
			return APR_EGENERAL;
	}

	apr_status_t rv = apr_shm_destroy(context->shm);
	oidc_sdebug(s, "apr_shm_destroy returned: %d", rv);
	context->shm = NULL;
	if ((locked == TRUE) && (oidc_cache_mutex_unlock(pool, s, context->mutex) == FALSE))
		rv = APR_EGENERAL;
	return rv;
}

static apr_status_t oidc_cache_shm_destroy_mutex(server_rec *s, oidc_cache_cfg_shm_t *context) {
	if ((context->mutex != NULL) && (oidc_cache_mutex_destroy(s, context->mutex) != TRUE))
		return APR_EGENERAL;
	context->mutex = NULL;
	context->mutex_ready = FALSE;
	return APR_SUCCESS;
}

static int oidc_cache_shm_destroy(apr_pool_t *pool, server_rec *s) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(s->module_config, &auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *)cfg->cache.cfg;
	apr_status_t rv = APR_SUCCESS;

	oidc_slog(s, APLOG_TRACE1, "destroy: %pp (shm=%pp,s=%pp, p=%d)", context, context ? context->shm : 0, s,
		  context ? context->is_parent : -1);

	if (context == NULL)
		return rv;
	if ((context->is_parent == TRUE) && (context->shm != NULL))
		rv = oidc_cache_shm_destroy_segment(pool, s, context);
	if (oidc_cache_shm_destroy_mutex(s, context) != APR_SUCCESS)
		rv = APR_EGENERAL;
	return rv;
}

// clang-format off

oidc_cache_t oidc_cache_shm = {
	"shm",
	0,
	oidc_cache_shm_post_config,
	oidc_cache_shm_child_init,
	oidc_cache_shm_get,
	oidc_cache_shm_set,
	oidc_cache_shm_destroy
};

// clang-format on
