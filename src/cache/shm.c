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
 * caching using a shared memory backend, FIFO-style
 * based on mod_auth_mellon code
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "cache/cache.h"
#include "cfg/cache.h"
#include "cfg/cfg_int.h"
#include <apr_shm.h>

typedef struct oidc_cache_cfg_shm_t {
	apr_shm_t *shm;
	oidc_cache_mutex_t *mutex;
	apr_byte_t is_parent;
} oidc_cache_cfg_shm_t;

/* size of key in cached key/value pairs */
#define OIDC_CACHE_SHM_KEY_MAX OIDC_CACHE_KEY_SIZE_MAX

/*
 * The segment is laid out as: header | bucket array | slot array. All references between
 * them are 1-based slot indexes (0 = nil) since the segment maps at different addresses in
 * different processes. Entries are chained per hash bucket and unused slots sit on a free
 * list, so get/set are O(chain length) instead of a linear scan over all slots, and the
 * global mutex is correspondingly held for a fraction of the time.
 */
typedef struct oidc_cache_shm_header_t {
	/* number of (fixed size) cache entry slots */
	apr_uint32_t nslots;
	/* number of hash buckets; a power of two >= nslots */
	apr_uint32_t nbuckets;
	/* configured size of one slot, including the entry struct itself */
	apr_uint32_t entry_size;
	/* head of the free list */
	apr_uint32_t free_head;
} oidc_cache_shm_header_t;

/* represents one (fixed size) cache entry, cq. name/value string pair */
typedef __attribute__((aligned(64))) struct oidc_cache_shm_entry_t {

	/* name of the cache entry */
	char section_key[OIDC_CACHE_SHM_KEY_MAX];
	/* last (read) access timestamp */
	apr_time_t access;
	/* expiry timestamp */
	apr_time_t expires;
	/* 1-based index of the next entry in the bucket chain or free list, 0 = none */
	apr_uint32_t next;
	/* value of the cache entry */
	char value[];
} oidc_cache_shm_entry_t;

/* number of random slots sampled when evicting: pick the least-recently-used of the sample
 * (the Redis approach) so a full-cache insert stays O(1) instead of scanning all slots */
#define OIDC_CACHE_SHM_EVICT_SAMPLES 8

static apr_uint32_t *oidc_cache_shm_buckets(oidc_cache_shm_header_t *hdr) {
	return (apr_uint32_t *)((uint8_t *)hdr + APR_ALIGN(sizeof(oidc_cache_shm_header_t), 64));
}

static oidc_cache_shm_entry_t *oidc_cache_shm_slot(oidc_cache_shm_header_t *hdr, apr_uint32_t idx) {
	uint8_t *slots =
	    (uint8_t *)oidc_cache_shm_buckets(hdr) + APR_ALIGN((apr_size_t)hdr->nbuckets * sizeof(apr_uint32_t), 64);
	return (oidc_cache_shm_entry_t *)(slots + (apr_size_t)(idx - 1) * hdr->entry_size);
}

static apr_size_t oidc_cache_shm_segment_size(int size_max, int entry_size_max, apr_uint32_t nbuckets) {
	return APR_ALIGN(sizeof(oidc_cache_shm_header_t), 64) +
	       APR_ALIGN((apr_size_t)nbuckets * sizeof(apr_uint32_t), 64) + (apr_size_t)entry_size_max * size_max;
}

/* FNV-1a over the section key; must be identical in every process attached to the segment */
static apr_uint32_t oidc_cache_shm_hash(const char *s) {
	apr_uint32_t h = 2166136261u;
	while (*s != '\0') {
		h ^= (unsigned char)*s++;
		h *= 16777619u;
	}
	return h;
}

/* put a slot (back) on the free list; must be called with the global mutex held */
static void oidc_cache_shm_slot_free(oidc_cache_shm_header_t *hdr, oidc_cache_shm_entry_t *t, apr_uint32_t idx) {
	t->section_key[0] = '\0';
	t->access = 0;
	t->next = hdr->free_head;
	hdr->free_head = idx;
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
	while (nbuckets < (apr_uint32_t)size_max)
		nbuckets <<= 1;

	/* create the shared memory segment */
	apr_status_t rv =
	    apr_shm_create(&context->shm, oidc_cache_shm_segment_size(size_max, entry_size_max, nbuckets), NULL, pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "apr_shm_create failed to create shared memory segment");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* initialize the header, the (empty) hash buckets and the free list holding all slots */
	oidc_cache_shm_header_t *hdr = apr_shm_baseaddr_get(context->shm);
	hdr->nslots = (apr_uint32_t)size_max;
	hdr->nbuckets = nbuckets;
	hdr->entry_size = (apr_uint32_t)entry_size_max;
	_oidc_memset(oidc_cache_shm_buckets(hdr), 0, (apr_size_t)nbuckets * sizeof(apr_uint32_t));
	for (apr_uint32_t i = 1; i <= hdr->nslots; i++) {
		oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, i);
		t->section_key[0] = '\0';
		t->access = 0;
		t->next = (i < hdr->nslots) ? i + 1 : 0;
	}
	hdr->free_head = 1;

	if (oidc_cache_mutex_post_config(pool, s, context->mutex, "shm") == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	oidc_sdebug(
	    s, "initialized shared memory with a cache size (# entries) of: %d, and a max (single) entry size of: %d",
	    size_max, entry_size_max);

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

	/* initialize the lock for the child process */
	return oidc_cache_mutex_child_init(p, s, context->mutex);
}

/*
 * assemble single key name based on section/key input
 */
static char *oidc_cache_shm_get_key(request_rec *r, const char *section, const char *key) {

	char *section_key = oidc_cache_section_key(r->pool, section, key);

	/* check that the passed in key is valid */
	if (_oidc_strlen(section_key) >= OIDC_CACHE_SHM_KEY_MAX) {
		oidc_error(r, "could not construct cache key since key size is too large (%d >= %d) (%s)",
			   (int)_oidc_strlen(section_key), OIDC_CACHE_SHM_KEY_MAX, section_key);
		return NULL;
	}

	return section_key;
}

/*
 * get a value from the shared memory cache
 */
static apr_byte_t oidc_cache_shm_get(request_rec *r, const char *section, const char *key, char **value) {

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *)cfg->cache.cfg;

	const char *section_key = oidc_cache_shm_get_key(r, section, key);
	if (section_key == NULL)
		return FALSE;

	*value = NULL;

	/* grab the global lock */
	if (oidc_cache_mutex_lock(r->pool, r->server, context->mutex) == FALSE)
		return FALSE;

	oidc_cache_shm_header_t *hdr = apr_shm_baseaddr_get(context->shm);
	apr_uint32_t *bucket = &oidc_cache_shm_buckets(hdr)[oidc_cache_shm_hash(section_key) & (hdr->nbuckets - 1)];

	/* walk the bucket chain, looking for the key */
	apr_uint32_t prev = 0;
	for (apr_uint32_t idx = *bucket; idx != 0; idx = oidc_cache_shm_slot(hdr, idx)->next) {

		oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);

		if (_oidc_strcmp(t->section_key, section_key) != 0) {
			prev = idx;
			continue;
		}

		/* found a match, check if it has expired */
		if (t->expires > apr_time_now()) {

			/* update access timestamp */
			t->access = apr_time_now();
			/* copy the value out while still holding the lock; returning the raw
			 * pointer into shared memory would let a concurrent set() tear the value
			 * after the lock below is released and the caller reads/decrypts it */
			*value = apr_pstrdup(r->pool, t->value);

		} else {

			/* unlink the expired entry and put its slot back on the free list */
			if (prev != 0)
				oidc_cache_shm_slot(hdr, prev)->next = t->next;
			else
				*bucket = t->next;
			oidc_cache_shm_slot_free(hdr, t, idx);
		}

		break;
	}

	/* release the global lock */
	oidc_cache_mutex_unlock(r->pool, r->server, context->mutex);

	return TRUE;
}

/*
 * unlink the specified slot from the bucket chain it is on; must be called with the mutex held
 */
static void oidc_cache_shm_unlink(oidc_cache_shm_header_t *hdr, apr_uint32_t idx) {
	oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
	apr_uint32_t *bucket = &oidc_cache_shm_buckets(hdr)[oidc_cache_shm_hash(t->section_key) & (hdr->nbuckets - 1)];
	apr_uint32_t prev = 0;
	for (apr_uint32_t i = *bucket; i != 0; i = oidc_cache_shm_slot(hdr, i)->next) {
		if (i == idx) {
			if (prev != 0)
				oidc_cache_shm_slot(hdr, prev)->next = t->next;
			else
				*bucket = t->next;
			return;
		}
		prev = i;
	}
}

/*
 * obtain a slot for a new entry when the free list is empty: sample a bounded number of
 * pseudo-randomly chosen occupied slots and evict an expired one, or else the least-recently-used
 * one of the sample; must be called with the mutex held
 */
static apr_uint32_t oidc_cache_shm_evict(request_rec *r, const oidc_cfg_t *cfg, oidc_cache_shm_header_t *hdr,
					 apr_time_t current_time) {
	apr_uint32_t victim = 0;
	apr_time_t oldest = 0;
	apr_byte_t expired = FALSE;
	const apr_uint32_t start = (apr_uint32_t)(apr_time_usec(current_time) + apr_time_sec(current_time));

	for (int i = 0; i < OIDC_CACHE_SHM_EVICT_SAMPLES; i++) {
		/* a Weyl sequence over the slot array approximates uniform random sampling */
		const apr_uint32_t idx =
		    (apr_uint32_t)(((apr_uint64_t)start + (apr_uint64_t)i * 2654435761u) % hdr->nslots) + 1;
		oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
		if (t->section_key[0] == '\0')
			continue;
		if (t->expires <= current_time) {
			victim = idx;
			expired = TRUE;
			break;
		}
		if ((victim == 0) || (t->access < oldest)) {
			victim = idx;
			oldest = t->access;
		}
	}

	/* cannot happen when the free list is empty (all slots occupied), but stay safe */
	if (victim == 0)
		return 0;

	if (expired == FALSE) {
		const apr_time_t age = (current_time - oidc_cache_shm_slot(hdr, victim)->access) / 1000000;
		if (age < 3600) {
			oidc_warn(r,
				  "dropping LRU entry with age = %" APR_TIME_T_FMT
				  "s, which is less than one hour; consider increasing the shared memory caching space "
				  "(which is %d now) with the (global) " OIDCCacheShmMax " setting.",
				  age, oidc_cfg_cache_shm_size_max_get(cfg));
		}
	}

	oidc_cache_shm_unlink(hdr, victim);

	return victim;
}

/*
 * store a value in the shared memory cache
 */
static apr_byte_t oidc_cache_shm_set(request_rec *r, const char *section, const char *key, const char *value,
				     apr_time_t expiry) {

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *)cfg->cache.cfg;
	const int entry_size_max = oidc_cfg_cache_shm_entry_size_max_get(cfg);

	const char *section_key = oidc_cache_shm_get_key(r, section, key);
	if (section_key == NULL)
		return FALSE;

	/* check that the passed in value is valid; reject at ">=" rather than ">" so the NUL terminator
	 * written by the _oidc_strcpy below always fits within the entry, independent of struct padding */
	if ((value != NULL) && (_oidc_strlen(value) >= (entry_size_max - sizeof(oidc_cache_shm_entry_t)))) {
		oidc_error(r,
			   "could not store value since value size is too large (%lu >= %lu); consider "
			   "increasing " OIDCCacheShmEntrySizeMax "",
			   (unsigned long)_oidc_strlen(value),
			   (unsigned long)(entry_size_max - sizeof(oidc_cache_shm_entry_t)));
		return FALSE;
	}

	/* grab the global lock */
	if (oidc_cache_mutex_lock(r->pool, r->server, context->mutex) == FALSE)
		return FALSE;

	const apr_time_t current_time = apr_time_now();

	oidc_cache_shm_header_t *hdr = apr_shm_baseaddr_get(context->shm);
	apr_uint32_t *bucket = &oidc_cache_shm_buckets(hdr)[oidc_cache_shm_hash(section_key) & (hdr->nbuckets - 1)];

	/* walk the bucket chain looking for an existing entry for this key */
	apr_uint32_t prev = 0;
	apr_uint32_t idx = *bucket;
	while (idx != 0) {
		if (_oidc_strcmp(oidc_cache_shm_slot(hdr, idx)->section_key, section_key) == 0)
			break;
		prev = idx;
		idx = oidc_cache_shm_slot(hdr, idx)->next;
	}

	if (value == NULL) {

		/* delete: unlink a matched entry and put its slot back on the free list */
		if (idx != 0) {
			oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
			if (prev != 0)
				oidc_cache_shm_slot(hdr, prev)->next = t->next;
			else
				*bucket = t->next;
			oidc_cache_shm_slot_free(hdr, t, idx);
		}

	} else {

		if (idx == 0) {

			/* no existing entry: take a slot from the free list, or evict one */
			idx = hdr->free_head;
			if (idx != 0)
				hdr->free_head = oidc_cache_shm_slot(hdr, idx)->next;
			else
				idx = oidc_cache_shm_evict(r, cfg, hdr, current_time);

			if (idx == 0) {
				/* cannot happen: an empty free list implies occupied slots to evict */
				oidc_cache_mutex_unlock(r->pool, r->server, context->mutex);
				oidc_error(r, "could not obtain a cache slot");
				return FALSE;
			}

			/* link the slot into this key's bucket chain */
			oidc_cache_shm_slot(hdr, idx)->next = *bucket;
			*bucket = idx;
		}

		/* fill out the entry with the provided data */
		oidc_cache_shm_entry_t *t = oidc_cache_shm_slot(hdr, idx);
		_oidc_strncpy(t->section_key, section_key, OIDC_CACHE_SHM_KEY_MAX - 1);
		/* strncpy does not NUL-terminate when the source is exactly OIDC_CACHE_SHM_KEY_MAX - 1
		 * characters long, so terminate explicitly to avoid an over-read on subsequent compares */
		t->section_key[OIDC_CACHE_SHM_KEY_MAX - 1] = '\0';
		_oidc_strcpy(t->value, value);
		t->expires = expiry;
		t->access = current_time;
	}

	/* release the global lock */
	oidc_cache_mutex_unlock(r->pool, r->server, context->mutex);

	return TRUE;
}

static int oidc_cache_shm_destroy(apr_pool_t *pool, server_rec *s) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(s->module_config, &auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *)cfg->cache.cfg;
	apr_status_t rv = APR_SUCCESS;

	oidc_slog(s, APLOG_TRACE1, "destroy: %pp (shm=%pp,s=%pp, p=%d)", context, context ? context->shm : 0, s,
		  context ? context->is_parent : -1);

	if (context && (context->is_parent == TRUE) && (context->shm) && (context->mutex)) {
		oidc_cache_mutex_lock(pool, s, context->mutex);
		rv = apr_shm_destroy(context->shm);
		oidc_sdebug(s, "apr_shm_destroy returned: %d", rv);
		context->shm = NULL;
		oidc_cache_mutex_unlock(pool, s, context->mutex);
	}

	if (context && (context->mutex)) {
		if (oidc_cache_mutex_destroy(s, context->mutex) != TRUE)
			rv = APR_EGENERAL;
		context->mutex = NULL;
	}

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
