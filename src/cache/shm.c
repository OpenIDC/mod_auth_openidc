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
 * Copyright (C) 2017-2019 ZmartZone IAM
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include "apr_shm.h"

#include "../mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

typedef struct oidc_cache_cfg_shm_t {
	apr_shm_t *shm;
	oidc_cache_mutex_t *mutex;
} oidc_cache_cfg_shm_t;

/* size of key in cached key/value pairs */
#define OIDC_CACHE_SHM_KEY_MAX 512

/* represents one (fixed size) cache entry, cq. name/value string pair */
typedef struct oidc_cache_shm_entry_t {
	/* name of the cache entry */
	char section_key[OIDC_CACHE_SHM_KEY_MAX];
	/* last (read) access timestamp */
	apr_time_t access;
	/* expiry timestamp */
	apr_time_t expires;
	/* value of the cache entry */
	char value[];
} oidc_cache_shm_entry_t;

/* create the cache context */
static void *oidc_cache_shm_cfg_create(apr_pool_t *pool) {
	oidc_cache_cfg_shm_t *context = apr_pcalloc(pool,
			sizeof(oidc_cache_cfg_shm_t));
	context->shm = NULL;
	context->mutex = oidc_cache_mutex_create(pool);
	return context;
}

#define OIDC_CACHE_SHM_ADD_OFFSET(t, size) t = (oidc_cache_shm_entry_t *)((uint8_t *)t + size)

/*
 * initialized the shared memory block in the parent process
 */
int oidc_cache_shm_post_config(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&auth_openidc_module);

	if (cfg->cache_cfg != NULL)
		return APR_SUCCESS;
	oidc_cache_cfg_shm_t *context = oidc_cache_shm_cfg_create(s->process->pool);
	cfg->cache_cfg = context;

	/* create the shared memory segment */
	apr_status_t rv = apr_shm_create(&context->shm,
			(apr_size_t) cfg->cache_shm_entry_size_max
			* cfg->cache_shm_size_max,
			NULL, s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "apr_shm_create failed to create shared memory segment");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* initialize the whole segment to '/0' */
	int i;
	oidc_cache_shm_entry_t *t = apr_shm_baseaddr_get(context->shm);
	for (i = 0; i < cfg->cache_shm_size_max;
			i++, OIDC_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {
		t->section_key[0] = '\0';
		t->access = 0;
	}

	if (oidc_cache_mutex_post_config(s, context->mutex, "shm") == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	oidc_sdebug(s,
			"initialized shared memory with a cache size (# entries) of: %d, and a max (single) entry size of: %d",
			cfg->cache_shm_size_max, cfg->cache_shm_entry_size_max);

	return OK;
}

/*
 * initialize the shared memory segment in a child process
 */
int oidc_cache_shm_child_init(apr_pool_t *p, server_rec *s) {
	oidc_cfg *cfg = ap_get_module_config(s->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *) cfg->cache_cfg;

	/* initialize the lock for the child process */
	return oidc_cache_mutex_child_init(p, s, context->mutex);
}

/*
 * assemble single key name based on section/key input
 */
static char *oidc_cache_shm_get_key(request_rec *r, const char *section,
		const char *key) {

	char *section_key = apr_psprintf(r->pool, "%s:%s", section, key);

	/* check that the passed in key is valid */
	if (strlen(section_key) >= OIDC_CACHE_SHM_KEY_MAX) {
		oidc_error(r,
				"could not construct cache key since key size is too large (%d >= %d) (%s)",
				(int )strlen(section_key), OIDC_CACHE_SHM_KEY_MAX, section_key);
		return NULL;
	}

	return section_key;
}

/*
 * get a value from the shared memory cache
 */
static apr_byte_t oidc_cache_shm_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *) cfg->cache_cfg;

	int i;
	const char *section_key = oidc_cache_shm_get_key(r, section, key);
	if (section_key == NULL)
		return FALSE;

	*value = NULL;

	/* grab the global lock */
	if (oidc_cache_mutex_lock(r->server, context->mutex) == FALSE)
		return FALSE;

	/* get the pointer to the start of the shared memory block */
	oidc_cache_shm_entry_t *t = apr_shm_baseaddr_get(context->shm);

	/* loop over the block, looking for the key */
	for (i = 0; i < cfg->cache_shm_size_max;
			i++, OIDC_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {
		const char *tablekey = t->section_key;

		if ((tablekey != NULL) && (apr_strnatcmp(tablekey, section_key) == 0)) {

			/* found a match, check if it has expired */
			if (t->expires > apr_time_now()) {

				/* update access timestamp */
				t->access = apr_time_now();
				*value = t->value;

			} else {

				/* clear the expired entry */
				t->section_key[0] = '\0';
				t->access = 0;

			}

			/* we safely can break now since we would not have found an expired match twice */
			break;
		}
	}

	/* release the global lock */
	oidc_cache_mutex_unlock(r->server, context->mutex);

	return TRUE;
}

/*
 * store a value in the shared memory cache
 */
static apr_byte_t oidc_cache_shm_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *) cfg->cache_cfg;

	oidc_cache_shm_entry_t *match, *free, *lru;
	oidc_cache_shm_entry_t *t;
	apr_time_t current_time;
	int i;
	apr_time_t age;

	const char *section_key = oidc_cache_shm_get_key(r, section, key);
	if (section_key == NULL)
		return FALSE;

	/* check that the passed in value is valid */
	if ((value != NULL)
			&& (strlen(value)
					> (cfg->cache_shm_entry_size_max
							- sizeof(oidc_cache_shm_entry_t)))) {
		oidc_error(r,
				"could not store value since value size is too large (%llu > %lu); consider increasing " OIDCCacheShmEntrySizeMax "",
				(unsigned long long )strlen(value),
				(unsigned long )(cfg->cache_shm_entry_size_max
						- sizeof(oidc_cache_shm_entry_t)));
		return FALSE;
	}

	/* grab the global lock */
	if (oidc_cache_mutex_lock(r->server, context->mutex) == FALSE)
		return FALSE;

	/* get a pointer to the shared memory block */
	t = apr_shm_baseaddr_get(context->shm);

	/* get the current time */
	current_time = apr_time_now();

	/* loop over the block, looking for the key */
	match = NULL;
	free = NULL;
	lru = t;
	for (i = 0; i < cfg->cache_shm_size_max;
			i++, OIDC_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {

		/* see if this slot is free */
		if (t->section_key[0] == '\0') {
			if (free == NULL)
				free = t;
			continue;
		}

		/* see if a value already exists for this key */
		if (apr_strnatcmp(t->section_key, section_key) == 0) {
			match = t;
			break;
		}

		/* see if this slot has expired */
		if (t->expires <= current_time) {
			if (free == NULL)
				free = t;
			continue;
		}

		/* see if this slot was less recently used than the current pointer */
		if (t->access < lru->access) {
			lru = t;
		}

	}

	/* if we have no free slots, issue a warning about the LRU entry */
	if (match == NULL && free == NULL) {
		age = (current_time - lru->access) / 1000000;
		if (age < 3600) {
			oidc_warn(r,
					"dropping LRU entry with age = %" APR_TIME_T_FMT "s, which is less than one hour; consider increasing the shared memory caching space (which is %d now) with the (global) " OIDCCacheShmMax " setting.",
					age, cfg->cache_shm_size_max);
		}
	}

	/* pick the best slot: choose one with a matching key over a free slot, over a least-recently-used one */
	t = match ? match : (free ? free : lru);

	/* see if we need to clear or set the value */
	if (value != NULL) {

		/* fill out the entry with the provided data */
		strcpy(t->section_key, section_key);
		strcpy(t->value, value);
		t->expires = expiry;
		t->access = current_time;

	} else {

		t->section_key[0] = '\0';
		t->access = 0;

	}

	/* release the global lock */
	oidc_cache_mutex_unlock(r->server, context->mutex);

	return TRUE;
}

static int oidc_cache_shm_destroy(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *) cfg->cache_cfg;
	apr_status_t rv = APR_SUCCESS;

	if (context == NULL)
		return rv;

	if (context->shm) {
		oidc_cache_mutex_lock(s, context->mutex);
		if (*context->mutex->sema == 1) {
			rv = apr_shm_destroy(context->shm);
			oidc_sdebug(s, "apr_shm_destroy returned: %d", rv);
		}
		context->shm = NULL;
		oidc_cache_mutex_unlock(s, context->mutex);
	}

	if (context->mutex == NULL)
		return rv;

	oidc_cache_mutex_destroy(s, context->mutex);
	context->mutex = NULL;

	return rv;
}

oidc_cache_t oidc_cache_shm = {
		"shm",
		0,
		oidc_cache_shm_post_config,
		oidc_cache_shm_child_init,
		oidc_cache_shm_get,
		oidc_cache_shm_set,
		oidc_cache_shm_destroy
};
