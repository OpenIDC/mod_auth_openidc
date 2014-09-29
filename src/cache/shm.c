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
 * Copyright (C) 2013-2014 Ping Identity Corporation
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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <unistd.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "../mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

typedef struct oidc_cache_cfg_shm_t {
	char *mutex_filename;
	apr_shm_t *shm;
	apr_global_mutex_t *mutex;
} oidc_cache_cfg_shm_t;

/* size of key in cached key/value pairs */
#define OIDC_CACHE_SHM_KEY_MAX 128
/* max value size */
#define OIDC_CACHE_SHM_VALUE_MAX 16384

/* represents one (fixed size) cache entry, cq. name/value string pair */
typedef struct oidc_cache_shm_entry_t {
	/* name of the cache entry */
	char section_key[OIDC_CACHE_SHM_KEY_MAX];
	/* value of the cache entry */
	char value[OIDC_CACHE_SHM_VALUE_MAX];
	/* last (read) access timestamp */
	apr_time_t access;
	/* expiry timestamp */
	apr_time_t expires;
} oidc_cache_shm_entry_t;

/* create the cache context */
static void *oidc_cache_shm_cfg_create(apr_pool_t *pool) {
	oidc_cache_cfg_shm_t *context = apr_pcalloc(pool,
			sizeof(oidc_cache_cfg_shm_t));
	context->mutex_filename = NULL;
	context->shm = NULL;
	context->mutex = NULL;
	return context;
}

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
			sizeof(oidc_cache_shm_entry_t) * cfg->cache_shm_size_max,
			NULL, s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "apr_shm_create failed to create shared memory segment");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* initialize the whole segment to '/0' */
	int i;
	oidc_cache_shm_entry_t *table = apr_shm_baseaddr_get(context->shm);
	for (i = 0; i < cfg->cache_shm_size_max; i++) {
		table[i].section_key[0] = '\0';
		table[i].access = 0;
	}

	const char *dir;
	apr_temp_dir_get(&dir, s->process->pool);
	/* construct the mutex filename */
	context->mutex_filename = apr_psprintf(s->process->pool,
			"%s/httpd_mutex.%ld.%pp", dir, (long int) getpid(), s);

	/* create the mutex lock */
	rv = apr_global_mutex_create(&context->mutex,
			(const char *) context->mutex_filename, APR_LOCK_DEFAULT,
			s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"apr_global_mutex_create failed to create mutex on file %s",
				context->mutex_filename);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* need this on Linux */
#ifdef AP_NEED_SET_MUTEX_PERMS
#if MODULE_MAGIC_NUMBER_MAJOR >= 20081201
	rv = ap_unixd_set_global_mutex_perms(context->mutex);
#else
	rv = unixd_set_global_mutex_perms(context->mutex);
#endif
	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"unixd_set_global_mutex_perms failed; could not set permissions ");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
#endif

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
	apr_status_t rv = apr_global_mutex_child_init(&context->mutex,
			(const char *) context->mutex_filename, p);

	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"apr_global_mutex_child_init failed to reopen mutex on file %s",
				context->mutex_filename);
	}

	return rv;
}

/*
 * assemble single key name based on section/key input
 */
static char *oidc_cache_shm_get_key(apr_pool_t *pool, const char *section,
		const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
}

/*
 * get a value from the shared memory cache
 */
static apr_byte_t oidc_cache_shm_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	oidc_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *) cfg->cache_cfg;

	apr_status_t rv;
	int i;
	const char *section_key = oidc_cache_shm_get_key(r->pool, section, key);

	*value = NULL;

	/* grab the global lock */
	if ((rv = apr_global_mutex_lock(context->mutex)) != APR_SUCCESS) {
		oidc_error(r, "apr_global_mutex_lock() failed [%d]", rv);
		return FALSE;
	}

	/* get the pointer to the start of the shared memory block */
	oidc_cache_shm_entry_t *table = apr_shm_baseaddr_get(context->shm);

	/* loop over the block, looking for the key */
	for (i = 0; i < cfg->cache_shm_size_max; i++) {
		const char *tablekey = table[i].section_key;

		if (tablekey == NULL)
			continue;

		if (apr_strnatcmp(tablekey, section_key) == 0) {

			/* found a match, check if it has expired */
			if (table[i].expires > apr_time_now()) {

				/* update access timestamp */
				table[i].access = apr_time_now();
				*value = table[i].value;
			}
		}
	}

	/* release the global lock */
	apr_global_mutex_unlock(context->mutex);

	return (*value == NULL) ? FALSE : TRUE;
}

/*
 * store a value in the shared memory cache
 */
static apr_byte_t oidc_cache_shm_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	oidc_debug(r, "enter, section=\"%s\", key=\"%s\", value size=%llu", section,
			key, value ? (unsigned long long )strlen(value) : 0);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *) cfg->cache_cfg;

	oidc_cache_shm_entry_t *match, *free, *lru;
	oidc_cache_shm_entry_t *table;
	apr_time_t current_time;
	int i;
	apr_time_t age;

	const char *section_key = oidc_cache_shm_get_key(r->pool, section, key);

	/* check that the passed in key is valid */
	if (strlen(section_key) > OIDC_CACHE_SHM_KEY_MAX) {
		oidc_error(r, "could not set value since key is too long (%s)",
				section_key);
		return FALSE;
	}

	/* check that the passed in value is valid */
	if ((value != NULL) && strlen(value) > OIDC_CACHE_SHM_VALUE_MAX) {
		oidc_error(r, "could not set value since value is too long (%zu > %d)",
				strlen(value), OIDC_CACHE_SHM_VALUE_MAX);
		return FALSE;
	}

	/* grab the global lock */
	if (apr_global_mutex_lock(context->mutex) != APR_SUCCESS) {
		oidc_error(r, "apr_global_mutex_lock() failed");
		return FALSE;
	}

	/* get a pointer to the shared memory block */
	table = apr_shm_baseaddr_get(context->shm);

	/* get the current time */
	current_time = apr_time_now();

	/* loop over the block, looking for the key */
	match = NULL;
	free = NULL;
	lru = &table[0];
	for (i = 0; i < cfg->cache_shm_size_max; i++) {

		/* see if this slot is free */
		if (table[i].section_key[0] == '\0') {
			if (free == NULL)
				free = &table[i];
			continue;
		}

		/* see if a value already exists for this key */
		if (apr_strnatcmp(table[i].section_key, section_key) == 0) {
			match = &table[i];
			break;
		}

		/* see if this slot has expired */
		if (table[i].expires <= current_time) {
			if (free == NULL)
				free = &table[i];
			continue;
		}

		/* see if this slot was less recently used than the current pointer */
		if (table[i].access < lru->access) {
			lru = &table[i];
		}

	}

	/* if we have no free slots, issue a warning about the LRU entry */
	if (match == NULL && free == NULL) {
		age = (current_time - lru->access) / 1000000;
		if (age < 3600) {
			oidc_warn(r,
					"dropping LRU entry with age = %" APR_TIME_T_FMT "s, which is less than one hour; consider increasing the shared memory caching space (which is %d now) with the (global) OIDCCacheShmMax setting.",
					age, cfg->cache_shm_size_max);
		}
	}

	oidc_cache_shm_entry_t *t = match ? match : (free ? free : lru);

	if (value != NULL) {

		/* fill out the entry with the provided data */
		strcpy(t->section_key, section_key);
		strcpy(t->value, value);
		t->expires = expiry;
		t->access = current_time;

	} else {

		t->section_key[0] = '\0';
	}

	/* release the global lock */
	apr_global_mutex_unlock(context->mutex);

	return TRUE;
}

static int oidc_cache_shm_destroy(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_shm_t *context = (oidc_cache_cfg_shm_t *) cfg->cache_cfg;
	apr_status_t rv = APR_SUCCESS;

	if (context->shm) {
		rv = apr_shm_destroy(context->shm);
		oidc_sdebug(s, "apr_shm_destroy returned: %d", rv);
		context->shm = NULL;
	}

	if (context->mutex) {
		rv = apr_global_mutex_destroy(context->mutex);
		oidc_sdebug(s, "apr_global_mutex_destroy returned: %d", rv);
		context->mutex = NULL;
	}

	return rv;
}

oidc_cache_t oidc_cache_shm = {
		oidc_cache_shm_cfg_create,
		oidc_cache_shm_post_config,
		oidc_cache_shm_child_init,
		oidc_cache_shm_get,
		oidc_cache_shm_set,
		oidc_cache_shm_destroy
};
