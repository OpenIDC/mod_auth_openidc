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
 * Copyright (C) 2013-2016 Ping Identity Corporation
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
 * caching using a memcache backend
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include "apr_general.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_memcache.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include "../mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

typedef struct oidc_cache_cfg_memcache_t {
	/* cache_type = memcache: memcache ptr */
	apr_memcache_t *cache_memcache;
} oidc_cache_cfg_memcache_t;

/* create the cache context */
static void *oidc_cache_memcache_cfg_create(apr_pool_t *pool) {
	oidc_cache_cfg_memcache_t *context = apr_pcalloc(pool,
			sizeof(oidc_cache_cfg_memcache_t));
	context->cache_memcache = NULL;
	return context;
}

/*
 * initialize the memcache struct to a number of memcache servers
 */
static int oidc_cache_memcache_post_config(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&auth_openidc_module);

	if (cfg->cache_cfg != NULL)
		return APR_SUCCESS;
	oidc_cache_cfg_memcache_t *context = oidc_cache_memcache_cfg_create(
			s->process->pool);
	cfg->cache_cfg = context;

	apr_status_t rv = APR_SUCCESS;
	int nservers = 0;
	char* split;
	char* tok;
	apr_pool_t *p = s->process->pool;

	if (cfg->cache_memcache_servers == NULL) {
		oidc_serror(s,
				"cache type is set to \"memcache\", but no valid OIDCMemCacheServers setting was found");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* loop over the provided memcache servers to find out the number of servers configured */
	char *cache_config = apr_pstrdup(p, cfg->cache_memcache_servers);
	split = apr_strtok(cache_config, " ", &tok);
	while (split) {
		nservers++;
		split = apr_strtok(NULL, " ", &tok);
	}

	/* allocated space for the number of servers */
	rv = apr_memcache_create(p, nservers, 0, &context->cache_memcache);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "failed to create memcache object of '%d' size",
				nservers);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* loop again over the provided servers */
	cache_config = apr_pstrdup(p, cfg->cache_memcache_servers);
	split = apr_strtok(cache_config, " ", &tok);
	while (split) {
		apr_memcache_server_t* st;
		char* host_str;
		char* scope_id;
		apr_port_t port;

		/* parse out host and port */
		rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
		if (rv != APR_SUCCESS) {
			oidc_serror(s, "failed to parse cache server: '%s'", split);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (host_str == NULL) {
			oidc_serror(s,
					"failed to parse cache server, no hostname specified: '%s'",
					split);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (port == 0)
			port = 11211;

		/* create the memcache server struct */
		// TODO: tune this
		rv = apr_memcache_server_create(p, host_str, port, 0, 1, 1, 60, &st);
		if (rv != APR_SUCCESS) {
			oidc_serror(s, "failed to create cache server: %s:%d", host_str,
					port);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* add the memcache server struct to the list */
		rv = apr_memcache_add_server(context->cache_memcache, st);
		if (rv != APR_SUCCESS) {
			oidc_serror(s, "failed to add cache server: %s:%d", host_str, port);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* go to the next entry */
		split = apr_strtok(NULL, " ", &tok);
	}

	return OK;
}

#define OIDC_CACHE_MEMCACHE_STATUS_ERR_SIZE  64

/*
 * printout readable error messages about memcache failures
 */
static void oidc_cache_memcache_log_status_error(request_rec *r, const char *s,
		apr_status_t rv) {
	char s_err[OIDC_CACHE_MEMCACHE_STATUS_ERR_SIZE];
	apr_strerror(rv, s_err, OIDC_CACHE_MEMCACHE_STATUS_ERR_SIZE);
	oidc_error(r,
			"%s returned an error: [%s]; check your that your memcache server is available/accessible.",
			s, s_err);
}

/*
 * assemble single key name based on section/key input
 */
static char *oidc_cache_memcache_get_key(apr_pool_t *pool, const char *section,
		const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
}

/*
 * get a name/value pair from memcache
 */
static apr_byte_t oidc_cache_memcache_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	oidc_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_memcache_t *context =
			(oidc_cache_cfg_memcache_t *) cfg->cache_cfg;

	apr_size_t len = 0;

	/* get it */
	apr_status_t rv = apr_memcache_getp(context->cache_memcache, r->pool,
			oidc_cache_memcache_get_key(r->pool, section, key), (char **) value,
			&len, NULL);

	if (rv == APR_NOTFOUND) {
		oidc_debug(r, "apr_memcache_getp: key %s not found in cache",
				oidc_cache_memcache_get_key(r->pool, section, key));
		return FALSE;
	} else if (rv != APR_SUCCESS) {
		oidc_cache_memcache_log_status_error(r, "apr_memcache_getp", rv);
		return FALSE;
	}

	/* do sanity checking on the string value */
	if ((*value) && (strlen(*value) != len)) {
		oidc_error(r,
				"apr_memcache_getp returned less bytes than expected: strlen(value) [%zu] != len [%" APR_SIZE_T_FMT "]",
				strlen(*value), len);
		return FALSE;
	}

	return TRUE;
}

/*
 * store a name/value pair in memcache
 */
static apr_byte_t oidc_cache_memcache_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	oidc_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_memcache_t *context =
			(oidc_cache_cfg_memcache_t *) cfg->cache_cfg;

	apr_status_t rv = APR_SUCCESS;

	/* see if we should be clearing this entry */
	if (value == NULL) {

		rv = apr_memcache_delete(context->cache_memcache,
				oidc_cache_memcache_get_key(r->pool, section, key), 0);

		if (rv == APR_NOTFOUND) {
			oidc_debug(r, "apr_memcache_delete: key %s not found in cache",
					oidc_cache_memcache_get_key(r->pool, section, key));
		} else if (rv != APR_SUCCESS) {
			oidc_cache_memcache_log_status_error(r, "apr_memcache_delete", rv);
		}

	} else {

		/* calculate the timeout from now */
		apr_uint32_t timeout = apr_time_sec(expiry - apr_time_now());

		/* store it */
		rv = apr_memcache_set(context->cache_memcache,
				oidc_cache_memcache_get_key(r->pool, section, key),
				(char *) value, strlen(value), timeout, 0);

		if (rv != APR_SUCCESS) {
			oidc_cache_memcache_log_status_error(r, "apr_memcache_set", rv);
		}
	}

	return (rv == APR_SUCCESS);
}

oidc_cache_t oidc_cache_memcache = {
		1,
		oidc_cache_memcache_cfg_create,
		oidc_cache_memcache_post_config,
		NULL,
		oidc_cache_memcache_get,
		oidc_cache_memcache_set,
		NULL
};
