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
 * caching using a memcache backend
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "cache/memcache.h"
#include "cfg/cfg_int.h"
#include "jose.h"
#include "util/util.h"
#include <ap_mpm.h>
#include <apr_optional.h>

/*
 * avoid including mod_http2.h (assume the function signature is stable)
 */
APR_DECLARE_OPTIONAL_FN(void, http2_get_num_workers, (server_rec * s, int *minw, int *max));

/* create the cache context */
static void *oidc_cache_memcache_cfg_create(apr_pool_t *pool) {
	oidc_cache_cfg_memcache_t *context = apr_pcalloc(pool, sizeof(oidc_cache_cfg_memcache_t));
	context->cache_memcache = NULL;
	return context;
}

/*
 * parse a single "host[:port]" entry and register it with the memcache context
 */
static int oidc_cache_memcache_add_server_impl(server_rec *s, apr_pool_t *p, oidc_cache_cfg_memcache_t *context,
					       char *split, apr_uint32_t min, apr_uint32_t smax, apr_uint32_t hmax,
					       apr_interval_time_t ttl) {
	apr_memcache_server_t *st;
	char *host_str;
	char *scope_id;
	apr_port_t port;
	apr_status_t rv;

	/* parse out host and port */
	rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "failed to parse cache server: '%s'", split);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (host_str == NULL) {
		oidc_serror(s, "failed to parse cache server, no hostname specified: '%s'", split);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (port == 0)
		port = 11211;

	oidc_sdebug(s, "creating server: %s:%d, min=%d, smax=%d, hmax=%d, ttl=%" APR_TIME_T_FMT, host_str, port, min,
		    smax, hmax, ttl);

	/* create the memcache server struct */
	rv = apr_memcache_server_create(p, host_str, port, min, smax, hmax, (apr_uint32_t)ttl, &st);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "failed to create cache server: %s:%d", host_str, port);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* add the memcache server struct to the list */
	rv = apr_memcache_add_server(context->cache_memcache, st);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "failed to add cache server: %s:%d", host_str, port);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * validate the configuration, allocate the memcache struct and compute the connection-pool sizes
 *
 * this does not add any servers and therefore does not open a connection, so it can be exercised
 * offline; the actual (connecting) server setup is done in oidc_cache_memcache_add_servers through
 * the injectable context->add_server operation
 */
int oidc_cache_memcache_post_config(apr_pool_t *pool, server_rec *s, oidc_cfg_t *cfg) {

	if (cfg->cache.cfg != NULL)
		return OK;
	oidc_cache_cfg_memcache_t *context = oidc_cache_memcache_cfg_create(pool);
	cfg->cache.cfg = context;

	apr_status_t rv = APR_SUCCESS;
	apr_uint16_t nservers = 0;
	const char *split;
	char *tok;
	APR_OPTIONAL_FN_TYPE(http2_get_num_workers) * get_h2_num_workers;
	int max_threads = 0;
	int minw = 0;
	int maxw = 0;
	apr_uint32_t min = 0;
	apr_uint32_t smax = 0;
	apr_uint32_t hmax = 0;
	apr_interval_time_t ttl = 0;

	if (oidc_cfg_cache_memcache_servers_get(cfg) == NULL) {
		oidc_serror(s, "cache type is set to \"memcache\", but no valid " OIDCMemCacheServers
			       " setting was found");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* loop over the provided memcache servers to find out the number of servers configured */
	char *cache_config = apr_pstrdup(pool, oidc_cfg_cache_memcache_servers_get(cfg));
	split = apr_strtok(cache_config, OIDC_STR_SPACE, &tok);
	while (split) {
		nservers++;
		split = apr_strtok(NULL, OIDC_STR_SPACE, &tok);
	}

	/* allocated space for the number of servers */
	rv = apr_memcache_create(pool, nservers, 0, &context->cache_memcache);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "failed to create memcache object of '%d' size", nservers);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * When mod_http2 is loaded we might have more threads since it has
	 * its own pool of processing threads.
	 */
	ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads);
	get_h2_num_workers = APR_RETRIEVE_OPTIONAL_FN(http2_get_num_workers);
	if (get_h2_num_workers) {
		get_h2_num_workers(s, &minw, &maxw);
		/* So now the max is:
		 * max_threads-1 threads for HTTP/1 each requiring one connection
		 * + one thread for HTTP/2 requiring maxw connections
		 */
		max_threads = max_threads - 1 + maxw;
	}
	min = oidc_cfg_cache_memcache_min_get(cfg);
	smax = oidc_cfg_cache_memcache_smax_get(cfg);
	hmax = oidc_cfg_cache_memcache_hmax_get(cfg);
	ttl = oidc_cfg_cache_memcache_ttl_get(cfg);
	if (max_threads > 0 && hmax == 0) {
		hmax = max_threads;
		if (smax == 0) {
			smax = hmax;
		}
		// NB: min is deliberately left at 0: defaulting it to hmax (or 1) does not
		// work at least on Mac OS X, so retain backwards compatibility with 0
	} else {
		if (hmax == 0) {
			hmax = 1;
		}
		if (smax == 0) {
			smax = 1;
		}
	}
	if (smax > hmax) {
		smax = hmax;
	}
	if (min > smax) {
		min = smax;
	}

	/* store the computed pool sizes so add_servers (and the unit tests) can use them */
	context->min = min;
	context->smax = smax;
	context->hmax = hmax;
	context->ttl = ttl;

	return OK;
}

/*
 * register all configured memcache servers with the context through the (injectable) add_server op
 */
int oidc_cache_memcache_add_servers(apr_pool_t *pool, server_rec *s, const oidc_cfg_t *cfg,
				    oidc_cache_cfg_memcache_t *context) {
	char *tok;
	char *cache_config = apr_pstrdup(pool, oidc_cfg_cache_memcache_servers_get(cfg));
	char *split = apr_strtok(cache_config, OIDC_STR_SPACE, &tok);
	while (split) {
		int rc = context->add_server(s, pool, context, split, context->min, context->smax, context->hmax,
					     context->ttl);
		if (rc != OK)
			return rc;
		split = apr_strtok(NULL, OIDC_STR_SPACE, &tok);
	}

	return OK;
}

/* default data-path operations, wired in oidc_cache_memcache_post_config_impl */
static apr_status_t oidc_cache_memcache_getp_impl(oidc_cache_cfg_memcache_t *context, apr_pool_t *p, const char *key,
						  char **baton, apr_size_t *len);
static apr_status_t oidc_cache_memcache_set_impl(oidc_cache_cfg_memcache_t *context, const char *key, char *baton,
						 apr_size_t len, apr_uint32_t timeout);
static apr_status_t oidc_cache_memcache_delete_impl(oidc_cache_cfg_memcache_t *context, const char *key);
static apr_byte_t oidc_cache_memcache_status_impl(const oidc_cache_cfg_memcache_t *context);

/*
 * initialize the memcache struct to a number of memcache servers
 */
static int oidc_cache_memcache_post_config_impl(apr_pool_t *pool, server_rec *s) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(s->module_config, &auth_openidc_module);

	if (cfg->cache.cfg != NULL)
		return OK;

	if (oidc_cache_memcache_post_config(pool, s, cfg) != OK)
		return HTTP_INTERNAL_SERVER_ERROR;

	oidc_cache_cfg_memcache_t *context = (oidc_cache_cfg_memcache_t *)cfg->cache.cfg;

	/* wire the real (connecting) per-server operation and the apr_memcache data-path operations */
	context->add_server = oidc_cache_memcache_add_server_impl;
	context->getp = oidc_cache_memcache_getp_impl;
	context->set = oidc_cache_memcache_set_impl;
	context->del = oidc_cache_memcache_delete_impl;
	context->status = oidc_cache_memcache_status_impl;

	return oidc_cache_memcache_add_servers(pool, s, cfg, context);
}

#define OIDC_CACHE_MEMCACHE_STATUS_ERR_SIZE 64

/*
 * printout readable error messages about memcache failures
 */
static void oidc_cache_memcache_log_status_error(request_rec *r, const char *s, apr_status_t rv) {
	char s_err[OIDC_CACHE_MEMCACHE_STATUS_ERR_SIZE];
	apr_strerror(rv, s_err, OIDC_CACHE_MEMCACHE_STATUS_ERR_SIZE);
	oidc_error(r, "%s returned an error: [%s]; check your that your memcache server is available/accessible.", s,
		   s_err);
}

/*
 * assemble single key name based on section/key input
 */
static char *oidc_cache_memcache_get_key(request_rec *r, const char *section, const char *key) {
	char *hashed = NULL;
	const char *section_key = apr_psprintf(r->pool, "%s:%s", section, key);
	/* hash the key so it always satisfies memcached's key constraints (<= 250 bytes, no whitespace or
	 * control characters), independent of the (possibly attacker-supplied) key contents and of whether
	 * OIDCCacheEncrypt is enabled */
	if (oidc_util_hash_string_and_base64url_encode(r, OIDC_JOSE_ALG_SHA256, section_key, &hashed) == FALSE) {
		oidc_error(r, "oidc_util_hash_string_and_base64url_encode returned an error");
		return NULL;
	}
	return hashed;
}

/*
 * check dead/alive status for all servers
 */
static apr_byte_t oidc_cache_memcache_status_impl(const oidc_cache_cfg_memcache_t *context) {
	for (int i = 0; i < context->cache_memcache->ntotal; i++) {
		if (context->cache_memcache->live_servers[i]->status != APR_MC_SERVER_DEAD)
			return TRUE;
	}
	return FALSE;
}

/* default getp operation: read a value from the configured memcache server(s) */
static apr_status_t oidc_cache_memcache_getp_impl(oidc_cache_cfg_memcache_t *context, apr_pool_t *p, const char *key,
						  char **baton, apr_size_t *len) {
	return apr_memcache_getp(context->cache_memcache, p, key, baton, len, NULL);
}

/* default set operation: store a value on the configured memcache server(s) */
static apr_status_t oidc_cache_memcache_set_impl(oidc_cache_cfg_memcache_t *context, const char *key, char *baton,
						 apr_size_t len, apr_uint32_t timeout) {
	return apr_memcache_set(context->cache_memcache, key, baton, len, timeout, 0);
}

/* default delete operation: remove a value from the configured memcache server(s) */
static apr_status_t oidc_cache_memcache_delete_impl(oidc_cache_cfg_memcache_t *context, const char *key) {
	return apr_memcache_delete(context->cache_memcache, key, 0);
}

/*
 * get a name/value pair from memcache
 */
apr_byte_t oidc_cache_memcache_get(request_rec *r, const char *section, const char *key, char **value) {

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_cache_cfg_memcache_t *context = (oidc_cache_cfg_memcache_t *)cfg->cache.cfg;

	apr_size_t len = 0;

	const char *s_key = oidc_cache_memcache_get_key(r, section, key);
	if (s_key == NULL)
		return FALSE;

	/* get it */
	apr_status_t rv = context->getp(context, r->pool, s_key, value, &len);

	if (rv == APR_NOTFOUND) {

		/*
		 * NB: workaround the fact that the apr_memcache returns APR_NOTFOUND if a server has been marked dead
		 */
		if (context->status(context) == FALSE) {

			oidc_cache_memcache_log_status_error(r, "apr_memcache_getp", rv);

			return FALSE;
		}

		oidc_debug(r, "apr_memcache_getp: key %s not found in cache", s_key);

		return TRUE;

	} else if (rv != APR_SUCCESS) {

		oidc_cache_memcache_log_status_error(r, "apr_memcache_getp", rv);

		return FALSE;
	}

	/* do sanity checking on the string value */
	if ((*value) && (_oidc_strlen(*value) != len)) {
		oidc_error(r,
			   "apr_memcache_getp returned less bytes than expected: _oidc_strlen(value) [%zu] != len "
			   "[%" APR_SIZE_T_FMT "]",
			   _oidc_strlen(*value), len);
		return FALSE;
	}

	return TRUE;
}

/*
 * store a name/value pair in memcache
 */
apr_byte_t oidc_cache_memcache_set(request_rec *r, const char *section, const char *key, const char *value,
				   apr_time_t expiry) {

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_cache_cfg_memcache_t *context = (oidc_cache_cfg_memcache_t *)cfg->cache.cfg;

	apr_status_t rv = APR_SUCCESS;

	const char *s_key = oidc_cache_memcache_get_key(r, section, key);
	if (s_key == NULL)
		return FALSE;

	/* see if we should be clearing this entry */
	if (value == NULL) {

		rv = context->del(context, s_key);

		if (rv == APR_NOTFOUND) {
			oidc_debug(r, "apr_memcache_delete: key %s not found in cache", s_key);
			rv = APR_SUCCESS;
		} else if (rv != APR_SUCCESS) {
			oidc_cache_memcache_log_status_error(r, "apr_memcache_delete", rv);
		}

	} else {

		/* calculate the timeout as a Unix timestamp which allows values > 30 days */
		apr_uint32_t timeout = (apr_uint32_t)apr_time_sec(expiry);

		/* store it */
		rv = context->set(context, s_key, (char *)value, _oidc_strlen(value), timeout);

		if (rv != APR_SUCCESS) {
			oidc_cache_memcache_log_status_error(r, "apr_memcache_set", rv);
		}
	}

	return (rv == APR_SUCCESS);
}

// clang-format off

oidc_cache_t oidc_cache_memcache = {
    "memcache",
	1,
	oidc_cache_memcache_post_config_impl,
	NULL,
	oidc_cache_memcache_get,
	oidc_cache_memcache_set,
	NULL
};

// clang-format on
