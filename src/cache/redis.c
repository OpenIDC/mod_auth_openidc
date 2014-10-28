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
 * caching using a Redis backend
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <unistd.h>

#include "apr_general.h"
#include "apr_strings.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "../mod_auth_openidc.h"

#include "hiredis/hiredis.h"

// TODO: proper Redis error reporting (server unreachable etc.)

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

typedef struct oidc_cache_cfg_redis_t {
	/* cache_type = redis: Redis ptr */
	redisContext *ctx;
	apr_global_mutex_t *mutex;
	char *mutex_filename;
} oidc_cache_cfg_redis_t;

/* create the cache context */
static void *oidc_cache_redis_cfg_create(apr_pool_t *pool) {
	oidc_cache_cfg_redis_t *context = apr_pcalloc(pool,
			sizeof(oidc_cache_cfg_redis_t));
	context->ctx = NULL;
	context->mutex = NULL;
	context->mutex_filename = NULL;
	return context;
}

/*
 * initialize the Redis struct the specified Redis server
 */
static int oidc_cache_redis_post_config(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&auth_openidc_module);

	if (cfg->cache_cfg != NULL)
		return APR_SUCCESS;
	oidc_cache_cfg_redis_t *context = oidc_cache_redis_cfg_create(
			s->process->pool);
	cfg->cache_cfg = context;

	apr_status_t rv = APR_SUCCESS;

	/* parse the host:post tuple from the configuration */
	if (cfg->cache_redis_server == NULL) {
		oidc_serror(s,
				"cache type is set to \"redis\", but no valid OIDCRedisCacheServer setting was found");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char* host_str;
	char* scope_id;
	apr_port_t port;
	rv = apr_parse_addr_port(&host_str, &scope_id, &port,
			cfg->cache_redis_server, s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "failed to parse cache server: '%s'",
				cfg->cache_redis_server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (host_str == NULL) {
		oidc_serror(s,
				"failed to parse cache server, no hostname specified: '%s'",
				cfg->cache_redis_server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (port == 0)
		port = 6379;

	/* connect to the configured Redis server */
	context->ctx = redisConnect(host_str, port);

	if ((context->ctx != NULL) && (context->ctx->err)) {
		oidc_serror(s, "failed to connect to Redis server: '%s'",
				context->ctx->errstr);
		return HTTP_INTERNAL_SERVER_ERROR;
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
 * initialize the Redis cache in a child process
 */
int oidc_cache_redis_child_init(apr_pool_t *p, server_rec *s) {
	oidc_cfg *cfg = ap_get_module_config(s->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *) cfg->cache_cfg;

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
static char *oidc_cache_redis_get_key(apr_pool_t *pool, const char *section,
		const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
}

/*
 * get a name/value pair from Redis
 */
static apr_byte_t oidc_cache_redis_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	oidc_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *) cfg->cache_cfg;
	apr_status_t rv;

	/* grab the global lock */
	if ((rv = apr_global_mutex_lock(context->mutex)) != APR_SUCCESS) {
		oidc_error(r, "apr_global_mutex_lock() failed [%d]", rv);
		return FALSE;
	}

	/* get */
	redisReply *reply = redisCommand(context->ctx, "GET %s",
			oidc_cache_redis_get_key(r->pool, section, key));

	/* errors should result in an empty reply */
	if (reply == NULL) {
		oidc_error(r, "redisCommand failed, reply == NULL: '%s'",
				context->ctx->errstr);
		apr_global_mutex_unlock(context->mutex);
		return FALSE;
	}

	/* check that we got a string back */
	if (reply->type != REDIS_REPLY_STRING) {
		freeReplyObject(reply);
		/* this is a normal cache miss, so we'll return OK */
		apr_global_mutex_unlock(context->mutex);
		return TRUE;
	}

	/* do a sanity check on the returned value */
	if (reply->len != strlen(reply->str)) {
		oidc_error(r, "redisCommand reply->len != strlen(reply->str): '%s'",
				reply->str);
		freeReplyObject(reply);
		apr_global_mutex_unlock(context->mutex);
		return FALSE;
	}

	/* copy it in to the request memory pool */
	*value = apr_pstrdup(r->pool, reply->str);
	freeReplyObject(reply);

	/* release the global lock */
	apr_global_mutex_unlock(context->mutex);

	return TRUE;
}

/*
 * store a name/value pair in Redis
 */
static apr_byte_t oidc_cache_redis_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	oidc_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *) cfg->cache_cfg;

	/* grab the global lock */
	if (apr_global_mutex_lock(context->mutex) != APR_SUCCESS) {
		oidc_error(r, "apr_global_mutex_lock() failed");
		return FALSE;
	}

	/* see if we should be clearing this entry */
	if (value == NULL) {

		/* delete it */
		redisReply *reply = redisCommand(context->ctx, "DEL %s",
				oidc_cache_redis_get_key(r->pool, section, key));

		if (reply == NULL) {
			oidc_error(r, "redisCommand failed, reply == NULL: '%s'",
					context->ctx->errstr);

			/* release the global lock */
			apr_global_mutex_unlock(context->mutex);

			return FALSE;
		}

		freeReplyObject(reply);

	} else {

		/* calculate the timeout from now */
		apr_uint32_t timeout = apr_time_sec(expiry - apr_time_now());

		/* store it */
		redisReply *reply = redisCommand(context->ctx, "SETEX %s %d %s",
				oidc_cache_redis_get_key(r->pool, section, key), timeout,
				value);

		if (reply == NULL) {
			oidc_error(r, "redisCommand failed, reply == NULL: '%s'",
					context->ctx->errstr);

			/* release the global lock */
			apr_global_mutex_unlock(context->mutex);

			return FALSE;
		}

		freeReplyObject(reply);

	}

	/* release the global lock */
	apr_global_mutex_unlock(context->mutex);

	return TRUE;
}

static int oidc_cache_redis_destroy(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *) cfg->cache_cfg;
	apr_status_t rv = APR_SUCCESS;

	if (context->ctx) {
		redisFree(context->ctx);
		context->ctx = NULL;
	}
	if (context->mutex) {
		rv = apr_global_mutex_destroy(context->mutex);
		oidc_sdebug(s, "apr_global_mutex_destroy returned: %d", rv);
		context->mutex = NULL;
	}
	return APR_SUCCESS;
}

oidc_cache_t oidc_cache_redis = {
		oidc_cache_redis_cfg_create,
		oidc_cache_redis_post_config,
		oidc_cache_redis_child_init,
		oidc_cache_redis_get,
		oidc_cache_redis_set,
		oidc_cache_redis_destroy
};
