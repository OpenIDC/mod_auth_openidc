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
 * Copyright (C) 2017-2021 ZmartZone Holding BV
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
 * caching using a Redis backend
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#include "apr_general.h"
#include "apr_strings.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include "../mod_auth_openidc.h"

#include "hiredis/hiredis.h"

// TODO: proper Redis error reporting (server unreachable etc.)

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

typedef struct oidc_cache_cfg_redis_t {
	oidc_cache_mutex_t *mutex;
	char *host_str;
	apr_port_t port;
	char *passwd;
	int database;
	struct timeval connect_timeout;
	struct timeval timeout;
	redisContext *ctx;
} oidc_cache_cfg_redis_t;

#define REDIS_CONNECT_TIMEOUT_DEFAULT 5
#define REDIS_TIMEOUT_DEFAULT 5

/* create the cache context */
static void *oidc_cache_redis_cfg_create(apr_pool_t *pool) {
	oidc_cache_cfg_redis_t *context = apr_pcalloc(pool,
			sizeof(oidc_cache_cfg_redis_t));
	context->mutex = oidc_cache_mutex_create(pool);
	context->host_str = NULL;
	context->passwd = NULL;
	context->database = -1;
	context->connect_timeout.tv_sec = REDIS_CONNECT_TIMEOUT_DEFAULT;
	context->connect_timeout.tv_usec = 0;
	context->timeout.tv_sec = REDIS_TIMEOUT_DEFAULT;
	context->timeout.tv_usec = 0;
	context->ctx = NULL;
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
				"cache type is set to \"redis\", but no valid " OIDCRedisCacheServer " setting was found");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char* scope_id;
	rv = apr_parse_addr_port(&context->host_str, &scope_id, &context->port,
			cfg->cache_redis_server, s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "failed to parse cache server: '%s'",
				cfg->cache_redis_server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (context->host_str == NULL) {
		oidc_serror(s,
				"failed to parse cache server, no hostname specified: '%s'",
				cfg->cache_redis_server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (context->port == 0)
		context->port = 6379;

	if (cfg->cache_redis_password != NULL) {
		context->passwd = apr_pstrdup(s->process->pool,
				cfg->cache_redis_password);
	}

	if (cfg->cache_redis_database != -1)
		context->database = cfg->cache_redis_database;

	if (cfg->cache_redis_connect_timeout != -1)
		context->connect_timeout.tv_sec = cfg->cache_redis_connect_timeout;

	if (cfg->cache_redis_timeout != -1)
		context->timeout.tv_sec = cfg->cache_redis_timeout;

	if (oidc_cache_mutex_post_config(s, context->mutex, "redis") == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

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
	return oidc_cache_mutex_child_init(p, s, context->mutex);
}

/*
 * assemble single key name based on section/key input
 */
static char *oidc_cache_redis_get_key(apr_pool_t *pool, const char *section,
		const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
}

/*
 * free resources allocated for the per-process Redis connection context
 */
static apr_status_t oidc_cache_redis_free(oidc_cache_cfg_redis_t *context) {
	if ((context != NULL) && (context->ctx != NULL)) {
		redisFree(context->ctx);
		context->ctx = NULL;
	}
	return APR_SUCCESS;
}

/*
 * free and nullify a reply object
 */
static void oidc_cache_redis_reply_free(redisReply **reply) {
	if (*reply != NULL) {
		freeReplyObject(*reply);
		*reply = NULL;
	}
}

/*
 * connect to Redis server
 */
static apr_status_t oidc_cache_redis_connect(request_rec *r,
		oidc_cache_cfg_redis_t *context) {

	redisReply *reply = NULL;

	if (context->ctx == NULL) {

		/* no connection, connect to the configured Redis server */
		oidc_debug(r, "calling redisConnectWithTimeout");
		context->ctx = redisConnectWithTimeout(context->host_str, context->port, context->connect_timeout);

		/* check for errors */
		if ((context->ctx == NULL) || (context->ctx->err != 0)) {
			oidc_error(r, "failed to connect to Redis server (%s:%d): '%s'",
					context->host_str, context->port,
					context->ctx != NULL ? context->ctx->errstr : "");
			oidc_cache_redis_free(context);
		} else {
			/* log the connection */
			oidc_debug(r, "successfully connected to Redis server (%s:%d)",
					context->host_str, context->port);

			/* see if we need to authenticate to the Redis server */
			if (context->passwd != NULL) {
				reply = redisCommand(context->ctx, "AUTH %s", context->passwd);
				if ((reply == NULL) || (reply->type == REDIS_REPLY_ERROR))
					oidc_error(r,
							"Redis AUTH command (%s:%d) failed: '%s' [%s]",
							context->host_str, context->port,
							context->ctx->errstr, reply ? reply->str : "<n/a>");
				else
					oidc_debug(r,
							"successfully authenticated to the Redis server: %s",
							reply ? reply->str : "<n/a>");

				/* free the auth answer */
				oidc_cache_redis_reply_free(&reply);
			}

			/* see if we need to set the database */
			if (context->database != -1) {
				reply = redisCommand(context->ctx, "SELECT %d",
						context->database);
				if ((reply == NULL) || (reply->type == REDIS_REPLY_ERROR))
					oidc_error(r,
							"Redis SELECT command (%s:%d) failed: '%s' [%s]",
							context->host_str, context->port,
							context->ctx->errstr, reply ? reply->str : "<n/a>");
				else
					oidc_debug(r,
							"successfully selected database %d on the Redis server: %s",
							context->database, reply ? reply->str : "<n/a>");

				/* free the database answer */
				oidc_cache_redis_reply_free(&reply);
			}

			if (redisSetTimeout(context->ctx, context->timeout) != REDIS_OK)
				oidc_error(r, "redisSetTimeout failed: %s", context->ctx->errstr);

		}
	}

	return (context->ctx != NULL) ? APR_SUCCESS : APR_EGENERAL;
}

#define OIDC_REDIS_MAX_TRIES 2

/*
 * execute Redis command and deal with return value
 */
static redisReply* oidc_cache_redis_command(request_rec *r,
		oidc_cache_cfg_redis_t *context, const char *format, ...) {

	redisReply *reply = NULL;
	int i = 0;
	va_list ap;
	va_start(ap, format);

	/* try to execute a command at max 2 times while reconnecting */
	for (i = 0; i < OIDC_REDIS_MAX_TRIES; i++) {

		/* connect */
		if (oidc_cache_redis_connect(r, context) != APR_SUCCESS)
			break;

		/* execute the actual command */
		reply = redisvCommand(context->ctx, format, ap);

		/* check for errors, need to return error replies for cache miss case REDIS_REPLY_NIL */
		if ((reply != NULL) && (reply->type != REDIS_REPLY_ERROR))
			/* break the loop and return the reply */
			break;

		/* something went wrong, log it */
		oidc_error(r,
				"Redis command (attempt=%d to %s:%d) failed, disconnecting: '%s' [%s]",
				i, context->host_str, context->port, context->ctx->errstr,
				reply ? reply->str : "<n/a>");

		/* free the reply (if there is one allocated) */
		oidc_cache_redis_reply_free(&reply);

		/* cleanup, we may try again (once) after reconnecting */
		oidc_cache_redis_free(context);
	}

	va_end(ap);

	return reply;
}

/*
 * get a name/value pair from Redis
 */
static apr_byte_t oidc_cache_redis_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *) cfg->cache_cfg;
	redisReply *reply = NULL;
	apr_byte_t rv = FALSE;

	/* grab the global lock */
	if (oidc_cache_mutex_lock(r->server, context->mutex) == FALSE)
		return FALSE;

	/* get */
	reply =
			oidc_cache_redis_command(r, context, "GET %s", oidc_cache_redis_get_key(r->pool, section, key));

	if (reply == NULL)
		goto end;

	/* check that we got a string back */
	if (reply->type == REDIS_REPLY_NIL) {
		/* this is a normal cache miss, so we'll return OK */
		rv = TRUE;
		goto end;
	}

	if (reply->type != REDIS_REPLY_STRING) {
		oidc_error(r, "redisCommand reply type is not string: %d", reply->type);
		goto end;
	}

	/* do a sanity check on the returned value */
	if ((reply->str == NULL)
			|| (reply->len != strlen(reply->str))) {
		oidc_error(r,
				"redisCommand reply->len (%d) != strlen(reply->str): '%s'",
				(int )reply->len, reply->str);
		goto end;
	}

	/* copy it in to the request memory pool */
	*value = apr_pstrdup(r->pool, reply->str);

	/* return success */
	rv = TRUE;

end:
	/* free the reply object resources */
	oidc_cache_redis_reply_free(&reply);

	/* unlock the global mutex */
	oidc_cache_mutex_unlock(r->server, context->mutex);

	/* return the status */
	return rv;
}

/*
 * store a name/value pair in Redis
 */
static apr_byte_t oidc_cache_redis_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *) cfg->cache_cfg;
	redisReply *reply = NULL;
	apr_byte_t rv = FALSE;
	apr_uint32_t timeout;

	/* grab the global lock */
	if (oidc_cache_mutex_lock(r->server, context->mutex) == FALSE)
		return FALSE;

	/* see if we should be clearing this entry */
	if (value == NULL) {

		/* delete it */
		reply =
				oidc_cache_redis_command(r, context, "DEL %s", oidc_cache_redis_get_key(r->pool, section, key));

	} else {

		/* calculate the timeout from now */
		timeout = apr_time_sec(expiry - apr_time_now());

		/* store it */
		reply =
				oidc_cache_redis_command(r, context, "SETEX %s %d %s", oidc_cache_redis_get_key(r->pool, section, key), timeout, value);

	}

	rv = (reply != NULL) && (reply->type != REDIS_REPLY_ERROR);

	/* free the reply object resources */
	oidc_cache_redis_reply_free(&reply);

	/* unlock the global mutex */
	oidc_cache_mutex_unlock(r->server, context->mutex);

	/* return the status */
	return rv;
}

static int oidc_cache_redis_destroy(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *) cfg->cache_cfg;

	if (context != NULL) {
		// TODO: why do we need this check...? it is set/checked to null inside of oidc_cache_redis_free, no?
		if (context->ctx != NULL) {
			oidc_cache_mutex_lock(s, context->mutex);
			oidc_cache_redis_free(context);
			oidc_cache_mutex_unlock(s, context->mutex);
		}
		oidc_cache_mutex_destroy(s, context->mutex);
	}

	return APR_SUCCESS;
}

oidc_cache_t oidc_cache_redis = {
		"redis",
		1,
		oidc_cache_redis_post_config,
		oidc_cache_redis_child_init,
		oidc_cache_redis_get,
		oidc_cache_redis_set,
		oidc_cache_redis_destroy
};
