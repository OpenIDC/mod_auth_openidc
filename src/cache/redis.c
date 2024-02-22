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
 * Copyright (C) 2017-2024 ZmartZone Holding BV
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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "redis.h"

// TODO: proper Redis error reporting (server unreachable etc.)

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

#define REDIS_CONNECT_TIMEOUT_DEFAULT 5
#define REDIS_TIMEOUT_DEFAULT 5
#define REDIS_KEEPALIVE_DEFAULT -1

/* create the cache context */
static oidc_cache_cfg_redis_t *oidc_cache_redis_cfg_create(apr_pool_t *pool) {
	oidc_cache_cfg_redis_t *context = apr_pcalloc(pool, sizeof(oidc_cache_cfg_redis_t));
	context->mutex = oidc_cache_mutex_create(pool, FALSE);
	context->username = NULL;
	context->passwd = NULL;
	context->database = -1;
	context->connect_timeout.tv_sec = REDIS_CONNECT_TIMEOUT_DEFAULT;
	context->connect_timeout.tv_usec = 0;
	context->keepalive = REDIS_KEEPALIVE_DEFAULT;
	context->timeout.tv_sec = REDIS_TIMEOUT_DEFAULT;
	context->timeout.tv_usec = 0;
	context->host_str = NULL;
	context->port = 0;
	context->rctx = NULL;
	return context;
}

int oidc_cache_redis_post_config(server_rec *s, oidc_cfg *cfg, const char *name) {
	oidc_cache_cfg_redis_t *context = oidc_cache_redis_cfg_create(s->process->pool);
	cfg->cache_cfg = context;

	/* parse the host:post tuple from the configuration */
	if (cfg->cache_redis_server == NULL) {
		oidc_serror(s,
			    "cache type is set to \"redis\", but no valid " OIDCRedisCacheServer " setting was found");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (cfg->cache_redis_username != NULL) {
		context->username = apr_pstrdup(s->process->pool, cfg->cache_redis_username);
	}
	if (cfg->cache_redis_password != NULL) {
		context->passwd = apr_pstrdup(s->process->pool, cfg->cache_redis_password);
	}

	if (cfg->cache_redis_database != -1)
		context->database = cfg->cache_redis_database;

	if (cfg->cache_redis_connect_timeout != -1)
		context->connect_timeout.tv_sec = cfg->cache_redis_connect_timeout;

	if (cfg->cache_redis_keepalive != -1)
		context->keepalive = cfg->cache_redis_keepalive;

	if (cfg->cache_redis_timeout != -1)
		context->timeout.tv_sec = cfg->cache_redis_timeout;

	if (oidc_cache_mutex_post_config(s, context->mutex, name) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	return OK;
}

static apr_status_t oidc_cache_redis_connect(request_rec *r, oidc_cache_cfg_redis_t *context);

/*
 * free resources allocated for the per-process Redis connection context
 */
apr_status_t oidc_cache_redis_disconnect(oidc_cache_cfg_redis_t *context) {
	if (context != NULL) {
		if (context->rctx != NULL) {
			redisFree(context->rctx);
			context->rctx = NULL;
		}
	}
	return APR_SUCCESS;
}

/*
 * initialize the Redis struct the specified Redis server
 */
static int oidc_cache_redis_post_config_impl(server_rec *s) {
	apr_status_t rv = APR_SUCCESS;
	oidc_cache_cfg_redis_t *context = NULL;
	oidc_cfg *cfg = (oidc_cfg *)ap_get_module_config(s->module_config, &auth_openidc_module);

	if (cfg->cache_cfg != NULL)
		return OK;

	if (oidc_cache_redis_post_config(s, cfg, "redis") != OK)
		return HTTP_INTERNAL_SERVER_ERROR;

	context = (oidc_cache_cfg_redis_t *)cfg->cache_cfg;

	/* parse the host:post tuple from the configuration */
	if (cfg->cache_redis_server == NULL) {
		oidc_serror(s,
			    "cache type is set to \"redis\", but no valid " OIDCRedisCacheServer " setting was found");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char *scope_id;
	rv = apr_parse_addr_port(&context->host_str, &scope_id, &context->port, cfg->cache_redis_server,
				 s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "failed to parse cache server: '%s'", cfg->cache_redis_server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (context->host_str == NULL) {
		oidc_serror(s, "failed to parse cache server, no hostname specified: '%s'", cfg->cache_redis_server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (context->port == 0)
		context->port = 6379;

	context->connect = oidc_cache_redis_connect;
	context->command = oidc_cache_redis_command;
	context->disconnect = oidc_cache_redis_disconnect;

	return OK;
}

/*
 * initialize the Redis cache in a child process
 */
int oidc_cache_redis_child_init(apr_pool_t *p, server_rec *s) {
	oidc_cfg *cfg = ap_get_module_config(s->module_config, &auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *)cfg->cache_cfg;

	/* initialize the lock for the child process */
	return oidc_cache_mutex_child_init(p, s, context->mutex);
}

/*
 * assemble single key name based on section/key input
 */
static char *oidc_cache_redis_get_key(apr_pool_t *pool, const char *section, const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
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

apr_byte_t oidc_cache_redis_set_keepalive(request_rec *r, redisContext *rctx, const int keepalive) {
	apr_byte_t rv = TRUE;

	// default is -1
	if (keepalive == 0) {
		oidc_debug(r, "not setting redisEnableKeepAlive");
		goto end;
	}

#if HIREDIS_MAJOR >= 1 && HIREDIS_MINOR >= 2

	if (keepalive == -1) {
		oidc_debug(r, "setting redisEnableKeepAlive to the default interval");
		if (redisEnableKeepAlive(rctx) != REDIS_OK) {
			oidc_error(r, "redisEnableKeepAlive failed: %s", rctx->errstr);
			rv = FALSE;
		}
		goto end;
	}

	oidc_debug(r, "setting redisEnableKeepAliveWithInterval: %d", keepalive);
	if (redisEnableKeepAliveWithInterval(rctx, keepalive) != REDIS_OK) {
		oidc_error(r, "redisEnableKeepAliveWithInterval failed: %s", rctx->errstr);
		rv = FALSE;
	}

#else

	// -1 or > 0
	oidc_debug(r, "setting redisEnableKeepAlive to the default interval");
	if (redisEnableKeepAlive(rctx) != REDIS_OK) {
		oidc_error(r, "redisEnableKeepAlive failed: %s", rctx->errstr);
		rv = FALSE;
	}

#endif

end:

	return rv;
}

apr_byte_t oidc_cache_redis_set_auth(request_rec *r, redisContext *rctx, const char *username, const char *password) {
	apr_byte_t rv = TRUE;
	redisReply *reply = NULL;

	if (password == NULL)
		goto end;

	if (username != NULL)
		reply = redisCommand(rctx, "AUTH %s %s", username, password);
	else
		reply = redisCommand(rctx, "AUTH %s", password);

	if ((reply == NULL) || (reply->type == REDIS_REPLY_ERROR)) {
		oidc_error(r, "Redis AUTH command failed: '%s' [%s]", rctx->errstr, reply ? reply->str : "<n/a>");
		rv = FALSE;
		goto end;
	}

	oidc_debug(r, "successfully authenticated to the Redis server: %s", reply ? reply->str : "<n/a>");

end:

	oidc_cache_redis_reply_free(&reply);

	return rv;
}

apr_byte_t oidc_cache_redis_set_database(request_rec *r, redisContext *rctx, const int database) {
	apr_byte_t rv = TRUE;
	redisReply *reply = NULL;

	if (database == -1)
		goto end;

	reply = redisCommand(rctx, "SELECT %d", database);
	if ((reply == NULL) || (reply->type == REDIS_REPLY_ERROR)) {
		oidc_error(r, "Redis SELECT command failed: '%s' [%s]", rctx->errstr, reply ? reply->str : "<n/a>");
		rv = FALSE;
		goto end;
	}

	oidc_debug(r, "successfully selected database %d on the Redis server: %s", database,
		   reply ? reply->str : "<n/a>");

end:

	oidc_cache_redis_reply_free(&reply);

	return rv;
}

redisContext *oidc_cache_redis_connect_with_timeout(request_rec *r, const char *host, int port, struct timeval ct,
						    struct timeval t, const char *msg) {
	redisContext *rctx = NULL;

	oidc_debug(r, "calling redisConnectWithTimeout: %d", (int)ct.tv_sec);
	rctx = redisConnectWithTimeout(host, port, ct);

	if ((rctx == NULL) || (rctx->err != 0)) {
		oidc_error(r, "failed to connect to Redis server (%s%s%s:%d): '%s'", msg ? msg : "", msg ? ":" : "",
			   host, port, rctx != NULL ? rctx->errstr : "");
		if (rctx)
			redisFree(rctx);
		return NULL;
	}

	oidc_debug(r, "successfully connected to Redis server (%s%s%s:%d)", msg ? msg : "", msg ? ":" : "", host, port);

	if (redisSetTimeout(rctx, t) != REDIS_OK)
		oidc_error(r, "redisSetTimeout failed: %s", rctx->errstr);

	return rctx;
}

/*
 * connect to Redis server
 */
static apr_status_t oidc_cache_redis_connect(request_rec *r, oidc_cache_cfg_redis_t *context) {

	if (context->rctx != NULL)
		return APR_SUCCESS;

	context->rctx = oidc_cache_redis_connect_with_timeout(r, context->host_str, context->port,
							      context->connect_timeout, context->timeout, NULL);
	if (context->rctx == NULL)
		return APR_EGENERAL;

	oidc_cache_redis_set_keepalive(r, context->rctx, context->keepalive);
	oidc_cache_redis_set_auth(r, context->rctx, context->username, context->passwd);
	oidc_cache_redis_set_database(r, context->rctx, context->database);

	return APR_SUCCESS;
}

redisReply *oidc_cache_redis_command(request_rec *r, oidc_cache_cfg_redis_t *context, char **errstr, const char *format,
				     va_list ap) {
	redisReply *reply = redisvCommand(context->rctx, format, ap);
	*errstr = apr_pstrdup(r->pool, context->rctx->errstr);
	return reply;
}

static int oidc_cache_redis_env2int(request_rec *r, const char *env_var_name, const int default_value) {
	const char *s = r->subprocess_env ? apr_table_get(r->subprocess_env, env_var_name) : NULL;
	return s ? _oidc_str_to_int(s) : default_value;
}

#define OIDC_REDIS_MAX_TRIES_ENV_VAR "OIDC_REDIS_MAX_TRIES"
#define OIDC_REDIS_MAX_TRIES_DEFAULT 2

#define OIDC_REDIS_RETRY_INTERVAL_ENV_VAR "OIDC_REDIS_RETRY_INTERVAL"
#define OIDC_REDIS_RETRY_INTERVAL_DEFAULT 300

#define OIDC_REDIS_WARN_OR_ERROR(cond, r, ...)                                                                         \
	if (cond)                                                                                                      \
		oidc_warn(r, ##__VA_ARGS__);                                                                           \
	else                                                                                                           \
		oidc_error(r, ##__VA_ARGS__);

/*
 * execute Redis command and deal with return value
 */
static redisReply *oidc_cache_redis_exec(request_rec *r, oidc_cache_cfg_redis_t *context, const char *format, ...) {

	redisReply *reply = NULL;
	char *errstr = NULL;
	int i = 0;
	va_list ap;
	int retries = oidc_cache_redis_env2int(r, OIDC_REDIS_MAX_TRIES_ENV_VAR, OIDC_REDIS_MAX_TRIES_DEFAULT);
	apr_time_t interval = apr_time_from_msec(
	    oidc_cache_redis_env2int(r, OIDC_REDIS_RETRY_INTERVAL_ENV_VAR, OIDC_REDIS_RETRY_INTERVAL_DEFAULT));

	/* try to execute a command at max n times while reconnecting */
	for (i = 1; i <= retries; i++) {

		/* connect */
		if (context->connect(r, context) != APR_SUCCESS) {
			OIDC_REDIS_WARN_OR_ERROR(i < retries, r, "Redis connect (attempt=%d/%d to %s:%d) failed", i,
						 retries, context->host_str, context->port);
			if (i < retries) {
				oidc_debug(r, "wait before retrying: %" APR_TIME_T_FMT " (msec)",
					   apr_time_as_msec(interval));
				apr_sleep(interval);
			}
			continue;
		}

		va_start(ap, format);
		/* execute the actual command */
		reply = context->command(r, context, &errstr, format, ap);
		va_end(ap);

		/* check for errors, need to return error replies for cache miss case REDIS_REPLY_NIL */
		if ((reply != NULL) && (reply->type != REDIS_REPLY_ERROR))
			/* break the loop and return the reply */
			break;

		/* something went wrong, log it */
		OIDC_REDIS_WARN_OR_ERROR(
		    i < retries, r, "Redis command (attempt=%d/%d to %s:%d) failed, disconnecting: '%s' [%s]", i,
		    retries, context->host_str, context->port, errstr, reply ? reply->str : "<n/a>");

		/* free the reply (if there is one allocated) */
		oidc_cache_redis_reply_free(&reply);

		/* cleanup, we may try again (once) after reconnecting */
		context->disconnect(context);
	}

	return reply;
}

/*
 * get a name/value pair from Redis
 */
apr_byte_t oidc_cache_redis_get(request_rec *r, const char *section, const char *key, char **value) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *)cfg->cache_cfg;
	redisReply *reply = NULL;
	apr_byte_t rv = FALSE;

	/* grab the processlock */
	if (oidc_cache_mutex_lock(r->pool, r->server, context->mutex) == FALSE)
		return FALSE;

	/* get */
	reply = oidc_cache_redis_exec(r, context, "GET %s", oidc_cache_redis_get_key(r->pool, section, key));

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
	if ((reply->str == NULL) || (reply->len != _oidc_strlen(reply->str))) {
		oidc_error(r, "redisCommand reply->len (%d) != _oidc_strlen(reply->str): '%s'", (int)reply->len,
			   reply->str);
		goto end;
	}

	/* copy it in to the request memory pool */
	*value = apr_pstrdup(r->pool, reply->str);

	/* return success */
	rv = TRUE;

end:

	/* free the reply object resources */
	oidc_cache_redis_reply_free(&reply);

	/* unlock the process mutex */
	oidc_cache_mutex_unlock(r->pool, r->server, context->mutex);

	/* return the status */
	return rv;
}

/*
 * store a name/value pair in Redis
 */
apr_byte_t oidc_cache_redis_set(request_rec *r, const char *section, const char *key, const char *value,
				apr_time_t expiry) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *)cfg->cache_cfg;
	redisReply *reply = NULL;
	apr_byte_t rv = FALSE;
	apr_uint32_t timeout;

	/* grab the process lock */
	if (oidc_cache_mutex_lock(r->pool, r->server, context->mutex) == FALSE)
		return FALSE;

	/* see if we should be clearing this entry */
	if (value == NULL) {

		/* delete it */
		reply = oidc_cache_redis_exec(r, context, "DEL %s", oidc_cache_redis_get_key(r->pool, section, key));

	} else {

		/* calculate the timeout from now */
		timeout = apr_time_sec(expiry - apr_time_now());

		/* store it */
		reply = oidc_cache_redis_exec(r, context, "SETEX %s %d %s",
					      oidc_cache_redis_get_key(r->pool, section, key), timeout, value);
	}

	rv = (reply != NULL) && (reply->type != REDIS_REPLY_ERROR);

	/* free the reply object resources */
	oidc_cache_redis_reply_free(&reply);

	/* unlock the process mutex */
	oidc_cache_mutex_unlock(r->pool, r->server, context->mutex);

	/* return the status */
	return rv;
}

static int oidc_cache_redis_destroy_impl(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *)ap_get_module_config(s->module_config, &auth_openidc_module);
	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *)cfg->cache_cfg;

	if (context != NULL) {
		oidc_cache_mutex_lock(s->process->pool, s, context->mutex);
		context->disconnect(context);
		oidc_cache_mutex_unlock(s->process->pool, s, context->mutex);
		oidc_cache_mutex_destroy(s, context->mutex);
		cfg->cache_cfg = NULL;
	}

	return APR_SUCCESS;
}

oidc_cache_t oidc_cache_redis = {"redis",
				 1,
				 oidc_cache_redis_post_config_impl,
				 oidc_cache_redis_child_init,
				 oidc_cache_redis_get,
				 oidc_cache_redis_set,
				 oidc_cache_redis_destroy_impl};
