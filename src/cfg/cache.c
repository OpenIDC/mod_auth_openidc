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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "cfg/cache.h"
#include "cfg/cfg_int.h"
#include "cfg/parse.h"

/*
 * set the cache type
 */
const char *oidc_cmd_cache_type_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	static const char *options[] = {"shm", "file",
#ifdef USE_MEMCACHE
					"memcache",
#endif
#ifdef USE_LIBHIREDIS
					"redis",
#endif
					NULL};
	const char *rv = oidc_cfg_parse_is_valid_option(cmd->pool, arg, options);
	if (rv == NULL) {

		if (_oidc_strcmp(arg, oidc_cache_shm.name) == 0) {
			cfg->cache.impl = &oidc_cache_shm;
		} else if (_oidc_strcmp(arg, oidc_cache_file.name) == 0) {
			cfg->cache.impl = &oidc_cache_file;
#ifdef USE_MEMCACHE
		} else if (_oidc_strcmp(arg, oidc_cache_memcache.name) == 0) {
			cfg->cache.impl = &oidc_cache_memcache;
#endif
#ifdef USE_LIBHIREDIS
		} else if (_oidc_strcmp(arg, oidc_cache_redis.name) == 0) {
			cfg->cache.impl = &oidc_cache_redis;
#endif
		} else {
			rv = apr_psprintf(cmd->pool, "unsupported cache type value: %s", arg);
		}
	}

	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_CFG_MEMBER_FUNC_CACHE_TYPE_GET(member, type, def_val, unset_val)                                          \
	type oidc_cfg_cache_##member##_get(oidc_cfg_t *cfg) {                                                          \
		if (cfg->cache.member == unset_val)                                                                    \
			return def_val;                                                                                \
		return cfg->cache.member;                                                                              \
	}

#define OIDC_CFG_MEMBER_FUNC_CACHE_SET(member, valid)                                                                  \
	const char *oidc_cmd_cache_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = valid;                                                                                \
		if (rv == NULL)                                                                                        \
			cfg->cache.member = apr_pstrdup(cmd->pool, arg);                                               \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}

#define OIDC_CFG_MEMBER_FUNCS_CACHE_PARSE(member, type, parse, def_val, unset_val)                                     \
	const char *oidc_cmd_cache_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		type v = -1;                                                                                           \
		const char *rv = parse;                                                                                \
		if (rv == NULL)                                                                                        \
			cfg->cache.member = v;                                                                         \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	OIDC_CFG_MEMBER_FUNC_CACHE_TYPE_GET(member, type, def_val, unset_val)

#define OIDC_CFG_MEMBER_FUNCS_CACHE_INT_EXT(member, parse, def_val)                                                    \
	OIDC_CFG_MEMBER_FUNCS_CACHE_PARSE(member, int, parse, def_val, OIDC_CONFIG_POS_INT_UNSET)

#define OIDC_CFG_MEMBER_FUNCS_CACHE_INT(member, min, max, def_val)                                                     \
	OIDC_CFG_MEMBER_FUNCS_CACHE_INT_EXT(member, oidc_cfg_parse_int_min_max(cmd->pool, arg, &v, min, max), def_val)

#define OIDC_CFG_MEMBER_FUNCS_CACHE_TIMEOUT(member, min, max, def_val)                                                 \
	OIDC_CFG_MEMBER_FUNCS_CACHE_PARSE(member, apr_interval_time_t,                                                 \
					  oidc_cfg_parse_timeout_min_max(cmd->pool, arg, &v, min, max), def_val,       \
					  OIDC_CONFIG_POS_TIMEOUT_UNSET)

#define OIDC_CFG_MEMBER_FUNCS_CACHE_BOOL(member, def_val)                                                              \
	OIDC_CFG_MEMBER_FUNCS_CACHE_INT_EXT(member, oidc_cfg_parse_boolean(cmd->pool, arg, &v), def_val)

OIDC_CFG_MEMBER_FUNCS_CACHE_BOOL(encrypt, cfg->cache.impl->encrypt_by_default)

#define OIDC_CFG_MEMBER_FUNCS_CACHE_STR_DEF(member, valid, def_val)                                                    \
	OIDC_CFG_MEMBER_FUNC_CACHE_SET(member, valid)                                                                  \
                                                                                                                       \
	const char *oidc_cfg_cache_##member##_get(oidc_cfg_t *cfg) {                                                   \
		return (cfg->cache.member != NULL) ? cfg->cache.member : def_val;                                      \
	}

/*
 * shm
 */

/* minimum shm cache size i.e. minimum number of entries  */
#define OIDC_CACHE_SHM_SIZE_MIN 128
/* maximum shm cache size i.e. maximum number of entries  */
#define OIDC_CACHE_SHM_SIZE_MAX 1024 * 1024 * 1024
/* default shm cache size i.e. the number of pre-allocated entries in the shm cache */
#define OIDC_DEFAULT_CACHE_SHM_SIZE 10000

OIDC_CFG_MEMBER_FUNCS_CACHE_INT(shm_size_max, OIDC_CACHE_SHM_SIZE_MIN, OIDC_CACHE_SHM_SIZE_MAX,
				OIDC_DEFAULT_CACHE_SHM_SIZE)

/* minimum size of a SHM cache entry */
#define OIDC_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX 8192 + 512 + 32 // 8Kb plus overhead
/* maximum size of a SHM cache entry */
#define OIDC_MAXIMUM_CACHE_SHM_ENTRY_SIZE_MAX 1024 * 1024 // 1Mb incl. overhead
/* default max cache entry size for shm: # value + # key + # overhead */
#define OIDC_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX 16384 + 512 + 32

/*
 * set the maximum size of a shared memory cache entry and enforces a minimum
 */
const char *oidc_cmd_cache_shm_entry_size_max_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv =
	    oidc_cfg_parse_int_min_max(cmd->pool, arg, &cfg->cache.shm_entry_size_max,
				       OIDC_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX, OIDC_MAXIMUM_CACHE_SHM_ENTRY_SIZE_MAX);
	if ((rv == NULL) && ((cfg->cache.shm_entry_size_max % 8) != 0))
		rv = "the slot size must be a multiple of 8";
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_CFG_MEMBER_FUNC_CACHE_TYPE_GET(shm_entry_size_max, int, OIDC_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX,
				    OIDC_CONFIG_POS_INT_UNSET)

static void oidc_cfg_cache_shm_create_server_config(oidc_cfg_t *c) {
	c->cache.shm_size_max = OIDC_DEFAULT_CACHE_SHM_SIZE;
	c->cache.shm_entry_size_max = OIDC_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX;
}

static void oidc_cfg_cache_shm_merge_server_config(oidc_cfg_t *c, oidc_cfg_t *base, oidc_cfg_t *add) {
	c->cache.shm_size_max =
	    add->cache.shm_size_max != OIDC_DEFAULT_CACHE_SHM_SIZE ? add->cache.shm_size_max : base->cache.shm_size_max;
	c->cache.shm_entry_size_max = add->cache.shm_entry_size_max != OIDC_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX
					  ? add->cache.shm_entry_size_max
					  : base->cache.shm_entry_size_max;
}

/*
 * file
 */

/* minimum cache files clean interval in seconds */
#define OIDC_CACHE_FILE_CLEAN_INTERVAL_MIN 0
/* maximum cache files clean interval in seconds */
#define OIDC_CACHE_FILE_CLEAN_INTERVAL_MAX 3600 * 24 * 7
/* default cache files clean interval in seconds */
#define OIDC_DEFAULT_CACHE_FILE_CLEAN_INTERVAL 60

OIDC_CFG_MEMBER_FUNCS_CACHE_INT(file_clean_interval, OIDC_CACHE_FILE_CLEAN_INTERVAL_MIN,
				OIDC_CACHE_FILE_CLEAN_INTERVAL_MAX, OIDC_DEFAULT_CACHE_FILE_CLEAN_INTERVAL)

const char *oidc_cmd_cache_file_dir_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_parse_dirname(cmd->pool, arg, &cfg->cache.file_dir);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

static void oidc_cfg_cache_file_create_server_config(oidc_cfg_t *c) {
	c->cache.file_dir = NULL;
	c->cache.file_clean_interval = OIDC_CONFIG_POS_INT_UNSET;
}

static void oidc_cfg_cache_file_merge_server_config(oidc_cfg_t *c, oidc_cfg_t *base, oidc_cfg_t *add) {
	c->cache.file_dir = add->cache.file_dir != NULL ? add->cache.file_dir : base->cache.file_dir;
	c->cache.file_clean_interval = add->cache.file_clean_interval != OIDC_CONFIG_POS_INT_UNSET
					   ? add->cache.file_clean_interval
					   : base->cache.file_clean_interval;
}

/*
 * memcache
 */

#ifdef USE_MEMCACHE

OIDC_CFG_MEMBER_FUNCS_CACHE_STR_DEF(memcache_servers, NULL, NULL)

#define OIDC_CACHE_MEMCACHE_CONNECTIONS_MIN_MIN 0
#define OIDC_CACHE_MEMCACHE_CONNECTIONS_MIN_MAX 2048
#define OIDC_DEFAULT_CACHE_MEMCACHE_CONNECTIONS_MIN 0

OIDC_CFG_MEMBER_FUNCS_CACHE_INT(memcache_min, OIDC_CACHE_MEMCACHE_CONNECTIONS_MIN_MIN,
				OIDC_CACHE_MEMCACHE_CONNECTIONS_MIN_MAX, OIDC_DEFAULT_CACHE_MEMCACHE_CONNECTIONS_MIN)

#define OIDC_CACHE_MEMCACHE_CONNECTIONS_SMAX_MIN 0
#define OIDC_CACHE_MEMCACHE_CONNECTIONS_SMAX_MAX 2048
#define OIDC_DEFAULT_CACHE_MEMCACHE_CONNECTIONS_SMAX 0

OIDC_CFG_MEMBER_FUNCS_CACHE_INT(memcache_smax, OIDC_CACHE_MEMCACHE_CONNECTIONS_SMAX_MIN,
				OIDC_CACHE_MEMCACHE_CONNECTIONS_SMAX_MAX, OIDC_DEFAULT_CACHE_MEMCACHE_CONNECTIONS_SMAX)

#define OIDC_CACHE_MEMCACHE_CONNECTIONS_HMAX_MIN 0
#define OIDC_CACHE_MEMCACHE_CONNECTIONS_HMAX_MAX 2048
#define OIDC_DEFAULT_CACHE_MEMCACHE_CONNECTIONS_HMAX 0

OIDC_CFG_MEMBER_FUNCS_CACHE_INT(memcache_hmax, OIDC_CACHE_MEMCACHE_CONNECTIONS_HMAX_MIN,
				OIDC_CACHE_MEMCACHE_CONNECTIONS_HMAX_MAX, OIDC_DEFAULT_CACHE_MEMCACHE_CONNECTIONS_HMAX)

#define OIDC_CACHE_MEMCACHE_CONNECTIONS_TTL_MIN (apr_interval_time_t)0
/*
 *  Due to a design error in the apr-util 1.x apr_memcache_server_create prototype
 *  (it uses an apr_uint32_t instead of an apr_interval_time_t) we need to limit
 *  the maximum value to 4292 seconds which is the maximum value in microseconds
 *  that can be represented by an apr_uint32_t.
 */
#define OIDC_CACHE_MEMCACHE_CONNECTIONS_TTL_MAX apr_time_from_sec(4294)
#define OIDC_DEFAULT_CACHE_MEMCACHE_CONNECTIONS_TTL apr_time_from_sec(60)

OIDC_CFG_MEMBER_FUNCS_CACHE_TIMEOUT(memcache_ttl, OIDC_CACHE_MEMCACHE_CONNECTIONS_TTL_MIN,
				    OIDC_CACHE_MEMCACHE_CONNECTIONS_TTL_MAX,
				    OIDC_DEFAULT_CACHE_MEMCACHE_CONNECTIONS_TTL)

static void oidc_cfg_cache_memcache_create_server_config(oidc_cfg_t *c) {
	c->cache.memcache_servers = NULL;
	c->cache.memcache_min = OIDC_CONFIG_POS_INT_UNSET;
	c->cache.memcache_smax = OIDC_CONFIG_POS_INT_UNSET;
	c->cache.memcache_hmax = OIDC_CONFIG_POS_INT_UNSET;
	c->cache.memcache_ttl = OIDC_CONFIG_POS_TIMEOUT_UNSET;
}

static void oidc_cfg_cache_memcache_merge_server_config(oidc_cfg_t *c, oidc_cfg_t *base, oidc_cfg_t *add) {
	c->cache.memcache_servers =
	    add->cache.memcache_servers != NULL ? add->cache.memcache_servers : base->cache.memcache_servers;
	c->cache.memcache_min =
	    add->cache.memcache_min != OIDC_CONFIG_POS_INT_UNSET ? add->cache.memcache_min : base->cache.memcache_min;
	c->cache.memcache_smax = add->cache.memcache_smax != OIDC_CONFIG_POS_INT_UNSET ? add->cache.memcache_smax
										       : base->cache.memcache_smax;
	c->cache.memcache_hmax = add->cache.memcache_hmax != OIDC_CONFIG_POS_INT_UNSET ? add->cache.memcache_hmax
										       : base->cache.memcache_hmax;
	c->cache.memcache_ttl = add->cache.memcache_ttl != OIDC_CONFIG_POS_TIMEOUT_UNSET ? add->cache.memcache_ttl
											 : base->cache.memcache_ttl;
}

#endif

/*
 * redis
 */

#ifdef USE_LIBHIREDIS

OIDC_CFG_MEMBER_FUNCS_CACHE_STR_DEF(redis_server, NULL, NULL)
OIDC_CFG_MEMBER_FUNCS_CACHE_STR_DEF(redis_username, NULL, NULL)
OIDC_CFG_MEMBER_FUNCS_CACHE_STR_DEF(redis_password, NULL, NULL)

#define OIDC_CACHE_REDIS_DATABASE_MIN 0
#define OIDC_CACHE_REDIS_DATABASE_MAX 1024

OIDC_CFG_MEMBER_FUNCS_CACHE_INT(redis_database, OIDC_CACHE_REDIS_DATABASE_MIN, OIDC_CACHE_REDIS_DATABASE_MAX,
				OIDC_CONFIG_POS_INT_UNSET)

#define OIDC_REDIS_CONNECT_TIMEOUT_MIN 1
#define OIDC_REDIS_CONNECT_TIMEOUT_MAX 3600

// NB: zero for turning off TCP keepalive, which is enabled by default
#define OIDC_REDIS_KEEPALIVE_TIMEOUT_MIN 0
#define OIDC_REDIS_KEEPALIVE_TIMEOUT_MAX 3600

const char *oidc_cmd_cache_redis_connect_timeout_set(cmd_parms *cmd, void *struct_ptr, const char *arg1,
						     const char *arg2) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = NULL;
	if (arg1)
		rv = oidc_cfg_parse_int_min_max(cmd->pool, arg1, &cfg->cache.redis_connect_timeout,
						OIDC_REDIS_CONNECT_TIMEOUT_MIN, OIDC_REDIS_CONNECT_TIMEOUT_MAX);
	if ((rv == NULL) && (arg2))
		rv = oidc_cfg_parse_int_min_max(cmd->pool, arg2, &cfg->cache.redis_keepalive,
						OIDC_REDIS_KEEPALIVE_TIMEOUT_MIN, OIDC_REDIS_KEEPALIVE_TIMEOUT_MAX);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_CFG_MEMBER_FUNC_CACHE_TYPE_GET(redis_connect_timeout, int, OIDC_CONFIG_POS_INT_UNSET, OIDC_CONFIG_POS_INT_UNSET)
OIDC_CFG_MEMBER_FUNC_CACHE_TYPE_GET(redis_keepalive, int, OIDC_CONFIG_POS_INT_UNSET, OIDC_CONFIG_POS_INT_UNSET)

#define OIDC_REDIS_TIMEOUT_MIN 1
#define OIDC_REDIS_TIMEOUT_MAX 3600

OIDC_CFG_MEMBER_FUNCS_CACHE_INT(redis_timeout, OIDC_REDIS_TIMEOUT_MIN, OIDC_REDIS_TIMEOUT_MAX,
				OIDC_CONFIG_POS_INT_UNSET)

static void oidc_cfg_cache_redis_create_server_config(oidc_cfg_t *c) {
	c->cache.redis_server = NULL;
	c->cache.redis_username = NULL;
	c->cache.redis_password = NULL;
	c->cache.redis_database = OIDC_CONFIG_POS_INT_UNSET;
	c->cache.redis_connect_timeout = OIDC_CONFIG_POS_INT_UNSET;
	c->cache.redis_keepalive = OIDC_CONFIG_POS_INT_UNSET;
	c->cache.redis_timeout = OIDC_CONFIG_POS_INT_UNSET;
}

static void oidc_cfg_cache_redis_merge_server_config(oidc_cfg_t *c, oidc_cfg_t *base, oidc_cfg_t *add) {
	c->cache.redis_server = add->cache.redis_server != NULL ? add->cache.redis_server : base->cache.redis_server;
	c->cache.redis_username =
	    add->cache.redis_username != NULL ? add->cache.redis_username : base->cache.redis_username;
	c->cache.redis_password =
	    add->cache.redis_password != NULL ? add->cache.redis_password : base->cache.redis_password;
	c->cache.redis_database = add->cache.redis_database != OIDC_CONFIG_POS_INT_UNSET ? add->cache.redis_database
											 : base->cache.redis_database;
	c->cache.redis_connect_timeout = add->cache.redis_connect_timeout != OIDC_CONFIG_POS_INT_UNSET
					     ? add->cache.redis_connect_timeout
					     : base->cache.redis_connect_timeout;
	c->cache.redis_keepalive = add->cache.redis_keepalive != OIDC_CONFIG_POS_INT_UNSET
				       ? add->cache.redis_keepalive
				       : base->cache.redis_keepalive;
	c->cache.redis_timeout = add->cache.redis_timeout != OIDC_CONFIG_POS_INT_UNSET ? add->cache.redis_timeout
										       : base->cache.redis_timeout;
}

#endif

/*
 * generic
 */
void oidc_cfg_cache_create_server_config(oidc_cfg_t *c) {
	c->cache.impl = NULL;
	c->cache.cfg = NULL;
	c->cache.encrypt = OIDC_CONFIG_POS_INT_UNSET;
	oidc_cfg_cache_shm_create_server_config(c);
	oidc_cfg_cache_file_create_server_config(c);
#ifdef USE_MEMCACHE
	oidc_cfg_cache_memcache_create_server_config(c);
#endif
#ifdef USE_LIBHIREDIS
	oidc_cfg_cache_redis_create_server_config(c);
#endif
}

void oidc_cfg_cache_merge_server_config(oidc_cfg_t *c, oidc_cfg_t *base, oidc_cfg_t *add) {
	c->cache.impl = (add->cache.impl != NULL) ? add->cache.impl : base->cache.impl;
	c->cache.encrypt = add->cache.encrypt != OIDC_CONFIG_POS_INT_UNSET ? add->cache.encrypt : base->cache.encrypt;
	c->cache.cfg = NULL;
	oidc_cfg_cache_shm_merge_server_config(c, base, add);
	oidc_cfg_cache_file_merge_server_config(c, base, add);
#ifdef USE_MEMCACHE
	oidc_cfg_cache_memcache_merge_server_config(c, base, add);
#endif

#ifdef USE_LIBHIREDIS
	oidc_cfg_cache_redis_merge_server_config(c, base, add);
#endif
}
