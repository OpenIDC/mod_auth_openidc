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
	type oidc_cfg_cache_##member##_get(const oidc_cfg_t *cfg) {                                                    \
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
	const char *oidc_cfg_cache_##member##_get(const oidc_cfg_t *cfg) {                                             \
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
	if ((rv == NULL) && arg2)
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

#endif

/*
 * generic
 */
#define OIDC_CACHE_M_CREATE_PTR(type, name) c->cache.name = NULL;
#define OIDC_CACHE_M_CREATE_INT(type, name) c->cache.name = OIDC_CONFIG_POS_INT_UNSET;
#define OIDC_CACHE_M_CREATE_TIMEOUT(name) c->cache.name = OIDC_CONFIG_POS_TIMEOUT_UNSET;
#define OIDC_CACHE_M_MERGE_PTR(type, name) c->cache.name = _oidc_cfg_merge_ptr(add->cache.name, base->cache.name);
#define OIDC_CACHE_M_MERGE_INT(type, name) c->cache.name = _oidc_cfg_merge_pos_int(add->cache.name, base->cache.name);
#define OIDC_CACHE_M_MERGE_TIMEOUT(name) c->cache.name = _oidc_cfg_merge_timeout(add->cache.name, base->cache.name);

void oidc_cfg_cache_create_server_config(oidc_cfg_t *c) {
	c->cache.impl = NULL;
	c->cache.cfg = NULL;
	OIDC_CACHE_CFG_SIMPLE_MEMBERS(OIDC_CACHE_M_CREATE_PTR, OIDC_CACHE_M_CREATE_INT, OIDC_CACHE_M_CREATE_TIMEOUT)
}

void oidc_cfg_cache_merge_server_config(oidc_cfg_t *c, const oidc_cfg_t *base, const oidc_cfg_t *add) {
	c->cache.impl = _oidc_cfg_merge_ptr(add->cache.impl, base->cache.impl);
	c->cache.cfg = NULL;
	OIDC_CACHE_CFG_SIMPLE_MEMBERS(OIDC_CACHE_M_MERGE_PTR, OIDC_CACHE_M_MERGE_INT, OIDC_CACHE_M_MERGE_TIMEOUT)
}
