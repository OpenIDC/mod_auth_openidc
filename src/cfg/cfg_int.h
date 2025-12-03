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

#ifndef _MOD_AUTH_OPENIDC_CFG_CFG_INT_H_
#define _MOD_AUTH_OPENIDC_CFG_CFG_INT_H_

#include "cfg/cfg.h"
#include "cfg/oauth.h"
#include "cfg/provider.h"

#include <apr_tables.h>

struct oidc_cfg_cache_t {

	/* pointer to cache functions */
	oidc_cache_t *impl;

	/* implementation specific config context */
	void *cfg;

	/* encrypt the stored values */
	int encrypt;

	/*
	 * file
	 */

	/* cache_type = shm: size of the shared memory segment (cq. max number of cached entries) */
	int shm_size_max;
	/* cache_type = shm: maximum size in bytes of a cache entry */
	int shm_entry_size_max;

	/*
	 * shm
	 */

	/* cache_type = file: directory that holds the cache files (if not set, we'll try and use an OS defined one like
	 * "/tmp" */
	char *file_dir;
	/* cache_type = file: clean interval */
	int file_clean_interval;

	/*
	 * memcache
	 */

#ifdef USE_MEMCACHE
	/* cache_type= memcache: list of memcache host/port servers to use */
	char *memcache_servers;
	/* cache_type= memcache: minimum number of connections to each memcache server per process*/
	int memcache_min;
	/* cache_type= memcache: soft maximum number of connections to each memcache server per process */
	int memcache_smax;
	/* cache_type= memcache: hard maximum number of connections to each memcache server per process */
	int memcache_hmax;
	/* cache_type= memcache: maximum time in microseconds a connection to a memcache server can be idle before being
	 * closed */
	apr_interval_time_t memcache_ttl;
#endif

	/*
	 * redis
	 */

#ifdef USE_LIBHIREDIS
	/* cache_type= redis: Redis host/port server to use */
	char *redis_server;
	char *redis_username;
	char *redis_password;
	int redis_database;
	int redis_connect_timeout;
	int redis_keepalive;
	int redis_timeout;
#endif
};

struct oidc_cfg_t {

	server_rec *svr;

	/* the redirect URI as configured with the OpenID Connect OP's that we talk to */
	char *redirect_uri;
	/* secret key(s) used for encryption */
	oidc_crypto_passphrase_t crypto_passphrase;

	/* (optional) default URL for 3rd-party initiated SSO */
	char *default_sso_url;
	/* (optional) default URL to go to after logout */
	char *default_slo_url;

	/* Javascript template to preserve POST data */
	char *post_preserve_template;
	/* Javascript template to restore POST data */
	char *post_restore_template;

	/* pointer to the cache implementation */
	struct oidc_cfg_cache_t cache;
	/* a pointer to the (single) provider that we connect to */
	/* NB: if metadata_dir is set, these settings will function as defaults for the metadata read from there) */
	oidc_provider_t *provider;
	/* a pointer to the oauth server settings */
	oidc_oauth_t *oauth;

	/* type of session management/storage */
	int session_type;
	int session_cache_fallback_to_cookie;

	/* session cookie or persistent cookie */
	int persistent_session_cookie;
	/* store the id_token in the session */
	int store_id_token;
	/* session cookie chunk size */
	int session_cookie_chunk_size;
	char *cookie_domain;
	int cookie_http_only;
	/* samesite cookie settings */
	int cookie_same_site_session;
	int cookie_same_site_state;
	int cookie_same_site_discovery_csrf;

	int state_timeout;
	int max_number_of_state_cookies;
	int delete_oldest_state_cookies;
	int state_input_headers;

	int session_inactivity_timeout;
	int provider_metadata_refresh_interval;

	oidc_http_timeout_t http_timeout_long;
	oidc_http_timeout_t http_timeout_short;
	oidc_http_outgoing_proxy_t outgoing_proxy;

	char *claim_delimiter;
	char *claim_prefix;
	oidc_remote_user_claim_t remote_user_claim;

	/* public keys in JWK format, used by parters for encrypting JWTs sent to us */
	apr_array_header_t *public_keys;
	/* private keys in JWK format used for decrypting encrypted JWTs sent to us */
	apr_array_header_t *private_keys;

	apr_hash_t *black_listed_claims;
	apr_hash_t *white_listed_claims;
	oidc_apr_expr_t *filter_claims_expr;

	apr_hash_t *info_hook_data;
	apr_hash_t *redirect_urls_allowed;
	char *ca_bundle_path;
	char *logout_x_frame_options;
	int x_forwarded_headers;
	int action_on_userinfo_error;
	int trace_parent;

	apr_hash_t *metrics_hook_data;
	char *metrics_path;
	int dpop_api_enabled;

	/* directory that holds the provider & client metadata files */
	char *metadata_dir;

	/* indicates whether this is a derived config, merged from a base one */
	unsigned int merged;
};

#define OIDC_CONFIG_DIR_RV(cmd, rv)                                                                                    \
	rv != NULL ? apr_psprintf(cmd->pool, "Invalid value for directive '%s': %s", cmd->directive->directive, rv)    \
		   : NULL

#define OIDC_CFG_MEMBER_FUNC_GET(member, type)                                                                         \
	type oidc_cfg_##member##_get(oidc_cfg_t *cfg) {                                                                \
		return cfg->member;                                                                                    \
	}

#define OIDC_CFG_MEMBER_FUNC_SET(member, valid)                                                                        \
	const char *oidc_cmd_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                              \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = valid;                                                                                \
		if (rv == NULL)                                                                                        \
			cfg->member = apr_pstrdup(cmd->pool, arg);                                                     \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}

#define OIDC_CFG_MEMBER_FUNCS_TYPE(member, type, valid)                                                                \
	OIDC_CFG_MEMBER_FUNC_SET(member, valid)                                                                        \
                                                                                                                       \
	OIDC_CFG_MEMBER_FUNC_GET(member, type)

#define OIDC_CFG_MEMBER_FUNC_TYPE_GET(member, type, def_val)                                                           \
	type oidc_cfg_##member##_get(oidc_cfg_t *cfg) {                                                                \
		if (cfg->member == OIDC_CONFIG_POS_INT_UNSET)                                                          \
			return def_val;                                                                                \
		return cfg->member;                                                                                    \
	}

#define OIDC_CFG_MEMBER_FUNCS_INT_EXT(member, parse, def_val)                                                          \
	const char *oidc_cmd_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                              \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		int v = -1;                                                                                            \
		const char *rv = parse;                                                                                \
		if (rv == NULL)                                                                                        \
			cfg->member = v;                                                                               \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	OIDC_CFG_MEMBER_FUNC_TYPE_GET(member, int, def_val)

#define OIDC_CFG_MEMBER_FUNCS_INT(member, min, max, def_val)                                                           \
	OIDC_CFG_MEMBER_FUNCS_INT_EXT(member, oidc_cfg_parse_int_min_max(cmd->pool, arg, &v, min, max), def_val)

#define OIDC_CFG_MEMBER_FUNCS_BOOL(member, def_val)                                                                    \
	OIDC_CFG_MEMBER_FUNCS_INT_EXT(member, oidc_cfg_parse_boolean(cmd->pool, arg, &v), def_val)

#define OIDC_CFG_MEMBER_FUNCS_STR_DEF(member, valid, def_val)                                                          \
	OIDC_CFG_MEMBER_FUNC_SET(member, valid)                                                                        \
                                                                                                                       \
	const char *oidc_cfg_##member##_get(oidc_cfg_t *cfg) {                                                         \
		return (cfg->member != NULL) ? cfg->member : def_val;                                                  \
	}

#define OIDC_CFG_MEMBER_FUNCS_URL(member)                                                                              \
	OIDC_CFG_MEMBER_FUNCS_TYPE(member, const char *, oidc_valid_http_url(cmd->pool, arg))

#endif // _MOD_AUTH_OPENIDC_CFG_CFG_INT_H_
