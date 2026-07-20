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

#ifndef _MOD_AUTH_OPENIDC_CFG_CFG_INT_H_
#define _MOD_AUTH_OPENIDC_CFG_CFG_INT_H_

#include "cfg/cfg.h"
#include "cfg/oauth.h"
#include "cfg/provider.h"

#include <apr_tables.h>

/*
 * pick the "add" pointer if non-NULL, otherwise fall back to "base"; the canonical helper for
 * "add wins when set" server/vhost config merging, shared by all merge functions under cfg/
 */
static inline void *_oidc_cfg_merge_ptr(const void *add, const void *base) {
	return (void *)(add != NULL ? add : base);
}

/*
 * pick the "add" int if it was explicitly configured, otherwise fall back to "base"
 */
static inline int _oidc_cfg_merge_pos_int(int add, int base) {
	return add != OIDC_CONFIG_POS_INT_UNSET ? add : base;
}

/*
 * pick the "add" timeout if it was explicitly configured, otherwise fall back to "base"
 */
static inline apr_interval_time_t _oidc_cfg_merge_timeout(apr_interval_time_t add, apr_interval_time_t base) {
	return add != OIDC_CONFIG_POS_TIMEOUT_UNSET ? add : base;
}

/*
 * single source of truth for the simple members of oidc_cfg_cache_t: the struct declaration and
 * the create/merge functions in cfg/cache.c are generated from these lists (see the same pattern
 * in cfg/oauth.c). Preprocessor conditionals cannot appear inside a macro body, so each
 * conditionally-compiled backend contributes its members through its own guarded sub-macro -
 * which is also how a derived branch adds backend members of its own.
 */
#ifdef USE_MEMCACHE
#define OIDC_CACHE_CFG_MEMCACHE_MEMBERS(PTR, INT, TIMEOUT)                                                             \
	/* cache_type= memcache: list of memcache host/port servers to use */                                          \
	PTR(char *, memcache_servers)                                                                                  \
	/* cache_type= memcache: minimum number of connections to each memcache server per process*/                   \
	INT(int, memcache_min)                                                                                         \
	/* cache_type= memcache: soft maximum number of connections to each memcache server per process */             \
	INT(int, memcache_smax)                                                                                        \
	/* cache_type= memcache: hard maximum number of connections to each memcache server per process */             \
	INT(int, memcache_hmax)                                                                                        \
	/* cache_type= memcache: maximum time in microseconds a connection to a memcache server can be idle before     \
	 * being closed */                                                                                                             \
	TIMEOUT(memcache_ttl)
#else
#define OIDC_CACHE_CFG_MEMCACHE_MEMBERS(PTR, INT, TIMEOUT)
#endif

#ifdef USE_LIBHIREDIS
#define OIDC_CACHE_CFG_REDIS_MEMBERS(PTR, INT, TIMEOUT)                                                                \
	/* cache_type= redis: Redis host/port server to use */                                                         \
	PTR(char *, redis_server)                                                                                      \
	PTR(char *, redis_username)                                                                                    \
	PTR(char *, redis_password)                                                                                    \
	INT(int, redis_database)                                                                                       \
	INT(int, redis_connect_timeout)                                                                                \
	INT(int, redis_keepalive)                                                                                      \
	INT(int, redis_timeout)
#else
#define OIDC_CACHE_CFG_REDIS_MEMBERS(PTR, INT, TIMEOUT)
#endif

#define OIDC_CACHE_CFG_SIMPLE_MEMBERS(PTR, INT, TIMEOUT)                                                               \
	/* encrypt the stored values */                                                                                \
	INT(int, encrypt)                                                                                              \
	/* shm: size of the segment (max number of cached entries) and max size in bytes of one entry */               \
	INT(int, shm_size_max)                                                                                         \
	INT(int, shm_entry_size_max)                                                                                   \
	/* file: directory holding the cache files (OS default like "/tmp" if unset) + clean interval */               \
	PTR(char *, file_dir)                                                                                          \
	INT(int, file_clean_interval)                                                                                  \
	OIDC_CACHE_CFG_MEMCACHE_MEMBERS(PTR, INT, TIMEOUT)                                                             \
	OIDC_CACHE_CFG_REDIS_MEMBERS(PTR, INT, TIMEOUT)

#define OIDC_CACHE_M_DECL(type, name) type name;
#define OIDC_CACHE_M_DECL_TIMEOUT(name) apr_interval_time_t name;

struct oidc_cfg_cache_t {

	/* pointer to cache functions */
	oidc_cache_t *impl;

	/* implementation specific config context */
	void *cfg;

	OIDC_CACHE_CFG_SIMPLE_MEMBERS(OIDC_CACHE_M_DECL, OIDC_CACHE_M_DECL, OIDC_CACHE_M_DECL_TIMEOUT)
};

/*
 * single source of truth for the simple pointer-merged and int-merged members of oidc_cfg_t: the
 * struct declaration below and oidc_cfg_server_create/oidc_cfg_server_merge in cfg/cfg.c are
 * generated from this list (see the same pattern in cfg/oauth.c); members with special create or
 * merge semantics remain hand-written in all three places
 */
#define OIDC_SVR_CFG_SIMPLE_MEMBERS(PTR, INT)                                                                          \
	/* the redirect URI as configured with the OpenID Connect OP's that we talk to */                              \
	PTR(char *, redirect_uri)                                                                                      \
	/* (optional) default URL for 3rd-party initiated SSO */                                                       \
	PTR(char *, default_sso_url)                                                                                   \
	/* (optional) default URL to go to after logout */                                                             \
	PTR(char *, default_slo_url)                                                                                   \
	/* Javascript template to preserve POST data */                                                                \
	PTR(char *, post_preserve_template)                                                                            \
	/* Javascript template to restore POST data */                                                                 \
	PTR(char *, post_restore_template)                                                                             \
	/* type of session management/storage */                                                                       \
	INT(session_type)                                                                                              \
	INT(session_cache_fallback_to_cookie)                                                                          \
	/* session cookie or persistent cookie */                                                                      \
	INT(persistent_session_cookie)                                                                                 \
	/* store the id_token in the session */                                                                        \
	INT(store_id_token)                                                                                            \
	/* session cookie chunk size */                                                                                \
	INT(session_cookie_chunk_size)                                                                                 \
	PTR(char *, cookie_domain)                                                                                     \
	INT(cookie_http_only)                                                                                          \
	/* samesite cookie settings */                                                                                 \
	INT(cookie_same_site_session)                                                                                  \
	INT(cookie_same_site_state)                                                                                    \
	INT(cookie_same_site_discovery_csrf)                                                                           \
	INT(state_timeout)                                                                                             \
	INT(max_number_of_state_cookies)                                                                               \
	INT(delete_oldest_state_cookies)                                                                               \
	INT(state_input_headers)                                                                                       \
	INT(session_inactivity_timeout)                                                                                \
	INT(provider_metadata_refresh_interval)                                                                        \
	PTR(char *, claim_delimiter)                                                                                   \
	PTR(char *, claim_prefix)                                                                                      \
	PTR(char *, ca_bundle_path)                                                                                    \
	PTR(char *, logout_x_frame_options)                                                                            \
	INT(x_forwarded_headers)                                                                                       \
	INT(action_on_userinfo_error)                                                                                  \
	INT(trace_parent)                                                                                              \
	PTR(char *, metrics_path)                                                                                      \
	INT(dpop_api_enabled)                                                                                          \
	/* directory that holds the provider & client metadata files */                                                \
	PTR(char *, metadata_dir)

#define OIDC_SVR_M_DECL_PTR(type, name) type name;
#define OIDC_SVR_M_DECL_INT(name) int name;

struct oidc_cfg_t {

	server_rec *svr;

	OIDC_SVR_CFG_SIMPLE_MEMBERS(OIDC_SVR_M_DECL_PTR, OIDC_SVR_M_DECL_INT)
	/* secret key(s) used for encryption */
	oidc_crypto_passphrase_t crypto_passphrase;

	/* pointer to the cache implementation */
	struct oidc_cfg_cache_t cache;
	/* a pointer to the (single) provider that we connect to */
	/* NB: if metadata_dir is set, these settings will function as defaults for the metadata read from there) */
	oidc_provider_t *provider;
	/* a pointer to the oauth server settings */
	oidc_oauth_t *oauth;

	oidc_http_timeout_t http_timeout_long;
	oidc_http_timeout_t http_timeout_short;
	oidc_http_outgoing_proxy_t outgoing_proxy;

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
	apr_hash_t *discover_issuers_allowed;

	apr_hash_t *metrics_hook_data;

	/* indicates whether this is a derived config, merged from a base one */
	unsigned int merged;
};

#define OIDC_CONFIG_DIR_RV(cmd, rv)                                                                                    \
	rv != NULL ? apr_psprintf(cmd->pool, "Invalid value for directive '%s': %s", cmd->directive->directive, rv)    \
		   : NULL

/*
 * Body generators for the per-server (oidc_cfg_t) accessors declared in
 * cfg/cfg.h. For member `foo` these emit the getter oidc_cfg_foo_get() and the
 * directive handler oidc_cmd_foo_set(), matching the prototypes declared there;
 * the OIDC_CFG_MEMBER_FUNCS_* aggregates in cfg/cfg.c build on them. The names
 * are token-pasted: see .ctags.d/mod_auth_openidc.ctags to index them.
 */
#define OIDC_CFG_MEMBER_FUNC_GET(member, type)                                                                         \
	type oidc_cfg_##member##_get(const oidc_cfg_t *cfg) {                                                          \
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
	type oidc_cfg_##member##_get(const oidc_cfg_t *cfg) {                                                          \
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
	const char *oidc_cfg_##member##_get(const oidc_cfg_t *cfg) {                                                   \
		return (cfg->member != NULL) ? cfg->member : def_val;                                                  \
	}

#define OIDC_CFG_MEMBER_FUNCS_URL(member)                                                                              \
	OIDC_CFG_MEMBER_FUNCS_TYPE(member, const char *, oidc_valid_http_url(cmd->pool, arg))

#endif // _MOD_AUTH_OPENIDC_CFG_CFG_INT_H_
