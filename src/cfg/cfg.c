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
#include "cfg/dir.h"
#include "cfg/oauth.h"
#include "cfg/parse.h"
#include "cfg/provider.h"
#include "jose.h"
#include "metrics.h"
#include "proto/proto.h"
#include "session.h"
#include "util/util.h"

const char *oidc_cfg_string_list_add(apr_pool_t *pool, apr_array_header_t **list, const char *arg) {
	if (*list == NULL)
		*list = apr_array_make(pool, 1, sizeof(const char *));
	APR_ARRAY_PUSH(*list, const char *) = arg;
	return NULL;
}

#define OIDC_DEFAULT_ACTION_ON_USERINFO_ERROR OIDC_ON_ERROR_502
OIDC_CFG_MEMBER_FUNC_TYPE_GET(action_on_userinfo_error, oidc_on_error_action_t, OIDC_DEFAULT_ACTION_ON_USERINFO_ERROR)

#define OIDC_CFG_MEMBER_FUNCS_HTTP_TIMEOUT(member, def_val)                                                            \
	const char *oidc_cmd_##member##_set(cmd_parms *cmd, void *ptr, const char *arg1, const char *arg2,             \
					    const char *arg3) {                                                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = oidc_cfg_parse_http_timeout(cmd->pool, arg1, arg2, arg3, &cfg->member);               \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	oidc_http_timeout_t *oidc_cfg_##member##_get(oidc_cfg_t *cfg) {                                                \
		if (cfg->member.request_timeout == OIDC_CONFIG_POS_INT_UNSET)                                          \
			/* NB: we are modifying in-config but post_config/merge has finished by now  */                \
			cfg->member.request_timeout = def_val;                                                         \
		return &cfg->member;                                                                                   \
	}

/* request timeout in seconds for HTTP calls that may take a long time */
#define OIDC_DEFAULT_HTTP_REQUEST_TIMEOUT_LONG 30
/* connect timeout in seconds for HTTP calls that may take a long time */
#define OIDC_DEFAULT_HTTP_CONNECT_TIMEOUT_LONG 10
/* nr of retries for HTTP calls that may take a long time */
#define OIDC_DEFAULT_HTTP_RETRIES_LONG 1
/* retry interval in milliseconds for HTTP calls that may take a long time */
#define OIDC_DEFAULT_HTTP_RETRY_INTERVAL_LONG 500
/* timeouts in seconds for HTTP calls that should take a short time (registry/discovery related) */
#define OIDC_DEFAULT_HTTP_REQUEST_TIMEOUT_SHORT 5
/* connect timeout in seconds for HTTP calls that may take a long time */
#define OIDC_DEFAULT_HTTP_CONNECT_TIMEOUT_SHORT 2
/* nr of retries for HTTP calls that should take a short time */
#define OIDC_DEFAULT_HTTP_RETRIES_SHORT 1
/* retry interval in milliseconds for HTTP calls that should take a short time */
#define OIDC_DEFAULT_HTTP_RETRY_INTERVAL_SHORT 300

OIDC_CFG_MEMBER_FUNCS_HTTP_TIMEOUT(http_timeout_long, OIDC_DEFAULT_HTTP_REQUEST_TIMEOUT_LONG)
OIDC_CFG_MEMBER_FUNCS_HTTP_TIMEOUT(http_timeout_short, OIDC_DEFAULT_HTTP_REQUEST_TIMEOUT_SHORT)

const char *oidc_cmd_crypto_passphrase_set(cmd_parms *cmd, void *struct_ptr, const char *arg1, const char *arg2) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = NULL;
	if (arg1)
		rv = oidc_cfg_parse_passphrase(cmd->pool, arg1, &cfg->crypto_passphrase.secret1);
	if ((rv == NULL) && (arg2 != NULL))
		rv = oidc_cfg_parse_passphrase(cmd->pool, arg2, &cfg->crypto_passphrase.secret2);
	return rv;
}

const oidc_crypto_passphrase_t *oidc_cfg_crypto_passphrase_get(oidc_cfg_t *cfg) {
	return &cfg->crypto_passphrase;
}

const char *oidc_cfg_crypto_passphrase_secret1_get(oidc_cfg_t *cfg) {
	return cfg->crypto_passphrase.secret1;
}

const char *oidc_cmd_outgoing_proxy_set(cmd_parms *cmd, void *ptr, const char *arg1, const char *arg2,
					const char *arg3) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = NULL;
	if (arg1)
		cfg->outgoing_proxy.host_port = apr_pstrdup(cmd->pool, arg1);
	if (arg2)
		cfg->outgoing_proxy.username_password = apr_pstrdup(cmd->pool, arg2);
	if (arg3) {
		rv = oidc_cfg_parse_is_valid_option(cmd->pool, arg3, oidc_http_proxy_auth_options());
		if (rv == NULL)
			cfg->outgoing_proxy.auth_type = oidc_http_proxy_s2auth(arg3);
	}
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

const oidc_http_outgoing_proxy_t *oidc_cfg_outgoing_proxy_get(oidc_cfg_t *cfg) {
	return &cfg->outgoing_proxy;
}

static const char *oidc_cfg_valid_cookie_domain(apr_pool_t *pool, const char *arg) {
	size_t sz, limit;
	char d;
	limit = _oidc_strlen(arg);
	for (sz = 0; sz < limit; sz++) {
		d = arg[sz];
		if ((d < '0' || d > '9') && (d < 'a' || d > 'z') && (d < 'A' || d > 'Z') && d != '.' && d != '-') {
			return (apr_psprintf(pool, "invalid character '%c' in cookie domain value: %s", d, arg));
		}
	}
	return NULL;
}

OIDC_CFG_MEMBER_FUNCS_TYPE(cookie_domain, const char *, oidc_cfg_valid_cookie_domain(cmd->pool, arg))

#define OIDC_SESSION_TYPE_SERVER_CACHE_STR "server-cache"
#define OIDC_SESSION_TYPE_CLIENT_COOKIE_STR "client-cookie"
#define OIDC_SESSION_TYPE_PERSISTENT "persistent"
#define OIDC_SESSION_TYPE_STORE_ID_TOKEN "store_id_token"
#define OIDC_SESSION_TYPE_SEPARATOR ":"

const char *oidc_cmd_session_type_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);

	static const char *options[] = {
	    OIDC_SESSION_TYPE_SERVER_CACHE_STR,
	    OIDC_SESSION_TYPE_SERVER_CACHE_STR OIDC_SESSION_TYPE_SEPARATOR OIDC_SESSION_TYPE_PERSISTENT,
	    OIDC_SESSION_TYPE_CLIENT_COOKIE_STR,
	    OIDC_SESSION_TYPE_CLIENT_COOKIE_STR OIDC_SESSION_TYPE_SEPARATOR OIDC_SESSION_TYPE_PERSISTENT,
	    OIDC_SESSION_TYPE_CLIENT_COOKIE_STR OIDC_SESSION_TYPE_SEPARATOR OIDC_SESSION_TYPE_STORE_ID_TOKEN,
	    OIDC_SESSION_TYPE_CLIENT_COOKIE_STR OIDC_SESSION_TYPE_SEPARATOR OIDC_SESSION_TYPE_PERSISTENT
		OIDC_SESSION_TYPE_SEPARATOR OIDC_SESSION_TYPE_STORE_ID_TOKEN,
	    NULL};

	const char *rv = oidc_cfg_parse_is_valid_option(cmd->pool, arg, options);
	if (rv != NULL)
		return OIDC_CONFIG_DIR_RV(cmd, rv);

	char *s = apr_pstrdup(cmd->pool, arg);
	char *p = _oidc_strstr(s, OIDC_SESSION_TYPE_SEPARATOR);

	if (p) {
		*p = '\0';
		p++;
	}

	if (_oidc_strcmp(s, OIDC_SESSION_TYPE_SERVER_CACHE_STR) == 0) {
		cfg->session_type = OIDC_SESSION_TYPE_SERVER_CACHE;
	} else if (_oidc_strcmp(s, OIDC_SESSION_TYPE_CLIENT_COOKIE_STR) == 0) {
		cfg->session_type = OIDC_SESSION_TYPE_CLIENT_COOKIE;
		cfg->store_id_token = 0;
	}

	if (p) {
		if (_oidc_strcmp(p, OIDC_SESSION_TYPE_PERSISTENT) == 0) {
			cfg->persistent_session_cookie = 1;
		} else if (_oidc_strcmp(p, OIDC_SESSION_TYPE_STORE_ID_TOKEN) == 0) {
			// only for client-cookie
			cfg->store_id_token = 1;
		} else if (_oidc_strcmp(p, OIDC_SESSION_TYPE_PERSISTENT OIDC_SESSION_TYPE_SEPARATOR
					       OIDC_SESSION_TYPE_STORE_ID_TOKEN) == 0) {
			// only for client-cookie
			cfg->persistent_session_cookie = 1;
			cfg->store_id_token = 1;
		}
	}

	return NULL;
}

#define OIDC_DEFAULT_SESSION_TYPE OIDC_SESSION_TYPE_SERVER_CACHE
OIDC_CFG_MEMBER_FUNC_TYPE_GET(session_type, int, OIDC_DEFAULT_SESSION_TYPE)

#define OIDC_DEFAULT_PERSISTENT_SESSION_COOKIE 0
OIDC_CFG_MEMBER_FUNC_TYPE_GET(persistent_session_cookie, int, OIDC_DEFAULT_PERSISTENT_SESSION_COOKIE)

#define OIDC_DEFAULT_STORE_ID_TOKEN 1
OIDC_CFG_MEMBER_FUNC_TYPE_GET(store_id_token, int, OIDC_DEFAULT_STORE_ID_TOKEN)

static const char *oidc_valid_endpoint_auth_method_impl(apr_pool_t *pool, const char *arg, apr_byte_t has_private_key) {
	static const char *options[] = {OIDC_ENDPOINT_AUTH_CLIENT_SECRET_POST,
					OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC,
					OIDC_ENDPOINT_AUTH_CLIENT_SECRET_JWT,
					OIDC_ENDPOINT_AUTH_NONE,
					OIDC_ENDPOINT_AUTH_BEARER_ACCESS_TOKEN,
					NULL,
					NULL};
	if (has_private_key)
		options[5] = OIDC_ENDPOINT_AUTH_PRIVATE_KEY_JWT;

	return oidc_cfg_parse_is_valid_option(pool, arg, options);
}

const char *oidc_cfg_valid_endpoint_auth_method(apr_pool_t *pool, const char *arg) {
	return oidc_valid_endpoint_auth_method_impl(pool, arg, TRUE);
}

const char *oidc_cfg_valid_endpoint_auth_method_no_private_key(apr_pool_t *pool, const char *arg) {
	return oidc_valid_endpoint_auth_method_impl(pool, arg, FALSE);
}

/*
 * return the right token endpoint authentication method validation function, based on whether private keys are set
 */
oidc_valid_function_t oidc_cfg_get_valid_endpoint_auth_function(oidc_cfg_t *cfg) {
	return (cfg->private_keys != NULL) ? &oidc_cfg_valid_endpoint_auth_method
					   : &oidc_cfg_valid_endpoint_auth_method_no_private_key;
}

#define OIDC_SESSION_INACTIVITY_TIMEOUT_MIN 10
#define OIDC_SESSION_INACTIVITY_TIMEOUT_MAX 3600 * 24 * 365
#define OIDC_DEFAULT_SESSION_INACTIVITY_TIMEOUT 300

OIDC_CFG_MEMBER_FUNCS_INT(session_inactivity_timeout, OIDC_SESSION_INACTIVITY_TIMEOUT_MIN,
			  OIDC_SESSION_INACTIVITY_TIMEOUT_MAX, OIDC_DEFAULT_SESSION_INACTIVITY_TIMEOUT)

const char *oidc_cmd_public_keys_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_parse_public_key_files(cmd->pool, arg, &cfg->public_keys);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_CFG_MEMBER_FUNC_GET(public_keys, const apr_array_header_t *)

/*
 * add a private key from an RSA/EC private key file to our list of JWKs with private keys
 */
const char *oidc_cmd_private_keys_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	char *use = NULL;

	char *kid = NULL, *name = NULL, *fname = NULL;
	int fname_len;
	const char *rv = oidc_cfg_parse_key_record(cmd->pool, arg, &kid, &name, &fname_len, &use, FALSE);
	if (rv != NULL)
		goto end;

	rv = oidc_cfg_parse_filename(cmd->pool, name, &fname);
	if (rv != NULL)
		goto end;

	if (oidc_jwk_parse_pem_private_key(cmd->pool, kid, fname, &jwk, &err) == FALSE) {
		rv = apr_psprintf(cmd->pool, "oidc_jwk_parse_pem_private_key failed for (kid=%s) \"%s\": %s", kid,
				  fname, oidc_jose_e2s(cmd->pool, err));
		goto end;
	}

	if (cfg->private_keys == NULL)
		cfg->private_keys = apr_array_make(cmd->pool, 4, sizeof(oidc_jwk_t *));
	if (use)
		jwk->use = apr_pstrdup(cmd->pool, use);
	APR_ARRAY_PUSH(cfg->private_keys, oidc_jwk_t *) = jwk;

end:

	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_CFG_MEMBER_FUNC_GET(private_keys, const apr_array_header_t *)

const char *oidc_cmd_remote_user_claim_set(cmd_parms *cmd, void *ptr, const char *v1, const char *v2, const char *v3) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_remote_user_claim(cmd->pool, v1, v2, v3, &cfg->remote_user_claim);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

const oidc_remote_user_claim_t *oidc_cfg_remote_user_claim_get(oidc_cfg_t *cfg) {
	return &cfg->remote_user_claim;
}

#define OIDC_DEFAULT_CLAIM_REMOTE_USER "sub@"

const char *oidc_cfg_remote_user_claim_name_get(oidc_cfg_t *cfg) {
	return cfg->remote_user_claim.claim_name != NULL ? cfg->remote_user_claim.claim_name
							 : OIDC_DEFAULT_CLAIM_REMOTE_USER;
}

#ifdef USE_LIBJQ

const char *oidc_cmd_filter_claims_expr_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_util_apr_expr_parse(cmd, arg, &cfg->filter_claims_expr, TRUE);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#endif

OIDC_CFG_MEMBER_FUNC_GET(filter_claims_expr, oidc_apr_expr_t *)

/*
 * define which data will be returned from the info hook
 */
const char *oidc_cmd_info_hook_data_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	static const char *options[] = {
	    OIDC_HOOK_INFO_TIMESTAMP,		OIDC_HOOK_INFO_ACCES_TOKEN, OIDC_HOOK_INFO_ACCES_TOKEN_EXP,
	    OIDC_HOOK_INFO_ID_TOKEN_HINT,	OIDC_HOOK_INFO_ID_TOKEN,    OIDC_HOOK_INFO_USER_INFO,
	    OIDC_HOOK_INFO_REFRESH_TOKEN,	OIDC_HOOK_INFO_SESSION_EXP, OIDC_HOOK_INFO_SESSION_TIMEOUT,
	    OIDC_HOOK_INFO_SESSION_REMOTE_USER, OIDC_HOOK_INFO_SESSION,	    NULL};
	const char *rv = oidc_cfg_parse_is_valid_option(cmd->pool, arg, options);
	if (rv != NULL)
		return OIDC_CONFIG_DIR_RV(cmd, rv);
	if (cfg->info_hook_data == NULL)
		cfg->info_hook_data = apr_hash_make(cmd->pool);
	apr_hash_set(cfg->info_hook_data, arg, APR_HASH_KEY_STRING, arg);
	return NULL;
}

OIDC_CFG_MEMBER_FUNC_GET(info_hook_data, apr_hash_t *)

const char *oidc_cmd_metrics_hook_data_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = NULL;
	char *valid_names = NULL;
	if (oidc_metrics_is_valid_classname(cmd->pool, arg, &valid_names) == TRUE) {
		if (cfg->metrics_hook_data == NULL)
			cfg->metrics_hook_data = apr_hash_make(cmd->pool);
		apr_hash_set(cfg->metrics_hook_data, arg, APR_HASH_KEY_STRING, arg);
	} else {
		rv = apr_psprintf(cmd->pool, "undefined metric class name: \"%s\", must be one of [%s]", arg,
				  valid_names);
	}
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_CFG_MEMBER_FUNC_GET(metrics_hook_data, apr_hash_t *)

#define OIDC_TRACE_PARENT_OFF_STR "off"
#define OIDC_TRACE_PARENT_PROPAGATE_STR "propagate"
#define OIDC_TRACE_PARENT_GENERATE_STR "generate"

const char *oidc_cmd_trace_parent_set(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	static const oidc_cfg_option_t options[] = {{OIDC_TRACE_PARENT_OFF, OIDC_TRACE_PARENT_OFF_STR},
						    {OIDC_TRACE_PARENT_PROPAGATE, OIDC_TRACE_PARENT_PROPAGATE_STR},
						    {OIDC_TRACE_PARENT_GENERATE, OIDC_TRACE_PARENT_GENERATE_STR}};
	const char *rv =
	    oidc_cfg_parse_option(cmd->pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg, &cfg->trace_parent);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_DEFAULT_TRACE_PARENT OIDC_TRACE_PARENT_OFF
OIDC_CFG_MEMBER_FUNC_TYPE_GET(trace_parent, oidc_trace_parent_t, OIDC_DEFAULT_TRACE_PARENT)

#define OIDC_DEFAULT_DPOP_API_ENABLED 0
OIDC_CFG_MEMBER_FUNC_TYPE_GET(dpop_api_enabled, int, OIDC_DEFAULT_DPOP_API_ENABLED)

const char *oidc_cmd_claim_prefix_set(cmd_parms *cmd, void *struct_ptr, const char *args) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	char *w = ap_getword_conf(cmd->pool, &args);
	if (*w == '\0' || *args != 0)
		cfg->claim_prefix = "";
	else
		cfg->claim_prefix = w;
	return NULL;
}

#define OIDC_DEFAULT_CLAIM_PREFIX "OIDC_CLAIM_"

const char *oidc_cfg_claim_prefix_get(oidc_cfg_t *cfg) {
	return (cfg->claim_prefix != NULL) ? cfg->claim_prefix : OIDC_DEFAULT_CLAIM_PREFIX;
}

#define OIDC_MAX_NUMBER_OF_STATE_COOKIES_MIN 0
#define OIDC_MAX_NUMBER_OF_STATE_COOKIES_MAX 255

const char *oidc_cmd_max_number_of_state_cookies_set(cmd_parms *cmd, void *struct_ptr, const char *arg1,
						     const char *arg2) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv =
	    oidc_cfg_parse_int_min_max(cmd->pool, arg1, &cfg->max_number_of_state_cookies,
				       OIDC_MAX_NUMBER_OF_STATE_COOKIES_MIN, OIDC_MAX_NUMBER_OF_STATE_COOKIES_MAX);
	if ((rv == NULL) && (arg2 != NULL))
		rv = oidc_cfg_parse_boolean(cmd->pool, arg2, &cfg->delete_oldest_state_cookies);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_DEFAULT_MAX_NUMBER_OF_STATE_COOKIES 7
OIDC_CFG_MEMBER_FUNC_TYPE_GET(max_number_of_state_cookies, int, OIDC_DEFAULT_MAX_NUMBER_OF_STATE_COOKIES)

#define OIDC_DEFAULT_DELETE_OLDEST_STATE_COOKIES 0
OIDC_CFG_MEMBER_FUNC_TYPE_GET(delete_oldest_state_cookies, int, OIDC_DEFAULT_DELETE_OLDEST_STATE_COOKIES)

const char *oidc_cmd_x_forwarded_headers_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	static const oidc_cfg_option_t options[] = {{OIDC_HDR_NONE, "none"},
						    {OIDC_HDR_X_FORWARDED_HOST, OIDC_HTTP_HDR_X_FORWARDED_HOST},
						    {OIDC_HDR_X_FORWARDED_PORT, OIDC_HTTP_HDR_X_FORWARDED_PORT},
						    {OIDC_HDR_X_FORWARDED_PROTO, OIDC_HTTP_HDR_X_FORWARDED_PROTO},
						    {OIDC_HDR_FORWARDED, OIDC_HTTP_HDR_FORWARDED}};
	int v = OIDC_CONFIG_POS_INT_UNSET;
	const char *rv = oidc_cfg_parse_option(cmd->pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg, &v);
	if ((rv == NULL) && (v != OIDC_CONFIG_POS_INT_UNSET)) {
		// NB: cannot use |= with UNSET/-1 !
		if (cfg->x_forwarded_headers == OIDC_CONFIG_POS_INT_UNSET)
			cfg->x_forwarded_headers = OIDC_HDR_NONE;
		cfg->x_forwarded_headers |= v;
	}
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_DEFAULT_X_FORWARDED_HEADERS OIDC_HDR_NONE
OIDC_CFG_MEMBER_FUNC_TYPE_GET(x_forwarded_headers, oidc_hdr_x_forwarded_t, OIDC_DEFAULT_X_FORWARDED_HEADERS)

#define OIDC_CHECK_X_FORWARDED_HDR_LOG_DISABLE "OIDC_CHECK_X_FORWARDED_HDR_LOG_DISABLE"

static void oidc_check_x_forwarded_hdr(request_rec *r, const apr_byte_t x_forwarded_headers, const apr_byte_t hdr_type,
				       const char *hdr_str, const char *(hdr_func)(const request_rec *r)) {
	apr_byte_t suppress = oidc_util_spaced_string_contains(
	    r->pool, apr_table_get(r->subprocess_env, OIDC_CHECK_X_FORWARDED_HDR_LOG_DISABLE), hdr_str);
	if (hdr_func(r)) {
		if (!(x_forwarded_headers & hdr_type) && !suppress)
			oidc_warn(r, "header %s received but %s not configured for it", hdr_str, OIDCXForwardedHeaders);
	} else {
		if ((x_forwarded_headers & hdr_type) && !suppress)
			oidc_warn(r, "%s configured for header %s but not found in request", OIDCXForwardedHeaders,
				  hdr_str);
	}
}

void oidc_cfg_x_forwarded_headers_check(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers) {
	oidc_check_x_forwarded_hdr(r, x_forwarded_headers, OIDC_HDR_X_FORWARDED_HOST, OIDC_HTTP_HDR_X_FORWARDED_HOST,
				   oidc_http_hdr_in_x_forwarded_host_get);
	oidc_check_x_forwarded_hdr(r, x_forwarded_headers, OIDC_HDR_X_FORWARDED_PORT, OIDC_HTTP_HDR_X_FORWARDED_PORT,
				   oidc_http_hdr_in_x_forwarded_port_get);
	oidc_check_x_forwarded_hdr(r, x_forwarded_headers, OIDC_HDR_X_FORWARDED_PROTO, OIDC_HTTP_HDR_X_FORWARDED_PROTO,
				   oidc_http_hdr_in_x_forwarded_proto_get);
	oidc_check_x_forwarded_hdr(r, x_forwarded_headers, OIDC_HDR_FORWARDED, OIDC_HTTP_HDR_FORWARDED,
				   oidc_http_hdr_in_forwarded_get);
}

#define OIDC_STATE_INPUT_HEADERS_AS_NONE "none"
#define OIDC_STATE_INPUT_HEADERS_AS_USER_AGENT "user-agent"
#define OIDC_STATE_INPUT_HEADERS_AS_X_FORWARDED_FOR "x-forwarded-for"
#define OIDC_STATE_INPUT_HEADERS_AS_BOTH "both"

/*
 * define which header we use for calculating the fingerprint of the state during authentication
 */
const char *oidc_cmd_state_input_headers_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	static const oidc_cfg_option_t options[] = {
	    {OIDC_STATE_INPUT_HEADERS_NONE, OIDC_STATE_INPUT_HEADERS_AS_NONE},
	    {OIDC_STATE_INPUT_HEADERS_USER_AGENT, OIDC_STATE_INPUT_HEADERS_AS_USER_AGENT},
	    {OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR, OIDC_STATE_INPUT_HEADERS_AS_X_FORWARDED_FOR},
	    {OIDC_STATE_INPUT_HEADERS_USER_AGENT | OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR,
	     OIDC_STATE_INPUT_HEADERS_AS_BOTH}};
	const char *rv =
	    oidc_cfg_parse_option(cmd->pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg, &cfg->state_input_headers);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_DEFAULT_STATE_INPUT_HEADERS OIDC_STATE_INPUT_HEADERS_USER_AGENT
OIDC_CFG_MEMBER_FUNC_TYPE_GET(state_input_headers, oidc_state_input_hdrs_t, OIDC_DEFAULT_STATE_INPUT_HEADERS)

const char *oidc_cmd_post_preserve_templates_set(cmd_parms *cmd, void *m, const char *arg1, const char *arg2) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = NULL;
	if (arg1 != NULL)
		rv = oidc_cfg_parse_filename(cmd->pool, arg1, &cfg->post_preserve_template);
	if ((rv == NULL) && (arg2 != NULL))
		rv = oidc_cfg_parse_filename(cmd->pool, arg2, &cfg->post_restore_template);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_CFG_MEMBER_FUNC_GET(post_preserve_template, const char *)
OIDC_CFG_MEMBER_FUNC_GET(post_restore_template, const char *)

const char *oidc_cmd_ca_bundle_path_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_parse_filename(cmd->pool, arg, &cfg->ca_bundle_path);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_CFG_MEMBER_FUNC_GET(ca_bundle_path, const char *)

const char *oidc_cmd_metadata_dir_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_parse_dirname(cmd->pool, arg, &cfg->metadata_dir);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_CFG_MEMBER_FUNC_GET(metadata_dir, const char *)

#define OIDC_DEFAULT_COOKIE_HTTPONLY 1
OIDC_CFG_MEMBER_FUNCS_BOOL(cookie_http_only, OIDC_DEFAULT_COOKIE_HTTPONLY)

#define OIDC_SAMESITE_COOKIE_OFF_STR "Off"
#define OIDC_SAMESITE_COOKIE_ON_STR "On"
#define OIDC_SAMESITE_COOKIE_DISABLED_STR "Disabled"
#define OIDC_SAMESITE_COOKIE_NONE_STR "None"
#define OIDC_SAMESITE_COOKIE_LAX_STR "Lax"
#define OIDC_SAMESITE_COOKIE_STRICT_STR "Strict"

/*
 * define which header we use for calculating the fingerprint of the state during authentication
 */
const char *oidc_cmd_cookie_same_site_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	// NB: On is made equal to Lax here and Off is equal to None (backwards compatibility)
	static const oidc_cfg_option_t options[] = {{OIDC_SAMESITE_COOKIE_NONE, OIDC_SAMESITE_COOKIE_OFF_STR},
						    {OIDC_SAMESITE_COOKIE_LAX, OIDC_SAMESITE_COOKIE_ON_STR},
						    {OIDC_SAMESITE_COOKIE_DISABLED, OIDC_SAMESITE_COOKIE_DISABLED_STR},
						    {OIDC_SAMESITE_COOKIE_NONE, OIDC_SAMESITE_COOKIE_NONE_STR},
						    {OIDC_SAMESITE_COOKIE_LAX, OIDC_SAMESITE_COOKIE_LAX_STR},
						    {OIDC_SAMESITE_COOKIE_STRICT, OIDC_SAMESITE_COOKIE_STRICT_STR}};
	const char *rv = oidc_cfg_parse_option_ignore_case(cmd->pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg,
							   &cfg->cookie_same_site);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_DEFAULT_COOKIE_SAME_SITE OIDC_SAMESITE_COOKIE_LAX
OIDC_CFG_MEMBER_FUNC_TYPE_GET(cookie_same_site, oidc_samesite_cookie_t, OIDC_DEFAULT_COOKIE_SAME_SITE)

#define OIDC_DEFAULT_SESSION_FALLBACK_TO_COOKIE 0
OIDC_CFG_MEMBER_FUNCS_BOOL(session_cache_fallback_to_cookie, OIDC_DEFAULT_SESSION_FALLBACK_TO_COOKIE)

#define OIDC_DEFAULT_CLAIM_DELIMITER ","
OIDC_CFG_MEMBER_FUNCS_STR_DEF(claim_delimiter, NULL, OIDC_DEFAULT_CLAIM_DELIMITER)

OIDC_CFG_MEMBER_FUNCS_STR_DEF(metrics_path, NULL, NULL)

#define OIDC_DEFAULT_LOGOUT_X_FRAME_OPTIONS "DENY"
OIDC_CFG_MEMBER_FUNCS_STR_DEF(logout_x_frame_options, NULL, OIDC_DEFAULT_LOGOUT_X_FRAME_OPTIONS)

#define OIDC_STATE_TIMEOUT_MIN 1
#define OIDC_STATE_TIMEOUT_MAX 3600 * 24 * 30
#define OIDC_DEFAULT_STATE_TIMEOUT 300

OIDC_CFG_MEMBER_FUNCS_INT(state_timeout, OIDC_STATE_TIMEOUT_MIN, OIDC_STATE_TIMEOUT_MAX, OIDC_DEFAULT_STATE_TIMEOUT)

#define OIDC_SESSION_CLIENT_COOKIE_CHUNK_SIZE_MIN 256
#define OIDC_SESSION_CLIENT_COOKIE_CHUNK_SIZE_MAX 1024 * 64
#define OIDC_DEFAULT_SESSION_CLIENT_COOKIE_CHUNK_SIZE 4000

OIDC_CFG_MEMBER_FUNCS_INT(session_cookie_chunk_size, OIDC_SESSION_CLIENT_COOKIE_CHUNK_SIZE_MIN,
			  OIDC_SESSION_CLIENT_COOKIE_CHUNK_SIZE_MAX, OIDC_DEFAULT_SESSION_CLIENT_COOKIE_CHUNK_SIZE)

#define OIDC_PROVIDER_METADATA_REFRESH_INTERVAL_MIN 30
#define OIDC_PROVIDER_METADATA_REFRESH_INTERVAL_MAX 3600 * 24 * 365
#define OIDC_DEFAULT_PROVIDER_METADATA_REFRESH_INTERVAL 0

OIDC_CFG_MEMBER_FUNCS_INT(provider_metadata_refresh_interval, OIDC_PROVIDER_METADATA_REFRESH_INTERVAL_MIN,
			  OIDC_PROVIDER_METADATA_REFRESH_INTERVAL_MAX, OIDC_DEFAULT_PROVIDER_METADATA_REFRESH_INTERVAL)

#define OIDC_CFG_MEMBER_FUNCS_HASHTABLE(member)                                                                        \
	const char *oidc_cmd_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                              \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		if (cfg->member == NULL)                                                                               \
			cfg->member = apr_hash_make(cmd->pool);                                                        \
		apr_hash_set(cfg->member, arg, APR_HASH_KEY_STRING, arg);                                              \
		return NULL;                                                                                           \
	}                                                                                                              \
                                                                                                                       \
	OIDC_CFG_MEMBER_FUNC_GET(member, apr_hash_t *)

OIDC_CFG_MEMBER_FUNCS_HASHTABLE(white_listed_claims)
OIDC_CFG_MEMBER_FUNCS_HASHTABLE(black_listed_claims)
OIDC_CFG_MEMBER_FUNCS_HASHTABLE(redirect_urls_allowed)

#define OIDC_CFG_MEMBER_FUNCS_ABS_OR_REL_URI(member)                                                                   \
	const char *oidc_cmd_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                              \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = oidc_cfg_parse_relative_or_absolute_url(cmd->pool, arg, &cfg->member);                \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	OIDC_CFG_MEMBER_FUNC_GET(member, const char *)

OIDC_CFG_MEMBER_FUNCS_ABS_OR_REL_URI(redirect_uri)
OIDC_CFG_MEMBER_FUNCS_ABS_OR_REL_URI(default_sso_url)
OIDC_CFG_MEMBER_FUNCS_ABS_OR_REL_URI(default_slo_url)

/*
 * destroy a server config record and its members
 */
static apr_status_t oidc_cfg_server_destroy(void *data) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)data;
	oidc_cfg_provider_destroy(cfg->provider);
	oidc_cfg_oauth_destroy(cfg->oauth);
	oidc_jwk_list_destroy(cfg->public_keys);
	oidc_jwk_list_destroy(cfg->private_keys);
	return APR_SUCCESS;
}

/*
 * create a new server config record with defaults
 */
void *oidc_cfg_server_create(apr_pool_t *pool, server_rec *svr) {
	oidc_cfg_t *c = apr_pcalloc(pool, sizeof(oidc_cfg_t));
	apr_pool_cleanup_register(pool, c, oidc_cfg_server_destroy, oidc_cfg_server_destroy);

	c->merged = FALSE;

	c->redirect_uri = NULL;
	c->default_sso_url = NULL;
	c->default_slo_url = NULL;
	c->public_keys = NULL;
	c->private_keys = NULL;

	c->provider = oidc_cfg_provider_create(pool);
	c->oauth = oidc_cfg_oauth_create(pool);
	oidc_cfg_cache_create_server_config(c);

	c->metadata_dir = NULL;
	c->session_type = OIDC_CONFIG_POS_INT_UNSET;
	c->session_cache_fallback_to_cookie = OIDC_CONFIG_POS_INT_UNSET;
	c->persistent_session_cookie = OIDC_CONFIG_POS_INT_UNSET;
	c->store_id_token = OIDC_CONFIG_POS_INT_UNSET;
	c->session_cookie_chunk_size = OIDC_CONFIG_POS_INT_UNSET;

	c->http_timeout_long.request_timeout = OIDC_CONFIG_POS_INT_UNSET;
	c->http_timeout_long.connect_timeout = OIDC_DEFAULT_HTTP_CONNECT_TIMEOUT_LONG;
	c->http_timeout_long.retries = OIDC_DEFAULT_HTTP_RETRIES_LONG;
	c->http_timeout_long.retry_interval = OIDC_DEFAULT_HTTP_RETRY_INTERVAL_LONG;
	c->http_timeout_short.request_timeout = OIDC_CONFIG_POS_INT_UNSET;
	c->http_timeout_short.connect_timeout = OIDC_DEFAULT_HTTP_CONNECT_TIMEOUT_SHORT;
	c->http_timeout_short.retries = OIDC_DEFAULT_HTTP_RETRIES_SHORT;
	c->http_timeout_short.retry_interval = OIDC_DEFAULT_HTTP_RETRY_INTERVAL_SHORT;

	c->state_timeout = OIDC_CONFIG_POS_INT_UNSET;
	c->max_number_of_state_cookies = OIDC_CONFIG_POS_INT_UNSET;
	c->delete_oldest_state_cookies = OIDC_CONFIG_POS_INT_UNSET;
	c->session_inactivity_timeout = OIDC_CONFIG_POS_INT_UNSET;

	c->cookie_domain = NULL;
	c->claim_delimiter = NULL;
	c->claim_prefix = NULL;
	c->remote_user_claim.claim_name = NULL;
	c->remote_user_claim.reg_exp = NULL;
	c->remote_user_claim.replace = NULL;
	c->cookie_http_only = OIDC_CONFIG_POS_INT_UNSET;
	c->cookie_same_site = OIDC_CONFIG_POS_INT_UNSET;

	c->outgoing_proxy.host_port = NULL;
	c->outgoing_proxy.username_password = NULL;
	c->outgoing_proxy.auth_type = OIDC_CONFIG_POS_INT_UNSET;

	c->crypto_passphrase.secret1 = NULL;
	c->crypto_passphrase.secret2 = NULL;

	c->post_preserve_template = NULL;
	c->post_restore_template = NULL;

	c->provider_metadata_refresh_interval = OIDC_CONFIG_POS_INT_UNSET;

	c->info_hook_data = NULL;
	c->metrics_hook_data = NULL;
	c->metrics_path = NULL;
	c->trace_parent = OIDC_CONFIG_POS_INT_UNSET;
	c->dpop_api_enabled = OIDC_CONFIG_POS_INT_UNSET;

	c->black_listed_claims = NULL;
	c->white_listed_claims = NULL;
	c->filter_claims_expr = NULL;

	c->state_input_headers = OIDC_CONFIG_POS_INT_UNSET;
	c->redirect_urls_allowed = NULL;
	c->ca_bundle_path = NULL;
	c->logout_x_frame_options = NULL;
	c->x_forwarded_headers = OIDC_CONFIG_POS_INT_UNSET;
	c->action_on_userinfo_error = OIDC_CONFIG_POS_INT_UNSET;

	return c;
}

/*
 * merge a new server config with a base one
 */
void *oidc_cfg_server_merge(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_cfg_t *base = (oidc_cfg_t *)BASE;
	oidc_cfg_t *add = (oidc_cfg_t *)ADD;

	oidc_cfg_t *c = apr_pcalloc(pool, sizeof(oidc_cfg_t));
	apr_pool_cleanup_register(pool, c, oidc_cfg_server_destroy, oidc_cfg_server_destroy);
	c->provider = oidc_cfg_provider_create(pool);
	c->oauth = oidc_cfg_oauth_create(pool);

	c->merged = TRUE;

	oidc_cfg_provider_merge(pool, c->provider, base->provider, add->provider);
	oidc_cfg_oauth_merge(pool, c->oauth, base->oauth, add->oauth);
	oidc_cfg_cache_merge_server_config(c, base, add);

	c->redirect_uri = add->redirect_uri != NULL ? add->redirect_uri : base->redirect_uri;
	c->default_sso_url = add->default_sso_url != NULL ? add->default_sso_url : base->default_sso_url;
	c->default_slo_url = add->default_slo_url != NULL ? add->default_slo_url : base->default_slo_url;
	c->public_keys = oidc_jwk_list_copy(pool, add->public_keys != NULL ? add->public_keys : base->public_keys);
	c->private_keys = oidc_jwk_list_copy(pool, add->private_keys != NULL ? add->private_keys : base->private_keys);

	if (add->http_timeout_long.request_timeout != OIDC_CONFIG_POS_INT_UNSET) {
		c->http_timeout_long.request_timeout = add->http_timeout_long.request_timeout;
		c->http_timeout_long.connect_timeout = add->http_timeout_long.connect_timeout;
		c->http_timeout_long.retries = add->http_timeout_long.retries;
		c->http_timeout_long.retry_interval = add->http_timeout_long.retry_interval;
	} else {
		c->http_timeout_long.request_timeout = base->http_timeout_long.request_timeout;
		c->http_timeout_long.connect_timeout = base->http_timeout_long.connect_timeout;
		c->http_timeout_long.retries = base->http_timeout_long.retries;
		c->http_timeout_long.retry_interval = base->http_timeout_long.retry_interval;
	}

	if (add->http_timeout_short.request_timeout != OIDC_CONFIG_POS_INT_UNSET) {
		c->http_timeout_short.request_timeout = add->http_timeout_short.request_timeout;
		c->http_timeout_short.connect_timeout = add->http_timeout_short.connect_timeout;
		c->http_timeout_short.retries = add->http_timeout_short.retries;
		c->http_timeout_short.retry_interval = add->http_timeout_short.retry_interval;
	} else {
		c->http_timeout_short.request_timeout = base->http_timeout_short.request_timeout;
		c->http_timeout_short.connect_timeout = base->http_timeout_short.connect_timeout;
		c->http_timeout_short.retries = base->http_timeout_short.retries;
		c->http_timeout_short.retry_interval = base->http_timeout_short.retry_interval;
	}

	c->state_timeout = add->state_timeout != OIDC_CONFIG_POS_INT_UNSET ? add->state_timeout : base->state_timeout;
	c->max_number_of_state_cookies = add->max_number_of_state_cookies != OIDC_CONFIG_POS_INT_UNSET
					     ? add->max_number_of_state_cookies
					     : base->max_number_of_state_cookies;
	c->delete_oldest_state_cookies = add->delete_oldest_state_cookies != OIDC_CONFIG_POS_INT_UNSET
					     ? add->delete_oldest_state_cookies
					     : base->delete_oldest_state_cookies;
	c->session_inactivity_timeout = add->session_inactivity_timeout != OIDC_CONFIG_POS_INT_UNSET
					    ? add->session_inactivity_timeout
					    : base->session_inactivity_timeout;

	c->metadata_dir = add->metadata_dir != NULL ? add->metadata_dir : base->metadata_dir;

	c->session_type = add->session_type != OIDC_CONFIG_POS_INT_UNSET ? add->session_type : base->session_type;
	c->session_cache_fallback_to_cookie = add->session_cache_fallback_to_cookie != OIDC_CONFIG_POS_INT_UNSET
						  ? add->session_cache_fallback_to_cookie
						  : base->session_cache_fallback_to_cookie;
	c->persistent_session_cookie = add->persistent_session_cookie != OIDC_CONFIG_POS_INT_UNSET
					   ? add->persistent_session_cookie
					   : base->persistent_session_cookie;
	c->store_id_token =
	    add->store_id_token != OIDC_CONFIG_POS_INT_UNSET ? add->store_id_token : base->store_id_token;
	c->session_cookie_chunk_size = add->session_cookie_chunk_size != OIDC_CONFIG_POS_INT_UNSET
					   ? add->session_cookie_chunk_size
					   : base->session_cookie_chunk_size;

	c->cookie_domain = add->cookie_domain != NULL ? add->cookie_domain : base->cookie_domain;
	c->claim_delimiter = add->claim_delimiter != NULL ? add->claim_delimiter : base->claim_delimiter;
	c->claim_prefix = add->claim_prefix != NULL ? add->claim_prefix : base->claim_prefix;

	if (add->remote_user_claim.claim_name != NULL) {
		c->remote_user_claim.claim_name = add->remote_user_claim.claim_name;
		c->remote_user_claim.reg_exp = add->remote_user_claim.reg_exp;
		c->remote_user_claim.replace = add->remote_user_claim.replace;
	} else {
		c->remote_user_claim.claim_name = base->remote_user_claim.claim_name;
		c->remote_user_claim.reg_exp = base->remote_user_claim.reg_exp;
		c->remote_user_claim.replace = base->remote_user_claim.replace;
	}

	c->cookie_http_only =
	    add->cookie_http_only != OIDC_CONFIG_POS_INT_UNSET ? add->cookie_http_only : base->cookie_http_only;
	c->cookie_same_site =
	    add->cookie_same_site != OIDC_CONFIG_POS_INT_UNSET ? add->cookie_same_site : base->cookie_same_site;

	if (add->outgoing_proxy.host_port != NULL) {
		c->outgoing_proxy.host_port = add->outgoing_proxy.host_port;
		c->outgoing_proxy.username_password = add->outgoing_proxy.username_password;
		c->outgoing_proxy.auth_type = add->outgoing_proxy.auth_type;
	} else {
		c->outgoing_proxy.host_port = base->outgoing_proxy.host_port;
		c->outgoing_proxy.username_password = base->outgoing_proxy.username_password;
		c->outgoing_proxy.auth_type = base->outgoing_proxy.auth_type;
	}

	if (add->crypto_passphrase.secret1 != NULL) {
		c->crypto_passphrase.secret1 = add->crypto_passphrase.secret1;
		c->crypto_passphrase.secret2 = add->crypto_passphrase.secret2;
	} else {
		c->crypto_passphrase.secret1 = base->crypto_passphrase.secret1;
		c->crypto_passphrase.secret2 = base->crypto_passphrase.secret2;
	}

	c->post_preserve_template =
	    add->post_preserve_template != NULL ? add->post_preserve_template : base->post_preserve_template;
	c->post_restore_template =
	    add->post_restore_template != NULL ? add->post_restore_template : base->post_restore_template;

	c->provider_metadata_refresh_interval = add->provider_metadata_refresh_interval != OIDC_CONFIG_POS_INT_UNSET
						    ? add->provider_metadata_refresh_interval
						    : base->provider_metadata_refresh_interval;

	c->info_hook_data = add->info_hook_data != NULL ? add->info_hook_data : base->info_hook_data;
	c->metrics_hook_data = add->metrics_hook_data != NULL ? add->metrics_hook_data : base->metrics_hook_data;
	c->metrics_path = add->metrics_path != NULL ? add->metrics_path : base->metrics_path;
	c->trace_parent = add->trace_parent != OIDC_CONFIG_POS_INT_UNSET ? add->trace_parent : base->trace_parent;
	c->dpop_api_enabled =
	    add->dpop_api_enabled != OIDC_CONFIG_POS_INT_UNSET ? add->dpop_api_enabled : base->dpop_api_enabled;

	c->black_listed_claims =
	    add->black_listed_claims != NULL ? add->black_listed_claims : base->black_listed_claims;
	c->white_listed_claims =
	    add->white_listed_claims != NULL ? add->white_listed_claims : base->white_listed_claims;
	c->filter_claims_expr = add->filter_claims_expr != NULL ? add->filter_claims_expr : base->filter_claims_expr;

	c->state_input_headers = add->state_input_headers != OIDC_CONFIG_POS_INT_UNSET ? add->state_input_headers
										       : base->state_input_headers;

	c->redirect_urls_allowed =
	    add->redirect_urls_allowed != NULL ? add->redirect_urls_allowed : base->redirect_urls_allowed;

	c->ca_bundle_path = add->ca_bundle_path != NULL ? add->ca_bundle_path : base->ca_bundle_path;

	c->logout_x_frame_options =
	    add->logout_x_frame_options != NULL ? add->logout_x_frame_options : base->logout_x_frame_options;

	c->x_forwarded_headers = add->x_forwarded_headers != OIDC_CONFIG_POS_INT_UNSET ? add->x_forwarded_headers
										       : base->x_forwarded_headers;

	c->action_on_userinfo_error = add->action_on_userinfo_error != OIDC_CONFIG_POS_INT_UNSET
					  ? add->action_on_userinfo_error
					  : base->action_on_userinfo_error;

	return c;
}

#if OPENSSL_API_COMPAT < 0x10100000L
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

/*
 * initialize before the post config handler runs
 */
void oidc_pre_config_init() {
#if OPENSSL_API_COMPAT < 0x10100000L
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
#else
	OPENSSL_init_crypto(0, NULL);
#endif
}

oidc_provider_t *oidc_cfg_provider_get(oidc_cfg_t *cfg) {
	return cfg->provider;
}

int oidc_cfg_merged_get(oidc_cfg_t *cfg) {
	return cfg->merged;
}

static oidc_cache_mutex_t *_oidc_refresh_mutex = NULL;

oidc_cache_mutex_t *oidc_cfg_refresh_mutex_get(oidc_cfg_t *cfg) {
	return _oidc_refresh_mutex;
}

int oidc_cfg_post_config(oidc_cfg_t *cfg, server_rec *s) {
	if (cfg->cache.impl == NULL)
		cfg->cache.impl = &oidc_cache_shm;
	if (cfg->cache.impl->post_config != NULL) {
		if (cfg->cache.impl->post_config(s) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (_oidc_refresh_mutex == NULL) {
		_oidc_refresh_mutex = oidc_cache_mutex_create(s->process->pool, TRUE);
		if (oidc_cache_mutex_post_config(s, _oidc_refresh_mutex, "refresh") != TRUE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (cfg->metrics_hook_data != NULL) {
		if (oidc_metrics_post_config(s) != TRUE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}
	return OK;
}

void oidc_cfg_child_init(apr_pool_t *pool, oidc_cfg_t *cfg, server_rec *s) {
	if (cfg->cache.impl->child_init != NULL) {
		if (cfg->cache.impl->child_init(pool, s) != APR_SUCCESS) {
			oidc_serror(s, "cfg->cache->child_init failed");
		}
	}
	if (_oidc_refresh_mutex != NULL) {
		if (oidc_cache_mutex_child_init(pool, s, _oidc_refresh_mutex) != APR_SUCCESS) {
			oidc_serror(s, "oidc_cache_mutex_child_init on refresh mutex failed");
		}
	}
	if (cfg->metrics_hook_data != NULL) {
		if (oidc_metrics_child_init(pool, s) != APR_SUCCESS) {
			oidc_serror(s, "oidc_metrics_cache_child_init failed");
		}
	}
}

void oidc_cfg_cleanup_child(oidc_cfg_t *cfg, server_rec *s) {
	if (cfg->cache.impl->destroy != NULL) {
		if (cfg->cache.impl->destroy(s) != APR_SUCCESS) {
			oidc_serror(s, "cache destroy function failed");
		}
	}
	if (_oidc_refresh_mutex != NULL) {
		if (oidc_cache_mutex_destroy(s, _oidc_refresh_mutex) != TRUE) {
			oidc_serror(s, "oidc_cache_mutex_destroy on refresh mutex failed");
		}
		// this is a singleton, make sure we call destroy only once
		_oidc_refresh_mutex = NULL;
	}
	if (cfg->metrics_hook_data != NULL) {
		if (oidc_metrics_cleanup(s) != APR_SUCCESS) {
			oidc_serror(s, "oidc_metrics_cleanup failed");
		}
	}
}
