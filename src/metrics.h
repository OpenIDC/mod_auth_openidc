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

#ifndef _MOD_AUTH_OPENIDC_METRICS_H_
#define _MOD_AUTH_OPENIDC_METRICS_H_

#include "const.h" // for the PACKAGE_* defines
#include <apr_hash.h>
#include <httpd.h>

apr_byte_t oidc_metrics_is_valid_classname(apr_pool_t *pool, const char *name, char **valid_names);
apr_byte_t oidc_metrics_post_config(apr_pool_t *pool, server_rec *s);
apr_status_t oidc_metrics_child_init(apr_pool_t *p, server_rec *s);
apr_status_t oidc_metrics_cleanup(server_rec *s);
int oidc_metrics_handle_request(request_rec *r);

// NB: order must match what is defined in metrics.c in array _oidc_metrics_timings_info
typedef enum {

	OM_MOD_AUTH_OPENIDC = 0,

	OM_AUTHN_REQUEST,
	OM_AUTHN_RESPONSE,

	OM_SESSION_VALID,

	OM_PROVIDER_METADATA,
	OM_PROVIDER_TOKEN,
	OM_PROVIDER_REFRESH,
	OM_PROVIDER_USERINFO,

	OM_CACHE_READ,
	OM_CACHE_WRITE,

} oidc_metrics_timing_type_t;

typedef struct oidc_metrics_timing_info_t {
	char *class_name;
	char *metric_name;
	char *desc;
} oidc_metrics_timing_info_t;

extern const oidc_metrics_timing_info_t _oidc_metrics_timings_info[];

void oidc_metrics_timing_add(request_rec *r, oidc_metrics_timing_type_t type, apr_time_t elapsed);

#define OIDC_METRICS_TIMING_VAR apr_time_t _oidc_metrics_tstart = 0;

#define OIDC_METRICS_TIMING_START(r, cfg)                                                                              \
	OIDC_METRICS_TIMING_VAR                                                                                        \
	if (oidc_cfg_metrics_hook_data_get(cfg) != NULL) {                                                             \
		_oidc_metrics_tstart = apr_time_now();                                                                 \
	}

#define OIDC_METRICS_TIMING_ADD(r, cfg, type)                                                                          \
	if (oidc_cfg_metrics_hook_data_get(cfg) != NULL) {                                                             \
		if (apr_hash_get(oidc_cfg_metrics_hook_data_get(cfg), _oidc_metrics_timings_info[type].class_name,     \
				 APR_HASH_KEY_STRING) != NULL) {                                                       \
			oidc_metrics_timing_add(r, type, apr_time_now() - _oidc_metrics_tstart);                       \
		}                                                                                                      \
	}
#define OIDC_METRICS_REQUEST_STATE_TIMER_KEY "oidc-metrics-request-timer"

#define OIDC_METRICS_TIMING_REQUEST_START(r, cfg)                                                                      \
	if (oidc_cfg_metrics_hook_data_get(cfg) != NULL) {                                                             \
		oidc_request_state_set(r, OIDC_METRICS_REQUEST_STATE_TIMER_KEY,                                        \
				       apr_psprintf(r->pool, "%" APR_TIME_T_FMT, apr_time_now()));                     \
	}

#define OIDC_METRICS_TIMING_REQUEST_ADD(r, cfg, type)                                                                  \
	OIDC_METRICS_TIMING_VAR                                                                                        \
	if (oidc_cfg_metrics_hook_data_get(cfg) != NULL) {                                                             \
		_oidc_metrics_tstart =                                                                                 \
		    _oidc_str_to_time(oidc_request_state_get(r, OIDC_METRICS_REQUEST_STATE_TIMER_KEY), -1);            \
		if (_oidc_metrics_tstart > -1) {                                                                       \
			OIDC_METRICS_TIMING_ADD(r, cfg, type);                                                         \
		} else {                                                                                               \
			oidc_warn(r,                                                                                   \
				  "metrics: could not add timing because start timer was not found in request state"); \
		}                                                                                                      \
	}

// NB: order must match what is defined in metrics.c in array _oidc_metrics_counters_info
/*
 * single source of truth binding each counter's enum value to its exported class, metric name
 * and description: the oidc_metrics_counter_type_t enum below and the
 * _oidc_metrics_counters_info table in metrics.c are both generated from this list, so the
 * index correspondence between them can no longer skew (the OM_CLASS_* string constants are
 * defined in metrics.c, where the table is expanded)
 */
// clang-format off
#define OIDC_METRICS_COUNTERS_LIST(X) \
	X(OM_AUTHTYPE_MOD_AUTH_OPENIDC,            OM_CLASS_AUTH_TYPE,     "mod_auth_openidc",              "requests handled by mod_auth_openidc") \
	X(OM_AUTHTYPE_OPENID_CONNECT,              OM_CLASS_AUTH_TYPE,     "openid-connect",                "requests handled by AuthType openid-connect") \
	X(OM_AUTHTYPE_OAUTH20,                     OM_CLASS_AUTH_TYPE,     "oauth20",                       "requests handled by AuthType oauth20") \
	X(OM_AUTHTYPE_AUTH_OPENIDC,                OM_CLASS_AUTH_TYPE,     "auth-openidc",                  "requests handled by AuthType auth-openidc") \
	X(OM_AUTHTYPE_DECLINED,                    OM_CLASS_AUTH_TYPE,     "declined",                      "requests not handled by mod_auth_openidc") \
	X(OM_AUTHN_REQUEST_ERROR_URL,              OM_CLASS_AUTHN,         "request.error.url",             "errors matching the incoming request URL against the configuration") \
	X(OM_AUTHN_RESPONSE_ERROR_STATE_MISMATCH,  OM_CLASS_AUTHN,         "response.error.state-mismatch", "state mismatch errors in authentication responses") \
	X(OM_AUTHN_RESPONSE_ERROR_STATE_EXPIRED,   OM_CLASS_AUTHN,         "response.error.state-expired",  "state expired errors in authentication responses") \
	X(OM_AUTHN_RESPONSE_ERROR_PROVIDER,        OM_CLASS_AUTHN,         "response.error.provider",       "errors returned by the provider in authentication responses") \
	X(OM_AUTHN_RESPONSE_ERROR_PROTOCOL,        OM_CLASS_AUTHN,         "response.error.protocol",       "protocol errors handling authentication responses") \
	X(OM_AUTHN_RESPONSE_ERROR_REMOTE_USER,     OM_CLASS_AUTHN,         "response.error.remote-user",    "errors identifying the remote user based on provided claims") \
	X(OM_AUTHZ_ACTION_AUTH,                    OM_CLASS_AUTHZ,         "action.auth",                   "step-up authentication requests") \
	X(OM_AUTHZ_ACTION_401,                     OM_CLASS_AUTHZ,         "action.401",                    "401 authorization errors") \
	X(OM_AUTHZ_ACTION_403,                     OM_CLASS_AUTHZ,         "action.403",                    "403 authorization errors") \
	X(OM_AUTHZ_ACTION_302,                     OM_CLASS_AUTHZ,         "action.302",                    "302 authorization errors") \
	X(OM_AUTHZ_ERROR_OAUTH20,                  OM_CLASS_AUTHZ,         "error.oauth20",                 "AuthType oauth20 (401) authorization errors") \
	X(OM_AUTHZ_MATCH_REQUIRE_CLAIM,            OM_CLASS_REQUIRE_CLAIM, "match",                         "(per-) Require claim authorization matches") \
	X(OM_AUTHZ_ERROR_REQUIRE_CLAIM,            OM_CLASS_REQUIRE_CLAIM, "error",                         "(per-) Require claim authorization errors") \
	X(OM_CLAIM_ID_TOKEN,                       OM_CLASS_CLAIM,         "id_token",                      "claim values in the ID Token") \
	X(OM_CLAIM_USER_INFO,                      OM_CLASS_CLAIM,         "userinfo",                      "claim values returned from the Userinfo Endpoint") \
	X(OM_PROVIDER_METADATA_ERROR,              OM_CLASS_PROVIDER,      "metadata.error",                "errors retrieving a provider discovery document") \
	X(OM_PROVIDER_TOKEN_ERROR,                 OM_CLASS_PROVIDER,      "token.error",                   "errors making a token request to a provider") \
	X(OM_PROVIDER_REFRESH_ERROR,               OM_CLASS_PROVIDER,      "refresh.error",                 "errors refreshing the access token at the token endpoint") \
	X(OM_PROVIDER_USERINFO_ERROR,              OM_CLASS_PROVIDER,      "userinfo.error",                "errors calling a provider userinfo endpoint") \
	X(OM_PROVIDER_CONNECT_ERROR,               OM_CLASS_PROVIDER,      "http.connect.error",            "(libcurl) provider/network connectivity errors") \
	X(OM_PROVIDER_HTTP_RESPONSE_CODE,          OM_CLASS_PROVIDER,      "http.response.code",            "HTTP response code calling a provider endpoint") \
	X(OM_SESSION_ERROR_COOKIE_DOMAIN,          OM_CLASS_SESSION,       "error.cookie-domain",           "cookie domain validation errors for existing sessions") \
	X(OM_SESSION_ERROR_EXPIRED,                OM_CLASS_SESSION,       "error.expired",                 "sessions that exceeded the maximum duration") \
	X(OM_SESSION_ERROR_REFRESH_ACCESS_TOKEN,   OM_CLASS_SESSION,       "error.refresh-access-token",    "errors refreshing the access token before expiry in existing sessions") \
	X(OM_SESSION_ERROR_REFRESH_USERINFO,       OM_CLASS_SESSION,       "error.refresh-user-info",       "errors refreshing claims from the userinfo endpoint in existing sessions") \
	X(OM_SESSION_ERROR_GENERAL,                OM_CLASS_SESSION,       "error.general",                 "existing sessions that failed validation") \
	X(OM_CACHE_ERROR,                          OM_CLASS_CACHE,         "cache.error",                   "cache read/write errors") \
	X(OM_REDIRECT_URI_AUTHN_RESPONSE_REDIRECT, OM_CLASS_REDIRECT_URI,  "authn.response.redirect",       "authentication responses received in a redirect") \
	X(OM_REDIRECT_URI_AUTHN_RESPONSE_POST,     OM_CLASS_REDIRECT_URI,  "authn.response.post",           "authentication responses received in a HTTP POST") \
	X(OM_REDIRECT_URI_AUTHN_RESPONSE_IMPLICIT, OM_CLASS_REDIRECT_URI,  "authn.response.implicit",       "(presumed) implicit authentication responses to the redirect URI") \
	X(OM_REDIRECT_URI_DISCOVERY_RESPONSE,      OM_CLASS_REDIRECT_URI,  "discovery.response",            "discovery responses to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_LOGOUT,          OM_CLASS_REDIRECT_URI,  "request.logout",                "logout requests to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_JWKS,            OM_CLASS_REDIRECT_URI,  "request.jwks",                  "JWKs retrieval requests to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_SESSION,         OM_CLASS_REDIRECT_URI,  "request.session",               "session management requests to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_REFRESH,         OM_CLASS_REDIRECT_URI,  "request.refresh",               "refresh access token requests to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_REQUEST_URI,     OM_CLASS_REDIRECT_URI,  "request.request_uri",           "Request URI calls to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE, OM_CLASS_REDIRECT_URI,  "request.remove_at_cache",       "access token cache removal requests to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_REVOKE_SESSION,  OM_CLASS_REDIRECT_URI,  "request.revoke_session",        "revoke session requests to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_INFO,            OM_CLASS_REDIRECT_URI,  "request.info",                  "info hook requests to the redirect URI") \
	X(OM_REDIRECT_URI_REQUEST_DPOP,            OM_CLASS_REDIRECT_URI,  "request.dpop",                  "DPoP requests to the redirect URI") \
	X(OM_REDIRECT_URI_ERROR_PROVIDER,          OM_CLASS_REDIRECT_URI,  "error.provider",                "provider authentication response errors received at the redirect URI") \
	X(OM_REDIRECT_URI_ERROR_INVALID,           OM_CLASS_REDIRECT_URI,  "error.invalid",                 "invalid requests to the redirect URI") \
	X(OM_CONTENT_REQUEST_DECLINED,             OM_CLASS_CONTENT,       "request.declined",              "requests declined by the content handler") \
	X(OM_CONTENT_REQUEST_INFO,                 OM_CLASS_CONTENT,       "request.info",                  "info hook requests to the content handler") \
	X(OM_CONTENT_REQUEST_DPOP,                 OM_CLASS_CONTENT,       "request.dpop",                  "DPoP requests to the content handler") \
	X(OM_CONTENT_REQUEST_JWKS,                 OM_CLASS_CONTENT,       "request.jwks",                  "JWKs requests to the content handler") \
	X(OM_CONTENT_REQUEST_DISCOVERY,            OM_CLASS_CONTENT,       "request.discovery",             "discovery requests to the content handler") \
	X(OM_CONTENT_REQUEST_POST_PRESERVE,        OM_CLASS_CONTENT,       "request.post-preserve",         "HTTP POST preservation requests to the content handler") \
	X(OM_CONTENT_REQUEST_AUTHN_POST,           OM_CLASS_CONTENT,       "request.authn-post",            "HTTP POST authentication requests to the content handler") \
	X(OM_CONTENT_REQUEST_UNKNOWN,              OM_CLASS_CONTENT,       "request.unknown",               "unknown requests to the content handler")
// clang-format on

typedef enum {
#define OIDC_METRICS_COUNTER_ENUM(id, class, name, desc) id,
	OIDC_METRICS_COUNTERS_LIST(OIDC_METRICS_COUNTER_ENUM)
#undef OIDC_METRICS_COUNTER_ENUM
	    OM_NUMBER_OF_COUNTERS
} oidc_metrics_counter_type_t;

typedef struct oidc_metrics_counter_info_t {
	char *class_name;
	char *metric_name;
	char *desc;
} oidc_metrics_counter_info_t;

extern const oidc_metrics_counter_info_t _oidc_metrics_counters_info[];

void oidc_metrics_counter_inc(request_rec *r, oidc_metrics_counter_type_t type, const char *name, const char *value);

// NB: "name" is overloaded here: when not NULL it also causes the metric_name to be included
static inline const char *_oidc_metrics_type_name2s(apr_pool_t *pool, unsigned int type, const char *name) {
	return apr_psprintf(pool, "%s%s%s%s%s", _oidc_metrics_counters_info[type].class_name, name ? "." : "",
			    name ? _oidc_metrics_counters_info[type].metric_name : "", name ? "." : "",
			    name ? name : "");
}

#define OIDC_METRICS_COUNTER_INC_NAME_VALUE(r, cfg, type, name, value)                                                 \
	do {                                                                                                           \
		if (oidc_cfg_metrics_hook_data_get(cfg) != NULL) {                                                     \
			if (apr_hash_get(oidc_cfg_metrics_hook_data_get(cfg),                                          \
					 _oidc_metrics_type_name2s(r->pool, type, name),                               \
					 APR_HASH_KEY_STRING) != NULL) {                                               \
				oidc_metrics_counter_inc(r, type, name, value);                                        \
			}                                                                                              \
		}                                                                                                      \
	} while (0)

#define OIDC_METRICS_COUNTER_INC_VALUE(r, cfg, type, value)                                                            \
	OIDC_METRICS_COUNTER_INC_NAME_VALUE(r, cfg, type, NULL, value)

#define OIDC_METRICS_COUNTER_INC(r, cfg, type) OIDC_METRICS_COUNTER_INC_NAME_VALUE(r, cfg, type, NULL, NULL)

#endif /* _MOD_AUTH_OPENIDC_METRICS_H_ */
