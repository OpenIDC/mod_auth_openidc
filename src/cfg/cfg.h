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

#ifndef _MOD_AUTH_OPENIDC_CFG_CFG_H_
#define _MOD_AUTH_OPENIDC_CFG_CFG_H_

#include "const.h" // for the PACKAGE_* defines
#include "http.h"
#include <http_config.h>
#include <http_core.h>
#include <httpd.h>

#include "cache/cache.h"

#define OIDC_CONFIG_POS_INT_UNSET -1

#define OIDCPublicKeyFiles "OIDCPublicKeyFiles"
#define OIDCDefaultLoggedOutURL "OIDCDefaultLoggedOutURL"
#define OIDCCookieHTTPOnly "OIDCCookieHTTPOnly"
#define OIDCCookieSameSite "OIDCCookieSameSite"
#define OIDCOutgoingProxy "OIDCOutgoingProxy"
#define OIDCClaimDelimiter "OIDCClaimDelimiter"
#define OIDCHTTPTimeoutLong "OIDCHTTPTimeoutLong"
#define OIDCHTTPTimeoutShort "OIDCHTTPTimeoutShort"
#define OIDCStateTimeout "OIDCStateTimeout"
#define OIDCStateMaxNumberOfCookies "OIDCStateMaxNumberOfCookies"
#define OIDCSessionInactivityTimeout "OIDCSessionInactivityTimeout"
#define OIDCMetadataDir "OIDCMetadataDir"
#define OIDCSessionCacheFallbackToCookie "OIDCSessionCacheFallbackToCookie"
#define OIDCSessionCookieChunkSize "OIDCSessionCookieChunkSize"
#define OIDCHTMLErrorTemplate "OIDCHTMLErrorTemplate"
#define OIDCPreservePostTemplates "OIDCPreservePostTemplates"
#define OIDCProviderMetadataRefreshInterval "OIDCProviderMetadataRefreshInterval"
#define OIDCBlackListedClaims "OIDCBlackListedClaims"
#define OIDCStateInputHeaders "OIDCStateInputHeaders"
#define OIDCRedirectURLsAllowed "OIDCRedirectURLsAllowed"
#define OIDCCABundlePath "OIDCCABundlePath"
#define OIDCLogoutXFrameOptions "OIDCLogoutXFrameOptions"
#define OIDCXForwardedHeaders "OIDCXForwardedHeaders"
#define OIDCFilterClaimsExpr "OIDCFilterClaimsExpr"
#define OIDCTraceParent "OIDCTraceParent"
#define OIDCPrivateKeyFiles "OIDCPrivateKeyFiles"
#define OIDCRedirectURI "OIDCRedirectURI"
#define OIDCDefaultURL "OIDCDefaultURL"
#define OIDCCookieDomain "OIDCCookieDomain"
#define OIDCClaimPrefix "OIDCClaimPrefix"
#define OIDCRemoteUserClaim "OIDCRemoteUserClaim"
#define OIDCOAuthRemoteUserClaim "OIDCOAuthRemoteUserClaim"
#define OIDCSessionType "OIDCSessionType"
#define OIDCInfoHook "OIDCInfoHook"
#define OIDCMetricsData "OIDCMetricsData"
#define OIDCMetricsPublish "OIDCMetricsPublish"
#define OIDCWhiteListedClaims "OIDCWhiteListedClaims"
#define OIDCCryptoPassphrase "OIDCCryptoPassphrase"

typedef enum {
	OIDC_STATE_INPUT_HEADERS_NONE = 0,
	OIDC_STATE_INPUT_HEADERS_USER_AGENT = 1,
	OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR = 2
} oidc_state_input_hdrs_t;

typedef enum {
	OIDC_HDR_NONE = 0,
	OIDC_HDR_X_FORWARDED_HOST = 1,
	OIDC_HDR_X_FORWARDED_PORT = 2,
	OIDC_HDR_X_FORWARDED_PROTO = 4,
	OIDC_HDR_FORWARDED = 8
} oidc_hdr_x_forwarded_t;

typedef enum {
	OIDC_TRACE_PARENT_OFF = 0,
	OIDC_TRACE_PARENT_PROPAGATE = 1,
	OIDC_TRACE_PARENT_GENERATE = 2
} oidc_trace_parent_t;

#define OIDC_ERROR_ENVVAR "OIDC_ERROR"
#define OIDC_ERROR_DESC_ENVVAR "OIDC_ERROR_DESC"

#define OIDC_HOOK_INFO_TIMESTAMP "iat"
#define OIDC_HOOK_INFO_ACCES_TOKEN "access_token"
#define OIDC_HOOK_INFO_ACCES_TOKEN_TYPE "access_token_type"
#define OIDC_HOOK_INFO_ACCES_TOKEN_EXP "access_token_expires"
#define OIDC_HOOK_INFO_ID_TOKEN_HINT "id_token_hint"
#define OIDC_HOOK_INFO_ID_TOKEN "id_token"
#define OIDC_HOOK_INFO_USER_INFO "userinfo"
#define OIDC_HOOK_INFO_SESSION "session"
#define OIDC_HOOK_INFO_SESSION_STATE "state"
#define OIDC_HOOK_INFO_SESSION_UUID "uuid"
#define OIDC_HOOK_INFO_SESSION_EXP "exp"
#define OIDC_HOOK_INFO_SESSION_TIMEOUT "timeout"
#define OIDC_HOOK_INFO_SESSION_REMOTE_USER "remote_user"
#define OIDC_HOOK_INFO_REFRESH_TOKEN "refresh_token"
#define OIDC_HOOK_INFO_DPOP "dpop"

#define OIDC_HTML_ERROR_TEMPLATE_DEPRECATED "deprecated"

typedef struct oidc_apr_expr_t {
#if HAVE_APACHE_24
	ap_expr_info_t *expr;
#endif
	char *str;
} oidc_apr_expr_t;

typedef struct oidc_crypto_passphrase_t {
	char *secret1;
	char *secret2;
} oidc_crypto_passphrase_t;

typedef struct oidc_remote_user_claim_t {
	const char *claim_name;
	const char *reg_exp;
	const char *replace;
} oidc_remote_user_claim_t;

typedef enum {
	/* pass userinfo as individual claims in headers (default) */
	OIDC_PASS_USERINFO_AS_CLAIMS = 1,
	/* pass userinfo payload as JSON object in header */
	OIDC_PASS_USERINFO_AS_JSON_OBJECT = 2,
	/* pass userinfo as a JWT in header (when returned as a JWT) */
	OIDC_PASS_USERINFO_AS_JWT = 4,
	/* pass as re-signed JWT including id_token claims */
	OIDC_PASS_USERINFO_AS_SIGNED_JWT = 8
} oidc_pass_userinfo_enum_t;

typedef struct oidc_pass_user_info_as_t {
	oidc_pass_userinfo_enum_t type;
	char *name;
} oidc_pass_user_info_as_t;

/* actions to be taken on access token / userinfo refresh error */
typedef enum { OIDC_ON_ERROR_502 = 0, OIDC_ON_ERROR_LOGOUT = 1, OIDC_ON_ERROR_AUTH = 2 } oidc_on_error_action_t;

#define OIDC_CFG_OPTIONS_SIZE(options) sizeof(options) / sizeof(oidc_cfg_option_t)

typedef struct oidc_provider_t oidc_provider_t;
typedef struct oidc_cfg_t oidc_cfg_t;

void oidc_cfg_x_forwarded_headers_check(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers);
const char *oidc_cfg_remote_user_claim_name_get(oidc_cfg_t *cfg);

oidc_provider_t *oidc_cfg_provider_get(oidc_cfg_t *);
int oidc_cfg_merged_get(oidc_cfg_t *cfg);

void oidc_pre_config_init();

void *oidc_cfg_server_create(apr_pool_t *pool, server_rec *svr);
void *oidc_cfg_server_merge(apr_pool_t *pool, void *BASE, void *ADD);
int oidc_cfg_post_config(oidc_cfg_t *cfg, server_rec *s);
void oidc_cfg_child_init(apr_pool_t *pool, oidc_cfg_t *cfg, server_rec *s);
void oidc_cfg_cleanup_child(oidc_cfg_t *cfg, server_rec *s);

#define OIDC_CFG_MEMBER_FUNC_NAME(member, type, method) oidc_##type##_##member##_##method

#define OIDC_CFG_MEMBER_FUNC_GET_DECL(member, type) type OIDC_CFG_MEMBER_FUNC_NAME(member, cfg, get)(oidc_cfg_t * cfg);

#define OIDC_CMD_MEMBER_FUNC_DECL(member, ...)                                                                         \
	const char *OIDC_CFG_MEMBER_FUNC_NAME(member, cmd, set)(cmd_parms *, void *, ##__VA_ARGS__);

#define OIDC_CFG_MEMBER_FUNCS_DECL(member, type, ...)                                                                  \
	OIDC_CMD_MEMBER_FUNC_DECL(member, const char *, ##__VA_ARGS__);                                                \
	OIDC_CFG_MEMBER_FUNC_GET_DECL(member, type)

OIDC_CFG_MEMBER_FUNCS_DECL(delete_oldest_state_cookies, int)
OIDC_CFG_MEMBER_FUNCS_DECL(action_on_userinfo_error, oidc_on_error_action_t)
OIDC_CFG_MEMBER_FUNCS_DECL(crypto_passphrase_secret1, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(refresh_mutex, oidc_cache_mutex_t *)
OIDC_CFG_MEMBER_FUNCS_DECL(store_id_token, int)
OIDC_CFG_MEMBER_FUNCS_DECL(post_preserve_template, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(post_restore_template, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(persistent_session_cookie, int)
OIDC_CFG_MEMBER_FUNCS_DECL(public_keys, const apr_array_header_t *)
OIDC_CFG_MEMBER_FUNCS_DECL(private_keys, const apr_array_header_t *)
OIDC_CFG_MEMBER_FUNCS_DECL(redirect_uri, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(default_sso_url, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(default_slo_url, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(cookie_domain, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(cookie_http_only, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cookie_same_site, int)
OIDC_CFG_MEMBER_FUNCS_DECL(claim_delimiter, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(claim_prefix, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(state_timeout, int)
OIDC_CFG_MEMBER_FUNCS_DECL(session_inactivity_timeout, int)
OIDC_CFG_MEMBER_FUNCS_DECL(metadata_dir, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(session_type, int)
OIDC_CFG_MEMBER_FUNCS_DECL(session_cache_fallback_to_cookie, int)
OIDC_CFG_MEMBER_FUNCS_DECL(session_cookie_chunk_size, int)
OIDC_CFG_MEMBER_FUNCS_DECL(html_error_template, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(provider_metadata_refresh_interval, int)
OIDC_CFG_MEMBER_FUNCS_DECL(info_hook_data, apr_hash_t *)
OIDC_CFG_MEMBER_FUNCS_DECL(metrics_hook_data, apr_hash_t *)
OIDC_CFG_MEMBER_FUNCS_DECL(metrics_path, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(trace_parent, oidc_trace_parent_t)
OIDC_CFG_MEMBER_FUNCS_DECL(black_listed_claims, apr_hash_t *)
OIDC_CFG_MEMBER_FUNCS_DECL(white_listed_claims, apr_hash_t *)
OIDC_CFG_MEMBER_FUNCS_DECL(state_input_headers, oidc_state_input_hdrs_t)
OIDC_CFG_MEMBER_FUNCS_DECL(redirect_urls_allowed, apr_hash_t *)
OIDC_CFG_MEMBER_FUNCS_DECL(ca_bundle_path, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(logout_x_frame_options, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(x_forwarded_headers, oidc_hdr_x_forwarded_t)

// 2 args
OIDC_CFG_MEMBER_FUNCS_DECL(post_preserve_templates, const char *, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(crypto_passphrase, const oidc_crypto_passphrase_t *, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(max_number_of_state_cookies, int, const char *)

// 3 args
OIDC_CFG_MEMBER_FUNCS_DECL(remote_user_claim, const oidc_remote_user_claim_t *, const char *, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(outgoing_proxy, const oidc_http_outgoing_proxy_t *, const char *, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(http_timeout_short, oidc_http_timeout_t *, const char *, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(http_timeout_long, oidc_http_timeout_t *, const char *, const char *)

// ifdefs
#ifdef USE_LIBJQ
OIDC_CMD_MEMBER_FUNC_DECL(filter_claims_expr, const char *arg)
#endif
OIDC_CFG_MEMBER_FUNC_GET_DECL(filter_claims_expr, oidc_apr_expr_t *)

extern const command_rec oidc_cfg_cmds[];

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_openidc);
#else
extern module AP_MODULE_DECLARE_DATA auth_openidc_module;
#endif

#endif // _MOD_AUTH_OPENIDC_CFG_CFG_H_
