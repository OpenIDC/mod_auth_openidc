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

#ifndef _MOD_AUTH_OPENIDC_CFG_DIR_H_
#define _MOD_AUTH_OPENIDC_CFG_DIR_H_

#include "cfg/cfg.h"

#define OIDCPathScope "OIDCPathScope"
#define OIDCPathAuthRequestParams "OIDCPathAuthRequestParams"
#define OIDCDiscoverURL "OIDCDiscoverURL"
#define OIDCPassCookies "OIDCPassCookies"
#define OIDCStripCookies "OIDCStripCookies"
#define OIDCAuthNHeader "OIDCAuthNHeader"
#define OIDCCookie "OIDCCookie"
#define OIDCUnAuthAction "OIDCUnAuthAction"
#define OIDCUnAutzAction "OIDCUnAutzAction"
#define OIDCPassClaimsAs "OIDCPassClaimsAs"
#define OIDCOAuthAcceptTokenAs "OIDCOAuthAcceptTokenAs"
#define OIDCOAuthTokenIntrospectionInterval "OIDCOAuthTokenIntrospectionInterval"
#define OIDCPreservePost "OIDCPreservePost"
#define OIDCPassAccessToken "OIDCPassAccessToken"
#define OIDCPassRefreshToken "OIDCPassRefreshToken"
#define OIDCRefreshAccessTokenBeforeExpiry "OIDCRefreshAccessTokenBeforeExpiry"
#define OIDCStateCookiePrefix "OIDCStateCookiePrefix"
#define OIDCPassIDTokenAs "OIDCPassIDTokenAs"
#define OIDCPassUserInfoAs "OIDCPassUserInfoAs"
#define OIDCUserInfoClaimsExpr "OIDCUserInfoClaimsExpr"
#define OIDCCookiePath "OIDCCookiePath"

typedef enum {
	/* pass id_token as individual claims in headers (default) */
	OIDC_PASS_IDTOKEN_AS_CLAIMS = 1,
	/* pass id_token payload as JSON object in header */
	OIDC_PASS_IDTOKEN_AS_PAYLOAD = 2,
	/* pass id_token in compact serialized format in header */
	OIDC_PASS_IDTOKEN_AS_SERIALIZED = 4,
	/* do not pass id_token */
	OIDC_PASS_IDTOKEN_OFF = 8
} oidc_pass_idtoken_as_t;

typedef enum {
	/* accept bearer token in header (default) */
	OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER = 1,
	/* accept bearer token as a post parameter */
	OIDC_OAUTH_ACCEPT_TOKEN_IN_POST = 2,
	/* accept bearer token as a query parameter */
	OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY = 4,
	/* accept bearer token as a cookie parameter (PingAccess) */
	OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE = 8,
	/* accept bearer token as basic auth password (non-oauth clients) */
	OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC = 16
} oidc_oauth_accept_token_in_t;

typedef enum {
	OIDC_APPINFO_PASS_NONE = 0,
	OIDC_APPINFO_PASS_HEADERS = 1,
	OIDC_APPINFO_PASS_ENVVARS = 2,
} oidc_appinfo_pass_in_t;

typedef enum {
	OIDC_APPINFO_ENCODING_NONE = 0,
	OIDC_APPINFO_ENCODING_BASE64URL = 1,
	OIDC_APPINFO_ENCODING_LATIN1 = 2
} oidc_appinfo_encoding_t;

/* the hash key of the cookie name value in the list of options */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME "cookie-name"

typedef enum {
	OIDC_UNAUTH_AUTHENTICATE = 1,
	OIDC_UNAUTH_PASS = 2,
	OIDC_UNAUTH_RETURN401 = 3,
	OIDC_UNAUTH_RETURN410 = 4,
	OIDC_UNAUTH_RETURN407 = 5
} oidc_unauth_action_t;

typedef enum {
	OIDC_UNAUTZ_RETURN403 = 1,
	OIDC_UNAUTZ_RETURN401 = 2,
	OIDC_UNAUTZ_AUTHENTICATE = 3,
	OIDC_UNAUTZ_RETURN302 = 4
} oidc_unautz_action_t;

#define OIDC_CMD_DIR_MEMBER_FUNC_DECL(member, ...)                                                                     \
	const char *OIDC_CFG_MEMBER_FUNC_NAME(member, cmd_dir, set)(cmd_parms *, void *, const char *, ##__VA_ARGS__);

#define OIDC_CFG_DIR_MEMBER_FUNC_GET_DECL(member, type)                                                                \
	type OIDC_CFG_MEMBER_FUNC_NAME(member, cfg_dir, get)(request_rec * r);

#define OIDC_CFG_DIR_MEMBER_FUNCS(member, type, ...)                                                                   \
	OIDC_CMD_DIR_MEMBER_FUNC_DECL(member, ##__VA_ARGS__)                                                           \
	OIDC_CFG_DIR_MEMBER_FUNC_GET_DECL(member, type)

OIDC_CFG_DIR_MEMBER_FUNCS(pass_userinfo_as, const apr_array_header_t *)
OIDC_CFG_DIR_MEMBER_FUNCS(accept_oauth_token_in, int)
OIDC_CFG_DIR_MEMBER_FUNCS(preserve_post, int)
OIDC_CFG_DIR_MEMBER_FUNCS(pass_claims_as, int, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(unauth_action, oidc_unauth_action_t, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(path_scope, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(path_auth_request_params, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(authn_header, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(cookie_path, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(cookie, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(pass_cookies, const apr_array_header_t *)
OIDC_CFG_DIR_MEMBER_FUNCS(strip_cookies, const apr_array_header_t *)
OIDC_CFG_DIR_MEMBER_FUNCS(token_introspection_interval, int)
OIDC_CFG_DIR_MEMBER_FUNCS(pass_access_token, apr_byte_t)
OIDC_CFG_DIR_MEMBER_FUNCS(pass_refresh_token, apr_byte_t)
OIDC_CFG_DIR_MEMBER_FUNCS(discover_url, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(state_cookie_prefix, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(pass_idtoken_as, oidc_pass_idtoken_as_t)

// 2 args
OIDC_CFG_DIR_MEMBER_FUNCS(unautz_action, oidc_unautz_action_t, const char *)
OIDC_CFG_DIR_MEMBER_FUNCS(refresh_access_token_before_expiry, int, const char *)

// ifdefs
#ifdef USE_LIBJQ
OIDC_CFG_DIR_MEMBER_FUNCS(userinfo_claims_expr, const char *)
#endif

// getters only
OIDC_CFG_DIR_MEMBER_FUNC_GET_DECL(action_on_error_refresh, oidc_on_error_action_t)
OIDC_CFG_DIR_MEMBER_FUNC_GET_DECL(pass_info_in, oidc_appinfo_pass_in_t)
OIDC_CFG_DIR_MEMBER_FUNC_GET_DECL(pass_info_encoding, oidc_appinfo_encoding_t)
OIDC_CFG_DIR_MEMBER_FUNC_GET_DECL(oauth_accept_token_in, oidc_oauth_accept_token_in_t)
OIDC_CFG_DIR_MEMBER_FUNC_GET_DECL(unauthz_arg, const char *)

// specials
const char *OIDC_CFG_MEMBER_FUNC_NAME(accept_token_in_option, cfg_dir, get)(request_rec *r, const char *key);
apr_byte_t OIDC_CFG_MEMBER_FUNC_NAME(unauth_expr, cfg_dir, is_set)(request_rec *r);
const char *OIDC_CFG_MEMBER_FUNC_NAME(accept_oauth_token, cfg_dir, in2str)(apr_pool_t *pool,
									   oidc_oauth_accept_token_in_t v);

typedef struct oidc_dir_cfg_t oidc_dir_cfg_t;

void *oidc_cfg_dir_config_create(apr_pool_t *, char *);
void *oidc_cfg_dir_config_merge(apr_pool_t *, void *, void *);

#endif // _MOD_AUTH_OPENIDC_CFG_DIR_H_
