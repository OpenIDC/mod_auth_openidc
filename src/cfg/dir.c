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

#include "cfg/dir.h"
#include "cfg/cfg_int.h"
#include "cfg/parse.h"
#include "util/util.h"

/*
 * directory related configuration
 */
struct oidc_dir_cfg_t {
	char *discover_url;
	char *cookie_path;
	char *cookie;
	char *authn_header;
	int unauth_action;
	int unautz_action;
	char *unauthz_arg;
	apr_array_header_t *pass_cookies;
	apr_array_header_t *strip_cookies;
	int pass_info_in;
	int pass_info_encoding;
	int oauth_accept_token_in;
	apr_hash_t *oauth_accept_token_options;
	int oauth_token_introspect_interval;
	int preserve_post;
	int pass_access_token;
	int pass_refresh_token;
	oidc_apr_expr_t *path_auth_request_expr;
	oidc_apr_expr_t *path_scope_expr;
	oidc_apr_expr_t *unauth_expression;
	oidc_apr_expr_t *userinfo_claims_expr;
	int refresh_access_token_before_expiry;
	int action_on_error_refresh;
	int action_on_userinfo_refresh;
	char *state_cookie_prefix;
	apr_array_header_t *pass_userinfo_as;
	int pass_idtoken_as;
};

#define OIDC_PASS_ID_TOKEN_AS_CLAIMS_STR "claims"
#define OIDC_PASS_IDTOKEN_AS_PAYLOAD_STR "payload"
#define OIDC_PASS_IDTOKEN_AS_SERIALIZED_STR "serialized"

/*
 * define how to pass the id_token/claims in HTTP headers
 */
const char *oidc_cmd_dir_pass_idtoken_as_set(cmd_parms *cmd, void *m, const char *v1, const char *v2, const char *v3) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;

	oidc_pass_idtoken_as_t type;
	const char *rv = NULL;

	static const oidc_cfg_option_t options[] = {
	    {OIDC_PASS_IDTOKEN_AS_CLAIMS, OIDC_PASS_ID_TOKEN_AS_CLAIMS_STR},
	    {OIDC_PASS_IDTOKEN_AS_PAYLOAD, OIDC_PASS_IDTOKEN_AS_PAYLOAD_STR},
	    {OIDC_PASS_IDTOKEN_AS_SERIALIZED, OIDC_PASS_IDTOKEN_AS_SERIALIZED_STR}};

	if (v1) {
		rv = oidc_cfg_parse_option(cmd->pool, options, OIDC_CFG_OPTIONS_SIZE(options), v1, (int *)&type);
		if (rv != NULL)
			return OIDC_CONFIG_DIR_RV(cmd, rv);
		// NB: assign the first to override the "unset" default
		dir_cfg->pass_idtoken_as = type;
	}

	if (v2) {
		rv = oidc_cfg_parse_option(cmd->pool, options, OIDC_CFG_OPTIONS_SIZE(options), v2, (int *)&type);
		if (rv != NULL)
			return OIDC_CONFIG_DIR_RV(cmd, rv);
		dir_cfg->pass_idtoken_as |= type;
	}

	if (v3) {
		rv = oidc_cfg_parse_option(cmd->pool, options, OIDC_CFG_OPTIONS_SIZE(options), v3, (int *)&type);
		if (rv != NULL)
			return OIDC_CONFIG_DIR_RV(cmd, rv);
		dir_cfg->pass_idtoken_as |= type;
	}

	return NULL;
}

#define OIDC_PASS_USERINFO_AS_CLAIMS_STR "claims"
#define OIDC_PASS_USERINFO_AS_JSON_OBJECT_STR "json"
#define OIDC_PASS_USERINFO_AS_JWT_STR "jwt"
#define OIDC_PASS_USERINFO_AS_SIGNED_JWT_STR "signed_jwt"

/*
 * parse a "pass id token as" value from the provided strings
 */
static const char *oidc_cfg_dir_parse_pass_userinfo_as(apr_pool_t *pool, const char *v,
						       oidc_pass_user_info_as_t **result) {
	char *name = NULL;
	const char *rv = NULL;
	oidc_pass_userinfo_enum_t type;
	static const oidc_cfg_option_t options[] = {
	    {OIDC_PASS_USERINFO_AS_CLAIMS, OIDC_PASS_USERINFO_AS_CLAIMS_STR},
	    {OIDC_PASS_USERINFO_AS_JSON_OBJECT, OIDC_PASS_USERINFO_AS_JSON_OBJECT_STR},
	    {OIDC_PASS_USERINFO_AS_JWT, OIDC_PASS_USERINFO_AS_JWT_STR},
	    {OIDC_PASS_USERINFO_AS_SIGNED_JWT, OIDC_PASS_USERINFO_AS_SIGNED_JWT_STR}};

	name = _oidc_strstr(v, ":");
	if (name) {
		*name = '\0';
		name++;
	}

	rv = oidc_cfg_parse_option(pool, options, OIDC_CFG_OPTIONS_SIZE(options), v, (int *)&type);
	if (rv != NULL)
		return rv;

	*result = apr_pcalloc(pool, sizeof(oidc_pass_user_info_as_t));
	(*result)->type = type;
	if (name)
		(*result)->name = apr_pstrdup(pool, name);

	return NULL;
}

/*
 * define how to pass the userinfo/claims in HTTP headers
 */
const char *oidc_cmd_dir_pass_userinfo_as_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	const char *rv = NULL;
	oidc_pass_user_info_as_t *p = NULL;
	rv = oidc_cfg_dir_parse_pass_userinfo_as(cmd->pool, arg, &p);
	if (rv != NULL)
		return OIDC_CONFIG_DIR_RV(cmd, rv);
	if (dir_cfg->pass_userinfo_as == NULL)
		dir_cfg->pass_userinfo_as = apr_array_make(cmd->pool, 3, sizeof(oidc_pass_user_info_as_t *));
	APR_ARRAY_PUSH(dir_cfg->pass_userinfo_as, oidc_pass_user_info_as_t *) = p;
	return NULL;
}

#define OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER_STR "header"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_POST_STR "post"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY_STR "query"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_STR "cookie"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC_STR "basic"

static const oidc_cfg_option_t oidc_oauth_accept_token_in_options[] = {
    {OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER, OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER_STR},
    {OIDC_OAUTH_ACCEPT_TOKEN_IN_POST, OIDC_OAUTH_ACCEPT_TOKEN_IN_POST_STR},
    {OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY, OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY_STR},
    {OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE, OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_STR},
    {OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC, OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC_STR}};

/*
 * convert an "accept OAuth 2.0 token in" byte value to a string representation
 */
const char *oidc_cfg_dir_accept_oauth_token_in2str(apr_pool_t *pool, oidc_oauth_accept_token_in_t v) {
	static oidc_cfg_option_t enabled[OIDC_CFG_OPTIONS_SIZE(oidc_oauth_accept_token_in_options)];
	int i = 0, j = 0;
	for (j = 0; j < OIDC_CFG_OPTIONS_SIZE(oidc_oauth_accept_token_in_options); j++) {
		if (v & oidc_oauth_accept_token_in_options[j].val) {
			enabled[i] = oidc_oauth_accept_token_in_options[j];
			i++;
		}
	}
	return oidc_cfg_parse_options_flatten(pool, enabled, i);
}

#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_NAME_DEFAULT "PA.global"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_SEPARATOR ":"

/*
 * define which method of pass an OAuth Bearer token is accepted
 */
const char *oidc_cmd_dir_accept_oauth_token_in_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	int v = 0;
	const char *rv = NULL, *s = NULL;
	char *p = NULL;

	s = apr_pstrdup(cmd->pool, arg);
	p = _oidc_strstr(s, OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_SEPARATOR);

	if (p != NULL) {
		*p = '\0';
		p++;
	} else {
		p = OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_NAME_DEFAULT;
	}

	rv = oidc_cfg_parse_option(cmd->pool, oidc_oauth_accept_token_in_options,
				   OIDC_CFG_OPTIONS_SIZE(oidc_oauth_accept_token_in_options), s, &v);
	if (rv != NULL)
		return OIDC_CONFIG_DIR_RV(cmd, rv);

	if (dir_cfg->oauth_accept_token_in == OIDC_CONFIG_POS_INT_UNSET)
		dir_cfg->oauth_accept_token_in = v;
	else
		dir_cfg->oauth_accept_token_in |= v;

	if (v == OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE)
		apr_hash_set(dir_cfg->oauth_accept_token_options, OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME,
			     APR_HASH_KEY_STRING, p);

	return NULL;
}

/*
 * specify cookies names to pass/strip
 */
const char *oidc_cmd_dir_strip_cookies_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	return oidc_cfg_string_list_add(cmd->pool, &dir_cfg->strip_cookies, arg);
}

const char *oidc_cmd_dir_pass_cookies_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	return oidc_cfg_string_list_add(cmd->pool, &dir_cfg->pass_cookies, arg);
}

#define OIDC_CFG_DIR_MEMBER_FUNC_GET(member, type, def_val, unset_val)                                                 \
	type oidc_cfg_dir_##member##_get(request_rec *r) {                                                             \
		oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);               \
		if (dir_cfg->member == unset_val)                                                                      \
			return def_val;                                                                                \
		return dir_cfg->member;                                                                                \
	}

#define OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(member, type, def_val)                                                        \
	OIDC_CFG_DIR_MEMBER_FUNC_GET(member, type, def_val, OIDC_CONFIG_POS_INT_UNSET)

#define OIDC_CFG_DIR_MEMBER_FUNCS_INT(member, type, parse, def_val)                                                    \
	const char *oidc_cmd_dir_##member##_set(cmd_parms *cmd, void *m, const char *arg) {                            \
		oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;                                                         \
		int v = -1;                                                                                            \
		const char *rv = parse;                                                                                \
		if (rv == NULL)                                                                                        \
			dir_cfg->member = v;                                                                           \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
	OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(member, type, def_val)

/* default for preserving POST parameters across authentication requests */
#define OIDC_DEFAULT_PRESERVE_POST 0
OIDC_CFG_DIR_MEMBER_FUNCS_INT(preserve_post, int, oidc_cfg_parse_boolean(cmd->pool, arg, &v),
			      OIDC_DEFAULT_PRESERVE_POST)

#define OIDC_APPINFO_ENCODING_NONE_STR "none"
#define OIDC_APPINFO_ENCODING_LATIN1_STR "latin1"
#define OIDC_APPINFO_ENCODING_BASE64URL_STR "base64url"

#define OIDC_APPINFO_PASS_NONE_STR "none"
#define OIDC_APPINFO_PASS_HEADERS_STR "headers"
#define OIDC_APPINFO_PASS_ENVVARS_STR "environment"
#define OIDC_APPINFO_PASS_BOTH_STR "both"

#define OIDC_APPINFO_PASS_BOTH (OIDC_APPINFO_PASS_HEADERS | OIDC_APPINFO_PASS_ENVVARS)

/*
 * define how to pass claims information to the application: in headers and/or environment variables
 * and optionally specify the encoding applied to the values
 */
const char *oidc_cmd_dir_pass_claims_as_set(cmd_parms *cmd, void *m, const char *arg1, const char *arg2) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	const char *rv = NULL;

	static const oidc_cfg_option_t pass_options[] = {{OIDC_APPINFO_PASS_NONE, OIDC_APPINFO_PASS_NONE_STR},
							 {OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_PASS_HEADERS_STR},
							 {OIDC_APPINFO_PASS_ENVVARS, OIDC_APPINFO_PASS_ENVVARS_STR},
							 {OIDC_APPINFO_PASS_BOTH, OIDC_APPINFO_PASS_BOTH_STR}};

	rv = oidc_cfg_parse_option(cmd->pool, pass_options, OIDC_CFG_OPTIONS_SIZE(pass_options), arg1,
				   &dir_cfg->pass_info_in);

	static const oidc_cfg_option_t encoding_options[] = {
	    {OIDC_APPINFO_ENCODING_NONE, OIDC_APPINFO_ENCODING_NONE_STR},
	    {OIDC_APPINFO_ENCODING_BASE64URL, OIDC_APPINFO_ENCODING_BASE64URL_STR},
	    {OIDC_APPINFO_ENCODING_LATIN1, OIDC_APPINFO_ENCODING_LATIN1_STR}};

	if ((rv == NULL) && (arg2 != NULL))
		rv = oidc_cfg_parse_option(cmd->pool, encoding_options, OIDC_CFG_OPTIONS_SIZE(encoding_options), arg2,
					   &dir_cfg->pass_info_encoding);

	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_UNAUTH_AUTHENTICATE_STR "auth"
#define OIDC_UNAUTH_PASS_STR "pass"
#define OIDC_UNAUTH_RETURN401_STR "401"
#define OIDC_UNAUTH_RETURN410_STR "410"
#define OIDC_UNAUTH_RETURN407_STR "407"

static const oidc_cfg_option_t unauth_action_options[] = {{OIDC_UNAUTH_AUTHENTICATE, OIDC_UNAUTH_AUTHENTICATE_STR},
							  {OIDC_UNAUTH_PASS, OIDC_UNAUTH_PASS_STR},
							  {OIDC_UNAUTH_RETURN401, OIDC_UNAUTH_RETURN401_STR},
							  {OIDC_UNAUTH_RETURN410, OIDC_UNAUTH_RETURN410_STR},
							  {OIDC_UNAUTH_RETURN407, OIDC_UNAUTH_RETURN407_STR}};

static const char *oidc_cfg_dir_unauth_action2str(oidc_unauth_action_t action) {
	int i = 0;
	for (i = 0; i < OIDC_CFG_OPTIONS_SIZE(unauth_action_options); i++) {
		if (action == unauth_action_options[i].val)
			return unauth_action_options[i].str;
	}
	return NULL;
}

/*
 * define how to act on unauthenticated requests
 */
const char *oidc_cmd_dir_unauth_action_set(cmd_parms *cmd, void *m, const char *arg1, const char *arg2) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	const char *rv =
	    oidc_cfg_parse_option(cmd->pool, unauth_action_options, OIDC_CFG_OPTIONS_SIZE(unauth_action_options), arg1,
				  &dir_cfg->unauth_action);
	if (rv == NULL)
		rv = oidc_util_apr_expr_parse(cmd, arg2, &dir_cfg->unauth_expression, FALSE);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_UNAUTZ_RETURN403_STR "403"
#define OIDC_UNAUTZ_RETURN401_STR "401"
#define OIDC_UNAUTZ_AUTHENTICATE_STR "auth"
#define OIDC_UNAUTZ_RETURN302_STR "302"

/*
 * define how to act on unauthorized requests
 */
const char *oidc_cmd_dir_unautz_action_set(cmd_parms *cmd, void *m, const char *arg1, const char *arg2) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	static const oidc_cfg_option_t options[] = {{OIDC_UNAUTZ_RETURN403, OIDC_UNAUTZ_RETURN403_STR},
						    {OIDC_UNAUTZ_RETURN401, OIDC_UNAUTZ_RETURN401_STR},
						    {OIDC_UNAUTZ_AUTHENTICATE, OIDC_UNAUTZ_AUTHENTICATE_STR},
						    {OIDC_UNAUTZ_RETURN302, OIDC_UNAUTZ_RETURN302_STR}};
	const char *rv =
	    oidc_cfg_parse_option(cmd->pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg1, &dir_cfg->unautz_action);
	if ((rv == NULL) && (arg2 != NULL)) {
		dir_cfg->unauthz_arg = apr_pstrdup(cmd->pool, arg2);
	} else if (dir_cfg->unautz_action == OIDC_UNAUTZ_RETURN302) {
		rv =
		    apr_psprintf(cmd->temp_pool, "the (2nd) URL argument to %s must be set", cmd->directive->directive);
		return rv;
	}
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#ifdef USE_LIBJQ

const char *oidc_cmd_dir_userinfo_claims_expr_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	const char *rv = oidc_util_apr_expr_parse(cmd, arg, &dir_cfg->userinfo_claims_expr, TRUE);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#endif

const char *oidc_cmd_dir_path_auth_request_params_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	const char *rv = NULL;
	rv = oidc_util_apr_expr_parse(cmd, arg, &dir_cfg->path_auth_request_expr, TRUE);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

const char *oidc_cmd_dir_path_scope_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	const char *rv = NULL;
	rv = oidc_util_apr_expr_parse(cmd, arg, &dir_cfg->path_scope_expr, TRUE);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY_MIN 0
#define OIDC_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY_MAX 3600 * 24 * 365

/*
 * set the time in seconds that the access token needs to be valid for
 */
const char *oidc_cmd_dir_refresh_access_token_before_expiry_set(cmd_parms *cmd, void *m, const char *arg1,
								const char *arg2) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	const char *rv = NULL;

	rv = oidc_cfg_parse_int_min_max(cmd->pool, arg1, &dir_cfg->refresh_access_token_before_expiry,
					OIDC_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY_MIN,
					OIDC_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY_MAX);
	if (rv != NULL)
		goto end;

	if (arg2)
		rv = oidc_cfg_parse_action_on_error_refresh_as(
		    cmd->pool, arg2, (oidc_on_error_action_t *)&dir_cfg->action_on_error_refresh);

end:

	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_CFG_DIR_MEMBER_FUNC_PTR(member, type, parse, def_val)                                                     \
	const char *oidc_cmd_dir_##member##_set(cmd_parms *cmd, void *m, const char *arg) {                            \
		oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;                                                         \
		const char *rv = parse;                                                                                \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	OIDC_CFG_DIR_MEMBER_FUNC_GET(member, type, def_val, NULL)

#define OIDC_CFG_DIR_MEMBER_FUNC_STR(member, type, def_val)                                                            \
	const char *oidc_cmd_dir_##member##_set(cmd_parms *cmd, void *m, const char *arg) {                            \
		oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;                                                         \
		dir_cfg->member = apr_pstrdup(cmd->pool, arg);                                                         \
		return NULL;                                                                                           \
	}                                                                                                              \
                                                                                                                       \
	OIDC_CFG_DIR_MEMBER_FUNC_GET(member, type, def_val, NULL)

/* define the default number of seconds that the access token needs to be valid for; -1 = no refresh */
#define OIDC_DEFAULT_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY -1
OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(refresh_access_token_before_expiry, int,
				 OIDC_DEFAULT_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY)

/* default action to be taken on access token refresh error */
#define OIDC_DEFAULT_ON_ERROR_REFRESH OIDC_ON_ERROR_502;
OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(action_on_error_refresh, oidc_on_error_action_t, OIDC_DEFAULT_ON_ERROR_REFRESH)

/* default prefix of the state cookie that binds the state in the authorization request/response to the browser */
#define OIDC_DEFAULT_STATE_COOKIE_PREFIX "mod_auth_openidc_state_"
OIDC_CFG_DIR_MEMBER_FUNC_STR(state_cookie_prefix, const char *, OIDC_DEFAULT_STATE_COOKIE_PREFIX)

OIDC_CFG_DIR_MEMBER_FUNC_PTR(discover_url, const char *,
			     oidc_cfg_parse_relative_or_absolute_url(cmd->pool, arg, &dir_cfg->discover_url), NULL)

/* default name of the session cookie */
#define OIDC_DEFAULT_COOKIE "mod_auth_openidc_session"
OIDC_CFG_DIR_MEMBER_FUNC_STR(cookie, const char *, OIDC_DEFAULT_COOKIE)

/* default cookie path */
#define OIDC_DEFAULT_COOKIE_PATH "/"
OIDC_CFG_DIR_MEMBER_FUNC_STR(cookie_path, const char *, OIDC_DEFAULT_COOKIE_PATH)

/* default for the HTTP header name in which the remote user name is passed */
#define OIDC_DEFAULT_AUTHN_HEADER NULL
OIDC_CFG_DIR_MEMBER_FUNC_STR(authn_header, const char *, OIDC_DEFAULT_AUTHN_HEADER)

/* default for passing app info in headers */
#define OIDC_DEFAULT_PASS_APPINFO_IN OIDC_APPINFO_PASS_BOTH
OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(pass_info_in, oidc_appinfo_pass_in_t, OIDC_DEFAULT_PASS_APPINFO_IN)

/* default for passing app info in a specific encoding */
#define OIDC_DEFAULT_APPINFO_ENCODING OIDC_APPINFO_ENCODING_LATIN1
OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(pass_info_encoding, oidc_appinfo_encoding_t, OIDC_DEFAULT_APPINFO_ENCODING)

/* default for passing the access token in a header/environment variable */
#define OIDC_DEFAULT_PASS_ACCESS_TOKEN 1
OIDC_CFG_DIR_MEMBER_FUNCS_INT(pass_access_token, apr_byte_t, oidc_cfg_parse_boolean(cmd->pool, arg, &v),
			      OIDC_DEFAULT_PASS_ACCESS_TOKEN)

/* default for passing the refresh token in a header/environment variable */
#define OIDC_DEFAULT_PASS_REFRESH_TOKEN 0
OIDC_CFG_DIR_MEMBER_FUNCS_INT(pass_refresh_token, apr_byte_t, oidc_cfg_parse_boolean(cmd->pool, arg, &v),
			      OIDC_DEFAULT_PASS_REFRESH_TOKEN)

#define OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER
OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(oauth_accept_token_in, oidc_oauth_accept_token_in_t,
				 OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT)

const char *oidc_cfg_dir_accept_token_in_option_get(request_rec *r, const char *key) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	return apr_hash_get(dir_cfg->oauth_accept_token_options, key, APR_HASH_KEY_STRING);
}

#define OIDC_OAUTH_ACCESS_TOKEN_INTROSPECTION_INTERVAL_MIN -1
#define OIDC_OAUTH_ACCESS_TOKEN_INTROSPECTION_INTERVAL_MAX 3600 * 24 * 365

/* default value for the token introspection interval (0 = disabled, no expiry of claims) */
#define OIDC_DEFAULT_TOKEN_INTROSPECTION_INTERVAL 0

const char *oidc_cmd_dir_token_introspection_interval_set(cmd_parms *cmd, void *m, const char *arg) {
	oidc_dir_cfg_t *dir_cfg = (oidc_dir_cfg_t *)m;
	const char *rv = oidc_cfg_parse_int_min_max(cmd->pool, arg, &dir_cfg->oauth_token_introspect_interval,
						    OIDC_OAUTH_ACCESS_TOKEN_INTROSPECTION_INTERVAL_MIN,
						    OIDC_OAUTH_ACCESS_TOKEN_INTROSPECTION_INTERVAL_MAX);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

int oidc_cfg_dir_token_introspection_interval_get(request_rec *r) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	// we use -2 here as an exception because -1 is a valid value
	if (dir_cfg->oauth_token_introspect_interval <= -2)
		return OIDC_DEFAULT_TOKEN_INTROSPECTION_INTERVAL;
	return dir_cfg->oauth_token_introspect_interval;
}

OIDC_CFG_DIR_MEMBER_FUNC_GET(pass_cookies, const apr_array_header_t *, NULL, NULL)
OIDC_CFG_DIR_MEMBER_FUNC_GET(strip_cookies, const apr_array_header_t *, NULL, NULL)

/* default action to take on an incoming unauthenticated request */
#define OIDC_DEFAULT_UNAUTH_ACTION OIDC_UNAUTH_AUTHENTICATE

oidc_unauth_action_t oidc_cfg_dir_unauth_action_get(request_rec *r) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	const char *s = NULL;
	oidc_unauth_action_t action = OIDC_CONFIG_POS_INT_UNSET;

	if (dir_cfg->unauth_action == OIDC_CONFIG_POS_INT_UNSET) {
		action = OIDC_DEFAULT_UNAUTH_ACTION;
		goto end;
	}

	if (dir_cfg->unauth_expression == NULL) {
		action = dir_cfg->unauth_action;
		goto end;
	}

	s = oidc_util_apr_expr_exec(r, dir_cfg->unauth_expression, FALSE);

	action = (s != NULL) ? dir_cfg->unauth_action : OIDC_DEFAULT_UNAUTH_ACTION;

	oidc_debug(r, "expression evaluation resulted in: %s (%s) for: %s", oidc_cfg_dir_unauth_action2str(action),
		   s != NULL ? "true" : "false (default)", dir_cfg->unauth_expression->str);

end:

	return action;
}

apr_byte_t oidc_cfg_dir_unauth_expr_is_set(request_rec *r) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	return (dir_cfg->unauth_expression != NULL) ? TRUE : FALSE;
}

/* default action to take on an incoming authorized request */
#define OIDC_DEFAULT_UNAUTZ_ACTION OIDC_UNAUTZ_RETURN403
OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(unautz_action, oidc_unautz_action_t, OIDC_DEFAULT_UNAUTZ_ACTION)

const char *oidc_cfg_dir_unauthz_arg_get(request_rec *r) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	return dir_cfg->unauthz_arg;
}

const char *oidc_cfg_dir_path_auth_request_params_get(request_rec *r) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	return oidc_util_apr_expr_exec(r, dir_cfg->path_auth_request_expr, TRUE);
}

/* default pass user info as */
#define OIDC_DEFAULT_PASS_USERINFO_AS OIDC_PASS_USERINFO_AS_CLAIMS_STR

static apr_array_header_t *pass_userinfo_as_default = NULL;

const apr_array_header_t *oidc_cfg_dir_pass_userinfo_as_get(request_rec *r) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	oidc_pass_user_info_as_t *p = NULL;
	if (dir_cfg->pass_userinfo_as == NULL) {
		if (pass_userinfo_as_default == NULL) {
			pass_userinfo_as_default =
			    apr_array_make(r->server->process->pconf, 3, sizeof(oidc_pass_user_info_as_t *));
			oidc_cfg_dir_parse_pass_userinfo_as(r->server->process->pconf, OIDC_DEFAULT_PASS_USERINFO_AS,
							    &p);
			APR_ARRAY_PUSH(pass_userinfo_as_default, oidc_pass_user_info_as_t *) = p;
		}
	}
	return dir_cfg->pass_userinfo_as ? dir_cfg->pass_userinfo_as : pass_userinfo_as_default;
}

/* default pass id_token as */
#define OIDC_DEFAULT_PASS_IDTOKEN_AS OIDC_PASS_IDTOKEN_AS_CLAIMS
OIDC_CFG_DIR_MEMBER_FUNC_INT_GET(pass_idtoken_as, oidc_pass_idtoken_as_t, OIDC_DEFAULT_PASS_IDTOKEN_AS)

#ifdef USE_LIBJQ
const char *oidc_cfg_dir_userinfo_claims_expr_get(request_rec *r) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	return oidc_util_apr_expr_exec(r, dir_cfg->userinfo_claims_expr, TRUE);
}
#endif

const char *oidc_cfg_dir_path_scope_get(request_rec *r) {
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	return oidc_util_apr_expr_exec(r, dir_cfg->path_scope_expr, TRUE);
}

/*
 * create a new directory config record with defaults
 */
void *oidc_cfg_dir_config_create(apr_pool_t *pool, char *path) {
	oidc_dir_cfg_t *c = apr_pcalloc(pool, sizeof(oidc_dir_cfg_t));
	c->discover_url = NULL;
	c->cookie = NULL;
	c->cookie_path = NULL;
	c->authn_header = NULL;
	c->unauth_action = OIDC_CONFIG_POS_INT_UNSET;
	c->unauth_expression = NULL;
	c->unautz_action = OIDC_CONFIG_POS_INT_UNSET;
	c->unauthz_arg = NULL;
	c->pass_cookies = NULL;
	c->strip_cookies = NULL;
	c->pass_info_in = OIDC_CONFIG_POS_INT_UNSET;
	c->pass_info_encoding = OIDC_CONFIG_POS_INT_UNSET;
	c->oauth_accept_token_in = OIDC_CONFIG_POS_INT_UNSET;
	c->oauth_accept_token_options = apr_hash_make(pool);
	c->oauth_token_introspect_interval = -2;
	c->preserve_post = OIDC_CONFIG_POS_INT_UNSET;
	c->pass_access_token = OIDC_CONFIG_POS_INT_UNSET;
	c->pass_refresh_token = OIDC_CONFIG_POS_INT_UNSET;
	c->path_auth_request_expr = NULL;
	c->path_scope_expr = NULL;
	c->userinfo_claims_expr = NULL;
	c->refresh_access_token_before_expiry = OIDC_CONFIG_POS_INT_UNSET;
	c->action_on_error_refresh = OIDC_CONFIG_POS_INT_UNSET;
	c->state_cookie_prefix = NULL;
	c->pass_userinfo_as = NULL;
	c->pass_idtoken_as = OIDC_CONFIG_POS_INT_UNSET;
	return (c);
}

/*
 * merge a new directory config with a base one
 */
void *oidc_cfg_dir_config_merge(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_dir_cfg_t *c = apr_pcalloc(pool, sizeof(oidc_dir_cfg_t));
	oidc_dir_cfg_t *base = BASE;
	oidc_dir_cfg_t *add = ADD;
	c->discover_url = add->discover_url != NULL ? add->discover_url : base->discover_url;
	c->cookie = add->cookie != NULL ? add->cookie : base->cookie;
	c->cookie_path = add->cookie_path != NULL ? add->cookie_path : base->cookie_path;
	c->authn_header = add->authn_header != NULL ? add->authn_header : base->authn_header;
	c->unauth_action = add->unauth_action != OIDC_CONFIG_POS_INT_UNSET ? add->unauth_action : base->unauth_action;
	c->unauth_expression = add->unauth_expression != NULL ? add->unauth_expression : base->unauth_expression;
	c->unautz_action = add->unautz_action != OIDC_CONFIG_POS_INT_UNSET ? add->unautz_action : base->unautz_action;
	c->unauthz_arg = add->unauthz_arg != NULL ? add->unauthz_arg : base->unauthz_arg;

	c->pass_cookies = add->pass_cookies != NULL ? add->pass_cookies : base->pass_cookies;
	c->strip_cookies = add->strip_cookies != NULL ? add->strip_cookies : base->strip_cookies;

	c->pass_info_in = add->pass_info_in != OIDC_CONFIG_POS_INT_UNSET ? add->pass_info_in : base->pass_info_in;
	c->pass_info_encoding =
	    add->pass_info_encoding != OIDC_CONFIG_POS_INT_UNSET ? add->pass_info_encoding : base->pass_info_encoding;
	c->oauth_accept_token_in = add->oauth_accept_token_in != OIDC_CONFIG_POS_INT_UNSET
				       ? add->oauth_accept_token_in
				       : base->oauth_accept_token_in;
	c->oauth_accept_token_options = apr_hash_count(add->oauth_accept_token_options) > 0
					    ? add->oauth_accept_token_options
					    : base->oauth_accept_token_options;
	c->oauth_token_introspect_interval = add->oauth_token_introspect_interval >= -1
						 ? add->oauth_token_introspect_interval
						 : base->oauth_token_introspect_interval;
	c->preserve_post = add->preserve_post != OIDC_CONFIG_POS_INT_UNSET ? add->preserve_post : base->preserve_post;
	c->pass_access_token =
	    add->pass_access_token != OIDC_CONFIG_POS_INT_UNSET ? add->pass_access_token : base->pass_access_token;
	c->pass_refresh_token =
	    add->pass_refresh_token != OIDC_CONFIG_POS_INT_UNSET ? add->pass_refresh_token : base->pass_refresh_token;
	c->path_auth_request_expr =
	    add->path_auth_request_expr != NULL ? add->path_auth_request_expr : base->path_auth_request_expr;
	c->path_scope_expr = add->path_scope_expr != NULL ? add->path_scope_expr : base->path_scope_expr;
	c->userinfo_claims_expr =
	    add->userinfo_claims_expr != NULL ? add->userinfo_claims_expr : base->userinfo_claims_expr;

	c->pass_userinfo_as = add->pass_userinfo_as != NULL ? add->pass_userinfo_as : base->pass_userinfo_as;
	c->pass_idtoken_as =
	    add->pass_idtoken_as != OIDC_CONFIG_POS_INT_UNSET ? add->pass_idtoken_as : base->pass_idtoken_as;

	c->refresh_access_token_before_expiry = add->refresh_access_token_before_expiry != OIDC_CONFIG_POS_INT_UNSET
						    ? add->refresh_access_token_before_expiry
						    : base->refresh_access_token_before_expiry;

	c->action_on_error_refresh = add->action_on_error_refresh != OIDC_CONFIG_POS_INT_UNSET
					 ? add->action_on_error_refresh
					 : base->action_on_error_refresh;

	c->state_cookie_prefix =
	    add->state_cookie_prefix != NULL ? add->state_cookie_prefix : base->state_cookie_prefix;

	return (c);
}
