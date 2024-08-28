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

#include "cfg/provider.h"
#include "cfg/cfg_int.h"
#include "cfg/parse.h"
#include "proto/proto.h"

struct oidc_provider_t {
	char *metadata_url;
	char *issuer;
	char *authorization_endpoint_url;
	char *token_endpoint_url;
	char *token_endpoint_auth;
	char *token_endpoint_params;
	char *userinfo_endpoint_url;
	char *revocation_endpoint_url;
	char *registration_endpoint_url;
	char *pushed_authorization_request_endpoint_url;
	char *check_session_iframe;
	char *end_session_endpoint;
	oidc_jwks_uri_t jwks_uri;
	apr_array_header_t *verify_public_keys;
	char *client_id;
	char *client_secret;
	char *token_endpoint_tls_client_key;
	char *token_endpoint_tls_client_key_pwd;
	char *token_endpoint_tls_client_cert;
	int backchannel_logout_supported;

	// the next ones function as global default settings too
	int ssl_validate_server;
	int validate_issuer;
	char *client_name;
	char *client_contact;
	char *registration_token;
	char *registration_endpoint_json;
	char *scope;
	char *response_type;
	char *response_mode;
	int idtoken_iat_slack;
	char *auth_request_params;
	char *logout_request_params;
	int session_max_duration;
	oidc_proto_pkce_t *pkce;
	oidc_dpop_mode_t dpop_mode;
	int userinfo_refresh_interval;
	apr_array_header_t *client_keys;
	char *client_jwks_uri;
	char *id_token_signed_response_alg;
	char *id_token_encrypted_response_alg;
	char *id_token_encrypted_response_enc;
	char *userinfo_signed_response_alg;
	char *userinfo_encrypted_response_alg;
	char *userinfo_encrypted_response_enc;
	oidc_userinfo_token_method_t userinfo_token_method;
	char *request_object;
	oidc_auth_request_method_t auth_request_method;
	int response_require_iss;
};

#define OIDC_PROVIDER_MEMBER_FUNCS_TYPE_DEF(member, type, def_val)                                                     \
                                                                                                                       \
	const char *oidc_cmd_provider_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                     \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = oidc_cfg_provider_##member##_set(cmd->pool, cfg->provider, arg);                      \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	type oidc_cfg_provider_##member##_get(oidc_provider_t *provider) {                                             \
		return provider->member != NULL ? provider->member : def_val;                                          \
	}

// simple string
#define OIDC_PROVIDER_MEMBER_FUNCS_STR(member, def_val)                                                                \
                                                                                                                       \
	const char *oidc_cfg_provider_##member##_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {   \
		provider->member = apr_pstrdup(pool, arg);                                                             \
		return NULL;                                                                                           \
	};                                                                                                             \
                                                                                                                       \
	OIDC_PROVIDER_MEMBER_FUNCS_TYPE_DEF(member, const char *, def_val)

#define OIDC_PROVIDER_MEMBER_FUNCS_FILE(member)                                                                        \
	const char *oidc_cfg_provider_##member##_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {   \
		return oidc_cfg_parse_filename(pool, arg, &provider->member);                                          \
	};                                                                                                             \
                                                                                                                       \
	OIDC_PROVIDER_MEMBER_FUNCS_TYPE_DEF(member, const char *, NULL)

#define OIDC_PROVIDER_MEMBER_GET_INT_DEF(member, type, def_val)                                                        \
	type oidc_cfg_provider_##member##_get(oidc_provider_t *provider) {                                             \
		return provider->member != OIDC_CONFIG_POS_INT_UNSET ? provider->member : def_val;                     \
	}

// array of strings, int index
#define OIDC_PROVIDER_MEMBER_FUNCS_STR_INT(member, fparse, type, def_val)                                              \
	void oidc_cfg_provider_##member##_int_set(oidc_provider_t *provider, type arg) {                               \
		provider->member = arg;                                                                                \
	}                                                                                                              \
                                                                                                                       \
	const char *oidc_cfg_provider_##member##_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {   \
		const char *rv = NULL;                                                                                 \
		type v;                                                                                                \
		rv = fparse(pool, arg, &v);                                                                            \
		if (rv == NULL)                                                                                        \
			provider->member = v;                                                                          \
		else                                                                                                   \
			provider->member = def_val;                                                                    \
		return rv;                                                                                             \
	}                                                                                                              \
                                                                                                                       \
	const char *oidc_cmd_provider_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                     \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = oidc_cfg_provider_##member##_set(cmd->pool, cfg->provider, arg);                      \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	OIDC_PROVIDER_MEMBER_GET_INT_DEF(member, type, def_val)

// string with validation routine (for metadata)
#define OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(member, fvalid, def_val)                                                  \
	const char *oidc_cfg_provider_##member##_valid(apr_pool_t *pool, const char *arg) {                            \
		return fvalid(pool, arg);                                                                              \
	}                                                                                                              \
                                                                                                                       \
	const char *oidc_cfg_provider_##member##_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {   \
		const char *rv = oidc_cfg_provider_##member##_valid(pool, arg);                                        \
		if (rv == NULL)                                                                                        \
			provider->member = apr_pstrdup(pool, arg);                                                     \
		return rv;                                                                                             \
	}                                                                                                              \
                                                                                                                       \
	OIDC_PROVIDER_MEMBER_FUNCS_TYPE_DEF(member, const char *, def_val)

#define OIDC_PROVIDER_MEMBER_FUNCS_INT(member, fparse, min_val, max_val, def_val)                                      \
                                                                                                                       \
	const char *oidc_cfg_provider_##member##_valid(apr_pool_t *pool, int arg) {                                    \
		return oidc_cfg_parse_is_valid_int(pool, arg, min_val, max_val);                                       \
	}                                                                                                              \
                                                                                                                       \
	const char *oidc_cfg_provider_##member##_set(apr_pool_t *pool, oidc_provider_t *provider, int arg) {           \
		const char *rv = oidc_cfg_provider_##member##_valid(pool, arg);                                        \
		if (rv == NULL)                                                                                        \
			provider->member = arg;                                                                        \
		else                                                                                                   \
			provider->member = def_val;                                                                    \
		return rv;                                                                                             \
	}                                                                                                              \
                                                                                                                       \
	const char *oidc_cmd_provider_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                     \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		int v = -1;                                                                                            \
		const char *rv = fparse(cmd->pool, arg, &v);                                                           \
		if (rv == NULL)                                                                                        \
			rv = oidc_cfg_provider_##member##_set(cmd->pool, cfg->provider, v);                            \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	OIDC_PROVIDER_MEMBER_GET_INT_DEF(member, int, def_val)

#define OIDC_PROVIDER_MEMBER_FUNCS_URL(member)                                                                         \
	OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(member, oidc_cfg_parse_is_valid_http_url, NULL)

#define OIDC_PROVIDER_MEMBER_FUNCS_FLAG(member, def_val)                                                               \
	OIDC_PROVIDER_MEMBER_FUNCS_INT(member, oidc_cfg_parse_boolean, 0, 1, def_val)

/*
 * passphrases
 */
#define OIDC_PROVIDER_TYPE_MEMBER_FUNCS_PASSPHRASE(member)                                                             \
                                                                                                                       \
	const char *oidc_cfg_provider_##member##_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {   \
		return oidc_cfg_parse_passphrase(pool, arg, &provider->member);                                        \
	}                                                                                                              \
                                                                                                                       \
	OIDC_PROVIDER_MEMBER_FUNCS_TYPE_DEF(member, const char *, NULL)

OIDC_PROVIDER_TYPE_MEMBER_FUNCS_PASSPHRASE(client_secret)
OIDC_PROVIDER_TYPE_MEMBER_FUNCS_PASSPHRASE(token_endpoint_tls_client_key_pwd)

/*
 * keys
 */
#define OIDC_PROVIDER_MEMBER_FUNCS_KEYS(member)                                                                        \
                                                                                                                       \
	const char *oidc_cfg_provider_##member##_set_keys(apr_pool_t *pool, oidc_provider_t *provider,                 \
							  apr_array_header_t *arg) {                                   \
		provider->member = arg;                                                                                \
		return NULL;                                                                                           \
	}                                                                                                              \
                                                                                                                       \
	const char *oidc_cfg_provider_##member##_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {   \
		return oidc_cfg_parse_public_key_files(pool, arg, &provider->member);                                  \
	}                                                                                                              \
	OIDC_PROVIDER_MEMBER_FUNCS_TYPE_DEF(member, const apr_array_header_t *, NULL)

OIDC_PROVIDER_MEMBER_FUNCS_KEYS(verify_public_keys)
OIDC_PROVIDER_MEMBER_FUNCS_KEYS(client_keys)

/*
 * PKCE
 */
#define OIDC_DEFAULT_PROVIDER_PKCE &oidc_pkce_s256

const char *oidc_cfg_provider_pkce_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {
	static const char *options[] = {OIDC_PKCE_METHOD_PLAIN, OIDC_PKCE_METHOD_S256, OIDC_PKCE_METHOD_NONE, NULL};
	if (_oidc_strcmp(arg, OIDC_PKCE_METHOD_PLAIN) == 0) {
		provider->pkce = &oidc_pkce_plain;
		return NULL;
	} else if (_oidc_strcmp(arg, OIDC_PKCE_METHOD_S256) == 0) {
		provider->pkce = &oidc_pkce_s256;
		return NULL;
	} else if (_oidc_strcmp(arg, OIDC_PKCE_METHOD_NONE) == 0) {
		provider->pkce = NULL;
		return NULL;
	}
	return oidc_cfg_parse_is_valid_option(pool, arg, options);
}

OIDC_PROVIDER_MEMBER_FUNCS_TYPE_DEF(pkce, const oidc_proto_pkce_t *, OIDC_DEFAULT_PROVIDER_PKCE)

/*
 * DPoP
 */
#define OIDC_DPOP_MODE_OFF_STR "off"
#define OIDC_DPOP_MODE_OPTIONAL_STR "optional"
#define OIDC_DPOP_MODE_REQUIRED_STR "required"

static const char *oidc_cfg_provider_parse_dop_method(apr_pool_t *pool, const char *arg, oidc_dpop_mode_t *mode) {
	static const oidc_cfg_option_t options[] = {
	    {OIDC_DPOP_MODE_OFF, OIDC_DPOP_MODE_OFF_STR},
	    {OIDC_DPOP_MODE_OPTIONAL, OIDC_DPOP_MODE_OPTIONAL_STR},
	    {OIDC_DPOP_MODE_REQUIRED, OIDC_DPOP_MODE_REQUIRED_STR},
	};
	return oidc_cfg_parse_option(pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg, (int *)mode);
}

#define OIDC_DEFAULT_DPOP_MODE OIDC_DPOP_MODE_OFF

OIDC_PROVIDER_MEMBER_GET_INT_DEF(dpop_mode, oidc_dpop_mode_t, OIDC_DEFAULT_DPOP_MODE)

void oidc_cfg_provider_dpop_mode_int_set(oidc_provider_t *provider, oidc_dpop_mode_t arg) {
	provider->dpop_mode = arg;
}

const char *oidc_cfg_provider_dpop_mode_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {
	const char *rv = NULL;
	oidc_dpop_mode_t v;
	rv = oidc_cfg_provider_parse_dop_method(pool, arg, &v);
	if (rv == NULL)
		provider->dpop_mode = v;
	else
		provider->dpop_mode = OIDC_DEFAULT_DPOP_MODE;
	return rv;
}

const char *oidc_cmd_provider_dpop_mode_set(cmd_parms *cmd, void *ptr, const char *arg1, const char *arg2) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_provider_dpop_mode_set(cmd->pool, cfg->provider, arg1);
	if ((rv == NULL) && (arg2))
		rv = oidc_cfg_parse_boolean(cmd->pool, arg2, &cfg->dpop_api_enabled);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_PROVIDER_MEMBER_FUNCS_STR(issuer, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_URL(authorization_endpoint_url)
OIDC_PROVIDER_MEMBER_FUNCS_STR(auth_request_params, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_URL(token_endpoint_url)
OIDC_PROVIDER_MEMBER_FUNCS_STR(token_endpoint_params, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_URL(userinfo_endpoint_url)
OIDC_PROVIDER_MEMBER_FUNCS_URL(registration_endpoint_url)
OIDC_PROVIDER_MEMBER_FUNCS_URL(pushed_authorization_request_endpoint_url)
OIDC_PROVIDER_MEMBER_FUNCS_URL(check_session_iframe)
OIDC_PROVIDER_MEMBER_FUNCS_URL(end_session_endpoint)
OIDC_PROVIDER_MEMBER_FUNCS_STR(client_contact, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_STR(client_id, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_URL(client_jwks_uri)
OIDC_PROVIDER_MEMBER_FUNCS_STR(logout_request_params, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_URL(metadata_url)
OIDC_PROVIDER_MEMBER_FUNCS_STR(registration_endpoint_json, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_STR(request_object, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_FILE(token_endpoint_tls_client_cert)
OIDC_PROVIDER_MEMBER_FUNCS_FILE(token_endpoint_tls_client_key)

/* default scope requested from the OP */
#define OIDC_DEFAULT_SCOPE "openid"
OIDC_PROVIDER_MEMBER_FUNCS_STR(scope, OIDC_DEFAULT_SCOPE)

#define OIDC_DEFAULT_CLIENT_NAME "OpenID Connect Apache Module (mod_auth_openidc)"
OIDC_PROVIDER_MEMBER_FUNCS_STR(client_name, OIDC_DEFAULT_CLIENT_NAME)

// TODO: no longer used as sid is also stored for frontchannel logout flows
OIDC_PROVIDER_MEMBER_FUNCS_FLAG(backchannel_logout_supported, 0)

#define OIDC_DEFAULT_SSL_VALIDATE_SERVER 1
OIDC_PROVIDER_MEMBER_FUNCS_FLAG(ssl_validate_server, OIDC_DEFAULT_SSL_VALIDATE_SERVER)

#define OIDC_DEFAULT_VALIDATE_ISSUER 1
OIDC_PROVIDER_MEMBER_FUNCS_FLAG(validate_issuer, OIDC_DEFAULT_VALIDATE_ISSUER)

// define whether the iss parameter will be required in the response to the redirect uri by default to mitigate the IDP
// mixup attack only used from metadata in multi-provider setups
#define OIDC_DEFAULT_PROVIDER_RESPONSE_REQUIRE_ISS 0
OIDC_PROVIDER_MEMBER_FUNCS_FLAG(response_require_iss, OIDC_DEFAULT_PROVIDER_RESPONSE_REQUIRE_ISS)
// only used from metadata in multi-provider setups
OIDC_PROVIDER_MEMBER_FUNCS_STR(registration_token, NULL)

OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(response_mode, oidc_cfg_parse_is_valid_response_mode, NULL)

#define OIDC_DEFAULT_RESPONSE_TYPE OIDC_PROTO_CODE
OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(response_type, oidc_cfg_parse_is_valid_response_type, OIDC_DEFAULT_RESPONSE_TYPE)

OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(id_token_signed_response_alg, oidc_cfg_parse_is_valid_signed_response_alg, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(id_token_encrypted_response_alg, oidc_cfg_parse_is_valid_encrypted_response_alg,
				     NULL)
OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(id_token_encrypted_response_enc, oidc_cfg_parse_is_valid_encrypted_response_enc,
				     NULL)

OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(userinfo_signed_response_alg, oidc_cfg_parse_is_valid_signed_response_alg, NULL)
OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(userinfo_encrypted_response_alg, oidc_cfg_parse_is_valid_encrypted_response_alg,
				     NULL)
OIDC_PROVIDER_MEMBER_FUNCS_PARSE_STR(userinfo_encrypted_response_enc, oidc_cfg_parse_is_valid_encrypted_response_enc,
				     NULL)

#define OIDC_AUTH_REQUEST_METHOD_GET_STR "GET"
#define OIDC_AUTH_REQUEST_METHOD_POST_STR "POST"
#define OIDC_AUTH_REQUEST_METHOD_PAR_STR "PAR"

static const char *oidc_cfg_provider_parse_auth_request_method(apr_pool_t *pool, const char *arg,
							       oidc_auth_request_method_t *method) {
	static const oidc_cfg_option_t options[] = {
	    {OIDC_AUTH_REQUEST_METHOD_GET, OIDC_AUTH_REQUEST_METHOD_GET_STR},
	    {OIDC_AUTH_REQUEST_METHOD_POST, OIDC_AUTH_REQUEST_METHOD_POST_STR},
	    {OIDC_AUTH_REQUEST_METHOD_PAR, OIDC_AUTH_REQUEST_METHOD_PAR_STR},
	};
	return oidc_cfg_parse_option(pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg, (int *)method);
}

#define OIDC_DEFAULT_AUTH_REQUEST_METHOD OIDC_AUTH_REQUEST_METHOD_GET
OIDC_PROVIDER_MEMBER_FUNCS_STR_INT(auth_request_method, oidc_cfg_provider_parse_auth_request_method,
				   oidc_auth_request_method_t, OIDC_DEFAULT_AUTH_REQUEST_METHOD)

#define OIDC_USER_INFO_TOKEN_METHOD_HEADER_STR "authz_header"
#define OIDC_USER_INFO_TOKEN_METHOD_POST_STR "post_param"

const char *oidc_cfg_provider_parse_userinfo_token_method(apr_pool_t *pool, const char *arg,
							  oidc_userinfo_token_method_t *method) {
	static const oidc_cfg_option_t options[] = {
	    {OIDC_USER_INFO_TOKEN_METHOD_HEADER, OIDC_USER_INFO_TOKEN_METHOD_HEADER_STR},
	    {OIDC_USER_INFO_TOKEN_METHOD_POST, OIDC_USER_INFO_TOKEN_METHOD_POST_STR}};
	return oidc_cfg_parse_option(pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg, (int *)method);
}

#define OIDC_DEFAULT_USER_INFO_TOKEN_METHOD OIDC_USER_INFO_TOKEN_METHOD_HEADER
OIDC_PROVIDER_MEMBER_FUNCS_STR_INT(userinfo_token_method, oidc_cfg_provider_parse_userinfo_token_method,
				   oidc_userinfo_token_method_t, OIDC_DEFAULT_USER_INFO_TOKEN_METHOD)

#define OIDC_IDTOKEN_IAT_SLACK_MIN 0
#define OIDC_IDTOKEN_IAT_SLACK_MAX 3600
#define OIDC_DEFAULT_IDTOKEN_IAT_SLACK 600

OIDC_PROVIDER_MEMBER_FUNCS_INT(idtoken_iat_slack, oidc_cfg_parse_int, OIDC_IDTOKEN_IAT_SLACK_MIN,
			       OIDC_IDTOKEN_IAT_SLACK_MAX, OIDC_DEFAULT_IDTOKEN_IAT_SLACK)

#define OIDC_SESSION_MAX_DURATION_MIN 15
#define OIDC_SESSION_MAX_DURATION_MAX 3600 * 24 * 365
#define OIDC_DEFAULT_SESSION_MAX_DURATION 3600 * 8

const char *oidc_cfg_provider_session_max_duration_set(apr_pool_t *pool, oidc_provider_t *provider, int arg) {
	const char *rv = NULL;
	if (arg != 0)
		rv = oidc_cfg_parse_is_valid_int(pool, arg, OIDC_SESSION_MAX_DURATION_MIN,
						 OIDC_SESSION_MAX_DURATION_MAX);
	if (rv == NULL)
		provider->session_max_duration = arg;
	else
		provider->session_max_duration = OIDC_DEFAULT_SESSION_MAX_DURATION;
	return rv;
}

const char *oidc_cmd_provider_session_max_duration_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	int v = -1;
	const char *rv = oidc_cfg_parse_int(cmd->pool, arg, &v);
	if (rv == NULL)
		rv = oidc_cfg_provider_session_max_duration_set(cmd->pool, cfg->provider, v);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

OIDC_PROVIDER_MEMBER_GET_INT_DEF(session_max_duration, int, OIDC_DEFAULT_SESSION_MAX_DURATION)

#define OIDC_JWKS_REFRESH_INTERVAL_MIN 300
#define OIDC_JWKS_REFRESH_INTERVAL_MAX 3600 * 24 * 365
#define OIDC_DEFAULT_JWKS_REFRESH_INTERVAL 3600

const char *oidc_cfg_provider_jwks_uri_refresh_interval_set(apr_pool_t *pool, oidc_provider_t *provider, int arg) {
	const char *rv =
	    oidc_cfg_parse_is_valid_int(pool, arg, OIDC_JWKS_REFRESH_INTERVAL_MIN, OIDC_JWKS_REFRESH_INTERVAL_MAX);
	if (rv == NULL)
		provider->jwks_uri.refresh_interval = arg;
	else
		provider->jwks_uri.refresh_interval = OIDC_DEFAULT_JWKS_REFRESH_INTERVAL;
	return rv;
}

const char *oidc_cmd_provider_jwks_uri_refresh_interval_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	int v;
	const char *rv = oidc_cfg_parse_int(cmd->pool, arg, &v);
	if (rv == NULL)
		rv = oidc_cfg_provider_jwks_uri_refresh_interval_set(cmd->pool, cfg->provider, v);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

int oidc_cfg_provider_jwks_uri_refresh_interval_get(oidc_provider_t *provider) {
	return provider->jwks_uri.refresh_interval != OIDC_CONFIG_POS_INT_UNSET ? provider->jwks_uri.refresh_interval
										: OIDC_DEFAULT_JWKS_REFRESH_INTERVAL;
}

const oidc_jwks_uri_t *oidc_cfg_provider_jwks_uri_get(oidc_provider_t *provider) {
	return &provider->jwks_uri;
}

const char *oidc_cfg_provider_jwks_uri_uri_get(oidc_provider_t *provider) {
	return provider->jwks_uri.uri;
}

const char *oidc_cfg_provider_jwks_uri_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg) {
	const char *rv = oidc_cfg_parse_is_valid_url(pool, arg, "https");
	if (rv == NULL)
		provider->jwks_uri.uri = apr_pstrdup(pool, arg);
	return rv;
}

const char *oidc_cmd_provider_jwks_uri_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_provider_jwks_uri_set(cmd->pool, cfg->provider, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

const char *oidc_cfg_provider_signed_jwks_uri_get(oidc_provider_t *provider) {
	return provider->jwks_uri.signed_uri;
}

apr_array_header_t *oidc_cfg_provider_signed_jwks_uri_keys_get(oidc_provider_t *provider) {
	return provider->jwks_uri.jwk_list;
}

const char *oidc_cfg_provider_signed_jwks_uri_keys_set(apr_pool_t *pool, oidc_provider_t *provider, json_t *json,
						       apr_array_header_t *def_val) {
	const char *rv = NULL;
	oidc_jose_error_t err;

	if (json == NULL)
		goto end;

	if (oidc_is_jwk(json)) {
		oidc_jwk_t *jwk = NULL;
		if (oidc_jwk_parse_json(pool, json, &jwk, &err) != TRUE) {
			rv = apr_psprintf(pool, "oidc_jwk_parse_json failed for the specified JWK: %s",
					  oidc_jose_e2s(pool, err));
			goto end;
		}
		provider->jwks_uri.jwk_list = apr_array_make(pool, 1, sizeof(oidc_jwk_t *));
		APR_ARRAY_PUSH(provider->jwks_uri.jwk_list, oidc_jwk_t *) = jwk;
		goto end;
	}

	if (oidc_is_jwks(json)) {
		if (oidc_jwks_parse_json(pool, json, &provider->jwks_uri.jwk_list, &err) != TRUE)
			rv = apr_psprintf(pool, "oidc_jwks_parse_json failed for the specified JWKs: %s",
					  oidc_jose_e2s(pool, err));
		goto end;
	}

	rv = apr_psprintf(pool, "invalid JWK/JWKs argument");

end:

	if (rv != NULL)
		provider->jwks_uri.jwk_list = def_val;

	return rv;
}

const char *oidc_cfg_provider_signed_jwks_uri_set(apr_pool_t *pool, oidc_provider_t *provider, const char *arg1,
						  const char *arg2) {
	const char *rv = NULL;
	json_error_t json_error;
	json_t *json = NULL;

	if ((arg1 != NULL) && (_oidc_strcmp(arg1, "") != 0)) {
		rv = oidc_cfg_parse_is_valid_url(pool, arg1, "https");
		if (rv != NULL)
			goto end;
		provider->jwks_uri.signed_uri = apr_pstrdup(pool, arg1);
	}

	if ((arg2 == NULL) || (_oidc_strcmp(arg2, "") == 0))
		goto end;

	json = json_loads(arg2, 0, &json_error);
	if (json == NULL) {
		rv = apr_psprintf(pool, "json_loads failed for the 2nd argument: %s", json_error.text);
		goto end;
	}

	rv = oidc_cfg_provider_signed_jwks_uri_keys_set(pool, provider, json, NULL);

end:

	if (json)
		json_decref(json);

	return rv;
}

const char *oidc_cmd_provider_signed_jwks_uri_set(cmd_parms *cmd, void *ptr, const char *arg1, const char *arg2) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_provider_signed_jwks_uri_set(cmd->pool, cfg->provider, arg1, arg2);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

const char *oidc_cfg_provider_token_endpoint_auth_set(apr_pool_t *pool, oidc_cfg_t *cfg, oidc_provider_t *provider,
						      const char *arg) {
	const char *rv = oidc_cfg_get_valid_endpoint_auth_function(cfg)(pool, arg);
	if (rv == NULL)
		provider->token_endpoint_auth = apr_pstrdup(pool, arg);
	return rv;
}

const char *oidc_cmd_provider_token_endpoint_auth_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_provider_token_endpoint_auth_set(cmd->pool, cfg, cfg->provider, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

const char *oidc_cfg_provider_token_endpoint_auth_get(oidc_provider_t *provider) {
	return provider->token_endpoint_auth;
}

#define OIDC_USERINFO_REFRESH_INTERVAL_MIN 0
#define OIDC_USERINFO_REFRESH_INTERVAL_MAX 3600 * 24 * 365
#define OIDC_DEFAULT_USERINFO_REFRESH_INTERVAL -1

const char *oidc_cfg_provider_userinfo_refresh_interval_set(apr_pool_t *pool, oidc_provider_t *provider, int arg) {
	const char *rv = oidc_cfg_parse_is_valid_int(pool, arg, OIDC_USERINFO_REFRESH_INTERVAL_MIN,
						     OIDC_USERINFO_REFRESH_INTERVAL_MAX);
	if (rv == NULL)
		provider->userinfo_refresh_interval = arg;
	else
		provider->userinfo_refresh_interval = OIDC_DEFAULT_USERINFO_REFRESH_INTERVAL;
	return rv;
}

const char *oidc_cmd_provider_userinfo_refresh_interval_set(cmd_parms *cmd, void *ptr, const char *arg1,
							    const char *arg2) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	int v;
	const char *rv = oidc_cfg_parse_int(cmd->pool, arg1, &v);
	if (rv == NULL)
		rv = oidc_cfg_provider_userinfo_refresh_interval_set(cmd->pool, cfg->provider, v);
	if ((rv == NULL) && (arg2))
		rv = oidc_cfg_parse_action_on_error_refresh_as(cmd->pool, arg2, &cfg->action_on_userinfo_error);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

int oidc_cfg_provider_userinfo_refresh_interval_get(oidc_provider_t *provider) {
	return provider->userinfo_refresh_interval != OIDC_CONFIG_POS_INT_UNSET
		   ? provider->userinfo_refresh_interval
		   : OIDC_DEFAULT_USERINFO_REFRESH_INTERVAL;
}

/*
 * revocation endpoint url, must allow empty string in base config
 */

const char *oidc_cfg_provider_revocation_endpoint_url_set(apr_pool_t *pool, oidc_provider_t *provider,
							  const char *arg) {
	const char *rv = oidc_cfg_parse_is_valid_http_url(pool, arg);
	if (rv == NULL)
		provider->revocation_endpoint_url = apr_pstrdup(pool, arg);
	return rv;
}

const char *oidc_cmd_provider_revocation_endpoint_url_set(cmd_parms *cmd, void *ptr, const char *args) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	char *w = ap_getword_conf(cmd->pool, &args);
	if (*w == '\0' || *args != 0) {
		cfg->provider->revocation_endpoint_url = "";
		return NULL;
	}
	return oidc_cfg_provider_revocation_endpoint_url_set(cmd->pool, cfg->provider, args);
}

const char *oidc_cfg_provider_revocation_endpoint_url_get(oidc_provider_t *provider) {
	return provider->revocation_endpoint_url;
}

/*
 * base
 */

static void oidc_cfg_provider_init(oidc_provider_t *provider) {
	provider->metadata_url = NULL;
	provider->issuer = NULL;
	provider->authorization_endpoint_url = NULL;
	provider->token_endpoint_url = NULL;
	provider->token_endpoint_auth = NULL;
	provider->token_endpoint_params = NULL;
	provider->userinfo_endpoint_url = NULL;
	provider->revocation_endpoint_url = NULL;
	provider->client_id = NULL;
	provider->client_secret = NULL;
	provider->token_endpoint_tls_client_cert = NULL;
	provider->token_endpoint_tls_client_key = NULL;
	provider->token_endpoint_tls_client_key_pwd = NULL;
	provider->registration_endpoint_url = NULL;
	provider->registration_endpoint_json = NULL;
	provider->pushed_authorization_request_endpoint_url = NULL;
	provider->check_session_iframe = NULL;
	provider->end_session_endpoint = NULL;
	provider->jwks_uri.uri = NULL;
	provider->jwks_uri.refresh_interval = OIDC_CONFIG_POS_INT_UNSET;
	provider->jwks_uri.signed_uri = NULL;
	provider->jwks_uri.jwk_list = NULL;
	provider->verify_public_keys = NULL;
	provider->backchannel_logout_supported = OIDC_CONFIG_POS_INT_UNSET;

	provider->ssl_validate_server = OIDC_CONFIG_POS_INT_UNSET;
	provider->validate_issuer = OIDC_CONFIG_POS_INT_UNSET;
	provider->client_name = NULL;
	provider->client_contact = NULL;
	provider->registration_token = NULL;
	provider->scope = NULL;
	provider->response_type = NULL;
	provider->response_mode = NULL;
	provider->idtoken_iat_slack = OIDC_CONFIG_POS_INT_UNSET;
	provider->session_max_duration = OIDC_CONFIG_POS_INT_UNSET;
	provider->auth_request_params = NULL;
	provider->logout_request_params = NULL;
	provider->pkce = NULL;
	provider->dpop_mode = OIDC_CONFIG_POS_INT_UNSET;

	provider->client_jwks_uri = NULL;
	provider->client_keys = NULL;

	provider->id_token_signed_response_alg = NULL;
	provider->id_token_encrypted_response_alg = NULL;
	provider->id_token_encrypted_response_enc = NULL;
	provider->userinfo_signed_response_alg = NULL;
	provider->userinfo_encrypted_response_alg = NULL;
	provider->userinfo_encrypted_response_enc = NULL;
	provider->userinfo_token_method = OIDC_CONFIG_POS_INT_UNSET;
	provider->auth_request_method = OIDC_CONFIG_POS_INT_UNSET;

	provider->userinfo_refresh_interval = OIDC_CONFIG_POS_INT_UNSET;
	provider->request_object = NULL;

	provider->response_require_iss = OIDC_CONFIG_POS_INT_UNSET;
}

void oidc_cfg_provider_merge(apr_pool_t *pool, oidc_provider_t *dst, const oidc_provider_t *base,
			     const oidc_provider_t *add) {
	dst->metadata_url = add->metadata_url != NULL ? add->metadata_url : base->metadata_url;
	dst->issuer = add->issuer != NULL ? add->issuer : base->issuer;
	dst->authorization_endpoint_url = add->authorization_endpoint_url != NULL ? add->authorization_endpoint_url
										  : base->authorization_endpoint_url;
	dst->token_endpoint_url = add->token_endpoint_url != NULL ? add->token_endpoint_url : base->token_endpoint_url;
	dst->token_endpoint_auth =
	    add->token_endpoint_auth != NULL ? add->token_endpoint_auth : base->token_endpoint_auth;
	dst->token_endpoint_params =
	    add->token_endpoint_params != NULL ? add->token_endpoint_params : base->token_endpoint_params;
	dst->userinfo_endpoint_url =
	    add->userinfo_endpoint_url != NULL ? add->userinfo_endpoint_url : base->userinfo_endpoint_url;
	dst->revocation_endpoint_url =
	    add->revocation_endpoint_url != NULL ? add->revocation_endpoint_url : base->revocation_endpoint_url;
	dst->jwks_uri.uri = add->jwks_uri.uri != NULL ? add->jwks_uri.uri : base->jwks_uri.uri;
	dst->jwks_uri.refresh_interval = add->jwks_uri.refresh_interval != OIDC_CONFIG_POS_INT_UNSET
					     ? add->jwks_uri.refresh_interval
					     : base->jwks_uri.refresh_interval;
	dst->jwks_uri.signed_uri =
	    add->jwks_uri.signed_uri != NULL ? add->jwks_uri.signed_uri : base->jwks_uri.signed_uri;
	dst->jwks_uri.jwk_list =
	    oidc_jwk_list_copy(pool, add->jwks_uri.jwk_list != NULL ? add->jwks_uri.jwk_list : base->jwks_uri.jwk_list);
	dst->verify_public_keys = oidc_jwk_list_copy(pool, add->verify_public_keys != NULL ? add->verify_public_keys
											   : base->verify_public_keys);
	dst->client_id = add->client_id != NULL ? add->client_id : base->client_id;
	dst->client_secret = add->client_secret != NULL ? add->client_secret : base->client_secret;

	dst->token_endpoint_tls_client_key = add->token_endpoint_tls_client_key != NULL
						 ? add->token_endpoint_tls_client_key
						 : base->token_endpoint_tls_client_key;
	dst->token_endpoint_tls_client_key_pwd = add->token_endpoint_tls_client_key_pwd != NULL
						     ? add->token_endpoint_tls_client_key_pwd
						     : base->token_endpoint_tls_client_key_pwd;
	dst->token_endpoint_tls_client_cert = add->token_endpoint_tls_client_cert != NULL
						  ? add->token_endpoint_tls_client_cert
						  : base->token_endpoint_tls_client_cert;

	dst->registration_endpoint_url =
	    add->registration_endpoint_url != NULL ? add->registration_endpoint_url : base->registration_endpoint_url;
	dst->registration_endpoint_json = add->registration_endpoint_json != NULL ? add->registration_endpoint_json
										  : base->registration_endpoint_json;
	dst->pushed_authorization_request_endpoint_url = add->pushed_authorization_request_endpoint_url != NULL
							     ? add->pushed_authorization_request_endpoint_url
							     : base->pushed_authorization_request_endpoint_url;

	dst->check_session_iframe =
	    add->check_session_iframe != NULL ? add->check_session_iframe : base->check_session_iframe;
	dst->end_session_endpoint =
	    add->end_session_endpoint != NULL ? add->end_session_endpoint : base->end_session_endpoint;
	dst->backchannel_logout_supported = add->backchannel_logout_supported != OIDC_CONFIG_POS_INT_UNSET
						? add->backchannel_logout_supported
						: base->backchannel_logout_supported;

	dst->ssl_validate_server = add->ssl_validate_server != OIDC_CONFIG_POS_INT_UNSET ? add->ssl_validate_server
											 : base->ssl_validate_server;
	dst->validate_issuer =
	    add->validate_issuer != OIDC_CONFIG_POS_INT_UNSET ? add->validate_issuer : base->validate_issuer;
	dst->client_name = add->client_name != NULL ? add->client_name : base->client_name;
	dst->client_contact = add->client_contact != NULL ? add->client_contact : base->client_contact;
	dst->registration_token = add->registration_token != NULL ? add->registration_token : base->registration_token;
	dst->scope = add->scope != NULL ? add->scope : base->scope;
	dst->response_type = add->response_type != NULL ? add->response_type : base->response_type;
	dst->response_mode = add->response_mode != NULL ? add->response_mode : base->response_mode;
	dst->idtoken_iat_slack =
	    add->idtoken_iat_slack != OIDC_CONFIG_POS_INT_UNSET ? add->idtoken_iat_slack : base->idtoken_iat_slack;
	dst->session_max_duration = add->session_max_duration != OIDC_CONFIG_POS_INT_UNSET ? add->session_max_duration
											   : base->session_max_duration;
	dst->auth_request_params =
	    add->auth_request_params != NULL ? add->auth_request_params : base->auth_request_params;
	dst->logout_request_params =
	    add->logout_request_params != NULL ? add->logout_request_params : base->logout_request_params;
	dst->pkce = add->pkce != NULL ? add->pkce : base->pkce;
	dst->dpop_mode = add->dpop_mode != OIDC_CONFIG_POS_INT_UNSET ? add->dpop_mode : base->dpop_mode;

	dst->client_jwks_uri = add->client_jwks_uri != NULL ? add->client_jwks_uri : base->client_jwks_uri;
	dst->client_keys = oidc_jwk_list_copy(pool, add->client_keys != NULL ? add->client_keys : base->client_keys);

	dst->id_token_signed_response_alg = add->id_token_signed_response_alg != NULL
						? add->id_token_signed_response_alg
						: base->id_token_signed_response_alg;
	dst->id_token_encrypted_response_alg = add->id_token_encrypted_response_alg != NULL
						   ? add->id_token_encrypted_response_alg
						   : base->id_token_encrypted_response_alg;
	dst->id_token_encrypted_response_enc = add->id_token_encrypted_response_enc != NULL
						   ? add->id_token_encrypted_response_enc
						   : base->id_token_encrypted_response_enc;
	dst->userinfo_signed_response_alg = add->userinfo_signed_response_alg != NULL
						? add->userinfo_signed_response_alg
						: base->userinfo_signed_response_alg;
	dst->userinfo_encrypted_response_alg = add->userinfo_encrypted_response_alg != NULL
						   ? add->userinfo_encrypted_response_alg
						   : base->userinfo_encrypted_response_alg;
	dst->userinfo_encrypted_response_enc = add->userinfo_encrypted_response_enc != NULL
						   ? add->userinfo_encrypted_response_enc
						   : base->userinfo_encrypted_response_enc;
	dst->userinfo_token_method = add->userinfo_token_method != OIDC_CONFIG_POS_INT_UNSET
					 ? add->userinfo_token_method
					 : base->userinfo_token_method;
	dst->auth_request_method = add->auth_request_method != OIDC_CONFIG_POS_INT_UNSET ? add->auth_request_method
											 : base->auth_request_method;

	dst->userinfo_refresh_interval = add->userinfo_refresh_interval != OIDC_CONFIG_POS_INT_UNSET
					     ? add->userinfo_refresh_interval
					     : base->userinfo_refresh_interval;
	dst->request_object = add->request_object != NULL ? add->request_object : base->request_object;

	dst->response_require_iss = add->response_require_iss != OIDC_CONFIG_POS_INT_UNSET ? add->response_require_iss
											   : base->response_require_iss;
}

oidc_provider_t *oidc_cfg_provider_create(apr_pool_t *pool) {
	oidc_provider_t *provider = apr_pcalloc(pool, sizeof(oidc_provider_t));
	oidc_cfg_provider_init(provider);
	return provider;
}

oidc_provider_t *oidc_cfg_provider_copy(apr_pool_t *pool, const oidc_provider_t *src) {
	oidc_provider_t *dst = oidc_cfg_provider_create(pool);
	oidc_cfg_provider_merge(pool, dst, dst, src);
	return dst;
}

void oidc_cfg_provider_destroy(oidc_provider_t *provider) {
	oidc_jwk_list_destroy(provider->jwks_uri.jwk_list);
	oidc_jwk_list_destroy(provider->verify_public_keys);
	oidc_jwk_list_destroy(provider->client_keys);
}
