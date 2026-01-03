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

#include "cfg/oauth.h"
#include "cfg/cfg_int.h"
#include "cfg/parse.h"
#include "jose.h"
#include "proto/proto.h"

struct oidc_oauth_t {

	char *metadata_url;

	char *verify_jwks_uri;

	apr_hash_t *verify_shared_keys;
	apr_array_header_t *verify_public_keys;

	char *client_id;
	char *client_secret;

	char *introspection_endpoint_url;
	int introspection_endpoint_method;
	char *introspection_token_param_name;
	char *introspection_endpoint_params;
	char *introspection_endpoint_auth;
	char *introspection_endpoint_auth_alg;
	char *introspection_client_auth_bearer_token;
	char *introspection_endpoint_tls_client_key;
	char *introspection_endpoint_tls_client_key_pwd;
	char *introspection_endpoint_tls_client_cert;
	char *introspection_token_expiry_claim_name;
	oidc_oauth_introspection_token_expiry_claim_format_t introspection_token_expiry_claim_format;
	oidc_oauth_introspection_token_expiry_claim_required_t introspection_token_expiry_claim_required;

	oidc_remote_user_claim_t remote_user_claim;

	int ssl_validate_server;
};

// helper
#define OIDC_OAUTH_MEMBER_FUNC_GET(member, type)                                                                       \
	type oidc_cfg_oauth_##member##_get(oidc_cfg_t *cfg) {                                                          \
		return cfg->oauth->member;                                                                             \
	}

#define OIDC_OAUTH_MEMBER_FUNCS_TYPE(member, type, valid)                                                              \
	const char *oidc_cmd_oauth_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = valid;                                                                                \
		if (rv == NULL)                                                                                        \
			cfg->oauth->member = apr_pstrdup(cmd->pool, arg);                                              \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
	OIDC_OAUTH_MEMBER_FUNC_GET(member, type)

#define OIDC_OAUTH_MEMBER_FUNCS_INT(member, parse, type, def_val)                                                      \
	const char *oidc_cmd_oauth_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		int v = -1;                                                                                            \
		const char *rv = parse;                                                                                \
		if (rv == NULL)                                                                                        \
			cfg->oauth->member = v;                                                                        \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
                                                                                                                       \
	type oidc_cfg_oauth_##member##_get(oidc_cfg_t *cfg) {                                                          \
		if (cfg->oauth->member == OIDC_CONFIG_POS_INT_UNSET)                                                   \
			return def_val;                                                                                \
		return cfg->oauth->member;                                                                             \
	}

#define OIDC_OAUTH_MEMBER_FUNCS_BOOL(member, def_val)                                                                  \
	OIDC_OAUTH_MEMBER_FUNCS_INT(member, oidc_cfg_parse_boolean(cmd->pool, arg, &v), int, def_val)

#define OIDC_OAUTH_MEMBER_FUNCS_KEYS(member)                                                                           \
	const char *oidc_cmd_oauth_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		return oidc_cfg_parse_public_key_files(cmd->pool, arg, &cfg->oauth->member);                           \
	}                                                                                                              \
	OIDC_OAUTH_MEMBER_FUNC_GET(member, const apr_array_header_t *)

#define OIDC_OAUTH_MEMBER_FUNCS_STR(member) OIDC_OAUTH_MEMBER_FUNCS_TYPE(member, const char *, NULL)
#define OIDC_OAUTH_MEMBER_FUNCS_URL(member)                                                                            \
	OIDC_OAUTH_MEMBER_FUNCS_TYPE(member, const char *, oidc_cfg_parse_is_valid_http_url(cmd->pool, arg))

#define OIDC_OAUTH_MEMBER_FUNC_STR_GET_DEF(member, def_val)                                                            \
	const char *oidc_cfg_oauth_##member##_get(oidc_cfg_t *cfg) {                                                   \
		return cfg->oauth->member ? cfg->oauth->member : def_val;                                              \
	}

#define OIDC_OAUTH_MEMBER_FUNCS_FILE(member)                                                                           \
	const char *oidc_cmd_oauth_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = oidc_cfg_parse_filename(cmd->pool, arg, &cfg->oauth->member);                         \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
	OIDC_OAUTH_MEMBER_FUNC_GET(member, const char *)

#define OIDC_OAUTH_MEMBER_FUNCS_PASSPHRASE(member)                                                                     \
	const char *oidc_cmd_oauth_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = oidc_cfg_parse_passphrase(cmd->pool, arg, &cfg->oauth->member);                       \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
	OIDC_OAUTH_MEMBER_FUNC_GET(member, const char *)

OIDC_OAUTH_MEMBER_FUNCS_URL(metadata_url)
OIDC_OAUTH_MEMBER_FUNCS_STR(client_id)
OIDC_OAUTH_MEMBER_FUNCS_STR(client_secret)
OIDC_OAUTH_MEMBER_FUNCS_STR(introspection_endpoint_params)
OIDC_OAUTH_MEMBER_FUNCS_FILE(introspection_endpoint_tls_client_cert)
OIDC_OAUTH_MEMBER_FUNCS_FILE(introspection_endpoint_tls_client_key)
OIDC_OAUTH_MEMBER_FUNCS_PASSPHRASE(introspection_endpoint_tls_client_key_pwd)
OIDC_OAUTH_MEMBER_FUNCS_KEYS(verify_public_keys)
OIDC_OAUTH_MEMBER_FUNC_GET(introspection_client_auth_bearer_token, const char *)
OIDC_OAUTH_MEMBER_FUNC_GET(introspection_token_expiry_claim_format,
			   oidc_oauth_introspection_token_expiry_claim_format_t)
OIDC_OAUTH_MEMBER_FUNC_GET(introspection_token_expiry_claim_required,
			   oidc_oauth_introspection_token_expiry_claim_required_t)
OIDC_OAUTH_MEMBER_FUNC_GET(verify_shared_keys, apr_hash_t *)

#define OIDC_DEFAULT_OAUTH_SSL_VALIDATE_SERVER 1
OIDC_OAUTH_MEMBER_FUNCS_BOOL(ssl_validate_server, OIDC_DEFAULT_OAUTH_SSL_VALIDATE_SERVER)

#define OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME OIDC_PROTO_EXPIRES_IN
OIDC_OAUTH_MEMBER_FUNC_STR_GET_DEF(introspection_token_expiry_claim_name, OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME)

#define OIDC_OAUTH_MEMBER_FUNCS_STR_VALID(member, valid, def_val)                                                      \
	const char *oidc_cfg_oauth_##member##_set(apr_pool_t *pool, oidc_cfg_t *cfg, const char *arg) {                \
		const char *rv = valid;                                                                                \
		if (rv == NULL)                                                                                        \
			cfg->oauth->member = apr_pstrdup(pool, arg);                                                   \
		return rv;                                                                                             \
	}                                                                                                              \
	const char *oidc_cmd_oauth_##member##_set(cmd_parms *cmd, void *ptr, const char *arg) {                        \
		oidc_cfg_t *cfg =                                                                                      \
		    (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);              \
		const char *rv = oidc_cfg_oauth_##member##_set(cmd->pool, cfg, arg);                                   \
		return OIDC_CONFIG_DIR_RV(cmd, rv);                                                                    \
	}                                                                                                              \
	OIDC_OAUTH_MEMBER_FUNC_STR_GET_DEF(member, def_val)

OIDC_OAUTH_MEMBER_FUNCS_STR_VALID(introspection_endpoint_url, oidc_cfg_parse_is_valid_http_url(pool, arg), NULL)
OIDC_OAUTH_MEMBER_FUNCS_STR_VALID(verify_jwks_uri, oidc_cfg_parse_is_valid_http_url(pool, arg), NULL)

#define OIDC_DEFAULT_OAUTH_TOKEN_PARAM_NAME "token"
OIDC_OAUTH_MEMBER_FUNCS_STR_VALID(introspection_token_param_name, NULL, OIDC_DEFAULT_OAUTH_TOKEN_PARAM_NAME)

const char *oidc_cfg_oauth_introspection_endpoint_auth_set(apr_pool_t *pool, oidc_cfg_t *cfg, const char *arg) {
	return oidc_cfg_endpoint_auth_set(pool, cfg, arg, &cfg->oauth->introspection_endpoint_auth,
					  &cfg->oauth->introspection_endpoint_auth_alg);
}

const char *oidc_cmd_oauth_introspection_endpoint_auth_set(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_oauth_introspection_endpoint_auth_set(cmd->pool, cfg, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

const char *oidc_cfg_oauth_introspection_endpoint_auth_get(oidc_cfg_t *cfg) {
	return cfg->oauth->introspection_endpoint_auth;
}

const char *oidc_cfg_oauth_introspection_endpoint_auth_alg_get(oidc_cfg_t *cfg) {
	return cfg->oauth->introspection_endpoint_auth_alg;
}

oidc_remote_user_claim_t *oidc_cfg_oauth_remote_user_claim_get(oidc_cfg_t *cfg) {
	return &cfg->oauth->remote_user_claim;
}

#define OIDC_DEFAULT_OAUTH_CLAIM_REMOTE_USER "sub"

const char *oidc_cfg_oauth_remote_user_claim_name_get(oidc_cfg_t *cfg) {
	return cfg->oauth->remote_user_claim.claim_name != NULL ? cfg->oauth->remote_user_claim.claim_name
								: OIDC_DEFAULT_OAUTH_CLAIM_REMOTE_USER;
}

const char *oidc_cmd_oauth_remote_user_claim_set(cmd_parms *cmd, void *ptr, const char *v1, const char *v2,
						 const char *v3) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_remote_user_claim(cmd->pool, v1, v2, v3, &cfg->oauth->remote_user_claim);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

#define OIDC_INTROSPECTION_METHOD_GET_STR "GET"
#define OIDC_INTROSPECTION_METHOD_POST_STR "POST"

static const char *oidc_parse_introspection_endpoint_method(apr_pool_t *pool, const char *arg, int *v) {
	static const oidc_cfg_option_t options[] = {
	    {OIDC_INTROSPECTION_METHOD_GET, OIDC_INTROSPECTION_METHOD_GET_STR},
	    {OIDC_INTROSPECTION_METHOD_POST, OIDC_INTROSPECTION_METHOD_POST_STR},
	};
	return oidc_cfg_parse_option(pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg, v);
}

#define OIDC_DEFAULT_OAUTH_ENDPOINT_METHOD OIDC_INTROSPECTION_METHOD_POST

OIDC_OAUTH_MEMBER_FUNCS_INT(introspection_endpoint_method, oidc_parse_introspection_endpoint_method(cmd->pool, arg, &v),
			    oidc_oauth_introspection_endpoint_method_t, OIDC_DEFAULT_OAUTH_ENDPOINT_METHOD)

/*
 * set the introspection authorization static bearer token
 */
const char *oidc_cmd_oauth_introspection_client_auth_bearer_token_set(cmd_parms *cmd, void *struct_ptr,
								      const char *args) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	char *w = ap_getword_conf(cmd->pool, &args);
	cfg->oauth->introspection_client_auth_bearer_token = (*w == '\0' || *args != 0) ? "" : w;
	return NULL;
}

#define OIDC_CLAIM_FORMAT_RELATIVE_STR "relative"
#define OIDC_CLAIM_FORMAT_ABSOLUTE_STR "absolute"

#define OIDC_CLAIM_REQUIRED_MANDATORY_STR "mandatory"
#define OIDC_CLAIM_REQUIRED_OPTIONAL_STR "optional"

/*
 * set the syntax of the token expiry claim in the introspection response
 */
const char *oidc_cmd_oauth_token_expiry_claim_set(cmd_parms *cmd, void *dummy, const char *claim_name,
						  const char *claim_format, const char *claim_required) {
	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);
	static const oidc_cfg_option_t claim_format_options[] = {
	    {OIDC_TOKEN_EXPIRY_CLAIM_FORMAT_RELATIVE, OIDC_CLAIM_FORMAT_RELATIVE_STR},
	    {OIDC_TOKEN_EXPIRY_CLAIM_FORMAT_ABSOLUTE, OIDC_CLAIM_FORMAT_ABSOLUTE_STR}};
	static const oidc_cfg_option_t claim_required_options[] = {
	    {OIDC_TOKEN_EXPIRY_CLAIM_REQUIRED_MANDATORY, OIDC_CLAIM_REQUIRED_MANDATORY_STR},
	    {OIDC_TOKEN_EXPIRY_CLAIM_REQUIRED_OPTIONAL, OIDC_CLAIM_REQUIRED_OPTIONAL_STR}};

	const char *rv = NULL;

	cfg->oauth->introspection_token_expiry_claim_name = apr_pstrdup(cmd->pool, claim_name);

	if ((rv == NULL) && (claim_format != NULL))
		rv = oidc_cfg_parse_option(cmd->pool, claim_format_options, OIDC_CFG_OPTIONS_SIZE(claim_format_options),
					   claim_format, (int *)&cfg->oauth->introspection_token_expiry_claim_format);

	if ((rv == NULL) && (claim_required != NULL))
		rv = oidc_cfg_parse_option(cmd->pool, claim_required_options,
					   OIDC_CFG_OPTIONS_SIZE(claim_required_options), claim_required,
					   (int *)&cfg->oauth->introspection_token_expiry_claim_required);

	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * add a shared key to a list of JWKs with shared keys
 */
const char *oidc_cmd_oauth_verify_shared_keys_set(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	char *use = NULL;

	oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(cmd->server->module_config, &auth_openidc_module);

	char *kid = NULL, *secret = NULL;
	int key_len = 0;
	const char *rv = oidc_cfg_parse_key_record(cmd->pool, arg, &kid, &secret, &key_len, &use, TRUE);
	if (rv != NULL)
		return rv;

	jwk = oidc_jwk_create_symmetric_key(cmd->pool, kid, (const unsigned char *)secret, key_len, TRUE, &err);
	if (jwk == NULL) {
		return apr_psprintf(cmd->pool, "oidc_jwk_create_symmetric_key failed for (kid=%s) \"%s\": %s", kid,
				    secret, oidc_jose_e2s(cmd->pool, err));
	}

	if (cfg->oauth->verify_shared_keys == NULL)
		cfg->oauth->verify_shared_keys = apr_hash_make(cmd->pool);
	if (use)
		jwk->use = apr_pstrdup(cmd->pool, use);
	apr_hash_set(cfg->oauth->verify_shared_keys, jwk->kid, APR_HASH_KEY_STRING, jwk);

	return NULL;
}

/* default OAuth 2.0 non-spec compliant introspection expiry claim format */
#define OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT OIDC_CLAIM_FORMAT_RELATIVE_STR
/* default OAuth 2.0 non-spec compliant introspection expiry claim required */
#define OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED TRUE

oidc_oauth_t *oidc_cfg_oauth_create(apr_pool_t *pool) {
	oidc_oauth_t *o = apr_pcalloc(pool, sizeof(oidc_oauth_t));
	o->ssl_validate_server = OIDC_CONFIG_POS_INT_UNSET;
	o->metadata_url = NULL;
	o->client_id = NULL;
	o->client_secret = NULL;
	o->introspection_endpoint_tls_client_cert = NULL;
	o->introspection_endpoint_tls_client_key = NULL;
	o->introspection_endpoint_url = NULL;
	o->introspection_endpoint_method = OIDC_CONFIG_POS_INT_UNSET;
	o->introspection_endpoint_params = NULL;
	o->introspection_endpoint_auth = NULL;
	o->introspection_endpoint_auth_alg = NULL;
	o->introspection_client_auth_bearer_token = NULL;
	o->introspection_token_param_name = NULL;
	o->introspection_token_expiry_claim_name = NULL;
	o->introspection_token_expiry_claim_format = OIDC_TOKEN_EXPIRY_CLAIM_FORMAT_RELATIVE;
	o->introspection_token_expiry_claim_required = OIDC_TOKEN_EXPIRY_CLAIM_REQUIRED_MANDATORY;
	o->remote_user_claim.claim_name = NULL;
	o->remote_user_claim.reg_exp = NULL;
	o->remote_user_claim.replace = NULL;
	o->verify_jwks_uri = NULL;
	o->verify_public_keys = NULL;
	o->verify_shared_keys = NULL;
	return o;
}

void oidc_cfg_oauth_merge(apr_pool_t *pool, oidc_oauth_t *dst, const oidc_oauth_t *base, const oidc_oauth_t *add) {
	dst->ssl_validate_server = add->ssl_validate_server != OIDC_CONFIG_POS_INT_UNSET ? add->ssl_validate_server
											 : base->ssl_validate_server;
	dst->metadata_url = add->metadata_url != NULL ? add->metadata_url : base->metadata_url;
	dst->client_id = add->client_id != NULL ? add->client_id : base->client_id;
	dst->client_secret = add->client_secret != NULL ? add->client_secret : base->client_secret;

	dst->introspection_endpoint_tls_client_key = add->introspection_endpoint_tls_client_key != NULL
							 ? add->introspection_endpoint_tls_client_key
							 : base->introspection_endpoint_tls_client_key;
	dst->introspection_endpoint_tls_client_cert = add->introspection_endpoint_tls_client_cert != NULL
							  ? add->introspection_endpoint_tls_client_cert
							  : base->introspection_endpoint_tls_client_cert;

	dst->introspection_endpoint_url = add->introspection_endpoint_url != NULL ? add->introspection_endpoint_url
										  : base->introspection_endpoint_url;
	dst->introspection_endpoint_method = add->introspection_endpoint_method != OIDC_CONFIG_POS_INT_UNSET
						 ? add->introspection_endpoint_method
						 : base->introspection_endpoint_method;
	dst->introspection_endpoint_params = add->introspection_endpoint_params != NULL
						 ? add->introspection_endpoint_params
						 : base->introspection_endpoint_params;
	dst->introspection_endpoint_auth = add->introspection_endpoint_auth != NULL ? add->introspection_endpoint_auth
										    : base->introspection_endpoint_auth;
	dst->introspection_endpoint_auth_alg = add->introspection_endpoint_auth_alg != NULL
						   ? add->introspection_endpoint_auth_alg
						   : base->introspection_endpoint_auth_alg;
	dst->introspection_client_auth_bearer_token = add->introspection_client_auth_bearer_token != NULL
							  ? add->introspection_client_auth_bearer_token
							  : base->introspection_client_auth_bearer_token;
	dst->introspection_token_param_name = add->introspection_token_param_name != NULL
						  ? add->introspection_token_param_name
						  : base->introspection_token_param_name;

	if (add->introspection_token_expiry_claim_name != NULL) {
		dst->introspection_token_expiry_claim_name = add->introspection_token_expiry_claim_name;
		dst->introspection_token_expiry_claim_format = add->introspection_token_expiry_claim_format;
		dst->introspection_token_expiry_claim_required = add->introspection_token_expiry_claim_required;
	} else {
		dst->introspection_token_expiry_claim_name = base->introspection_token_expiry_claim_name;
		dst->introspection_token_expiry_claim_format = base->introspection_token_expiry_claim_format;
		dst->introspection_token_expiry_claim_required = base->introspection_token_expiry_claim_required;
	}

	if (add->remote_user_claim.claim_name != NULL) {
		dst->remote_user_claim.claim_name = add->remote_user_claim.claim_name;
		dst->remote_user_claim.reg_exp = add->remote_user_claim.reg_exp;
		dst->remote_user_claim.replace = add->remote_user_claim.replace;
	} else {
		dst->remote_user_claim.claim_name = base->remote_user_claim.claim_name;
		dst->remote_user_claim.reg_exp = base->remote_user_claim.reg_exp;
		dst->remote_user_claim.replace = base->remote_user_claim.replace;
	}

	dst->verify_jwks_uri = add->verify_jwks_uri != NULL ? add->verify_jwks_uri : base->verify_jwks_uri;
	dst->verify_public_keys = oidc_jwk_list_copy(pool, add->verify_public_keys != NULL ? add->verify_public_keys
											   : base->verify_public_keys);
	dst->verify_shared_keys = add->verify_shared_keys != NULL ? add->verify_shared_keys : base->verify_shared_keys;
}

void oidc_cfg_oauth_destroy(oidc_oauth_t *o) {
	if (o == NULL)
		return;
	oidc_jwk_list_destroy(o->verify_public_keys);
	o->verify_public_keys = NULL;
	oidc_jwk_list_destroy_hash(o->verify_shared_keys);
	o->verify_shared_keys = NULL;
}
