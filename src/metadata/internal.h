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
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#ifndef _MOD_AUTH_OPENIDC_METADATA_INTERNAL_H_
#define _MOD_AUTH_OPENIDC_METADATA_INTERNAL_H_

#include "cfg/cfg.h"
#include "cfg/parse.h"
#include "cfg/provider.h"
#include "jose.h"
#include "metadata.h"

#include "json.h"

/* metadata file suffixes */
#define OIDC_METADATA_SUFFIX_PROVIDER "provider"
#define OIDC_METADATA_SUFFIX_CLIENT "client"
#define OIDC_METADATA_SUFFIX_CONF "conf"

/* provider metadata keys */
#define OIDC_METADATA_ISSUER "issuer"
#define OIDC_METADATA_RESPONSE_TYPES_SUPPORTED "response_types_supported"
#define OIDC_METADATA_RESPONSE_MODES_SUPPORTED "response_modes_supported"
#define OIDC_METADATA_AUTHORIZATION_ENDPOINT "authorization_endpoint"
#define OIDC_METADATA_TOKEN_ENDPOINT "token_endpoint"
#define OIDC_METADATA_INTROSPECTION_ENDPOINT "introspection_endpoint"
#define OIDC_METADATA_USERINFO_ENDPOINT "userinfo_endpoint"
#define OIDC_METADATA_REVOCATION_ENDPOINT "revocation_endpoint"
#define OIDC_METADATA_PAR_ENDPOINT "pushed_authorization_request_endpoint"
#define OIDC_METADATA_JWKS_URI "jwks_uri"
#define OIDC_METADATA_SIGNED_JWKS_URI "signed_jwks_uri"
#define OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED "token_endpoint_auth_methods_supported"
#define OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED "introspection_endpoint_auth_methods_supported"
#define OIDC_METADATA_REGISTRATION_ENDPOINT "registration_endpoint"
#define OIDC_METADATA_CHECK_SESSION_IFRAME "check_session_iframe"
#define OIDC_METADATA_BACKCHANNEL_LOGOUT_SUPPORTED "backchannel_logout_supported"
#define OIDC_METADATA_END_SESSION_ENDPOINT "end_session_endpoint"

/* client metadata keys */
#define OIDC_METADATA_CLIENT_ID "client_id"
#define OIDC_METADATA_CLIENT_SECRET "client_secret"
#define OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT "client_secret_expires_at"
#define OIDC_METADATA_CLIENT_NAME "client_name"
#define OIDC_METADATA_REDIRECT_URIS "redirect_uris"
#define OIDC_METADATA_RESPONSE_TYPES "response_types"
#define OIDC_METADATA_GRANT_TYPES "grant_types"
#define OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHOD "token_endpoint_auth_method"
#define OIDC_METADATA_CONTACTS "contacts"
#define OIDC_METADATA_INITIATE_LOGIN_URI "initiate_login_uri"
#define OIDC_METADATA_FRONTCHANNEL_LOGOUT_URI "frontchannel_logout_uri"
#define OIDC_METADATA_BACKCHANNEL_LOGOUT_URI "backchannel_logout_uri"
#define OIDC_METADATA_POST_LOGOUT_REDIRECT_URIS "post_logout_redirect_uris"

#define OIDC_METADATA_KEYS OIDC_JOSE_JWKS_KEYS_STR

/* conf file keys */
#define OIDC_METADATA_CLIENT_JWKS_URI "client_jwks_uri"
#define OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG "id_token_signed_response_alg"
#define OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG "id_token_encrypted_response_alg"
#define OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC "id_token_encrypted_response_enc"
#define OIDC_METADATA_ID_TOKEN_AUD_VALUES "id_token_aud_values"
#define OIDC_METADATA_PROFILE "profile"
#define OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG "userinfo_signed_response_alg"
#define OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG "userinfo_encrypted_response_alg"
#define OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC "userinfo_encrypted_response_enc"
#define OIDC_METADATA_SSL_VALIDATE_SERVER "ssl_validate_server"
#define OIDC_METADATA_VALIDATE_ISSUER "validate_issuer"
#define OIDC_METADATA_SCOPE "scope"
#define OIDC_METADATA_JWKS_REFRESH_INTERVAL "jwks_refresh_interval"
#define OIDC_METADATA_IDTOKEN_IAT_SLACK "idtoken_iat_slack"
#define OIDC_METADATA_SESSION_MAX_DURATION "session_max_duration"
#define OIDC_METADATA_AUTH_REQUEST_PARAMS "auth_request_params"
#define OIDC_METADATA_LOGOUT_REQUEST_PARAMS "logout_request_params"
#define OIDC_METADATA_TOKEN_ENDPOINT_PARAMS "token_endpoint_params"
#define OIDC_METADATA_RESPONSE_MODE "response_mode"
#define OIDC_METADATA_PKCE_METHOD "pkce_method"
#define OIDC_METADATA_DPOP_MODE "dpop_mode"
#define OIDC_METADATA_CLIENT_CONTACT "client_contact"
#define OIDC_METADATA_TOKEN_ENDPOINT_AUTH "token_endpoint_auth"
#define OIDC_METADATA_REGISTRATION_TOKEN "registration_token"
#define OIDC_METADATA_REGISTRATION_ENDPOINT_JSON "registration_endpoint_json"
#define OIDC_METADATA_RESPONSE_TYPE "response_type"
#define OIDC_METADATA_USERINFO_REFRESH_INTERVAL "userinfo_refresh_interval"
#define OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_CERT "token_endpoint_tls_client_cert"
#define OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_KEY "token_endpoint_tls_client_key"
#define OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_KEY_PWD "token_endpoint_tls_client_key_pwd"
#define OIDC_METADATA_REQUEST_OBJECT "request_object"
#define OIDC_METADATA_USERINFO_TOKEN_METHOD "userinfo_token_method"
#define OIDC_METADATA_AUTH_REQUEST_METHOD "auth_request_method"
#define OIDC_METADATA_RESPONSE_REQUIRE_ISS "response_require_iss"

/*
 * conditional setter macros — assume `r`, `provider`, `rv` are in scope
 */
#define OIDC_METADATA_PROVIDER_SET(member, value, rv)                                                                  \
	if (value != NULL) {                                                                                           \
		rv = oidc_cfg_provider_##member##_set(r->pool, provider, value);                                       \
		if (rv != NULL)                                                                                        \
			oidc_error(r, "oidc_cfg_provider_%s_set: %s", TOSTRING(member), rv);                           \
	}

#define OIDC_METADATA_PROVIDER_SET_INT(provider, member, ivalue, rv)                                                   \
	if (ivalue != OIDC_CONFIG_POS_INT_UNSET) {                                                                     \
		rv = oidc_cfg_provider_##member##_set(r->pool, provider, ivalue);                                      \
		if (rv != NULL)                                                                                        \
			oidc_error(r, "oidc_cfg_provider_%s_set: %s", TOSTRING(member), rv);                           \
	}

/*
 * conf-parse helpers — read a single key from `j_conf`, default to the global
 * provider config, and apply it via the typed setter. Assume `r`, `cfg`,
 * `provider` are in scope.
 */
#define OIDC_METADATA_CONF_STR(j_conf, key, member)                                                                    \
	do {                                                                                                           \
		char *_v_ = NULL;                                                                                      \
		oidc_json_object_get_string(r->pool, j_conf, key, &_v_,                                                \
					    oidc_cfg_provider_##member##_get(oidc_cfg_provider_get(cfg)));             \
		if (_v_ != NULL) {                                                                                     \
			const char *_rv_ = oidc_cfg_provider_##member##_set(r->pool, provider, _v_);                   \
			if (_rv_ != NULL)                                                                              \
				oidc_error(r, "oidc_cfg_provider_%s_set: %s", #member, _rv_);                          \
		}                                                                                                      \
	} while (0)

#define OIDC_METADATA_CONF_INT(j_conf, key, member)                                                                    \
	do {                                                                                                           \
		int _v_ = OIDC_CONFIG_POS_INT_UNSET;                                                                   \
		oidc_json_object_get_int(j_conf, key, &_v_,                                                            \
					 oidc_cfg_provider_##member##_get(oidc_cfg_provider_get(cfg)));                \
		if (_v_ != OIDC_CONFIG_POS_INT_UNSET) {                                                                \
			const char *_rv_ = oidc_cfg_provider_##member##_set(r->pool, provider, _v_);                   \
			if (_rv_ != NULL)                                                                              \
				oidc_error(r, "oidc_cfg_provider_%s_set: %s", #member, _rv_);                          \
		}                                                                                                      \
	} while (0)

#define OIDC_METADATA_CONF_BOOL(j_conf, key, member)                                                                   \
	do {                                                                                                           \
		int _v_ = OIDC_CONFIG_POS_INT_UNSET;                                                                   \
		oidc_metadata_parse_boolean(r, j_conf, key, &_v_,                                                      \
					    oidc_cfg_provider_##member##_get(oidc_cfg_provider_get(cfg)));             \
		const char *_rv_ = oidc_cfg_provider_##member##_set(r->pool, provider, _v_);                           \
		if (_rv_ != NULL)                                                                                      \
			oidc_error(r, "oidc_cfg_provider_%s_set: %s", #member, _rv_);                                  \
	} while (0)

/*
 * shared internal helpers (see src/metadata/util.c)
 */
apr_byte_t oidc_metadata_is_valid_uri(request_rec *r, const char *type, const char *issuer, const oidc_json_t *json,
				      const char *key, char **value, apr_byte_t is_mandatory);
const char *oidc_metadata_valid_string_in_array(apr_pool_t *pool, const oidc_json_t *json, const char *key,
						oidc_valid_function_t valid_function, char **value, apr_byte_t optional,
						const char *preference);
void oidc_metadata_parse_boolean(request_rec *r, const oidc_json_t *json, const char *key, int *value,
				 int default_value);
void oidc_metadata_parse_url(request_rec *r, const char *type, const char *issuer, const oidc_json_t *json,
			     const char *key, char **value, const char *default_value);
void oidc_metadata_get_jwks(request_rec *r, const oidc_json_t *json, apr_array_header_t **jwk_list);
apr_byte_t oidc_metadata_file_read_json(request_rec *r, const char *path, oidc_json_t **result);

/* path/filename helpers */
const char *oidc_metadata_issuer_to_filename(request_rec *r, const char *issuer);
const char *oidc_metadata_filename_to_issuer(request_rec *r, const char *filename);
const char *oidc_metadata_provider_file_path(request_rec *r, const char *issuer);
const char *oidc_metadata_client_file_path(request_rec *r, const char *issuer);
const char *oidc_metadata_conf_path(request_rec *r, const char *issuer);

/*
 * cross-domain entry points used only by the metadata.c orchestrator
 */
apr_byte_t oidc_metadata_conf_get(request_rec *r, const char *issuer, oidc_json_t **j_conf);
apr_byte_t oidc_metadata_client_get(request_rec *r, oidc_cfg_t *cfg, const char *issuer,
				    const oidc_provider_t *provider, oidc_json_t **j_client);
apr_byte_t oidc_metadata_client_register(request_rec *r, oidc_cfg_t *cfg, const oidc_provider_t *provider,
					 oidc_json_t **j_client, char **response);

#endif /* _MOD_AUTH_OPENIDC_METADATA_INTERNAL_H_ */
