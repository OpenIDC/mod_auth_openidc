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
 * Per-issuer .conf overrides — read from disk, validate JOSE algorithms,
 * and apply each section onto a partially-built oidc_provider_t.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "metadata/internal.h"

#include "cfg/parse.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

#include <apr_file_io.h>

/*
 * check is a specified JOSE feature is supported
 */
static apr_byte_t oidc_metadata_conf_jose_is_supported(request_rec *r, const json_t *j_conf, const char *issuer,
						       const char *key, oidc_valid_function_t valid_function) {
	char *s_value = NULL;
	oidc_util_json_object_get_string(r->pool, j_conf, key, &s_value, NULL);
	if (s_value == NULL)
		return TRUE;
	const char *rv = valid_function(r->pool, s_value);
	if (rv != NULL) {
		oidc_error(r,
			   "(%s) JSON conf data has \"%s\" entry but it contains an unsupported algorithm or "
			   "encryption type: \"%s\" (%s)",
			   issuer, key, s_value, rv);
		return FALSE;
	}
	return TRUE;
}

/*
 * check to see if JSON configuration data is valid
 */
static apr_byte_t oidc_metadata_conf_is_valid(request_rec *r, json_t *j_conf, const char *issuer) {

	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer, OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG,
						 oidc_cfg_parse_is_valid_signed_response_alg) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG,
						 oidc_cfg_parse_is_valid_encrypted_response_alg) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC,
						 oidc_cfg_parse_is_valid_encrypted_response_enc) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer, OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG,
						 oidc_cfg_parse_is_valid_signed_response_alg) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG,
						 oidc_cfg_parse_is_valid_encrypted_response_alg) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC,
						 oidc_cfg_parse_is_valid_encrypted_response_enc) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * see if we have config metadata
 */
apr_byte_t oidc_metadata_conf_get(request_rec *r, const char *issuer, json_t **j_conf) {

	/* get the full file path to the conf metadata for this issuer */
	const char *conf_path = oidc_metadata_conf_path(r, issuer);

	/* the .conf file is optional */
	apr_finfo_t fi;
	if (apr_stat(&fi, conf_path, APR_FINFO_MTIME, r->pool) != APR_SUCCESS)
		return TRUE;

	/* see if we have valid metadata already, if so, return it */
	if (oidc_metadata_file_read_json(r, conf_path, j_conf) == TRUE) {

		/* return the validation result */
		return oidc_metadata_conf_is_valid(r, *j_conf, issuer);
	}

	return FALSE;
}

/*
 * apply the conf profile; must run first so it can override potentially non-conformant / insecure settings
 */
static void oidc_metadata_conf_parse_profile(request_rec *r, oidc_cfg_t *cfg, const json_t *j_conf,
					     oidc_provider_t *provider) {
	const char *rv = NULL;
	char *value = NULL;

	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_PROFILE, &value, NULL);
	if (value) {
		rv = oidc_cfg_provider_profile_set(r->pool, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_profile_set: %s", rv);
	} else {
		oidc_cfg_provider_profile_int_set(provider, oidc_cfg_provider_profile_get(oidc_cfg_provider_get(cfg)));
	}
}

/*
 * apply the client JWKS settings: jwks_uri, inline keys and signed-jwks-uri verification keys
 */
static void oidc_metadata_conf_parse_keys(request_rec *r, oidc_cfg_t *cfg, const json_t *j_conf,
					  oidc_provider_t *provider) {
	const char *rv = NULL;
	apr_array_header_t *keys = NULL;

	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_CLIENT_JWKS_URI, client_jwks_uri);

	oidc_metadata_get_jwks(r, j_conf, &keys);
	if (keys != NULL) {
		rv = oidc_cfg_provider_client_keys_set_keys(r->pool, provider, keys);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_client_keys_set: %s", rv);
	}

	rv = oidc_cfg_provider_signed_jwks_uri_keys_set(
	    r->pool, provider, json_object_get(j_conf, "signed_jwks_uri_key"),
	    oidc_cfg_provider_signed_jwks_uri_keys_get(oidc_cfg_provider_get(cfg)));
	if (rv != NULL)
		oidc_error(r, "oidc_cfg_provider_signed_jwks_uri_keys_set: %s", rv);
}

/*
 * apply the id_token signing & encryption settings and the audience override
 */
static void oidc_metadata_conf_parse_id_token(request_rec *r, oidc_cfg_t *cfg, const json_t *j_conf,
					      oidc_provider_t *provider) {
	const char *rv = NULL;
	apr_array_header_t *auds = NULL;

	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG, id_token_signed_response_alg);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG, id_token_encrypted_response_alg);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC, id_token_encrypted_response_enc);

	oidc_util_json_object_get_string_array(
	    r->pool, j_conf, OIDC_METADATA_ID_TOKEN_AUD_VALUES, &auds,
	    oidc_proto_profile_id_token_aud_values_get(r->pool, oidc_cfg_provider_get(cfg)));
	if (auds != NULL) {
		rv = oidc_cfg_provider_id_token_aud_values_set_str_list(r->pool, provider, auds);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_aud_values_set: %s", rv);
	}
}

/*
 * apply the userinfo signing & encryption settings, refresh interval and token presentation method
 */
static void oidc_metadata_conf_parse_userinfo(request_rec *r, oidc_cfg_t *cfg, const json_t *j_conf,
					      oidc_provider_t *provider) {
	const char *rv = NULL;
	char *value = NULL;

	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG, userinfo_signed_response_alg);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG, userinfo_encrypted_response_alg);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC, userinfo_encrypted_response_enc);
	OIDC_METADATA_CONF_INT(j_conf, OIDC_METADATA_USERINFO_REFRESH_INTERVAL, userinfo_refresh_interval);

	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_USERINFO_TOKEN_METHOD, &value, NULL);
	if (value) {
		rv = oidc_cfg_provider_userinfo_token_method_set(r->pool, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_userinfo_token_method_set: %s", rv);
	} else {
		oidc_cfg_provider_userinfo_token_method_int_set(
		    provider, oidc_cfg_provider_userinfo_token_method_get(oidc_cfg_provider_get(cfg)));
	}
}

/*
 * apply SSL/issuer validation flags and session-related interval overrides
 */
static void oidc_metadata_conf_parse_session(request_rec *r, oidc_cfg_t *cfg, json_t *j_conf,
					     oidc_provider_t *provider) {
	OIDC_METADATA_CONF_BOOL(j_conf, OIDC_METADATA_SSL_VALIDATE_SERVER, ssl_validate_server);
	OIDC_METADATA_CONF_BOOL(j_conf, OIDC_METADATA_VALIDATE_ISSUER, validate_issuer);
	OIDC_METADATA_CONF_INT(j_conf, OIDC_METADATA_JWKS_REFRESH_INTERVAL, jwks_uri_refresh_interval);
	OIDC_METADATA_CONF_INT(j_conf, OIDC_METADATA_IDTOKEN_IAT_SLACK, idtoken_iat_slack);
	OIDC_METADATA_CONF_INT(j_conf, OIDC_METADATA_SESSION_MAX_DURATION, session_max_duration);
}

/*
 * apply the scope, the various request-parameter overrides and the request_object setting
 */
static void oidc_metadata_conf_parse_request_params(request_rec *r, oidc_cfg_t *cfg, const json_t *j_conf,
						    oidc_provider_t *provider) {
	// TODO: use the provider "scopes_supported" to mix-and-match with what we've configured for the client
	// TODO: check that "openid" is always included in the configured scopes, right?
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_SCOPE, scope);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_AUTH_REQUEST_PARAMS, auth_request_params);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_LOGOUT_REQUEST_PARAMS, logout_request_params);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_TOKEN_ENDPOINT_PARAMS, token_endpoint_params);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_REQUEST_OBJECT, request_object);
}

/*
 * apply the response/PKCE settings
 */
static void oidc_metadata_conf_parse_response(request_rec *r, oidc_cfg_t *cfg, json_t *j_conf,
					      oidc_provider_t *provider) {
	const char *rv = NULL;
	char *value = NULL;
	int ivalue = OIDC_CONFIG_POS_INT_UNSET;

	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_RESPONSE_MODE, response_mode);

	/* pkce default uses the proto-profile default, not the global config */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_PKCE_METHOD, &value,
					 oidc_proto_profile_pkce_get(provider)->method);
	OIDC_METADATA_PROVIDER_SET(pkce, value, rv)

	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_RESPONSE_TYPE, response_type);

	oidc_metadata_parse_boolean(r, j_conf, OIDC_METADATA_RESPONSE_REQUIRE_ISS, &ivalue,
				    oidc_proto_profile_response_require_iss_get(provider));
	OIDC_METADATA_PROVIDER_SET_INT(provider, response_require_iss, ivalue, rv)
}

/*
 * apply the client name/contact and dynamic registration metadata overrides
 */
static void oidc_metadata_conf_parse_client(request_rec *r, oidc_cfg_t *cfg, const json_t *j_conf,
					    oidc_provider_t *provider) {
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_CLIENT_NAME, client_name);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_CLIENT_CONTACT, client_contact);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_REGISTRATION_TOKEN, registration_token);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_REGISTRATION_ENDPOINT_JSON, registration_endpoint_json);
}

/*
 * apply the token endpoint authentication method
 */
static void oidc_metadata_conf_parse_endpoint_auth(request_rec *r, oidc_cfg_t *cfg, const json_t *j_conf,
						   oidc_provider_t *provider) {
	const char *rv = NULL;
	char *value = NULL;

	// TODO: token_endpoint_auth_alg inheritance from global setting does not work now
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_TOKEN_ENDPOINT_AUTH, &value,
					 oidc_cfg_provider_token_endpoint_auth_get(oidc_cfg_provider_get(cfg)));
	if (value != NULL) {
		rv = oidc_cfg_provider_token_endpoint_auth_set(r->pool, cfg, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_token_endpoint_auth_set: %s", rv);
	}
}

/*
 * apply the TLS client certificate auth settings for the token endpoint
 */
static void oidc_metadata_conf_parse_tls_client(request_rec *r, oidc_cfg_t *cfg, const json_t *j_conf,
						oidc_provider_t *provider) {
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_CERT, token_endpoint_tls_client_cert);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_KEY, token_endpoint_tls_client_key);
	OIDC_METADATA_CONF_STR(j_conf, OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_KEY_PWD,
			       token_endpoint_tls_client_key_pwd);
}

/*
 * apply the DPoP mode
 */
static void oidc_metadata_conf_parse_dpop_mode(request_rec *r, const json_t *j_conf, oidc_provider_t *provider) {
	const char *rv = NULL;
	char *value = NULL;

	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_DPOP_MODE, &value, NULL);
	if (value) {
		rv = oidc_cfg_provider_dpop_mode_set(r->pool, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_dpop_mode_set: %s", rv);
	} else {
		oidc_cfg_provider_dpop_mode_int_set(provider, oidc_proto_profile_dpop_mode_get(provider));
	}
}

/*
 * apply the HTTP method used to deliver the authentication request
 */
static void oidc_metadata_conf_parse_auth_request_method(request_rec *r, const json_t *j_conf,
							 oidc_provider_t *provider) {
	const char *rv = NULL;
	char *value = NULL;

	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_AUTH_REQUEST_METHOD, &value, NULL);
	if (value) {
		rv = oidc_cfg_provider_auth_request_method_set(r->pool, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_auth_request_method_set: %s", rv);
	} else {
		oidc_cfg_provider_auth_request_method_int_set(provider,
							      oidc_proto_profile_auth_request_method_get(provider));
	}
}

/*
 * parse the JSON conf metadata in to a oidc_provider_t struct
 */
apr_byte_t oidc_metadata_conf_parse(request_rec *r, oidc_cfg_t *cfg, json_t *j_conf, oidc_provider_t *provider) {
	oidc_metadata_conf_parse_profile(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_keys(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_id_token(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_userinfo(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_session(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_request_params(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_response(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_client(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_endpoint_auth(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_tls_client(r, cfg, j_conf, provider);
	oidc_metadata_conf_parse_dpop_mode(r, j_conf, provider);
	oidc_metadata_conf_parse_auth_request_method(r, j_conf, provider);
	return TRUE;
}
