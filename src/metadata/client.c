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
 * Client metadata: validation, parsing, on-disk read, and Dynamic Client
 * Registration with the OP.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "metadata/internal.h"

#include "cfg/dir.h"
#include "http.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

#include <apr_strings.h>

/*
 * check to see if dynamically registered JSON client metadata is valid and has not expired
 */
static apr_byte_t oidc_metadata_client_is_valid(request_rec *r, json_t *j_client, const char *issuer) {

	char *str;

	/* get a handle to the client_id we need to use for this provider */
	str = NULL;
	oidc_util_json_object_get_string(r->pool, j_client, OIDC_METADATA_CLIENT_ID, &str, NULL);
	if (str == NULL) {
		oidc_error(r, "client (%s) JSON metadata did not contain a \"" OIDC_METADATA_CLIENT_ID "\" string",
			   issuer);
		return FALSE;
	}

	/* get a handle to the client_secret we need to use for this provider */
	str = NULL;
	oidc_util_json_object_get_string(r->pool, j_client, OIDC_METADATA_CLIENT_SECRET, &str, NULL);
	if (str == NULL) {
		oidc_warn(r, "client (%s) JSON metadata did not contain a \"" OIDC_METADATA_CLIENT_SECRET "\" string",
			  issuer);
	}

	/* the expiry timestamp from the JSON object */
	json_t *expires_at = json_object_get(j_client, OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT);
	if ((expires_at == NULL) || (!json_is_integer(expires_at))) {
		oidc_debug(
		    r, "client (%s) metadata did not contain a \"" OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT "\" setting",
		    issuer);
		/* assume that it never expires */
		return TRUE;
	}

	/* see if it is unrestricted */
	if (json_integer_value(expires_at) == 0) {
		oidc_debug(r, "client (%s) metadata never expires (" OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT "=0)",
			   issuer);
		return TRUE;
	}

	/* check if the value >= now */
	if (apr_time_sec(apr_time_now()) > json_integer_value(expires_at)) {
		oidc_warn(r, "client (%s) secret expired", issuer);
		return FALSE;
	}

	oidc_debug(r, "client (%s) metadata is valid", issuer);

	return TRUE;
}

/*
 * register the client with the OP using Dynamic Client Registration
 */
apr_byte_t oidc_metadata_client_register(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider, json_t **j_client,
					 char **response) {

	/* assemble the JSON registration request */
	json_t *data = json_object();
	json_object_set_new(data, OIDC_METADATA_CLIENT_NAME, json_string(oidc_cfg_provider_client_name_get(provider)));
	json_object_set_new(data, OIDC_METADATA_REDIRECT_URIS, json_pack("[s]", oidc_util_url_redirect_uri(r, cfg)));

	json_t *response_types = json_array();
	apr_array_header_t *flows = oidc_proto_supported_flows(r->pool);
	int i = 0;
	for (i = 0; i < flows->nelts; i++)
		json_array_append_new(response_types, json_string(APR_ARRAY_IDX(flows, i, const char *)));
	json_object_set_new(data, OIDC_METADATA_RESPONSE_TYPES, response_types);

	json_object_set_new(data, OIDC_METADATA_GRANT_TYPES,
			    json_pack("[s, s, s]", "authorization_code", "implicit", "refresh_token"));

	if (oidc_cfg_provider_token_endpoint_auth_get(provider) != NULL) {
		json_object_set_new(data, OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHOD,
				    json_string(oidc_cfg_provider_token_endpoint_auth_get(provider)));
	}

	if (oidc_cfg_provider_client_contact_get(provider) != NULL) {
		json_object_set_new(data, OIDC_METADATA_CONTACTS,
				    json_pack("[s]", oidc_cfg_provider_client_contact_get(provider)));
	}

	if (oidc_cfg_provider_client_jwks_uri_get(provider)) {
		json_object_set_new(data, OIDC_METADATA_JWKS_URI,
				    json_string(oidc_cfg_provider_client_jwks_uri_get(provider)));
	} else if (oidc_cfg_public_keys_get(cfg) != NULL) {
		json_object_set_new(data, OIDC_METADATA_JWKS_URI,
				    json_string(apr_psprintf(r->pool, "%s?%s=rsa", oidc_util_url_redirect_uri(r, cfg),
							     OIDC_REDIRECT_URI_REQUEST_JWKS)));
	}

	if (oidc_cfg_provider_id_token_signed_response_alg_get(provider) != NULL) {
		json_object_set_new(data, OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG,
				    json_string(oidc_cfg_provider_id_token_signed_response_alg_get(provider)));
	}
	if (oidc_cfg_provider_id_token_encrypted_response_alg_get(provider) != NULL) {
		json_object_set_new(data, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG,
				    json_string(oidc_cfg_provider_id_token_encrypted_response_alg_get(provider)));
	}
	if (oidc_cfg_provider_id_token_encrypted_response_enc_get(provider) != NULL) {
		json_object_set_new(data, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC,
				    json_string(oidc_cfg_provider_id_token_encrypted_response_enc_get(provider)));
	}

	if (oidc_cfg_provider_userinfo_signed_response_alg_get(provider) != NULL) {
		json_object_set_new(data, OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG,
				    json_string(oidc_cfg_provider_userinfo_signed_response_alg_get(provider)));
	}
	if (oidc_cfg_provider_userinfo_encrypted_response_alg_get(provider) != NULL) {
		json_object_set_new(data, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG,
				    json_string(oidc_cfg_provider_userinfo_encrypted_response_alg_get(provider)));
	}
	if (oidc_cfg_provider_userinfo_encrypted_response_enc_get(provider) != NULL) {
		json_object_set_new(data, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC,
				    json_string(oidc_cfg_provider_userinfo_encrypted_response_enc_get(provider)));
	}

	if (oidc_cfg_provider_request_object_get(provider) != NULL) {
		json_t *request_object_config = NULL;
		if (oidc_util_json_decode_object(r, oidc_cfg_provider_request_object_get(provider),
						 &request_object_config) == TRUE) {
			json_t *crypto = json_object_get(request_object_config, "crypto");
			char *alg = "none";
			oidc_util_json_object_get_string(r->pool, crypto, "sign_alg", &alg, "none");
			json_object_set_new(data, "request_object_signing_alg", json_string(alg));
			json_decref(request_object_config);
		}
	}

	json_object_set_new(data, OIDC_METADATA_INITIATE_LOGIN_URI, json_string(oidc_util_url_redirect_uri(r, cfg)));

	json_object_set_new(
	    data, OIDC_METADATA_FRONTCHANNEL_LOGOUT_URI,
	    json_string(apr_psprintf(r->pool, "%s?%s=%s", oidc_util_url_redirect_uri(r, cfg),
				     OIDC_REDIRECT_URI_REQUEST_LOGOUT, OIDC_GET_STYLE_LOGOUT_PARAM_VALUE)));

	// TODO: may want to add backchannel_logout_session_required
	json_object_set_new(
	    data, OIDC_METADATA_BACKCHANNEL_LOGOUT_URI,
	    json_string(apr_psprintf(r->pool, "%s?%s=%s", oidc_util_url_redirect_uri(r, cfg),
				     OIDC_REDIRECT_URI_REQUEST_LOGOUT, OIDC_BACKCHANNEL_STYLE_LOGOUT_PARAM_VALUE)));

	if (oidc_cfg_default_slo_url_get(cfg) != NULL) {
		json_object_set_new(data, OIDC_METADATA_POST_LOGOUT_REDIRECT_URIS,
				    json_pack("[s]", oidc_util_url_abs(r, cfg, oidc_cfg_default_slo_url_get(cfg))));
	}

	/* add any custom JSON in to the registration request */
	if (oidc_cfg_provider_registration_endpoint_json_get(provider) != NULL) {
		json_t *json = NULL;
		if (oidc_util_json_decode_object(r, oidc_cfg_provider_registration_endpoint_json_get(provider),
						 &json) == FALSE)
			return FALSE;
		oidc_util_json_merge(r, json, data);
		json_decref(json);
	}

	/* dynamically register the client with the specified parameters */
	if (oidc_http_post_json(r, oidc_cfg_provider_registration_endpoint_url_get(provider), data, NULL,
				oidc_cfg_provider_registration_token_get(provider), NULL,
				oidc_cfg_provider_ssl_validate_server_get(provider), response, NULL, NULL,
				oidc_cfg_http_timeout_short_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
				oidc_cfg_dir_pass_cookies_get(r), NULL, NULL, NULL) == FALSE) {
		json_decref(data);
		return FALSE;
	}
	json_decref(data);

	/* decode and see if it is not an error response somehow */
	if (oidc_util_json_decode_and_check_error(r, *response, j_client) == FALSE) {
		oidc_error(r, "JSON parsing of dynamic client registration response failed");
		return FALSE;
	}

	return TRUE;
}

/*
 * see if we have client metadata and check its validity
 * if not, use OpenID Connect Client Registration to get it, check it and store it
 */
apr_byte_t oidc_metadata_client_get(request_rec *r, oidc_cfg_t *cfg, const char *issuer, oidc_provider_t *provider,
				    json_t **j_client) {

	/* get the full file path to the client metadata for this issuer */
	const char *client_path = oidc_metadata_client_file_path(r, issuer);

	/* see if we have valid metadata already, if so, return it */
	/* if we have valid client metadata already, return it */
	if ((oidc_metadata_file_read_json(r, client_path, j_client) == TRUE) &&
	    (oidc_metadata_client_is_valid(r, *j_client, issuer) == TRUE))
		return TRUE;

	/* at this point we have no valid client metadata, see if there's a registration endpoint for this provider */
	if (oidc_cfg_provider_registration_endpoint_url_get(provider) == NULL) {
		oidc_error(r,
			   "no (valid) client metadata exists for provider (%s) and provider JSON object did not "
			   "contain a (valid) \"" OIDC_METADATA_REGISTRATION_ENDPOINT "\" string",
			   issuer);
		return FALSE;
	}

	/* try and get client metadata by registering the client at the registration endpoint */
	char *response = NULL;
	if (oidc_metadata_client_register(r, cfg, provider, j_client, &response) == FALSE)
		return FALSE;

	/* check to see if it is valid metadata */
	if (oidc_metadata_client_is_valid(r, *j_client, issuer) == FALSE)
		return FALSE;

	/* since it is valid, write the obtained client metadata file */
	if (oidc_util_file_write(r, client_path, response) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * override the provider token endpoint auth method when the client metadata specifies one
 */
static void oidc_metadata_client_parse_token_endpoint_auth(request_rec *r, oidc_cfg_t *cfg, json_t *j_client,
							   oidc_provider_t *provider) {

	char *value = NULL;
	oidc_util_json_object_get_string(r->pool, j_client, OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHOD, &value, NULL);
	if (value == NULL)
		return;

	const char *rv = oidc_cfg_provider_token_endpoint_auth_set(r->pool, cfg, provider, value);
	if (rv != NULL)
		oidc_error(r, "oidc_provider_token_endpoint_auth_set: %s", value);
}

/*
 * determine the provider response_type when not already set by .conf: default from the global config,
 * then fall back to the first entry of the client metadata "response_types" array if the configured
 * one is not advertised as supported
 */
static void oidc_metadata_client_parse_response_type(request_rec *r, oidc_cfg_t *cfg, json_t *j_client,
						     oidc_provider_t *provider) {

	const char *rv = NULL;
	char *value = NULL;

	if (oidc_cfg_provider_response_type_get(provider) != NULL)
		return;

	oidc_cfg_provider_response_type_set(r->pool, provider,
					    oidc_cfg_provider_response_type_get(oidc_cfg_provider_get(cfg)));

	// "response_types" is an array in the client metadata as by spec
	json_t *j_response_types = json_object_get(j_client, OIDC_METADATA_RESPONSE_TYPES);
	if ((j_response_types == NULL) || (!json_is_array(j_response_types)))
		return;

	// if there's an array we'll prefer the configured response_type if supported
	if (oidc_util_json_array_has_value(r, j_response_types, oidc_cfg_provider_response_type_get(provider)) == TRUE)
		return;

	// if the configured response_type is not supported, we'll fallback to the first one that is listed
	json_t *j_response_type = json_array_get(j_response_types, 0);
	if (json_is_string(j_response_type)) {
		value = apr_pstrdup(r->pool, json_string_value(j_response_type));
		OIDC_METADATA_PROVIDER_SET(response_type, value, rv)
	}
}

/*
 * parse the JSON client metadata in to a oidc_provider_t struct
 */
apr_byte_t oidc_metadata_client_parse(request_rec *r, oidc_cfg_t *cfg, json_t *j_client, oidc_provider_t *provider) {

	const char *rv = NULL;
	char *value = NULL;

	/* get a handle to the client_id we need to use for this provider */
	oidc_util_json_object_get_string(r->pool, j_client, OIDC_METADATA_CLIENT_ID, &value, NULL);
	OIDC_METADATA_PROVIDER_SET(client_id, value, rv)

	/* get a handle to the client_secret we need to use for this provider */
	oidc_util_json_object_get_string(r->pool, j_client, OIDC_METADATA_CLIENT_SECRET, &value, NULL);
	OIDC_METADATA_PROVIDER_SET(client_secret, value, rv)

	/* see if the token endpoint auth method defined in the client metadata overrides the provider one */
	oidc_metadata_client_parse_token_endpoint_auth(r, cfg, j_client, provider);

	/* determine the response type if not set by .conf */
	oidc_metadata_client_parse_response_type(r, cfg, j_client, provider);

	oidc_util_json_object_get_string(
	    r->pool, j_client, OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG, &value,
	    oidc_cfg_provider_id_token_signed_response_alg_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(id_token_signed_response_alg, value, rv)

	// TODO: id_token_encrypted_response_alg etc.?

	return TRUE;
}
