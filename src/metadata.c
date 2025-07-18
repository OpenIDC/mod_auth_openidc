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
 * Copyright (C) 2013-2017 Ping Identity Corporation
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
 * OpenID Connect metadata handling routines, for both OP discovery and client registration
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "metadata.h"
#include "cfg/dir.h"
#include "cfg/oauth.h"
#include "cfg/parse.h"
#include "cfg/provider.h"
#include "metrics.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

#define OIDC_METADATA_SUFFIX_PROVIDER "provider"
#define OIDC_METADATA_SUFFIX_CLIENT "client"
#define OIDC_METADATA_SUFFIX_CONF "conf"

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
#define OIDC_METADATA_CLIENT_ID "client_id"
#define OIDC_METADATA_CLIENT_SECRET "client_secret"
#define OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT "client_secret_expires_at"

#define OIDC_METADATA_KEYS OIDC_JOSE_JWKS_KEYS_STR

#define OIDC_METADATA_CLIENT_JWKS_URI "client_jwks_uri"
#define OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG "id_token_signed_response_alg"
#define OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG "id_token_encrypted_response_alg"
#define OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC "id_token_encrypted_response_enc"
#define OIDC_METADATA_ID_TOKEN_AUD_VALUES "id_token_aud_values"
#define OIDC_METADATA_PROFILE "profile"
#define OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG "userinfo_signed_response_alg"
#define OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG "userinfo_encrypted_response_alg"
#define OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC "userinfo_encrypted_response_enc"

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
 * get the metadata filename for a specified issuer (cq. urlencode it)
 */
static const char *oidc_metadata_issuer_to_filename(request_rec *r, const char *issuer) {

	/* strip leading https:// */
	char *p = _oidc_strstr(issuer, "https://");
	if (p == issuer) {
		p = apr_pstrdup(r->pool, issuer + _oidc_strlen("https://"));
	} else {
		p = _oidc_strstr(issuer, "http://");
		if (p == issuer) {
			p = apr_pstrdup(r->pool, issuer + _oidc_strlen("http://"));
		} else {
			p = apr_pstrdup(r->pool, issuer);
		}
	}

	/* strip trailing '/' */
	int n = _oidc_strlen(p);
	if (p[n - 1] == OIDC_CHAR_FORWARD_SLASH)
		p[n - 1] = '\0';

	return oidc_http_url_encode(r, p);
}

/*
 * get the issuer from a metadata filename (cq. urldecode it)
 */
static const char *oidc_metadata_filename_to_issuer(request_rec *r, const char *filename) {
	char *result = apr_pstrdup(r->pool, filename);
	char *p = strrchr(result, OIDC_CHAR_DOT);
	*p = '\0';
	p = oidc_http_url_decode(r, result);
	return apr_psprintf(r->pool, "https://%s", p);
}

/*
 * get the full path to the metadata file for a specified issuer and directory
 */
static const char *oidc_metadata_file_path(request_rec *r, oidc_cfg_t *cfg, const char *issuer, const char *type) {
	return apr_psprintf(r->pool, "%s/%s.%s", oidc_cfg_metadata_dir_get(cfg),
			    oidc_metadata_issuer_to_filename(r, issuer), type);
}

/*
 * get the full path to the provider metadata file for a specified issuer
 */
static const char *oidc_metadata_provider_file_path(request_rec *r, const char *issuer) {
	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_PROVIDER);
}

/*
 * get the full path to the client metadata file for a specified issuer
 */
static const char *oidc_metadata_client_file_path(request_rec *r, const char *issuer) {
	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CLIENT);
}

/*
 * get the full path to the custom config file for a specified issuer
 */
static const char *oidc_metadata_conf_path(request_rec *r, const char *issuer) {
	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CONF);
}

/*
 * get cache key for the JWKs file for a specified URI
 */
static const char *oidc_metadata_jwks_cache_key(const oidc_jwks_uri_t *jwks_uri) {
	return jwks_uri->signed_uri ? jwks_uri->signed_uri : jwks_uri->uri;
}

/*
 * read a JSON metadata file from disk
 */
static apr_byte_t oidc_metadata_file_read_json(request_rec *r, const char *path, json_t **result) {
	char *buf = NULL;

	/* read the file contents */
	if (oidc_util_file_read(r, path, r->pool, &buf) == FALSE)
		return FALSE;

	/* decode the JSON contents of the buffer */
	return oidc_util_json_decode_object(r, buf, result);
}

/*
 * check if the specified entry in metadata is a valid URI
 */
static apr_byte_t oidc_metadata_is_valid_uri(request_rec *r, const char *type, const char *issuer, json_t *json,
					     const char *key, char **value, apr_byte_t is_mandatory) {

	char *s_value = NULL;
	oidc_util_json_object_get_string(r->pool, json, key, &s_value, NULL);

	if (s_value == NULL) {
		if (is_mandatory) {
			oidc_error(r, "%s (%s) JSON metadata does not contain the mandatory \"%s\" string entry", type,
				   issuer, key);
		}
		return (!is_mandatory);
	}

	if (oidc_cfg_parse_is_valid_http_url(r->pool, s_value) != NULL) {
		oidc_warn(r, "\"%s\" is not a valid http URL for key \"%s\"", s_value, key);
		return FALSE;
	}

	if (value)
		*value = s_value;

	return TRUE;
}

/*
 * check if there's a valid entry in a string of arrays, with a preference
 */
static const char *oidc_metadata_valid_string_in_array(apr_pool_t *pool, json_t *json, const char *key,
						       oidc_valid_function_t valid_function, char **value,
						       apr_byte_t optional, const char *preference) {
	int i = 0;
	if (value)
		*value = NULL;
	json_t *json_arr = json_object_get(json, key);
	apr_byte_t found = FALSE;
	if ((json_arr != NULL) && (json_is_array(json_arr))) {
		for (i = 0; i < json_array_size(json_arr); i++) {
			json_t *elem = json_array_get(json_arr, i);
			if (!json_is_string(elem))
				continue;
			if (valid_function(pool, json_string_value(elem)) == NULL) {
				found = TRUE;
				if (value != NULL) {
					if ((preference != NULL) &&
					    (_oidc_strcmp(json_string_value(elem), preference) == 0)) {
						*value = apr_pstrdup(pool, json_string_value(elem));
						break;
					}
					if (*value == NULL) {
						*value = apr_pstrdup(pool, json_string_value(elem));
					}
				}
			}
		}
		if (found == FALSE) {
			return apr_psprintf(pool, "could not find a valid array string element for entry \"%s\"", key);
		}
	} else if (optional == FALSE) {
		return apr_psprintf(pool, "JSON object did not contain a \"%s\" array", key);
	}
	return NULL;
}

/*
 * check to see if JSON provider metadata is valid
 */
apr_byte_t oidc_metadata_provider_is_valid(request_rec *r, oidc_cfg_t *cfg, json_t *j_provider, const char *issuer) {

	/* get the "issuer" from the provider metadata and double-check that it matches what we looked for */
	char *s_issuer = NULL;
	oidc_util_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER, &s_issuer, NULL);
	if (s_issuer == NULL) {
		oidc_error(r, "provider (%s) JSON metadata did not contain an \"" OIDC_METADATA_ISSUER "\" string",
			   issuer);
		return FALSE;
	}

	/* check that the issuer matches */
	if (issuer != NULL) {
		if (oidc_util_issuer_match(issuer, s_issuer) == FALSE) {
			oidc_error(r,
				   "requested issuer (%s) does not match the \"" OIDC_METADATA_ISSUER
				   "\" value in the provider metadata file: %s",
				   issuer, s_issuer);
			return FALSE;
		}
	}

	/* verify that the provider supports the a flow that we implement */
	if (oidc_metadata_valid_string_in_array(r->pool, j_provider, OIDC_METADATA_RESPONSE_TYPES_SUPPORTED,
						oidc_cfg_parse_is_valid_response_type, NULL, FALSE, NULL) != NULL) {
		if (json_object_get(j_provider, OIDC_METADATA_RESPONSE_TYPES_SUPPORTED) != NULL) {
			oidc_error(r,
				   "could not find a supported response type in provider metadata (%s) for entry "
				   "\"" OIDC_METADATA_RESPONSE_TYPES_SUPPORTED "\"",
				   issuer);
			return FALSE;
		}
		oidc_warn(
		    r,
		    "could not find (required) supported response types  (\"" OIDC_METADATA_RESPONSE_TYPES_SUPPORTED
		    "\") in provider metadata (%s); assuming that \"code\" flow is supported...",
		    issuer);
	}

	/* verify that the provider supports a response_mode that we implement */
	if (oidc_metadata_valid_string_in_array(r->pool, j_provider, OIDC_METADATA_RESPONSE_MODES_SUPPORTED,
						oidc_cfg_parse_is_valid_response_mode, NULL, TRUE, NULL) != NULL) {
		oidc_error(r,
			   "could not find a supported response mode in provider metadata (%s) for entry "
			   "\"" OIDC_METADATA_RESPONSE_MODES_SUPPORTED "\"",
			   issuer);
		return FALSE;
	}

	/* check the required authorization endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider,
				       OIDC_METADATA_AUTHORIZATION_ENDPOINT, NULL, TRUE) == FALSE)
		return FALSE;

	/* check the optional token endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider,
				       OIDC_METADATA_TOKEN_ENDPOINT, NULL, FALSE) == FALSE)
		return FALSE;

	/* check the optional user info endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider,
				       OIDC_METADATA_USERINFO_ENDPOINT, NULL, FALSE) == FALSE)
		return FALSE;

	/* check the optional JWKs URI */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider, OIDC_METADATA_JWKS_URI,
				       NULL, FALSE) == FALSE)
		return FALSE;

	/* check the optional signed JWKs URI */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider,
				       OIDC_METADATA_SIGNED_JWKS_URI, NULL, FALSE) == FALSE)
		return FALSE;

	/* find out what type of authentication the token endpoint supports */
	if (oidc_metadata_valid_string_in_array(
		r->pool, j_provider, OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
		oidc_cfg_get_valid_endpoint_auth_function(cfg), NULL, TRUE, NULL) != NULL) {
		oidc_error(r,
			   "could not find a supported token endpoint authentication method in provider metadata (%s) "
			   "for entry \"" OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED "\"",
			   issuer);
		return FALSE;
	}

	return TRUE;
}

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
 * checks if a parsed JWKs file is a valid one, cq. contains "keys"
 */
static apr_byte_t oidc_metadata_jwks_is_valid(request_rec *r, const char *url, const json_t *j_jwks) {

	const json_t *keys = json_object_get(j_jwks, OIDC_METADATA_KEYS);
	if ((keys == NULL) || (!json_is_array(keys))) {
		oidc_error(
		    r, "JWKs JSON metadata obtained from URL \"%s\" did not contain a \"" OIDC_METADATA_KEYS "\" array",
		    url);
		return FALSE;
	}
	return TRUE;
}

/*
 * check is a specified JOSE feature is supported
 */
static apr_byte_t oidc_metadata_conf_jose_is_supported(request_rec *r, json_t *j_conf, const char *issuer,
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
 * register the client with the OP using Dynamic Client Registration
 */
static apr_byte_t oidc_metadata_client_register(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
						json_t **j_client, char **response) {

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
 * helper function to get the JWKs for the specified issuer
 */
static apr_byte_t oidc_metadata_jwks_retrieve_and_cache(request_rec *r, oidc_cfg_t *cfg,
							const oidc_jwks_uri_t *jwks_uri, int ssl_validate_server,
							json_t **j_jwks) {

	char *response = NULL;
	const char *url = (jwks_uri->signed_uri != NULL) ? jwks_uri->signed_uri : jwks_uri->uri;

	/* get the JWKs from the specified URL with the specified parameters */
	if (oidc_http_get(r, url, NULL, NULL, NULL, NULL, ssl_validate_server, &response, NULL, NULL,
			  oidc_cfg_http_timeout_long_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
			  oidc_cfg_dir_pass_cookies_get(r), NULL, NULL, NULL) == FALSE)
		return FALSE;

	if ((jwks_uri->signed_uri != NULL) && (jwks_uri->jwk_list != NULL)) {

		oidc_jwt_t *jwt = NULL;
		oidc_jose_error_t err;
		apr_hash_t *keys = apr_hash_make(r->pool);

		oidc_debug(r, "signed_jwks verifier keys count=%d", jwks_uri->jwk_list->nelts);
		for (int i = 0; i < jwks_uri->jwk_list->nelts; i++) {
			oidc_jwk_t *jwk = APR_ARRAY_IDX(jwks_uri->jwk_list, i, oidc_jwk_t *);
			if (jwk->kid != NULL) {
				oidc_debug(r, "signed_jwks verifier kid=%s", jwk->kid);
				apr_hash_set(keys, jwk->kid, APR_HASH_KEY_STRING, jwk);
			} else {
				const char *kid = apr_psprintf(r->pool, "%d", apr_hash_count(keys));
				oidc_debug(r, "signed_jwks verifier kid=%s", kid);
				apr_hash_set(keys, kid, APR_HASH_KEY_STRING, jwk);
			}
		}

		if (oidc_jwt_parse(r->pool, response, &jwt, keys, FALSE, &err) == FALSE) {
			oidc_error(r, "parsing JWT failed: %s", oidc_jose_e2s(r->pool, err));
			return FALSE;
		}

		oidc_debug(r, "successfully parsed JWT returned from \"signed_jwks_uri\" endpoint");

		if (oidc_jwt_verify(r->pool, jwt, keys, &err) == FALSE) {
			oidc_error(r, "verifying JWT failed: %s", oidc_jose_e2s(r->pool, err));
			oidc_jwt_destroy(jwt);
			return FALSE;
		}

		// TODO: add issuer?
		if (oidc_proto_jwt_validate(r, jwt, NULL, FALSE, FALSE, -1) == FALSE)
			return FALSE;

		oidc_debug(r, "successfully verified and validated JWKs JWT");

		response = jwt->payload.value.str;
		oidc_jwt_destroy(jwt);
	}

	/* decode and see if it is not an error response somehow */
	if (oidc_util_json_decode_and_check_error(r, response, j_jwks) == FALSE) {
		oidc_error(r, "JSON parsing of JWKs published at the jwks_uri failed");
		return FALSE;
	}

	/* check to see if it is a set of valid JWKs */
	if (oidc_metadata_jwks_is_valid(r, url, *j_jwks) == FALSE)
		return FALSE;

	/* store the JWKs in the cache */
	oidc_cache_set_jwks(r, oidc_metadata_jwks_cache_key(jwks_uri), response,
			    apr_time_now() + apr_time_from_sec(oidc_cfg_jwks_uri_refresh_interval_get(jwks_uri)));

	return TRUE;
}

/*
 * return JWKs for the specified issuer
 */
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg_t *cfg, const oidc_jwks_uri_t *jwks_uri,
				  int ssl_validate_server, json_t **j_jwks, apr_byte_t *refresh) {
	char *value = NULL;
	const char *url = jwks_uri->signed_uri ? jwks_uri->signed_uri : jwks_uri->uri;

	oidc_debug(r, "enter, %sjwks_uri=%s, refresh=%d", jwks_uri->signed_uri ? "signed_" : "", url, *refresh);

	/* see if we need to do a forced refresh */
	if (*refresh == TRUE) {
		oidc_debug(r, "doing a forced refresh of the JWKs from URI \"%s\"", url);
		if (oidc_metadata_jwks_retrieve_and_cache(r, cfg, jwks_uri, ssl_validate_server, j_jwks) == TRUE)
			return TRUE;
		// else: fall back to any cached JWKs
	}

	/* see if the JWKs is cached */
	if ((oidc_cache_get_jwks(r, oidc_metadata_jwks_cache_key(jwks_uri), &value) == TRUE) && (value != NULL)) {
		/* decode and see if it is not a cached error response somehow */
		if (oidc_util_json_decode_and_check_error(r, value, j_jwks) == FALSE) {
			oidc_warn(r, "JSON parsing of cached JWKs data failed");
			value = NULL;
		}
	}

	if (value == NULL) {
		/* it is non-existing, invalid or expired: do a forced refresh */
		*refresh = TRUE;
		return oidc_metadata_jwks_retrieve_and_cache(r, cfg, jwks_uri, ssl_validate_server, j_jwks);
	}

	return TRUE;
}

/*
 * use OpenID Connect Discovery to get metadata for the specified issuer
 */
apr_byte_t oidc_metadata_provider_retrieve(request_rec *r, oidc_cfg_t *cfg, const char *issuer, const char *url,
					   json_t **j_metadata, char **response) {

	OIDC_METRICS_TIMING_START(r, cfg);

	/* get provider metadata from the specified URL with the specified parameters */
	if (oidc_http_get(r, url, NULL, NULL, NULL, NULL,
			  oidc_cfg_provider_ssl_validate_server_get(oidc_cfg_provider_get(cfg)), response, NULL, NULL,
			  oidc_cfg_http_timeout_short_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
			  oidc_cfg_dir_pass_cookies_get(r), NULL, NULL, NULL) == FALSE) {
		OIDC_METRICS_COUNTER_INC(r, cfg, OM_PROVIDER_METADATA_ERROR);
		return FALSE;
	}

	OIDC_METRICS_TIMING_ADD(r, cfg, OM_PROVIDER_METADATA);

	/* decode and see if it is not an error response somehow */
	if (oidc_util_json_decode_and_check_error(r, *response, j_metadata) == FALSE) {
		oidc_error(r, "JSON parsing of retrieved Discovery document failed");
		return FALSE;
	}

	/* check to see if it is valid metadata */
	if (oidc_metadata_provider_is_valid(r, cfg, *j_metadata, issuer) == FALSE) {
		json_decref(*j_metadata);
		return FALSE;
	}

	/* all OK */
	return TRUE;
}

/*
 * see if we have provider metadata and check its validity
 * if not, use OpenID Connect Discovery to get it, check it and store it
 */
apr_byte_t oidc_metadata_provider_get(request_rec *r, oidc_cfg_t *cfg, const char *issuer, json_t **j_provider,
				      apr_byte_t allow_discovery) {

	/* holds the response data/string/JSON from the OP */
	char *response = NULL;

	/* get the full file path to the provider metadata for this issuer */
	const char *provider_path = oidc_metadata_provider_file_path(r, issuer);

	/* check the last-modified timestamp */
	apr_byte_t use_cache = TRUE;
	apr_finfo_t fi;
	json_t *j_cache = NULL;
	apr_byte_t have_cache = FALSE;

	/* see if we are refreshing metadata and we need a refresh */
	if (oidc_cfg_provider_metadata_refresh_interval_get(cfg) > 0) {

		have_cache = (apr_stat(&fi, provider_path, APR_FINFO_MTIME, r->pool) == APR_SUCCESS);

		if (have_cache == TRUE)
			use_cache =
			    (apr_time_now() <
			     fi.mtime + apr_time_from_sec(oidc_cfg_provider_metadata_refresh_interval_get(cfg)));

		oidc_debug(r, "use_cache: %s", use_cache ? "yes" : "no");
	}

	/* see if we have valid metadata already, if so, return it */
	if (oidc_metadata_file_read_json(r, provider_path, &j_cache) == TRUE) {

		/* return the validation result */
		if (use_cache == TRUE) {
			*j_provider = j_cache;
			return oidc_metadata_provider_is_valid(r, cfg, *j_provider, issuer);
		}
	}

	if ((have_cache == FALSE) && (!allow_discovery)) {
		oidc_warn(r, "no metadata found for the requested issuer (%s), and Discovery is not allowed", issuer);
		return FALSE;
	}

	/* assemble the URL to the .well-known OpenID metadata */
	const char *url =
	    apr_psprintf(r->pool, "%s",
			 ((_oidc_strstr(issuer, "http://") == issuer) || (_oidc_strstr(issuer, "https://") == issuer))
			     ? issuer
			     : apr_psprintf(r->pool, "https://%s", issuer));
	url =
	    apr_psprintf(r->pool, "%s%s.well-known/openid-configuration", url,
			 (url && url[_oidc_strlen(url) - 1] != OIDC_CHAR_FORWARD_SLASH) ? OIDC_STR_FORWARD_SLASH : "");

	/* get the metadata for the issuer using OpenID Connect Discovery and validate it */
	if (oidc_metadata_provider_retrieve(r, cfg, issuer, url, j_provider, &response) == FALSE) {

		oidc_debug(r, "could not retrieve provider metadata; have_cache: %s (data=%pp)",
			   have_cache ? "yes" : "no", j_cache);

		/* see if we can use at least the cache that may have expired by now */
		if ((oidc_cfg_provider_metadata_refresh_interval_get(cfg) > 0) && (have_cache == TRUE) &&
		    (j_cache != NULL)) {

			/* reset the file-modified timestamp so it is cached for a while again */
			apr_file_mtime_set(provider_path, apr_time_now(), r->pool);

			/* return the validated cached data */
			*j_provider = j_cache;
			return oidc_metadata_provider_is_valid(r, cfg, *j_provider, issuer);
		}

		return FALSE;
	}

	/* since it is valid, write the obtained provider metadata file */
	if (oidc_util_file_write(r, provider_path, response) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * see if we have config metadata
 */
static apr_byte_t oidc_metadata_conf_get(request_rec *r, const char *issuer, json_t **j_conf) {

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
 * see if we have client metadata and check its validity
 * if not, use OpenID Connect Client Registration to get it, check it and store it
 */
static apr_byte_t oidc_metadata_client_get(request_rec *r, oidc_cfg_t *cfg, const char *issuer,
					   oidc_provider_t *provider, json_t **j_client) {

	/* get the full file path to the client metadata for this issuer */
	const char *client_path = oidc_metadata_client_file_path(r, issuer);

	/* see if we have valid metadata already, if so, return it */
	if (oidc_metadata_file_read_json(r, client_path, j_client) == TRUE) {

		/* if the client metadata is (still) valid, return it */
		if (oidc_metadata_client_is_valid(r, *j_client, issuer) == TRUE)
			return TRUE;
	}

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
 * get a list of configured OIDC providers based on the entries in the provider metadata directory
 */
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg_t *cfg, apr_array_header_t **list) {
	apr_status_t rc;
	apr_dir_t *dir;
	apr_finfo_t fi;
	char s_err[128];

	oidc_debug(r, "enter");

	/* open the metadata directory */
	if ((rc = apr_dir_open(&dir, oidc_cfg_metadata_dir_get(cfg), r->pool)) != APR_SUCCESS) {
		oidc_error(r, "error opening metadata directory '%s' (%s)", oidc_cfg_metadata_dir_get(cfg),
			   apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* allocate some space in the array that will hold the list of providers */
	*list = apr_array_make(r->pool, 5, sizeof(const char *));
	/* BTW: we could estimate the number in the array based on # directory entries... */

	/* loop over the entries in the provider metadata directory */
	while (apr_dir_read(&fi, APR_FINFO_NAME, dir) == APR_SUCCESS) {

		/* skip "." and ".." entries */
		if (fi.name[0] == OIDC_CHAR_DOT)
			continue;
		/* skip other non-provider entries */
		const char *ext = strrchr(fi.name, OIDC_CHAR_DOT);
		if (ext == NULL)
			continue;
		ext++;
		if (_oidc_strcmp(ext, OIDC_METADATA_SUFFIX_PROVIDER) != 0)
			continue;

		/* get the issuer from the filename */
		const char *issuer = oidc_metadata_filename_to_issuer(r, fi.name);

		/* get the provider and client metadata, do all checks and registration if possible */
		oidc_provider_t *provider = NULL;
		if (oidc_metadata_get(r, cfg, issuer, &provider, FALSE) == TRUE) {
			/* push the decoded issuer filename in to the array */
			APR_ARRAY_PUSH(*list, const char *) = oidc_cfg_provider_issuer_get(provider);
		}
	}

	/* we're done, cleanup now */
	apr_dir_close(dir);

	return TRUE;
}

/*
 * parse boolean value from JSON configuration
 */
static void oidc_metadata_parse_boolean(request_rec *r, json_t *json, const char *key, int *value, int default_value) {
	int int_value = 0;
	char *s_value = NULL;
	if (oidc_util_json_object_get_bool(json, key, &int_value, default_value) == FALSE) {
		oidc_util_json_object_get_string(r->pool, json, key, &s_value, NULL);
		if (s_value != NULL) {
			const char *rv = oidc_cfg_parse_boolean(r->pool, s_value, &int_value);
			if (rv != NULL) {
				oidc_warn(r, "%s: %s", key, rv);
				int_value = default_value;
			}
		} else {
			oidc_util_json_object_get_int(json, key, &int_value, default_value);
		}
	}
	*value = (int_value != 0) ? TRUE : FALSE;
}

/*
 * parse URL value from JSON configuration
 */
static void oidc_metadata_parse_url(request_rec *r, const char *type, const char *issuer, json_t *json, const char *key,
				    char **value, const char *default_value) {
	*value = NULL;
	if ((oidc_metadata_is_valid_uri(r, type, issuer, json, key, value, FALSE) == FALSE) ||
	    ((*value == NULL) && (default_value != NULL))) {
		*value = apr_pstrdup(r->pool, default_value);
	}
}

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
 * parse the JSON provider metadata in to a oidc_provider_t struct but do not override values already set
 */
apr_byte_t oidc_metadata_provider_parse(request_rec *r, oidc_cfg_t *cfg, json_t *j_provider,
					oidc_provider_t *provider) {

	const char *rv = NULL;
	char *value = NULL;
	int ivalue = OIDC_CONFIG_POS_INT_UNSET;

	if (oidc_cfg_provider_issuer_get(provider) == NULL) {
		/* get the "issuer" from the provider metadata */
		oidc_util_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(issuer, value, rv);
	}

	if (oidc_cfg_provider_authorization_endpoint_url_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_AUTHORIZATION_ENDPOINT, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(authorization_endpoint_url, value, rv)
	}

	if (oidc_cfg_provider_token_endpoint_url_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_TOKEN_ENDPOINT, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(token_endpoint_url, value, rv)
	}

	if (oidc_cfg_provider_userinfo_endpoint_url_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_USERINFO_ENDPOINT, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(userinfo_endpoint_url, value, rv)
	}

	if (oidc_cfg_provider_revocation_endpoint_url_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_REVOCATION_ENDPOINT, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(revocation_endpoint_url, value, rv)
	}

	if (oidc_cfg_provider_pushed_authorization_request_endpoint_url_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_PAR_ENDPOINT, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(pushed_authorization_request_endpoint_url, value, rv)
	}

	if (oidc_cfg_provider_jwks_uri_uri_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_JWKS_URI, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(jwks_uri, value, rv)
	}

	if (oidc_cfg_provider_signed_jwks_uri_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_SIGNED_JWKS_URI, &value, NULL);
		if (value != NULL) {
			rv = oidc_cfg_provider_signed_jwks_uri_set(r->pool, provider, value, NULL);
			if (rv != NULL)
				oidc_error(r, "oidc_provider_signed_jwks_uri_set: %s", rv);
		}
	}

	if (oidc_cfg_provider_registration_endpoint_url_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_REGISTRATION_ENDPOINT, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(registration_endpoint_url, value, rv)
	}

	if (oidc_cfg_provider_check_session_iframe_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_CHECK_SESSION_IFRAME, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(check_session_iframe, value, rv)
	}

	if (oidc_cfg_provider_end_session_endpoint_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_END_SESSION_ENDPOINT, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(end_session_endpoint, value, rv)
	}

	// NB: here we don't actually override with the global setting/default, merely apply it when no value is
	// provided
	oidc_metadata_parse_boolean(r, j_provider, OIDC_METADATA_BACKCHANNEL_LOGOUT_SUPPORTED, &ivalue,
				    oidc_cfg_provider_backchannel_logout_supported_get(provider));
	OIDC_METADATA_PROVIDER_SET_INT(provider, backchannel_logout_supported, ivalue, rv)

	if (oidc_cfg_provider_token_endpoint_auth_get(provider) == NULL) {
		if (oidc_metadata_valid_string_in_array(r->pool, j_provider,
							OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
							oidc_cfg_get_valid_endpoint_auth_function(cfg), &value, TRUE,
							OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC) != NULL) {
			oidc_error(r,
				   "could not find a supported token endpoint authentication method in provider"
				   "metadata (%s) for entry \"" OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
				   "\"",
				   oidc_cfg_provider_issuer_get(provider));
			return FALSE;
		}
		rv = oidc_cfg_provider_token_endpoint_auth_set(r->pool, cfg, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_provider_token_endpoint_auth_set: %s", rv);
	}

	return TRUE;
}

/*
 * parse the JSON OAuth 2.0 provider metadata in to the cfg->oauth struct
 */
apr_byte_t oidc_oauth_metadata_provider_parse(request_rec *r, oidc_cfg_t *c, json_t *j_provider) {

	char *issuer = NULL, *value = NULL;
	const char *rv = NULL;

	/* get the "issuer" from the provider metadata */
	oidc_util_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER, &issuer, NULL);

	// TOOD: should check for "if c->oauth.introspection_endpoint_url == NULL and
	//       allocate the string from the process/config pool
	//
	// https://github.com/OpenIDC/mod_auth_openidc/commit/32321024ed5bdbc02ba8b5d61aabc4a4c3745c89
	// https://groups.google.com/forum/#!topic/mod_auth_openidc/o1K_1Yh-TQA

	/* get a handle to the introspection endpoint */
	oidc_util_json_object_get_string(r->pool, j_provider, OIDC_METADATA_INTROSPECTION_ENDPOINT, &value, NULL);
	if (value != NULL) {
		rv = oidc_cfg_oauth_introspection_endpoint_url_set(r->pool, c, value);
		if (rv != NULL)
			oidc_error(r, "oidc_oauth_introspection_endpoint_url_set error: %s", rv);
	}

	/* get a handle to the jwks_uri endpoint */
	oidc_util_json_object_get_string(r->pool, j_provider, OIDC_METADATA_JWKS_URI, &value, NULL);
	if (value != NULL) {
		rv = oidc_cfg_oauth_verify_jwks_uri_set(r->pool, c, value);
		if (rv != NULL)
			oidc_error(r, "oidc_oauth_verify_jwks_uri_set error: %s", rv);
	}

	if (oidc_metadata_valid_string_in_array(r->pool, j_provider,
						OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED,
						oidc_cfg_get_valid_endpoint_auth_function(c), &value, TRUE,
						OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC) != NULL) {
		oidc_error(r,
			   "could not find a supported token endpoint authentication method in provider metadata (%s) "
			   "for entry \"" OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED "\"",
			   issuer);
		return FALSE;
	} else {
		rv = oidc_cfg_oauth_introspection_endpoint_auth_set(r->pool, c, value);
		if (rv != NULL)
			oidc_error(r, "oidc_oauth_introspection_endpoint_auth_set error: %s", rv);
	}

	return TRUE;
}

/*
 * get a string value from a JSON object and see if it is a valid value according to the specified validation function
 */
void oidc_metadata_get_valid_string(request_rec *r, json_t *json, const char *key, oidc_valid_function_t valid_function,
				    char **str_value, const char *default_str_value) {
	char *v = NULL;
	oidc_util_json_object_get_string(r->pool, json, key, &v, default_str_value);
	if (v != NULL) {
		const char *rv = valid_function(r->pool, v);
		if (rv != NULL) {
			oidc_warn(r, "string value %s for key \"%s\" is invalid: %s; using default: %s", v, key, rv,
				  default_str_value);
			v = apr_pstrdup(r->pool, default_str_value);
		}
	}
	*str_value = v;
}

/*
 * parse a set of JWKs from a JSON metadata object
 */
static void oidc_metadata_get_jwks(request_rec *r, json_t *json, apr_array_header_t **jwk_list) {
	json_t *keys = NULL;
	int i = 0;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	json_t *elem = NULL;

	keys = json_object_get(json, OIDC_JOSE_JWKS_KEYS_STR);
	if (keys == NULL)
		return;

	if (!json_is_array(keys)) {
		oidc_error(r, "trying to parse a list of JWKs but the value for key \"%s\" is not a JSON array",
			   OIDC_JOSE_JWKS_KEYS_STR);
		return;
	}

	for (i = 0; i < json_array_size(keys); i++) {

		elem = json_array_get(keys, i);

		if (oidc_jwk_parse_json(r->pool, elem, &jwk, &err) == FALSE) {
			oidc_warn(r, "oidc_jwk_parse_json failed: %s", oidc_jose_e2s(r->pool, err));
			continue;
		}

		if (*jwk_list == NULL)
			*jwk_list = apr_array_make(r->pool, 4, sizeof(oidc_jwk_t *));
		APR_ARRAY_PUSH(*jwk_list, oidc_jwk_t *) = jwk;
	}
}

/*
 * parse the JSON conf metadata in to a oidc_provider_t struct
 */
apr_byte_t oidc_metadata_conf_parse(request_rec *r, oidc_cfg_t *cfg, json_t *j_conf, oidc_provider_t *provider) {

	const char *rv = NULL;
	char *value = NULL;
	int ivalue = OIDC_CONFIG_POS_INT_UNSET;
	apr_array_header_t *keys = NULL, *auds = NULL;

	// NB: need this first so the profile - if explicitly configured - will override
	//     potentially non-conformant / insecure settings
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_PROFILE, &value, NULL);
	if (value) {
		rv = oidc_cfg_provider_profile_set(r->pool, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_profile_set: %s", rv);
	} else {
		oidc_cfg_provider_profile_int_set(provider, oidc_cfg_provider_profile_get(oidc_cfg_provider_get(cfg)));
	}

	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_CLIENT_JWKS_URI, &value,
					 oidc_cfg_provider_client_jwks_uri_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(client_jwks_uri, value, rv)

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

	/* get the (optional) signing & encryption settings for the id_token */
	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG, &value,
	    oidc_cfg_provider_id_token_signed_response_alg_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(id_token_signed_response_alg, value, rv)

	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG, &value,
	    oidc_cfg_provider_id_token_encrypted_response_alg_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(id_token_encrypted_response_alg, value, rv)

	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC, &value,
	    oidc_cfg_provider_id_token_encrypted_response_enc_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(id_token_encrypted_response_enc, value, rv)

	oidc_util_json_object_get_string_array(
	    r->pool, j_conf, OIDC_METADATA_ID_TOKEN_AUD_VALUES, &auds,
	    oidc_proto_profile_id_token_aud_values_get(r->pool, oidc_cfg_provider_get(cfg)));
	if (auds != NULL) {
		rv = oidc_cfg_provider_id_token_aud_values_set_str_list(r->pool, provider, auds);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_aud_values_set: %s", rv);
	}

	/* get the (optional) signing & encryption settings for the userinfo response */
	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG, &value,
	    oidc_cfg_provider_userinfo_signed_response_alg_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(userinfo_signed_response_alg, value, rv)

	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG, &value,
	    oidc_cfg_provider_userinfo_encrypted_response_alg_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(userinfo_encrypted_response_alg, value, rv)

	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC, &value,
	    oidc_cfg_provider_userinfo_encrypted_response_enc_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(userinfo_encrypted_response_enc, value, rv)

	/* find out if we need to perform SSL server certificate validation on the token_endpoint and user_info_endpoint
	 * for this provider */
	oidc_metadata_parse_boolean(r, j_conf, OIDC_METADATA_SSL_VALIDATE_SERVER, &ivalue,
				    oidc_cfg_provider_ssl_validate_server_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET_INT(provider, ssl_validate_server, ivalue, rv)

	oidc_metadata_parse_boolean(r, j_conf, OIDC_METADATA_VALIDATE_ISSUER, &ivalue,
				    oidc_cfg_provider_validate_issuer_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET_INT(provider, validate_issuer, ivalue, rv)

	/* find out what scopes we should be requesting from this provider */
	// TODO: use the provider "scopes_supported" to mix-and-match with what we've configured for the client
	// TODO: check that "openid" is always included in the configured scopes, right?
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_SCOPE, &value,
					 oidc_cfg_provider_scope_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(scope, value, rv)

	/* see if we've got a custom JWKs refresh interval */
	oidc_util_json_object_get_int(j_conf, OIDC_METADATA_JWKS_REFRESH_INTERVAL, &ivalue,
				      oidc_cfg_provider_jwks_uri_refresh_interval_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET_INT(provider, jwks_uri_refresh_interval, ivalue, rv)

	/* see if we've got a custom IAT slack interval */
	oidc_util_json_object_get_int(j_conf, OIDC_METADATA_IDTOKEN_IAT_SLACK, &ivalue,
				      oidc_cfg_provider_idtoken_iat_slack_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET_INT(provider, idtoken_iat_slack, ivalue, rv)

	/* see if we've got a custom max session duration */
	oidc_util_json_object_get_int(j_conf, OIDC_METADATA_SESSION_MAX_DURATION, &ivalue,
				      oidc_cfg_provider_session_max_duration_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET_INT(provider, session_max_duration, ivalue, rv)

	/* see if we've got custom authentication request parameter values */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_AUTH_REQUEST_PARAMS, &value,
					 oidc_cfg_provider_auth_request_params_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(auth_request_params, value, rv)

	/* see if we've got custom logout request parameter values */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_LOGOUT_REQUEST_PARAMS, &value,
					 oidc_cfg_provider_logout_request_params_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(logout_request_params, value, rv)

	/* see if we've got custom token endpoint parameter values */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_TOKEN_ENDPOINT_PARAMS, &value,
					 oidc_cfg_provider_token_endpoint_params_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(token_endpoint_params, value, rv)

	/* get the response mode to use */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_RESPONSE_MODE, &value,
					 oidc_cfg_provider_response_mode_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(response_mode, value, rv)

	/* get the PKCE method to use */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_PKCE_METHOD, &value,
					 oidc_proto_profile_pkce_get(provider)->method);
	OIDC_METADATA_PROVIDER_SET(pkce, value, rv)

	/* see if we've got a custom DPoP mode */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_DPOP_MODE, &value, NULL);
	if (value) {
		rv = oidc_cfg_provider_dpop_mode_set(r->pool, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_dpop_mode_set: %s", rv);
	} else {
		oidc_cfg_provider_dpop_mode_int_set(provider, oidc_proto_profile_dpop_mode_get(provider));
	}

	/* get the client name */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_CLIENT_NAME, &value,
					 oidc_cfg_provider_client_name_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(client_name, value, rv)

	/* get the client contact */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_CLIENT_CONTACT, &value,
					 oidc_cfg_provider_client_contact_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(client_contact, value, rv)

	/* get the token endpoint authentication method */
	// TODO: token_endpoint_auth_alg inheritance from global setting does not work now
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_TOKEN_ENDPOINT_AUTH, &value,
					 oidc_cfg_provider_token_endpoint_auth_get(oidc_cfg_provider_get(cfg)));
	if (value != NULL) {
		rv = oidc_cfg_provider_token_endpoint_auth_set(r->pool, cfg, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_token_endpoint_auth_set: %s", rv);
	}

	/* get the dynamic client registration token */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_REGISTRATION_TOKEN, &value,
					 oidc_cfg_provider_registration_token_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(registration_token, value, rv)

	/* see if we've got custom registration request parameter values */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_REGISTRATION_ENDPOINT_JSON, &value,
					 oidc_cfg_provider_registration_endpoint_json_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(registration_endpoint_json, value, rv)

	/* get the flow to use; let the .client file set it otherwise (pass NULL as default value) */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_RESPONSE_TYPE, &value,
					 oidc_cfg_provider_response_type_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(response_type, value, rv)

	/* see if we've got a custom user info refresh interval */
	oidc_util_json_object_get_int(j_conf, OIDC_METADATA_USERINFO_REFRESH_INTERVAL, &ivalue,
				      oidc_cfg_provider_userinfo_refresh_interval_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET_INT(provider, userinfo_refresh_interval, ivalue, rv)

	/* TLS client cert auth settings */
	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_CERT, &value,
	    oidc_cfg_provider_token_endpoint_tls_client_cert_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(token_endpoint_tls_client_cert, value, rv)

	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_KEY, &value,
	    oidc_cfg_provider_token_endpoint_tls_client_key_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(token_endpoint_tls_client_key, value, rv)

	oidc_util_json_object_get_string(
	    r->pool, j_conf, OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_KEY_PWD, &value,
	    oidc_cfg_provider_token_endpoint_tls_client_key_pwd_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(token_endpoint_tls_client_key_pwd, value, rv)

	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_REQUEST_OBJECT, &value,
					 oidc_cfg_provider_request_object_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(request_object, value, rv)

	/* see if we've got a custom userinfo endpoint token presentation method */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_USERINFO_TOKEN_METHOD, &value, NULL);
	if (value) {
		rv = oidc_cfg_provider_userinfo_token_method_set(r->pool, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_userinfo_token_method_set: %s", rv);
	} else {
		oidc_cfg_provider_userinfo_token_method_int_set(
		    provider, oidc_cfg_provider_userinfo_token_method_get(oidc_cfg_provider_get(cfg)));
	}

	/* see if we've got a custom HTTP method for passing the auth request */
	oidc_util_json_object_get_string(r->pool, j_conf, OIDC_METADATA_AUTH_REQUEST_METHOD, &value, NULL);
	if (value) {
		rv = oidc_cfg_provider_auth_request_method_set(r->pool, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_cfg_provider_auth_request_method_set: %s", rv);
	} else {
		oidc_cfg_provider_auth_request_method_int_set(provider,
							      oidc_proto_profile_auth_request_method_get(provider));
	}

	/* get the issuer specific redirect URI option */
	oidc_metadata_parse_boolean(r, j_conf, OIDC_METADATA_RESPONSE_REQUIRE_ISS, &ivalue,
				    oidc_proto_profile_response_require_iss_get(provider));
	OIDC_METADATA_PROVIDER_SET_INT(provider, response_require_iss, ivalue, rv)

	return TRUE;
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
	oidc_util_json_object_get_string(r->pool, j_client, OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHOD, &value, NULL);
	if (value != NULL) {
		rv = oidc_cfg_provider_token_endpoint_auth_set(r->pool, cfg, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_provider_token_endpoint_auth_set: %s", value);
	}

	/* determine the response type if not set by .conf */

	if (oidc_cfg_provider_response_type_get(provider) == NULL) {

		oidc_cfg_provider_response_type_set(r->pool, provider,
						    oidc_cfg_provider_response_type_get(oidc_cfg_provider_get(cfg)));

		// "response_types" is an array in the client metadata as by spec
		json_t *j_response_types = json_object_get(j_client, OIDC_METADATA_RESPONSE_TYPES);
		if ((j_response_types != NULL) && (json_is_array(j_response_types))) {
			// if there's an array we'll prefer the configured response_type if supported
			if (oidc_util_json_array_has_value(r, j_response_types,
							   oidc_cfg_provider_response_type_get(provider)) == FALSE) {
				// if the configured response_type is not supported, we'll fallback to the first one
				// that is listed
				json_t *j_response_type = json_array_get(j_response_types, 0);
				if (json_is_string(j_response_type)) {
					value = apr_pstrdup(r->pool, json_string_value(j_response_type));
					OIDC_METADATA_PROVIDER_SET(response_type, value, rv)
				}
			}
		}
	}

	oidc_util_json_object_get_string(
	    r->pool, j_client, OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG, &value,
	    oidc_cfg_provider_id_token_signed_response_alg_get(oidc_cfg_provider_get(cfg)));
	OIDC_METADATA_PROVIDER_SET(id_token_signed_response_alg, value, rv)

	// TODO: id_token_encrypted_response_alg etc.?

	return TRUE;
}

/*
 * get the metadata for a specified issuer
 *
 * this fill the oidc_provider_t struct based on the issuer filename by reading and merging
 * contents from both provider metadata directory and client metadata directory
 */
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg_t *cfg, const char *issuer, oidc_provider_t **provider,
			     apr_byte_t allow_discovery) {

	apr_byte_t rc = FALSE;

	/* pointers to the parsed JSON metadata */
	json_t *j_provider = NULL;
	json_t *j_client = NULL;
	json_t *j_conf = NULL;

	/* allocate space for a parsed-and-merged metadata struct */
	*provider = oidc_cfg_provider_create(r->pool);

	/*
	 * read and parse the provider, conf and client metadata respectively
	 * NB: order is important here
	 */

	if (oidc_metadata_provider_get(r, cfg, issuer, &j_provider, allow_discovery) == FALSE)
		goto end;
	if (oidc_metadata_provider_parse(r, cfg, j_provider, *provider) == FALSE)
		goto end;

	if (oidc_metadata_conf_get(r, issuer, &j_conf) == FALSE)
		goto end;
	if (oidc_metadata_conf_parse(r, cfg, j_conf, *provider) == FALSE)
		goto end;

	if (oidc_metadata_client_get(r, cfg, issuer, *provider, &j_client) == FALSE)
		goto end;
	if (oidc_metadata_client_parse(r, cfg, j_client, *provider) == FALSE)
		goto end;

	rc = TRUE;

end:

	if (j_provider)
		json_decref(j_provider);
	if (j_conf)
		json_decref(j_conf);
	if (j_client)
		json_decref(j_client);

	return rc;
}
