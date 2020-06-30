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
 * Copyright (C) 2017-2020 ZmartZone IAM
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#include <apr_hash.h>
#include <apr_time.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include <httpd.h>
#include <http_log.h>

#include "mod_auth_openidc.h"
#include "parse.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

#define OIDC_METADATA_SUFFIX_PROVIDER                              "provider"
#define OIDC_METADATA_SUFFIX_CLIENT                                "client"
#define OIDC_METADATA_SUFFIX_CONF                                  "conf"

#define OIDC_METADATA_ISSUER                                       "issuer"
#define OIDC_METADATA_RESPONSE_TYPES_SUPPORTED                     "response_types_supported"
#define OIDC_METADATA_RESPONSE_MODES_SUPPORTED                     "response_modes_supported"
#define OIDC_METADATA_AUTHORIZATION_ENDPOINT                       "authorization_endpoint"
#define OIDC_METADATA_TOKEN_ENDPOINT                               "token_endpoint"
#define OIDC_METADATA_INTROSPECTION_ENDPOINT                       "introspection_endpoint"
#define OIDC_METADATA_USERINFO_ENDPOINT                            "userinfo_endpoint"
#define OIDC_METADATA_REVOCATION_ENDPOINT                          "revocation_endpoint"
#define OIDC_METADATA_JWKS_URI                                     "jwks_uri"
#define OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED        "token_endpoint_auth_methods_supported"
#define OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED "introspection_endpoint_auth_methods_supported"
#define OIDC_METADATA_REGISTRATION_ENDPOINT                        "registration_endpoint"
#define OIDC_METADATA_CHECK_SESSION_IFRAME                         "check_session_iframe"
#define OIDC_METADATA_BACKCHANNEL_LOGOUT_SUPPORTED                 "backchannel_logout_supported"

#define OIDC_METADATA_END_SESSION_ENDPOINT                         "end_session_endpoint"
#define OIDC_METADATA_CLIENT_ID                                    "client_id"
#define OIDC_METADATA_CLIENT_SECRET                                "client_secret"
#define OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT                     "client_secret_expires_at"

#define OIDC_METADATA_KEYS                                         "keys"

#define OIDC_METADATA_CLIENT_JWKS_URI                              "client_jwks_uri"
#define OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG                 "id_token_signed_response_alg"
#define OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG              "id_token_encrypted_response_alg"
#define OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC              "id_token_encrypted_response_enc"
#define OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG                 "userinfo_signed_response_alg"
#define OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG              "userinfo_encrypted_response_alg"
#define OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC              "userinfo_encrypted_response_enc"

#define OIDC_METADATA_CLIENT_NAME                                  "client_name"
#define OIDC_METADATA_REDIRECT_URIS                                "redirect_uris"
#define OIDC_METADATA_RESPONSE_TYPES                               "response_types"
#define OIDC_METADATA_GRANT_TYPES                                  "grant_types"
#define OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHOD                   "token_endpoint_auth_method"
#define OIDC_METADATA_CONTACTS                                     "contacts"
#define OIDC_METADATA_INITIATE_LOGIN_URI                           "initiate_login_uri"
#define OIDC_METADATA_FRONTCHANNEL_LOGOUT_URI                      "frontchannel_logout_uri"
#define OIDC_METADATA_BACKCHANNEL_LOGOUT_URI                       "backchannel_logout_uri"
#define OIDC_METADATA_POST_LOGOUT_REDIRECT_URIS                    "post_logout_redirect_uris"
#define OIDC_METADATA_IDTOKEN_BINDING_CNF                          "id_token_token_binding_cnf"
#define OIDC_METADATA_SSL_VALIDATE_SERVER                          "ssl_validate_server"
#define OIDC_METADATA_VALIDATE_ISSUER                              "validate_issuer"
#define OIDC_METADATA_SCOPE                                        "scope"
#define OIDC_METADATA_JWKS_REFRESH_INTERVAL                        "jwks_refresh_interval"
#define OIDC_METADATA_IDTOKEN_IAT_SLACK                            "idtoken_iat_slack"
#define OIDC_METADATA_SESSION_MAX_DURATION                         "session_max_duration"
#define OIDC_METADATA_AUTH_REQUEST_PARAMS                          "auth_request_params"
#define OIDC_METADATA_TOKEN_ENDPOINT_PARAMS                        "token_endpoint_params"
#define OIDC_METADATA_RESPONSE_MODE                                "response_mode"
#define OIDC_METADATA_PKCE_METHOD                                  "pkce_method"
#define OIDC_METADATA_CLIENT_CONTACT                               "client_contact"
#define OIDC_METADATA_TOKEN_ENDPOINT_AUTH                          "token_endpoint_auth"
#define OIDC_METADATA_REGISTRATION_TOKEN                           "registration_token"
#define OIDC_METADATA_REGISTRATION_ENDPOINT_JSON                   "registration_endpoint_json"
#define OIDC_METADATA_RESPONSE_TYPE                                "response_type"
#define OIDC_METADATA_USERINFO_REFRESH_INTERVAL                    "userinfo_refresh_interval"
#define OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_CERT               "token_endpoint_tls_client_cert"
#define OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_KEY                "token_endpoint_tls_client_key"
#define OIDC_METADATA_REQUEST_OBJECT                               "request_object"
#define OIDC_METADATA_USERINFO_TOKEN_METHOD                        "userinfo_token_method"
#define OIDC_METADATA_TOKEN_BINDING_POLICY                         "token_binding_policy"
#define OIDC_METADATA_AUTH_REQUEST_METHOD                          "auth_request_method"
#define OIDC_METADATA_ISSUER_SPECIFIC_REDIRECT_URI                 "issuer_specific_redirect_uri"

/*
 * get the metadata filename for a specified issuer (cq. urlencode it)
 */
static const char *oidc_metadata_issuer_to_filename(request_rec *r,
		const char *issuer) {

	/* strip leading https:// */
	char *p = strstr(issuer, "https://");
	if (p == issuer) {
		p = apr_pstrdup(r->pool, issuer + strlen("https://"));
	} else {
		p = strstr(issuer, "http://");
		if (p == issuer) {
			p = apr_pstrdup(r->pool, issuer + strlen("http://"));
		} else {
			p = apr_pstrdup(r->pool, issuer);
		}
	}

	/* strip trailing '/' */
	int n = strlen(p);
	if (p[n - 1] == OIDC_CHAR_FORWARD_SLASH)
		p[n - 1] = '\0';

	return oidc_util_escape_string(r, p);
}

/*
 * get the issuer from a metadata filename (cq. urldecode it)
 */
static const char *oidc_metadata_filename_to_issuer(request_rec *r,
		const char *filename) {
	char *result = apr_pstrdup(r->pool, filename);
	char *p = strrchr(result, OIDC_CHAR_DOT);
	*p = '\0';
	p = oidc_util_unescape_string(r, result);
	return apr_psprintf(r->pool, "https://%s", p);
}

/*
 * get the full path to the metadata file for a specified issuer and directory
 */
static const char *oidc_metadata_file_path(request_rec *r, oidc_cfg *cfg,
		const char *issuer, const char *type) {
	return apr_psprintf(r->pool, "%s/%s.%s", cfg->metadata_dir,
			oidc_metadata_issuer_to_filename(r, issuer), type);
}

/*
 * get the full path to the provider metadata file for a specified issuer
 */
static const char *oidc_metadata_provider_file_path(request_rec *r,
		const char *issuer) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer,
			OIDC_METADATA_SUFFIX_PROVIDER);
}

/*
 * get the full path to the client metadata file for a specified issuer
 */
static const char *oidc_metadata_client_file_path(request_rec *r,
		const char *issuer) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CLIENT);
}

/*
 * get the full path to the custom config file for a specified issuer
 */
static const char *oidc_metadata_conf_path(request_rec *r, const char *issuer) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CONF);
}

/*
 * get cache key for the JWKs file for a specified URI
 */
static const char *oidc_metadata_jwks_cache_key(request_rec *r,
		const char *jwks_uri) {
	return jwks_uri;
}

/*
 * read a JSON metadata file from disk
 */
static apr_byte_t oidc_metadata_file_read_json(request_rec *r, const char *path,
		json_t **result) {
	char *buf = NULL;

	/* read the file contents */
	if (oidc_util_file_read(r, path, r->pool, &buf) == FALSE)
		return FALSE;

	/* decode the JSON contents of the buffer */
	return oidc_util_decode_json_object(r, buf, result);
}

/*
 * check if the specified entry in metadata is a valid URI
 */
static apr_byte_t oidc_metadata_is_valid_uri(request_rec *r, const char *type,
		const char *issuer, json_t *json, const char *key, char **value,
		apr_byte_t is_mandatory) {

	char *s_value = NULL;
	oidc_json_object_get_string(r->pool, json, key, &s_value, NULL);

	if (s_value == NULL) {
		if (is_mandatory) {
			oidc_error(r,
					"%s (%s) JSON metadata does not contain the mandatory \"%s\" string entry",
					type, issuer, key);
		}
		return (!is_mandatory);
	}

	if (oidc_valid_http_url(r->pool, s_value) != NULL) {
		oidc_warn(r, "\"%s\" is not a valid http URL for key \"%s\"", s_value,
				key);
		return FALSE;
	}

	if (value)
		*value = s_value;

	return TRUE;
}

/*
 * check to see if JSON provider metadata is valid
 */
apr_byte_t oidc_metadata_provider_is_valid(request_rec *r, oidc_cfg *cfg,
		json_t *j_provider, const char *issuer) {

	/* get the "issuer" from the provider metadata and double-check that it matches what we looked for */
	char *s_issuer = NULL;
	oidc_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER,
			&s_issuer, NULL);
	if (s_issuer == NULL) {
		oidc_error(r,
				"provider (%s) JSON metadata did not contain an \"" OIDC_METADATA_ISSUER "\" string",
				issuer);
		return FALSE;
	}

	/* check that the issuer matches */
	if (issuer != NULL) {
		if (oidc_util_issuer_match(issuer, s_issuer) == FALSE) {
			oidc_error(r,
					"requested issuer (%s) does not match the \"" OIDC_METADATA_ISSUER "\" value in the provider metadata file: %s",
					issuer, s_issuer);
			return FALSE;
		}
	}

	/* verify that the provider supports the a flow that we implement */
	if (oidc_valid_string_in_array(r->pool, j_provider,
			OIDC_METADATA_RESPONSE_TYPES_SUPPORTED, oidc_valid_response_type, NULL,
			FALSE, NULL) != NULL) {
		if (json_object_get(j_provider,
				OIDC_METADATA_RESPONSE_TYPES_SUPPORTED) != NULL) {
			oidc_error(r,
					"could not find a supported response type in provider metadata (%s) for entry \"" OIDC_METADATA_RESPONSE_TYPES_SUPPORTED "\"",
					issuer);
			return FALSE;
		}
		oidc_warn(r,
				"could not find (required) supported response types  (\"" OIDC_METADATA_RESPONSE_TYPES_SUPPORTED "\") in provider metadata (%s); assuming that \"code\" flow is supported...",
				issuer);
	}

	/* verify that the provider supports a response_mode that we implement */
	if (oidc_valid_string_in_array(r->pool, j_provider,
			OIDC_METADATA_RESPONSE_MODES_SUPPORTED, oidc_valid_response_mode, NULL,
			TRUE, NULL) != NULL) {
		oidc_error(r,
				"could not find a supported response mode in provider metadata (%s) for entry \"" OIDC_METADATA_RESPONSE_MODES_SUPPORTED "\"",
				issuer);
		return FALSE;
	}

	/* check the required authorization endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer,
			j_provider,
			OIDC_METADATA_AUTHORIZATION_ENDPOINT, NULL, TRUE) == FALSE)
		return FALSE;

	/* check the optional token endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer,
			j_provider,
			OIDC_METADATA_TOKEN_ENDPOINT, NULL, FALSE) == FALSE)
		return FALSE;

	/* check the optional user info endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer,
			j_provider,
			OIDC_METADATA_USERINFO_ENDPOINT, NULL, FALSE) == FALSE)
		return FALSE;

	/* check the optional JWKs URI */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer,
			j_provider,
			OIDC_METADATA_JWKS_URI, NULL, FALSE) == FALSE)
		return FALSE;

	/* find out what type of authentication the token endpoint supports */
	if (oidc_valid_string_in_array(r->pool, j_provider,
			OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
			oidc_cfg_get_valid_endpoint_auth_function(cfg), NULL,
			TRUE, NULL) != NULL) {
		oidc_error(r,
				"could not find a supported token endpoint authentication method in provider metadata (%s) for entry \"" OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED "\"",
				issuer);
		return FALSE;
	}

	return TRUE;
}

/*
 * check to see if dynamically registered JSON client metadata is valid and has not expired
 */
static apr_byte_t oidc_metadata_client_is_valid(request_rec *r,
		json_t *j_client, const char *issuer) {

	char *str;

	/* get a handle to the client_id we need to use for this provider */
	str = NULL;
	oidc_json_object_get_string(r->pool, j_client, OIDC_METADATA_CLIENT_ID,
			&str, NULL);
	if (str == NULL) {
		oidc_error(r,
				"client (%s) JSON metadata did not contain a \"" OIDC_METADATA_CLIENT_ID "\" string",
				issuer);
		return FALSE;
	}

	/* get a handle to the client_secret we need to use for this provider */
	str = NULL;
	oidc_json_object_get_string(r->pool, j_client, OIDC_METADATA_CLIENT_SECRET,
			&str, NULL);
	if (str == NULL) {
		oidc_warn(r,
				"client (%s) JSON metadata did not contain a \"" OIDC_METADATA_CLIENT_SECRET "\" string",
				issuer);
	}

	/* the expiry timestamp from the JSON object */
	json_t *expires_at = json_object_get(j_client,
			OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT);
	if ((expires_at == NULL) || (!json_is_integer(expires_at))) {
		oidc_debug(r,
				"client (%s) metadata did not contain a \"" OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT "\" setting",
				issuer);
		/* assume that it never expires */
		return TRUE;
	}

	/* see if it is unrestricted */
	if (json_integer_value(expires_at) == 0) {
		oidc_debug(r,
				"client (%s) metadata never expires (" OIDC_METADATA_CLIENT_SECRET_EXPIRES_AT "=0)",
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
static apr_byte_t oidc_metadata_jwks_is_valid(request_rec *r,
		const oidc_jwks_uri_t *jwks_uri, json_t *j_jwks) {

	json_t *keys = json_object_get(j_jwks, OIDC_METADATA_KEYS);
	if ((keys == NULL) || (!json_is_array(keys))) {
		oidc_error(r,
				"JWKs JSON metadata obtained from URL \"%s\" did not contain a \"" OIDC_METADATA_KEYS "\" array",
				jwks_uri->url);
		return FALSE;
	}
	return TRUE;
}

/*
 * check is a specified JOSE feature is supported
 */
static apr_byte_t oidc_metadata_conf_jose_is_supported(request_rec *r,
		json_t *j_conf, const char *issuer, const char *key,
		oidc_valid_function_t valid_function) {
	char *s_value = NULL;
	oidc_json_object_get_string(r->pool, j_conf, key, &s_value, NULL);
	if (s_value == NULL)
		return TRUE;
	const char *rv = valid_function(r->pool, s_value);
	if (rv != NULL) {
		oidc_error(r,
				"(%s) JSON conf data has \"%s\" entry but it contains an unsupported algorithm or encryption type: \"%s\" (%s)",
				issuer, key, s_value, rv);
		return FALSE;
	}
	return TRUE;
}

/*
 * check to see if JSON configuration data is valid
 */
static apr_byte_t oidc_metadata_conf_is_valid(request_rec *r, json_t *j_conf,
		const char *issuer) {

	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG,
			oidc_valid_signed_response_alg) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG,
			oidc_valid_encrypted_response_alg) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC,
			oidc_valid_encrypted_response_enc) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG,
			oidc_valid_signed_response_alg) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG,
			oidc_valid_encrypted_response_alg) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC,
			oidc_valid_encrypted_response_enc) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * register the client with the OP using Dynamic Client Registration
 */
static apr_byte_t oidc_metadata_client_register(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, json_t **j_client, char **response) {

	/* assemble the JSON registration request */
	json_t *data = json_object();
	json_object_set_new(data, OIDC_METADATA_CLIENT_NAME,
			json_string(provider->client_name));
	json_object_set_new(data, OIDC_METADATA_REDIRECT_URIS,
			json_pack("[s]", oidc_get_redirect_uri_iss(r, cfg, provider)));

	json_t *response_types = json_array();
	apr_array_header_t *flows = oidc_proto_supported_flows(r->pool);
	int i;
	for (i = 0; i < flows->nelts; i++) {
		json_array_append_new(response_types,
				json_string(((const char**) flows->elts)[i]));
	}
	json_object_set_new(data, OIDC_METADATA_RESPONSE_TYPES, response_types);

	json_object_set_new(data, OIDC_METADATA_GRANT_TYPES,
			json_pack("[s, s, s]", "authorization_code", "implicit",
					"refresh_token"));

	if (provider->token_endpoint_auth != NULL) {
		json_object_set_new(data, OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHOD,
				json_string(provider->token_endpoint_auth));
	}

	if (provider->client_contact != NULL) {
		json_object_set_new(data, OIDC_METADATA_CONTACTS,
				json_pack("[s]", provider->client_contact));
	}

	if (provider->client_jwks_uri) {
		json_object_set_new(data, OIDC_METADATA_JWKS_URI,
				json_string(provider->client_jwks_uri));
	} else if (cfg->public_keys != NULL) {
		json_object_set_new(data, OIDC_METADATA_JWKS_URI,
				json_string(
						apr_psprintf(r->pool, "%s?%s=rsa",
								oidc_get_redirect_uri(r, cfg),
								OIDC_REDIRECT_URI_REQUEST_JWKS)));
	}

	if (provider->id_token_signed_response_alg != NULL) {
		json_object_set_new(data, OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG,
				json_string(provider->id_token_signed_response_alg));
	}
	if (provider->id_token_encrypted_response_alg != NULL) {
		json_object_set_new(data, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG,
				json_string(provider->id_token_encrypted_response_alg));
	}
	if (provider->id_token_encrypted_response_enc != NULL) {
		json_object_set_new(data, OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC,
				json_string(provider->id_token_encrypted_response_enc));
	}

	if (provider->userinfo_signed_response_alg != NULL) {
		json_object_set_new(data, OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG,
				json_string(provider->userinfo_signed_response_alg));
	}
	if (provider->userinfo_encrypted_response_alg != NULL) {
		json_object_set_new(data, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG,
				json_string(provider->userinfo_encrypted_response_alg));
	}
	if (provider->userinfo_encrypted_response_enc != NULL) {
		json_object_set_new(data, OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC,
				json_string(provider->userinfo_encrypted_response_enc));
	}

	json_object_set_new(data, OIDC_METADATA_INITIATE_LOGIN_URI,
			json_string(oidc_get_redirect_uri(r, cfg)));

	json_object_set_new(data, OIDC_METADATA_FRONTCHANNEL_LOGOUT_URI,
			json_string(
					apr_psprintf(r->pool, "%s?%s=%s",
							oidc_get_redirect_uri(r, cfg),
							OIDC_REDIRECT_URI_REQUEST_LOGOUT,
							OIDC_GET_STYLE_LOGOUT_PARAM_VALUE)));

	// TODO: may want to add backchannel_logout_session_required
	json_object_set_new(data, OIDC_METADATA_BACKCHANNEL_LOGOUT_URI,
			json_string(
					apr_psprintf(r->pool, "%s?%s=%s",
							oidc_get_redirect_uri(r, cfg),
							OIDC_REDIRECT_URI_REQUEST_LOGOUT,
							OIDC_BACKCHANNEL_STYLE_LOGOUT_PARAM_VALUE)));

	if (provider->token_binding_policy > OIDC_TOKEN_BINDING_POLICY_DISABLED) {
		json_object_set_new(data, OIDC_METADATA_IDTOKEN_BINDING_CNF,
				json_string(OIDC_CLAIM_CNF_TBH));
	}

	if (cfg->default_slo_url != NULL) {
		json_object_set_new(data, OIDC_METADATA_POST_LOGOUT_REDIRECT_URIS,
				json_pack("[s]", cfg->default_slo_url));
	}

	/* add any custom JSON in to the registration request */
	if (provider->registration_endpoint_json != NULL) {
		json_t *json = NULL;
		if (oidc_util_decode_json_object(r,
				provider->registration_endpoint_json, &json) == FALSE)
			return FALSE;
		oidc_util_json_merge(r, json, data);
		json_decref(json);
	}

	/* dynamically register the client with the specified parameters */
	if (oidc_util_http_post_json(r, provider->registration_endpoint_url, data,
			NULL, provider->registration_token, provider->ssl_validate_server, response,
			cfg->http_timeout_short, cfg->outgoing_proxy,
			oidc_dir_cfg_pass_cookies(r),
			NULL, NULL) == FALSE) {
		json_decref(data);
		return FALSE;
	}
	json_decref(data);

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, *response, j_client) == FALSE) {
		oidc_error(r,
				"JSON parsing of dynamic client registration response failed");
		return FALSE;
	}

	return TRUE;
}

/*
 * helper function to get the JWKs for the specified issuer
 */
static apr_byte_t oidc_metadata_jwks_retrieve_and_cache(request_rec *r,
		oidc_cfg *cfg, const oidc_jwks_uri_t *jwks_uri, json_t **j_jwks) {

	char *response = NULL;

	/* no valid provider metadata, get it at the specified URL with the specified parameters */
	if (oidc_util_http_get(r, jwks_uri->url, NULL, NULL,
			NULL, jwks_uri->ssl_validate_server, &response, cfg->http_timeout_long,
			cfg->outgoing_proxy, oidc_dir_cfg_pass_cookies(r), NULL,
			NULL) == FALSE)
		return FALSE;

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, response, j_jwks) == FALSE) {
		oidc_error(r, "JSON parsing of JWKs published at the jwks_uri failed");
		return FALSE;
	}

	/* check to see if it is valid metadata */
	if (oidc_metadata_jwks_is_valid(r, jwks_uri, *j_jwks) == FALSE)
		return FALSE;

	/* store the JWKs in the cache */
	oidc_cache_set_jwks(r, oidc_metadata_jwks_cache_key(r, jwks_uri->url),
			response,
			apr_time_now() + apr_time_from_sec(jwks_uri->refresh_interval));

	return TRUE;
}

/*
 * return JWKs for the specified issuer
 */
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg *cfg,
		const oidc_jwks_uri_t *jwks_uri, json_t **j_jwks, apr_byte_t *refresh) {

	oidc_debug(r, "enter, jwks_uri=%s, refresh=%d", jwks_uri->url, *refresh);

	/* see if we need to do a forced refresh */
	if (*refresh == TRUE) {
		oidc_debug(r, "doing a forced refresh of the JWKs from URI \"%s\"",
				jwks_uri->url);
		if (oidc_metadata_jwks_retrieve_and_cache(r, cfg, jwks_uri,
				j_jwks) == TRUE)
			return TRUE;
		// else: fallback on any cached JWKs
	}

	/* see if the JWKs is cached */
	char *value = NULL;
	oidc_cache_get_jwks(r, oidc_metadata_jwks_cache_key(r, jwks_uri->url),
			&value);

	if (value == NULL) {
		/* it is non-existing or expired: do a forced refresh */
		*refresh = TRUE;
		return oidc_metadata_jwks_retrieve_and_cache(r, cfg, jwks_uri, j_jwks);
	}

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, value, j_jwks) == FALSE) {
		oidc_error(r, "JSON parsing of cached JWKs data failed");
		return FALSE;
	}

	return TRUE;
}

/*
 * use OpenID Connect Discovery to get metadata for the specified issuer
 */
apr_byte_t oidc_metadata_provider_retrieve(request_rec *r, oidc_cfg *cfg,
		const char *issuer, const char *url, json_t **j_metadata,
		char **response) {

	/* get provider metadata from the specified URL with the specified parameters */
	if (oidc_util_http_get(r, url, NULL, NULL, NULL,
			cfg->provider.ssl_validate_server, response,
			cfg->http_timeout_short, cfg->outgoing_proxy,
			oidc_dir_cfg_pass_cookies(r),
			NULL, NULL) == FALSE)
		return FALSE;

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, *response, j_metadata) == FALSE) {
		oidc_error(r, "JSON parsing of retrieved Discovery document failed");
		return FALSE;
	}

	/* check to see if it is valid metadata */
	if (oidc_metadata_provider_is_valid(r, cfg, *j_metadata, issuer) == FALSE)
		return FALSE;

	/* all OK */
	return TRUE;
}

/*
 * see if we have provider metadata and check its validity
 * if not, use OpenID Connect Discovery to get it, check it and store it
 */
static apr_byte_t oidc_metadata_provider_get(request_rec *r, oidc_cfg *cfg,
		const char *issuer, json_t **j_provider, apr_byte_t allow_discovery) {

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
	if (cfg->provider_metadata_refresh_interval > 0) {

		have_cache = (apr_stat(&fi, provider_path, APR_FINFO_MTIME, r->pool)
				== APR_SUCCESS);

		if (have_cache == TRUE)
			use_cache = (apr_time_now()
					< fi.mtime
					+ apr_time_from_sec(
							cfg->provider_metadata_refresh_interval));

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
		oidc_warn(r,
				"no metadata found for the requested issuer (%s), and Discovery is not allowed",
				issuer);
		return FALSE;
	}

	/* assemble the URL to the .well-known OpenID metadata */
	const char *url = apr_psprintf(r->pool, "%s",
			((strstr(issuer, "http://") == issuer)
					|| (strstr(issuer, "https://") == issuer)) ?
							issuer : apr_psprintf(r->pool, "https://%s", issuer));
	url = apr_psprintf(r->pool, "%s%s.well-known/openid-configuration", url,
			url[strlen(url) - 1] != OIDC_CHAR_FORWARD_SLASH ?
					OIDC_STR_FORWARD_SLASH :
					"");

	/* get the metadata for the issuer using OpenID Connect Discovery and validate it */
	if (oidc_metadata_provider_retrieve(r, cfg, issuer, url, j_provider,
			&response) == FALSE) {

		oidc_debug(r,
				"could not retrieve provider metadata; have_cache: %s (data=%pp)",
				have_cache ? "yes" : "no", j_cache);

		/* see if we can use at least the cache that may have expired by now */
		if ((cfg->provider_metadata_refresh_interval > 0)
				&& (have_cache == TRUE) && (j_cache != NULL)) {

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
static apr_byte_t oidc_metadata_conf_get(request_rec *r, oidc_cfg *cfg,
		const char *issuer, json_t **j_conf) {

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
static apr_byte_t oidc_metadata_client_get(request_rec *r, oidc_cfg *cfg,
		const char *issuer, oidc_provider_t *provider, json_t **j_client) {

	/* get the full file path to the client metadata for this issuer */
	const char *client_path = oidc_metadata_client_file_path(r, issuer);

	/* see if we have valid metadata already, if so, return it */
	if (oidc_metadata_file_read_json(r, client_path, j_client) == TRUE) {

		/* if the client metadata is (still) valid, return it */
		if (oidc_metadata_client_is_valid(r, *j_client, issuer) == TRUE)
			return TRUE;
	}

	/* at this point we have no valid client metadata, see if there's a registration endpoint for this provider */
	if (provider->registration_endpoint_url == NULL) {
		oidc_error(r,
				"no (valid) client metadata exists for provider (%s) and provider JSON object did not contain a (valid) \"" OIDC_METADATA_REGISTRATION_ENDPOINT "\" string",
				issuer);
		return FALSE;
	}

	/* try and get client metadata by registering the client at the registration endpoint */
	char *response = NULL;
	if (oidc_metadata_client_register(r, cfg, provider, j_client,
			&response) == FALSE)
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
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg *cfg,
		apr_array_header_t **list) {
	apr_status_t rc;
	apr_dir_t *dir;
	apr_finfo_t fi;
	char s_err[128];

	oidc_debug(r, "enter");

	/* open the metadata directory */
	if ((rc = apr_dir_open(&dir, cfg->metadata_dir, r->pool)) != APR_SUCCESS) {
		oidc_error(r, "error opening metadata directory '%s' (%s)",
				cfg->metadata_dir, apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* allocate some space in the array that will hold the list of providers */
	*list = apr_array_make(r->pool, 5, sizeof(const char*));
	/* BTW: we could estimate the number in the array based on # directory entries... */

	/* loop over the entries in the provider metadata directory */
	while (apr_dir_read(&fi, APR_FINFO_NAME, dir) == APR_SUCCESS) {

		/* skip "." and ".." entries */
		if (fi.name[0] == OIDC_CHAR_DOT)
			continue;
		/* skip other non-provider entries */
		char *ext = strrchr(fi.name, OIDC_CHAR_DOT);
		if ((ext == NULL)
				|| (strcmp(++ext, OIDC_METADATA_SUFFIX_PROVIDER) != 0))
			continue;

		/* get the issuer from the filename */
		const char *issuer = oidc_metadata_filename_to_issuer(r, fi.name);

		/* get the provider and client metadata, do all checks and registration if possible */
		oidc_provider_t *provider = NULL;
		if (oidc_metadata_get(r, cfg, issuer, &provider, FALSE) == TRUE) {
			/* push the decoded issuer filename in to the array */
			*(const char**) apr_array_push(*list) = provider->issuer;
		}
	}

	/* we're done, cleanup now */
	apr_dir_close(dir);

	return TRUE;
}

/*
 * parse boolean value from JSON configuration
 */
static void oidc_metadata_parse_boolean(request_rec *r, json_t *json,
		const char *key, int *value, int default_value) {
	int int_value = 0;
	char *s_value = NULL;
	if (oidc_json_object_get_bool(r->pool, json, key, &int_value,
			default_value) == FALSE) {
		oidc_json_object_get_string(r->pool, json, key, &s_value,
				NULL);
		if (s_value != NULL) {
			const char *rv = oidc_parse_boolean(r->pool, s_value, &int_value);
			if (rv != NULL) {
				oidc_warn(r, "%s: %s", key, rv);
				int_value = default_value;
			}
		} else {
			oidc_json_object_get_int(r->pool, json, key, &int_value,
					default_value);
		}
	}
	*value = (int_value != 0) ? TRUE : FALSE;
}

/*
 * parse URL value from JSON configuration
 */
static void oidc_metadata_parse_url(request_rec *r, const char *type,
		const char *issuer, json_t *json, const char *key, char **value,
		const char *default_value) {
	if ((oidc_metadata_is_valid_uri(r, type, issuer, json, key, value,
			FALSE) == FALSE) || ((*value == NULL) && (default_value != NULL))) {
		*value = apr_pstrdup(r->pool, default_value);
	}
}

/*
 * parse the JSON provider metadata in to a oidc_provider_t struct but do not override values already set
 */
apr_byte_t oidc_metadata_provider_parse(request_rec *r, oidc_cfg *cfg,
		json_t *j_provider, oidc_provider_t *provider) {

	if (provider->issuer == NULL) {
		/* get the "issuer" from the provider metadata */
		oidc_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER,
				&provider->issuer, NULL);
	}

	if (provider->authorization_endpoint_url == NULL) {
		/* get a handle to the authorization endpoint */
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER,
				provider->issuer, j_provider,
				OIDC_METADATA_AUTHORIZATION_ENDPOINT,
				&provider->authorization_endpoint_url,
				NULL);
	}

	if (provider->token_endpoint_url == NULL) {
		/* get a handle to the token endpoint */
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER,
				provider->issuer, j_provider,
				OIDC_METADATA_TOKEN_ENDPOINT, &provider->token_endpoint_url,
				NULL);
	}

	if (provider->userinfo_endpoint_url == NULL) {
		/* get a handle to the user_info endpoint */
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER,
				provider->issuer, j_provider,
				OIDC_METADATA_USERINFO_ENDPOINT,
				&provider->userinfo_endpoint_url, NULL);
	}

	if (provider->revocation_endpoint_url == NULL) {
		/* get a handle to the token revocation endpoint */
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER,
				provider->issuer, j_provider,
				OIDC_METADATA_REVOCATION_ENDPOINT,
				&provider->revocation_endpoint_url, NULL);
	}

	if (provider->jwks_uri == NULL) {
		/* get a handle to the jwks_uri endpoint */
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER,
				provider->issuer, j_provider,
				OIDC_METADATA_JWKS_URI, &provider->jwks_uri,
				NULL);
	}

	if (provider->registration_endpoint_url == NULL) {
		/* get a handle to the client registration endpoint */
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER,
				provider->issuer, j_provider,
				OIDC_METADATA_REGISTRATION_ENDPOINT,
				&provider->registration_endpoint_url,
				NULL);
	}

	if (provider->check_session_iframe == NULL) {
		/* get a handle to the check session iframe */
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER,
				provider->issuer, j_provider,
				OIDC_METADATA_CHECK_SESSION_IFRAME,
				&provider->check_session_iframe, NULL);
	}

	if (provider->end_session_endpoint == NULL) {
		/* get a handle to the end session endpoint */
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER,
				provider->issuer, j_provider,
				OIDC_METADATA_END_SESSION_ENDPOINT,
				&provider->end_session_endpoint, NULL);
	}

	// TODO: default 0 should have a defined default that may be 1...
	if (provider->backchannel_logout_supported == OIDC_CONFIG_POS_INT_UNSET) {
		oidc_metadata_parse_boolean(r, j_provider,
				OIDC_METADATA_BACKCHANNEL_LOGOUT_SUPPORTED,
				&provider->backchannel_logout_supported, 0);
	}

	if (provider->token_endpoint_auth == NULL) {
		if (oidc_valid_string_in_array(r->pool, j_provider,
				OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
				oidc_cfg_get_valid_endpoint_auth_function(cfg),
				&provider->token_endpoint_auth,
				TRUE, OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC) != NULL) {
			oidc_error(r,
					"could not find a supported token endpoint authentication method in provider metadata (%s) for entry \"" OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED "\"",
					provider->issuer);
			return FALSE;
		}
	}

	return TRUE;
}

apr_byte_t oidc_oauth_metadata_provider_parse(request_rec *r, oidc_cfg *c,
		json_t *j_provider) {

	char *issuer = NULL;

	/* get the "issuer" from the provider metadata */
	oidc_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER,
			&issuer, NULL);

	// TOOD: should check for "if c->oauth.introspection_endpoint_url == NULL and
	//       allocate the string from the process/config pool
	//
	// https://github.com/zmartzone/mod_auth_openidc/commit/32321024ed5bdbc02ba8b5d61aabc4a4c3745c89
	// https://groups.google.com/forum/#!topic/mod_auth_openidc/o1K_1Yh-TQA

	/* get a handle to the introspection endpoint */
	oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer,
			j_provider,
			OIDC_METADATA_INTROSPECTION_ENDPOINT,
			&c->oauth.introspection_endpoint_url,
			NULL);

	/* get a handle to the jwks_uri endpoint */
	oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer,
			j_provider,
			OIDC_METADATA_JWKS_URI, &c->oauth.verify_jwks_uri,
			NULL);

	if (oidc_valid_string_in_array(r->pool, j_provider,
			OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED,
			oidc_cfg_get_valid_endpoint_auth_function(c),
			&c->oauth.introspection_endpoint_auth,
			TRUE, OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC) != NULL) {
		oidc_error(r,
				"could not find a supported token endpoint authentication method in provider metadata (%s) for entry \"" OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED "\"",
				issuer);
		return FALSE;
	}

	return TRUE;
}

/*
 * get a string value from a JSON object and see if it is a valid value according to the specified validation function
 */
void oidc_metadata_get_valid_string(request_rec *r, json_t *json,
		const char *key, oidc_valid_function_t valid_function, char **str_value,
		const char *default_str_value) {
	char *v = NULL;
	oidc_json_object_get_string(r->pool, json, key, &v, default_str_value);
	if (v != NULL) {
		const char *rv = valid_function(r->pool, v);
		if (rv != NULL) {
			oidc_warn(r,
					"string value %s for key \"%s\" is invalid: %s; using default: %s",
					v, key, rv, default_str_value);
			v = apr_pstrdup(r->pool, default_str_value);
		}
	}
	*str_value = v;
}

/*
 * get an integer value from a JSON object and see if it is a valid value according to the specified validation function
 */
void oidc_metadata_get_valid_int(request_rec *r, json_t *json, const char *key,
		oidc_valid_int_function_t valid_int_function, int *int_value,
		int default_int_value) {
	int v = 0;
	oidc_json_object_get_int(r->pool, json, key, &v, default_int_value);
	const char *rv = valid_int_function(r->pool, v);
	if (rv != NULL) {
		oidc_warn(r,
				"integer value %d for key \"%s\" is invalid: %s; using default: %d",
				v, key, rv, default_int_value);
		v = default_int_value;
	}
	*int_value = v;
}

void oidc_metadata_get_jwks(request_rec *r, json_t *json, const char *s_use,
		apr_hash_t **jwk_list) {
	json_t *keys = NULL;
	int i = 0;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	json_t *elem = NULL;
	const char *use = NULL;

	keys = json_object_get(json, OIDC_JWK_KEYS);
	if (keys == NULL)
		return;

	if (!json_is_array(keys)) {
		oidc_error(r,
				"trying to parse a list of JWKs but the value for key \"%s\" is not a JSON array",
				OIDC_JWK_KEYS);
		return;
	}

	for (i = 0; i < json_array_size(keys); i++) {

		elem = json_array_get(keys, i);

		use = json_string_value(json_object_get(elem, OIDC_JWK_USE));
		if ((use != NULL) && (strcmp(use, s_use) != 0)) {
			oidc_debug(r,
					"skipping key because of non-matching \"%s\": \"%s\" != \"%s\"",
					OIDC_JWK_USE, use, s_use);
			continue;
		}

		if (oidc_jwk_parse_json(r->pool, elem, &jwk, &err) == FALSE) {
			oidc_warn(r, "oidc_jwk_parse_json failed: %s",
					oidc_jose_e2s(r->pool, err));
			continue;
		}

		if (*jwk_list == NULL)
			*jwk_list = apr_hash_make(r->pool);
		apr_hash_set(*jwk_list, jwk->kid, APR_HASH_KEY_STRING, jwk);
	}
}

/*
 * parse the JSON conf metadata in to a oidc_provider_t struct
 */
apr_byte_t oidc_metadata_conf_parse(request_rec *r, oidc_cfg *cfg,
		json_t *j_conf, oidc_provider_t *provider) {

	oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_CONF, provider->issuer,
			j_conf,
			OIDC_METADATA_CLIENT_JWKS_URI, &provider->client_jwks_uri,
			cfg->provider.client_jwks_uri);

	oidc_metadata_get_jwks(r, j_conf,
			OIDC_JWK_SIG, &provider->client_signing_keys);
	oidc_metadata_get_jwks(r, j_conf,
			OIDC_JWK_ENC, &provider->client_encryption_keys);

	/* get the (optional) signing & encryption settings for the id_token */
	oidc_metadata_get_valid_string(r, j_conf,
			OIDC_METADATA_ID_TOKEN_SIGNED_RESPONSE_ALG, oidc_valid_signed_response_alg,
			&provider->id_token_signed_response_alg,
			cfg->provider.id_token_signed_response_alg);
	oidc_metadata_get_valid_string(r, j_conf,
			OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ALG,
			oidc_valid_encrypted_response_alg,
			&provider->id_token_encrypted_response_alg,
			cfg->provider.id_token_encrypted_response_alg);
	oidc_metadata_get_valid_string(r, j_conf,
			OIDC_METADATA_ID_TOKEN_ENCRYPTED_RESPONSE_ENC,
			oidc_valid_encrypted_response_enc,
			&provider->id_token_encrypted_response_enc,
			cfg->provider.id_token_encrypted_response_enc);

	/* get the (optional) signing & encryption settings for the userinfo response */
	oidc_metadata_get_valid_string(r, j_conf,
			OIDC_METADATA_USERINFO_SIGNED_RESPONSE_ALG, oidc_valid_signed_response_alg,
			&provider->userinfo_signed_response_alg,
			cfg->provider.userinfo_signed_response_alg);
	oidc_metadata_get_valid_string(r, j_conf,
			OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ALG,
			oidc_valid_encrypted_response_alg,
			&provider->userinfo_encrypted_response_alg,
			cfg->provider.userinfo_encrypted_response_alg);
	oidc_metadata_get_valid_string(r, j_conf,
			OIDC_METADATA_USERINFO_ENCRYPTED_RESPONSE_ENC,
			oidc_valid_encrypted_response_enc,
			&provider->userinfo_encrypted_response_enc,
			cfg->provider.userinfo_encrypted_response_enc);

	/* find out if we need to perform SSL server certificate validation on the token_endpoint and user_info_endpoint for this provider */
	oidc_metadata_parse_boolean(r, j_conf, OIDC_METADATA_SSL_VALIDATE_SERVER,
			&provider->ssl_validate_server, cfg->provider.ssl_validate_server);

	oidc_metadata_parse_boolean(r, j_conf, OIDC_METADATA_VALIDATE_ISSUER,
			&provider->validate_issuer, cfg->provider.validate_issuer);

	/* find out what scopes we should be requesting from this provider */
	// TODO: use the provider "scopes_supported" to mix-and-match with what we've configured for the client
	// TODO: check that "openid" is always included in the configured scopes, right?
	oidc_json_object_get_string(r->pool, j_conf, OIDC_METADATA_SCOPE,
			&provider->scope, cfg->provider.scope);

	/* see if we've got a custom JWKs refresh interval */
	oidc_metadata_get_valid_int(r, j_conf, OIDC_METADATA_JWKS_REFRESH_INTERVAL,
			oidc_valid_jwks_refresh_interval, &provider->jwks_refresh_interval,
			cfg->provider.jwks_refresh_interval);

	/* see if we've got a custom IAT slack interval */
	oidc_metadata_get_valid_int(r, j_conf, OIDC_METADATA_IDTOKEN_IAT_SLACK,
			oidc_valid_idtoken_iat_slack, &provider->idtoken_iat_slack,
			cfg->provider.idtoken_iat_slack);

	/* see if we've got a custom max session duration */
	oidc_metadata_get_valid_int(r, j_conf, OIDC_METADATA_SESSION_MAX_DURATION,
			oidc_valid_session_max_duration, &provider->session_max_duration,
			cfg->provider.session_max_duration);

	/* see if we've got custom authentication request parameter values */
	oidc_json_object_get_string(r->pool, j_conf,
			OIDC_METADATA_AUTH_REQUEST_PARAMS, &provider->auth_request_params,
			cfg->provider.auth_request_params);

	/* see if we've got custom token endpoint parameter values */
	oidc_json_object_get_string(r->pool, j_conf,
			OIDC_METADATA_TOKEN_ENDPOINT_PARAMS, &provider->token_endpoint_params,
			cfg->provider.token_endpoint_params);

	/* get the response mode to use */
	oidc_metadata_get_valid_string(r, j_conf, OIDC_METADATA_RESPONSE_MODE,
			oidc_valid_response_mode, &provider->response_mode,
			cfg->provider.response_mode);

	/* get the PKCE method to use */
	char *pkce_method = NULL;
	oidc_metadata_get_valid_string(r, j_conf, OIDC_METADATA_PKCE_METHOD,
			oidc_valid_pkce_method, &pkce_method,
			cfg->provider.pkce ? cfg->provider.pkce->method : NULL);
	if (pkce_method != NULL)
		oidc_parse_pkce_type(r->pool, pkce_method, &provider->pkce);

	/* get the client name */
	oidc_json_object_get_string(r->pool, j_conf, OIDC_METADATA_CLIENT_NAME,
			&provider->client_name, cfg->provider.client_name);

	/* get the client contact */
	oidc_json_object_get_string(r->pool, j_conf, OIDC_METADATA_CLIENT_CONTACT,
			&provider->client_contact, cfg->provider.client_contact);

	/* get the token endpoint authentication method */
	oidc_metadata_get_valid_string(r, j_conf, OIDC_METADATA_TOKEN_ENDPOINT_AUTH,
			oidc_cfg_get_valid_endpoint_auth_function(cfg),
			&provider->token_endpoint_auth, provider->token_endpoint_auth);

	/* get the dynamic client registration token */
	oidc_json_object_get_string(r->pool, j_conf,
			OIDC_METADATA_REGISTRATION_TOKEN, &provider->registration_token,
			cfg->provider.registration_token);

	/* see if we've got custom registration request parameter values */
	oidc_json_object_get_string(r->pool, j_conf,
			OIDC_METADATA_REGISTRATION_ENDPOINT_JSON,
			&provider->registration_endpoint_json,
			cfg->provider.registration_endpoint_json);

	/* get the flow to use; let the .client file set it otherwise (pass NULL as default value) */
	oidc_metadata_get_valid_string(r, j_conf, OIDC_METADATA_RESPONSE_TYPE,
			oidc_valid_response_type, &provider->response_type,
			NULL);

	/* see if we've got a custom user info refresh interval */
	oidc_metadata_get_valid_int(r, j_conf,
			OIDC_METADATA_USERINFO_REFRESH_INTERVAL,
			oidc_valid_userinfo_refresh_interval,
			&provider->userinfo_refresh_interval,
			cfg->provider.userinfo_refresh_interval);

	/* TLS client cert auth settings */
	oidc_json_object_get_string(r->pool, j_conf,
			OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_CERT,
			&provider->token_endpoint_tls_client_cert,
			cfg->provider.token_endpoint_tls_client_cert);
	oidc_json_object_get_string(r->pool, j_conf,
			OIDC_METADATA_TOKEN_ENDPOINT_TLS_CLIENT_KEY,
			&provider->token_endpoint_tls_client_key,
			cfg->provider.token_endpoint_tls_client_key);

	oidc_json_object_get_string(r->pool, j_conf, OIDC_METADATA_REQUEST_OBJECT,
			&provider->request_object, cfg->provider.request_object);

	/* see if we've got a custom userinfo endpoint token presentation method */
	char *method = NULL;
	oidc_metadata_get_valid_string(r, j_conf,
			OIDC_METADATA_USERINFO_TOKEN_METHOD, oidc_valid_userinfo_token_method,
			&method,
			NULL);
	if (method != NULL)
		oidc_parse_userinfo_token_method(r->pool, method,
				&provider->userinfo_token_method);
	else
		provider->userinfo_token_method = OIDC_USER_INFO_TOKEN_METHOD_HEADER;

	/* see if we've got a custom token binding policy */
	char *policy = NULL;
	oidc_metadata_get_valid_string(r, j_conf,
			OIDC_METADATA_TOKEN_BINDING_POLICY, oidc_valid_token_binding_policy,
			&policy,
			NULL);
	if (policy != NULL)
		oidc_parse_token_binding_policy(r->pool, policy,
				&provider->token_binding_policy);
	else
		provider->token_binding_policy = cfg->provider.token_binding_policy;

	/* see if we've got a custom HTTP method for passing the auth request */
	oidc_metadata_get_valid_string(r, j_conf, OIDC_METADATA_AUTH_REQUEST_METHOD,
			oidc_valid_auth_request_method, &method,
			NULL);
	if (method != NULL)
		oidc_parse_auth_request_method(r->pool, method,
				&provider->auth_request_method);
	else
		provider->auth_request_method = cfg->provider.auth_request_method;

	/* get the issuer specific redirect URI option */
	oidc_metadata_parse_boolean(r, j_conf,
			OIDC_METADATA_ISSUER_SPECIFIC_REDIRECT_URI,
			&provider->issuer_specific_redirect_uri,
			cfg->provider.issuer_specific_redirect_uri);

	return TRUE;
}

/*
 * parse the JSON client metadata in to a oidc_provider_t struct
 */
apr_byte_t oidc_metadata_client_parse(request_rec *r, oidc_cfg *cfg,
		json_t *j_client, oidc_provider_t *provider) {

	/* get a handle to the client_id we need to use for this provider */
	oidc_json_object_get_string(r->pool, j_client, OIDC_METADATA_CLIENT_ID,
			&provider->client_id, NULL);

	/* get a handle to the client_secret we need to use for this provider */
	oidc_json_object_get_string(r->pool, j_client, OIDC_METADATA_CLIENT_SECRET,
			&provider->client_secret, NULL);

	/* see if the token endpoint auth method defined in the client metadata overrides the provider one */
	char *token_endpoint_auth = NULL;
	oidc_json_object_get_string(r->pool, j_client,
			OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHOD, &token_endpoint_auth,
			NULL);

	if (token_endpoint_auth != NULL) {
		if (oidc_cfg_get_valid_endpoint_auth_function(cfg)(r->pool,
				token_endpoint_auth) == NULL) {
			provider->token_endpoint_auth = apr_pstrdup(r->pool,
					token_endpoint_auth);
		} else {
			oidc_warn(r,
					"unsupported client auth method \"%s\" in client metadata for entry \"" OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHOD "\"",
					token_endpoint_auth);
		}
	}

	/* determine the response type if not set by .conf */
	if (provider->response_type == NULL) {

		provider->response_type = cfg->provider.response_type;

		/* "response_types" is an array in the client metadata as by spec */
		json_t *j_response_types = json_object_get(j_client,
				OIDC_METADATA_RESPONSE_TYPES);
		if ((j_response_types != NULL) && (json_is_array(j_response_types))) {
			/* if there's an array we'll prefer the configured response_type if supported */
			if (oidc_util_json_array_has_value(r, j_response_types,
					provider->response_type) == FALSE) {
				/* if the configured response_type is not supported, we'll fallback to the first one that is listed */
				json_t *j_response_type = json_array_get(j_response_types, 0);
				if (json_is_string(j_response_type)) {
					provider->response_type = apr_pstrdup(r->pool,
							json_string_value(j_response_type));
				}
			}
		}
	}

	return TRUE;
}

/*
 * get the metadata for a specified issuer
 *
 * this fill the oidc_provider_t struct based on the issuer filename by reading and merging
 * contents from both provider metadata directory and client metadata directory
 */
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg *cfg, const char *issuer,
		oidc_provider_t **provider, apr_byte_t allow_discovery) {

	apr_byte_t rc = FALSE;

	/* pointers to the parsed JSON metadata */
	json_t *j_provider = NULL;
	json_t *j_client = NULL;
	json_t *j_conf = NULL;

	/* allocate space for a parsed-and-merged metadata struct */
	*provider = apr_pcalloc(r->pool, sizeof(oidc_provider_t));
	oidc_cfg_provider_init(*provider);

	/*
	 * read and parse the provider, conf and client metadata respectively
	 * NB: order is important here
	 */

	if (oidc_metadata_provider_get(r, cfg, issuer, &j_provider,
			allow_discovery) == FALSE)
		goto end;
	if (oidc_metadata_provider_parse(r, cfg, j_provider, *provider) == FALSE)
		goto end;

	if (oidc_metadata_conf_get(r, cfg, issuer, &j_conf) == FALSE)
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
