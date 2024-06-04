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

#include "cfg/dir.h"
#include "handle/handle.h"
#include "metadata.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"

/*
 * add extra configured authentication request parameters (global or per-path)
 */
static void oidc_proto_request_auth_params_add(request_rec *r, apr_table_t *params, const char *auth_request_params) {
	char *key = NULL;
	char *val = NULL;

	if (auth_request_params == NULL)
		return;

	while (*auth_request_params) {
		val = ap_getword(r->pool, &auth_request_params, OIDC_CHAR_AMP);
		if (val == NULL)
			break;
		key = ap_getword(r->pool, (const char **)&val, OIDC_CHAR_EQUAL);
		ap_unescape_url(key);
		ap_unescape_url(val);
		if (_oidc_strcmp(val, OIDC_STR_HASH) != 0) {
			apr_table_add(params, key, val);
			continue;
		}
		if (oidc_util_request_has_parameter(r, key) == TRUE) {
			oidc_util_request_parameter_get(r, key, &val);
			apr_table_add(params, key, val);
		}
	}
}

/*
 * send a Pushed Authorization Request (PAR) to the Provider
 */
static int oidc_proto_request_auth_push(request_rec *r, struct oidc_provider_t *provider, apr_table_t *params) {
	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	char *response = NULL, *basic_auth = NULL, *bearer_auth = NULL;
	char *request_uri = NULL;
	int expires_in = 0;
	char *authorization_request = NULL;
	json_t *j_result = NULL;
	int rv = HTTP_INTERNAL_SERVER_ERROR;
	const char *endpoint_url = oidc_cfg_provider_pushed_authorization_request_endpoint_url_get(provider);

	oidc_debug(r, "enter");

	if (endpoint_url == NULL) {
		oidc_error(r, "the Provider's OAuth 2.0 Pushed Authorization Request endpoint URL is not set, PAR "
			      "cannot be used");
		goto out;
	}

	/* add the token endpoint authentication credentials to the pushed authorization request */
	if (oidc_proto_token_endpoint_auth(
		r, cfg, oidc_cfg_provider_token_endpoint_auth_get(provider), oidc_cfg_provider_client_id_get(provider),
		oidc_cfg_provider_client_secret_get(provider), oidc_cfg_provider_client_keys_get(provider),
		oidc_cfg_provider_issuer_get(provider), params, NULL, &basic_auth, &bearer_auth) == FALSE)
		goto out;

	if (oidc_http_post_form(r, endpoint_url, params, basic_auth, bearer_auth, NULL,
				oidc_cfg_provider_ssl_validate_server_get(provider), &response, NULL,
				oidc_cfg_http_timeout_long_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
				oidc_cfg_dir_pass_cookies_get(r), NULL, NULL, NULL) == FALSE)
		goto out;

	/* check for errors, the response itself will have been logged already */
	if (oidc_util_decode_json_and_check_error(r, response, &j_result) == FALSE)
		goto out;

	/* get the request_uri from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_REQUEST_URI, &request_uri, NULL);

	/* get the expires_in value from the parsed response */
	oidc_util_json_object_get_int(j_result, OIDC_PROTO_EXPIRES_IN, &expires_in, 60);

	/* assemble the resulting authentication request and redirect */
	apr_table_clear(params);
	apr_table_setn(params, OIDC_PROTO_CLIENT_ID, oidc_cfg_provider_client_id_get(provider));
	apr_table_setn(params, OIDC_PROTO_REQUEST_URI, request_uri);
	authorization_request =
	    oidc_http_query_encoded_url(r, oidc_cfg_provider_authorization_endpoint_url_get(provider), params);
	oidc_http_hdr_out_location_set(r, authorization_request);
	rv = HTTP_MOVED_TEMPORARILY;

out:

	if (j_result)
		json_decref(j_result);

	return rv;
}

/* context structure for encoding parameters */
typedef struct oidc_proto_form_post_ctx_t {
	request_rec *r;
	const char *html_body;
} oidc_proto_form_post_ctx_t;

/*
 * add a key/value pair post parameter
 */
static int oidc_proto_request_form_post_param_add(void *rec, const char *key, const char *value) {
	oidc_proto_form_post_ctx_t *ctx = (oidc_proto_form_post_ctx_t *)rec;
	oidc_debug(ctx->r, "processing: %s=%s", key, value);
	ctx->html_body =
	    apr_psprintf(ctx->r->pool, "%s      <input type=\"hidden\" name=\"%s\" value=\"%s\">\n", ctx->html_body,
			 oidc_util_html_escape(ctx->r->pool, key), oidc_util_html_escape(ctx->r->pool, value));
	return 1;
}

/*
 * make the browser POST parameters through Javascript auto-submit
 */
static int oidc_proto_request_html_post(request_rec *r, const char *url, apr_table_t *params) {

	oidc_debug(r, "enter");

	const char *html_body = apr_psprintf(r->pool,
					     "    <p>Submitting Authentication Request...</p>\n"
					     "    <form method=\"post\" action=\"%s\">\n"
					     "      <p>\n",
					     url);

	oidc_proto_form_post_ctx_t data = {r, html_body};
	apr_table_do(oidc_proto_request_form_post_param_add, &data, params, NULL);

	html_body = apr_psprintf(r->pool, "%s%s", data.html_body,
				 "      </p>\n"
				 "    </form>\n");

	return oidc_util_html_send(r, "Submitting...", NULL, "document.forms[0].submit", html_body, OK);
}

#define OIDC_REQUEST_OJBECT_COPY_FROM_REQUEST "copy_from_request"
#define OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST "copy_and_remove_from_request"
#define OIDC_REQUEST_OJBECT_TTL "ttl"
#define OIDC_REQUEST_OBJECT_TTL_DEFAULT 30

/*
 * indicates whether a request parameter from the authorization request needs to be
 * copied and/or deleted to/from the protected request object based on the settings specified
 * in the "copy_from_request"/"copy_and_remove_from_request" JSON array in the request object
 */
static apr_byte_t oidc_proto_request_uri_param_needs_action(json_t *request_object_config, const char *parameter_name,
							    const char *action) {
	json_t *copy_from_request = json_object_get(request_object_config, action);
	size_t index = 0;
	while (index < json_array_size(copy_from_request)) {
		json_t *value = json_array_get(copy_from_request, index);
		if ((json_is_string(value)) && (_oidc_strcmp(json_string_value(value), parameter_name) == 0)) {
			return TRUE;
		}
		index++;
	}
	return FALSE;
}

/* context structure for copying request parameters */
typedef struct oidc_request_uri_copy_req_ctx_t {
	request_rec *r;
	json_t *request_object_config;
	oidc_jwt_t *request_object;
	apr_table_t *params2;
} oidc_request_uri_copy_req_ctx_t;

/*
 * copy a parameter key/value from the authorizion request to the
 * request object if the configuration setting says to include it
 */
static int oidc_request_uri_copy_from_request(void *rec, const char *name, const char *value) {
	oidc_request_uri_copy_req_ctx_t *ctx = (oidc_request_uri_copy_req_ctx_t *)rec;

	oidc_debug(ctx->r, "processing name: %s, value: %s", name, value);

	if (oidc_proto_request_uri_param_needs_action(ctx->request_object_config, name,
						      OIDC_REQUEST_OJBECT_COPY_FROM_REQUEST) ||
	    oidc_proto_request_uri_param_needs_action(ctx->request_object_config, name,
						      OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST)) {
		json_t *result = NULL;
		json_error_t json_error;
		result = json_loads(value, JSON_DECODE_ANY, &json_error);
		if (result == NULL)
			/* assume string */
			result = json_string(value);
		if (result) {
			json_object_set_new(ctx->request_object->payload.value.json, name, json_deep_copy(result));
			json_decref(result);
		}

		if (oidc_proto_request_uri_param_needs_action(ctx->request_object_config, name,
							      OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST)) {
			apr_table_set(ctx->params2, name, name);
		}
	}

	return 1;
}

/*
 * delete a parameter key/value from the authorizion request if the configuration setting says to remove it
 */
static int oidc_request_uri_delete_from_request(void *rec, const char *name, const char *value) {
	oidc_request_uri_copy_req_ctx_t *ctx = (oidc_request_uri_copy_req_ctx_t *)rec;

	oidc_debug(ctx->r, "deleting from query parameters: name: %s, value: %s", name, value);

	if (oidc_proto_request_uri_param_needs_action(ctx->request_object_config, name,
						      OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST)) {
		apr_table_unset(ctx->params2, name);
	}

	return 1;
}

/*
 * obtain the public key for a provider to encrypt the request object with
 */
static apr_byte_t oidc_request_uri_encryption_jwk_by_type(request_rec *r, oidc_cfg_t *cfg,
							  struct oidc_provider_t *provider, int key_type,
							  oidc_jwk_t **jwk) {

	oidc_jose_error_t err;
	json_t *j_jwks = NULL;
	apr_byte_t force_refresh = TRUE;
	oidc_jwk_t *key = NULL;
	char *jwk_json = NULL;
	int i = 0;

	/* TODO: forcefully refresh now; we may want to relax that */
	oidc_metadata_jwks_get(r, cfg, oidc_cfg_provider_jwks_uri_get(provider),
			       oidc_cfg_provider_ssl_validate_server_get(provider), &j_jwks, &force_refresh);

	if (j_jwks == NULL) {
		oidc_error(r, "could not retrieve JSON Web Keys");
		return FALSE;
	}

	json_t *keys = json_object_get(j_jwks, OIDC_JOSE_JWKS_KEYS_STR);
	if ((keys == NULL) || !(json_is_array(keys))) {
		oidc_error(r, "\"%s\" array element is not a JSON array", OIDC_JOSE_JWKS_KEYS_STR);
		return FALSE;
	}

	/* walk the set of published keys to find the first that has a matching type */
	for (i = 0; i < json_array_size(keys); i++) {

		json_t *elem = json_array_get(keys, i);

		const char *use = json_string_value(json_object_get(elem, OIDC_JOSE_JWK_USE_STR));
		if ((use != NULL) && (_oidc_strcmp(use, OIDC_JOSE_JWK_ENC_STR) != 0)) {
			oidc_debug(r, "skipping key because of non-matching \"%s\": \"%s\"", OIDC_JOSE_JWK_USE_STR,
				   use);
			continue;
		}

		if (oidc_jwk_parse_json(r->pool, elem, &key, &err) == FALSE) {
			oidc_warn(r, "oidc_jwk_parse_json failed: %s", oidc_jose_e2s(r->pool, err));
			continue;
		}

		if (key_type == key->kty) {
			oidc_jwk_to_json(r->pool, key, &jwk_json, &err);
			oidc_debug(r, "found matching encryption key type for key: %s", jwk_json);
			*jwk = key;
			break;
		}

		oidc_jwk_destroy(key);
	}

	/* no need anymore for the parsed json_t contents, release the it */
	json_decref(j_jwks);

	return (*jwk != NULL);
}

/*
 * generate a request object
 */
static char *oidc_request_uri_request_object(request_rec *r, struct oidc_provider_t *provider,
					     json_t *request_object_config, apr_table_t *params, int ttl) {

	oidc_jwk_t *sjwk = NULL;
	int jwk_needs_destroy = 0;

	oidc_debug(r, "enter");

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	/* create the request object value */
	oidc_jwt_t *request_object = oidc_jwt_new(r->pool, TRUE, TRUE);

	/* set basic values: iss, aud, iat and exp */
	json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_ISS,
			    json_string(oidc_cfg_provider_client_id_get(provider)));
	json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_AUD,
			    json_string(oidc_cfg_provider_issuer_get(provider)));
	json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_IAT,
			    json_integer(apr_time_sec(apr_time_now())));
	json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_EXP,
			    json_integer(apr_time_sec(apr_time_now()) + ttl));

	/* add static values to the request object as configured in the .conf file; may override iss/aud */
	oidc_util_json_merge(r, json_object_get(request_object_config, "static"), request_object->payload.value.json);

	/* copy parameters from the authorization request as configured in the .conf file */
	apr_table_t *delete_from_query_params = apr_table_make(r->pool, 0);
	oidc_request_uri_copy_req_ctx_t data = {r, request_object_config, request_object, delete_from_query_params};
	apr_table_do(oidc_request_uri_copy_from_request, &data, params, NULL);

	/* delete parameters from the query parameters of the authorization request as configured in the .conf file */
	data.params2 = params;
	apr_table_do(oidc_request_uri_delete_from_request, &data, delete_from_query_params, NULL);

	/* debug logging */
	oidc_debug(r, "request object: %s",
		   oidc_util_encode_json_object(r, request_object->payload.value.json, JSON_COMPACT));

	char *serialized_request_object = NULL;
	oidc_jose_error_t err;
	int kty = -1;

	/* get the crypto settings from the configuration */
	json_t *crypto = json_object_get(request_object_config, "crypto");
	oidc_util_json_object_get_string(r->pool, crypto, "sign_alg", &request_object->header.alg, "none");

	/* see if we need to sign the request object */
	if (_oidc_strcmp(request_object->header.alg, "none") != 0) {

		sjwk = NULL;
		jwk_needs_destroy = 0;
		kty = oidc_jwt_alg2kty(request_object);
		switch (kty) {
		case CJOSE_JWK_KTY_RSA:
		case CJOSE_JWK_KTY_EC:
			if ((oidc_cfg_provider_client_keys_get(provider) != NULL) ||
			    (oidc_cfg_private_keys_get(cfg) != NULL)) {
				sjwk = oidc_cfg_provider_client_keys_get(provider)
					   ? oidc_util_key_list_first(oidc_cfg_provider_client_keys_get(provider), kty,
								      OIDC_JOSE_JWK_SIG_STR)
					   : oidc_util_key_list_first(oidc_cfg_private_keys_get(cfg), kty,
								      OIDC_JOSE_JWK_SIG_STR);
				if (sjwk && sjwk->kid)
					request_object->header.kid = apr_pstrdup(r->pool, sjwk->kid);
				else
					oidc_error(r, "could not find a usable signing key");
			} else {
				oidc_error(r, "no global or per-provider private keys have been configured to use for "
					      "request object signing");
			}
			break;
		case CJOSE_JWK_KTY_OCT:
			oidc_util_create_symmetric_key(r, oidc_cfg_provider_client_secret_get(provider), 0, NULL, FALSE,
						       &sjwk);
			jwk_needs_destroy = 1;
			break;
		default:
			oidc_error(r, "unsupported signing algorithm, no key type for algorithm: %s",
				   request_object->header.alg);
			break;
		}

		if (sjwk == NULL) {
			oidc_jwt_destroy(request_object);
			json_decref(request_object_config);
			return NULL;
		}

		if (oidc_jwt_sign(r->pool, request_object, sjwk, FALSE, &err) == FALSE) {
			oidc_error(r, "signing Request Object failed: %s", oidc_jose_e2s(r->pool, err));
			if (jwk_needs_destroy)
				oidc_jwk_destroy(sjwk);
			oidc_jwt_destroy(request_object);
			json_decref(request_object_config);
			return NULL;
		}

		if (jwk_needs_destroy)
			oidc_jwk_destroy(sjwk);
	}

	oidc_jwt_t *jwe = oidc_jwt_new(r->pool, TRUE, FALSE);
	if (jwe == NULL) {
		oidc_error(r, "creating JWE failed");
		oidc_jwt_destroy(request_object);
		json_decref(request_object_config);
		return NULL;
	}

	oidc_util_json_object_get_string(r->pool, crypto, "crypt_alg", &jwe->header.alg, NULL);
	oidc_util_json_object_get_string(r->pool, crypto, "crypt_enc", &jwe->header.enc, NULL);

	char *cser = oidc_jwt_serialize(r->pool, request_object, &err);

	/* see if we need to encrypt the request object */
	if (jwe->header.alg != NULL) {

		oidc_jwk_t *ejwk = NULL;

		switch (oidc_jwt_alg2kty(jwe)) {
		case CJOSE_JWK_KTY_RSA:
		case CJOSE_JWK_KTY_EC:
			oidc_request_uri_encryption_jwk_by_type(r, cfg, provider, oidc_jwt_alg2kty(jwe), &ejwk);
			break;
		case CJOSE_JWK_KTY_OCT:
			oidc_util_create_symmetric_key(r, oidc_cfg_provider_client_secret_get(provider),
						       oidc_alg2keysize(jwe->header.alg), OIDC_JOSE_ALG_SHA256, FALSE,
						       &ejwk);
			break;
		default:
			oidc_error(r, "unsupported encryption algorithm, no key type for algorithm: %s",
				   request_object->header.alg);
			break;
		}

		if (ejwk == NULL) {
			oidc_jwt_destroy(jwe);
			oidc_jwt_destroy(request_object);
			json_decref(request_object_config);
			return NULL;
		}

		if (jwe->header.enc == NULL)
			jwe->header.enc = apr_pstrdup(r->pool, CJOSE_HDR_ENC_A128CBC_HS256);

		if (ejwk->kid != NULL)
			jwe->header.kid = ejwk->kid;

		if (oidc_jwt_encrypt(r->pool, jwe, ejwk, cser, _oidc_strlen(cser) + 1, &serialized_request_object,
				     &err) == FALSE) {
			oidc_error(r, "encrypting JWT failed: %s", oidc_jose_e2s(r->pool, err));
			oidc_jwk_destroy(ejwk);
			oidc_jwt_destroy(jwe);
			oidc_jwt_destroy(request_object);
			json_decref(request_object_config);
			return NULL;
		}

		oidc_jwk_destroy(ejwk);

	} else {

		/* should be sign only or "none" */
		serialized_request_object = cser;
	}

	oidc_jwt_destroy(request_object);
	oidc_jwt_destroy(jwe);
	json_decref(request_object_config);

	oidc_debug(r, "serialized request object JWT header = \"%s\"",
		   oidc_proto_peek_jwt_header(r, serialized_request_object, NULL, NULL, NULL));
	oidc_debug(r, "serialized request object = \"%s\"", serialized_request_object);

	return serialized_request_object;
}

/*
 * generate a request object and pass it by reference in the authorization request
 */
static char *oidc_proto_request_uri_create(request_rec *r, struct oidc_provider_t *provider,
					   json_t *request_object_config, const char *redirect_uri, apr_table_t *params,
					   int ttl) {

	oidc_debug(r, "enter");

	/* see if we need to override the resolver URL, mostly for test purposes */
	char *resolver_url = NULL;
	if (json_object_get(request_object_config, "url") != NULL)
		resolver_url = apr_pstrdup(r->pool, json_string_value(json_object_get(request_object_config, "url")));
	else
		resolver_url = apr_pstrdup(r->pool, redirect_uri);

	char *serialized_request_object =
	    oidc_request_uri_request_object(r, provider, request_object_config, params, ttl);

	/* generate a temporary reference, store the request object in the cache and generate a Request URI that
	 * references it */
	char *request_uri = NULL;
	if (serialized_request_object != NULL) {
		char *request_ref = NULL;
		if (oidc_util_generate_random_string(r, &request_ref, 16) == TRUE) {
			oidc_cache_set_request_uri(r, request_ref, serialized_request_object,
						   apr_time_now() + apr_time_from_sec(ttl));
			request_uri = apr_psprintf(r->pool, "%s?%s=%s", resolver_url, OIDC_PROTO_REQUEST_URI,
						   oidc_http_url_encode(r, request_ref));
		}
	}

	return request_uri;
}

/*
 * Generic function to generate request/request_object parameter with value
 */
static void oidc_proto_request_uri_request_param_add(request_rec *r, struct oidc_provider_t *provider,
						     const char *redirect_uri, apr_table_t *params) {

	/* parse the request object configuration from a string in to a JSON structure */
	json_t *request_object_config = NULL;
	if (oidc_util_decode_json_object(r, oidc_cfg_provider_request_object_get(provider), &request_object_config) ==
	    FALSE)
		return;

	/* request_uri is used as default parameter for sending Request Object */
	char *parameter = OIDC_PROTO_REQUEST_URI;

	/* get request_object_type parameter from config */
	json_t *request_object_type = json_object_get(request_object_config, "request_object_type");
	if (request_object_type != NULL) {
		const char *request_object_type_str = json_string_value(request_object_type);
		if (request_object_type_str == NULL) {
			oidc_error(r, "Value of request_object_type in request_object config is not a string");
			return;
		}

		/* ensure parameter variable to have a valid value */
		if (_oidc_strcmp(request_object_type_str, OIDC_PROTO_REQUEST_OBJECT) == 0) {
			parameter = OIDC_PROTO_REQUEST_OBJECT;
		} else if (_oidc_strcmp(request_object_type_str, OIDC_PROTO_REQUEST_URI) != 0) {
			oidc_error(r, "Bad request_object_type in config: %s", request_object_type_str);
			return;
		}
	}

	/* create request value */
	char *value = NULL;
	int ttl = OIDC_REQUEST_OBJECT_TTL_DEFAULT;
	oidc_util_json_object_get_int(request_object_config, "ttl", &ttl, OIDC_REQUEST_OBJECT_TTL_DEFAULT);
	if (_oidc_strcmp(parameter, OIDC_PROTO_REQUEST_URI) == 0) {
		/* parameter is "request_uri" */
		value = oidc_proto_request_uri_create(r, provider, request_object_config, redirect_uri, params, ttl);
		apr_table_set(params, OIDC_PROTO_REQUEST_URI, value);
	} else {
		/* parameter is "request" */
		value = oidc_request_uri_request_object(r, provider, request_object_config, params, ttl);
		apr_table_set(params, OIDC_PROTO_REQUEST_OBJECT, value);
	}
}

/*
 * send an OpenID Connect authorization request to the specified provider
 */
int oidc_proto_authorization_request(request_rec *r, struct oidc_provider_t *provider, const char *login_hint,
				     const char *redirect_uri, const char *state, oidc_proto_state_t *proto_state,
				     const char *id_token_hint, const char *code_challenge,
				     const char *auth_request_params, const char *path_scope) {

	/* log some stuff */
	oidc_debug(r,
		   "enter, issuer=%s, redirect_uri=%s, state=%s, proto_state=%s, code_challenge=%s, "
		   "auth_request_params=%s, path_scope=%s",
		   oidc_cfg_provider_issuer_get(provider), redirect_uri, state,
		   oidc_proto_state_to_string(r, proto_state), code_challenge, auth_request_params, path_scope);

	int rv = OK;
	char *authorization_request = NULL;

	/* assemble parameters to call the token endpoint for validation */
	apr_table_t *params = apr_table_make(r->pool, 4);

	/* add the response type */
	apr_table_setn(params, OIDC_PROTO_RESPONSE_TYPE, oidc_proto_state_get_response_type(proto_state));

	/* concat the per-path scopes with the per-provider scopes */
	const char *scope = oidc_cfg_provider_scope_get(provider);
	if (path_scope != NULL)
		scope = ((scope != NULL) && (_oidc_strcmp(scope, "") != 0))
			    ? apr_pstrcat(r->pool, scope, OIDC_STR_SPACE, path_scope, NULL)
			    : path_scope;

	if (scope != NULL) {
		if (!oidc_util_spaced_string_contains(r->pool, scope, OIDC_PROTO_SCOPE_OPENID)) {
			oidc_warn(r,
				  "the configuration for the \"%s\" parameter does not include the \"%s\" scope, your "
				  "provider may not return an \"id_token\": %s",
				  OIDC_PROTO_SCOPE, OIDC_PROTO_SCOPE_OPENID, scope);
		}
		apr_table_setn(params, OIDC_PROTO_SCOPE, scope);
	}

	if (oidc_cfg_provider_client_id_get(provider) == NULL) {
		oidc_error(r, "no Client ID set for the provider: perhaps you are accessing an endpoint protected with "
			      "\"AuthType openid-connect\" instead of \"AuthType oauth20\"?)");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* add the client ID */
	apr_table_setn(params, OIDC_PROTO_CLIENT_ID, oidc_cfg_provider_client_id_get(provider));

	/* add the state */
	apr_table_setn(params, OIDC_PROTO_STATE, state);

	/* add the redirect uri */
	apr_table_setn(params, OIDC_PROTO_REDIRECT_URI, redirect_uri);

	/* add the nonce if set */
	const char *nonce = oidc_proto_state_get_nonce(proto_state);
	if (nonce != NULL)
		apr_table_setn(params, OIDC_PROTO_NONCE, nonce);

	/* add PKCE code challenge if set */
	if ((code_challenge != NULL) && (oidc_cfg_provider_pkce_get(provider) != NULL)) {
		apr_table_setn(params, OIDC_PROTO_CODE_CHALLENGE, code_challenge);
		apr_table_setn(params, OIDC_PROTO_CODE_CHALLENGE_METHOD, oidc_cfg_provider_pkce_get(provider)->method);
	}

	/* add the response_mode if explicitly set */
	const char *response_mode = oidc_proto_state_get_response_mode(proto_state);
	if (response_mode != NULL)
		apr_table_setn(params, OIDC_PROTO_RESPONSE_MODE, response_mode);

	/* add the login_hint if provided */
	if (login_hint != NULL)
		apr_table_setn(params, OIDC_PROTO_LOGIN_HINT, login_hint);

	/* add the id_token_hint if provided */
	if (id_token_hint != NULL)
		apr_table_setn(params, OIDC_PROTO_ID_TOKEN_HINT, id_token_hint);

	/* add the prompt setting if provided (e.g. "none" for no-GUI checks) */
	const char *prompt = oidc_proto_state_get_prompt(proto_state);
	if (prompt != NULL)
		apr_table_setn(params, OIDC_PROTO_PROMPT, prompt);

	/* add any statically configured custom authorization request parameters */
	oidc_proto_request_auth_params_add(r, params, oidc_cfg_provider_auth_request_params_get(provider));

	/* add any dynamically configured custom authorization request parameters */
	oidc_proto_request_auth_params_add(r, params, auth_request_params);

	/* add request parameter (request or request_uri) if set */
	if (oidc_cfg_provider_request_object_get(provider) != NULL)
		oidc_proto_request_uri_request_param_add(r, provider, redirect_uri, params);

	/* send the full authentication request via POST or GET */
	if (oidc_cfg_provider_auth_request_method_get(provider) == OIDC_AUTH_REQUEST_METHOD_POST) {

		/* construct a HTML POST auto-submit page with the authorization request parameters */
		rv =
		    oidc_proto_request_html_post(r, oidc_cfg_provider_authorization_endpoint_url_get(provider), params);

	} else if (oidc_cfg_provider_auth_request_method_get(provider) == OIDC_AUTH_REQUEST_METHOD_PAR) {

		rv = oidc_proto_request_auth_push(r, provider, params);

	} else if (oidc_cfg_provider_auth_request_method_get(provider) == OIDC_AUTH_REQUEST_METHOD_GET) {

		/* construct the full authorization request URL */
		authorization_request =
		    oidc_http_query_encoded_url(r, oidc_cfg_provider_authorization_endpoint_url_get(provider), params);

		// TODO: should also enable this when using the POST binding for the auth request
		/* see if we need to preserve POST parameters through Javascript/HTML5 storage */
		if (oidc_response_post_preserve_javascript(r, authorization_request, NULL, NULL) == FALSE) {

			/* add the redirect location header */
			oidc_http_hdr_out_location_set(r, authorization_request);

			/* and tell Apache to return an HTTP Redirect (302) message */
			rv = HTTP_MOVED_TEMPORARILY;

		} else {

			/* signal this to the content handler */
			oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_AUTHN, "");
			r->user = "";
			rv = OK;
		}

	} else {
		oidc_error(r, "oidc_cfg_provider_auth_request_method_get(provider) set to an unknown value: %d",
			   oidc_cfg_provider_auth_request_method_get(provider));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* cleanup */
	oidc_proto_state_destroy(proto_state);

	/* no cache */
	oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_CACHE_CONTROL, "no-cache, no-store, max-age=0");

	/* log our exit code */
	oidc_debug(r, "return: %d", rv);

	return rv;
}
