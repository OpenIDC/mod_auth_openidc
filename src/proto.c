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
 * Copyright (C) 2017-2018 ZmartZone IAM
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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include "mod_auth_openidc.h"
#include "parse.h"

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/*
 * generate a random string value value of a specified length
 */
static apr_byte_t oidc_proto_generate_random_string(request_rec *r,
		char **output, int len) {
	unsigned char *bytes = apr_pcalloc(r->pool, len);
	if (apr_generate_random_bytes(bytes, len) != APR_SUCCESS) {
		oidc_error(r, "apr_generate_random_bytes returned an error");
		return FALSE;
	}
	if (oidc_base64url_encode(r, output, (const char *) bytes, len, TRUE)
			<= 0) {
		oidc_error(r, "oidc_base64url_encode returned an error");
		return FALSE;
	}
	return TRUE;
}

#define OIDC_REQUEST_OJBECT_COPY_FROM_REQUEST "copy_from_request"
#define OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST "copy_and_remove_from_request"

/*
 * indicates wether a request parameter from the authorization request needs to be
 * copied and/or deleted to/from the protected request object based on the settings specified
 * in the "copy_from_request"/"copy_and_remove_from_request" JSON array in the request object
 */
static apr_byte_t oidc_proto_param_needs_action(json_t *request_object_config,
		const char *parameter_name, const char *action) {
	json_t *copy_from_request = json_object_get(request_object_config, action);
	size_t index = 0;
	while (index < json_array_size(copy_from_request)) {
		json_t *value = json_array_get(copy_from_request, index);
		if ((json_is_string(value))
				&& (apr_strnatcmp(json_string_value(value), parameter_name) == 0)) {
			return TRUE;
		}
		index++;
	}
	return FALSE;
}

/* context structure for copying request parameters */
typedef struct oidc_proto_copy_req_ctx_t {
	request_rec *r;
	json_t *request_object_config;
	oidc_jwt_t *request_object;
	apr_table_t *params2;
} oidc_proto_copy_req_ctx_t;

/*
 * copy a parameter key/value from the authorizion request to the
 * request object if the configuration setting says to include it
 */
static int oidc_proto_copy_from_request(void* rec, const char* name,
		const char* value) {
	oidc_proto_copy_req_ctx_t *ctx = (oidc_proto_copy_req_ctx_t *) rec;

	oidc_debug(ctx->r, "processing name: %s, value: %s", name, value);

	if (oidc_proto_param_needs_action(ctx->request_object_config, name,
			OIDC_REQUEST_OJBECT_COPY_FROM_REQUEST)
			|| oidc_proto_param_needs_action(ctx->request_object_config, name,
					OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST)) {
		json_t *result = NULL;
		json_error_t json_error;
		result = json_loads(value, JSON_DECODE_ANY, &json_error);
		if (result == NULL)
			/* assume string */
			result = json_string(value);
		if (result) {
			json_object_set_new(ctx->request_object->payload.value.json, name,
					json_deep_copy(result));
			json_decref(result);
		}

		if (oidc_proto_param_needs_action(ctx->request_object_config, name,
				OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST)) {
			apr_table_set(ctx->params2, name, name);
		}

	}

	return 1;
}

/*
 * delete a parameter key/value from the authorizion request if the configuration setting says to remove it
 */
static int oidc_proto_delete_from_request(void* rec, const char* name,
		const char* value) {
	oidc_proto_copy_req_ctx_t *ctx = (oidc_proto_copy_req_ctx_t *) rec;

	oidc_debug(ctx->r, "deleting from query parameters: name: %s, value: %s",
			name, value);

	if (oidc_proto_param_needs_action(ctx->request_object_config, name,
			OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST)) {
		apr_table_unset(ctx->params2, name);
	}

	return 1;
}

/*
 * obtain the public key for a provider to encrypt the request object with
 */
apr_byte_t oidc_proto_get_encryption_jwk_by_type(request_rec *r, oidc_cfg *cfg,
		struct oidc_provider_t *provider, int key_type, oidc_jwk_t **jwk) {

	oidc_jwks_uri_t jwks_uri = { provider->jwks_uri,
			provider->jwks_refresh_interval, provider->ssl_validate_server };

	oidc_jose_error_t err;
	json_t *j_jwks = NULL;
	apr_byte_t force_refresh = TRUE;
	oidc_jwk_t *key = NULL;
	char *jwk_json = NULL;

	/* TODO: forcefully refresh now; we may want to relax that */
	oidc_metadata_jwks_get(r, cfg, &jwks_uri, &j_jwks, &force_refresh);

	if (j_jwks == NULL) {
		oidc_error(r, "could not retrieve JSON Web Keys");
		return FALSE;
	}

	json_t *keys = json_object_get(j_jwks, "keys");
	if ((keys == NULL) || !(json_is_array(keys))) {
		oidc_error(r, "\"keys\" array element is not a JSON array");
		return FALSE;
	}

	int i;
	/* walk the set of published keys to find the first that has a matching type */
	for (i = 0; i < json_array_size(keys); i++) {

		json_t *elem = json_array_get(keys, i);

		const char *use = json_string_value(
				json_object_get(elem, OIDC_JWK_USE));
		if ((use != NULL) && (strcmp(use, OIDC_JWK_ENC) != 0)) {
			oidc_debug(r, "skipping key because of non-matching \"%s\": \"%s\"",
					OIDC_JWK_USE, use);
			continue;
		}

		if (oidc_jwk_parse_json(r->pool, elem, &key, &err) == FALSE) {
			oidc_warn(r, "oidc_jwk_parse_json failed: %s",
					oidc_jose_e2s(r->pool, err));
			continue;
		}

		if (key_type == key->kty) {
			oidc_jwk_to_json(r->pool, key, &jwk_json, &err);
			oidc_debug(r, "found matching encryption key type for key: %s",
					jwk_json);
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
char *oidc_proto_create_request_object(request_rec *r,
		struct oidc_provider_t *provider, json_t * request_object_config,
		apr_table_t *params) {

	oidc_debug(r, "enter");

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	/* create the request object value */
	oidc_jwt_t *request_object = oidc_jwt_new(r->pool, TRUE, TRUE);

	/* set basic values: iss and aud */
	json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_ISS,
			json_string(provider->client_id));
	json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_AUD,
			json_string(provider->issuer));

	/* add static values to the request object as configured in the .conf file; may override iss/aud */
	oidc_util_json_merge(r, json_object_get(request_object_config, "static"),
			request_object->payload.value.json);

	/* copy parameters from the authorization request as configured in the .conf file */
	apr_table_t *delete_from_query_params = apr_table_make(r->pool, 0);
	oidc_proto_copy_req_ctx_t data = { r, request_object_config, request_object,
			delete_from_query_params };
	apr_table_do(oidc_proto_copy_from_request, &data, params, NULL);

	/* delete parameters from the query parameters of the authorization request as configured in the .conf file */
	data.params2 = params;
	apr_table_do(oidc_proto_delete_from_request, &data,
			delete_from_query_params, NULL);

	/* debug logging */
	oidc_debug(r, "request object: %s",
			oidc_util_encode_json_object(r, request_object->payload.value.json, JSON_COMPACT));

	char *serialized_request_object = NULL;
	oidc_jose_error_t err;

	/* get the crypto settings from the configuration */
	json_t *crypto = json_object_get(request_object_config, "crypto");
	oidc_json_object_get_string(r->pool, crypto, "sign_alg",
			&request_object->header.alg, "none");

	/* see if we need to sign the request object */
	if (strcmp(request_object->header.alg, "none") != 0) {

		oidc_jwk_t *jwk = NULL;
		int jwk_needs_destroy = 0;

		switch (oidc_jwt_alg2kty(request_object)) {
		case CJOSE_JWK_KTY_RSA:
			if (cfg->private_keys != NULL) {
				apr_ssize_t klen = 0;
				apr_hash_index_t *hi = apr_hash_first(r->pool,
						cfg->private_keys);
				apr_hash_this(hi, (const void **) &request_object->header.kid,
						&klen, (void **) &jwk);
			} else {
				oidc_error(r,
						"no private keys have been configured to use for private_key_jwt client authentication (" OIDCPrivateKeyFiles ")");
			}
			break;
		case CJOSE_JWK_KTY_OCT:
			oidc_util_create_symmetric_key(r, provider->client_secret, 0, NULL,
					FALSE, &jwk);
			jwk_needs_destroy = 1;
			break;
		default:
			oidc_error(r,
					"unsupported signing algorithm, no key type for algorithm: %s",
					request_object->header.alg);
			break;
		}

		if (jwk == NULL) {
			oidc_jwt_destroy(request_object);
			json_decref(request_object_config);
			return FALSE;
		}

		if (oidc_jwt_sign(r->pool, request_object, jwk, &err) == FALSE) {
			oidc_error(r, "signing Request Object failed: %s",
					oidc_jose_e2s(r->pool, err));
			if (jwk_needs_destroy)
				oidc_jwk_destroy(jwk);
			oidc_jwt_destroy(request_object);
			json_decref(request_object_config);
			return FALSE;
		}

		if (jwk_needs_destroy)
			oidc_jwk_destroy(jwk);
	}

	oidc_jwt_t *jwe = oidc_jwt_new(r->pool, TRUE, FALSE);
	if (jwe == NULL) {
		oidc_error(r, "creating JWE failed");
		oidc_jwt_destroy(request_object);
		json_decref(request_object_config);
		return FALSE;
	}

	oidc_json_object_get_string(r->pool, crypto, "crypt_alg", &jwe->header.alg,
			NULL);
	oidc_json_object_get_string(r->pool, crypto, "crypt_enc", &jwe->header.enc,
			NULL);

	char *cser = oidc_jwt_serialize(r->pool, request_object, &err);

	/* see if we need to encrypt the request object */
	if (jwe->header.alg != NULL) {

		oidc_jwk_t *jwk = NULL;

		switch (oidc_jwt_alg2kty(jwe)) {
		case CJOSE_JWK_KTY_RSA:
			oidc_proto_get_encryption_jwk_by_type(r, cfg, provider,
					CJOSE_JWK_KTY_RSA, &jwk);
			break;
		case CJOSE_JWK_KTY_OCT:
			oidc_util_create_symmetric_key(r, provider->client_secret,
					oidc_alg2keysize(jwe->header.alg), OIDC_JOSE_ALG_SHA256,
					FALSE, &jwk);
			break;
		default:
			oidc_error(r,
					"unsupported encryption algorithm, no key type for algorithm: %s",
					request_object->header.alg);
			break;
		}

		if (jwk == NULL) {
			oidc_jwt_destroy(jwe);
			oidc_jwt_destroy(request_object);
			json_decref(request_object_config);
			return FALSE;
		}

		if (jwe->header.enc == NULL)
			jwe->header.enc = apr_pstrdup(r->pool, CJOSE_HDR_ENC_A128CBC_HS256);

		if (jwk->kid != NULL)
			jwe->header.kid = jwk->kid;

		if (oidc_jwt_encrypt(r->pool, jwe, jwk, cser,
				&serialized_request_object, &err) == FALSE) {
			oidc_error(r, "encrypting JWT failed: %s",
					oidc_jose_e2s(r->pool, err));
			oidc_jwk_destroy(jwk);
			oidc_jwt_destroy(jwe);
			oidc_jwt_destroy(request_object);
			json_decref(request_object_config);
			return FALSE;
		}

		oidc_jwk_destroy(jwk);

	} else {

		/* should be sign only or "none" */
		serialized_request_object = cser;
	}

	oidc_jwt_destroy(request_object);
	oidc_jwt_destroy(jwe);
	json_decref(request_object_config);

	oidc_debug(r, "serialized request object JWT header = \"%s\"",
			oidc_proto_peek_jwt_header(r, serialized_request_object, NULL));
	oidc_debug(r, "serialized request object = \"%s\"",
			serialized_request_object);

	return serialized_request_object;
}

/*
 * generate a request object and pass it by reference in the authorization request
 */
static char *oidc_proto_create_request_uri(request_rec *r,
		struct oidc_provider_t *provider, json_t * request_object_config,
		const char *redirect_uri, apr_table_t *params) {

	oidc_debug(r, "enter");

	/* see if we need to override the resolver URL, mostly for test purposes */
	char *resolver_url = NULL;
	if (json_object_get(request_object_config, "url") != NULL)
		resolver_url = apr_pstrdup(r->pool,
				json_string_value(
						json_object_get(request_object_config, "url")));
	else
		resolver_url = apr_pstrdup(r->pool, redirect_uri);

	char *serialized_request_object = oidc_proto_create_request_object(r,
			provider, request_object_config, params);

	/* generate a temporary reference, store the request object in the cache and generate a Request URI that references it */
	char *request_uri = NULL;
	if (serialized_request_object != NULL) {
		char *request_ref = NULL;
		if (oidc_proto_generate_random_string(r, &request_ref, 16) == TRUE) {
			oidc_cache_set_request_uri(r, request_ref,
					serialized_request_object,
					apr_time_now() + apr_time_from_sec(OIDC_REQUEST_URI_CACHE_DURATION));
			request_uri = apr_psprintf(r->pool, "%s?%s=%s", resolver_url,
					OIDC_PROTO_REQUEST_URI, oidc_util_escape_string(r, request_ref));
		}
	}

	return request_uri;
}

/*
 * Generic function to generate request/request_object parameter with value
 */
static void oidc_proto_add_request_param(request_rec *r,
		struct oidc_provider_t *provider, const char *redirect_uri,
		apr_table_t *params) {

	/* parse the request object configuration from a string in to a JSON structure */
	json_t *request_object_config = NULL;
	if (oidc_util_decode_json_object(r, provider->request_object,
			&request_object_config) == FALSE)
		return;

	/* request_uri is used as default parameter for sending Request Object */
	char* parameter = OIDC_PROTO_REQUEST_URI;

	/* get request_object_type parameter from config */
	json_t *request_object_type = json_object_get(request_object_config,
			"request_object_type");
	if (request_object_type != NULL) {
		const char* request_object_type_str = json_string_value(
				request_object_type);
		if (request_object_type_str == NULL) {
			oidc_error(r,
					"Value of request_object_type in request_object config is not a string");
			return;
		}

		/* ensure parameter variable to have a valid value */
		if (strcmp(request_object_type_str, OIDC_PROTO_REQUEST_OBJECT) == 0) {
			parameter = OIDC_PROTO_REQUEST_OBJECT;
		} else if (strcmp(request_object_type_str, OIDC_PROTO_REQUEST_URI)
				!= 0) {
			oidc_error(r, "Bad request_object_type in config: %s",
					request_object_type_str);
			return;
		}
	}

	/* create request value */
	char * value = NULL;
	if (strcmp(parameter, OIDC_PROTO_REQUEST_URI) == 0) {
		/* parameter is "request_uri" */
		value = oidc_proto_create_request_uri(r, provider,
				request_object_config, redirect_uri, params);
		apr_table_set(params, OIDC_PROTO_REQUEST_URI, value);
	} else {
		/* parameter is "request" */
		value = oidc_proto_create_request_object(r, provider,
				request_object_config, params);
		apr_table_set(params, OIDC_PROTO_REQUEST_OBJECT, value);
	}
}

/* context structure for encoding parameters */
typedef struct oidc_proto_form_post_ctx_t {
	request_rec *r;
	const char *html_body;
} oidc_proto_form_post_ctx_t;

/*
 * add a key/value pair post parameter
 */
static int oidc_proto_add_form_post_param(void* rec, const char* key,
		const char* value) {
	oidc_proto_form_post_ctx_t *ctx = (oidc_proto_form_post_ctx_t *) rec;
	oidc_debug(ctx->r, "processing: %s=%s", key, value);
	ctx->html_body = apr_psprintf(ctx->r->pool,
			"%s      <input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
			ctx->html_body, oidc_util_html_escape(ctx->r->pool, key),
			oidc_util_html_escape(ctx->r->pool, value));
	return 1;
}

/*
 * make the browser POST parameters through Javascript auto-submit
 */
static int oidc_proto_html_post(request_rec *r, const char *url,
		apr_table_t *params) {

	oidc_debug(r, "enter");

	const char *html_body = apr_psprintf(r->pool,
			"    <p>Submitting Authentication Request...</p>\n"
			"    <form method=\"post\" action=\"%s\">\n"
			"      <p>\n", url);

	oidc_proto_form_post_ctx_t data = { r, html_body };
	apr_table_do(oidc_proto_add_form_post_param, &data, params, NULL);

	html_body = apr_psprintf(r->pool, "%s%s", data.html_body, "      </p>\n"
			"    </form>\n");

	return oidc_util_html_send(r, "Submitting...", NULL,
			"document.forms[0].submit()", html_body, DONE);
}

/*
 * send an OpenID Connect authorization request to the specified provider
 */
int oidc_proto_authorization_request(request_rec *r,
		struct oidc_provider_t *provider, const char *login_hint,
		const char *redirect_uri, const char *state,
		oidc_proto_state_t *proto_state, const char *id_token_hint,
		const char *code_challenge, const char *auth_request_params,
		const char *path_scope) {

	/* log some stuff */
	oidc_debug(r,
			"enter, issuer=%s, redirect_uri=%s, state=%s, proto_state=%s, code_challenge=%s, auth_request_params=%s, path_scope=%s",
			provider->issuer, redirect_uri, state,
			oidc_proto_state_to_string(r, proto_state), code_challenge,
			auth_request_params, path_scope);

	int rv = DONE;
	char *authorization_request = NULL;

	/* assemble parameters to call the token endpoint for validation */
	apr_table_t *params = apr_table_make(r->pool, 4);

	/* add the response type */
	apr_table_setn(params, OIDC_PROTO_RESPONSE_TYPE,
			oidc_proto_state_get_response_type(proto_state));

	/* concat the per-path scopes with the per-provider scopes */
	const char *scope = provider->scope;
	if (path_scope != NULL)
		scope = ((scope != NULL) && (apr_strnatcmp(scope, "") != 0)) ?
				apr_pstrcat(r->pool, scope, OIDC_STR_SPACE, path_scope, NULL) :
				path_scope;

	if (scope != NULL) {
		if (!oidc_util_spaced_string_contains(r->pool, scope,
				OIDC_PROTO_SCOPE_OPENID)) {
			oidc_warn(r,
					"the configuration for the \"%s\" parameter does not include the \"%s\" scope, your provider may not return an \"id_token\": %s",
					OIDC_PROTO_SCOPE, OIDC_PROTO_SCOPE_OPENID, provider->scope);
		}
		apr_table_setn(params, OIDC_PROTO_SCOPE, scope);
	}

	/* add the client ID */
	apr_table_setn(params, OIDC_PROTO_CLIENT_ID, provider->client_id);

	/* add the state */
	apr_table_setn(params, OIDC_PROTO_STATE, state);

	/* add the redirect uri */
	apr_table_setn(params, OIDC_PROTO_REDIRECT_URI, redirect_uri);

	/* add the nonce if set */
	const char *nonce = oidc_proto_state_get_nonce(proto_state);
	if (nonce != NULL)
		apr_table_setn(params, OIDC_PROTO_NONCE, nonce);

	/* add PKCE code challenge if set */
	if (code_challenge != NULL) {
		apr_table_setn(params, OIDC_PROTO_CODE_CHALLENGE, code_challenge);
		apr_table_setn(params, OIDC_PROTO_CODE_CHALLENGE_METHOD,
				provider->pkce->method);
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
	if (provider->auth_request_params != NULL)
		oidc_util_table_add_query_encoded_params(r->pool, params,
				provider->auth_request_params);

	/* add any dynamically configured custom authorization request parameters */
	if (auth_request_params != NULL)
		oidc_util_table_add_query_encoded_params(r->pool, params,
				auth_request_params);

	/* add request parameter (request or request_uri) if set */
	if (provider->request_object != NULL)
		oidc_proto_add_request_param(r, provider, redirect_uri, params);

	/* send the full authentication request via POST or GET */
	if (provider->auth_request_method == OIDC_AUTH_REQUEST_METHOD_POST) {

		/* construct a HTML POST auto-submit page with the authorization request parameters */
		rv = oidc_proto_html_post(r, provider->authorization_endpoint_url,
				params);

	} else {

		/* construct the full authorization request URL */
		authorization_request = oidc_util_http_query_encoded_url(r,
				provider->authorization_endpoint_url, params);

		// TODO: should also enable this when using the POST binding for the auth request
		/* see if we need to preserve POST parameters through Javascript/HTML5 storage */
		if (oidc_post_preserve_javascript(r, authorization_request, NULL,
				NULL) == FALSE) {

			/* add the redirect location header */
			oidc_util_hdr_out_location_set(r, authorization_request);

			/* and tell Apache to return an HTTP Redirect (302) message */
			rv = HTTP_MOVED_TEMPORARILY;
		}
	}

	/* add a referred token binding request for the provider if enabled */
	if ((provider->token_binding_policy > OIDC_TOKEN_BINDING_POLICY_DISABLED)
			&& (oidc_util_get_provided_token_binding_id(r) != NULL))
		oidc_util_hdr_err_out_add(r,
				OIDC_HTTP_HDR_INCLUDE_REFERRED_TOKEN_BINDING_ID, "true");

	/* cleanup */
	oidc_proto_state_destroy(proto_state);

	/* no cache */
	oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_CACHE_CONTROL,
			"no-cache, no-store, max-age=0");

	/* log our exit code */
	oidc_debug(r, "return: %d", rv);

	return rv;
}

/*
 * indicate whether the incoming HTTP POST request is an OpenID Connect Authorization Response
 */
apr_byte_t oidc_proto_is_post_authorization_response(request_rec *r,
		oidc_cfg *cfg) {

	/* prereq: this is a call to the configured redirect_uri; see if it is a POST */
	return (r->method_number == M_POST);
}

/*
 * indicate whether the incoming HTTP GET request is an OpenID Connect Authorization Response
 */
apr_byte_t oidc_proto_is_redirect_authorization_response(request_rec *r,
		oidc_cfg *cfg) {

	/* prereq: this is a call to the configured redirect_uri; see if it is a GET with state and id_token or code parameters */
	return ((r->method_number == M_GET)
			&& oidc_util_request_has_parameter(r, OIDC_PROTO_STATE)
			&& (oidc_util_request_has_parameter(r, OIDC_PROTO_ID_TOKEN)
					|| oidc_util_request_has_parameter(r, OIDC_PROTO_CODE)));
}

/*
 * generate a random value (nonce) to correlate request/response through browser state
 */
apr_byte_t oidc_proto_generate_nonce(request_rec *r, char **nonce, int len) {
	return oidc_proto_generate_random_string(r, nonce, len);
}

/*
 * PCKE "plain" proto state
 */
static apr_byte_t oidc_proto_pkce_state_plain(request_rec *r, char **state) {
	return oidc_proto_generate_random_string(r, state,
			OIDC_PROTO_CODE_VERIFIER_LENGTH);
}

/*
 * PCKE "plain" code_challenge
 */
static apr_byte_t oidc_proto_pkce_challenge_plain(request_rec *r,
		const char *state, char **code_challenge) {
	*code_challenge = apr_pstrdup(r->pool, state);
	return TRUE;
}

/*
 * PCKE "plain" code_verifier
 */
static apr_byte_t oidc_proto_pkce_verifier_plain(request_rec *r,
		const char *state, char **code_verifier) {
	*code_verifier = apr_pstrdup(r->pool, state);
	return TRUE;
}

/*
 * PCKE "s256" proto state
 */
static apr_byte_t oidc_proto_pkce_state_s256(request_rec *r, char **state) {
	return oidc_proto_generate_random_string(r, state,
			OIDC_PROTO_CODE_VERIFIER_LENGTH);
}

/*
 * PCKE "s256" code_challenge
 */
static apr_byte_t oidc_proto_pkce_challenge_s256(request_rec *r,
		const char *state, char **code_challenge) {
	if (oidc_util_hash_string_and_base64url_encode(r, OIDC_JOSE_ALG_SHA256,
			state, code_challenge) == FALSE) {
		oidc_error(r,
				"oidc_util_hash_string_and_base64url_encode returned an error for the code verifier");
		return FALSE;
	}
	return TRUE;
}

/*
 * PCKE "s256" code_verifier
 */
static apr_byte_t oidc_proto_pkce_verifier_s256(request_rec *r,
		const char *state, char **code_verifier) {
	*code_verifier = apr_pstrdup(r->pool, state);
	return TRUE;
}

/*
 * PCKE "referred_tb" proto state
 */
static apr_byte_t oidc_proto_pkce_state_referred_tb(request_rec *r,
		char **state) {
	*state = NULL;
	return TRUE;
}

/*
 * PCKE "referred_tb" code_challenge
 */
static apr_byte_t oidc_proto_pkce_challenge_referred_tb(request_rec *r,
		const char *state, char **code_challenge) {
	// state should be NULL
	*code_challenge = OIDC_PKCE_METHOD_REFERRED_TB;
	return TRUE;
}

/*
 * PCKE "referred_tb" code_verifier
 */
static apr_byte_t oidc_proto_pkce_verifier_referred_tb(request_rec *r,
		const char *state, char **code_verifier) {
	const char *tb_id = oidc_util_get_provided_token_binding_id(r);
	*code_verifier = tb_id ? apr_pstrdup(r->pool, tb_id) : NULL;
	return TRUE;
}

/*
 * PKCE plain
 */
oidc_proto_pkce_t oidc_pkce_plain = {
		OIDC_PKCE_METHOD_PLAIN,
		oidc_proto_pkce_state_plain,
		oidc_proto_pkce_verifier_plain,
		oidc_proto_pkce_challenge_plain
};

/*
 * PKCE s256
 */
oidc_proto_pkce_t oidc_pkce_s256 = {
		OIDC_PKCE_METHOD_S256,
		oidc_proto_pkce_state_s256,
		oidc_proto_pkce_verifier_s256,
		oidc_proto_pkce_challenge_s256
};

/*
 * PKCE referred_tb
 */
oidc_proto_pkce_t oidc_pkce_referred_tb = {
		OIDC_PKCE_METHOD_REFERRED_TB,
		oidc_proto_pkce_state_referred_tb,
		oidc_proto_pkce_verifier_referred_tb,
		oidc_proto_pkce_challenge_referred_tb
};

#define OIDC_PROTO_STATE_ISSUER          "i"
#define OIDC_PROTO_STATE_ORIGINAL_URL    "ou"
#define OIDC_PROTO_STATE_ORIGINAL_METHOD "om"
#define OIDC_PROTO_STATE_RESPONSE_MODE   "rm"
#define OIDC_PROTO_STATE_RESPONSE_TYPE   "rt"
#define OIDC_PROTO_STATE_NONCE           "n"
#define OIDC_PROTO_STATE_TIMESTAMP       "t"
#define OIDC_PROTO_STATE_PROMPT          "pr"
#define OIDC_PROTO_STATE_PKCE_STATE      "ps"
#define OIDC_PROTO_STATE_STATE           "s"

static const char *oidc_proto_state_get_string_value(
		oidc_proto_state_t *proto_state, const char *name) {
	json_t *v = json_object_get(proto_state, name);
	return v ? json_string_value(v) : NULL;
}

static void oidc_proto_state_set_string_value(oidc_proto_state_t *proto_state,
		const char *name, const char *value) {
	json_object_set_new(proto_state, name, json_string(value));
}

oidc_proto_state_t *oidc_proto_state_new() {
	return json_object();
}

void oidc_proto_state_destroy(oidc_proto_state_t *proto_state) {
	json_decref(proto_state);
}

oidc_proto_state_t * oidc_proto_state_from_cookie(request_rec *r, oidc_cfg *c,
		const char *cookieValue) {
	json_t *result = NULL;
	oidc_util_jwt_verify(r, c->crypto_passphrase, cookieValue, &result);
	return result;
}

char *oidc_proto_state_to_cookie(request_rec *r, oidc_cfg *c,
		oidc_proto_state_t *proto_state) {
	char *cookieValue = NULL;
	oidc_util_jwt_create(r, c->crypto_passphrase, proto_state, &cookieValue);
	return cookieValue;
}
char *oidc_proto_state_to_string(request_rec *r,
		oidc_proto_state_t *proto_state) {
	return oidc_util_encode_json_object(r, proto_state, JSON_COMPACT);
}

const char *oidc_proto_state_get_issuer(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_ISSUER);
}

const char *oidc_proto_state_get_nonce(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_NONCE);
}

apr_time_t oidc_proto_state_get_timestamp(oidc_proto_state_t *proto_state) {
	json_t *v = json_object_get(proto_state, OIDC_PROTO_STATE_TIMESTAMP);
	return v ? apr_time_from_sec(json_integer_value(v)) : -1;
}

const char *oidc_proto_state_get_prompt(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_PROMPT);
}

const char *oidc_proto_state_get_response_type(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_RESPONSE_TYPE);
}

const char *oidc_proto_state_get_response_mode(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_RESPONSE_MODE);
}

const char *oidc_proto_state_get_original_url(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_ORIGINAL_URL);
}

const char *oidc_proto_state_get_original_method(
		oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_ORIGINAL_METHOD);
}

const char *oidc_proto_state_get_state(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_STATE);
}

const char *oidc_proto_state_get_pkce_state(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state,
			OIDC_PROTO_STATE_PKCE_STATE);
}

void oidc_proto_state_set_state(oidc_proto_state_t *proto_state,
		const char *state) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_STATE,
			state);
}

void oidc_proto_state_set_issuer(oidc_proto_state_t *proto_state,
		const char *issuer) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_ISSUER,
			issuer);
}

void oidc_proto_state_set_original_url(oidc_proto_state_t *proto_state,
		const char *original_url) {
	oidc_proto_state_set_string_value(proto_state,
			OIDC_PROTO_STATE_ORIGINAL_URL, original_url);
}

void oidc_proto_state_set_original_method(oidc_proto_state_t *proto_state,
		const char *original_method) {
	oidc_proto_state_set_string_value(proto_state,
			OIDC_PROTO_STATE_ORIGINAL_METHOD, original_method);
}

void oidc_proto_state_set_response_mode(oidc_proto_state_t *proto_state,
		const char *response_mode) {
	oidc_proto_state_set_string_value(proto_state,
			OIDC_PROTO_STATE_RESPONSE_MODE, response_mode);
}

void oidc_proto_state_set_response_type(oidc_proto_state_t *proto_state,
		const char *response_type) {
	oidc_proto_state_set_string_value(proto_state,
			OIDC_PROTO_STATE_RESPONSE_TYPE, response_type);
}

void oidc_proto_state_set_nonce(oidc_proto_state_t *proto_state,
		const char *nonce) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_NONCE,
			nonce);
}

void oidc_proto_state_set_prompt(oidc_proto_state_t *proto_state,
		const char *prompt) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_PROMPT,
			prompt);
}

void oidc_proto_state_set_pkce_state(oidc_proto_state_t *proto_state,
		const char *pkce_state) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_PKCE_STATE,
			pkce_state);
}

void oidc_proto_state_set_timestamp_now(oidc_proto_state_t *proto_state) {
	json_object_set_new(proto_state, OIDC_PROTO_STATE_TIMESTAMP,
			json_integer(apr_time_sec(apr_time_now())));
}

/*
 * if a nonce was passed in the authorization request (and stored in the browser state),
 * check that it matches the nonce value in the id_token payload
 */
// non-static for test.c
apr_byte_t oidc_proto_validate_nonce(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *nonce, oidc_jwt_t *jwt) {

	oidc_jose_error_t err;

	/* see if we have this nonce cached already */
	char *replay = NULL;
	oidc_cache_get_nonce(r, nonce, &replay);
	if (replay != NULL) {
		oidc_error(r,
				"the nonce value (%s) passed in the browser state was found in the cache already; possible replay attack!?",
				nonce);
		return FALSE;
	}

	/* get the "nonce" value in the id_token payload */
	char *j_nonce = NULL;
	if (oidc_jose_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_NONCE,
			TRUE, &j_nonce, &err) == FALSE) {
		oidc_error(r,
				"id_token JSON payload did not contain a \"%s\" string: %s",
				OIDC_CLAIM_NONCE, oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	/* see if the nonce in the id_token matches the one that we sent in the authorization request */
	if (apr_strnatcmp(nonce, j_nonce) != 0) {
		oidc_error(r,
				"the nonce value (%s) in the id_token did not match the one stored in the browser session (%s)",
				j_nonce, nonce);
		return FALSE;
	}

	/*
	 * nonce cache duration (replay prevention window) is the 2x the configured
	 * slack on the timestamp (+-) for token issuance plus 10 seconds for safety
	 */
	apr_time_t nonce_cache_duration = apr_time_from_sec(
			provider->idtoken_iat_slack * 2 + 10);

	/* store it in the cache for the calculated duration */
	oidc_cache_set_nonce(r, nonce, nonce,
			apr_time_now() + nonce_cache_duration);

	oidc_debug(r,
			"nonce \"%s\" validated successfully and is now cached for %" APR_TIME_T_FMT " seconds",
			nonce, apr_time_sec(nonce_cache_duration));

	return TRUE;
}

/*
 * validate the "aud" and "azp" claims in the id_token payload
 */
static apr_byte_t oidc_proto_validate_aud_and_azp(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, oidc_jwt_payload_t *id_token_payload) {

	char *azp = NULL;
	oidc_jose_get_string(r->pool, id_token_payload->value.json, OIDC_CLAIM_AZP,
			FALSE, &azp,
			NULL);

	/*
	 * the "azp" claim is only needed when the id_token has a single audience value and that audience
	 * is different than the authorized party; it MAY be included even when the authorized party is
	 * the same as the sole audience.
	 */
	if ((azp != NULL) && (apr_strnatcmp(azp, provider->client_id) != 0)) {
		oidc_error(r,
				"the \"%s\" claim (%s) is present in the id_token, but is not equal to the configured client_id (%s)",
				OIDC_CLAIM_AZP, azp, provider->client_id);
		return FALSE;
	}

	/* get the "aud" value from the JSON payload */
	json_t *aud = json_object_get(id_token_payload->value.json, OIDC_CLAIM_AUD);
	if (aud != NULL) {

		/* check if it is a single-value */
		if (json_is_string(aud)) {

			/* a single-valued audience must be equal to our client_id */
			if (apr_strnatcmp(json_string_value(aud), provider->client_id)
					!= 0) {
				oidc_error(r,
						"the configured client_id (%s) did not match the \"%s\" claim value (%s) in the id_token",
						provider->client_id, OIDC_CLAIM_AUD,
						json_string_value(aud));
				return FALSE;
			}

			/* check if this is a multi-valued audience */
		} else if (json_is_array(aud)) {

			if ((json_array_size(aud) > 1) && (azp == NULL)) {
				oidc_debug(r,
						"the \"%s\" claim value in the id_token is an array with more than 1 element, but \"%s\" claim is not present (a SHOULD in the spec...)",
						OIDC_CLAIM_AUD, OIDC_CLAIM_AZP);
			}

			if (oidc_util_json_array_has_value(r, aud,
					provider->client_id) == FALSE) {
				oidc_error(r,
						"our configured client_id (%s) could not be found in the array of values for \"%s\" claim",
						provider->client_id, OIDC_CLAIM_AUD);
				return FALSE;
			}
		} else {
			oidc_error(r,
					"id_token JSON payload \"%s\" claim is not a string nor an array",
					OIDC_CLAIM_AUD);
			return FALSE;
		}

	} else {
		oidc_error(r, "id_token JSON payload did not contain an \"%s\" claim",
				OIDC_CLAIM_AUD);
		return FALSE;
	}

	return TRUE;
}

#define OIDC_CLAIM_CNF     "cnf"
#define OIDC_CLAIM_CNF_TBH "tbh"

/*
 * validate the "cnf" claims in the id_token payload
 */
static apr_byte_t oidc_proto_validate_cnf(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, oidc_jwt_payload_t *id_token_payload) {
	char *tbh_str = NULL;
	char *tbh = NULL;
	int tbh_len = -1;
	const char *tbp_str = NULL;
	char *tbp = NULL;
	int tbp_len = -1;
	unsigned char *tbp_hash = NULL;
	unsigned int tbp_hash_len = -1;

	oidc_debug(r, "enter: policy=%s",
			oidc_token_binding_policy2str(r->pool,
					provider->token_binding_policy));

	if (provider->token_binding_policy == OIDC_TOKEN_BINDING_POLICY_DISABLED)
		return TRUE;

	tbp_str = oidc_util_get_provided_token_binding_id(r);
	if (tbp_str == NULL) {
		oidc_debug(r,
				"no Provided Token Binding ID environment variable found");
		goto out_err;
	}

	tbp_len = oidc_base64url_decode(r->pool, &tbp, tbp_str);
	if (tbp_len <= 0) {
		oidc_warn(r,
				"Provided Token Binding ID environment variable could not be decoded");
		return FALSE;
	}

	if (oidc_jose_hash_bytes(r->pool, OIDC_JOSE_ALG_SHA256,
			(const unsigned char *) tbp, tbp_len, &tbp_hash, &tbp_hash_len,
			NULL) == FALSE) {
		oidc_warn(r,
				"hashing Provided Token Binding ID environment variable failed");
		return FALSE;
	}

	json_t *cnf = json_object_get(id_token_payload->value.json, OIDC_CLAIM_CNF);
	if (cnf == NULL) {
		oidc_debug(r, "no \"cnf\" claim found in id_token");
		goto out_err;
	}

	oidc_jose_get_string(r->pool, cnf, OIDC_CLAIM_CNF_TBH, FALSE, &tbh_str,
			NULL);
	if (tbh_str == NULL) {
		oidc_debug(r,
				" \"cnf\" claim found in id_token but no \"tbh\" claim inside found");
		goto out_err;
	}

	tbh_len = oidc_base64url_decode(r->pool, &tbh, tbh_str);
	if (tbh_len <= 0) {
		oidc_warn(r, "cnf[\"tbh\"] provided but it could not be decoded");
		return FALSE;
	}

	if (tbp_hash_len != tbh_len) {
		oidc_warn(r,
				"hash length of provided token binding ID environment variable: %d does not match length of cnf[\"tbh\"]: %d",
				tbp_hash_len, tbh_len);
		return FALSE;
	}

	if (memcmp(tbp_hash, tbh, tbh_len) != 0) {
		oidc_warn(r,
				"hash of provided token binding ID environment variable does not match cnf[\"tbh\"]");
		return FALSE;
	}

	oidc_debug(r,
			"hash of provided token binding ID environment variable matches cnf[\"tbh\"]");

	return TRUE;

out_err:

	if (provider->token_binding_policy == OIDC_TOKEN_BINDING_POLICY_OPTIONAL)
		return TRUE;
	if (provider->token_binding_policy == OIDC_TOKEN_BINDING_POLICY_ENFORCED)
		return FALSE;

	// provider->token_binding_policy == OIDC_TOKEN_BINDING_POLICY_REQURIED
	return (tbp_str == NULL);
}

/*
 * validate "iat" claim in JWT
 */
static apr_byte_t oidc_proto_validate_iat(request_rec *r, oidc_jwt_t *jwt,
		apr_byte_t is_mandatory, int slack) {

	/* get the current time */
	apr_time_t now = apr_time_sec(apr_time_now());

	/* sanity check for iat being set */
	if (jwt->payload.iat == OIDC_JWT_CLAIM_TIME_EMPTY) {
		if (is_mandatory) {
			oidc_error(r, "JWT did not contain an \"%s\" number value",
					OIDC_CLAIM_IAT);
			return FALSE;
		}
		return TRUE;
	}

	/* see if we are asked to enforce a time window at all */
	if (slack < 0) {
		oidc_debug(r, "slack for JWT set < 0, do not enforce boundary check");
		return TRUE;
	}

	/* check if this id_token has been issued just now +- slack (default 10 minutes) */
	if ((now - slack) > jwt->payload.iat) {
		oidc_error(r,
				"\"iat\" validation failure (%ld): JWT was issued more than %d seconds ago",
				(long )jwt->payload.iat, slack);
		return FALSE;
	}
	if ((now + slack) < jwt->payload.iat) {
		oidc_error(r,
				"\"iat\" validation failure (%ld): JWT was issued more than %d seconds in the future",
				(long )jwt->payload.iat, slack);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate "exp" claim in JWT
 */
static apr_byte_t oidc_proto_validate_exp(request_rec *r, oidc_jwt_t *jwt,
		apr_byte_t is_mandatory) {

	/* get the current time */
	apr_time_t now = apr_time_sec(apr_time_now());

	/* sanity check for exp being set */
	if (jwt->payload.exp == OIDC_JWT_CLAIM_TIME_EMPTY) {
		if (is_mandatory) {
			oidc_error(r, "JWT did not contain an \"%s\" number value",
					OIDC_CLAIM_EXP);
			return FALSE;
		}
		return TRUE;
	}

	/* see if now is beyond the JWT expiry timestamp */
	apr_time_t expires = jwt->payload.exp;
	if (now > expires) {
		oidc_error(r,
				"\"exp\" validation failure (%ld): JWT expired %ld seconds ago",
				(long )expires, (long )(now - expires));
		return FALSE;
	}

	return TRUE;
}

/*
 * validate a JSON Web token
 */
apr_byte_t oidc_proto_validate_jwt(request_rec *r, oidc_jwt_t *jwt,
		const char *iss, apr_byte_t exp_is_mandatory,
		apr_byte_t iat_is_mandatory, int iat_slack) {

	if (iss != NULL) {

		/* issuer is set and must match */
		if (jwt->payload.iss == NULL) {
			oidc_error(r,
					"JWT did not contain an \"%s\" string (requested value: %s)",
					OIDC_CLAIM_ISS, iss);
			return FALSE;
		}

		/* check if the issuer matches the requested value */
		if (oidc_util_issuer_match(iss, jwt->payload.iss) == FALSE) {
			oidc_error(r,
					"requested issuer (%s) does not match received \"%s\" value in id_token (%s)",
					iss, OIDC_CLAIM_ISS, jwt->payload.iss);
			return FALSE;
		}
	}

	/* check exp */
	if (oidc_proto_validate_exp(r, jwt, exp_is_mandatory) == FALSE)
		return FALSE;

	/* check iat */
	if (oidc_proto_validate_iat(r, jwt, iat_is_mandatory, iat_slack) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * check whether the provided JWT is a valid id_token for the specified "provider"
 */
static apr_byte_t oidc_proto_validate_idtoken(request_rec *r,
		oidc_provider_t *provider, oidc_jwt_t *jwt, const char *nonce) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	oidc_debug(r, "enter, jwt.header=\"%s\", jwt.payload=\"%s\", nonce=\"%s\"",
			jwt->header.value.str, jwt->payload.value.str, nonce);

	/* if a nonce is not passed, we're doing a ("code") flow where the nonce is optional */
	if (nonce != NULL) {
		/* if present, verify the nonce */
		if (oidc_proto_validate_nonce(r, cfg, provider, nonce, jwt) == FALSE)
			return FALSE;
	}

	/* validate the ID Token JWT, requiring iss match, and valid exp + iat */
	if (oidc_proto_validate_jwt(r, jwt, provider->issuer, TRUE, TRUE,
			provider->idtoken_iat_slack) == FALSE)
		return FALSE;

	/* check if the required-by-spec "sub" claim is present */
	if (jwt->payload.sub == NULL) {
		oidc_error(r,
				"id_token JSON payload did not contain the required-by-spec \"%s\" string value",
				OIDC_CLAIM_SUB);
		return FALSE;
	}

	/* verify the "aud" and "azp" values */
	if (oidc_proto_validate_aud_and_azp(r, cfg, provider,
			&jwt->payload) == FALSE)
		return FALSE;

	/* verify the included token binding ID if provided */
	if (oidc_proto_validate_cnf(r, cfg, provider, &jwt->payload) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * get the key from the JWKs that corresponds with the key specified in the header
 */
static apr_byte_t oidc_proto_get_key_from_jwks(request_rec *r, oidc_jwt_t *jwt,
		json_t *j_jwks, apr_hash_t *result) {

	apr_byte_t rc = TRUE;
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	char *jwk_json = NULL;

	/* get the (optional) thumbprint for comparison */
	const char *x5t = oidc_jwt_hdr_get(jwt, OIDC_JWK_X5T);
	oidc_debug(r, "search for kid \"%s\" or thumbprint x5t \"%s\"",
			jwt->header.kid, x5t);

	/* get the "keys" JSON array from the JWKs object */
	json_t *keys = json_object_get(j_jwks, OIDC_JWK_KEYS);
	if ((keys == NULL) || !(json_is_array(keys))) {
		oidc_error(r, "\"%s\" array element is not a JSON array",
				OIDC_JWK_KEYS);
		return FALSE;
	}

	int i;
	for (i = 0; i < json_array_size(keys); i++) {

		/* get the next element in the array */
		json_t *elem = json_array_get(keys, i);

		if (oidc_jwk_parse_json(r->pool, elem, &jwk, &err) == FALSE) {
			oidc_warn(r, "oidc_jwk_parse_json failed: %s",
					oidc_jose_e2s(r->pool, err));
			continue;
		}

		/* get the key type and see if it is the type that we are looking for */
		if (oidc_jwt_alg2kty(jwt) != jwk->kty) {
			oidc_debug(r,
					"skipping non matching kty=%d for kid=%s because it doesn't match requested kty=%d, kid=%s",
					jwk->kty, jwk->kid, oidc_jwt_alg2kty(jwt), jwt->header.kid);
			oidc_jwk_destroy(jwk);
			continue;
		}

		/* see if we were looking for a specific kid, if not we'll include any key that matches the type */
		if ((jwt->header.kid == NULL) && (x5t == NULL)) {
			const char *use = json_string_value(
					json_object_get(elem, OIDC_JWK_USE));
			if ((use != NULL) && (strcmp(use, OIDC_JWK_SIG) != 0)) {
				oidc_debug(r,
						"skipping key because of non-matching \"%s\": \"%s\"",
						OIDC_JWK_USE, use);
				oidc_jwk_destroy(jwk);
			} else {
				oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
				oidc_debug(r,
						"no kid/x5t to match, include matching key type: %s",
						jwk_json);
				if (jwk->kid != NULL)
					apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
				else
					// can do this because we never remove anything from the list
					apr_hash_set(result,
							apr_psprintf(r->pool, "%d", apr_hash_count(result)),
							APR_HASH_KEY_STRING, jwk);
			}
			continue;
		}

		/* we are looking for a specific kid, get the kid from the current element */
		/* compare the requested kid against the current element */
		if ((jwt->header.kid != NULL) && (jwk->kid != NULL)
				&& (apr_strnatcmp(jwt->header.kid, jwk->kid) == 0)) {
			oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
			oidc_debug(r, "found matching kid: \"%s\" for jwk: %s",
					jwt->header.kid, jwk_json);
			apr_hash_set(result, jwt->header.kid, APR_HASH_KEY_STRING, jwk);
			break;
		}

		/* we are looking for a specific x5t, get the x5t from the current element */
		char *s_x5t = NULL;
		oidc_json_object_get_string(r->pool, elem, OIDC_JWK_X5T, &s_x5t, NULL);
		/* compare the requested thumbprint against the current element */
		if ((s_x5t != NULL) && (x5t != NULL)
				&& (apr_strnatcmp(x5t, s_x5t) == 0)) {
			oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
			oidc_debug(r, "found matching %s: \"%s\" for jwk: %s", OIDC_JWK_X5T,
					x5t, jwk_json);
			apr_hash_set(result, x5t, APR_HASH_KEY_STRING, jwk);
			break;
		}

		/* the right key type but no matching kid/x5t */
		oidc_jwk_destroy(jwk);
	}

	return rc;
}

/*
 * get the keys from the (possibly cached) set of JWKs on the jwk_uri that corresponds with the key specified in the header
 */
apr_byte_t oidc_proto_get_keys_from_jwks_uri(request_rec *r, oidc_cfg *cfg,
		oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri, apr_hash_t *keys,
		apr_byte_t *force_refresh) {

	json_t *j_jwks = NULL;

	/* get the set of JSON Web Keys for this provider (possibly by downloading them from the specified provider->jwk_uri) */
	oidc_metadata_jwks_get(r, cfg, jwks_uri, &j_jwks, force_refresh);
	if (j_jwks == NULL) {
		oidc_error(r, "could not %s JSON Web Keys",
				*force_refresh ? "refresh" : "get");
		return FALSE;
	}

	/*
	 * get the key corresponding to the kid from the header, referencing the key that
	 * was used to sign this message (or get all keys in case no kid was set)
	 *
	 * we don't check the error return value because we'll treat "error" in the same
	 * way as "key not found" i.e. by refreshing the keys from the JWKs URI if not
	 * already done
	 */
	oidc_proto_get_key_from_jwks(r, jwt, j_jwks, keys);

	/* no need anymore for the parsed json_t contents, release the it */
	json_decref(j_jwks);

	/* if we've got no keys and we did not do a fresh download, then the cache may be stale */
	if ((apr_hash_count(keys) < 1) && (*force_refresh == FALSE)) {

		/* we did not get a key, but we have not refreshed the JWKs from the jwks_uri yet */
		oidc_warn(r,
				"could not find a key in the cached JSON Web Keys, doing a forced refresh in case keys were rolled over");
		/* get the set of JSON Web Keys forcing a fresh download from the specified JWKs URI */
		*force_refresh = TRUE;
		return oidc_proto_get_keys_from_jwks_uri(r, cfg, jwt, jwks_uri, keys,
				force_refresh);
	}

	oidc_debug(r,
			"returning %d key(s) obtained from the (possibly cached) JWKs URI",
			apr_hash_count(keys));

	return TRUE;
}

/*
 * verify the signature on a JWT using the dynamically obtained and statically configured keys
 */
apr_byte_t oidc_proto_jwt_verify(request_rec *r, oidc_cfg *cfg, oidc_jwt_t *jwt,
		const oidc_jwks_uri_t *jwks_uri, apr_hash_t *static_keys) {

	oidc_jose_error_t err;
	apr_hash_t *dynamic_keys = apr_hash_make(r->pool);

	/* see if we've got a JWKs URI set for signature validation with dynamically obtained asymmetric keys */
	if (jwks_uri->url == NULL) {
		oidc_debug(r,
				"\"jwks_uri\" is not set, signature validation will only be performed against statically configured keys");
		/* the JWKs URI was provided, but let's see if it makes sense to pull down keys, i.e. if it is an asymmetric signature */
	} /*else if (oidc_jose_signature_is_hmac(r->pool, jwt)) {
	 oidc_debug(r,
	 "\"jwks_uri\" is set, but the JWT has a symmetric signature so we won't pull/use keys from there");
	 } */else {
		 apr_byte_t force_refresh = FALSE;
		 /* get the key from the JWKs that corresponds with the key specified in the header */
		 if (oidc_proto_get_keys_from_jwks_uri(r, cfg, jwt, jwks_uri,
				 dynamic_keys, &force_refresh) == FALSE) {
			 oidc_jwk_list_destroy(r->pool, dynamic_keys);
			 return FALSE;
		 }
	 }

	/* do the actual JWS verification with the locally and remotely provided key material */
	// TODO: now static keys "win" if the same `kid` was used in both local and remote key sets
	if (oidc_jwt_verify(r->pool, jwt,
			oidc_util_merge_key_sets(r->pool, static_keys, dynamic_keys),
			&err) == FALSE) {
		oidc_error(r, "JWT signature verification failed: %s",
				oidc_jose_e2s(r->pool, err));
		oidc_jwk_list_destroy(r->pool, dynamic_keys);
		return FALSE;
	}

	oidc_debug(r,
			"JWT signature verification with algorithm \"%s\" was successful",
			jwt->header.alg);

	oidc_jwk_list_destroy(r->pool, dynamic_keys);
	return TRUE;
}

/*
 * return the compact-encoded JWT header contents
 */
char *oidc_proto_peek_jwt_header(request_rec *r,
		const char *compact_encoded_jwt, char **alg) {
	char *input = NULL, *result = NULL;
	char *p = strstr(compact_encoded_jwt ? compact_encoded_jwt : "", ".");
	if (p == NULL) {
		oidc_warn(r,
				"could not parse first element separated by \".\" from input");
		return NULL;
	}
	input = apr_pstrmemdup(r->pool, compact_encoded_jwt,
			strlen(compact_encoded_jwt) - strlen(p));
	if (oidc_base64url_decode(r->pool, &result, input) <= 0) {
		oidc_warn(r, "oidc_base64url_decode returned an error");
		return NULL;
	}
	if (alg) {
		json_t *json = NULL;
		oidc_util_decode_json_object(r, result, &json);
		if (json)
			*alg = apr_pstrdup(r->pool,
					json_string_value(json_object_get(json, CJOSE_HDR_ALG)));
		json_decref(json);
	}
	return result;
}

/*
 * check whether the provided string is a valid id_token and return its parsed contents
 */
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *id_token, const char *nonce,
		oidc_jwt_t **jwt, apr_byte_t is_code_flow) {

	char *alg = NULL;
	oidc_debug(r, "enter: id_token header=%s",
			oidc_proto_peek_jwt_header(r, id_token, &alg));

	char buf[APR_RFC822_DATE_LEN + 1];
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	if (oidc_util_create_symmetric_key(r, provider->client_secret,
			oidc_alg2keysize(alg), OIDC_JOSE_ALG_SHA256,
			TRUE, &jwk) == FALSE)
		return FALSE;

	if (oidc_jwt_parse(r->pool, id_token, jwt,
			oidc_util_merge_symmetric_key(r->pool, cfg->private_keys, jwk),
			&err) == FALSE) {
		oidc_error(r, "oidc_jwt_parse failed: %s", oidc_jose_e2s(r->pool, err));
		oidc_jwt_destroy(*jwt);
		*jwt = NULL;
		return FALSE;
	}

	oidc_jwk_destroy(jwk);
	oidc_debug(r,
			"successfully parsed (and possibly decrypted) JWT with header=%s, and payload=%s",
			(*jwt)->header.value.str, (*jwt)->payload.value.str);

	// make signature validation exception for 'code' flow and the algorithm NONE
	if (is_code_flow == FALSE || strcmp((*jwt)->header.alg, "none") != 0) {

		jwk = NULL;
		if (oidc_util_create_symmetric_key(r, provider->client_secret, 0,
				NULL, TRUE, &jwk) == FALSE)
			return FALSE;

		oidc_jwks_uri_t jwks_uri = { provider->jwks_uri,
				provider->jwks_refresh_interval, provider->ssl_validate_server };
		if (oidc_proto_jwt_verify(r, cfg, *jwt, &jwks_uri,
				oidc_util_merge_symmetric_key(r->pool, NULL, jwk)) == FALSE) {

			oidc_error(r,
					"id_token signature could not be validated, aborting");
			oidc_jwt_destroy(*jwt);
			*jwt = NULL;
			oidc_jwk_destroy(jwk);
			return FALSE;
		}
		oidc_jwk_destroy(jwk);
	}

	/* this is where the meat is */
	if (oidc_proto_validate_idtoken(r, provider, *jwt, nonce) == FALSE) {
		oidc_error(r, "id_token payload could not be validated, aborting");
		oidc_jwt_destroy(*jwt);
		*jwt = NULL;
		return FALSE;
	}

	/* log our results */

	apr_rfc822_date(buf, apr_time_from_sec((*jwt)->payload.exp));
	oidc_debug(r,
			"valid id_token for user \"%s\" expires: [%s], in %ld secs from now)",
			(*jwt)->payload.sub, buf,
			(long)((*jwt)->payload.exp - apr_time_sec(apr_time_now())));

	/* since we've made it so far, we may as well say it is a valid id_token */
	return TRUE;
}

/*
 * check that the access_token type is supported
 */
static apr_byte_t oidc_proto_validate_token_type(request_rec *r,
		oidc_provider_t *provider, const char *token_type) {
	/*  we only support bearer/Bearer  */
	if ((token_type != NULL)
			&& (apr_strnatcasecmp(token_type, OIDC_PROTO_BEARER) != 0)
			&& (provider->userinfo_endpoint_url != NULL)) {
		oidc_error(r,
				"token_type is \"%s\" and UserInfo endpoint (%s) for issuer \"%s\" is set: can only deal with \"%s\" authentication against a UserInfo endpoint!",
				token_type, provider->userinfo_endpoint_url, provider->issuer,
				OIDC_PROTO_BEARER);
		return FALSE;
	}
	return TRUE;
}

/*
 * setup for an endpoint call without authentication
 */
static apr_byte_t oidc_proto_endpoint_auth_none(request_rec *r,
		const char *client_id, apr_table_t *params) {
	oidc_debug(r,
			"no client secret is configured; calling the token endpoint without client authentication; only public clients are supported");
	apr_table_set(params, OIDC_PROTO_CLIENT_ID, client_id);
	return TRUE;
}

/*
 * setup for an endpoint call with HTTP Basic authentication
 */
static apr_byte_t oidc_proto_endpoint_auth_basic(request_rec *r,
		const char *client_id, const char *client_secret, char **basic_auth_str) {
	oidc_debug(r, "enter");
	if (client_secret == NULL) {
		oidc_error(r, "no client secret is configured");
		return FALSE;
	}
	*basic_auth_str = apr_psprintf(r->pool, "%s:%s", client_id, client_secret);
	return TRUE;
}

/*
 * setup for an endpoint call with authentication in POST parameters
 */
static apr_byte_t oidc_proto_endpoint_auth_post(request_rec *r,
		const char *client_id, const char *client_secret, apr_table_t *params) {
	oidc_debug(r, "enter");
	if (client_secret == NULL) {
		oidc_error(r, "no client secret is configured");
		return FALSE;
	}
	apr_table_set(params, OIDC_PROTO_CLIENT_ID, client_id);
	apr_table_set(params, OIDC_PROTO_CLIENT_SECRET, client_secret);
	return TRUE;
}

#define OIDC_PROTO_ASSERTION_JTI_LEN 16

/*
 * helper function to create a JWT assertion for endpoint authentication
 */
static apr_byte_t oidc_proto_jwt_create(request_rec *r, const char *client_id,
		const char *audience, oidc_jwt_t **out) {

	*out = oidc_jwt_new(r->pool, TRUE, TRUE);
	oidc_jwt_t *jwt = *out;

	char *jti = NULL;
	oidc_proto_generate_random_string(r, &jti, OIDC_PROTO_ASSERTION_JTI_LEN);

	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_ISS,
			json_string(client_id));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_SUB,
			json_string(client_id));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_AUD,
			json_string(audience));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_JTI,
			json_string(jti));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_EXP,
			json_integer(apr_time_sec(apr_time_now()) + 60));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_IAT,
			json_integer(apr_time_sec(apr_time_now())));

	return TRUE;
}

/*
 * helper function to add a JWT assertion to the HTTP request as endpoint authentication
 */
static apr_byte_t oidc_proto_jwt_sign_and_add(request_rec *r,
		apr_table_t *params, oidc_jwt_t *jwt, oidc_jwk_t *jwk) {
	oidc_jose_error_t err;

	if (oidc_jwt_sign(r->pool, jwt, jwk, &err) == FALSE) {
		oidc_error(r, "signing JWT failed: %s", oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	char *cser = oidc_jwt_serialize(r->pool, jwt, &err);
	if (cser == NULL) {
		oidc_error(r, "oidc_jwt_serialize failed: %s",
				oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	apr_table_setn(params, OIDC_PROTO_CLIENT_ASSERTION_TYPE,
			OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER);
	apr_table_set(params, OIDC_PROTO_CLIENT_ASSERTION, cser);

	return TRUE;
}

#define OIDC_PROTO_JWT_ASSERTION_SYMMETRIC_ALG CJOSE_HDR_ALG_HS256

static apr_byte_t oidc_proto_endpoint_auth_client_secret_jwt(request_rec *r,
		const char *client_id, const char *client_secret, const char *audience,
		apr_table_t *params) {
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;

	oidc_debug(r, "enter");

	if (oidc_proto_jwt_create(r, client_id, audience, &jwt) == FALSE)
		return FALSE;

	oidc_jwk_t *jwk = oidc_jwk_create_symmetric_key(r->pool, NULL,
			(const unsigned char *) client_secret, strlen(client_secret), FALSE,
			&err);
	if (jwk == NULL) {
		oidc_error(r, "parsing of client secret into JWK failed: %s",
				oidc_jose_e2s(r->pool, err));
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	jwt->header.alg = apr_pstrdup(r->pool,
			OIDC_PROTO_JWT_ASSERTION_SYMMETRIC_ALG);

	oidc_proto_jwt_sign_and_add(r, params, jwt, jwk);

	oidc_jwt_destroy(jwt);
	oidc_jwk_destroy(jwk);

	return TRUE;
}

static apr_byte_t oidc_proto_endpoint_access_token_bearer(request_rec *r,
		oidc_cfg *cfg, const char *bearer_access_token, char **bearer_auth_str) {

	apr_byte_t rv = TRUE;

	if (bearer_access_token != NULL) {
		*bearer_auth_str = apr_psprintf(r->pool, "%s", bearer_access_token);
	} else {
		oidc_error(r,
				"endpoint auth method set to bearer access token but no token is provided");
		rv = FALSE;
	}

	return rv;
}

#define OIDC_PROTO_JWT_ASSERTION_ASYMMETRIC_ALG CJOSE_HDR_ALG_RS256

static apr_byte_t oidc_proto_endpoint_auth_private_key_jwt(request_rec *r,
		oidc_cfg *cfg, const char *client_id, const char *audience,
		apr_table_t *params) {
	oidc_jwt_t *jwt = NULL;
	oidc_jwk_t *jwk = NULL;

	oidc_debug(r, "enter");

	if (oidc_proto_jwt_create(r, client_id, audience, &jwt) == FALSE)
		return FALSE;

	if (cfg->private_keys == NULL) {
		oidc_error(r,
				"no private keys have been configured to use for private_key_jwt client authentication (" OIDCPrivateKeyFiles ")");
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	apr_ssize_t klen = 0;
	apr_hash_index_t *hi = apr_hash_first(r->pool, cfg->private_keys);
	apr_hash_this(hi, (const void **) &jwt->header.kid, &klen, (void **) &jwk);

	jwt->header.alg = apr_pstrdup(r->pool, CJOSE_HDR_ALG_RS256);

	oidc_proto_jwt_sign_and_add(r, params, jwt, jwk);

	oidc_jwt_destroy(jwt);

	return TRUE;
}

apr_byte_t oidc_proto_token_endpoint_auth(request_rec *r, oidc_cfg *cfg,
		const char *token_endpoint_auth, const char *client_id,
		const char *client_secret, const char *audience, apr_table_t *params,
		const char *bearer_access_token, char **basic_auth_str, char **bearer_auth_str) {

	oidc_debug(r, "token_endpoint_auth=%s", token_endpoint_auth);

	if (client_id == NULL) {
		oidc_debug(r, "no client ID set: assume we don't need to authenticate");
		return TRUE;
	}

	// default is client_secret_basic, but only if a client_secret is set,
	// otherwise we are a public client
	if ((token_endpoint_auth == NULL) && (client_secret != NULL))
		token_endpoint_auth = OIDC_PROTO_CLIENT_SECRET_BASIC;

	if ((token_endpoint_auth == NULL) || (apr_strnatcmp(token_endpoint_auth,
			OIDC_PROTO_ENDPOINT_AUTH_NONE) == 0))
		return oidc_proto_endpoint_auth_none(r, client_id, params);

	// if no client_secret is set and we don't authenticate using private_key_jwt,
	// we can only be a public client since the other methods require a client_secret
	if ((client_secret == NULL) && (apr_strnatcmp(token_endpoint_auth,
			OIDC_PROTO_PRIVATE_KEY_JWT) != 0)) {
		oidc_debug(r,
				"no client secret set and not using private_key_jwt, assume we are a public client");
		return oidc_proto_endpoint_auth_none(r, client_id, params);
	}

	if (apr_strnatcmp(token_endpoint_auth,
			OIDC_PROTO_CLIENT_SECRET_BASIC) == 0)
		return oidc_proto_endpoint_auth_basic(r, client_id, client_secret,
				basic_auth_str);

	if (apr_strnatcmp(token_endpoint_auth,
			OIDC_PROTO_CLIENT_SECRET_POST) == 0)
		return oidc_proto_endpoint_auth_post(r, client_id, client_secret,
				params);

	if (apr_strnatcmp(token_endpoint_auth,
			OIDC_PROTO_CLIENT_SECRET_JWT) == 0)
		return oidc_proto_endpoint_auth_client_secret_jwt(r, client_id,
				client_secret, audience, params);

	if (apr_strnatcmp(token_endpoint_auth,
			OIDC_PROTO_PRIVATE_KEY_JWT) == 0)
		return oidc_proto_endpoint_auth_private_key_jwt(r, cfg, client_id,
				audience, params);

	if (apr_strnatcmp(token_endpoint_auth,
			OIDC_PROTO_BEARER_ACCESS_TOKEN) == 0) {
		return oidc_proto_endpoint_access_token_bearer(r, cfg, bearer_access_token, bearer_auth_str);
	}

	oidc_error(r, "uhm, shouldn't be here...");

	return FALSE;
}

/*
 * send a code/refresh request to the token endpoint and return the parsed contents
 */
static apr_byte_t oidc_proto_token_endpoint_request(request_rec *r,
		oidc_cfg *cfg, oidc_provider_t *provider, apr_table_t *params,
		char **id_token, char **access_token, char **token_type,
		int *expires_in, char **refresh_token) {

	char *response = NULL;
	char *basic_auth = NULL;
	char *bearer_auth = NULL;

	/* add the token endpoint authentication credentials */
	if (oidc_proto_token_endpoint_auth(r, cfg, provider->token_endpoint_auth,
			provider->client_id, provider->client_secret,
			provider->token_endpoint_url, params, NULL, &basic_auth,
			&bearer_auth) == FALSE)
		return FALSE;

	/* add any configured extra static parameters to the token endpoint */
	oidc_util_table_add_query_encoded_params(r->pool, params,
			provider->token_endpoint_params);

	/* send the refresh request to the token endpoint */
	if (oidc_util_http_post_form(r, provider->token_endpoint_url, params,
			basic_auth, bearer_auth, provider->ssl_validate_server, &response,
			cfg->http_timeout_long, cfg->outgoing_proxy,
			oidc_dir_cfg_pass_cookies(r),
			oidc_util_get_full_path(r->pool,
					provider->token_endpoint_tls_client_cert),
					oidc_util_get_full_path(r->pool,
							provider->token_endpoint_tls_client_key)) == FALSE) {
		oidc_warn(r, "error when calling the token endpoint (%s)",
				provider->token_endpoint_url);
		return FALSE;
	}

	/* check for errors, the response itself will have been logged already */
	json_t *result = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	/* get the id_token from the parsed response */
	oidc_json_object_get_string(r->pool, result, OIDC_PROTO_ID_TOKEN, id_token,
			NULL);

	/* get the access_token from the parsed response */
	oidc_json_object_get_string(r->pool, result, OIDC_PROTO_ACCESS_TOKEN,
			access_token,
			NULL);

	/* get the token type from the parsed response */
	oidc_json_object_get_string(r->pool, result, OIDC_PROTO_TOKEN_TYPE,
			token_type,
			NULL);

	/* check the new token type */
	if (token_type != NULL) {
		if (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE) {
			oidc_warn(r, "access token type did not validate, dropping it");
			*access_token = NULL;
		}
	}

	/* get the expires_in value */
	oidc_json_object_get_int(r->pool, result, OIDC_PROTO_EXPIRES_IN, expires_in,
			-1);

	/* get the refresh_token from the parsed response */
	oidc_json_object_get_string(r->pool, result, OIDC_PROTO_REFRESH_TOKEN,
			refresh_token,
			NULL);

	json_decref(result);

	return TRUE;
}

/*
 * resolves the code received from the OP in to an id_token, access_token and refresh_token
 */
static apr_byte_t oidc_proto_resolve_code(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *code, const char *code_verifier,
		char **id_token, char **access_token, char **token_type,
		int *expires_in, char **refresh_token, const char *state) {

	oidc_debug(r, "enter");

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE,
			OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE);
	apr_table_setn(params, OIDC_PROTO_CODE, code);
	apr_table_set(params, OIDC_PROTO_REDIRECT_URI,
			oidc_get_redirect_uri_iss(r, cfg, provider));

	if (code_verifier)
		apr_table_setn(params, OIDC_PROTO_CODE_VERIFIER, code_verifier);

	if (state)
		apr_table_setn(params, OIDC_PROTO_STATE, state);

	return oidc_proto_token_endpoint_request(r, cfg, provider, params, id_token,
			access_token, token_type, expires_in, refresh_token);
}

/*
 * refreshes the access_token/id_token /refresh_token received from the OP using the refresh_token
 */
apr_byte_t oidc_proto_refresh_request(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *rtoken, char **id_token,
		char **access_token, char **token_type, int *expires_in,
		char **refresh_token) {

	oidc_debug(r, "enter");

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE,
			OIDC_PROTO_GRANT_TYPE_REFRESH_TOKEN);
	apr_table_setn(params, OIDC_PROTO_REFRESH_TOKEN, rtoken);
	apr_table_setn(params, OIDC_PROTO_SCOPE, provider->scope);

	return oidc_proto_token_endpoint_request(r, cfg, provider, params, id_token,
			access_token, token_type, expires_in, refresh_token);
}

static apr_byte_t oidc_user_info_response_validate(request_rec *r,
		oidc_cfg *cfg, oidc_provider_t *provider, char **response,
		json_t **claims, char **userinfo_jwt) {

	oidc_debug(r,
			"enter: userinfo_signed_response_alg=%s, userinfo_encrypted_response_alg=%s, userinfo_encrypted_response_enc=%s",
			provider->userinfo_signed_response_alg,
			provider->userinfo_encrypted_response_alg,
			provider->userinfo_encrypted_response_enc);

	char *alg = NULL;
	if ((provider->userinfo_signed_response_alg != NULL)
			|| (provider->userinfo_encrypted_response_alg != NULL)
			|| (provider->userinfo_encrypted_response_enc != NULL)) {
		oidc_debug(r, "JWT header=%s",
				oidc_proto_peek_jwt_header(r, *response, &alg));
	}

	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	oidc_jwt_t *jwt = NULL;
	char *payload = NULL;

	if (oidc_util_create_symmetric_key(r, provider->client_secret,
			oidc_alg2keysize(alg), OIDC_JOSE_ALG_SHA256,
			TRUE, &jwk) == FALSE)
		return FALSE;

	if (provider->userinfo_encrypted_response_alg != NULL) {
		if (oidc_jwe_decrypt(r->pool, *response,
				oidc_util_merge_symmetric_key(r->pool, cfg->private_keys, jwk),
				&payload, &err, TRUE) == FALSE) {
			oidc_error(r, "oidc_jwe_decrypt failed: %s",
					oidc_jose_e2s(r->pool, err));
			oidc_jwk_destroy(jwk);
			return FALSE;
		} else {
			oidc_debug(r,
					"successfully decrypted JWE returned from userinfo endpoint: %s",
					payload);
			*response = payload;
		}
	}

	if (provider->userinfo_signed_response_alg != NULL) {
		if (oidc_jwt_parse(r->pool, *response, &jwt,
				oidc_util_merge_symmetric_key(r->pool, cfg->private_keys, jwk),
				&err) == FALSE) {
			oidc_error(r, "oidc_jwt_parse failed: %s",
					oidc_jose_e2s(r->pool, err));
			oidc_jwt_destroy(jwt);
			oidc_jwk_destroy(jwk);
			return FALSE;
		}
		oidc_debug(r, "successfully parsed JWT with header=%s, and payload=%s",
				jwt->header.value.str, jwt->payload.value.str);

		oidc_jwk_destroy(jwk);

		jwk = NULL;
		if (oidc_util_create_symmetric_key(r, provider->client_secret, 0,
				NULL, TRUE, &jwk) == FALSE)
			return FALSE;

		oidc_jwks_uri_t jwks_uri = { provider->jwks_uri,
				provider->jwks_refresh_interval, provider->ssl_validate_server };
		if (oidc_proto_jwt_verify(r, cfg, jwt, &jwks_uri,
				oidc_util_merge_symmetric_key(r->pool, NULL, jwk)) == FALSE) {

			oidc_error(r, "JWT signature could not be validated, aborting");
			oidc_jwt_destroy(jwt);
			oidc_jwk_destroy(jwk);
			return FALSE;
		}
		oidc_jwk_destroy(jwk);
		oidc_debug(r,
				"successfully verified signed JWT returned from userinfo endpoint: %s",
				jwt->payload.value.str);

		*userinfo_jwt = apr_pstrdup(r->pool, *response);
		*claims = json_deep_copy(jwt->payload.value.json);
		*response = apr_pstrdup(r->pool, jwt->payload.value.str);
		oidc_jwt_destroy(jwt);

		return TRUE;
	}

	oidc_jwk_destroy(jwk);

	return oidc_util_decode_json_and_check_error(r, *response, claims);
}

#define OIDC_COMPOSITE_CLAIM_NAMES        "_claim_names"
#define OIDC_COMPOSITE_CLAIM_SOURCES      "_claim_sources"
#define OIDC_COMPOSITE_CLAIM_JWT          "JWT"
#define OIDC_COMPOSITE_CLAIM_ACCESS_TOKEN OIDC_PROTO_ACCESS_TOKEN
#define OIDC_COMPOSITE_CLAIM_ENDPOINT     "endpoint"

static apr_byte_t oidc_proto_resolve_composite_claims(request_rec *r,
		oidc_cfg *cfg, json_t *claims) {
	const char *key;
	json_t *value;
	void *iter;
	json_t *sources, *names, *decoded;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;

	oidc_debug(r, "enter");

	names = json_object_get(claims, OIDC_COMPOSITE_CLAIM_NAMES);
	if ((names == NULL) || (!json_is_object(names)))
		return FALSE;

	sources = json_object_get(claims, OIDC_COMPOSITE_CLAIM_SOURCES);
	if ((sources == NULL) || (!json_is_object(sources))) {
		oidc_debug(r, "%s found, but no %s found", OIDC_COMPOSITE_CLAIM_NAMES,
				OIDC_COMPOSITE_CLAIM_SOURCES);
		return FALSE;
	}

	decoded = json_object();

	iter = json_object_iter(sources);
	while (iter) {
		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		if ((value != NULL) && (json_is_object(value))) {
			json_t *jwt = json_object_get(value, OIDC_COMPOSITE_CLAIM_JWT);
			char *s_json = NULL;
			if ((jwt != NULL) && (json_is_string(jwt))) {
				s_json = apr_pstrdup(r->pool, json_string_value(jwt));
			} else {
				const char *access_token = json_string_value(
						json_object_get(value,
								OIDC_COMPOSITE_CLAIM_ACCESS_TOKEN));
				const char *endpoint = json_string_value(
						json_object_get(value, OIDC_COMPOSITE_CLAIM_ENDPOINT));
				if ((access_token != NULL) && (endpoint != NULL)) {
					oidc_util_http_get(r, endpoint,
							NULL, NULL, access_token, cfg->provider.ssl_validate_server,
							&s_json, cfg->http_timeout_long,
							cfg->outgoing_proxy, oidc_dir_cfg_pass_cookies(r),
							NULL, NULL);
				}
			}
			if ((s_json != NULL) && (strcmp(s_json, "") != 0)) {
				oidc_jwt_t *jwt = NULL;
				if (oidc_jwt_parse(r->pool, s_json, &jwt,
						oidc_util_merge_symmetric_key(r->pool,
								cfg->private_keys, jwk), &err) == FALSE) {
					oidc_error(r,
							"could not parse JWT from aggregated claim \"%s\": %s",
							key, oidc_jose_e2s(r->pool, err));
				} else {
					json_t *v = json_object_get(decoded, key);
					if (v == NULL) {
						v = json_object();
						json_object_set_new(decoded, key, v);
					}
					oidc_util_json_merge(r, jwt->payload.value.json, v);
				}
				oidc_jwt_destroy(jwt);
			}
		}
		iter = json_object_iter_next(sources, iter);
	}

	iter = json_object_iter(names);
	while (iter) {
		key = json_object_iter_key(iter);
		const char *s_value = json_string_value(json_object_iter_value(iter));
		if (s_value != NULL) {
			oidc_debug(r, "processing: %s: %s", key, s_value);
			json_t *values = json_object_get(decoded, s_value);
			if (values != NULL) {
				json_object_set(claims, key, json_object_get(values, key));
			} else {
				oidc_warn(r, "no values for source \"%s\" found", s_value);
			}
		} else {
			oidc_warn(r, "no string value found for claim \"%s\"", key);
		}
		iter = json_object_iter_next(names, iter);
	}

	json_object_del(claims, OIDC_COMPOSITE_CLAIM_NAMES);
	json_object_del(claims, OIDC_COMPOSITE_CLAIM_SOURCES);
	json_decref(decoded);

	return TRUE;
}

/*
 * get claims from the OP UserInfo endpoint using the provided access_token
 */
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *id_token_sub,
		const char *access_token, char **response, char **userinfo_jwt) {

	oidc_debug(r, "enter, endpoint=%s, access_token=%s",
			provider->userinfo_endpoint_url, access_token);

	/* get the JSON response */
	if (provider->userinfo_token_method == OIDC_USER_INFO_TOKEN_METHOD_HEADER) {
		if (oidc_util_http_get(r, provider->userinfo_endpoint_url,
				NULL, NULL, access_token, provider->ssl_validate_server, response,
				cfg->http_timeout_long, cfg->outgoing_proxy,
				oidc_dir_cfg_pass_cookies(r), NULL, NULL) == FALSE)
			return FALSE;
	} else if (provider->userinfo_token_method
			== OIDC_USER_INFO_TOKEN_METHOD_POST) {
		apr_table_t *params = apr_table_make(r->pool, 4);
		apr_table_setn(params, OIDC_PROTO_ACCESS_TOKEN, access_token);
		if (oidc_util_http_post_form(r, provider->userinfo_endpoint_url, params,
				NULL, access_token, provider->ssl_validate_server, response,
				cfg->http_timeout_long, cfg->outgoing_proxy,
				oidc_dir_cfg_pass_cookies(r), NULL, NULL) == FALSE)
			return FALSE;
	} else {
		oidc_error(r, "unsupported userinfo token presentation method: %d",
				provider->userinfo_token_method);
		return FALSE;
	}

	json_t *claims = NULL;
	if (oidc_user_info_response_validate(r, cfg, provider, response, &claims,
			userinfo_jwt) == FALSE)
		return FALSE;

	if (oidc_proto_resolve_composite_claims(r, cfg, claims) == TRUE)
		*response = oidc_util_encode_json_object(r, claims,
				JSON_PRESERVE_ORDER | JSON_COMPACT);

	char *user_info_sub = NULL;
	oidc_jose_get_string(r->pool, claims, OIDC_CLAIM_SUB, FALSE, &user_info_sub,
			NULL);

	oidc_debug(r, "id_token_sub=%s, user_info_sub=%s", id_token_sub,
			user_info_sub);

	if ((id_token_sub != NULL) && (user_info_sub != NULL)) {
		if (apr_strnatcmp(id_token_sub, user_info_sub) != 0) {
			oidc_error(r,
					"\"%s\" claim (\"%s\") returned from userinfo endpoint does not match the one in the id_token (\"%s\")",
					OIDC_CLAIM_SUB, user_info_sub, id_token_sub);
			json_decref(claims);
			return FALSE;
		}
	}

	json_decref(claims);

	return TRUE;
}

/*
 * based on a resource perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and store its metadata
 */
static apr_byte_t oidc_proto_webfinger_discovery(request_rec *r, oidc_cfg *cfg,
		const char *resource, const char *domain, char **issuer) {

	const char *url = apr_psprintf(r->pool, "https://%s/.well-known/webfinger",
			domain);

	apr_table_t *params = apr_table_make(r->pool, 1);
	apr_table_setn(params, "resource", resource);
	apr_table_setn(params, "rel", "http://openid.net/specs/connect/1.0/issuer");

	char *response = NULL;
	if (oidc_util_http_get(r, url, params, NULL, NULL,
			cfg->provider.ssl_validate_server, &response,
			cfg->http_timeout_short, cfg->outgoing_proxy,
			oidc_dir_cfg_pass_cookies(r), NULL, NULL) == FALSE) {
		/* errors will have been logged by now */
		return FALSE;
	}

	/* decode and see if it is not an error response somehow */
	json_t *j_response = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &j_response) == FALSE)
		return FALSE;

	/* get the links parameter */
	json_t *j_links = json_object_get(j_response, "links");
	if ((j_links == NULL) || (!json_is_array(j_links))) {
		oidc_error(r, "response JSON object did not contain a \"links\" array");
		json_decref(j_response);
		return FALSE;
	}

	/* get the one-and-only object in the "links" array */
	json_t *j_object = json_array_get(j_links, 0);
	if ((j_object == NULL) || (!json_is_object(j_object))) {
		oidc_error(r,
				"response JSON object did not contain a JSON object as the first element in the \"links\" array");
		json_decref(j_response);
		return FALSE;
	}

	/* get the href from that object, which is the issuer value */
	json_t *j_href = json_object_get(j_object, "href");
	if ((j_href == NULL) || (!json_is_string(j_href))) {
		oidc_error(r,
				"response JSON object did not contain a \"href\" element in the first \"links\" array object");
		json_decref(j_response);
		return FALSE;
	}

	/* check that the link is on secure HTTPs */
	if (oidc_valid_url(r->pool, json_string_value(j_href), "https") != NULL) {
		oidc_error(r,
				"response JSON object contains an \"href\" value that is not a valid \"https\" URL: %s",
				json_string_value(j_href));
		json_decref(j_response);
		return FALSE;
	}

	*issuer = apr_pstrdup(r->pool, json_string_value(j_href));

	oidc_debug(r,
			"returning issuer \"%s\" for resource \"%s\" after doing successful webfinger-based discovery",
			*issuer, resource);

	json_decref(j_response);

	return TRUE;
}

/*
 * based on an account name, perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and store its metadata
 */
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg,
		const char *acct, char **issuer) {

	// TODO: maybe show intermediate/progress screen "discovering..."

	oidc_debug(r, "enter, acct=%s", acct);

	const char *resource = apr_psprintf(r->pool, "acct:%s", acct);
	const char *domain = strrchr(acct, OIDC_CHAR_AT);
	if (domain == NULL) {
		oidc_error(r, "invalid account name");
		return FALSE;
	}
	domain++;

	return oidc_proto_webfinger_discovery(r, cfg, resource, domain, issuer);
}

/*
 * based on user identifier URL, perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and store its metadata
 */
apr_byte_t oidc_proto_url_based_discovery(request_rec *r, oidc_cfg *cfg,
		const char *url, char **issuer) {

	oidc_debug(r, "enter, url=%s", url);

	apr_uri_t uri;
	apr_uri_parse(r->pool, url, &uri);

	char *domain = uri.hostname;
	if (uri.port_str != NULL)
		domain = apr_psprintf(r->pool, "%s:%s", domain, uri.port_str);

	return oidc_proto_webfinger_discovery(r, cfg, url, domain, issuer);
}

int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c) {

	oidc_debug(r, "enter");

	const char *java_script =
			"    <script type=\"text/javascript\">\n"
			"      function postOnLoad() {\n"
			"        encoded = location.hash.substring(1).split('&');\n"
			"        for (i = 0; i < encoded.length; i++) {\n"
			"          encoded[i].replace(/\\+/g, ' ');\n"
			"          var n = encoded[i].indexOf('=');\n"
			"          var input = document.createElement('input');\n"
			"          input.type = 'hidden';\n"
			"          input.name = decodeURIComponent(encoded[i].substring(0, n));\n"
			"          input.value = decodeURIComponent(encoded[i].substring(n+1));\n"
			"          document.forms[0].appendChild(input);\n"
			"        }\n"
			"        document.forms[0].action = window.location.href.substr(0, window.location.href.indexOf('#'));\n"
			"        document.forms[0].submit();\n"
			"      }\n"
			"    </script>\n";

	const char *html_body =
			"    <p>Submitting...</p>\n"
			"    <form method=\"post\" action=\"\">\n"
			"      <p>\n"
			"        <input type=\"hidden\" name=\"" OIDC_PROTO_RESPONSE_MODE "\" value=\"" OIDC_PROTO_RESPONSE_MODE_FRAGMENT "\">\n"
			"      </p>\n"
			"    </form>\n";

	return oidc_util_html_send(r, "Submitting...", java_script, "postOnLoad",
			html_body, DONE);
}

/*
 * check a provided hash value (at_hash|c_hash) against a corresponding hash calculated for a specified value and algorithm
 */
static apr_byte_t oidc_proto_validate_hash(request_rec *r, const char *alg,
		const char *hash, const char *value, const char *type) {

	char *calc = NULL;
	unsigned int calc_len = 0;
	unsigned int hash_len = oidc_jose_hash_length(alg) / 2;
	oidc_jose_error_t err;

	/* hash the provided access_token */
	if (oidc_jose_hash_string(r->pool, alg, value, &calc, &calc_len,
			&err) == FALSE) {
		oidc_error(r, "oidc_jose_hash_string failed: %s",
				oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	/* calculate the base64url-encoded value of the hash */
	char *decoded = NULL;
	unsigned int decoded_len = oidc_base64url_decode(r->pool, &decoded, hash);
	if (decoded_len <= 0) {
		oidc_error(r, "oidc_base64url_decode returned an error");
		return FALSE;
	}

	oidc_debug(r, "hash_len=%d, decoded_len=%d, calc_len=%d", hash_len,
			decoded_len, calc_len);

	/* compare the calculated hash against the provided hash */
	if ((decoded_len < hash_len) || (calc_len < hash_len)
			|| (memcmp(decoded, calc, hash_len) != 0)) {
		oidc_error(r,
				"provided \"%s\" hash value (%s) does not match the calculated value",
				type, hash);
		return FALSE;
	}

	oidc_debug(r,
			"successfully validated the provided \"%s\" hash value (%s) against the calculated value",
			type, hash);

	return TRUE;
}

/*
 * check a hash value in the id_token against the corresponding hash calculated over a provided value
 */
static apr_byte_t oidc_proto_validate_hash_value(request_rec *r,
		oidc_provider_t *provider, oidc_jwt_t *jwt, const char *response_type,
		const char *value, const char *key,
		apr_array_header_t *required_for_flows) {

	/*
	 * get the hash value from the id_token
	 */
	char *hash = NULL;
	oidc_jose_get_string(r->pool, jwt->payload.value.json, key, FALSE, &hash,
			NULL);

	/*
	 * check if the hash was present
	 */
	if (hash == NULL) {

		/* no hash..., now see if the flow required it */
		int i;
		for (i = 0; i < required_for_flows->nelts; i++) {
			if (oidc_util_spaced_string_equals(r->pool, response_type,
					((const char**) required_for_flows->elts)[i])) {
				oidc_warn(r, "flow is \"%s\", but no %s found in id_token",
						response_type, key);
				return FALSE;
			}
		}

		/* no hash but it was not required anyway */
		return TRUE;
	}

	/*
	 * we have a hash, validate it and return the result
	 */
	return oidc_proto_validate_hash(r, jwt->header.alg, hash, value, key);
}

/*
 * check the c_hash value in the id_token against the code
 */
apr_byte_t oidc_proto_validate_code(request_rec *r, oidc_provider_t *provider,
		oidc_jwt_t *jwt, const char *response_type, const char *code) {
	apr_array_header_t *required_for_flows = apr_array_make(r->pool, 2,
			sizeof(const char*));
	*(const char**) apr_array_push(required_for_flows) =
			OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN;
	*(const char**) apr_array_push(required_for_flows) =
			OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;
	if (oidc_proto_validate_hash_value(r, provider, jwt, response_type, code,
			OIDC_CLAIM_C_HASH, required_for_flows) == FALSE) {
		oidc_error(r, "could not validate code against \"%s\" claim value",
				OIDC_CLAIM_C_HASH);
		return FALSE;
	}
	return TRUE;
}

/*
 * check the at_hash value in the id_token against the access_token
 */
apr_byte_t oidc_proto_validate_access_token(request_rec *r,
		oidc_provider_t *provider, oidc_jwt_t *jwt, const char *response_type,
		const char *access_token) {
	apr_array_header_t *required_for_flows = apr_array_make(r->pool, 2,
			sizeof(const char*));
	*(const char**) apr_array_push(required_for_flows) =
			OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN;
	*(const char**) apr_array_push(required_for_flows) =
			OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;
	if (oidc_proto_validate_hash_value(r, provider, jwt, response_type,
			access_token, OIDC_CLAIM_AT_HASH, required_for_flows) == FALSE) {
		oidc_error(r,
				"could not validate access token against \"%s\" claim value",
				OIDC_CLAIM_AT_HASH);
		return FALSE;
	}
	return TRUE;
}

/*
 * return the supported flows
 */
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 6, sizeof(const char*));
	*(const char**) apr_array_push(result) = OIDC_PROTO_RESPONSE_TYPE_CODE;
	*(const char**) apr_array_push(result) = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN;
	*(const char**) apr_array_push(result) =
			OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN;
	*(const char**) apr_array_push(result) =
			OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN;
	*(const char**) apr_array_push(result) =
			OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN;
	*(const char**) apr_array_push(result) =
			OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;
	return result;
}

/*
 * check if a particular OpenID Connect flow is supported
 */
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow) {
	apr_array_header_t *flows = oidc_proto_supported_flows(pool);
	int i;
	for (i = 0; i < flows->nelts; i++) {
		if (oidc_util_spaced_string_equals(pool, flow,
				((const char**) flows->elts)[i]))
			return TRUE;
	}
	return FALSE;
}

/*
 * check the required parameters for the various flows after resolving the authorization code
 */
static apr_byte_t oidc_proto_validate_code_response(request_rec *r,
		const char *response_type, char *id_token, char *access_token,
		char *token_type) {

	oidc_debug(r, "enter");

	/*
	 * check id_token parameter
	 */
	if (!oidc_util_spaced_string_contains(r->pool, response_type,
			OIDC_PROTO_RESPONSE_TYPE_IDTOKEN)) {
		if (id_token == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"%s\" parameter found in the code response",
					response_type, OIDC_PROTO_ID_TOKEN);
			return FALSE;
		}
	} else {
		if (id_token != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is an \"%s\" parameter in the code response that will be dropped",
					response_type, OIDC_PROTO_ID_TOKEN);
		}
	}

	/*
	 * check access_token parameter
	 */
	if (!oidc_util_spaced_string_contains(r->pool, response_type,
			OIDC_PROTO_RESPONSE_TYPE_TOKEN)) {
		if (access_token == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"%s\" parameter found in the code response",
					response_type, OIDC_PROTO_ACCESS_TOKEN);
			return FALSE;
		}
		if (token_type == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"%s\" parameter found in the code response",
					response_type, OIDC_PROTO_TOKEN_TYPE);
			return FALSE;
		}
	} else {
		if (access_token != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is an \"%s\" parameter in the code response that will be dropped",
					response_type, OIDC_PROTO_ACCESS_TOKEN);
		}

		if (token_type != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is a \"%s\" parameter in the code response that will be dropped",
					response_type, OIDC_PROTO_TOKEN_TYPE);
		}
	}

	return TRUE;
}

/*
 * validate the response parameters provided by the OP against the requested response type
 */
static apr_byte_t oidc_proto_validate_response_type(request_rec *r,
		const char *requested_response_type, const char *code,
		const char *id_token, const char *access_token) {

	if (oidc_util_spaced_string_contains(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_CODE)) {
		if (code == NULL) {
			oidc_error(r,
					"the requested response type was (%s) but the response does not contain a \"%s\" parameter",
					requested_response_type, OIDC_PROTO_CODE);
			return FALSE;
		}
	} else if (code != NULL) {
		oidc_error(r,
				"the requested response type was (%s) but the response contains a \"%s\" parameter",
				requested_response_type, OIDC_PROTO_CODE);
		return FALSE;
	}

	if (oidc_util_spaced_string_contains(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_IDTOKEN)) {
		if (id_token == NULL) {
			oidc_error(r,
					"the requested response type was (%s) but the response does not contain an \"%s\" parameter",
					requested_response_type, OIDC_PROTO_ID_TOKEN);
			return FALSE;
		}
	} else if (id_token != NULL) {
		oidc_error(r,
				"the requested response type was (%s) but the response contains an \"%s\" parameter",
				requested_response_type, OIDC_PROTO_ID_TOKEN);
		return FALSE;
	}

	if (oidc_util_spaced_string_contains(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_TOKEN)) {
		if (access_token == NULL) {
			oidc_error(r,
					"the requested response type was (%s) but the response does not contain an \"%s\" parameter",
					requested_response_type, OIDC_PROTO_ACCESS_TOKEN);
			return FALSE;
		}
	} else if (access_token != NULL) {
		oidc_error(r,
				"the requested response type was (%s) but the response contains an \"%s\" parameter",
				requested_response_type, OIDC_PROTO_ACCESS_TOKEN);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate the response mode used by the OP against the requested response mode
 */
static apr_byte_t oidc_proto_validate_response_mode(request_rec *r,
		oidc_proto_state_t *proto_state, const char *response_mode,
		const char *default_response_mode) {

	const char *requested_response_mode = oidc_proto_state_get_response_mode(
			proto_state);
	if (requested_response_mode == NULL)
		requested_response_mode = default_response_mode;

	if (apr_strnatcmp(requested_response_mode, response_mode) != 0) {
		oidc_error(r,
				"requested response mode (%s) does not match the response mode used by the OP (%s)",
				requested_response_mode, response_mode);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate the client_id/iss provided by the OP against the client_id/iss registered with the provider that the request was sent to
 */
static apr_byte_t oidc_proto_validate_issuer_client_id(request_rec *r,
		const char *configured_issuer, const char *response_issuer,
		const char *configured_client_id, const char *response_client_id) {

	if (response_issuer != NULL) {
		if (apr_strnatcmp(configured_issuer, response_issuer) != 0) {
			oidc_error(r,
					"configured issuer (%s) does not match the issuer provided in the response by the OP (%s)",
					configured_issuer, response_issuer);
			return FALSE;
		}
	}

	if (response_client_id != NULL) {
		if (apr_strnatcmp(configured_client_id, response_client_id) != 0) {
			oidc_error(r,
					"configured client_id (%s) does not match the client_id provided in the response by the OP (%s)",
					configured_client_id, response_client_id);
			return FALSE;
		}
	}

	oidc_debug(r, "iss and/or client_id matched OK: %s, %s, %s, %s",
			response_issuer, configured_issuer, response_client_id,
			configured_client_id);

	return TRUE;
}

/*
 * helper function to validate both the response type and the response mode in a single function call
 */
static apr_byte_t oidc_proto_validate_response_type_mode_issuer(request_rec *r,
		const char *requested_response_type, apr_table_t *params,
		oidc_proto_state_t *proto_state, const char *response_mode,
		const char *default_response_mode, const char *issuer,
		const char *c_client_id) {

	const char *code = apr_table_get(params, OIDC_PROTO_CODE);
	const char *id_token = apr_table_get(params, OIDC_PROTO_ID_TOKEN);
	const char *access_token = apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN);
	const char *iss = apr_table_get(params, OIDC_PROTO_ISS);
	const char *client_id = apr_table_get(params, OIDC_PROTO_CLIENT_ID);

	if (oidc_proto_validate_issuer_client_id(r, issuer, iss, c_client_id,
			client_id) == FALSE)
		return FALSE;

	if (oidc_proto_validate_response_type(r, requested_response_type, code,
			id_token, access_token) == FALSE)
		return FALSE;

	if (oidc_proto_validate_response_mode(r, proto_state, response_mode,
			default_response_mode) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * parse and id_token and check the c_hash if the code is provided
 */
static apr_byte_t oidc_proto_parse_idtoken_and_validate_code(request_rec *r,
		oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider,
		const char *response_type, apr_table_t *params, oidc_jwt_t **jwt,
		apr_byte_t must_validate_code) {

	const char *code = apr_table_get(params, OIDC_PROTO_CODE);
	const char *id_token = apr_table_get(params, OIDC_PROTO_ID_TOKEN);

	apr_byte_t is_code_flow = (oidc_util_spaced_string_contains(r->pool,
			response_type, OIDC_PROTO_RESPONSE_TYPE_CODE) == TRUE)
					&& (oidc_util_spaced_string_contains(r->pool, response_type,
							OIDC_PROTO_RESPONSE_TYPE_IDTOKEN) == FALSE);

	const char *nonce = oidc_proto_state_get_nonce(proto_state);
	if (oidc_proto_parse_idtoken(r, c, provider, id_token, nonce, jwt,
			is_code_flow) == FALSE)
		return FALSE;

	if ((must_validate_code == TRUE)
			&& (oidc_proto_validate_code(r, provider, *jwt, response_type, code)
					== FALSE))
		return FALSE;

	return TRUE;
}

/*
 * resolve the code against the token endpoint and validate the response that is returned by the OP
 */
static apr_byte_t oidc_proto_resolve_code_and_validate_response(request_rec *r,
		oidc_cfg *c, oidc_provider_t *provider, const char *response_type,
		apr_table_t *params, oidc_proto_state_t *proto_state) {

	char *id_token = NULL;
	char *access_token = NULL;
	char *token_type = NULL;
	int expires_in = -1;
	char *refresh_token = NULL;
	char *code_verifier = NULL;

	if (provider->pkce != NULL)
		provider->pkce->verifier(r,
				oidc_proto_state_get_pkce_state(proto_state), &code_verifier);

	const char *state = oidc_proto_state_get_state(proto_state);

	if (oidc_proto_resolve_code(r, c, provider,
			apr_table_get(params, OIDC_PROTO_CODE), code_verifier, &id_token,
			&access_token, &token_type, &expires_in, &refresh_token,
			state) == FALSE) {
		oidc_error(r, "failed to resolve the code");
		return FALSE;
	}

	if (oidc_proto_validate_code_response(r, response_type, id_token,
			access_token, token_type) == FALSE) {
		oidc_error(r, "code response validation failed");
		return FALSE;
	}

	/* don't override parameters that may already have been (rightfully) set in the authorization response */
	if ((apr_table_get(params, OIDC_PROTO_ID_TOKEN) == NULL)
			&& (id_token != NULL)) {
		apr_table_set(params, OIDC_PROTO_ID_TOKEN, id_token);
	}

	if ((apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN) == NULL)
			&& (access_token != NULL)) {
		apr_table_set(params, OIDC_PROTO_ACCESS_TOKEN, access_token);
		if (token_type != NULL)
			apr_table_set(params, OIDC_PROTO_TOKEN_TYPE, token_type);
		if (expires_in != -1)
			apr_table_setn(params, OIDC_PROTO_EXPIRES_IN,
					apr_psprintf(r->pool, "%d", expires_in));
	}

	/* refresh token should not have been set before */
	if (refresh_token != NULL) {
		apr_table_set(params, OIDC_PROTO_REFRESH_TOKEN, refresh_token);
	}

	return TRUE;
}

/*
 * handle the "code id_token" response type
 */
apr_byte_t oidc_proto_authorization_response_code_idtoken(request_rec *r,
		oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider,
		apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN;

	if (oidc_proto_validate_response_type_mode_issuer(r, response_type, params,
			proto_state, response_mode, OIDC_PROTO_RESPONSE_MODE_FRAGMENT,
			provider->issuer, provider->client_id) == FALSE)
		return FALSE;

	if (oidc_proto_parse_idtoken_and_validate_code(r, c, proto_state, provider,
			response_type, params, jwt, TRUE) == FALSE)
		return FALSE;

	/* clear parameters that should only be set from the token endpoint */
	apr_table_unset(params, OIDC_PROTO_ACCESS_TOKEN);
	apr_table_unset(params, OIDC_PROTO_TOKEN_TYPE);
	apr_table_unset(params, OIDC_PROTO_EXPIRES_IN);
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	if (oidc_proto_resolve_code_and_validate_response(r, c, provider,
			response_type, params, proto_state) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * handle the "code token" response type
 */
apr_byte_t oidc_proto_handle_authorization_response_code_token(request_rec *r,
		oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider,
		apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN;

	if (oidc_proto_validate_response_type_mode_issuer(r, response_type, params,
			proto_state, response_mode, OIDC_PROTO_RESPONSE_MODE_FRAGMENT,
			provider->issuer, provider->client_id) == FALSE)
		return FALSE;

	/* clear parameters that should only be set from the token endpoint */
	apr_table_unset(params, OIDC_PROTO_ID_TOKEN);
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	if (oidc_proto_resolve_code_and_validate_response(r, c, provider,
			response_type, params, proto_state) == FALSE)
		return FALSE;

	if (oidc_proto_parse_idtoken_and_validate_code(r, c, proto_state, provider,
			response_type, params, jwt, FALSE) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * handle the "code" response type
 */
apr_byte_t oidc_proto_handle_authorization_response_code(request_rec *r,
		oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider,
		apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_CODE;

	if (oidc_proto_validate_response_type_mode_issuer(r, response_type, params,
			proto_state, response_mode, OIDC_PROTO_RESPONSE_MODE_QUERY,
			provider->issuer, provider->client_id) == FALSE)
		return FALSE;

	/* clear parameters that should only be set from the token endpoint */
	apr_table_unset(params, OIDC_PROTO_ACCESS_TOKEN);
	apr_table_unset(params, OIDC_PROTO_TOKEN_TYPE);
	apr_table_unset(params, OIDC_PROTO_EXPIRES_IN);
	apr_table_unset(params, OIDC_PROTO_ID_TOKEN);
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	if (oidc_proto_resolve_code_and_validate_response(r, c, provider,
			response_type, params, proto_state) == FALSE)
		return FALSE;

	/*
	 * in this flow it is actually optional to check the code token against the c_hash
	 */
	if (oidc_proto_parse_idtoken_and_validate_code(r, c, proto_state, provider,
			response_type, params, jwt, TRUE) == FALSE)
		return FALSE;

	/*
	 * in this flow it is actually optional to check the access token against the at_hash
	 */
	if ((apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN) != NULL)
			&& (oidc_proto_validate_access_token(r, provider, *jwt,
					response_type,
					apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN)) == FALSE))
		return FALSE;

	return TRUE;
}

/*
 * helper function for implicit flows: shared code for "id_token token" and "id_token"
 */
static apr_byte_t oidc_proto_handle_implicit_flow(request_rec *r, oidc_cfg *c,
		const char *response_type, oidc_proto_state_t *proto_state,
		oidc_provider_t *provider, apr_table_t *params,
		const char *response_mode, oidc_jwt_t **jwt) {

	if (oidc_proto_validate_response_type_mode_issuer(r, response_type, params,
			proto_state, response_mode, OIDC_PROTO_RESPONSE_MODE_FRAGMENT,
			provider->issuer, provider->client_id) == FALSE)
		return FALSE;

	if (oidc_proto_parse_idtoken_and_validate_code(r, c, proto_state, provider,
			response_type, params, jwt, TRUE) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * handle the "code id_token token" response type
 */
apr_byte_t oidc_proto_authorization_response_code_idtoken_token(request_rec *r,
		oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider,
		apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type =
			OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;

	if (oidc_proto_handle_implicit_flow(r, c, response_type, proto_state,
			provider, params, response_mode, jwt) == FALSE)
		return FALSE;

	if (oidc_proto_validate_access_token(r, provider, *jwt, response_type,
			apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN)) == FALSE)
		return FALSE;

	/* clear parameters that should only be set from the token endpoint */
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	if (oidc_proto_resolve_code_and_validate_response(r, c, provider,
			response_type, params, proto_state) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * handle the "id_token token" response type
 */
apr_byte_t oidc_proto_handle_authorization_response_idtoken_token(
		request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state,
		oidc_provider_t *provider, apr_table_t *params,
		const char *response_mode, oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN;

	if (oidc_proto_handle_implicit_flow(r, c, response_type, proto_state,
			provider, params, response_mode, jwt) == FALSE)
		return FALSE;

	if (oidc_proto_validate_access_token(r, provider, *jwt, response_type,
			apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN)) == FALSE)
		return FALSE;

	/* clear parameters that should not be part of this flow */
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	return TRUE;
}

/*
 * handle the "id_token" response type
 */
apr_byte_t oidc_proto_handle_authorization_response_idtoken(request_rec *r,
		oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider,
		apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN;

	if (oidc_proto_handle_implicit_flow(r, c, response_type, proto_state,
			provider, params, response_mode, jwt) == FALSE)
		return FALSE;

	/* clear parameters that should not be part of this flow */
	apr_table_unset(params, OIDC_PROTO_TOKEN_TYPE);
	apr_table_unset(params, OIDC_PROTO_EXPIRES_IN);
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	return TRUE;
}
