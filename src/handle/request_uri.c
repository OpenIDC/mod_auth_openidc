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

#include "handle/handle.h"

#define OIDC_REQUEST_OJBECT_COPY_FROM_REQUEST "copy_from_request"
#define OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST "copy_and_remove_from_request"
#define OIDC_REQUEST_OJBECT_TTL "ttl"
#define OIDC_REQUEST_OBJECT_TTL_DEFAULT 30

/*
 * indicates whether a request parameter from the authorization request needs to be
 * copied and/or deleted to/from the protected request object based on the settings specified
 * in the "copy_from_request"/"copy_and_remove_from_request" JSON array in the request object
 */
static apr_byte_t oidc_request_uri_param_needs_action(json_t *request_object_config, const char *parameter_name,
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

	if (oidc_request_uri_param_needs_action(ctx->request_object_config, name,
						OIDC_REQUEST_OJBECT_COPY_FROM_REQUEST) ||
	    oidc_request_uri_param_needs_action(ctx->request_object_config, name,
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

		if (oidc_request_uri_param_needs_action(ctx->request_object_config, name,
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

	if (oidc_request_uri_param_needs_action(ctx->request_object_config, name,
						OIDC_REQUEST_OJBECT_COPY_AND_REMOVE_FROM_REQUEST)) {
		apr_table_unset(ctx->params2, name);
	}

	return 1;
}

/*
 * obtain the public key for a provider to encrypt the request object with
 */
static apr_byte_t oidc_request_uri_encryption_jwk_by_type(request_rec *r, oidc_cfg *cfg,
							  struct oidc_provider_t *provider, int key_type,
							  oidc_jwk_t **jwk) {

	oidc_jose_error_t err;
	json_t *j_jwks = NULL;
	apr_byte_t force_refresh = TRUE;
	oidc_jwk_t *key = NULL;
	char *jwk_json = NULL;
	int i = 0;

	/* TODO: forcefully refresh now; we may want to relax that */
	oidc_metadata_jwks_get(r, cfg, &provider->jwks_uri, provider->ssl_validate_server, &j_jwks, &force_refresh);

	if (j_jwks == NULL) {
		oidc_error(r, "could not retrieve JSON Web Keys");
		return FALSE;
	}

	json_t *keys = json_object_get(j_jwks, OIDC_JWK_KEYS);
	if ((keys == NULL) || !(json_is_array(keys))) {
		oidc_error(r, "\"%s\" array element is not a JSON array", OIDC_JWK_KEYS);
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

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	/* create the request object value */
	oidc_jwt_t *request_object = oidc_jwt_new(r->pool, TRUE, TRUE);

	/* set basic values: iss, aud, iat and exp */
	json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_ISS, json_string(provider->client_id));
	json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_AUD, json_string(provider->issuer));
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
	oidc_json_object_get_string(r->pool, crypto, "sign_alg", &request_object->header.alg, "none");

	/* see if we need to sign the request object */
	if (_oidc_strcmp(request_object->header.alg, "none") != 0) {

		sjwk = NULL;
		jwk_needs_destroy = 0;
		kty = oidc_jwt_alg2kty(request_object);
		switch (kty) {
		case CJOSE_JWK_KTY_RSA:
		case CJOSE_JWK_KTY_EC:
			if ((provider->client_keys != NULL) || (cfg->private_keys != NULL)) {
				sjwk = provider->client_keys
					   ? oidc_util_key_list_first(provider->client_keys, kty, OIDC_JOSE_JWK_SIG_STR)
					   : oidc_util_key_list_first(cfg->private_keys, kty, OIDC_JOSE_JWK_SIG_STR);
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
			oidc_util_create_symmetric_key(r, provider->client_secret, 0, NULL, FALSE, &sjwk);
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

	oidc_json_object_get_string(r->pool, crypto, "crypt_alg", &jwe->header.alg, NULL);
	oidc_json_object_get_string(r->pool, crypto, "crypt_enc", &jwe->header.enc, NULL);

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
			oidc_util_create_symmetric_key(r, provider->client_secret, oidc_alg2keysize(jwe->header.alg),
						       OIDC_JOSE_ALG_SHA256, FALSE, &ejwk);
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
static char *oidc_request_uri_create(request_rec *r, struct oidc_provider_t *provider, json_t *request_object_config,
				     const char *redirect_uri, apr_table_t *params, int ttl) {

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
		if (oidc_proto_generate_random_string(r, &request_ref, 16) == TRUE) {
			oidc_cache_set_request_uri(r, request_ref, serialized_request_object,
						   apr_time_now() + apr_time_from_sec(ttl));
			request_uri = apr_psprintf(r->pool, "%s?%s=%s", resolver_url, OIDC_PROTO_REQUEST_URI,
						   oidc_http_escape_string(r, request_ref));
		}
	}

	return request_uri;
}

/*
 * Generic function to generate request/request_object parameter with value
 */
void oidc_request_uri_add_request_param(request_rec *r, struct oidc_provider_t *provider, const char *redirect_uri,
					apr_table_t *params) {

	/* parse the request object configuration from a string in to a JSON structure */
	json_t *request_object_config = NULL;
	if (oidc_util_decode_json_object(r, provider->request_object, &request_object_config) == FALSE)
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
	oidc_json_object_get_int(request_object_config, "ttl", &ttl, OIDC_REQUEST_OBJECT_TTL_DEFAULT);
	if (_oidc_strcmp(parameter, OIDC_PROTO_REQUEST_URI) == 0) {
		/* parameter is "request_uri" */
		value = oidc_request_uri_create(r, provider, request_object_config, redirect_uri, params, ttl);
		apr_table_set(params, OIDC_PROTO_REQUEST_URI, value);
	} else {
		/* parameter is "request" */
		value = oidc_request_uri_request_object(r, provider, request_object_config, params, ttl);
		apr_table_set(params, OIDC_PROTO_REQUEST_OBJECT, value);
	}
}

/*
 * handle request object by reference request
 */
int oidc_request_uri(request_rec *r, oidc_cfg *c) {

	char *request_ref = NULL;
	oidc_http_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_REQUEST_URI, &request_ref);
	if (request_ref == NULL) {
		oidc_error(r, "no \"%s\" parameter found", OIDC_REDIRECT_URI_REQUEST_REQUEST_URI);
		return HTTP_BAD_REQUEST;
	}

	char *jwt = NULL;
	oidc_cache_get_request_uri(r, request_ref, &jwt);
	if (jwt == NULL) {
		oidc_error(r, "no cached JWT found for %s reference: %s", OIDC_REDIRECT_URI_REQUEST_REQUEST_URI,
			   request_ref);
		return HTTP_NOT_FOUND;
	}

	oidc_cache_set_request_uri(r, request_ref, NULL, 0);

	return oidc_http_send(r, jwt, _oidc_strlen(jwt), OIDC_HTTP_CONTENT_TYPE_JWT, OK);
}
