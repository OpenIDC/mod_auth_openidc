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

#include "metadata.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

#define OIDC_REQUEST_OBJECT_TTL_DEFAULT 30

/*
 * indicates whether a request parameter from the authorization request needs to be
 * copied and/or deleted to/from the protected request object based on the settings specified
 * in the "copy_from_request"/"copy_and_remove_from_request" JSON array in the request object
 */
static apr_byte_t oidc_proto_request_object_param_needs_action(const oidc_json_t *request_object_config,
							       const char *parameter_name, const char *action) {
	const oidc_json_t *copy_from_request = oidc_json_object_get(request_object_config, action);
	size_t index = 0;
	while (index < oidc_json_array_size(copy_from_request)) {
		const oidc_json_t *value = oidc_json_array_get(copy_from_request, index);
		if ((oidc_json_is_string(value)) &&
		    (_oidc_strcmp(oidc_json_string_value(value), parameter_name) == 0)) {
			return TRUE;
		}
		index++;
	}
	return FALSE;
}

/*
 * indicates whether the named authorization request parameter is defined as a string in the
 * OpenID Connect/OAuth 2.0 specifications and thus must never be subjected to JSON type
 * interpretation
 */
static apr_byte_t oidc_proto_request_object_param_is_spec_string(const char *name) {
	static const char *spec_string_params[] = {OIDC_PROTO_SCOPE,
						   OIDC_PROTO_RESPONSE_TYPE,
						   OIDC_PROTO_CLIENT_ID,
						   OIDC_PROTO_REDIRECT_URI,
						   OIDC_PROTO_STATE,
						   OIDC_PROTO_RESPONSE_MODE,
						   OIDC_PROTO_NONCE,
						   OIDC_PROTO_DISPLAY,
						   OIDC_PROTO_PROMPT,
						   OIDC_PROTO_UI_LOCALES,
						   OIDC_PROTO_ID_TOKEN_HINT,
						   OIDC_PROTO_LOGIN_HINT,
						   OIDC_PROTO_ACR_VALUES,
						   OIDC_PROTO_CLAIMS_LOCALES,
						   OIDC_PROTO_CODE_CHALLENGE,
						   OIDC_PROTO_CODE_CHALLENGE_METHOD,
						   OIDC_PROTO_REQUEST_URI,
						   OIDC_PROTO_REQUEST_OBJECT,
						   NULL};
	int i = 0;
	while (spec_string_params[i] != NULL) {
		if (_oidc_strcmp(name, spec_string_params[i]) == 0)
			return TRUE;
		i++;
	}
	return FALSE;
}

/* context structure for copying request parameters */
typedef struct oidc_proto_request_object_copy_req_ctx_t {
	request_rec *r;
	oidc_json_t *request_object_config;
	oidc_jwt_t *request_object;
	apr_table_t *params2;
} oidc_proto_request_object_copy_req_ctx_t;

/*
 * copy a parameter key/value from the authorizion request to the
 * request object if the configuration setting says to include it
 */
static int oidc_proto_request_object_copy_from_request(void *rec, const char *name, const char *value) {
	oidc_proto_request_object_copy_req_ctx_t *ctx = (oidc_proto_request_object_copy_req_ctx_t *)rec;

	oidc_debug(ctx->r, "processing name: %s, value: %s", name, value);

	if (oidc_proto_request_object_param_needs_action(ctx->request_object_config, name,
							 OIDC_REQUEST_OBJECT_COPY_FROM_REQUEST) ||
	    oidc_proto_request_object_param_needs_action(ctx->request_object_config, name,
							 OIDC_REQUEST_OBJECT_COPY_AND_REMOVE_FROM_REQUEST)) {
		oidc_json_t *result = NULL;
		/* parameters that the specifications define as strings must not be subject to JSON
		 * type interpretation (e.g. a numeric "state" value becoming a json_int) */
		if (oidc_proto_request_object_param_is_spec_string(name) == FALSE)
			oidc_json_parse(ctx->r->pool, value, OIDC_JSON_DECODE_ANY, &result, NULL);
		if (result == NULL)
			/* assume string */
			result = oidc_json_string(value);
		if (result)
			oidc_json_object_set_new(ctx->request_object->payload.value.json, name, result);
		else
			oidc_warn(ctx->r, "oidc_json_string failed for name: %s, value: %s", name, value);

		if (oidc_proto_request_object_param_needs_action(ctx->request_object_config, name,
								 OIDC_REQUEST_OBJECT_COPY_AND_REMOVE_FROM_REQUEST)) {
			apr_table_set(ctx->params2, name, name);
		}
	}

	return 1;
}

/*
 * delete a parameter key/value from the authorizion request if the configuration setting says to remove it
 */
static int oidc_proto_request_object_delete_from_request(void *rec, const char *name, const char *value) {
	oidc_proto_request_object_copy_req_ctx_t *ctx = (oidc_proto_request_object_copy_req_ctx_t *)rec;

	oidc_debug(ctx->r, "deleting from query parameters: name: %s, value: %s", name, value);

	if (oidc_proto_request_object_param_needs_action(ctx->request_object_config, name,
							 OIDC_REQUEST_OBJECT_COPY_AND_REMOVE_FROM_REQUEST)) {
		apr_table_unset(ctx->params2, name);
	}

	return 1;
}

/*
 * obtain the public key for a provider to encrypt the request object with
 */
static apr_byte_t oidc_proto_request_object_encryption_jwk_by_type(request_rec *r, oidc_cfg_t *cfg,
								   const struct oidc_provider_t *provider, int key_type,
								   oidc_jwk_t **jwk) {

	oidc_jose_error_t err;
	oidc_json_t *j_jwks = NULL;
	apr_byte_t force_refresh = TRUE;
	oidc_jwk_t *key = NULL;
	char *jwk_json = NULL;

	/* NB: force a fresh JWKS fetch here rather than relying on the cache */
	oidc_metadata_jwks_get(r, cfg, oidc_cfg_provider_jwks_uri_get(provider),
			       oidc_cfg_provider_ssl_validate_server_get(provider), &j_jwks, &force_refresh);

	if (j_jwks == NULL) {
		oidc_error(r, "could not retrieve JSON Web Keys");
		return FALSE;
	}

	const oidc_json_t *keys = oidc_json_object_get(j_jwks, OIDC_JOSE_JWKS_KEYS_STR);
	if ((keys == NULL) || !(oidc_json_is_array(keys))) {
		oidc_error(r, "\"%s\" array element is not a JSON array", OIDC_JOSE_JWKS_KEYS_STR);
		return FALSE;
	}

	/* walk the set of published keys to find the first that has a matching type */
	for (int i = 0; i < oidc_json_array_size(keys); i++) {

		const oidc_json_t *elem = oidc_json_array_get(keys, i);

		const char *use = oidc_json_string_value(oidc_json_object_get(elem, OIDC_JOSE_JWK_USE_STR));
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

	/* no need anymore for the parsed oidc_json_t contents, release the it */
	oidc_json_decref(j_jwks);

	return (*jwk != NULL);
}

/*
 * populate iss/aud/iat/nbf/exp on the request object and merge "static" config values into it
 */
static void oidc_proto_request_object_claims_set(request_rec *r, const struct oidc_provider_t *provider,
						 const oidc_json_t *request_object_config, oidc_jwt_t *request_object,
						 int ttl) {
	oidc_json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_ISS,
				 oidc_json_string(oidc_cfg_provider_client_id_get(provider)));
	oidc_json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_AUD,
				 oidc_json_string(oidc_cfg_provider_issuer_get(provider)));
	oidc_json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_IAT,
				 oidc_json_integer(apr_time_sec(apr_time_now())));
	oidc_json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_NBF,
				 oidc_json_integer(apr_time_sec(apr_time_now())));
	oidc_json_object_set_new(request_object->payload.value.json, OIDC_CLAIM_EXP,
				 oidc_json_integer(apr_time_sec(apr_time_now()) + ttl));

	/* may override iss/aud */
	oidc_json_merge(r, oidc_json_object_get(request_object_config, OIDC_REQUEST_OBJECT_STATIC),
			request_object->payload.value.json);
}

/*
 * copy parameters from the authorization request to the request object and remove the marked ones from the query
 */
static void oidc_proto_request_object_params_copy(request_rec *r, oidc_json_t *request_object_config,
						  oidc_jwt_t *request_object, apr_table_t *params) {
	apr_table_t *delete_from_query_params = apr_table_make(r->pool, 0);
	oidc_proto_request_object_copy_req_ctx_t data = {r, request_object_config, request_object,
							 delete_from_query_params};
	apr_table_do(oidc_proto_request_object_copy_from_request, &data, params, NULL);

	data.params2 = params;
	apr_table_do(oidc_proto_request_object_delete_from_request, &data, delete_from_query_params, NULL);
}

/*
 * resolve the JWK to sign the request object with, based on the configured signing algorithm
 */
static oidc_jwk_t *oidc_proto_request_object_signing_jwk_get(request_rec *r, const oidc_cfg_t *cfg,
							     const struct oidc_provider_t *provider,
							     oidc_jwt_t *request_object, int *jwk_needs_destroy) {
	oidc_jwk_t *sjwk = NULL;
	int kty = oidc_jwt_alg2kty(request_object);

	*jwk_needs_destroy = 0;

	switch (kty) {
	case OIDC_JOSE_JWK_KTY_RSA:
	case OIDC_JOSE_JWK_KTY_EC:
		if ((oidc_cfg_provider_client_keys_get(provider) == NULL) && (oidc_cfg_private_keys_get(cfg) == NULL)) {
			oidc_error(r, "no global or per-provider private keys have been configured to use for "
				      "request object signing");
			return NULL;
		}
		sjwk = oidc_cfg_provider_client_keys_get(provider)
			   ? oidc_util_key_list_first(oidc_cfg_provider_client_keys_get(provider), kty,
						      OIDC_JOSE_JWK_SIG_STR)
			   : oidc_util_key_list_first(oidc_cfg_private_keys_get(cfg), kty, OIDC_JOSE_JWK_SIG_STR);
		if (sjwk && sjwk->kid)
			request_object->header.kid = apr_pstrdup(r->pool, sjwk->kid);
		else
			oidc_error(r, "could not find a usable signing key");
		return sjwk;
	case OIDC_JOSE_JWK_KTY_OCT:
		oidc_util_key_symmetric_create(r, oidc_cfg_provider_client_secret_get(provider), 0, NULL, FALSE, &sjwk);
		*jwk_needs_destroy = 1;
		return sjwk;
	default:
		oidc_error(r, "unsupported signing algorithm, no key type for algorithm: %s",
			   request_object->header.alg);
		return NULL;
	}
}

/*
 * sign the request object in place
 */
static apr_byte_t oidc_proto_request_object_sign(request_rec *r, const oidc_cfg_t *cfg,
						 const struct oidc_provider_t *provider, oidc_jwt_t *request_object) {
	oidc_jose_error_t err;
	int jwk_needs_destroy = 0;

	oidc_jwk_t *sjwk =
	    oidc_proto_request_object_signing_jwk_get(r, cfg, provider, request_object, &jwk_needs_destroy);
	if (sjwk == NULL)
		return FALSE;

	apr_byte_t rv = oidc_jwt_sign(r->pool, request_object, sjwk, FALSE, &err);
	if (rv == FALSE)
		oidc_error(r, "signing Request Object failed: %s", oidc_jose_e2s(r->pool, err));

	if (jwk_needs_destroy)
		oidc_jwk_destroy(sjwk);

	return rv;
}

/*
 * resolve the JWK to encrypt the request object with, based on the configured encryption algorithm
 *
 * NB: signing_alg is only used to preserve the original (technically incorrect, but stable) error message that
 * references the signing algorithm rather than the encryption algorithm
 */
static oidc_jwk_t *oidc_proto_request_object_encryption_jwk_get(request_rec *r, oidc_cfg_t *cfg,
								const struct oidc_provider_t *provider,
								const oidc_jwt_t *jwe, const char *signing_alg) {
	oidc_jwk_t *ejwk = NULL;

	switch (oidc_jwt_alg2kty(jwe)) {
	case OIDC_JOSE_JWK_KTY_RSA:
	case OIDC_JOSE_JWK_KTY_EC:
		oidc_proto_request_object_encryption_jwk_by_type(r, cfg, provider, oidc_jwt_alg2kty(jwe), &ejwk);
		break;
	case OIDC_JOSE_JWK_KTY_OCT:
		oidc_util_key_symmetric_create(r, oidc_cfg_provider_client_secret_get(provider),
					       oidc_alg2keysize(jwe->header.alg), OIDC_JOSE_ALG_SHA256, FALSE, &ejwk);
		break;
	default:
		oidc_error(r, "unsupported encryption algorithm, no key type for algorithm: %s", signing_alg);
		break;
	}

	return ejwk;
}

/*
 * encrypt the (already serialized) signed request object into a JWE and return the compact serialization
 */
static char *oidc_proto_request_object_encrypt(request_rec *r, oidc_cfg_t *cfg, const struct oidc_provider_t *provider,
					       oidc_jwt_t *jwe, const char *cser, const char *signing_alg) {
	oidc_jose_error_t err;
	char *serialized = NULL;

	oidc_jwk_t *ejwk = oidc_proto_request_object_encryption_jwk_get(r, cfg, provider, jwe, signing_alg);
	if (ejwk == NULL)
		return NULL;

	if (jwe->header.enc == NULL)
		jwe->header.enc = apr_pstrdup(r->pool, OIDC_JOSE_HDR_ENC_A128CBC_HS256);

	if (ejwk->kid != NULL)
		jwe->header.kid = ejwk->kid;

	/* NB: encrypt exactly the serialized bytes, without the trailing NUL: a JWE
	 * plaintext that is a Nested JWT must be the bare compact JWS, or the OP's
	 * base64url decode of the inner signature segment trips over the stray byte */
	if (oidc_jwt_encrypt(r->pool, jwe, ejwk, cser, (int)_oidc_strlen(cser), &serialized, &err) == FALSE) {
		oidc_error(r, "encrypting JWT failed: %s", oidc_jose_e2s(r->pool, err));
		serialized = NULL;
	}

	oidc_jwk_destroy(ejwk);

	return serialized;
}

/*
 * generate a request object
 */
static char *oidc_proto_request_object_create(request_rec *r, const struct oidc_provider_t *provider,
					      oidc_json_t *request_object_config, apr_table_t *params, int ttl) {

	oidc_jose_error_t err;
	char *serialized_request_object = NULL;
	oidc_jwt_t *jwe = NULL;

	oidc_debug(r, "enter");

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	/* create the request object value */
	oidc_jwt_t *request_object = oidc_jwt_new(r->pool, TRUE, TRUE);

	/* set basic values: iss, aud, iat, nbf, exp and merge static config */
	oidc_proto_request_object_claims_set(r, provider, request_object_config, request_object, ttl);

	/* copy/delete parameters from the authorization request as configured in the .conf file */
	oidc_proto_request_object_params_copy(r, request_object_config, request_object, params);

	/* debug logging */
	oidc_debug(r, "request object: %s",
		   oidc_json_encode(r->pool, request_object->payload.value.json,
				    OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT));

	/* get the crypto settings from the configuration */
	const oidc_json_t *crypto = oidc_json_object_get(request_object_config, OIDC_REQUEST_OBJECT_CRYPTO);
	oidc_json_object_get_string(r->pool, crypto, OIDC_REQUEST_OBJECT_CRYPTO_SIGN_ALG, &request_object->header.alg,
				    "none");

	/* see if we need to sign the request object */
	if ((_oidc_strcmp(request_object->header.alg, "none") != 0) &&
	    (oidc_proto_request_object_sign(r, cfg, provider, request_object) == FALSE))
		goto out;

	jwe = oidc_jwt_new(r->pool, TRUE, FALSE);
	if (jwe == NULL) {
		oidc_error(r, "creating JWE failed");
		goto out;
	}

	oidc_json_object_get_string(r->pool, crypto, OIDC_REQUEST_OBJECT_CRYPTO_CRYPT_ALG, &jwe->header.alg, NULL);
	oidc_json_object_get_string(r->pool, crypto, OIDC_REQUEST_OBJECT_CRYPTO_CRYPT_ENC, &jwe->header.enc, NULL);

	char *cser = oidc_jose_jwt_serialize(r->pool, request_object, &err);

	/* see if we need to encrypt the request object */
	if (jwe->header.alg != NULL) {
		/* the encrypted payload is itself a JWT (the signed - or "none" - request
		 * object), so mark the JWE as a Nested JWT per RFC 7519 section 5.2:
		 * "cty":"JWT" tells the OP to re-parse the decrypted plaintext as a JWS
		 * rather than as a bare JSON claims set (e.g. Keycloak otherwise rejects
		 * it with "Failed to deserialize JWT") */
		jwe->header.cty = apr_pstrdup(r->pool, "JWT");
		serialized_request_object =
		    oidc_proto_request_object_encrypt(r, cfg, provider, jwe, cser, request_object->header.alg);
	} else
		/* should be sign only or "none" */
		serialized_request_object = cser;

out:

	oidc_jwt_destroy(request_object);
	oidc_jwt_destroy(jwe);

	if (serialized_request_object != NULL) {
		oidc_debug(r, "serialized request object JWT header = \"%s\"",
			   oidc_proto_jwt_header_peek(r, serialized_request_object, NULL, NULL, NULL));
		oidc_debug(r, "serialized request object = \"%s\"", serialized_request_object);
	}

	return serialized_request_object;
}

#define OIDC_PROTO_REQUEST_URI_REF_LEN 16

/*
 * generate a request object and pass it by reference in the authorization request
 */
static char *oidc_proto_request_uri_create(request_rec *r, const struct oidc_provider_t *provider,
					   oidc_json_t *request_object_config, const char *redirect_uri,
					   apr_table_t *params, int ttl) {

	oidc_debug(r, "enter");

	/* see if we need to override the resolver URL, mostly for test purposes */
	char *resolver_url = NULL;
	if (oidc_json_object_get(request_object_config, OIDC_REQUEST_OBJECT_URL) != NULL)
		resolver_url = apr_pstrdup(r->pool, oidc_json_string_value(oidc_json_object_get(
							request_object_config, OIDC_REQUEST_OBJECT_URL)));
	else
		resolver_url = apr_pstrdup(r->pool, redirect_uri);

	const char *serialized_request_object =
	    oidc_proto_request_object_create(r, provider, request_object_config, params, ttl);

	/* generate a temporary reference, store the request object in the cache and generate a Request URI that
	 * references it */
	char *request_uri = NULL;
	if (serialized_request_object != NULL) {
		char *request_ref = NULL;
		if (oidc_util_rand_str(r, &request_ref, OIDC_PROTO_REQUEST_URI_REF_LEN) == TRUE) {
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
void oidc_proto_request_object_param_add(request_rec *r, const struct oidc_provider_t *provider,
					 const char *redirect_uri, apr_table_t *params) {

	/* parse the request object configuration from a string in to a JSON structure */
	oidc_json_t *request_object_config = NULL;
	if (oidc_json_decode_object(r, oidc_cfg_provider_request_object_get(provider), &request_object_config) == FALSE)
		return;

	/* request_uri is used as default parameter for sending Request Object */
	const char *parameter = OIDC_PROTO_REQUEST_URI;
	const char *value = NULL;

	/* get request_object_type parameter from config */
	const oidc_json_t *request_object_type = oidc_json_object_get(request_object_config, OIDC_REQUEST_OBJECT_TYPE);
	if (request_object_type != NULL) {
		const char *request_object_type_str = oidc_json_string_value(request_object_type);
		if (request_object_type_str == NULL) {
			oidc_error(r, "Value of request_object_type in request_object config is not a string");
			goto end;
		}

		/* ensure parameter variable to have a valid value */
		if (_oidc_strcmp(request_object_type_str, OIDC_PROTO_REQUEST_OBJECT) == 0) {
			parameter = OIDC_PROTO_REQUEST_OBJECT;
		} else if (_oidc_strcmp(request_object_type_str, OIDC_PROTO_REQUEST_URI) != 0) {
			oidc_error(r, "Bad request_object_type in config: %s", request_object_type_str);
			goto end;
		}
	}

	/* create request value */
	int ttl = OIDC_REQUEST_OBJECT_TTL_DEFAULT;
	oidc_json_object_get_int(request_object_config, OIDC_REQUEST_OBJECT_TTL, &ttl, OIDC_REQUEST_OBJECT_TTL_DEFAULT);
	if (_oidc_strcmp(parameter, OIDC_PROTO_REQUEST_URI) == 0) {
		/* parameter is "request_uri" */
		value = oidc_proto_request_uri_create(r, provider, request_object_config, redirect_uri, params, ttl);
	} else {
		/* parameter is "request" */
		value = oidc_proto_request_object_create(r, provider, request_object_config, params, ttl);
	}

	/* don't add an empty parameter when creating the request object failed */
	if (value != NULL)
		apr_table_set(params, parameter, value);
	else
		oidc_warn(r, "creating the \"%s\" parameter value failed; the authorization request is sent without it",
			  parameter);

end:

	/* the configuration object is owned here: none of the helpers above keeps a reference */
	oidc_json_decref(request_object_config);
}
