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

#include "metrics.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"

/*
 * parse a JWT response from the userinfo endpoint: at this point the response is not a JSON object
 * if the response is an encrypted and/or signed JWT, decrypt/verify it before validating it
 */
static apr_byte_t oidc_proto_userinfo_response_jwt_parse(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
							 char **response, json_t **claims, char **userinfo_jwt) {
	apr_byte_t rv = FALSE;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	oidc_jwt_t *jwt = NULL;
	char *alg = NULL;
	char *payload = NULL;
	char *s_jwt_hdr = oidc_proto_jwt_header_peek(r, *response, &alg, NULL, NULL);

	if (s_jwt_hdr == NULL) {
		oidc_error(r, "no JSON/JWT could be parsed from the userinfo endpoint response");
		goto end;
	}

	oidc_debug(r,
		   "enter: JWT header=%s, userinfo_signed_response_alg=%s, userinfo_encrypted_response_alg=%s, "
		   "userinfo_encrypted_response_enc=%s",
		   s_jwt_hdr, oidc_cfg_provider_userinfo_signed_response_alg_get(provider),
		   oidc_cfg_provider_userinfo_encrypted_response_alg_get(provider),
		   oidc_cfg_provider_userinfo_encrypted_response_enc_get(provider));

	if (oidc_util_create_symmetric_key(r, oidc_cfg_provider_client_secret_get(provider), oidc_alg2keysize(alg),
					   OIDC_JOSE_ALG_SHA256, TRUE, &jwk) == FALSE)
		goto end;

	if (oidc_cfg_provider_userinfo_encrypted_response_alg_get(provider) != NULL) {
		if (oidc_jwe_decrypt(r->pool, *response,
				     oidc_util_merge_symmetric_key(r->pool, oidc_cfg_private_keys_get(cfg), jwk),
				     &payload, NULL, &err, TRUE) == FALSE) {
			oidc_error(r, "oidc_jwe_decrypt failed: %s", oidc_jose_e2s(r->pool, err));
			goto end;
		}
		oidc_debug(r, "successfully decrypted JWE returned from userinfo endpoint: %s", payload);
		*response = payload;
	}

	if (oidc_cfg_provider_userinfo_signed_response_alg_get(provider) == NULL) {
		oidc_error(r, "no signed userinfo response algorithm configured to verify the JWT returned from the "
			      "userinfo endpoint");
		goto end;
	}

	if (oidc_jwt_parse(r->pool, *response, &jwt,
			   oidc_util_merge_symmetric_key(r->pool, oidc_cfg_private_keys_get(cfg), jwk), FALSE,
			   &err) == FALSE) {
		oidc_error(r, "oidc_jwt_parse failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}
	oidc_debug(r, "successfully parsed JWT with header=%s, and payload=%s", jwt->header.value.str,
		   jwt->payload.value.str);

	// discard the encryption key and load the signing key
	oidc_jwk_destroy(jwk);
	jwk = NULL;

	if (oidc_util_create_symmetric_key(r, oidc_cfg_provider_client_secret_get(provider), 0, NULL, TRUE, &jwk) ==
	    FALSE)
		goto end;

	if (oidc_proto_jwt_verify(r, cfg, jwt, oidc_cfg_provider_jwks_uri_get(provider),
				  oidc_cfg_provider_ssl_validate_server_get(provider),
				  oidc_util_merge_symmetric_key(r->pool, NULL, jwk),
				  oidc_cfg_provider_userinfo_signed_response_alg_get(provider)) == FALSE) {

		oidc_error(r, "JWT signature could not be validated, aborting");
		goto end;
	}
	oidc_debug(r, "successfully verified signed JWT returned from userinfo endpoint: %s", jwt->payload.value.str);

	*userinfo_jwt = apr_pstrdup(r->pool, *response);
	*claims = json_deep_copy(jwt->payload.value.json);
	*response = apr_pstrdup(r->pool, jwt->payload.value.str);

	rv = TRUE;

end:

	if (jwt)
		oidc_jwt_destroy(jwt);
	if (jwk)
		oidc_jwk_destroy(jwk);

	return rv;
}

#define OIDC_COMPOSITE_CLAIM_NAMES "_claim_names"
#define OIDC_COMPOSITE_CLAIM_SOURCES "_claim_sources"
#define OIDC_COMPOSITE_CLAIM_JWT "JWT"
#define OIDC_COMPOSITE_CLAIM_ACCESS_TOKEN OIDC_PROTO_ACCESS_TOKEN
#define OIDC_COMPOSITE_CLAIM_ENDPOINT "endpoint"

/*
 * if the userinfo response contains composite claims then resolve those
 */
static apr_byte_t oidc_proto_userinfo_request_composite_claims(request_rec *r, oidc_cfg_t *cfg, json_t *claims) {
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
		oidc_debug(r, "%s found, but no %s found", OIDC_COMPOSITE_CLAIM_NAMES, OIDC_COMPOSITE_CLAIM_SOURCES);
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
				const char *access_token =
				    json_string_value(json_object_get(value, OIDC_COMPOSITE_CLAIM_ACCESS_TOKEN));
				const char *endpoint =
				    json_string_value(json_object_get(value, OIDC_COMPOSITE_CLAIM_ENDPOINT));
				if ((access_token != NULL) && (endpoint != NULL)) {
					oidc_http_get(
					    r, endpoint, NULL, NULL, access_token, NULL,
					    oidc_cfg_provider_ssl_validate_server_get(oidc_cfg_provider_get(cfg)),
					    &s_json, NULL, NULL, oidc_cfg_http_timeout_long_get(cfg),
					    oidc_cfg_outgoing_proxy_get(cfg), oidc_cfg_dir_pass_cookies_get(r), NULL,
					    NULL, NULL);
				}
			}
			if ((s_json != NULL) && (_oidc_strcmp(s_json, "") != 0)) {
				oidc_jwt_t *jwt = NULL;
				if (oidc_jwt_parse(
					r->pool, s_json, &jwt,
					oidc_util_merge_symmetric_key(r->pool, oidc_cfg_private_keys_get(cfg), jwk),
					FALSE, &err) == FALSE) {
					oidc_error(r, "could not parse JWT from aggregated claim \"%s\": %s", key,
						   oidc_jose_e2s(r->pool, err));
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
 * send the request to the userinfo endpoint
 */
static apr_byte_t oidc_proto_userinfo_endpoint_call(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
						    const char *access_token, const char *dpop, char **response,
						    long *response_code, apr_hash_t *response_hdrs) {

	OIDC_METRICS_TIMING_START(r, cfg);

	/* get the JSON response */
	if (oidc_cfg_provider_userinfo_token_method_get(provider) == OIDC_USER_INFO_TOKEN_METHOD_HEADER) {
		if (oidc_http_get(r, oidc_cfg_provider_userinfo_endpoint_url_get(provider), NULL, NULL, access_token,
				  dpop, oidc_cfg_provider_ssl_validate_server_get(provider), response, response_code,
				  response_hdrs, oidc_cfg_http_timeout_long_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
				  oidc_cfg_dir_pass_cookies_get(r), NULL, NULL, NULL) == FALSE) {
			OIDC_METRICS_COUNTER_INC(r, cfg, OM_PROVIDER_USERINFO_ERROR);
			return FALSE;
		}
	} else if (oidc_cfg_provider_userinfo_token_method_get(provider) == OIDC_USER_INFO_TOKEN_METHOD_POST) {
		apr_table_t *params = apr_table_make(r->pool, 4);
		apr_table_setn(params, OIDC_PROTO_ACCESS_TOKEN, access_token);
		if (oidc_http_post_form(r, oidc_cfg_provider_userinfo_endpoint_url_get(provider), params, NULL, NULL,
					dpop, oidc_cfg_provider_ssl_validate_server_get(provider), response,
					response_code, response_hdrs, oidc_cfg_http_timeout_long_get(cfg),
					oidc_cfg_outgoing_proxy_get(cfg), oidc_cfg_dir_pass_cookies_get(r), NULL, NULL,
					NULL) == FALSE) {
			OIDC_METRICS_COUNTER_INC(r, cfg, OM_PROVIDER_USERINFO_ERROR);
			return FALSE;
		}
	} else {
		oidc_error(r, "unsupported userinfo token presentation method: %d",
			   oidc_cfg_provider_userinfo_token_method_get(provider));
		return FALSE;
	}

	OIDC_METRICS_TIMING_ADD(r, cfg, OM_PROVIDER_USERINFO);

	return TRUE;
}

/*
 * get claims from the OP UserInfo endpoint using the provided access_token
 */
apr_byte_t oidc_proto_userinfo_request(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
				       const char *id_token_sub, const char *access_token,
				       const char *access_token_type, char **response, char **userinfo_jwt,
				       long *response_code) {
	apr_byte_t rv = FALSE;
	char *dpop = NULL;
	apr_hash_t *response_hdrs = NULL;
	json_t *j_result = NULL;
	const char *method =
	    oidc_cfg_provider_userinfo_token_method_get(provider) == OIDC_USER_INFO_TOKEN_METHOD_POST ? "POST" : "GET";

	oidc_debug(r, "enter, endpoint=%s, access_token=%s, token_type=%s",
		   oidc_cfg_provider_userinfo_endpoint_url_get(provider), access_token, access_token_type);

	if (_oidc_strnatcasecmp(access_token_type, OIDC_PROTO_DPOP) == 0) {
		response_hdrs = apr_hash_make(r->pool);
		apr_hash_set(response_hdrs, OIDC_HTTP_HDR_AUTHORIZATION, APR_HASH_KEY_STRING, "");
		apr_hash_set(response_hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING, "");
		apr_hash_set(response_hdrs, OIDC_HTTP_HDR_CONTENT_TYPE, APR_HASH_KEY_STRING, "");
		if (oidc_proto_dpop_create(r, cfg, oidc_cfg_provider_userinfo_endpoint_url_get(provider), method,
					   access_token, NULL, &dpop) == FALSE)
			goto end;
	}

	if (oidc_proto_userinfo_endpoint_call(r, cfg, provider, access_token, dpop, response, response_code,
					      response_hdrs) == FALSE)
		goto end;

	if (oidc_util_decode_json_object_err(r, *response, &j_result, FALSE) == FALSE) {

		// must be a JWT
		if (oidc_proto_userinfo_response_jwt_parse(r, cfg, provider, response, &j_result, userinfo_jwt) ==
		    FALSE)
			goto end;

	} else if (oidc_util_check_json_error(r, j_result) == TRUE) {

		if (oidc_proto_dpop_use_nonce(r, cfg, j_result, response_hdrs,
					      oidc_cfg_provider_userinfo_endpoint_url_get(provider), method,
					      access_token, &dpop) == FALSE)
			// a regular error response
			goto end;

		if (oidc_proto_userinfo_endpoint_call(r, cfg, provider, access_token, dpop, response, response_code,
						      response_hdrs) == FALSE)
			goto end;

		json_decref(j_result);

		if (oidc_util_decode_json_object_err(r, *response, &j_result, FALSE) == FALSE) {

			// must be a JWT
			if (oidc_proto_userinfo_response_jwt_parse(r, cfg, provider, response, &j_result,
								   userinfo_jwt) == FALSE)
				goto end;
		}

		if (oidc_util_check_json_error(r, j_result) == TRUE)
			goto end;
	}

	if (oidc_proto_userinfo_request_composite_claims(r, cfg, j_result) == TRUE)
		*response = oidc_util_encode_json_object(r, j_result, JSON_PRESERVE_ORDER | JSON_COMPACT);

	char *user_info_sub = NULL;
	oidc_jose_get_string(r->pool, j_result, OIDC_CLAIM_SUB, FALSE, &user_info_sub, NULL);

	oidc_debug(r, "id_token_sub=%s, user_info_sub=%s", id_token_sub, user_info_sub);

	if ((user_info_sub == NULL) && (apr_table_get(r->subprocess_env, "OIDC_NO_USERINFO_SUB") == NULL)) {
		oidc_error(r,
			   "mandatory claim (\"%s\") was not returned from userinfo endpoint "
			   "(https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)",
			   OIDC_CLAIM_SUB);
		goto end;
	}

	if ((id_token_sub != NULL) && (user_info_sub != NULL)) {
		if (_oidc_strcmp(id_token_sub, user_info_sub) != 0) {
			oidc_error(r,
				   "\"%s\" claim (\"%s\") returned from userinfo endpoint does not match the one in "
				   "the id_token (\"%s\")",
				   OIDC_CLAIM_SUB, user_info_sub, id_token_sub);
			goto end;
		}
	}

	rv = TRUE;

end:

	if (j_result)
		json_decref(j_result);

	return rv;
}
