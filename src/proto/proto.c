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

#include "proto/proto.h"
#include "cfg/dir.h"
#include "cfg/parse.h"
#include "handle/handle.h"
#include "metadata.h"
#include "metrics.h"
#include "mod_auth_openidc.h"
#include "util.h"

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

/*
 * generate a random value (nonce) to correlate request/response through browser state
 */
apr_byte_t oidc_proto_generate_nonce(request_rec *r, char **nonce, int len) {
	return oidc_util_generate_random_string(r, nonce, len);
}

/*
 * if a nonce was passed in the authorization request (and stored in the browser state),
 * check that it matches the nonce value in the id_token payload
 */
// non-static for test.c
apr_byte_t oidc_proto_validate_nonce(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider, const char *nonce,
				     oidc_jwt_t *jwt) {

	oidc_jose_error_t err;

	/* see if we have this nonce cached already */
	char *replay = NULL;
	oidc_cache_get_nonce(r, nonce, &replay);
	if (replay != NULL) {
		oidc_error(r,
			   "the nonce value (%s) passed in the browser state was found in the cache already; possible "
			   "replay attack!?",
			   nonce);
		return FALSE;
	}

	/* get the "nonce" value in the id_token payload */
	char *j_nonce = NULL;
	if (oidc_jose_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_NONCE, TRUE, &j_nonce, &err) == FALSE) {
		oidc_error(r, "id_token JSON payload did not contain a \"%s\" string: %s", OIDC_CLAIM_NONCE,
			   oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	/* see if the nonce in the id_token matches the one that we sent in the authorization request */
	if (_oidc_strcmp(nonce, j_nonce) != 0) {
		oidc_error(
		    r, "the nonce value (%s) in the id_token did not match the one stored in the browser session (%s)",
		    j_nonce, nonce);
		return FALSE;
	}

	/*
	 * nonce cache duration (replay prevention window) is the 2x the configured
	 * slack on the timestamp (+-) for token issuance plus 10 seconds for safety
	 */
	apr_time_t nonce_cache_duration = apr_time_from_sec(oidc_cfg_provider_idtoken_iat_slack_get(provider) * 2 + 10);

	/* store it in the cache for the calculated duration */
	oidc_cache_set_nonce(r, nonce, nonce, apr_time_now() + nonce_cache_duration);

	oidc_debug(r, "nonce \"%s\" validated successfully and is now cached for %" APR_TIME_T_FMT " seconds", nonce,
		   apr_time_sec(nonce_cache_duration));

	return TRUE;
}

/*
 * validate the "aud" and "azp" claims in the id_token payload
 */
apr_byte_t oidc_proto_validate_aud_and_azp(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
					   oidc_jwt_payload_t *id_token_payload) {

	char *azp = NULL;
	oidc_jose_get_string(r->pool, id_token_payload->value.json, OIDC_CLAIM_AZP, FALSE, &azp, NULL);

	/*
	 * the "azp" claim is only needed when the id_token has a single audience value and that audience
	 * is different than the authorized party; it MAY be included even when the authorized party is
	 * the same as the sole audience.
	 */
	if ((azp != NULL) && (_oidc_strcmp(azp, oidc_cfg_provider_client_id_get(provider)) != 0)) {
		oidc_error(r,
			   "the \"%s\" claim (%s) is present in the id_token, but is not equal to the configured "
			   "client_id (%s)",
			   OIDC_CLAIM_AZP, azp, oidc_cfg_provider_client_id_get(provider));
		return FALSE;
	}

	/* get the "aud" value from the JSON payload */
	json_t *aud = json_object_get(id_token_payload->value.json, OIDC_CLAIM_AUD);
	if (aud != NULL) {

		/* check if it is a single-value */
		if (json_is_string(aud)) {

			/* a single-valued audience must be equal to our client_id */
			if (_oidc_strcmp(json_string_value(aud), oidc_cfg_provider_client_id_get(provider)) != 0) {
				oidc_error(r,
					   "the configured client_id (%s) did not match the \"%s\" claim value (%s) in "
					   "the id_token",
					   oidc_cfg_provider_client_id_get(provider), OIDC_CLAIM_AUD,
					   json_string_value(aud));
				return FALSE;
			}

			/* check if this is a multi-valued audience */
		} else if (json_is_array(aud)) {

			if ((json_array_size(aud) > 1) && (azp == NULL)) {
				oidc_warn(r,
					  "the \"%s\" claim value in the id_token is an array with more than 1 "
					  "element, but \"%s\" claim is not present (a SHOULD in the spec...)",
					  OIDC_CLAIM_AUD, OIDC_CLAIM_AZP);
			}

			if (oidc_util_json_array_has_value(r, aud, oidc_cfg_provider_client_id_get(provider)) ==
			    FALSE) {
				oidc_error(r,
					   "our configured client_id (%s) could not be found in the array of values "
					   "for \"%s\" claim",
					   oidc_cfg_provider_client_id_get(provider), OIDC_CLAIM_AUD);
				return FALSE;
			}

			if (json_array_size(aud) > 1) {
				oidc_error(
				    r,
				    "our configured client_id (%s) was found in the array of values "
				    "for \"%s\" claim, but there are other unknown/untrusted values included as well",
				    oidc_cfg_provider_client_id_get(provider), OIDC_CLAIM_AUD);
				return FALSE;
			}

		} else {
			oidc_error(r, "id_token JSON payload \"%s\" claim is not a string nor an array",
				   OIDC_CLAIM_AUD);
			return FALSE;
		}

	} else {
		oidc_error(r, "id_token JSON payload did not contain an \"%s\" claim", OIDC_CLAIM_AUD);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate "iat" claim in JWT
 */
static apr_byte_t oidc_proto_validate_iat(request_rec *r, oidc_jwt_t *jwt, apr_byte_t is_mandatory, int slack) {

	/* get the current time */
	apr_time_t now = apr_time_sec(apr_time_now());

	/* sanity check for iat being set */
	if (jwt->payload.iat == OIDC_JWT_CLAIM_TIME_EMPTY) {
		if (is_mandatory) {
			oidc_error(r, "JWT did not contain an \"%s\" number value", OIDC_CLAIM_IAT);
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
		oidc_error(r, "\"iat\" validation failure (%ld): JWT was issued more than %d seconds ago",
			   (long)jwt->payload.iat, slack);
		return FALSE;
	}
	if ((now + slack) < jwt->payload.iat) {
		oidc_error(r, "\"iat\" validation failure (%ld): JWT was issued more than %d seconds in the future",
			   (long)jwt->payload.iat, slack);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate "exp" claim in JWT
 */
static apr_byte_t oidc_proto_validate_exp(request_rec *r, oidc_jwt_t *jwt, apr_byte_t is_mandatory) {

	/* get the current time */
	apr_time_t now = apr_time_sec(apr_time_now());

	/* sanity check for exp being set */
	if (jwt->payload.exp == OIDC_JWT_CLAIM_TIME_EMPTY) {
		if (is_mandatory) {
			oidc_error(r, "JWT did not contain an \"%s\" number value", OIDC_CLAIM_EXP);
			return FALSE;
		}
		return TRUE;
	}

	/* see if now is beyond the JWT expiry timestamp */
	apr_time_t expires = jwt->payload.exp;
	if (now > expires) {
		oidc_error(r, "\"exp\" validation failure (%ld): JWT expired %ld seconds ago", (long)expires,
			   (long)(now - expires));
		return FALSE;
	}

	return TRUE;
}

/*
 * validate a JSON Web token
 */
apr_byte_t oidc_proto_validate_jwt(request_rec *r, oidc_jwt_t *jwt, const char *iss, apr_byte_t exp_is_mandatory,
				   apr_byte_t iat_is_mandatory, int iat_slack) {

	if (iss != NULL) {

		/* issuer is set and must match */
		if (jwt->payload.iss == NULL) {
			oidc_error(r, "JWT did not contain an \"%s\" string (requested value: %s)", OIDC_CLAIM_ISS,
				   iss);
			return FALSE;
		}

		/* check if the issuer matches the requested value */
		if (oidc_util_issuer_match(iss, jwt->payload.iss) == FALSE) {
			oidc_error(r, "requested issuer (%s) does not match received \"%s\" value in id_token (%s)",
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
static apr_byte_t oidc_proto_validate_idtoken(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
					      const char *nonce) {

	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	oidc_debug(r, "enter, jwt.header=\"%s\", jwt.payload=\"%s\", nonce=\"%s\"", jwt->header.value.str,
		   jwt->payload.value.str, nonce);

	/* if a nonce is not passed, we're doing a ("code") flow where the nonce is optional */
	if (nonce != NULL) {
		/* if present, verify the nonce */
		if (oidc_proto_validate_nonce(r, cfg, provider, nonce, jwt) == FALSE)
			return FALSE;
	}

	/* validate the ID Token JWT, requiring iss match, and valid exp + iat */
	if (oidc_proto_validate_jwt(
		r, jwt, oidc_cfg_provider_validate_issuer_get(provider) ? oidc_cfg_provider_issuer_get(provider) : NULL,
		TRUE, TRUE, oidc_cfg_provider_idtoken_iat_slack_get(provider)) == FALSE)
		return FALSE;

	/* check if the required-by-spec "sub" claim is present */
	if (jwt->payload.sub == NULL) {
		oidc_error(r, "id_token JSON payload did not contain the required-by-spec \"%s\" string value",
			   OIDC_CLAIM_SUB);
		return FALSE;
	}

	/* verify the "aud" and "azp" values */
	if (oidc_proto_validate_aud_and_azp(r, cfg, provider, &jwt->payload) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * verify the signature on a JWT using the dynamically obtained and statically configured keys
 */
apr_byte_t oidc_proto_jwt_verify(request_rec *r, oidc_cfg_t *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri,
				 int ssl_validate_server, apr_hash_t *static_keys, const char *alg) {

	oidc_jose_error_t err;
	apr_hash_t *dynamic_keys = NULL;
	apr_byte_t force_refresh = FALSE;
	apr_byte_t rv = FALSE;

	if (alg != NULL) {
		if (_oidc_strcmp(jwt->header.alg, alg) != 0) {
			oidc_error(r, "JWT was not signed with the expected configured algorithm: %s != %s",
				   jwt->header.alg, alg);
			return FALSE;
		}
	}

	dynamic_keys = apr_hash_make(r->pool);

	/* see if we've got a JWKs URI set for signature validation with dynamically obtained asymmetric keys */
	if ((jwks_uri->uri == NULL) && (jwks_uri->signed_uri == NULL)) {
		oidc_debug(r, "\"jwks_uri\" and \"signed_jwks_uri\" are not set, signature validation will only be "
			      "performed against statically configured keys");
		/* the JWKs URI was provided, but let's see if it makes sense to pull down keys, i.e. if it is an
		 * asymmetric signature */
	} else if (oidc_jwt_alg2kty(jwt) == CJOSE_JWK_KTY_OCT) {
		oidc_debug(r,
			   "\"%s\" is set, but the JWT has a symmetric signature so we won't pull/use keys from there",
			   (jwks_uri->signed_uri != NULL) ? "signed_jwks_uri" : "jwks_uri");
	} else {
		/* get the key from the JWKs that corresponds with the key specified in the header */
		force_refresh = FALSE;
		if (oidc_proto_jwks_uri_keys(r, cfg, jwt, jwks_uri, ssl_validate_server, dynamic_keys,
					     &force_refresh) == FALSE) {
			oidc_jwk_list_destroy_hash(dynamic_keys);
			return FALSE;
		}
	}

	/* do the actual JWS verification with the locally and remotely provided key material */
	// TODO: now static keys "win" if the same `kid` was used in both local and remote key sets
	rv = oidc_jwt_verify(r->pool, jwt, oidc_util_merge_key_sets_hash(r->pool, static_keys, dynamic_keys), &err);

	/* if no kid was provided we may have used stale keys from the cache, so we'll refresh it */
	if ((rv == FALSE) && (jwt->header.kid == NULL)) {
		oidc_warn(
		    r, "JWT signature verification failed (%s) for JWT with no kid, re-trying with forced refresh now",
		    oidc_jose_e2s(r->pool, err));
		force_refresh = TRUE;
		/* destroy the list to avoid memory leaks when keys with the same kid are retrieved */
		oidc_jwk_list_destroy_hash(dynamic_keys);
		oidc_proto_jwks_uri_keys(r, cfg, jwt, jwks_uri, ssl_validate_server, dynamic_keys, &force_refresh);
		rv = oidc_jwt_verify(r->pool, jwt, oidc_util_merge_key_sets_hash(r->pool, static_keys, dynamic_keys),
				     &err);
	}

	if (rv == FALSE) {
		oidc_error(r, "JWT signature verification failed: %s", oidc_jose_e2s(r->pool, err));
		oidc_jwk_list_destroy_hash(dynamic_keys);
		return FALSE;
	}

	oidc_debug(r, "JWT signature verification with algorithm \"%s\" was successful", jwt->header.alg);

	oidc_jwk_list_destroy_hash(dynamic_keys);
	return TRUE;
}

/*
 * return the compact-encoded JWT header contents
 */
char *oidc_proto_peek_jwt_header(request_rec *r, const char *compact_encoded_jwt, char **alg, char **enc, char **kid) {
	char *input = NULL, *result = NULL;
	char *p = _oidc_strstr(compact_encoded_jwt ? compact_encoded_jwt : "", ".");
	if (p == NULL) {
		oidc_warn(r, "could not parse first element separated by \".\" from input");
		return NULL;
	}
	input = apr_pstrmemdup(r->pool, compact_encoded_jwt, _oidc_strlen(compact_encoded_jwt) - _oidc_strlen(p));
	if (oidc_util_base64url_decode(r->pool, &result, input) <= 0) {
		oidc_warn(r, "oidc_base64url_decode returned an error");
		return NULL;
	}
	if ((alg != NULL) || (enc != NULL)) {
		json_t *json = NULL;
		oidc_util_decode_json_object(r, result, &json);
		if (json) {
			if (alg)
				*alg = apr_pstrdup(r->pool, json_string_value(json_object_get(json, CJOSE_HDR_ALG)));
			if (enc)
				*enc = apr_pstrdup(r->pool, json_string_value(json_object_get(json, CJOSE_HDR_ENC)));
			if (kid)
				*kid = apr_pstrdup(r->pool, json_string_value(json_object_get(json, CJOSE_HDR_KID)));
		}
		json_decref(json);
	}
	return result;
}

/*
 * check whether the provided string is a valid id_token and return its parsed contents
 */
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider, const char *id_token,
				    const char *nonce, oidc_jwt_t **jwt, apr_byte_t is_code_flow) {

	char *alg = NULL;
	oidc_debug(r, "enter: id_token header=%s", oidc_proto_peek_jwt_header(r, id_token, &alg, NULL, NULL));
	apr_hash_t *decryption_keys = NULL;

	char buf[APR_RFC822_DATE_LEN + 1];
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	if (oidc_util_create_symmetric_key(r, oidc_cfg_provider_client_secret_get(provider), oidc_alg2keysize(alg),
					   OIDC_JOSE_ALG_SHA256, TRUE, &jwk) == FALSE)
		return FALSE;

	decryption_keys = oidc_util_merge_symmetric_key(r->pool, oidc_cfg_private_keys_get(cfg), jwk);
	if (oidc_cfg_provider_client_keys_get(provider))
		decryption_keys =
		    oidc_util_merge_key_sets(r->pool, decryption_keys, oidc_cfg_provider_client_keys_get(provider));

	if (oidc_jwt_parse(r->pool, id_token, jwt, decryption_keys, FALSE, &err) == FALSE) {
		oidc_error(r, "oidc_jwt_parse failed: %s", oidc_jose_e2s(r->pool, err));
		oidc_jwt_destroy(*jwt);
		*jwt = NULL;
		return FALSE;
	}

	oidc_jwk_destroy(jwk);
	oidc_debug(r, "successfully parsed (and possibly decrypted) JWT with header=%s, and payload=%s",
		   (*jwt)->header.value.str, (*jwt)->payload.value.str);

	// make signature validation exception for 'code' flow and the algorithm NONE
	if (is_code_flow == FALSE || _oidc_strcmp((*jwt)->header.alg, "none") != 0) {

		jwk = NULL;
		if (oidc_util_create_symmetric_key(r, oidc_cfg_provider_client_secret_get(provider), 0, NULL, TRUE,
						   &jwk) == FALSE) {
			oidc_jwt_destroy(*jwt);
			*jwt = NULL;
			return FALSE;
		}

		if (oidc_proto_jwt_verify(
			r, cfg, *jwt, oidc_cfg_provider_jwks_uri_get(provider),
			oidc_cfg_provider_ssl_validate_server_get(provider),
			oidc_util_merge_symmetric_key(r->pool, oidc_cfg_provider_verify_public_keys_get(provider), jwk),
			oidc_cfg_provider_id_token_signed_response_alg_get(provider)) == FALSE) {

			oidc_error(r, "id_token signature could not be validated, aborting");
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
	oidc_debug(r, "valid id_token for user \"%s\" expires: [%s], in %ld secs from now)", (*jwt)->payload.sub, buf,
		   (long)((*jwt)->payload.exp - apr_time_sec(apr_time_now())));

	/* since we've made it so far, we may as well say it is a valid id_token */
	return TRUE;
}

/*
 * check that the access_token type is supported
 */
static apr_byte_t oidc_proto_validate_token_type(request_rec *r, oidc_provider_t *provider, const char *token_type) {
	/*  we only support bearer/Bearer and DPoP/dpop */
	if ((token_type != NULL) && (_oidc_strnatcasecmp(token_type, OIDC_PROTO_BEARER) != 0) &&
	    (_oidc_strnatcasecmp(token_type, OIDC_PROTO_DPOP) != 0) &&
	    (oidc_cfg_provider_userinfo_endpoint_url_get(provider) != NULL)) {
		oidc_error(r,
			   "token_type is \"%s\" and UserInfo endpoint (%s) for issuer \"%s\" is set: can only deal "
			   "with \"%s\" or \"%s\" authentication against a UserInfo endpoint!",
			   token_type, oidc_cfg_provider_userinfo_endpoint_url_get(provider),
			   oidc_cfg_provider_issuer_get(provider), OIDC_PROTO_BEARER, OIDC_PROTO_DPOP);
		return FALSE;
	}
	return TRUE;
}

/*
 * send a code/refresh request to the token endpoint and return the parsed contents
 */
apr_byte_t oidc_proto_token_endpoint_request(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
					     apr_table_t *params, char **id_token, char **access_token,
					     char **token_type, int *expires_in, char **refresh_token) {

	char *response = NULL;
	char *basic_auth = NULL;
	char *bearer_auth = NULL;
	char *dpop = NULL;
	json_t *j_result = NULL, *j_expires_in = NULL;

	/* add the token endpoint authentication credentials */
	if (oidc_proto_token_endpoint_auth(
		r, cfg, oidc_cfg_provider_token_endpoint_auth_get(provider), oidc_cfg_provider_client_id_get(provider),
		oidc_cfg_provider_client_secret_get(provider), oidc_cfg_provider_client_keys_get(provider),
		oidc_cfg_provider_token_endpoint_url_get(provider), params, NULL, &basic_auth, &bearer_auth) == FALSE)
		return FALSE;

	/* add any configured extra static parameters to the token endpoint */
	oidc_util_table_add_query_encoded_params(r->pool, params,
						 oidc_cfg_provider_token_endpoint_params_get(provider));

	if (oidc_cfg_provider_response_require_iss_get(provider))
		dpop = oidc_proto_dpop(r, cfg, oidc_cfg_provider_token_endpoint_url_get(provider), "POST", NULL);

	/* send the request to the token endpoint */
	if (oidc_http_post_form(r, oidc_cfg_provider_token_endpoint_url_get(provider), params, basic_auth, bearer_auth,
				dpop, oidc_cfg_provider_ssl_validate_server_get(provider), &response, NULL,
				oidc_cfg_http_timeout_long_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
				oidc_cfg_dir_pass_cookies_get(r),
				oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider),
				oidc_cfg_provider_token_endpoint_tls_client_key_get(provider),
				oidc_cfg_provider_token_endpoint_tls_client_key_pwd_get(provider)) == FALSE) {
		oidc_warn(r, "error when calling the token endpoint (%s)",
			  oidc_cfg_provider_token_endpoint_url_get(provider));
		return FALSE;
	}

	/* check for errors, the response itself will have been logged already */
	if (oidc_util_decode_json_and_check_error(r, response, &j_result) == FALSE)
		return FALSE;

	/* get the id_token from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_ID_TOKEN, id_token, NULL);

	/* get the access_token from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_ACCESS_TOKEN, access_token, NULL);

	/* get the token type from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_TOKEN_TYPE, token_type, NULL);

	/* check the new token type */
	if (token_type != NULL) {
		if (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE) {
			oidc_warn(r, "access token type did not validate, dropping it");
			*access_token = NULL;
		}
	}

	/* get the access token expires_in value */
	*expires_in = -1;
	j_expires_in = json_object_get(j_result, OIDC_PROTO_EXPIRES_IN);
	if (j_expires_in != NULL) {
		/* cater for string values (old Azure AD) */
		if (json_is_string(j_expires_in))
			*expires_in = _oidc_str_to_int(json_string_value(j_expires_in), -1);
		else if (json_is_integer(j_expires_in))
			*expires_in = json_integer_value(j_expires_in);
	}

	/* get the refresh_token from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_REFRESH_TOKEN, refresh_token, NULL);

	json_decref(j_result);

	return TRUE;
}

/*
 * refreshes the access_token/id_token /refresh_token received from the OP using the refresh_token
 */
apr_byte_t oidc_proto_refresh_request(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider, const char *rtoken,
				      char **id_token, char **access_token, char **token_type, int *expires_in,
				      char **refresh_token) {

	oidc_debug(r, "enter");

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_REFRESH_TOKEN);
	apr_table_setn(params, OIDC_PROTO_REFRESH_TOKEN, rtoken);
	apr_table_setn(params, OIDC_PROTO_SCOPE, oidc_cfg_provider_scope_get(provider));

	return oidc_proto_token_endpoint_request(r, cfg, provider, params, id_token, access_token, token_type,
						 expires_in, refresh_token);
}

/*
 * return the Javascript code used to handle an Implicit grant type
 * i.e. that posts the data returned by the OP in the URL fragment to the OIDCRedirectURI
 */
int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg_t *c) {

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

	const char *html_body = "    <p>Submitting...</p>\n"
				"    <form method=\"post\" action=\"\">\n"
				"      <p>\n"
				"        <input type=\"hidden\" name=\"" OIDC_PROTO_RESPONSE_MODE
				"\" value=\"" OIDC_PROTO_RESPONSE_MODE_FRAGMENT "\">\n"
				"      </p>\n"
				"    </form>\n";

	return oidc_util_html_send(r, "Submitting...", java_script, "postOnLoad", html_body, OK);
}

/*
 * check a provided hash value (at_hash|c_hash) against a corresponding hash calculated for a specified value and
 * algorithm
 */
static apr_byte_t oidc_proto_validate_hash(request_rec *r, const char *alg, const char *hash, const char *value,
					   const char *type) {

	char *calc = NULL;
	unsigned int calc_len = 0;
	unsigned int hash_len = oidc_jose_hash_length(alg) / 2;
	oidc_jose_error_t err;

	/* hash the provided access_token */
	if (oidc_jose_hash_string(r->pool, alg, value, &calc, &calc_len, &err) == FALSE) {
		oidc_error(r, "oidc_jose_hash_string failed: %s", oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	/* calculate the base64url-encoded value of the hash */
	char *decoded = NULL;
	unsigned int decoded_len = oidc_util_base64url_decode(r->pool, &decoded, hash);
	if (decoded_len <= 0) {
		oidc_error(r, "oidc_base64url_decode returned an error");
		return FALSE;
	}

	oidc_debug(r, "hash_len=%d, decoded_len=%d, calc_len=%d", hash_len, decoded_len, calc_len);

	/* compare the calculated hash against the provided hash */
	if ((decoded_len != hash_len) || (calc_len < hash_len) || (memcmp(decoded, calc, hash_len) != 0)) {
		oidc_error(r, "provided \"%s\" hash value (%s) does not match the calculated value", type, hash);
		return FALSE;
	}

	oidc_debug(r, "successfully validated the provided \"%s\" hash value (%s) against the calculated value", type,
		   hash);

	return TRUE;
}

/*
 * check a hash value in the id_token against the corresponding hash calculated over a provided value
 */
static apr_byte_t oidc_proto_validate_hash_value(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
						 const char *response_type, const char *value, const char *key,
						 apr_array_header_t *required_for_flows) {

	/*
	 * get the hash value from the id_token
	 */
	char *hash = NULL;
	oidc_jose_get_string(r->pool, jwt->payload.value.json, key, FALSE, &hash, NULL);

	/*
	 * check if the hash was present
	 */
	if (hash == NULL) {

		/* no hash..., now see if the flow required it */
		int i;
		for (i = 0; i < required_for_flows->nelts; i++) {
			if (oidc_util_spaced_string_equals(r->pool, response_type,
							   APR_ARRAY_IDX(required_for_flows, i, const char *))) {
				oidc_warn(r, "flow is \"%s\", but no %s found in id_token", response_type, key);
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
apr_byte_t oidc_proto_validate_code(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
				    const char *response_type, const char *code) {
	apr_array_header_t *required_for_flows = apr_array_make(r->pool, 2, sizeof(const char *));
	APR_ARRAY_PUSH(required_for_flows, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN;
	APR_ARRAY_PUSH(required_for_flows, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;
	if (oidc_proto_validate_hash_value(r, provider, jwt, response_type, code, OIDC_CLAIM_C_HASH,
					   required_for_flows) == FALSE) {
		oidc_error(r, "could not validate code against \"%s\" claim value", OIDC_CLAIM_C_HASH);
		return FALSE;
	}
	return TRUE;
}

/*
 * check the at_hash value in the id_token against the access_token
 */
apr_byte_t oidc_proto_validate_access_token(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
					    const char *response_type, const char *access_token) {
	apr_array_header_t *required_for_flows = apr_array_make(r->pool, 2, sizeof(const char *));
	APR_ARRAY_PUSH(required_for_flows, const char *) = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN;
	APR_ARRAY_PUSH(required_for_flows, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;
	if (oidc_proto_validate_hash_value(r, provider, jwt, response_type, access_token, OIDC_CLAIM_AT_HASH,
					   required_for_flows) == FALSE) {
		oidc_error(r, "could not validate access token against \"%s\" claim value", OIDC_CLAIM_AT_HASH);
		return FALSE;
	}
	return TRUE;
}

/*
 * return the supported flows
 */
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 6, sizeof(const char *));
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;
	return result;
}

/*
 * check if a particular OpenID Connect flow is supported
 */
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow) {
	apr_array_header_t *flows = oidc_proto_supported_flows(pool);
	int i;
	for (i = 0; i < flows->nelts; i++) {
		if (oidc_util_spaced_string_equals(pool, flow, APR_ARRAY_IDX(flows, i, const char *)))
			return TRUE;
	}
	return FALSE;
}

/*
 * set the WWW-Authenticate response header according to https://tools.ietf.org/html/rfc6750#section-3
 */
int oidc_proto_return_www_authenticate(request_rec *r, const char *error, const char *error_description) {
	apr_byte_t accept_token_in = oidc_cfg_dir_oauth_accept_token_in_get(r);
	char *hdr;
	if (accept_token_in == OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC) {
		hdr = apr_psprintf(r->pool, "%s", OIDC_PROTO_BASIC);
	} else {
		hdr = apr_psprintf(r->pool, "%s", OIDC_PROTO_BEARER);
	}

	if (ap_auth_name(r) != NULL)
		hdr = apr_psprintf(r->pool, "%s %s=\"%s\"", hdr, OIDC_PROTO_REALM, ap_auth_name(r));
	if (error != NULL)
		hdr =
		    apr_psprintf(r->pool, "%s%s %s=\"%s\"", hdr, (ap_auth_name(r) ? "," : ""), OIDC_PROTO_ERROR, error);
	if (error_description != NULL)
		hdr = apr_psprintf(r->pool, "%s, %s=\"%s\"", hdr, OIDC_PROTO_ERROR_DESCRIPTION, error_description);
	oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_WWW_AUTHENTICATE, hdr);
	return HTTP_UNAUTHORIZED;
}
