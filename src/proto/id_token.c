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

#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

/*
 * if a nonce was passed in the authorization request (and stored in the browser state),
 * check that it matches the nonce value in the id_token payload
 */
// non-static for test.c
apr_byte_t oidc_proto_idtoken_validate_nonce(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
					     const char *nonce, oidc_jwt_t *jwt) {

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

#define OIDC_PROTO_IDTOKEN_AUD_CLIENT_ID_SPECIAL_VALUE "@"

/*
 * validate the "aud" and "azp" claims in the id_token payload
 */
apr_byte_t oidc_proto_idtoken_validate_aud_and_azp(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
						   oidc_jwt_payload_t *id_token_payload) {

	char *azp = NULL;
	const char *s_aud = NULL;
	const apr_array_header_t *arr = NULL;
	int i = 0;

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

		arr = oidc_proto_profile_id_token_aud_values_get(r->pool, provider);

		/* check if it is a single-value */
		if (json_is_string(aud)) {

			if (arr == NULL) {

				/* a single-valued audience must be equal to our client_id */
				if (_oidc_strcmp(json_string_value(aud), oidc_cfg_provider_client_id_get(provider)) !=
				    0) {
					oidc_error(r,
						   "the configured client_id (%s) did not match the \"%s\" claim value "
						   "(%s) in "
						   "the id_token",
						   oidc_cfg_provider_client_id_get(provider), OIDC_CLAIM_AUD,
						   json_string_value(aud));
					return FALSE;
				}

			} else {

				for (i = 0; i < arr->nelts; i++) {
					s_aud = APR_ARRAY_IDX(arr, i, const char *);
					if (_oidc_strcmp(s_aud, OIDC_PROTO_IDTOKEN_AUD_CLIENT_ID_SPECIAL_VALUE) == 0)
						s_aud = oidc_cfg_provider_client_id_get(provider);
					if (_oidc_strcmp(json_string_value(aud), s_aud) == 0)
						break;
				}

				if (i == arr->nelts) {
					oidc_error(
					    r, "none of our configured audience values could be found in \"%s\" claim",
					    OIDC_CLAIM_AUD);
					return FALSE;
				}
			}

			/* check if this is a multi-valued audience */
		} else if (json_is_array(aud)) {

			if (arr == NULL) {

				if ((json_array_size(aud) > 1) && (azp == NULL)) {
					oidc_warn(r,
						  "the \"%s\" claim value in the id_token is an array with more than 1 "
						  "element, but \"%s\" claim is not present (a SHOULD in the spec...)",
						  OIDC_CLAIM_AUD, OIDC_CLAIM_AZP);
				}

				if (oidc_util_json_array_has_value(r, aud, oidc_cfg_provider_client_id_get(provider)) ==
				    FALSE) {
					oidc_error(
					    r,
					    "our configured client_id (%s) could not be found in the array of values "
					    "for \"%s\" claim",
					    oidc_cfg_provider_client_id_get(provider), OIDC_CLAIM_AUD);
					return FALSE;
				}

			} else {

				/* handle explicit and exhaustive configuration of acceptable audience values */

				for (i = 0; i < arr->nelts; i++) {
					s_aud = APR_ARRAY_IDX(arr, i, const char *);
					if (_oidc_strcmp(s_aud, OIDC_PROTO_IDTOKEN_AUD_CLIENT_ID_SPECIAL_VALUE) == 0)
						s_aud = oidc_cfg_provider_client_id_get(provider);
					if (oidc_util_json_array_has_value(r, aud, s_aud) == FALSE) {
						oidc_error(r,
							   "our configured audience value (%s) could not be found in "
							   "the array of values "
							   "for \"%s\" claim",
							   APR_ARRAY_IDX(arr, i, const char *), OIDC_CLAIM_AUD);
						return FALSE;
					}
				}

				if (json_array_size(aud) > arr->nelts) {
					oidc_error(
					    r,
					    "our configured audience values are all present in the array of values "
					    "for \"%s\" claim, but there are other unknown/untrusted values included "
					    "as well",
					    OIDC_CLAIM_AUD);
					return FALSE;
				}
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
 * check the at_hash value in the id_token against the access_token
 */
apr_byte_t oidc_proto_idtoken_validate_access_token(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
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
 * check the c_hash value in the id_token against the code
 */
apr_byte_t oidc_proto_idtoken_validate_code(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
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
		if (oidc_proto_idtoken_validate_nonce(r, cfg, provider, nonce, jwt) == FALSE)
			return FALSE;
	}

	/* validate the ID Token JWT, requiring iss match, and valid exp + iat */
	if (oidc_proto_jwt_validate(
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
	if (oidc_proto_idtoken_validate_aud_and_azp(r, cfg, provider, &jwt->payload) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * check whether the provided string is a valid id_token and return its parsed contents
 */
apr_byte_t oidc_proto_idtoken_parse(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider, const char *id_token,
				    const char *nonce, oidc_jwt_t **jwt, apr_byte_t is_code_flow) {

	char *alg = NULL;
	oidc_debug(r, "enter: id_token header=%s", oidc_proto_jwt_header_peek(r, id_token, &alg, NULL, NULL));
	apr_hash_t *decryption_keys = NULL;

	char buf[APR_RFC822_DATE_LEN + 1];
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	if (oidc_util_key_symmetric_create(r, oidc_cfg_provider_client_secret_get(provider), oidc_alg2keysize(alg),
					   OIDC_JOSE_ALG_SHA256, TRUE, &jwk) == FALSE)
		return FALSE;

	decryption_keys = oidc_util_key_symmetric_merge(r->pool, oidc_cfg_private_keys_get(cfg), jwk);
	if (oidc_cfg_provider_client_keys_get(provider))
		decryption_keys =
		    oidc_util_key_sets_merge(r->pool, decryption_keys, oidc_cfg_provider_client_keys_get(provider));

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
		if (oidc_util_key_symmetric_create(r, oidc_cfg_provider_client_secret_get(provider), 0, NULL, TRUE,
						   &jwk) == FALSE) {
			oidc_jwt_destroy(*jwt);
			*jwt = NULL;
			return FALSE;
		}

		if (oidc_proto_jwt_verify(
			r, cfg, *jwt, oidc_cfg_provider_jwks_uri_get(provider),
			oidc_cfg_provider_ssl_validate_server_get(provider),
			oidc_util_key_symmetric_merge(r->pool, oidc_cfg_provider_verify_public_keys_get(provider), jwk),
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
