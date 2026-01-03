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
apr_byte_t oidc_proto_jwt_validate(request_rec *r, oidc_jwt_t *jwt, const char *iss, apr_byte_t exp_is_mandatory,
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
	rv = oidc_jwt_verify(r->pool, jwt, oidc_util_key_sets_hash_merge(r->pool, static_keys, dynamic_keys), &err);

	/* if no kid was provided we may have used stale keys from the cache, so we'll refresh it */
	if ((rv == FALSE) && (jwt->header.kid == NULL)) {
		oidc_warn(
		    r, "JWT signature verification failed (%s) for JWT with no kid, re-trying with forced refresh now",
		    oidc_jose_e2s(r->pool, err));
		force_refresh = TRUE;
		/* destroy the list to avoid memory leaks when keys with the same kid are retrieved */
		oidc_jwk_list_destroy_hash(dynamic_keys);
		oidc_proto_jwks_uri_keys(r, cfg, jwt, jwks_uri, ssl_validate_server, dynamic_keys, &force_refresh);
		rv = oidc_jwt_verify(r->pool, jwt, oidc_util_key_sets_hash_merge(r->pool, static_keys, dynamic_keys),
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
char *oidc_proto_jwt_header_peek(request_rec *r, const char *compact_encoded_jwt, char **alg, char **enc, char **kid) {
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
		oidc_util_json_decode_object(r, result, &json);
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

apr_byte_t oidc_proto_jwt_create_from_first_pkey(request_rec *r, oidc_cfg_t *cfg, oidc_jwk_t **jwk, oidc_jwt_t **jwt,
						 apr_byte_t use_psa_for_rsa) {
	apr_byte_t rv = FALSE;

	oidc_debug(r, "enter");

	*jwk = oidc_util_key_list_first(oidc_cfg_private_keys_get(cfg), -1, OIDC_JOSE_JWK_SIG_STR);
	if (*jwk == NULL) {
		oidc_error(r, "no RSA/EC private signing keys have been configured (in " OIDCPrivateKeyFiles ")");
		goto end;
	}

	*jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	if (*jwt == NULL)
		goto end;

	(*jwt)->header.kid = apr_pstrdup(r->pool, (*jwk)->kid);

	if ((*jwk)->kty == CJOSE_JWK_KTY_RSA)
		(*jwt)->header.alg = apr_pstrdup(r->pool, use_psa_for_rsa ? CJOSE_HDR_ALG_PS256 : CJOSE_HDR_ALG_RS256);
	else if ((*jwk)->kty == CJOSE_JWK_KTY_EC)
		(*jwt)->header.alg = apr_pstrdup(r->pool, CJOSE_HDR_ALG_ES256);
	else {
		oidc_error(r, "no usable RSA/EC signing keys has been configured (in " OIDCPrivateKeyFiles ")");
		goto end;
	}

	rv = TRUE;

end:

	// also in case of errors, jwt will be destroyed in the caller function
	return rv;
}

apr_byte_t oidc_proto_jwt_sign_and_serialize(request_rec *r, oidc_jwk_t *jwk, oidc_jwt_t *jwt, char **cser) {
	apr_byte_t rv = FALSE;
	oidc_jose_error_t err;

	if (oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err) == FALSE) {
		oidc_error(r, "oidc_jwt_sign failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	*cser = oidc_jose_jwt_serialize(r->pool, jwt, &err);
	if (*cser == NULL) {
		oidc_error(r, "oidc_jose_jwt_serialize failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	rv = TRUE;

end:

	return rv;
}
