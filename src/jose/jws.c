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
 * JSON Web Signature (JWS) / JWT signing, parsing and verification
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "jose.h"

#include "jose/internal.h"

#include <jansson.h>

#include <cjose/cjose.h>

#include "util/util.h"

/*
 * set a header value in a JWT
 */
void oidc_jwt_hdr_set(oidc_jwt_t *jwt, const char *key, const char *value) {
	json_object_set_new(jwt->header.value.json, key, json_string(value));
}

/*
 * create a new JWT
 */
oidc_jwt_t *oidc_jwt_new(apr_pool_t *pool, int create_header, int create_payload) {
	oidc_jwt_t *jwt = apr_pcalloc(pool, sizeof(oidc_jwt_t));
	if (create_header) {
		jwt->header.value.json = json_object();
	}
	if (create_payload) {
		jwt->payload.value.json = json_object();
	}
	return jwt;
}

/*
 * get a header value from a JWT
 */
const char *oidc_jwt_hdr_get(oidc_jwt_t *jwt, const char *key) {
	cjose_err cjose_err;
	cjose_header_t *hdr = cjose_jws_get_protected(jwt->cjose_jws);
	return hdr ? cjose_header_get(hdr, key, &cjose_err) : NULL;
}

/*
 * set a JWT header member to a raw (pre-serialized) JSON value
 */
apr_byte_t oidc_jwt_hdr_set_json(oidc_jwt_t *jwt, const char *key, const char *raw_json, oidc_jose_error_t *err) {
	json_error_t json_error;
	json_t *value = json_loads(raw_json, 0, &json_error);
	if (value == NULL) {
		oidc_jose_error(err, "json_loads failed: %s", json_error.text);
		return FALSE;
	}
	json_object_set_new(jwt->header.value.json, key, value);
	return TRUE;
}

/* base64url-encoded {"alg":"none"} JOSE header */
#define OIDC_JOSE_HDR_ALG_NONE "eyJhbGciOiJub25lIn0"

/*
 * perform compact serialization on a JWT and return the resulting string
 */
char *oidc_jose_jwt_serialize(apr_pool_t *pool, oidc_jwt_t *jwt, oidc_jose_error_t *err) {
	cjose_err cjose_err;
	char *result = NULL;
	const char *s_payload = NULL;
	char *out = NULL;
	size_t out_len;

	if (_oidc_strcmp(jwt->header.alg, CJOSE_HDR_ALG_NONE) == 0) {

		s_payload =
		    oidc_json_encode(pool, jwt->payload.value.json, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT);
		if (s_payload == NULL) {
			oidc_jose_error(err, "oidc_util_encode_json failed");
			return NULL;
		}

		// out is allocated by cjose and must be freed explicitly by cjose_get_dealloc()()
		if (cjose_base64url_encode((const uint8_t *)s_payload, _oidc_strlen(s_payload), &out, &out_len,
					   &cjose_err) == FALSE) {
			oidc_jose_error(err, "cjose_base64url_encode failed: %s", oidc_cjose_e2s(pool, cjose_err));
			return NULL;
		}

		result = apr_pstrmemdup(pool, out, out_len);
		cjose_get_dealloc()(out);
		result = apr_psprintf(pool, "%s.%s.", OIDC_JOSE_HDR_ALG_NONE, result);

	} else {

		// out: "the returned string pointer is owned by the JWS, the caller should not attempt to free it
		// directly"
		if (cjose_jws_export(jwt->cjose_jws, (const char **)&out, &cjose_err) == FALSE) {
			oidc_jose_error(err, "cjose_jws_export failed: %s", oidc_cjose_e2s(pool, cjose_err));
			return NULL;
		}

		result = apr_pstrdup(pool, out);
	}

	return result;
}

/*
 * return the key type for an algorithm
 */
int oidc_alg2kty(const char *alg) {
	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_DIR) == 0)
		return CJOSE_JWK_KTY_OCT;
	if (_oidc_strncmp(alg, "RS", 2) == 0)
		return CJOSE_JWK_KTY_RSA;
	if (_oidc_strncmp(alg, "PS", 2) == 0)
		return CJOSE_JWK_KTY_RSA;
	if (_oidc_strncmp(alg, "HS", 2) == 0)
		return CJOSE_JWK_KTY_OCT;
#if (OIDC_JOSE_EC_SUPPORT)
	if (_oidc_strncmp(alg, "ES", 2) == 0)
		return CJOSE_JWK_KTY_EC;
#endif
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_A128KW) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_A192KW) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_A256KW) == 0))
		return CJOSE_JWK_KTY_OCT;
	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_RSA_OAEP) == 0)
		return CJOSE_JWK_KTY_RSA;
	return -1;
}

/*
 * return the key type of a JWT
 */
int oidc_jwt_alg2kty(const oidc_jwt_t *jwt) {
	return oidc_alg2kty(jwt->header.alg);
}

/*
 * return the key size for an algorithm
 */
unsigned int oidc_alg2keysize(const char *alg) {

	if (alg == NULL)
		return 0;

	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_A128KW) == 0)
		return 16;
	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_A192KW) == 0)
		return 24;
	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_A256KW) == 0)
		return 32;

	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS256) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS256) == 0))
		return 32;
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS384) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS384) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS384) == 0))
		return 48;
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS512) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS512) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS512) == 0))
		return 64;

	return 0;
}

#define OIDC_JOSE_JWT_ISS "iss"
#define OIDC_JOSE_JWT_SUB "sub"
#define OIDC_JOSE_JWT_EXP "exp"
#define OIDC_JOSE_JWT_IAT "iat"

/*
 * parse JWT payload
 */
static apr_byte_t oidc_jose_parse_payload(apr_pool_t *pool, const char *s_payload, size_t s_payload_len,
					  oidc_jwt_payload_t *payload, oidc_jose_error_t *err) {

	/* decode the string in to a JSON structure into value->json */
	json_error_t json_error;
	payload->value.str = apr_pstrndup(pool, s_payload, s_payload_len);
	payload->value.json = json_loads(payload->value.str, 0, &json_error);

	/* check that we've actually got a JSON value back */
	if (payload->value.json == NULL) {
		oidc_jose_error(err, "JSON parsing (json_loads) failed: %s (%s)", json_error.text, payload->value.str);
		return FALSE;
	}

	/* check that the value is a JSON object */
	if (!json_is_object(payload->value.json)) {
		oidc_jose_error(err, "JSON value is not an object");
		return FALSE;
	}

	/* get the (optional) "iss" value from the JSON payload */
	oidc_jose_get_string(pool, payload->value.json, OIDC_JOSE_JWT_ISS, FALSE, &payload->iss, NULL);

	/* get the (optional) "exp" value from the JSON payload */
	oidc_jose_get_timestamp(pool, payload->value.json, OIDC_JOSE_JWT_EXP, FALSE, &payload->exp, NULL);

	/* get the (optional) "iat" value from the JSON payload */
	oidc_jose_get_timestamp(pool, payload->value.json, OIDC_JOSE_JWT_IAT, FALSE, &payload->iat, NULL);

	/* get the (optional) "sub" value from the JSON payload */
	oidc_jose_get_string(pool, payload->value.json, OIDC_JOSE_JWT_SUB, FALSE, &payload->sub, NULL);

	return TRUE;
}

/*
 * parse and (optionally) decrypt a JSON Web Token
 */
apr_byte_t oidc_jwt_parse(apr_pool_t *pool, const char *input_json, oidc_jwt_t **j_jwt, apr_hash_t *keys,
			  apr_byte_t compress, oidc_jose_error_t *err) {

	cjose_err cjose_err;
	char *s_json = NULL;

	if (oidc_jwe_decrypt(pool, input_json, keys, &s_json, NULL, err, FALSE) == FALSE)
		return FALSE;

	*j_jwt = oidc_jwt_new(pool, FALSE, FALSE);
	if (*j_jwt == NULL)
		return FALSE;
	oidc_jwt_t *jwt = *j_jwt;

	jwt->cjose_jws = cjose_jws_import(s_json, _oidc_strlen(s_json), &cjose_err);
	if (jwt->cjose_jws == NULL) {
		oidc_jose_error(err, "cjose_jws_import failed: %s", oidc_cjose_e2s(pool, cjose_err));
		oidc_jwt_destroy(jwt);
		*j_jwt = NULL;
		return FALSE;
	}

	cjose_header_t *hdr = cjose_jws_get_protected(jwt->cjose_jws);
	jwt->header.value.json = json_copy((json_t *)hdr);
	jwt->header.value.str =
	    oidc_json_encode(pool, jwt->header.value.json, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT);

	jwt->header.alg = apr_pstrdup(pool, cjose_header_get(hdr, CJOSE_HDR_ALG, &cjose_err));
	jwt->header.enc = apr_pstrdup(pool, cjose_header_get(hdr, CJOSE_HDR_ENC, &cjose_err));
	jwt->header.kid = apr_pstrdup(pool, cjose_header_get(hdr, CJOSE_HDR_KID, &cjose_err));

	uint8_t *plaintext = NULL;
	size_t plaintext_len = 0;
	if (cjose_jws_get_plaintext(jwt->cjose_jws, &plaintext, &plaintext_len, &cjose_err) == FALSE) {
		oidc_jwt_destroy(jwt);
		*j_jwt = NULL;
		oidc_jose_error(err, "cjose_jws_get_plaintext failed: %s", oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	if (compress == TRUE) {
		char *payload = NULL;
		int payload_len = 0;
		if (oidc_jose_uncompress(pool, (char *)plaintext, (int)plaintext_len, &payload, &payload_len, err) ==
		    FALSE) {
			oidc_jwt_destroy(jwt);
			*j_jwt = NULL;
			return FALSE;
		}
		plaintext = (uint8_t *)payload;
		plaintext_len = payload_len;
	}

	if (oidc_jose_parse_payload(pool, (const char *)plaintext, plaintext_len, &jwt->payload, err) == FALSE) {
		oidc_jwt_destroy(jwt);
		*j_jwt = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * destroy resources allocated for JWT
 */
void oidc_jwt_destroy(oidc_jwt_t *jwt) {
	if (jwt) {
		if (jwt->header.value.json) {
			json_decref(jwt->header.value.json);
			jwt->header.value.json = NULL;
			jwt->header.value.str = NULL;
		}
		if (jwt->payload.value.json) {
			json_decref(jwt->payload.value.json);
			jwt->payload.value.json = NULL;
			jwt->payload.value.str = NULL;
		}
		if (jwt->cjose_jws) {
			cjose_jws_release(jwt->cjose_jws);
			jwt->cjose_jws = NULL;
		}
	}
}

/*
 * sign a JWT
 */
apr_byte_t oidc_jwt_sign(apr_pool_t *pool, oidc_jwt_t *jwt, const oidc_jwk_t *jwk, apr_byte_t compress,
			 oidc_jose_error_t *err) {

	cjose_header_t *hdr = (cjose_header_t *)jwt->header.value.json;

	if (jwt->header.alg)
		oidc_jwt_hdr_set(jwt, CJOSE_HDR_ALG, jwt->header.alg);
	if (jwt->header.kid)
		oidc_jwt_hdr_set(jwt, CJOSE_HDR_KID, jwt->header.kid);
	if (jwt->header.enc)
		oidc_jwt_hdr_set(jwt, CJOSE_HDR_ENC, jwt->header.enc);
	if (jwt->header.x5t)
		oidc_jwt_hdr_set(jwt, OIDC_JOSE_JWK_X5T_STR, jwt->header.x5t);

	if (jwt->cjose_jws)
		cjose_jws_release(jwt->cjose_jws);

	cjose_err cjose_err;
	char *plaintext = oidc_json_encode(pool, jwt->payload.value.json, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT);

	char *s_payload = NULL;
	int payload_len = 0;
	if (compress == TRUE) {
		if (oidc_jose_compress(pool, plaintext, (int)_oidc_strlen(plaintext), &s_payload, &payload_len, err) ==
		    FALSE) {
			return FALSE;
		}
	} else {
		s_payload = plaintext;
		payload_len = (int)_oidc_strlen(plaintext);
		jwt->payload.value.str = plaintext;
	}

	jwt->cjose_jws = cjose_jws_sign(jwk->cjose_jwk, hdr, (const uint8_t *)s_payload, payload_len, &cjose_err);

	if (jwt->cjose_jws == NULL) {
		oidc_jose_error(err, "cjose_jws_sign failed: %s", oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	return TRUE;
}

/*
 * verify the signature of a JWT
 */
/*
 * verify a JWS against a single JWK, reporting failure into err and clearing
 * jwt->cjose_jws when the linked cjose version is known to leave it in an
 * unusable state after a failed verify
 */
static apr_byte_t oidc_jwt_verify_with_key(apr_pool_t *pool, oidc_jwt_t *jwt, const oidc_jwk_t *jwk,
					   oidc_jose_error_t *err) {
	cjose_err cjose_err;
	apr_byte_t rc = cjose_jws_verify(jwt->cjose_jws, jwk->cjose_jwk, &cjose_err);
	if (rc == FALSE) {
		oidc_jose_error(err, "cjose_jws_verify failed: %s", oidc_cjose_e2s(pool, cjose_err));
		if (oidc_jose_version_deprecated(pool))
			jwt->cjose_jws = NULL;
	}
	return rc;
}

/*
 * verify a JWS by iterating over all configured keys with a matching kty
 */
static apr_byte_t oidc_jwt_verify_any(apr_pool_t *pool, oidc_jwt_t *jwt, apr_hash_t *keys, oidc_jose_error_t *err) {
	oidc_jwk_t *jwk = NULL;
	apr_byte_t rc = FALSE;

	for (apr_hash_index_t *hi = apr_hash_first(pool, keys); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, NULL, NULL, (void **)&jwk);
		if (jwk->kty == oidc_jwt_alg2kty(jwt))
			rc = oidc_jwt_verify_with_key(pool, jwt, jwk, err);
		if ((rc == TRUE) || (jwt->cjose_jws == NULL))
			break;
	}

	if (rc == FALSE)
		oidc_jose_error(
		    err, "could not verify signature against any of the (%d) provided keys%s", apr_hash_count(keys),
		    apr_hash_count(keys) > 0
			? ""
			: apr_psprintf(pool,
				       "; you have probably provided no or incorrect keys/key-types for algorithm: %s",
				       jwt->header.alg));

	return rc;
}

apr_byte_t oidc_jwt_verify(apr_pool_t *pool, oidc_jwt_t *jwt, apr_hash_t *keys, oidc_jose_error_t *err) {

	if (jwt->header.kid == NULL)
		return oidc_jwt_verify_any(pool, jwt, keys, err);

	const oidc_jwk_t *jwk = apr_hash_get(keys, jwt->header.kid, APR_HASH_KEY_STRING);
	if (jwk == NULL) {
		oidc_jose_error(err, "could not find key with kid: %s", jwt->header.kid);
		return FALSE;
	}

	/* make sure the key type is compatible with the algorithm, just as the no-kid path does, rather than
	 * relying solely on cjose to reject a mismatch (defense in depth against key/algorithm confusion) */
	if (jwk->kty != oidc_jwt_alg2kty(jwt)) {
		oidc_jose_error(err, "key type of key with kid \"%s\" does not match the JWT \"alg\" header \"%s\"",
				jwt->header.kid, jwt->header.alg);
		return FALSE;
	}

	return oidc_jwt_verify_with_key(pool, jwt, jwk, err);
}
