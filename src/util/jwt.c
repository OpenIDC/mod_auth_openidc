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

#include "proto/proto.h"
#include "util/util.h"
#include "util/util_cfg.h"

#define OIDC_JWT_INTERNAL_NO_COMPRESS_ENV_VAR "OIDC_JWT_INTERNAL_NO_COMPRESS"

/*
 * helper function to override a variable value with an optionally provided environment variable
 */
static apr_byte_t oidc_util_env_var_override(const request_rec *r, const char *env_var_name,
					     apr_byte_t return_when_set) {
	const char *s = NULL;
	if (r->subprocess_env == NULL)
		return !return_when_set;
	s = apr_table_get(r->subprocess_env, env_var_name);
	return (s != NULL) && (_oidc_strcmp(s, "true") == 0) ? return_when_set : !return_when_set;
}

/*
 * check if we need to compress (internal) encrypted JWTs or not
 */
static apr_byte_t oidc_util_jwt_internal_compress(const request_rec *r) {
	// avoid compressing JWTs that need to be compatible with external producers/consumers
	return oidc_util_env_var_override(r, OIDC_JWT_INTERNAL_NO_COMPRESS_ENV_VAR, FALSE);
}

/*
 * wrap the precomputed PBKDF2-derived key material for a crypto passphrase into a JWK; the
 * expensive stretching itself happens once, at post_config time (see
 * oidc_cfg_crypto_passphrase_derive_keys()), not on every request
 */
static apr_byte_t oidc_util_jwt_key_from_derived(request_rec *r, const unsigned char *derived_key,
						 apr_byte_t derived_key_set, oidc_jwk_t **jwk) {
	oidc_jose_error_t err;
	if (derived_key_set == FALSE) {
		oidc_error(r, "no derived key material available for the configured passphrase");
		return FALSE;
	}
	*jwk = oidc_jwk_create_symmetric_key(r->pool, NULL, derived_key, OIDC_CRYPTO_PASSPHRASE_DERIVED_KEY_LEN, FALSE,
					     &err);
	if (*jwk == NULL) {
		oidc_error(r, "oidc_jwk_create_symmetric_key failed: %s", oidc_jose_e2s(r->pool, err));
		return FALSE;
	}
	return TRUE;
}

/*
 * the protected header member that binds an encrypted cache value to the cache entry it was stored under: the
 * cookies and the cache values are encrypted with the same key, so without it a value read from the cache would
 * be accepted as a (client-cookie) session cookie, and a value moved to another cache entry would be accepted
 * for that entry; the header is authenticated by the A256GCM tag
 */
#define OIDC_UTIL_JWT_HDR_BINDING "ck"

/*
 * create an encrypted JWT for internal purposes, bound to a cache entry when binding is not NULL
 */
static apr_byte_t oidc_util_jwt_create_impl(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
					    const char *s_payload, const char *binding, char **compact_encoded_jwt) {

	apr_byte_t rv = FALSE;
	oidc_jose_error_t err;
	char *cser = NULL;
	int cser_len = 0;

	oidc_jwk_t *jwk = NULL;
	oidc_jwt_t *jwe = NULL;

	if (passphrase->secret1 == NULL) {
		oidc_error(r, "secret is not set");
		goto end;
	}

	if (oidc_util_jwt_key_from_derived(r, passphrase->derived_key1, passphrase->derived_key1_set, &jwk) == FALSE)
		goto end;

	if (oidc_util_jwt_internal_compress(r)) {
		if (oidc_jose_compress(r->pool, s_payload, (int)_oidc_strlen(s_payload), &cser, &cser_len, &err) ==
		    FALSE) {
			oidc_error(r, "oidc_jose_compress failed: %s", oidc_jose_e2s(r->pool, err));
			goto end;
		}
	} else {
		cser = apr_pstrdup(r->pool, s_payload);
		cser_len = (int)_oidc_strlen(s_payload);
	}

	jwe = oidc_jwt_new(r->pool, TRUE, FALSE);
	if (jwe == NULL) {
		oidc_error(r, "creating JWE failed");
		goto end;
	}

	jwe->header.alg = apr_pstrdup(r->pool, OIDC_JOSE_HDR_ALG_DIR);
	jwe->header.enc = apr_pstrdup(r->pool, OIDC_JOSE_HDR_ENC_A256GCM);
	if (passphrase->secret2 != NULL)
		jwe->header.kid = apr_pstrdup(r->pool, "1");
	if (binding != NULL)
		oidc_jwt_hdr_set(jwe, OIDC_UTIL_JWT_HDR_BINDING, binding);

	if (oidc_jwt_encrypt(r->pool, jwe, jwk, cser, cser_len, compact_encoded_jwt, &err) == FALSE) {
		oidc_error(r, "encrypting JWT failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	rv = TRUE;

end:

	if (jwe != NULL)
		oidc_jwt_destroy(jwe);
	if (jwk != NULL)
		oidc_jwk_destroy(jwk);

	return rv;
}

/*
 * create an encrypted JWT for internal purposes (i.e. state cookie or session cookie)
 */
apr_byte_t oidc_util_jwt_create(request_rec *r, const oidc_crypto_passphrase_t *passphrase, const char *s_payload,
				char **compact_encoded_jwt) {
	return oidc_util_jwt_create_impl(r, passphrase, s_payload, NULL, compact_encoded_jwt);
}

/*
 * create an encrypted JWT for a cache value, bound to the cache entry identified by binding
 */
apr_byte_t oidc_util_jwt_create_bound(request_rec *r, const oidc_crypto_passphrase_t *passphrase, const char *s_payload,
				      const char *binding, char **compact_encoded_jwt) {
	return oidc_util_jwt_create_impl(r, passphrase, s_payload, binding, compact_encoded_jwt);
}

/*
 * check the cache entry binding in the (authenticated) protected header: without an expected binding, i.e. for
 * a cookie, there must be none; with one, it must match, or be absent in a value written by an earlier version
 */
static apr_byte_t oidc_util_jwt_binding_check(request_rec *r, const char *s_header, const char *binding) {
	oidc_json_t *header = NULL;
	apr_byte_t rv = FALSE;

	if (oidc_json_decode_object(r, s_header, &header) == FALSE)
		return FALSE;

	const oidc_json_t *j_value = oidc_json_object_get(header, OIDC_UTIL_JWT_HDR_BINDING);
	const char *value = oidc_json_string_value(j_value);
	if (j_value == NULL)
		rv = TRUE;
	else if (binding == NULL)
		oidc_error(r, "refusing an encrypted cache value where a cookie was expected");
	else if ((value != NULL) && (_oidc_strcmp(value, binding) == 0))
		rv = TRUE;
	else
		oidc_error(r, "refusing an encrypted cache value that was stored under another cache entry");

	oidc_json_decref(header);
	return rv;
}

/*
 * verify an encrypted JWT for internal purposes, bound to a cache entry when binding is not NULL
 */
static apr_byte_t oidc_util_jwt_verify_impl(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
					    const char *compact_encoded_jwt, const char *binding, char **s_payload) {

	apr_byte_t rv = FALSE;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	char *payload = NULL;
	int payload_len = 0;
	char *plaintext = NULL;
	int plaintext_len = 0;
	apr_hash_t *keys = NULL;
	char *alg = NULL;
	char *enc = NULL;
	char *kid = NULL;

	const char *s_header = oidc_proto_jwt_header_peek(r, compact_encoded_jwt, &alg, &enc, &kid);
	if ((_oidc_strcmp(alg, OIDC_JOSE_HDR_ALG_DIR) != 0) || (_oidc_strcmp(enc, OIDC_JOSE_HDR_ENC_A256GCM) != 0)) {
		oidc_error(r, "corrupted JWE header, alg=\"%s\" enc=\"%s\"", alg, enc);
		goto end;
	}

	keys = apr_hash_make(r->pool);

	if ((passphrase->secret2 != NULL) && (kid == NULL)) {
		if (oidc_util_jwt_key_from_derived(r, passphrase->derived_key2, passphrase->derived_key2_set, &jwk) ==
		    FALSE)
			goto end;
	} else {
		if (oidc_util_jwt_key_from_derived(r, passphrase->derived_key1, passphrase->derived_key1_set, &jwk) ==
		    FALSE)
			goto end;
	}
	apr_hash_set(keys, "1", APR_HASH_KEY_STRING, jwk);

	/* Require JWE import so a matching header cannot make unauthenticated input pass verification. */
	if (oidc_jwe_decrypt(r->pool, compact_encoded_jwt, keys, &plaintext, &plaintext_len, &err, TRUE) == FALSE) {
		oidc_error(r, "decrypting JWE failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	/* the protected header is authenticated now that decryption succeeded */
	if (oidc_util_jwt_binding_check(r, s_header, binding) == FALSE)
		goto end;

	/* Always detect on read; OIDC_JWT_INTERNAL_NO_COMPRESS controls only future writes. */
	if (oidc_jose_uncompress(r->pool, plaintext, plaintext_len, &payload, &payload_len, &err) == FALSE) {
		oidc_error(r, "oidc_jose_uncompress failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	*s_payload = apr_pstrndup(r->pool, payload, payload_len);

	rv = TRUE;

end:

	if (jwk != NULL)
		oidc_jwk_destroy(jwk);

	return rv;
}

/*
 * verify an encrypted JWT for internal purposes (i.e. state cookie or session cookie), refusing a cache value
 */
apr_byte_t oidc_util_jwt_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
				const char *compact_encoded_jwt, char **s_payload) {
	return oidc_util_jwt_verify_impl(r, passphrase, compact_encoded_jwt, NULL, s_payload);
}

/*
 * verify an encrypted cache value, refusing one that is bound to another cache entry than binding
 */
apr_byte_t oidc_util_jwt_verify_bound(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
				      const char *compact_encoded_jwt, const char *binding, char **s_payload) {
	return oidc_util_jwt_verify_impl(r, passphrase, compact_encoded_jwt, binding, s_payload);
}
