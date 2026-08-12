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
 * create an encrypted JWT for internal purposes (i.e. state cookie, session cookie, or encrypted cache value)
 */
apr_byte_t oidc_util_jwt_create(request_rec *r, const oidc_crypto_passphrase_t *passphrase, const char *s_payload,
				char **compact_encoded_jwt) {

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
 * verify an encrypted JWT for internal purposes
 */
apr_byte_t oidc_util_jwt_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
				const char *compact_encoded_jwt, char **s_payload) {

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

	oidc_proto_jwt_header_peek(r, compact_encoded_jwt, &alg, &enc, &kid);
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

	/* import_must_succeed=TRUE: the header was pinned to dir/A256GCM above, so require a genuine,
	 * GCM-authenticated JWE here. With FALSE, a value that merely carries that header but is not an
	 * importable JWE would be handed back verbatim and reported as verified - a fail-open in a
	 * function named _verify; the caller must never treat unauthenticated input as authenticated. */
	if (oidc_jwe_decrypt(r->pool, compact_encoded_jwt, keys, &plaintext, &plaintext_len, &err, TRUE) == FALSE) {
		oidc_error(r, "decrypting JWE failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	/*
	 * unconditionally, rather than gated on OIDC_JWT_INTERNAL_NO_COMPRESS as the write side is:
	 * that variable says how payloads are written from now on, not how the one in hand was
	 * written. Reading it here meant that setting or clearing it under running traffic made
	 * every existing session unreadable. oidc_jose_uncompress() decides from the payload and
	 * passes an uncompressed one through untouched.
	 */
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
