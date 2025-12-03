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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
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

/*
 * return the serialized header part of a A256GCM encrypted JWT (input)
 */
static const char *oidc_util_jwt_hdr_dir_a256gcm(request_rec *r, char *input) {
	char *compact_encoded_jwt = NULL;
	char *p = NULL;
	static const char *_oidc_jwt_hdr_dir_a256gcm = NULL;
	static oidc_crypto_passphrase_t passphrase;

	if (_oidc_jwt_hdr_dir_a256gcm != NULL)
		return _oidc_jwt_hdr_dir_a256gcm;

	if (input == NULL) {
		passphrase.secret1 = "needs_non_empty_string";
		passphrase.secret2 = NULL;
		oidc_util_jwt_create(r, &passphrase, "some_string", &compact_encoded_jwt);
	} else {
		compact_encoded_jwt = input;
	}

	p = _oidc_strstr(compact_encoded_jwt, "..");
	if (p) {
		_oidc_jwt_hdr_dir_a256gcm = apr_pstrndup(r->server->process->pool, compact_encoded_jwt,
							 _oidc_strlen(compact_encoded_jwt) - _oidc_strlen(p) + 2);
		oidc_debug(r, "saved _oidc_jwt_hdr_dir_a256gcm header: %s", _oidc_jwt_hdr_dir_a256gcm);
	}
	return _oidc_jwt_hdr_dir_a256gcm;
}

#define OIDC_JWT_INTERNAL_NO_COMPRESS_ENV_VAR "OIDC_JWT_INTERNAL_NO_COMPRESS"

/*
 * helper function to override a variable value with an optionally provided environment variable
 */
static apr_byte_t oidc_util_env_var_override(request_rec *r, const char *env_var_name, apr_byte_t return_when_set) {
	const char *s = NULL;
	if (r->subprocess_env == NULL)
		return !return_when_set;
	s = apr_table_get(r->subprocess_env, env_var_name);
	return (s != NULL) && (_oidc_strcmp(s, "true") == 0) ? return_when_set : !return_when_set;
}

/*
 * check if we need to compress (internal) encrypted JWTs or not
 */
static apr_byte_t oidc_util_jwt_internal_compress(request_rec *r) {
	// avoid compressing JWTs that need to be compatible with external producers/consumers
	return oidc_util_env_var_override(r, OIDC_JWT_INTERNAL_NO_COMPRESS_ENV_VAR, FALSE);
}

#define OIDC_JWT_INTERNAL_STRIP_HDR_ENV_VAR "OIDC_JWT_INTERNAL_STRIP_HDR"

/*
 * check if we need to strip the header from (internal) encrypted JWTs or not
 */
static apr_byte_t oidc_util_jwt_internal_strip_header(request_rec *r) {
	// avoid stripping JWT headers that need to be compatible with external producers/consumers
	return oidc_util_env_var_override(r, OIDC_JWT_INTERNAL_STRIP_HDR_ENV_VAR, TRUE);
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

	if (oidc_util_key_symmetric_create(r, passphrase->secret1, 0, OIDC_JOSE_ALG_SHA256, FALSE, &jwk) == FALSE)
		goto end;

	if (oidc_util_jwt_internal_compress(r)) {
		if (oidc_jose_compress(r->pool, s_payload, _oidc_strlen(s_payload), &cser, &cser_len, &err) == FALSE) {
			oidc_error(r, "oidc_jose_compress failed: %s", oidc_jose_e2s(r->pool, err));
			goto end;
		}
	} else {
		cser = apr_pstrdup(r->pool, s_payload);
		cser_len = _oidc_strlen(s_payload);
	}

	jwe = oidc_jwt_new(r->pool, TRUE, FALSE);
	if (jwe == NULL) {
		oidc_error(r, "creating JWE failed");
		goto end;
	}

	jwe->header.alg = apr_pstrdup(r->pool, CJOSE_HDR_ALG_DIR);
	jwe->header.enc = apr_pstrdup(r->pool, CJOSE_HDR_ENC_A256GCM);
	if (passphrase->secret2 != NULL)
		jwe->header.kid = apr_pstrdup(r->pool, "1");

	if (oidc_jwt_encrypt(r->pool, jwe, jwk, cser, cser_len, compact_encoded_jwt, &err) == FALSE) {
		oidc_error(r, "encrypting JWT failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	if ((*compact_encoded_jwt != NULL) && (oidc_util_jwt_internal_strip_header(r)))
		*compact_encoded_jwt += _oidc_strlen(oidc_util_jwt_hdr_dir_a256gcm(r, *compact_encoded_jwt));

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

	if (oidc_util_jwt_internal_strip_header(r))
		compact_encoded_jwt =
		    apr_pstrcat(r->pool, oidc_util_jwt_hdr_dir_a256gcm(r, NULL), compact_encoded_jwt, NULL);

	oidc_proto_jwt_header_peek(r, compact_encoded_jwt, &alg, &enc, &kid);
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_DIR) != 0) || (_oidc_strcmp(enc, CJOSE_HDR_ENC_A256GCM) != 0)) {
		oidc_error(r, "corrupted JWE header, alg=\"%s\" enc=\"%s\"", alg, enc);
		goto end;
	}

	keys = apr_hash_make(r->pool);

	if ((passphrase->secret2 != NULL) && (kid == NULL)) {
		if (oidc_util_key_symmetric_create(r, passphrase->secret2, 0, OIDC_JOSE_ALG_SHA256, FALSE, &jwk) ==
		    FALSE)
			goto end;
	} else {
		if (oidc_util_key_symmetric_create(r, passphrase->secret1, 0, OIDC_JOSE_ALG_SHA256, FALSE, &jwk) ==
		    FALSE)
			goto end;
	}
	apr_hash_set(keys, "1", APR_HASH_KEY_STRING, jwk);

	if (oidc_jwe_decrypt(r->pool, compact_encoded_jwt, keys, &plaintext, &plaintext_len, &err, FALSE) == FALSE) {
		oidc_error(r, "decrypting JWE failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	if (oidc_util_jwt_internal_compress(r)) {

		if (oidc_jose_uncompress(r->pool, (char *)plaintext, plaintext_len, &payload, &payload_len, &err) ==
		    FALSE) {
			oidc_error(r, "oidc_jose_uncompress failed: %s", oidc_jose_e2s(r->pool, err));
			goto end;
		}

	} else {

		payload = plaintext;
		payload_len = plaintext_len;
	}

	*s_payload = apr_pstrndup(r->pool, payload, payload_len);

	rv = TRUE;

end:

	if (jwk != NULL)
		oidc_jwk_destroy(jwk);

	return rv;
}
