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
 * JSON Web Encryption (JWE) encryption and decryption
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "jose.h"

#include "jose/internal.h"

#include <cjose/cjose.h>

#include "util/util.h"

/*
 * decrypt a JWE using the key whose kid matches the JWE protected header
 */
static uint8_t *oidc_jwe_decrypt_by_kid(apr_pool_t *pool, cjose_jwe_t *jwe, apr_hash_t *keys, const char *kid,
					const char *alg, size_t *content_len, oidc_jose_error_t *err) {
	cjose_err cjose_err;
	const oidc_jwk_t *jwk = apr_hash_get(keys, kid, APR_HASH_KEY_STRING);

	if (jwk == NULL) {
		oidc_jose_error(err, "could not find key with kid: %s", kid);
		return NULL;
	}

	/* make sure the key type is compatible with the algorithm, just as the no-kid path does, rather than
	 * relying solely on cjose to reject a mismatch (defense in depth against key/algorithm confusion) */
	if (jwk->kty != oidc_alg2kty(alg)) {
		oidc_jose_error(err, "key type of key with kid \"%s\" does not match the JWE \"alg\" header \"%s\"",
				kid, alg);
		return NULL;
	}

	if ((jwk->use != NULL) && (_oidc_strcmp(jwk->use, OIDC_JOSE_JWK_ENC_STR) != 0)) {
		oidc_jose_error(err, "cannot use non-encryption (\"use=enc\") key with kid: %s", kid);
		return NULL;
	}

	uint8_t *decrypted = cjose_jwe_decrypt(jwe, jwk->cjose_jwk, content_len, &cjose_err);
	if (decrypted == NULL)
		oidc_jose_error(err, "encrypted JWT could not be decrypted with kid %s: %s", kid,
				oidc_cjose_e2s(pool, cjose_err));
	return decrypted;
}

/*
 * decrypt a JWE by trying every configured key whose kty/use is compatible
 * with the JWE's algorithm
 */
static uint8_t *oidc_jwe_decrypt_any(apr_pool_t *pool, cjose_jwe_t *jwe, apr_hash_t *keys, const char *alg,
				     size_t *content_len, oidc_jose_error_t *err) {
	cjose_err cjose_err;
	uint8_t *decrypted = NULL;
	oidc_jwk_t *jwk = NULL;
	int n_tried = 0;

	for (apr_hash_index_t *hi = apr_hash_first(pool, keys); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, NULL, NULL, (void **)&jwk);

		if (jwk->kty != oidc_alg2kty(alg))
			continue;
		if ((jwk->use) && (_oidc_strcmp(jwk->use, OIDC_JOSE_JWK_ENC_STR) != 0))
			continue;

		n_tried++;
		decrypted = cjose_jwe_decrypt(jwe, jwk->cjose_jwk, content_len, &cjose_err);
		if (decrypted != NULL)
			return decrypted;
	}

	if (n_tried == 0)
		oidc_jose_error(err,
				"encrypted JWT could not be decrypted: none of the %d configured keys is compatible "
				"with alg \"%s\"",
				apr_hash_count(keys), alg);
	else
		oidc_jose_error(
		    err,
		    "encrypted JWT could not be decrypted with any of the %d compatible keys: error for last "
		    "tried key is: %s",
		    n_tried, oidc_cjose_e2s(pool, cjose_err));
	return NULL;
}

/*
 * decrypt a JWT and return the plaintext
 */
static uint8_t *oidc_jwe_decrypt_impl(apr_pool_t *pool, cjose_jwe_t *jwe, apr_hash_t *keys, size_t *content_len,
				      oidc_jose_error_t *err) {

	cjose_err cjose_err;
	cjose_header_t *hdr = cjose_jwe_get_protected(jwe);
	const char *kid = cjose_header_get(hdr, CJOSE_HDR_KID, &cjose_err);
	const char *alg = cjose_header_get(hdr, CJOSE_HDR_ALG, &cjose_err);

	if ((keys == NULL) || (apr_hash_count(keys) == 0)) {
		oidc_jose_error(err, "no decryption keys configured");
		return NULL;
	}

	if (kid != NULL)
		return oidc_jwe_decrypt_by_kid(pool, jwe, keys, kid, alg, content_len, err);

	return oidc_jwe_decrypt_any(pool, jwe, keys, alg, content_len, err);
}

/*
 * decrypt a JSON Web Token
 */
apr_byte_t oidc_jwe_decrypt(apr_pool_t *pool, const char *input_json, apr_hash_t *keys, char **plaintext,
			    int *plaintext_len, oidc_jose_error_t *err, apr_byte_t import_must_succeed) {
	cjose_err cjose_err;
	cjose_jwe_t *jwe = cjose_jwe_import(input_json, _oidc_strlen(input_json), &cjose_err);
	if (jwe != NULL) {
		size_t content_len = 0;
		uint8_t *decrypted = oidc_jwe_decrypt_impl(pool, jwe, keys, &content_len, err);
		if (decrypted != NULL) {
			*plaintext = apr_pcalloc(pool, content_len + 1);
			_oidc_memcpy(*plaintext, decrypted, content_len);
			(*plaintext)[content_len] = '\0';
			cjose_get_dealloc()(decrypted);
			if (plaintext_len)
				*plaintext_len = (int)content_len;
		}
		cjose_jwe_release(jwe);
	} else if (import_must_succeed == FALSE) {
		*plaintext = apr_pstrdup(pool, input_json);
		if (plaintext_len)
			*plaintext_len = (int)_oidc_strlen(input_json);
	} else {
		oidc_jose_error(err, "cjose_jwe_import failed: %s", oidc_cjose_e2s(pool, cjose_err));
	}
	return (*plaintext != NULL);
}

/*
 * encrypt a JWT
 */
apr_byte_t oidc_jwt_encrypt(apr_pool_t *pool, oidc_jwt_t *jwe, const oidc_jwk_t *jwk, const char *payload,
			    int payload_len, char **serialized, oidc_jose_error_t *err) {

	cjose_header_t *hdr = (cjose_header_t *)jwe->header.value.json;

	if (jwe->header.alg)
		oidc_jwt_hdr_set(jwe, CJOSE_HDR_ALG, jwe->header.alg);
	if (jwe->header.kid)
		oidc_jwt_hdr_set(jwe, CJOSE_HDR_KID, jwe->header.kid);
	if (jwe->header.enc)
		oidc_jwt_hdr_set(jwe, CJOSE_HDR_ENC, jwe->header.enc);
	if (jwe->header.cty)
		oidc_jwt_hdr_set(jwe, CJOSE_HDR_CTY, jwe->header.cty);

	cjose_err cjose_err;
	cjose_jwe_t *cjose_jwe =
	    cjose_jwe_encrypt(jwk->cjose_jwk, hdr, (const uint8_t *)payload, payload_len, &cjose_err);
	if (cjose_jwe == NULL) {
		oidc_jose_error(err, "cjose_jwe_encrypt failed: %s", oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	char *cser = cjose_jwe_export(cjose_jwe, &cjose_err);
	if (cser == NULL) {
		oidc_jose_error(err, "cjose_jwe_export failed: %s", oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	*serialized = apr_pstrdup(pool, cser);
	cjose_get_dealloc()(cser);
	cjose_jwe_release(cjose_jwe);

	return TRUE;
}
