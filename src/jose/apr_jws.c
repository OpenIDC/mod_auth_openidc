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
 * Copyright (C) 2013-2014 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * JSON Web Signatures handling
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>

#include <apr_base64.h>

#include "apr_jose.h"

// TODO: complete separation
//       a) remove references to OIDC_DEBUG
//       b) remove references to request_rec (use only pool), so no printouts (comparable to apr_json_decode/encode)

#ifndef OIDC_DEBUG
#define OIDC_DEBUG APLOG_DEBUG
#endif

/*
 * return OpenSSL digest for JWK algorithm
 */
static char *apr_jwt_alg_to_openssl_digest(const char *alg) {
	if ((strcmp(alg, "RS256") == 0) || (strcmp(alg, "PS256") == 0)
			|| (strcmp(alg, "HS256") == 0)) {
		return "sha256";
	}
	if ((strcmp(alg, "RS384") == 0) || (strcmp(alg, "PS384") == 0)
			|| (strcmp(alg, "HS384") == 0)) {
		return "sha384";
	}
	if ((strcmp(alg, "RS512") == 0) || (strcmp(alg, "PS512") == 0)
			|| (strcmp(alg, "HS512") == 0)) {
		return "sha512";
	}
	if (strcmp(alg, "NONE") == 0) {
		return "NONE";
	}
	return NULL;
}

/*
 * return an EVP structure for the specified algorithm
 */
static const EVP_MD *apr_jws_crypto_alg_to_evp(request_rec *r, const char *alg) {
	const EVP_MD *result = NULL;

	char *digest = apr_jwt_alg_to_openssl_digest(alg);

	if (digest == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_crypto_alg_to_evp: unsupported OpenSSL algorithm: %s",
				alg);
		return NULL;
	}

	result = EVP_get_digestbyname(digest);

	if (result == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_crypto_alg_to_evp: EVP_get_digestbyname failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	return result;
}

/*
 * verify HMAC signature on JWT
 */
static apr_byte_t apr_jws_verify_hmac(request_rec *r, apr_jwt_t *jwt,
		const char *secret) {

	/* get the OpenSSL digest function */
	const EVP_MD *digest = NULL;
	if ((digest = apr_jws_crypto_alg_to_evp(r, jwt->header.alg)) == NULL)
		return FALSE;

	/* prepare the key */
	unsigned char *key = (unsigned char *) secret;
	int key_len = strlen(secret);

	/* prepare the message */
	unsigned char *msg = (unsigned char *) jwt->message;
	unsigned int msg_len = strlen(jwt->message);

	/* prepare the hash */
	unsigned int md_len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];

	/* apply the HMAC function to the message with the provided key */
	if (!HMAC(digest, key, key_len, msg, msg_len, md, &md_len)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_hmac: HMAC function failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return FALSE;
	}

	/* check that the length of the hash matches what was provided to us in the signature */
	if (md_len != jwt->signature.length) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_hmac: hash length does not match signature length");
		return FALSE;
	}

	/* do a comparison of the provided hash value against calculated hash value */
	if (memcmp(md, jwt->signature.bytes, md_len) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_hmac: HMAC verification failed");
		return FALSE;
	}

	/* all OK if we got to here */
	return TRUE;
}

static int apr_jws_alg_to_rsa_openssl_padding(const char *alg) {
	if ((strcmp(alg, "RS256") == 0) || (strcmp(alg, "RS384") == 0)
			|| (strcmp(alg, "RS512") == 0)) {
		return RSA_PKCS1_PADDING;
	}
	if ((strcmp(alg, "PS256") == 0) || (strcmp(alg, "PS384") == 0)
			|| (strcmp(alg, "PS512") == 0)) {
		return RSA_PKCS1_PSS_PADDING;
	}
	return -1;
}

/*
 * verify HMAC signature on JWT
 */
static apr_byte_t apr_jws_verify_rsa(request_rec *r, apr_jwt_t *jwt,
		apr_jwk_t *jwk) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"apr_jws_verify_rsa: entering (%s)", jwt->header.alg);

	apr_byte_t rc = FALSE;

	/* get the OpenSSL digest function */
	const EVP_MD *digest = NULL;
	if ((digest = apr_jws_crypto_alg_to_evp(r, jwt->header.alg)) == NULL)
		return FALSE;

	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);

	RSA * pubkey = RSA_new();

	BIGNUM * modulus = BN_new();
	BIGNUM * exponent = BN_new();

	BN_bin2bn(jwk->key.rsa->modulus, jwk->key.rsa->modulus_len, modulus);
	BN_bin2bn(jwk->key.rsa->exponent, jwk->key.rsa->exponent_len, exponent);

	pubkey->n = modulus;
	pubkey->e = exponent;

	EVP_PKEY* pRsaKey = EVP_PKEY_new();
	if (!EVP_PKEY_assign_RSA(pRsaKey, pubkey)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_rsa: EVP_PKEY_assign_RSA failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		pRsaKey = NULL;
		goto end;
	}

	ctx.pctx = EVP_PKEY_CTX_new(pRsaKey, NULL);
	if (!EVP_PKEY_verify_init(ctx.pctx)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_rsa: EVP_PKEY_verify_init failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}
	if (!EVP_PKEY_CTX_set_rsa_padding(ctx.pctx,
			apr_jws_alg_to_rsa_openssl_padding(jwt->header.alg))) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_rsa: EVP_PKEY_CTX_set_rsa_padding failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	if (!EVP_VerifyInit_ex(&ctx, digest, NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_rsa: EVP_VerifyInit_ex failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	if (!EVP_VerifyUpdate(&ctx, jwt->message, strlen(jwt->message))) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_rsa: EVP_VerifyUpdate failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	if (!EVP_VerifyFinal(&ctx, (const unsigned char *) jwt->signature.bytes,
			jwt->signature.length, pRsaKey)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify_rsa: EVP_VerifyFinal failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	rc = TRUE;

	end: if (pRsaKey) {
		EVP_PKEY_free(pRsaKey);
	} else if (pubkey) {
		RSA_free(pubkey);
	}
	EVP_MD_CTX_cleanup(&ctx);

	return rc;
}

/*
 * verify the signature on a JWT token
 */
apr_byte_t apr_jws_verify(request_rec *r, apr_jwt_t *jwt, const char *secret,
		apr_jwk_t *jwk) {

	// TODO: probably move to separate validation function
	if (jwt->header.alg == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify: JWT header object did not specify an algorithm");
		return FALSE;
	}

	if (strncmp(jwt->header.alg, "HS", 2) == 0) {

		/* verify the HMAC signature on the JWT */
		if (apr_jws_verify_hmac(r, jwt, secret) == FALSE)
			return FALSE;

	} else if (strncmp(jwt->header.alg, "RS", 2) == 0) {

		/* verify the RSA signature on the JWT */
		if (apr_jws_verify_rsa(r, jwt, jwk) == FALSE)
			return FALSE;

	} else {

		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jws_verify: JWT header contains an unsupported algorithm: %s",
				jwt->header.alg);

		return FALSE;
	}

	return TRUE;
}
