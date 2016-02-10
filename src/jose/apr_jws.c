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
 * Copyright (C) 2013-2016 Ping Identity Corporation
 * All rights reserved.
 *
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
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <apr_base64.h>

#include "apr_jose.h"

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

/*
 * return all supported signing algorithms
 */
apr_array_header_t *apr_jws_supported_algorithms(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 12, sizeof(const char*));
	*(const char**) apr_array_push(result) = "RS256";
	*(const char**) apr_array_push(result) = "RS384";
	*(const char**) apr_array_push(result) = "RS512";
	*(const char**) apr_array_push(result) = "PS256";
	*(const char**) apr_array_push(result) = "PS384";
	*(const char**) apr_array_push(result) = "PS512";
	*(const char**) apr_array_push(result) = "HS256";
	*(const char**) apr_array_push(result) = "HS384";
	*(const char**) apr_array_push(result) = "HS512";
#if (APR_JWS_EC_SUPPORT)
	*(const char**) apr_array_push(result) = "ES256";
	*(const char**) apr_array_push(result) = "ES384";
	*(const char**) apr_array_push(result) = "ES512";
#endif
	*(const char**) apr_array_push(result) = "none";
	return result;
}

/*
 * check if the provided signing algorithm is supported
 */
apr_byte_t apr_jws_algorithm_is_supported(apr_pool_t *pool, const char *alg) {
	return apr_jwt_array_has_string(apr_jws_supported_algorithms(pool), alg);
}

/*
 * helper function to determine the type of signature on a JWT
 */
static apr_byte_t apr_jws_signature_starts_with(apr_pool_t *pool,
		const char *alg, const char *match) {
	if (alg == NULL)
		return FALSE;
	return (strncmp(alg, match, strlen(match)) == 0);
}

/*
 * return OpenSSL digest for JWK algorithm
 */
static char *apr_jws_alg_to_openssl_digest(const char *alg) {
	if ((strcmp(alg, "RS256") == 0) || (strcmp(alg, "PS256") == 0)
			|| (strcmp(alg, "HS256") == 0) || (strcmp(alg, "ES256") == 0)) {
		return "sha256";
	}
	if ((strcmp(alg, "RS384") == 0) || (strcmp(alg, "PS384") == 0)
			|| (strcmp(alg, "HS384") == 0) || (strcmp(alg, "ES384") == 0)) {
		return "sha384";
	}
	if ((strcmp(alg, "RS512") == 0) || (strcmp(alg, "PS512") == 0)
			|| (strcmp(alg, "HS512") == 0) || (strcmp(alg, "ES512") == 0)) {
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
const EVP_MD *apr_jws_crypto_alg_to_evp(apr_pool_t *pool, const char *alg,
		apr_jwt_error_t *err) {
	const EVP_MD *result = NULL;

	char *digest = apr_jws_alg_to_openssl_digest(alg);
	if (digest == NULL) {
		apr_jwt_error(err,
				"no OpenSSL digest algorithm name found for algorithm \"%s\"",
				alg);
		return NULL;
	}

	result = EVP_get_digestbyname(digest);
	if (result == NULL) {
		apr_jwt_error(err,
				"no OpenSSL digest algorithm found for algorithm \"%s\"",
				digest);
		return NULL;
	}

	return result;
}

/*
 * verify HMAC signature on JWT
 */
static apr_byte_t apr_jws_verify_hmac(apr_pool_t *pool, apr_jwt_t *jwt,
		apr_jwk_t *jwk, apr_jwt_error_t *err) {

	if (jwk->type != APR_JWK_KEY_OCT) {
		apr_jwt_error(err,
				"key type of provided JWK cannot be used for HMAC verification: %d",
				jwk->type);
		return FALSE;
	}

	/* get the OpenSSL digest function */
	const EVP_MD *digest = NULL;
	if ((digest = apr_jws_crypto_alg_to_evp(pool, jwt->header.alg, err)) == NULL)
		return FALSE;

	/* prepare the message */
	unsigned char *msg = (unsigned char *) jwt->message;
	unsigned int msg_len = strlen(jwt->message);

	/* prepare the hash */
	unsigned int md_len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];

	/* apply the HMAC function to the message with the provided key */
	if (!HMAC(digest, jwk->key.oct->k, jwk->key.oct->k_len, msg, msg_len, md,
			&md_len)) {
		apr_jwt_error_openssl(err, "HMAC");
		return FALSE;
	}

	/* check that the length of the hash matches what was provided to us in the signature */
	if (md_len != jwt->signature.length) {
		apr_jwt_error(err,
				"calculated hash length (%d) differs from the length of the signature provided in the JWT (%d)", md_len, jwt->signature.length);
		return FALSE;
	}

	/* do a comparison of the provided hash value against calculated hash value */
	if (apr_jwt_memcmp(md, jwt->signature.bytes, md_len) == FALSE) {
		apr_jwt_error(err,
				"calculated hash differs from the signature provided in the JWT");
		return FALSE;
	}

	/* all OK if we got to here */
	return TRUE;
}

/*
 * hash a byte sequence with the specified algorithm
 */
apr_byte_t apr_jws_hash_bytes(apr_pool_t *pool, const char *s_digest,
		const unsigned char *input, unsigned int input_len,
		unsigned char **output, unsigned int *output_len, apr_jwt_error_t *err) {
	unsigned char md_value[EVP_MAX_MD_SIZE];

	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);

	const EVP_MD *evp_digest = NULL;
	if ((evp_digest = EVP_get_digestbyname(s_digest)) == NULL) {
		apr_jwt_error(err,
				"no OpenSSL digest algorithm found for algorithm \"%s\"",
				s_digest);
		return FALSE;
	}

	if (!EVP_DigestInit_ex(&ctx, evp_digest, NULL)) {
		apr_jwt_error_openssl(err, "EVP_DigestInit_ex");
		return FALSE;
	}
	if (!EVP_DigestUpdate(&ctx, input, input_len)) {
		apr_jwt_error_openssl(err, "EVP_DigestUpdate");
		return FALSE;
	}
	if (!EVP_DigestFinal_ex(&ctx, md_value, output_len)) {
		apr_jwt_error_openssl(err, "EVP_DigestFinal_ex");
		return FALSE;
	}

	EVP_MD_CTX_cleanup(&ctx);

	*output = apr_pcalloc(pool, *output_len);
	memcpy(*output, md_value, *output_len);

	return TRUE;
}

/*
 * hash a string value with the specified algorithm
 */
apr_byte_t apr_jws_hash_string(apr_pool_t *pool, const char *alg,
		const char *msg, char **hash, unsigned int *hash_len,
		apr_jwt_error_t *err) {

	char *s_digest = apr_jws_alg_to_openssl_digest(alg);
	if (s_digest == NULL) {
		apr_jwt_error(err,
				"no OpenSSL digest algorithm name found for algorithm \"%s\"",
				alg);
		return FALSE;
	}

	return apr_jws_hash_bytes(pool, s_digest, (const unsigned char *) msg,
			strlen(msg), (unsigned char **) hash, hash_len, err);
}

/*
 * return hash length
 */
int apr_jws_hash_length(const char *alg) {
	if ((strcmp(alg, "RS256") == 0) || (strcmp(alg, "PS256") == 0)
			|| (strcmp(alg, "HS256") == 0) || (strcmp(alg, "ES256") == 0)) {
		return 32;
	}
	if ((strcmp(alg, "RS384") == 0) || (strcmp(alg, "PS384") == 0)
			|| (strcmp(alg, "HS384") == 0) || (strcmp(alg, "ES384") == 0)) {
		return 48;
	}
	if ((strcmp(alg, "RS512") == 0) || (strcmp(alg, "PS512") == 0)
			|| (strcmp(alg, "HS512") == 0) || (strcmp(alg, "ES512") == 0)) {
		return 64;
	}
	return 0;
}

/*
 * verify HMAC signature on JWT
 */
static apr_byte_t apr_jws_verify_rsa(apr_pool_t *pool, apr_jwt_t *jwt,
		apr_jwk_t *jwk, apr_jwt_error_t *err) {

	apr_byte_t rc = FALSE;

	/* get the OpenSSL digest function */
	const EVP_MD *digest = NULL;
	if ((digest = apr_jws_crypto_alg_to_evp(pool, jwt->header.alg, err)) == NULL)
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
		pRsaKey = NULL;
		apr_jwt_error_openssl(err, "EVP_PKEY_assign_RSA");
		goto end;
	}

	if (apr_jws_signature_starts_with(pool, jwt->header.alg, "PS") == TRUE) {

		int status = 0;
		unsigned char *pDecrypted = apr_pcalloc(pool, jwt->signature.length);
		status = RSA_public_decrypt(jwt->signature.length, jwt->signature.bytes,
				pDecrypted, pubkey, RSA_NO_PADDING);
		if (status == -1) {
			apr_jwt_error_openssl(err, "RSA_public_decrypt");
			goto end;
		}

		unsigned char *pDigest = apr_pcalloc(pool, RSA_size(pubkey));
		unsigned int uDigestLen = RSA_size(pubkey);

		if (!EVP_DigestInit(&ctx, digest)) {
			apr_jwt_error_openssl(err, "EVP_DigestInit");
			goto end;
		}
		if (!EVP_DigestUpdate(&ctx, jwt->message, strlen(jwt->message))) {
			apr_jwt_error_openssl(err, "EVP_DigestUpdate");
			goto end;
		}
		if (!EVP_DigestFinal(&ctx, pDigest, &uDigestLen)) {
			apr_jwt_error_openssl(err, "wrong key? EVP_DigestFinal");
			goto end;
		}

		/* verify the data */
		status = RSA_verify_PKCS1_PSS(pubkey, pDigest, digest, pDecrypted,
				-2 /* salt length recovered from signature*/);
		if (status != 1) {
			apr_jwt_error_openssl(err, "RSA_verify_PKCS1_PSS");
			goto end;
		}

		rc = TRUE;

	} else if (apr_jws_signature_starts_with(pool, jwt->header.alg,
			"RS") == TRUE) {

		if (!EVP_VerifyInit_ex(&ctx, digest, NULL)) {
			apr_jwt_error_openssl(err, "EVP_VerifyInit_ex");
			goto end;
		}
		if (!EVP_VerifyUpdate(&ctx, jwt->message, strlen(jwt->message))) {
			apr_jwt_error_openssl(err, "EVP_VerifyUpdate");
			goto end;
		}
		if (!EVP_VerifyFinal(&ctx, (const unsigned char *) jwt->signature.bytes,
				jwt->signature.length, pRsaKey)) {
			apr_jwt_error_openssl(err, "wrong key? EVP_VerifyFinal");
			goto end;
		}

		rc = TRUE;

	}

end:

	if (pRsaKey) {
		EVP_PKEY_free(pRsaKey);
	} else if (pubkey) {
		RSA_free(pubkey);
	}
	EVP_MD_CTX_cleanup(&ctx);

	return rc;
}

#if (APR_JWS_EC_SUPPORT)

/*
 * return the OpenSSL Elliptic Curve NID for a JWT algorithm
 */
static int apr_jws_ec_alg_to_curve(const char *alg) {
	if (strcmp(alg, "ES256") == 0)
		return NID_X9_62_prime256v1;
	if (strcmp(alg, "ES384") == 0)
		return NID_secp384r1;
	if (strcmp(alg, "ES512") == 0)
		return NID_secp521r1;
	return -1;
}

/*
 * verify EC signature on JWT
 */
static apr_byte_t apr_jws_verify_ec(apr_pool_t *pool, apr_jwt_t *jwt,
		apr_jwk_t *jwk, apr_jwt_error_t *err) {

	int nid = apr_jws_ec_alg_to_curve(jwt->header.alg);
	if (nid == -1) {
		apr_jwt_error(err,
				"no OpenSSL Elliptic Curve identifier found for algorithm \"%s\"",
				jwt->header.alg);
		return FALSE;
	}

	EC_GROUP *curve = EC_GROUP_new_by_curve_name(nid);
	if (curve == NULL) {
		apr_jwt_error(err,
				"no OpenSSL Elliptic Curve found for algorithm \"%s\"",
				jwt->header.alg);
		return FALSE;
	}

	apr_byte_t rc = FALSE;

	/* get the OpenSSL digest function */
	const EVP_MD *digest = NULL;
	if ((digest = apr_jws_crypto_alg_to_evp(pool, jwt->header.alg, err)) == NULL)
		return FALSE;

	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);

	EC_KEY * pubkey = EC_KEY_new();
	EC_KEY_set_group(pubkey, curve);

	BIGNUM * x = BN_new();
	BIGNUM * y = BN_new();

	BN_bin2bn(jwk->key.ec->x, jwk->key.ec->x_len, x);
	BN_bin2bn(jwk->key.ec->y, jwk->key.ec->y_len, y);

	if (!EC_KEY_set_public_key_affine_coordinates(pubkey, x, y)) {
		apr_jwt_error_openssl(err, "EC_KEY_set_public_key_affine_coordinates");
		return FALSE;
	}

	EVP_PKEY* pEcKey = EVP_PKEY_new();
	if (!EVP_PKEY_assign_EC_KEY(pEcKey, pubkey)) {
		pEcKey = NULL;
		apr_jwt_error_openssl(err, "EVP_PKEY_assign_EC_KEY");
		goto end;
	}

	ctx.pctx = EVP_PKEY_CTX_new(pEcKey, NULL);

	if (!EVP_PKEY_verify_init(ctx.pctx)) {
		apr_jwt_error_openssl(err, "EVP_PKEY_verify_init");
		goto end;
	}
	if (!EVP_VerifyInit_ex(&ctx, digest, NULL)) {
		apr_jwt_error_openssl(err, "EVP_VerifyInit_ex");
		goto end;
	}
	if (!EVP_VerifyUpdate(&ctx, jwt->message, strlen(jwt->message))) {
		apr_jwt_error_openssl(err, "EVP_VerifyUpdate");
		goto end;
	}
	if (!EVP_VerifyFinal(&ctx, (const unsigned char *) jwt->signature.bytes,
			jwt->signature.length, pEcKey)) {
		apr_jwt_error_openssl(err, "wrong key? EVP_VerifyFinal");
		goto end;
	}

	rc = TRUE;

end:

	if (pEcKey) {
		EVP_PKEY_free(pEcKey);
	} else if (pubkey) {
		EC_KEY_free(pubkey);
	}
	EVP_MD_CTX_cleanup(&ctx);

	return rc;
}

#endif

/*
 * check if the signature on the JWT is HMAC-based
 */
apr_byte_t apr_jws_signature_is_hmac(apr_pool_t *pool, apr_jwt_t *jwt) {
	return apr_jws_signature_starts_with(pool, jwt->header.alg, "HS");
}

/*
 * check if the signature on the JWT is RSA-based
 */
apr_byte_t apr_jws_signature_is_rsa(apr_pool_t *pool, apr_jwt_t *jwt) {
	return apr_jws_signature_starts_with(pool, jwt->header.alg, "RS")
			|| apr_jws_signature_starts_with(pool, jwt->header.alg, "PS");
}

#if (APR_JWS_EC_SUPPORT)

/*
 * check if the signature on the JWT is Elliptic Curve based
 */
apr_byte_t apr_jws_signature_is_ec(apr_pool_t *pool, apr_jwt_t *jwt) {
	return apr_jws_signature_starts_with(pool, jwt->header.alg, "ES");
}

#endif

/*
 * check the signature on a JWT against the provided keys
 */
static apr_byte_t apr_jws_verify_with_jwk(apr_pool_t *pool, apr_jwt_t *jwt,
		apr_jwk_t *jwk, apr_jwt_error_t *err) {

	apr_byte_t rc = FALSE;

	if (apr_jws_signature_is_hmac(pool, jwt)) {

		rc = (jwk->type == APR_JWK_KEY_OCT)
				&& apr_jws_verify_hmac(pool, jwt, jwk, err);

	} else if (apr_jws_signature_is_rsa(pool, jwt)) {

		rc = (jwk->type == APR_JWK_KEY_RSA)
				&& apr_jws_verify_rsa(pool, jwt, jwk, err);

#if (APR_JWS_EC_SUPPORT)
	} else if (apr_jws_signature_is_ec(pool, jwt)) {

		rc = (jwk->type == APR_JWK_KEY_EC)
				&& apr_jws_verify_ec(pool, jwt, jwk, err);

#endif
	}

	return rc;
}

/*
 * verify the signature on a JWT
 */
apr_byte_t apr_jws_verify(apr_pool_t *pool, apr_jwt_t *jwt, apr_hash_t *keys,
		apr_jwt_error_t *err) {
	apr_byte_t rc = FALSE;

	apr_jwk_t *jwk = NULL;
	apr_hash_index_t *hi;

	if (jwt->header.kid != NULL) {

		jwk = apr_hash_get(keys, jwt->header.kid,
				APR_HASH_KEY_STRING);
		if (jwk != NULL) {
			rc = apr_jws_verify_with_jwk(pool, jwt, jwk, err);
		} else {
			apr_jwt_error(err, "could not find key with kid: %s",
					jwt->header.kid);
			rc = FALSE;
		}

	} else {

		for (hi = apr_hash_first(pool, keys); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, (void **) &jwk);
			rc = apr_jws_verify_with_jwk(pool, jwt, jwk, err);
			if (rc == TRUE)
				break;
		}

		if (rc == FALSE)
			apr_jwt_error(err,
					"could not verify signature against any of the (%d) provided keys%s",
					apr_hash_count(keys),
					apr_hash_count(keys) > 0 ?
							"" :
							apr_psprintf(pool,
									"; you have probably provided no or incorrect keys/key-types for algorithm: %s",
									jwt->header.alg));
	}

	return rc;
}
