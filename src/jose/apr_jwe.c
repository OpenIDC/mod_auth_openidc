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
 * Copyright (C) 2013-2015 Ping Identity Corporation
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
 * JSON Web Encryption handling
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

/*
 * return all supported content encryption key algorithms
 */
apr_array_header_t *apr_jwe_supported_algorithms(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 4, sizeof(const char*));
	*(const char**) apr_array_push(result) = "RSA1_5";
	*(const char**) apr_array_push(result) = "A128KW";
	*(const char**) apr_array_push(result) = "A192KW";
	*(const char**) apr_array_push(result) = "A256KW";
	*(const char**) apr_array_push(result) = "RSA-OAEP";
	return result;
}

/*
 * check if the provided content encryption key algorithm is supported
 */
apr_byte_t apr_jwe_algorithm_is_supported(apr_pool_t *pool, const char *alg) {
	return apr_jwt_array_has_string(apr_jwe_supported_algorithms(pool), alg);
}

/*
 * return all supported encryption algorithms
 */
apr_array_header_t *apr_jwe_supported_encryptions(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 5, sizeof(const char*));
	*(const char**) apr_array_push(result) = "A128CBC-HS256";
	*(const char**) apr_array_push(result) = "A192CBC-HS384";
	*(const char**) apr_array_push(result) = "A256CBC-HS512";
#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)
	*(const char**) apr_array_push(result) = "A128GCM";
	*(const char**) apr_array_push(result) = "A192GCM";
	*(const char**) apr_array_push(result) = "A256GCM";
#endif
	return result;
}

/*
 * check if the provided encryption algorithm is supported
 */
apr_byte_t apr_jwe_encryption_is_supported(apr_pool_t *pool, const char *enc) {
	return apr_jwt_array_has_string(apr_jwe_supported_encryptions(pool), enc);
}

/*
 * check if the the JWT is encrypted
 */
apr_byte_t apr_jwe_is_encrypted_jwt(apr_pool_t *pool, apr_jwt_header_t *hdr) {
	return (apr_jwe_algorithm_is_supported(pool, hdr->alg)
			&& (apr_jwe_encryption_is_supported(pool, hdr->enc)));
}

/*
 * return OpenSSL cipher for JWE encryption algorithm
 */
static const EVP_CIPHER *apr_jwe_enc_to_openssl_cipher(const char *enc) {
	if (apr_strnatcmp(enc, "A128CBC-HS256") == 0) {
		return EVP_aes_128_cbc();
	}
	if (apr_strnatcmp(enc, "A192CBC-HS384") == 0) {
		return EVP_aes_192_cbc();
	}
	if (apr_strnatcmp(enc, "A256CBC-HS512") == 0) {
		return EVP_aes_256_cbc();
	}
#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)
	if (apr_strnatcmp(enc, "A128CM") == 0) {
		return EVP_aes_128_gcm();
	}
	if (apr_strnatcmp(enc, "A192GCM") == 0) {
		return EVP_aes_192_gcm();
	}
	if (apr_strnatcmp(enc, "A256GCM") == 0) {
		return EVP_aes_256_gcm();
	}
#endif
	return NULL;
}

/*
 * return OpenSSL hash for JWE encryption algorithm
 */
static const EVP_MD *apr_jwe_enc_to_openssl_hash(const char *enc) {
	if (apr_strnatcmp(enc, "A128CBC-HS256") == 0) {
		return EVP_sha256();
	}
	if (apr_strnatcmp(enc, "A192CBC-HS384") == 0) {
		return EVP_sha384();
	}
	if (apr_strnatcmp(enc, "A256CBC-HS512") == 0) {
		return EVP_sha512();
	}
	return NULL;
}

/*
 * convert a JWK (RSA) key to an OpenSSL RSA key
 */
static RSA* apr_jwe_jwk_to_openssl_rsa_key(apr_jwk_t *jwk) {
	RSA * key = RSA_new();

	BIGNUM * modulus = BN_new();
	BIGNUM * exponent = BN_new();

	BN_bin2bn(jwk->key.rsa->modulus, jwk->key.rsa->modulus_len, modulus);
	BN_bin2bn(jwk->key.rsa->exponent, jwk->key.rsa->exponent_len, exponent);

	BIGNUM * private_exp = NULL;
	/* check if there's a private_exponent component, i.e. this is a private key */
	if (jwk->key.rsa->private_exponent != NULL) {
		private_exp = BN_new();
		BN_bin2bn(jwk->key.rsa->private_exponent,
				jwk->key.rsa->private_exponent_len, private_exp);
	}

	key->n = modulus;
	key->e = exponent;
	/* private_exp is NULL for public keys */
	key->d = private_exp;

	return key;
}

/*
 * pointer to base64url decoded JWT elements
 */
typedef struct apr_jwe_unpacked_t {
	char *value;
	int len;
} apr_jwe_unpacked_t;

/*
 * base64url decode deserialized JWT elements
 */
static apr_array_header_t *apr_jwe_unpacked_base64url_decode(apr_pool_t *pool,
		apr_array_header_t *unpacked) {
	apr_array_header_t *result = apr_array_make(pool, unpacked->nelts,
			sizeof(const char*));
	int i;
	for (i = 0; i < unpacked->nelts; i++) {
		apr_jwe_unpacked_t *elem = apr_pcalloc(pool,
				sizeof(apr_jwe_unpacked_t));
		elem->len = apr_jwt_base64url_decode(pool, &elem->value,
				((const char**) unpacked->elts)[i], 1);
		if (elem->len <= 0)
			continue;
		APR_ARRAY_PUSH(result, apr_jwe_unpacked_t *) = elem;
	}
	return result;
}

/* indexes in to a compact serialized JSON element */
#define APR_JWE_ENCRYPTED_KEY_INDEX         1
#define APR_JWE_INITIALIZATION_VECTOR_INDEX 2
#define APR_JWE_CIPHER_TEXT_INDEX           3
#define APR_JWE_AUTHENTICATION_TAG_INDEX    4

/*
 * decrypt RSA encrypted Content Encryption Key
 */
static apr_byte_t apr_jwe_decrypt_cek_rsa(apr_pool_t *pool, int padding,
		apr_jwt_header_t *header, apr_array_header_t *unpacked_decoded,
		apr_jwk_t *jwk_rsa, unsigned char **cek, int *cek_len,
		apr_jwt_error_t *err) {

	RSA *pkey = apr_jwe_jwk_to_openssl_rsa_key(jwk_rsa);
	if (pkey == NULL) {
		apr_jwt_error(err, "apr_jwe_jwk_to_openssl_rsa_key failed");
		return FALSE;
	}

	/* find and decrypt Content Encryption Key */
	apr_jwe_unpacked_t *encrypted_key =
			((apr_jwe_unpacked_t **) unpacked_decoded->elts)[APR_JWE_ENCRYPTED_KEY_INDEX];
	*cek = apr_pcalloc(pool, RSA_size(pkey));
	*cek_len = RSA_private_decrypt(encrypted_key->len,
			(const unsigned char *) encrypted_key->value, *cek, pkey, padding);
	if (*cek_len <= 0)
		apr_jwt_error_openssl(err, "RSA_private_decrypt");

	/* free allocated resources */
	RSA_free(pkey);

	/* set return value based on decrypt result */
	return (*cek_len > 0);
}

/*
 * decrypt AES wrapped Content Encryption Key with the provided symmetric key
 */
static apr_byte_t apr_jwe_decrypt_cek_oct_aes(apr_pool_t *pool,
		apr_jwt_header_t *header, apr_array_header_t *unpacked_decoded,
		const unsigned char *shared_key, const int shared_key_len,
		unsigned char **cek, int *cek_len, apr_jwt_error_t *err) {

	/* determine key length in bits */
	int key_bits_len = 0;
	if (apr_strnatcmp(header->alg, "A128KW") == 0) key_bits_len = 128;
	if (apr_strnatcmp(header->alg, "A192KW") == 0) key_bits_len = 192;
	if (apr_strnatcmp(header->alg, "A256KW") == 0) key_bits_len = 256;

	if (shared_key_len * 8 < key_bits_len) {
		apr_jwt_error(err,
				"symmetric key length is too short: %d (should be at least %d)",
				shared_key_len * 8, key_bits_len);
		return FALSE;
	}

	/* create the AES decryption key from the shared key */
	AES_KEY akey;
	if (AES_set_decrypt_key((const unsigned char *) shared_key, key_bits_len,
			&akey) < 0) {
		apr_jwt_error_openssl(err, "AES_set_decrypt_key");
		return FALSE;
	}

	/* determine the Content Encryption Key key length based on the content encryption algorithm */
	*cek_len = (apr_strnatcmp(header->enc, "A128CBC-HS256") == 0) ? 32 : 64;

	/* get the encrypted key from the compact serialized JSON representation */
	apr_jwe_unpacked_t *encrypted_key = APR_ARRAY_IDX(unpacked_decoded,
			APR_JWE_ENCRYPTED_KEY_INDEX, apr_jwe_unpacked_t *);

	/* unwrap the AES key */
	*cek = apr_pcalloc(pool, *cek_len);

	int rv = AES_unwrap_key(&akey, (const unsigned char*) NULL, *cek,
			(const unsigned char *) encrypted_key->value, encrypted_key->len);

	if (rv <= 0)
		apr_jwt_error_openssl(err, "AES_unwrap_key");

	/* return success based on the return value of AES_unwrap_key */
	return (rv > 0);
}

/*
 * try to decrypt the Content Encryption key with the specified JWK
 */
static apr_byte_t apr_jwe_decrypt_cek_with_jwk(apr_pool_t *pool,
		apr_jwt_header_t *header, apr_array_header_t *unpacked_decoded,
		apr_jwk_t *jwk, unsigned char **cek, int *cek_len, apr_jwt_error_t *err) {

	apr_byte_t rc = FALSE;

	if (apr_strnatcmp(header->alg, "RSA1_5") == 0) {

		rc = (jwk->type == APR_JWK_KEY_RSA)
				&& apr_jwe_decrypt_cek_rsa(pool, RSA_PKCS1_PADDING, header,
						unpacked_decoded, jwk, cek, cek_len, err);

	} else if ((apr_strnatcmp(header->alg, "A128KW") == 0)
			|| (apr_strnatcmp(header->alg, "A192KW") == 0)
			|| (apr_strnatcmp(header->alg, "A256KW") == 0)) {

		rc = (jwk->type == APR_JWK_KEY_OCT)
				&& apr_jwe_decrypt_cek_oct_aes(pool, header, unpacked_decoded,
						jwk->key.oct->k, jwk->key.oct->k_len, cek, cek_len,
						err);

	} else if (apr_strnatcmp(header->alg, "RSA-OAEP") == 0) {

		rc = (jwk->type == APR_JWK_KEY_RSA)
				&& apr_jwe_decrypt_cek_rsa(pool, RSA_PKCS1_OAEP_PADDING, header,
						unpacked_decoded, jwk, cek, cek_len, err);

	}

	return rc;
}

/*
 * decrypt the Content Encryption Key with one out of a list of keys
 * based on the content key encryption algorithm in the header
 */
static apr_byte_t apr_jwe_decrypt_cek(apr_pool_t *pool,
		apr_jwt_header_t *header, apr_array_header_t *unpacked_decoded,
		apr_hash_t *keys, unsigned char **cek, int *cek_len,
		apr_jwt_error_t *err) {

	apr_byte_t rc = FALSE;

	apr_jwk_t *jwk = NULL;
	apr_hash_index_t *hi;

	if (header->kid != NULL) {

		jwk = apr_hash_get(keys, header->kid,
			APR_HASH_KEY_STRING);
		if (jwk != NULL) {
			rc = apr_jwe_decrypt_cek_with_jwk(pool, header, unpacked_decoded,
					jwk, cek, cek_len, err);
		} else {
			apr_jwt_error(err, "could not find key with kid: %s", header->kid);
			rc = FALSE;
		}

	} else {

		for (hi = apr_hash_first(pool, keys); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, (void **) &jwk);
			rc = apr_jwe_decrypt_cek_with_jwk(pool, header, unpacked_decoded,
					jwk, cek, cek_len, err);
			if (rc == TRUE)
				break;
		}
	}

	return rc;
}

#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)
/*
 * Decrypt AES-GCM content
 */
apr_byte_t apr_jwe_decrypt_content_aesgcm(apr_pool_t *pool,
		apr_jwt_header_t *header, apr_jwe_unpacked_t *cipher_text,
		unsigned char *cek, int cek_len, apr_jwe_unpacked_t *iv, char *aad,
		int aad_len, apr_jwe_unpacked_t *tag, char **decrypted,
		apr_jwt_error_t *err) {

	EVP_CIPHER_CTX *ctx;
	int outlen, rv;

	ctx = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit_ex(ctx, apr_jwe_enc_to_openssl_cipher(header->enc),
			NULL, NULL, NULL)) {
		apr_jwt_error_openssl(err, "EVP_DecryptInit_ex (aes-gcm)");
		return FALSE;
	}

	unsigned char *plaintext = apr_palloc(pool,
			cipher_text->len
			+ EVP_CIPHER_block_size(
					apr_jwe_enc_to_openssl_cipher(header->enc)));

	/* set IV length, omit for 96 bits */
	//EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
	// TODO: check cek_len == ??
	// TODO: check iv->len == 96 bits
	/* specify key and IV */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, cek,
			(unsigned char *) iv->value)) {
		apr_jwt_error_openssl(err, "EVP_DecryptInit_ex (iv)");
		return FALSE;
	}
	/* zero or more calls to specify any AAD */
	if (!EVP_DecryptUpdate(ctx, NULL, &outlen, (unsigned char *) aad,
			aad_len)) {
		apr_jwt_error_openssl(err, "EVP_DecryptUpdate (aad)");
		return FALSE;
	}
	/* decrypt plaintext */
	if (!EVP_DecryptUpdate(ctx, plaintext, &outlen,
			(unsigned char *) cipher_text->value, cipher_text->len)) {
		apr_jwt_error_openssl(err, "EVP_DecryptUpdate (ciphertext)");
		return FALSE;
	}
	/* set expected tag value. */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag->len, tag->value)) {
		apr_jwt_error_openssl(err, "EVP_CIPHER_CTX_ctrl");
		return FALSE;
	}

	/* finalise: note get no output for GCM */
	rv = EVP_DecryptFinal_ex(ctx, plaintext, &outlen);

	EVP_CIPHER_CTX_free(ctx);

	if (rv > 0) {
		*decrypted = (char *) plaintext;
		return TRUE;
	}

	apr_jwt_error_openssl(err, "EVP_DecryptFinal_ex");

	return FALSE;
}
#endif

/*
 * Decrypt A128CBC-HS256, A192CBC-HS384 and A256CBC-HS512 content
 */
apr_byte_t apr_jwe_decrypt_content_aescbc(apr_pool_t *pool,
		apr_jwt_header_t *header, const unsigned char *msg, int msg_len,
		apr_jwe_unpacked_t *cipher_text, unsigned char *cek, int cek_len,
		apr_jwe_unpacked_t *iv, char *aad, int aad_len,
		apr_jwe_unpacked_t *auth_tag, char **decrypted, apr_jwt_error_t *err) {

	/* extract MAC key from CEK: second half of CEK bits */
	unsigned char *mac_key = apr_pcalloc(pool, cek_len / 2);
	memcpy(mac_key, cek, cek_len / 2);
	/* extract encryption key from CEK: first half of CEK bits */
	unsigned char *enc_key = apr_pcalloc(pool, cek_len / 2);
	memcpy(enc_key, cek + cek_len / 2, cek_len / 2);

	/* calculate the Authentication Tag value over AAD + IV + ciphertext + AAD length */
	unsigned int md_len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	if (!HMAC(apr_jwe_enc_to_openssl_hash(header->enc), mac_key, cek_len / 2,
			msg, msg_len, md, &md_len)) {
		apr_jwt_error_openssl(err, "Authentication Tag calculation HMAC");
		return FALSE;
	}
	/* use only the first half of the bits */
	md_len = md_len / 2;

	/* verify the provided Authentication Tag against what we've calculated ourselves */
	if (md_len != auth_tag->len) {
		apr_jwt_error(err,
				"calculated Authentication Tag hash length differs from the length of the Authentication Tag length in the encrypted JWT");
		return FALSE;
	}

	if (apr_jwt_memcmp(md, auth_tag->value, md_len) == FALSE) {
		apr_jwt_error(err,
				"calculated Authentication Tag hash differs from the Authentication Tag in the encrypted JWT");
		return FALSE;
	}

	/* if everything still OK, now AES (128/192/256) decrypt the ciphertext */

	int p_len = cipher_text->len, f_len = 0;
	/* allocate ciphertext length + one block padding for plaintext */
	unsigned char *plaintext = apr_palloc(pool, p_len + AES_BLOCK_SIZE);

	/* initialize decryption context */
	EVP_CIPHER_CTX decrypt_ctx;
	EVP_CIPHER_CTX_init(&decrypt_ctx);
	/* pass the extracted encryption key and Initialization Vector */
	if (!EVP_DecryptInit_ex(&decrypt_ctx,
			apr_jwe_enc_to_openssl_cipher(header->enc), NULL, enc_key,
			(const unsigned char *) iv->value)) {
		apr_jwt_error_openssl(err, "EVP_DecryptInit_ex");
		return FALSE;
	}

	/* decrypt the ciphertext in to the plaintext */
	if (!EVP_DecryptUpdate(&decrypt_ctx, plaintext, &p_len,
			(const unsigned char *) cipher_text->value, cipher_text->len)) {
		apr_jwt_error_openssl(err, "EVP_DecryptUpdate");
		return FALSE;
	}

	/* decrypt the remaining bits/padding */
	if (!EVP_DecryptFinal_ex(&decrypt_ctx, plaintext + p_len, &f_len)) {
		apr_jwt_error_openssl(err, "EVP_DecryptFinal_ex");
		return FALSE;
	}

	plaintext[p_len + f_len] = '\0';
	*decrypted = (char *) plaintext;

	/* cleanup */
	EVP_CIPHER_CTX_cleanup(&decrypt_ctx);

	/* if we got here, all must be fine */
	return TRUE;
}

static unsigned char *apr_jwe_cek_dummy =
		(unsigned char *) "01234567890123456789012345678901";
static int apr_jwe_cek_len_dummy = 32;

/*
 * decrypt encrypted JWT
 */
apr_byte_t apr_jwe_decrypt_jwt(apr_pool_t *pool, apr_jwt_header_t *header,
		apr_array_header_t *unpacked, apr_hash_t *keys, char **decrypted,
		apr_jwt_error_t *err_r) {

	apr_jwt_error_t err_dummy, *err = err_r;
	unsigned char *cek = NULL;
	int cek_len = 0;

	/* base64url decode all elements of the compact serialized JSON representation */
	apr_array_header_t *unpacked_decoded = apr_jwe_unpacked_base64url_decode(
			pool, unpacked);

	/* since this is an encrypted JWT it must have 5 elements */
	if (unpacked_decoded->nelts != 5) {
		apr_jwt_error(err,
				"could not successfully base64url decode 5 elements from encrypted JWT header but only %d",
				unpacked_decoded->nelts);
		return FALSE;
	}

	/* decrypt the Content Encryption Key */
	if (apr_jwe_decrypt_cek(pool, header, unpacked_decoded, keys, &cek,
			&cek_len, err) == FALSE) {
		/* substitute dummy CEK to avoid timing attacks */
		cek = apr_jwe_cek_dummy;
		cek_len = apr_jwe_cek_len_dummy;
		/* save the original error, now in err_r */
		err = &err_dummy;
	}

	/* get the other elements (Initialization Vector, encrypted text and Authentication Tag) from the compact serialized JSON representation */
	apr_jwe_unpacked_t *iv = APR_ARRAY_IDX(unpacked_decoded,
			APR_JWE_INITIALIZATION_VECTOR_INDEX, apr_jwe_unpacked_t *);
	apr_jwe_unpacked_t *cipher_text = APR_ARRAY_IDX(unpacked_decoded,
			APR_JWE_CIPHER_TEXT_INDEX, apr_jwe_unpacked_t *);
	apr_jwe_unpacked_t *auth_tag = APR_ARRAY_IDX(unpacked_decoded,
			APR_JWE_AUTHENTICATION_TAG_INDEX, apr_jwe_unpacked_t *);

	/* determine the Additional Authentication Data: the protected JSON header */
	char *aad = NULL;
	if (apr_jwt_base64url_encode(pool, &aad, (const char *) header->value.str,
			strlen(header->value.str), 0) <= 0) {
		apr_jwt_error(err, "apr_jwt_base64url_encode of JSON header failed");
		return FALSE;
	}
	int aad_len = strlen(aad);

	/* Additional Authentication Data length in # of bits in 64 bit length field */
	uint64_t al = aad_len * 8;

	/* concatenate AAD + IV + ciphertext + AAD length field */
	int msg_len = aad_len + iv->len + cipher_text->len + sizeof(uint64_t);
	const unsigned char *msg = apr_pcalloc(pool, msg_len);
	char *p = (char*) msg;
	memcpy(p, aad, aad_len);
	p += aad_len;
	memcpy(p, iv->value, iv->len);
	p += iv->len;
	memcpy(p, cipher_text->value, cipher_text->len);
	p += cipher_text->len;

	/* check if we are on a big endian or little endian machine */
	int c = 1;
	if (*(char *) &c == 1) {
		// little endian machine: reverse AAD length for big endian representation
		al = (al & 0x00000000FFFFFFFF) << 32 | (al & 0xFFFFFFFF00000000) >> 32;
		al = (al & 0x0000FFFF0000FFFF) << 16 | (al & 0xFFFF0000FFFF0000) >> 16;
		al = (al & 0x00FF00FF00FF00FF) << 8 | (al & 0xFF00FF00FF00FF00) >> 8;
	}
	memcpy(p, &al, sizeof(uint64_t));

	if ((apr_strnatcmp(header->enc, "A128CBC-HS256") == 0)
			|| (apr_strnatcmp(header->enc, "A192CBC-HS384") == 0)
			|| (apr_strnatcmp(header->enc, "A256CBC-HS512") == 0)) {

		return apr_jwe_decrypt_content_aescbc(pool, header, msg, msg_len,
				cipher_text, cek, cek_len, iv, aad, aad_len, auth_tag,
				decrypted, err_r);

#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)

	} else if ((apr_strnatcmp(header->enc, "A128GCM") == 0)
			|| (apr_strnatcmp(header->enc, "A192GCM") == 0)
			|| (apr_strnatcmp(header->enc, "A256GCM") == 0)) {

		return apr_jwe_decrypt_content_aesgcm(pool, header, cipher_text, cek,
				cek_len, iv, aad, aad_len, auth_tag, decrypted, err_r);

#endif

	}

	return FALSE;
}
