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
	apr_array_header_t *result = apr_array_make(pool, 3, sizeof(const char*));
	*(const char**) apr_array_push(result) = "RSA1_5";
	*(const char**) apr_array_push(result) = "A128KW";
	*(const char**) apr_array_push(result) = "A256KW";
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
	apr_array_header_t *result = apr_array_make(pool, 3, sizeof(const char*));
	*(const char**) apr_array_push(result) = "A128CBC-HS256";
	*(const char**) apr_array_push(result) = "A256CBC-HS512";
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
	if (apr_strnatcmp(enc, "A256CBC-HS512") == 0) {
		return EVP_aes_256_cbc();
	}
	return NULL;
}

/*
 * return OpenSSL hash for JWE encryption algorithm
 */
static const EVP_MD *apr_jwe_enc_to_openssl_hash(const char *enc) {
	if (apr_strnatcmp(enc, "A128CBC-HS256") == 0) {
		return EVP_sha256();
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

	BIGNUM * private = NULL;
	/* check if there's a private_exponent component, i.e. this is a private key */
	if (jwk->key.rsa->private_exponent != NULL) {
		private = BN_new();
			BN_bin2bn(jwk->key.rsa->private_exponent,
					jwk->key.rsa->private_exponent_len, private);
	}

	key->n = modulus;
	key->e = exponent;
	/* private is NULL for public keys */
	key->d = private;

	return key;
}

/*
 * convert a JSON JWK key to an OpenSSL RSA key
 */
static RSA * apr_jwe_jwk_json_to_openssl_rsa_key(apr_pool_t *pool,
		const char *jwk_json) {

	json_t *j_jwk = NULL;

	json_error_t json_error;
	j_jwk = json_loads(jwk_json, 0, &json_error);

	if (j_jwk == NULL)
		return NULL;

	if ((j_jwk == NULL) || (!json_is_object(j_jwk)))
		return NULL;

	apr_jwk_t *jwk = NULL;
	apr_byte_t rc = apr_jwk_parse_json(pool, j_jwk, jwk_json, &jwk);

	json_decref(j_jwk);

	return (rc == TRUE) ? apr_jwe_jwk_to_openssl_rsa_key(jwk) : NULL;
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
static apr_array_header_t *apr_jwe_unpacked_base64url_decode(apr_pool_t *pool, apr_array_header_t *unpacked) {
	apr_array_header_t *result = apr_array_make(pool, unpacked->nelts, sizeof(const char*));
	int i;
	for (i = 0; i < unpacked->nelts; i++) {
		apr_jwe_unpacked_t *elem = apr_pcalloc(pool, sizeof(apr_jwe_unpacked_t));
		elem->len = apr_jwt_base64url_decode(pool, &elem->value, ((const char**) unpacked->elts)[i], 1);
		if (elem->len <= 0) continue;
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
static apr_byte_t apr_jwe_decrypt_cek_rsa(apr_pool_t *pool, apr_jwt_header_t *header, apr_array_header_t *unpacked_decoded, apr_hash_t *private_keys, unsigned char **cek, int *cek_len) {

	RSA *pkey = NULL;
	const char *private_key_jwk = NULL;
	apr_byte_t rv = FALSE;

	/* need RSA private keys set to decrypt */
	if (private_keys == NULL)
		goto end;

	/*
	 * if there's a key identifier set, try and find the corresponding private
	 * key or else just use the first key in the list of private keys (JWKs)
	 */
	if (header->kid != NULL) {
		private_key_jwk = apr_hash_get(private_keys, header->kid, APR_HASH_KEY_STRING);
	} else {
		apr_hash_index_t *hi = apr_hash_first(NULL, private_keys);
		apr_hash_this(hi, NULL, NULL, (void**) &private_key_jwk);
	}

	/* by now we should really have a private key set */
	if (private_key_jwk == NULL)
		goto end;

	/* convert the private key to an OpenSSL RSA representation */
	if ((pkey = apr_jwe_jwk_json_to_openssl_rsa_key(pool, private_key_jwk)) == NULL)
		goto end;

	/* find and decrypt Content Encryption Key */
	apr_jwe_unpacked_t *encrypted_key = ((apr_jwe_unpacked_t **) unpacked_decoded->elts)[APR_JWE_ENCRYPTED_KEY_INDEX];
	*cek = apr_pcalloc(pool, RSA_size(pkey));
	*cek_len = RSA_private_decrypt(encrypted_key->len,
			(const unsigned char *) encrypted_key->value, *cek, pkey,
			RSA_PKCS1_PADDING);

	/* set return value based on decrypt result */
	rv = (cek_len > 0);

end:
	if (pkey) RSA_free(pkey);

	return rv;
}

/*
 * decrypt AES wrapped Content Encryption Key
 */
static apr_byte_t apr_jwe_cek_aes_unwrap_key(apr_pool_t *pool, apr_jwt_header_t *header, apr_array_header_t *unpacked_decoded, const char *shared_key, unsigned char **cek, int *cek_len) {

	/* sha256 hash the client_secret first */
	unsigned char *hashed_key = NULL;
	unsigned int hashed_key_len = 0;
	apr_jws_hash_bytes(pool, "sha256", (const unsigned char *)shared_key, strlen(shared_key), &hashed_key, &hashed_key_len);

	/* determine key length in bits */
	int key_bits_len = (apr_strnatcmp(header->alg, "A128KW") == 0) ? 128 : 256;
	/* set the hashed secret as the AES decryption key */
	AES_KEY akey;
	AES_set_decrypt_key((const unsigned char *)hashed_key, key_bits_len, &akey);

	/* determine the Content Encryption Key key length based on the content encryption algorithm */
	*cek_len = (apr_strnatcmp(header->enc, "A128CBC-HS256") == 0) ? 32 : 64;

	/* get the encrypted key from the compact serialized JSON representation */
	apr_jwe_unpacked_t *encrypted_key = APR_ARRAY_IDX(unpacked_decoded, APR_JWE_ENCRYPTED_KEY_INDEX, apr_jwe_unpacked_t *);

	/* get the Initialization Vector from the compact serialized JSON representation */
	//apr_jwe_unpacked_t *iv = APR_ARRAY_IDX(unpacked_decoded, APR_JWE_INITIALIZATION_VECTOR_INDEX, apr_jwe_unpacked_t *);
	//ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "iv_len: %d, (should be 16)", iv->len);

	/* unwrap the AES key */
	*cek = apr_pcalloc(pool, *cek_len);
	int rv = AES_unwrap_key(&akey, (const unsigned char*)NULL, *cek, (const unsigned char *)encrypted_key->value, encrypted_key->len);

	/* return success based on the return value of AES_unwrap_key */
	return (rv > 0);
}

static unsigned char *apr_jwe_cek_dummy = (unsigned char *)"01234567890123456789012345678901";
static int apr_jwe_cek_len_dummy = 32;

/*
 * decrypt encrypted JWT
 */
apr_byte_t apr_jwe_decrypt_jwt(apr_pool_t *pool, apr_jwt_header_t *header,
		apr_array_header_t *unpacked, apr_hash_t *private_keys,
		const char *shared_key, char **decrypted) {

	unsigned char *cek = NULL;
	int cek_len = 0;

	/* base64url decode all elements of the compact serialized JSON representation */
	apr_array_header_t *unpacked_decoded = apr_jwe_unpacked_base64url_decode(pool, unpacked);

	/* since this is an encrypted JWT it must have 5 elements */
	if (unpacked_decoded->nelts != 5)
		return FALSE;

	/* decrypt the Content Encryption Key based on the content key encryption algorithm in the header */
	if (apr_strnatcmp(header->alg, "RSA1_5") == 0) {
		if (apr_jwe_decrypt_cek_rsa(pool, header, unpacked_decoded, private_keys,
				&cek, &cek_len) == FALSE) {
			/* substitute dummy CEK to avoid timing attacks */
			cek = apr_jwe_cek_dummy;
			cek_len = apr_jwe_cek_len_dummy;
		}
	} else if ((apr_strnatcmp(header->alg, "A128KW") == 0)
			|| (apr_strnatcmp(header->alg, "A256KW") == 0)) {
		if (apr_jwe_cek_aes_unwrap_key(pool, header, unpacked_decoded,
				shared_key, &cek, &cek_len) == FALSE) {
			/* substitute dummy CEK to avoid timing attacks */
			cek = apr_jwe_cek_dummy;
			cek_len = apr_jwe_cek_len_dummy;
		}
	}

	/* get the other elements (Initialization Vector, encrypted text and Authentication Tag) from the compact serialized JSON representation */
	apr_jwe_unpacked_t *iv = APR_ARRAY_IDX(unpacked_decoded, APR_JWE_INITIALIZATION_VECTOR_INDEX, apr_jwe_unpacked_t *);
	apr_jwe_unpacked_t *cipher_text = APR_ARRAY_IDX(unpacked_decoded, APR_JWE_CIPHER_TEXT_INDEX, apr_jwe_unpacked_t *);
	apr_jwe_unpacked_t *auth_tag = APR_ARRAY_IDX(unpacked_decoded, APR_JWE_AUTHENTICATION_TAG_INDEX, apr_jwe_unpacked_t *);

	/* extract MAC key from CEK: second half of CEK bits */
	unsigned char *mac_key = apr_pcalloc(pool, cek_len / 2);
	memcpy(mac_key, cek, cek_len / 2);
	/* extract encryption key from CEK: first half of CEK bits */
	unsigned char *enc_key = apr_pcalloc(pool, cek_len / 2);
	memcpy(enc_key, cek + cek_len / 2, cek_len / 2);

	/* determine the Additional Authentication Data: the protected JSON header */
	char *aad = NULL;
	apr_jwt_base64url_encode(pool, &aad, (const char *) header->value.str, strlen( header->value.str), 0);
	int aad_len = strlen(aad);

	/* Additional Authentication Data length in # of bits in 64 bit length field */
	uint64_t al = aad_len * 8;

	/* concatenate AAD + IV + ciphertext + AAD length field */
	int msg_len = aad_len + iv->len + cipher_text->len + sizeof(uint64_t);
	const unsigned char *msg = apr_pcalloc(pool, msg_len);
	char *p = (char*)msg;
	memcpy(p, aad, aad_len);
	p += aad_len;
	memcpy(p, iv->value, iv->len);
	p += iv->len;
	memcpy(p, cipher_text->value, cipher_text->len);
	p += cipher_text->len;

	char *src = (char *)&al;
	unsigned int i = 1;
	char *c = (char*)&i;
	if (*c) {
		// little endian machine: reverse AAD length for big endian representation
		for (i=0; i < sizeof(int64_t); ++i) p[sizeof(uint64_t)-1-i] = src[i];
	}
	else
		memcpy(p, &al, sizeof(uint64_t));

//	uint64_t big_endian = htobe64(al);
//	memcpy(p, &big_endian, sizeof(int64_t));

	/* calculate the Authentication Tag value over AAD + IV + ciphertext + AAD length */
	unsigned int md_len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	if (!HMAC(apr_jwe_enc_to_openssl_hash(header->enc), mac_key, cek_len / 2, msg, msg_len, md, &md_len))
			return FALSE;
	/* use only the first half of the bits */
	md_len = md_len / 2;

	/* verify the provided Authentication Tag against what we've calculated ourselves */
	if (md_len != auth_tag->len)
		return FALSE;
	if (memcmp(md, auth_tag->value, md_len) != 0)
		return FALSE;

	/* if everything still OK, now AES (128/256) decrypt the ciphertext */

	int p_len = cipher_text->len, f_len = 0;
	/* allocate ciphertext length + one block padding for plaintext */
	unsigned char *plaintext = apr_palloc(pool, p_len + AES_BLOCK_SIZE);

	/* initialize decryption context */
	EVP_CIPHER_CTX decrypt_ctx;
	EVP_CIPHER_CTX_init(&decrypt_ctx);
	/* pass the extracted encryption key and Initialization Vector */
	if (!EVP_DecryptInit_ex(&decrypt_ctx, apr_jwe_enc_to_openssl_cipher(header->enc), NULL, enc_key,
			(const unsigned char *) iv->value))
		return FALSE;
	/* decrypt the ciphertext in to the plaintext */
	if (!EVP_DecryptUpdate(&decrypt_ctx, plaintext, &p_len,
			(const unsigned char *) cipher_text->value, cipher_text->len))
		return FALSE;
	/* decrypt the remaining bits/padding */
	if (!EVP_DecryptFinal_ex(&decrypt_ctx, plaintext + p_len, &f_len))
		return FALSE;

	plaintext[p_len + f_len] = '\0';
	*decrypted = (char *) plaintext;

	/* cleanup */
	EVP_CIPHER_CTX_cleanup(&decrypt_ctx);

	/* if we got here, all must be fine */
	return TRUE;
}
