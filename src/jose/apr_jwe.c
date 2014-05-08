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
	/*
	 *(const char**) apr_array_push(result) = "A128KW";
	 *(const char**) apr_array_push(result) = "A256KW";
	 */
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
	/*
	 *(const char**) apr_array_push(result) = "A256CBC-HS512";
	 */
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
 * convert a JWK (RSA) key to an OpenSSL RSA key
 */
static RSA * apr_jwe_jwk_to_openssl_rsa_key(apr_pool_t *pool,
		const char *public_key_jwk) {

	apr_json_value_t *j_jwk = NULL;
	if (apr_json_decode(&j_jwk, public_key_jwk, strlen(public_key_jwk),
			pool) != APR_SUCCESS)
		return NULL;

	if ((j_jwk == NULL) || (j_jwk->type != APR_JSON_OBJECT))
		return NULL;

	apr_jwk_t *jwk = NULL;
	if (apr_jwk_parse_json(pool, j_jwk, public_key_jwk, &jwk) == FALSE)
		return NULL;

	RSA * key = RSA_new();

	BIGNUM * modulus = BN_new();
	BIGNUM * exponent = BN_new();

	BN_bin2bn(jwk->key.rsa->modulus, jwk->key.rsa->modulus_len, modulus);
	BN_bin2bn(jwk->key.rsa->exponent, jwk->key.rsa->exponent_len, exponent);

	BIGNUM * private = NULL;
	if (jwk->key.rsa->private_exponent != NULL) {
	private = BN_new();
		BN_bin2bn(jwk->key.rsa->private_exponent,
				jwk->key.rsa->private_exponent_len, private);
	}

	key->n = modulus;
	key->e = exponent;
	key->d = private;

	return key;
}

/*
 * decrypt encrypted JWT
 */
apr_byte_t apr_jwe_decrypt_jwt(apr_pool_t *pool, apr_jwt_header_t *header,
		apr_array_header_t *unpacked, apr_hash_t *private_keys,
		char **decrypted) {

	if (unpacked->nelts != 5) return FALSE;

	/* extract the encryption key */
	char *encrypted_key = NULL;
	int encrypted_key_len = apr_jwt_base64url_decode(pool, &encrypted_key,
			((const char**) unpacked->elts)[1], 1);
	if (encrypted_key_len < 0)
		return FALSE;

	/* extract the initialization vector */
	char *iv = NULL;
	int iv_len = apr_jwt_base64url_decode(pool, &iv,
			((const char**) unpacked->elts)[2], 1);
	if (iv_len < 0)
		return FALSE;

	/* extract the ciphertext */
	char *ciphertext = NULL;
	int ciphertext_len = apr_jwt_base64url_decode(pool, &ciphertext,
			((const char**) unpacked->elts)[3], 1);
	if (ciphertext_len < 0)
		return FALSE;

	/* extract the authentication tag */
	char *tag = NULL;
	int tag_len = apr_jwt_base64url_decode(pool, &tag,
			((const char**) unpacked->elts)[4], 1);
	if (tag_len < 0)
		return FALSE;

	if (private_keys == NULL)
		return FALSE;

	const char *private_key_jwk = NULL;
	if (private_keys != NULL) {
		if (header->kid != NULL) {
			apr_hash_get(private_keys, header->kid, APR_HASH_KEY_STRING);
		} else {
			apr_hash_index_t *hi = apr_hash_first(NULL, private_keys);
			apr_hash_this(hi, NULL, NULL, (void**) &private_key_jwk);
		}
	}

	if (private_key_jwk == NULL)
		return FALSE;

	RSA *pkey = apr_jwe_jwk_to_openssl_rsa_key(pool, private_key_jwk);
	if (pkey == NULL)
		return FALSE;

	unsigned char *cek = apr_pcalloc(pool, RSA_size(pkey));
	int cek_len = RSA_private_decrypt(encrypted_key_len,
			(const unsigned char *) encrypted_key, cek, pkey,
			RSA_PKCS1_PADDING);
	if (cek_len < 0)
		return FALSE;

	unsigned char *mac_key = apr_pcalloc(pool, cek_len / 2);
	memcpy(mac_key, cek, cek_len / 2);
	unsigned char *enc_key = apr_pcalloc(pool, cek_len / 2);
	memcpy(enc_key, cek + cek_len / 2, cek_len / 2);

	char *aad = NULL;
	apr_jwt_base64url_encode(pool, &aad, (const char *) header->value.str, strlen( header->value.str), 0);
	int aad_len = strlen(aad);
	int64_t al = aad_len * 8;

	int msg_len = aad_len + iv_len + ciphertext_len + sizeof(int64_t);
	const unsigned char *msg = apr_pcalloc(pool, msg_len);
	char *p = (char*)msg;
	memcpy(p, aad, aad_len);
	p += aad_len;
	memcpy(p, iv, iv_len);
	p += iv_len;
	memcpy(p, ciphertext, ciphertext_len);
	p += ciphertext_len;

	int i;
	char *src = (char *)&al;
	// big endian
	for (i=0; i < sizeof(int64_t); ++i) p[sizeof(int64_t)-1-i] = src[i];

	unsigned int md_len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	if (!HMAC(EVP_sha256(), mac_key, cek_len / 2, msg, msg_len, md, &md_len))
			return FALSE;

	/* use only the first half (128) of the 256 bits */
	md_len = md_len / 2;

	if (md_len != tag_len)
		return FALSE;

	if (memcmp(md, tag, md_len) != 0)
		return FALSE;

	EVP_CIPHER_CTX decrypt_ctx;
	EVP_CIPHER_CTX_init(&decrypt_ctx);
	if (!EVP_DecryptInit_ex(&decrypt_ctx, EVP_aes_128_cbc(), NULL, enc_key,
			(const unsigned char *) iv))
		return FALSE;

	int p_len = ciphertext_len, f_len = 0;
	unsigned char *plaintext = apr_palloc(pool, p_len + AES_BLOCK_SIZE);

	if (!EVP_DecryptUpdate(&decrypt_ctx, plaintext, &p_len,
			(const unsigned char *) ciphertext, ciphertext_len))
		return FALSE;

	/* update plaintext with the final remaining bytes */
	if (!EVP_DecryptFinal_ex(&decrypt_ctx, plaintext + p_len, &f_len))
		return FALSE;

	int len = p_len + f_len;
	plaintext[len] = '\0';

	EVP_CIPHER_CTX_cleanup(&decrypt_ctx);
	RSA_free(pkey);

	*decrypted = (char *) plaintext;

	return TRUE;
}
