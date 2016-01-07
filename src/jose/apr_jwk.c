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
 * JSON Web Key handling
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "apr_jose.h"

/*
 * parse an RSA JWK in raw format (n,e,d)
 */
static apr_byte_t apr_jwk_parse_rsa_raw(apr_pool_t *pool, json_t *json,
		apr_jwk_key_rsa_t **jwk_key_rsa, apr_jwt_error_t *err) {

	/* allocate space */
	*jwk_key_rsa = apr_pcalloc(pool, sizeof(apr_jwk_key_rsa_t));
	apr_jwk_key_rsa_t *key = *jwk_key_rsa;

	/* parse the mandatory modulus */
	char *s_modulus = NULL;
	if (apr_jwt_get_string(pool, json, "n", TRUE, &s_modulus, err) == FALSE)
		return FALSE;

	/* base64url decode the modulus and get its size */
	key->modulus_len = apr_jwt_base64url_decode(pool, (char **) &key->modulus,
			s_modulus, 1);
	if (key->modulus_len <= 0) {
		apr_jwt_error(err, "apr_jwt_base64url_decode of modulus failed");
		return FALSE;
	}

	/* parse the mandatory exponent */
	char *s_exponent = NULL;
	if (apr_jwt_get_string(pool, json, "e", TRUE, &s_exponent, err) == FALSE)
		return FALSE;

	/* base64url decode the exponent and get its size */
	key->exponent_len = apr_jwt_base64url_decode(pool, (char **) &key->exponent,
			s_exponent, 1);
	if (key->exponent_len <= 0) {
		apr_jwt_error(err, "apr_jwt_base64url_decode of exponent failed");
		return FALSE;
	}

	/* parse the optional private exponent */
	char *s_private_exponent = NULL;
	apr_jwt_get_string(pool, json, "d", FALSE, &s_private_exponent, NULL);
	if (s_private_exponent != NULL) {
		/* base64url decode the private exponent and get its size */
		key->private_exponent_len = apr_jwt_base64url_decode(pool,
				(char **) &key->private_exponent, s_private_exponent, 1);
		if (key->private_exponent_len <= 0) {
			apr_jwt_error(err,
					"apr_jwt_base64url_decode of private exponent failed");
			return FALSE;
		}
	}

	/* that went well */
	return TRUE;
}

/*
 * convert the RSA public key in the X.509 certificate in the BIO pointed to
 * by "input" to a JSON Web Key object
 */
static apr_byte_t apr_jwk_rsa_bio_to_key(apr_pool_t *pool, BIO *input,
		apr_jwk_key_rsa_t **jwk_key_rsa, int is_private_key,
		apr_jwt_error_t *err) {

	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	apr_byte_t rv = FALSE;

	if (is_private_key) {
		/* get the private key struct from the BIO */
		if ((pkey = PEM_read_bio_PrivateKey(input, NULL, NULL, NULL)) == NULL) {
			apr_jwt_error_openssl(err, "PEM_read_bio_PrivateKey");
			goto end;
		}
	} else {
		/* read the X.509 struct */
		if ((x509 = PEM_read_bio_X509_AUX(input, NULL, NULL, NULL)) == NULL) {
			apr_jwt_error_openssl(err, "PEM_read_bio_X509_AUX");
			goto end;
		}
		/* get the public key struct from the X.509 struct */
		if ((pkey = X509_get_pubkey(x509)) == NULL) {
			apr_jwt_error_openssl(err, "X509_get_pubkey");
			goto end;
		}
	}

	/* allocate space */
	*jwk_key_rsa = apr_pcalloc(pool, sizeof(apr_jwk_key_rsa_t));
	apr_jwk_key_rsa_t *key = *jwk_key_rsa;

	/* get the RSA key from the public key struct */
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		apr_jwt_error_openssl(err, "EVP_PKEY_get1_RSA");
		goto end;
	}

	/* convert the modulus bignum in to a key/len */
	key->modulus_len = BN_num_bytes(rsa->n);
	key->modulus = apr_pcalloc(pool, key->modulus_len);
	BN_bn2bin(rsa->n, key->modulus);

	/* convert the exponent bignum in to a key/len */
	key->exponent_len = BN_num_bytes(rsa->e);
	key->exponent = apr_pcalloc(pool, key->exponent_len);
	BN_bn2bin(rsa->e, key->exponent);

	/* convert the private exponent bignum in to a key/len */
	if (rsa->d != NULL) {
		key->private_exponent_len = BN_num_bytes(rsa->d);
		key->private_exponent = apr_pcalloc(pool, key->private_exponent_len);
		BN_bn2bin(rsa->d, key->private_exponent);
	}

	RSA_free(rsa);

	rv = TRUE;

end:

	if (pkey)
		EVP_PKEY_free(pkey);
	if (x509)
		X509_free(x509);

	return rv;
}

/*
 * parse an RSA JWK in X.509 format (x5c)
 */
static apr_byte_t apr_jwk_parse_rsa_x5c(apr_pool_t *pool, json_t *json,
		apr_jwk_t *jwk, apr_jwt_error_t *err) {

	apr_byte_t rv = FALSE;

	/* get the "x5c" array element from the JSON object */
	json_t *v = json_object_get(json, "x5c");
	if (v == NULL) {
		apr_jwt_error(err, "JSON key \"%s\" could not be found", "x5c");
		return FALSE;
	}
	if (!json_is_array(v)) {
		apr_jwt_error(err,
				"JSON key \"%s\" was found but its value is not a JSON array",
				"x5c");
		return FALSE;
	}

	/* take the first element of the array */
	v = json_array_get(v, 0);
	if (v == NULL) {
		apr_jwt_error(err, "first element in JSON array is \"null\"");
		return FALSE;
	}
	if (!json_is_string(v)) {
		apr_jwt_error(err, "first element in array is not a JSON string");
		return FALSE;
	}

	const char *s_x5c = json_string_value(v);

	/* PEM-format it */
	const int len = 75;
	int i = 0;
	char *s = apr_psprintf(pool, "-----BEGIN CERTIFICATE-----\n");
	while (i < strlen(s_x5c)) {
		s = apr_psprintf(pool, "%s%s\n", s, apr_pstrndup(pool, s_x5c + i, len));
		i += len;
	}
	s = apr_psprintf(pool, "%s-----END CERTIFICATE-----\n", s);

	BIO *input = NULL;

	/* put it in BIO memory */
	if ((input = BIO_new(BIO_s_mem())) == NULL) {
		apr_jwt_error_openssl(err, "memory allocation BIO_new/BIO_s_mem");
		return FALSE;
	}

	if (BIO_puts(input, s) <= 0) {
		BIO_free(input);
		apr_jwt_error_openssl(err, "BIO_puts");
		return FALSE;
	}

	/* do the actual parsing */
	rv = apr_jwk_rsa_bio_to_key(pool, input, &jwk->key.rsa, FALSE, err);

	BIO_free(input);

	return rv;
}

/*
 * parse an RSA JWK
 */
static apr_byte_t apr_jwk_parse_rsa(apr_pool_t *pool, json_t *json,
		apr_jwk_t *jwk, apr_jwt_error_t *err) {

	jwk->type = APR_JWK_KEY_RSA;

	char *s_test = NULL;
	apr_jwt_get_string(pool, json, "n", FALSE, &s_test, NULL);
	if (s_test != NULL)
		return apr_jwk_parse_rsa_raw(pool, json, &jwk->key.rsa, err);

	json_t *v = json_object_get(json, "x5c");
	if (v != NULL)
		return apr_jwk_parse_rsa_x5c(pool, json, jwk, err);

	apr_jwt_error(err,
			"wrong or unsupported RSA key representation, no \"n\" or \"x5c\" key found in JWK JSON value");
	return FALSE;
}

/*
 * parse an EC JWK
 */
static apr_byte_t apr_jwk_parse_ec(apr_pool_t *pool, json_t *json,
		apr_jwk_t *jwk, apr_jwt_error_t *err) {

	/* allocated space and set key type */
	jwk->type = APR_JWK_KEY_EC;
	jwk->key.ec = apr_pcalloc(pool, sizeof(apr_jwk_key_ec_t));

	/* parse x */
	char *s_x = NULL;
	if (apr_jwt_get_string(pool, json, "x", TRUE, &s_x, err) == FALSE)
		return FALSE;

	/* base64url decode x and get its size */
	jwk->key.ec->x_len = apr_jwt_base64url_decode(pool,
			(char **) &jwk->key.ec->x, s_x, 1);
	if (jwk->key.ec->x_len <= 0) {
		apr_jwt_error(err, "apr_jwt_base64url_decode of x length failed");
		return FALSE;
	}

	/* parse y */
	char *s_y = NULL;
	if (apr_jwt_get_string(pool, json, "y", TRUE, &s_y, err) == FALSE)
		return FALSE;

	/* base64url decode y and get its size */
	jwk->key.ec->y_len = apr_jwt_base64url_decode(pool,
			(char **) &jwk->key.ec->y, s_y, 1);
	if (jwk->key.ec->y_len <= 0) {
		apr_jwt_error(err, "apr_jwt_base64url_decode of y length failed");
		return FALSE;
	}

	/* that went well */
	return TRUE;
}

/*
 * parse a an octet sequence used to represent a symmetric key
 */
static apr_byte_t apr_jwk_parse_oct(apr_pool_t *pool, json_t *json,
		apr_jwk_t *jwk, apr_jwt_error_t *err) {

	/* allocated space and set key type */
	jwk->type = APR_JWK_KEY_OCT;
	jwk->key.oct = apr_pcalloc(pool, sizeof(apr_jwk_key_oct_t));

	/* parse k */
	char *s_k = NULL;
	if (apr_jwt_get_string(pool, json, "k", TRUE, &s_k, err) == FALSE)
		return FALSE;

	/* base64url decode k and get its size */
	jwk->key.oct->k_len = apr_jwt_base64url_decode(pool,
			(char **) &jwk->key.oct->k, s_k, 1);
	if (jwk->key.oct->k_len <= 0) {
		apr_jwt_error(err, "apr_jwt_base64url_decode of k length failed");
		return FALSE;
	}

	/* that went well */
	return TRUE;
}

/*
 * calculate a hash and base64url encode the result
 */
static apr_byte_t apr_jwk_hash_and_base64urlencode(apr_pool_t *pool,
		const unsigned char *input, const int input_len, char **output,
		apr_jwt_error_t *err) {

	unsigned int hash_len = SHA_DIGEST_LENGTH;
	unsigned char hash[SHA_DIGEST_LENGTH];

	// TODO: upgrade to SHA2?

	/* hash it */
	if (!SHA1(input, input_len, hash)) {
		apr_jwt_error_openssl(err, "SHA1");
		return FALSE;
	}

	/* base64url encode the key fingerprint */
	if (apr_jwt_base64url_encode(pool, output, (const char *) hash, hash_len, 0)
			<= 0) {
		apr_jwt_error(err, "apr_jwt_base64url_encode of hash failed");
		return FALSE;
	}

	return TRUE;
}

/*
 * parse a symmetric key in to an "oct" JWK
 */
apr_byte_t apr_jwk_parse_symmetric_key(apr_pool_t *pool, const char *kid,
		const unsigned char *key, unsigned int key_len, apr_jwk_t **j_jwk,
		apr_jwt_error_t *err) {

	/* allocate memory for the JWK */
	*j_jwk = apr_pcalloc(pool, sizeof(apr_jwk_t));
	apr_jwk_t *jwk = *j_jwk;

	/* allocated space and set key type */
	jwk->type = APR_JWK_KEY_OCT;
	jwk->key.oct = apr_pcalloc(pool, sizeof(apr_jwk_key_oct_t));

	//	/* set the values */
	jwk->key.oct->k = apr_pcalloc(pool, key_len);
	memcpy(jwk->key.oct->k, key, key_len);
	jwk->key.oct->k_len = key_len;

	if (kid != NULL) {
		jwk->kid = apr_pstrdup(pool, kid);
	} else {
		/* calculate a unique key identifier (kid) by fingerprinting the key params */
		if (apr_jwk_hash_and_base64urlencode(pool, jwk->key.oct->k,
				jwk->key.oct->k_len, &jwk->kid, err) == FALSE)
			return FALSE;
	}

	return TRUE;
}

/*
 * parse JSON JWK
 */
apr_byte_t apr_jwk_parse_json(apr_pool_t *pool, json_t *json, apr_jwk_t **j_jwk,
		apr_jwt_error_t *err) {

	/* check that we've actually got a JSON value back */
	if (json == NULL) {
		apr_jwt_error(err, "JWK JSON is NULL");
		return FALSE;
	}

	/* check that the value is a JSON object */
	if (!json_is_object(json)) {
		apr_jwt_error(err, "JWK JSON is not a JSON object");
		return FALSE;
	}

	/* allocate memory for the JWK */
	*j_jwk = apr_pcalloc(pool, sizeof(apr_jwk_t));
	apr_jwk_t *jwk = *j_jwk;

	/* get the mandatory key type */
	char *kty = NULL;
	if (apr_jwt_get_string(pool, json, "kty", TRUE, &kty, err) == FALSE)
		return FALSE;

	/* get the optional kid */
	apr_jwt_get_string(pool, json, "kid", FALSE, &jwk->kid, NULL);

	/* parse the key */
	if (apr_strnatcmp(kty, "RSA") == 0)
		return apr_jwk_parse_rsa(pool, json, jwk, err);

	if (apr_strnatcmp(kty, "EC") == 0)
		return apr_jwk_parse_ec(pool, json, jwk, err);

	if (apr_strnatcmp(kty, "oct") == 0)
		return apr_jwk_parse_oct(pool, json, jwk, err);

	apr_jwt_error(err,
			"wrong or unsupported JWK key representation \"%s\" (\"RSA\", \"EC\" and \"oct\" are supported key types)",
			kty);

	return FALSE;
}

/*
 * convert RSA key to JWK JSON string representation and kid
 */
apr_byte_t apr_jwk_to_json(apr_pool_t *pool, apr_jwk_t *jwk, char **s_json,
		apr_jwt_error_t *err) {

	if (jwk->type != APR_JWK_KEY_RSA) {
		apr_jwt_error(err, "non RSA keys (%d) not yet supported", jwk->type);
		return FALSE;
	}

	apr_jwk_key_rsa_t *key = jwk->key.rsa;

	unsigned char *n_enc = NULL;
	int n_len = apr_jwt_base64url_encode(pool, (char **) &n_enc,
			(const char *) key->modulus, key->modulus_len, 0);
	if (n_len <= 0) {
		apr_jwt_error(err, "apr_jwt_base64url_encode of modulus failed");
		return FALSE;
	}

	unsigned char *e_enc = NULL;
	if (apr_jwt_base64url_encode(pool, (char **) &e_enc,
			(const char *) key->exponent, key->exponent_len, 0) <= 0) {
		apr_jwt_error(err,
				"apr_jwt_base64url_encode of public exponent failed");
		return FALSE;
	}

	unsigned char *d_enc = NULL;
	if (key->private_exponent_len > 0) {
		if (apr_jwt_base64url_encode(pool, (char **) &d_enc,
				(const char *) key->private_exponent, key->private_exponent_len,
				0) <= 0) {
			apr_jwt_error(err,
					"apr_jwt_base64url_encode of private exponent failed");
			return FALSE;
		}
	}

	char *p = apr_psprintf(pool, "{ \"kty\" : \"RSA\"");
	p = apr_psprintf(pool, "%s, \"n\": \"%s\"", p, n_enc);
	p = apr_psprintf(pool, "%s, \"e\": \"%s\"", p, e_enc);
	if (d_enc != NULL)
		p = apr_psprintf(pool, "%s, \"d\": \"%s\"", p, d_enc);
	p = apr_psprintf(pool, "%s, \"kid\" : \"%s\"", p, jwk->kid);
	p = apr_psprintf(pool, "%s }", p);

	*s_json = p;

	return TRUE;
}

static apr_byte_t apr_jwk_parse_rsa_key(apr_pool_t *pool, int is_private_key,
		const char *kid, const char *filename, apr_jwk_t **j_jwk, apr_jwt_error_t *err) {
	BIO *input = NULL;
	apr_jwk_key_rsa_t *key = NULL;
	apr_byte_t rv = FALSE;

	if ((input = BIO_new(BIO_s_file())) == NULL) {
		apr_jwt_error_openssl(err, "BIO_new/BIO_s_file");
		goto end;
	}

	if (BIO_read_filename(input, filename) <= 0) {
		apr_jwt_error_openssl(err, "BIO_read_filename");
		goto end;
	}

	if (apr_jwk_rsa_bio_to_key(pool, input, &key, is_private_key, err) == FALSE)
		goto end;

	/* allocate memory for the JWK */
	*j_jwk = apr_pcalloc(pool, sizeof(apr_jwk_t));
	apr_jwk_t *jwk = *j_jwk;

	jwk->type = APR_JWK_KEY_RSA;
	jwk->key.rsa = key;

	if (kid != NULL) {
		jwk->kid = apr_pstrdup(pool, kid);
	} else {
		/* calculate a unique key identifier (kid) by fingerprinting the key params */
		// TODO: based just on sha1 hash of modulus "n" now..., could do this based on jwk->value.str
		if (apr_jwk_hash_and_base64urlencode(pool, key->modulus, key->modulus_len,
				&jwk->kid, err) == FALSE)
			goto end;
	}

	rv = TRUE;

end:

	if (input)
		BIO_free(input);

	return rv;
}

apr_byte_t apr_jwk_parse_rsa_private_key(apr_pool_t *pool, const char *filename,
		apr_jwk_t **j_jwk, apr_jwt_error_t *err) {
	return apr_jwk_parse_rsa_key(pool, TRUE, NULL, filename, j_jwk, err);
}

apr_byte_t apr_jwk_parse_rsa_public_key(apr_pool_t *pool, const char *kid, const char *filename,
		apr_jwk_t **j_jwk, apr_jwt_error_t *err) {
	return apr_jwk_parse_rsa_key(pool, FALSE, kid, filename, j_jwk, err);
}
