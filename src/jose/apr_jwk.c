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
 * JSON Web Signatures handling
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "apr_jose.h"

/*
 * parse an RSA JWK in raw format (n,e,d)
 */
static apr_byte_t apr_jwk_parse_rsa_raw(apr_pool_t *pool, apr_jwt_value_t *jwk,
		apr_jwk_key_rsa_t **jwk_key_rsa) {

	/* allocate space */
	*jwk_key_rsa = apr_pcalloc(pool, sizeof(apr_jwk_key_rsa_t));
	apr_jwk_key_rsa_t *key = *jwk_key_rsa;

	/* parse the modulus */
	char *s_modulus = NULL;
	apr_jwt_get_string(pool, jwk, "n", &s_modulus);
	if (s_modulus == NULL)
		return FALSE;

	/* parse the modulus size */
	key->modulus_len = apr_jwt_base64url_decode(pool, (char **) &key->modulus,
			s_modulus, 1);

	/* parse the exponent */
	char *s_exponent = NULL;
	apr_jwt_get_string(pool, jwk, "e", &s_exponent);
	if (s_exponent == NULL)
		return FALSE;

	/* parse the exponent size */
	key->exponent_len = apr_jwt_base64url_decode(pool, (char **) &key->exponent,
			s_exponent, 1);

	/* parse the private exponent */
	char *s_private_exponent = NULL;
	apr_jwt_get_string(pool, jwk, "d", &s_private_exponent);
	if (s_private_exponent != NULL) {
		/* parse the private exponent size */
		key->private_exponent_len = apr_jwt_base64url_decode(pool,
				(char **) &key->private_exponent, s_private_exponent, 1);
	}

	/* that went well */
	return TRUE;
}

/*
 * convert the RSA public key in the X.509 certificate in the BIO pointed to
 * by "input" to a JSON Web Key object
 */
static apr_byte_t apr_jwk_rsa_bio_to_key(apr_pool_t *pool, BIO *input,
		apr_jwk_key_rsa_t **jwk_key_rsa, int is_private_key) {

	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	apr_byte_t rv = FALSE;

	if (is_private_key) {
		/* get the private key struct from the BIO */
		if ((pkey = PEM_read_bio_PrivateKey(input, NULL, NULL, NULL)) == NULL)
			goto end;
	} else {
		/* read the X.509 struct */
		if ((x509 = PEM_read_bio_X509_AUX(input, NULL, NULL, NULL)) == NULL)
			goto end;
		/* get the public key struct from the X.509 struct */
		if ((pkey = X509_get_pubkey(x509)) == NULL)
			goto end;
	}

	/* allocate space */
	*jwk_key_rsa = apr_pcalloc(pool, sizeof(apr_jwk_key_rsa_t));
	apr_jwk_key_rsa_t *key = *jwk_key_rsa;

	/* get the RSA key from the public key struct */
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL)
		goto end;

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
static apr_byte_t apr_jwk_parse_rsa_x5c(apr_pool_t *pool, apr_jwk_t *jwk) {

	apr_byte_t rv = FALSE;

	/* get the "x5c" array element from the JSON object */
	json_t *v = json_object_get(jwk->value.json, "x5c");
	if ((v == NULL) || (!json_is_array(v)))
		return FALSE;

	/* take the first element of the array */
	v = json_array_get(v, 0);
	if ((v == NULL) || (!json_is_string(v)))
		return FALSE;
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
	if ((input = BIO_new(BIO_s_mem())) == NULL)
		return FALSE;

	if (BIO_puts(input, s) <= 0) {
		BIO_free(input);
		return FALSE;
	}

	/* do the actual parsing */
	rv = apr_jwk_rsa_bio_to_key(pool, input, &jwk->key.rsa, FALSE);

	BIO_free(input);

	return rv;
}

/*
 * parse an RSA JWK
 */
static apr_byte_t apr_jwk_parse_rsa(apr_pool_t *pool, apr_jwk_t *jwk) {

	jwk->type = APR_JWK_KEY_RSA;

	char *s_test = NULL;
	apr_jwt_get_string(pool, &jwk->value, "n", &s_test);
	if (s_test != NULL)
		return apr_jwk_parse_rsa_raw(pool, &jwk->value, &jwk->key.rsa);

	json_t *v = json_object_get(jwk->value.json, "x5c");
	if (v != NULL)
		return apr_jwk_parse_rsa_x5c(pool, jwk);

	return FALSE;
}

/*
 * parse an EC JWK
 */
static apr_byte_t apr_jwk_parse_ec(apr_pool_t *pool, apr_jwk_t *jwk) {

	/* allocated space and set key type */
	jwk->type = APR_JWK_KEY_EC;
	jwk->key.ec = apr_pcalloc(pool, sizeof(apr_jwk_key_ec_t));

	/* parse x */
	char *s_x = NULL;
	apr_jwt_get_string(pool, &jwk->value, "x", &s_x);
	if (s_x == NULL)
		return FALSE;

	/* parse x size */
	jwk->key.ec->x_len = apr_jwt_base64url_decode(pool,
			(char **) &jwk->key.ec->x, s_x, 1);

	/* parse y */
	char *s_y = NULL;
	apr_jwt_get_string(pool, &jwk->value, "y", &s_y);
	if (s_y == NULL)
		return FALSE;

	/* parse y size */
	jwk->key.ec->y_len = apr_jwt_base64url_decode(pool,
			(char **) &jwk->key.ec->y, s_y, 1);

	/* that went well */
	return TRUE;
}

/*
 * parse JSON JWK
 */
apr_byte_t apr_jwk_parse_json(apr_pool_t *pool, json_t *j_json,
		const char *s_json, apr_jwk_t **j_jwk) {

	/* check that we've actually got a JSON value back */
	if (j_json == NULL)
		return FALSE;

	/* check that the value is a JSON object */
	if (!json_is_object(j_json))
		return FALSE;

	/* allocate memory for the JWK */
	*j_jwk = apr_pcalloc(pool, sizeof(apr_jwk_t));
	apr_jwk_t *jwk = *j_jwk;

	/* set the raw JSON/string representations */
	jwk->value.json = j_json;
	jwk->value.str = apr_pstrdup(pool, s_json);

	/* get the key type */
	char *kty = NULL;
	if (apr_jwt_get_string(pool, &jwk->value, "kty", &kty) == FALSE)
		return FALSE;

	/* kty is mandatory */
	if (kty == NULL)
		return FALSE;

	/* parse the key */
	if (apr_strnatcmp(kty, "RSA") == 0)
		return apr_jwk_parse_rsa(pool, jwk);

	if (apr_strnatcmp(kty, "EC") == 0)
		return apr_jwk_parse_ec(pool, jwk);

	return FALSE;
}

/*
 * convert RSA key to JWK JSON string representation and kid
 */
static apr_byte_t apr_jwk_rsa_to_json(apr_pool_t *pool, apr_jwk_key_rsa_t *key,
		char **jwk, char**kid) {

	unsigned char *n_enc = NULL;
	int n_len = apr_jwt_base64url_encode(pool, (char **) &n_enc,
			(const char *) key->modulus, key->modulus_len, 0);

	unsigned char *e_enc = NULL;
	apr_jwt_base64url_encode(pool, (char **) &e_enc,
			(const char *) key->exponent, key->exponent_len, 0);

	unsigned char *d_enc = NULL;
	if (key->private_exponent_len > 0)
		apr_jwt_base64url_encode(pool, (char **) &d_enc,
				(const char *) key->private_exponent, key->private_exponent_len,
				0);

	/* calculate a unique key identifier (kid) by fingerprinting the key params */
	// TODO: based just on sha1 hash of baseurl-encoded "n" now...
	unsigned int fp_len = SHA_DIGEST_LENGTH;
	unsigned char fp[SHA_DIGEST_LENGTH];
	if (!SHA1(n_enc, n_len, fp))
		return FALSE;
	char *fp_enc = NULL;
	if (apr_jwt_base64url_encode(pool, &fp_enc, (const char *) fp, fp_len,
			0) == FALSE)
		return FALSE;

	char *p = apr_psprintf(pool, "{ \"kty\" : \"RSA\"");
	p = apr_psprintf(pool, "%s, \"n\": \"%s\"", p, n_enc);
	p = apr_psprintf(pool, "%s, \"e\": \"%s\"", p, e_enc);
	if (d_enc != NULL)
		p = apr_psprintf(pool, "%s, \"d\": \"%s\"", p, d_enc);
	p = apr_psprintf(pool, "%s, \"kid\" : \"%s\"", p, fp_enc);
	p = apr_psprintf(pool, "%s }", p);

	*jwk = p;
	*kid = fp_enc;

	return TRUE;
}

/*
 * convert PEM formatted public/private key file to JSON string representation
 */
static apr_byte_t apr_jwk_pem_to_json_impl(apr_pool_t *pool,
		const char *filename, char **s_jwk, char**s_kid, int is_private_key) {
	BIO *input = NULL;
	apr_jwk_key_rsa_t *key = NULL;
	apr_byte_t rv = FALSE;

	if ((input = BIO_new(BIO_s_file())) == NULL)
		goto end;

	if (BIO_read_filename(input, filename) <= 0)
		goto end;

	if (apr_jwk_rsa_bio_to_key(pool, input, &key, is_private_key) == FALSE)
		goto end;

	rv = apr_jwk_rsa_to_json(pool, key, s_jwk, s_kid);

end:

	if (input)
		BIO_free(input);

	return rv;
}

/*
 * convert the RSA public key in the X.509 certificate in the file pointed to
 * by "filename" to a JSON Web Key string representation
 */
apr_byte_t apr_jwk_pem_to_json(apr_pool_t *pool, const char *filename,
		char **s_jwk, char**s_kid) {
	return apr_jwk_pem_to_json_impl(pool, filename, s_jwk, s_kid, FALSE);
}

/*
 * convert the RSA private key in the PEM file pointed to by "filename"
 * to a JSON Web Key string representation
 */
apr_byte_t apr_jwk_private_key_to_rsa_jwk(apr_pool_t *pool,
		const char *filename, char **s_jwk, char**s_kid) {
	return apr_jwk_pem_to_json_impl(pool, filename, s_jwk, s_kid, TRUE);
}
