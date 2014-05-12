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

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "apr_jose.h"

/*
 * parse an RSA JWK
 */
static apr_byte_t apr_jwk_parse_rsa(apr_pool_t *pool, apr_jwk_t *jwk) {

	/* allocated space and set key type */
	jwk->type = APR_JWK_KEY_RSA;
	jwk->key.rsa = apr_pcalloc(pool, sizeof(apr_jwk_key_rsa_t));

	/* parse the modulus */
	char *s_modulus = NULL;
	apr_jwt_get_string(pool, &jwk->value, "n", &s_modulus);
	if (s_modulus == NULL)
		return FALSE;

	/* parse the modulus size */
	jwk->key.rsa->modulus_len = apr_jwt_base64url_decode(pool,
			(char **) &jwk->key.rsa->modulus, s_modulus, 1);

	/* parse the exponent */
	char *s_exponent = NULL;
	apr_jwt_get_string(pool, &jwk->value, "e", &s_exponent);
	if (s_exponent == NULL)
		return FALSE;

	/* parse the exponent size */
	jwk->key.rsa->exponent_len = apr_jwt_base64url_decode(pool,
			(char **) &jwk->key.rsa->exponent, s_exponent, 1);

	/* parse the private exponent */
	char *s_private_exponent = NULL;
	apr_jwt_get_string(pool, &jwk->value, "d", &s_private_exponent);
	if (s_private_exponent != NULL) {
		/* parse the private exponent size */
		jwk->key.rsa->private_exponent_len = apr_jwt_base64url_decode(pool,
				(char **) &jwk->key.rsa->private_exponent, s_private_exponent,
				1);
	}

	/* that went well */
	return TRUE;
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
apr_byte_t apr_jwk_parse_json(apr_pool_t *pool, apr_json_value_t *j_json,
		const char *s_json, apr_jwk_t **j_jwk) {

	/* check that we've actually got a JSON value back */
	if (j_json == NULL)
		return FALSE;

	/* check that the value is a JSON object */
	if (j_json->type != APR_JSON_OBJECT)
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
 * parse (JSON) string representation of JWK
 */
apr_byte_t apr_jwk_parse_string(apr_pool_t *pool, const char *s_json,
		apr_jwk_t **j_jwk) {

	apr_json_value_t *j_value = NULL;

	/* decode the string in to a JSON structure */
	if (apr_json_decode(&j_value, s_json, strlen(s_json), pool) != APR_SUCCESS)
		return FALSE;

	return apr_jwk_parse_json(pool, j_value, s_json, j_jwk);
}

/*
 * convert OpenSSL BIGNUM type to base64url-encoded raw bytes value
 */
static apr_byte_t apr_jwk_bignum_base64enc(apr_pool_t *pool, BIGNUM *v,
		unsigned char **v_enc, int *v_len) {
	*v_len = BN_num_bytes(v);
	unsigned char *v_bytes = apr_pcalloc(pool, *v_len);
	BN_bn2bin(v, v_bytes);
	return apr_jwt_base64url_encode(pool, (char **) v_enc,
			(const char *) v_bytes, *v_len, 0);
}

/*
 * convert OpenSSL EVP public/private key to JWK JSON and kid
 */
static apr_byte_t apr_jwk_openssl_evp_pkey_rsa_to_json(apr_pool_t *pool,
		EVP_PKEY *pkey, char **jwk, char**kid) {

	RSA *rsa = EVP_PKEY_get1_RSA(pkey);

	unsigned char *n_enc = NULL;
	int n_len = 0;
	if (apr_jwk_bignum_base64enc(pool, rsa->n, &n_enc, &n_len) == FALSE)
		return FALSE;

	unsigned char *e_enc = NULL;
	int e_len = 0;
	if (apr_jwk_bignum_base64enc(pool, rsa->e, &e_enc, &e_len) == FALSE)
		return FALSE;

	unsigned char *d_enc = NULL;
	int d_len = 0;
	if (rsa->d) {
		if (apr_jwk_bignum_base64enc(pool, rsa->d, &d_enc, &d_len) == FALSE)
			return FALSE;
	}

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
 * convert the RSA public key in the X.509 certificate in the file pointed to
 * by "filename" to a JSON Web Key object
 */
apr_byte_t apr_jwk_x509_to_rsa_jwk(apr_pool_t *pool, const char *filename,
		char **jwk, char**kid) {

	BIO *input = NULL;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;

	apr_byte_t rv = FALSE;

	if ((input = BIO_new(BIO_s_file())) == NULL)
		goto end;
	if (BIO_read_filename(input, filename) <= 0)
		goto end;
	if ((x509 = PEM_read_bio_X509_AUX(input, NULL, NULL, NULL)) == NULL)
		goto end;
	if ((pkey = X509_get_pubkey(x509)) == NULL)
		goto end;

	rv = apr_jwk_openssl_evp_pkey_rsa_to_json(pool, pkey, jwk, kid);

end:

	if (pkey)
		EVP_PKEY_free(pkey);
	if (x509)
		X509_free(x509);
	if (input)
		BIO_free(input);

	return rv;
}

/*
 * convert the RSA private key in the PEM file pointed to by "filename" to a JSON Web Key object
 */
apr_byte_t apr_jwk_private_key_to_rsa_jwk(apr_pool_t *pool,
		const char *filename, char **jwk, char**kid) {

	BIO *input = NULL;
	EVP_PKEY *pkey = NULL;

	apr_byte_t rv = FALSE;

	if ((input = BIO_new(BIO_s_file())) == NULL)
		goto end;
	if (BIO_read_filename(input, filename) <= 0)
		goto end;
	if ((pkey = PEM_read_bio_PrivateKey(input, NULL, NULL, NULL)) == NULL)
		goto end;

	rv = apr_jwk_openssl_evp_pkey_rsa_to_json(pool, pkey, jwk, kid);

end: if (pkey)
		EVP_PKEY_free(pkey);
	if (input)
		BIO_free(input);

	return rv;
}
