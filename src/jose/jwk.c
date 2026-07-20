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
 * JSON Web Key (JWK) parsing, serialization and PEM/X.509 conversion
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "jose.h"

#include "jose/internal.h"

#include <jansson.h>

#include <cjose/cjose.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "util/util.h"

/*
 * extract a b64 encoded certificate representation as a single string
 */
static int oidc_jose_util_get_b64encoded_certificate_data(apr_pool_t *p, const X509 *x509_cert,
							  char **b64_encoded_certificate, oidc_jose_error_t *err) {
	int rc = 0;
	char *name = NULL;
	char *header = NULL;
	long len = 0;
	long b64_len = 0;
	BIO *bio = NULL;
	unsigned char *data = NULL;

	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		oidc_jose_error_openssl(err, "BIO_new");
		goto end;
	}

	if (!PEM_write_bio_X509(bio, (X509 *)x509_cert)) {
		oidc_jose_error_openssl(err, "PEM_write_bio_X509");
		goto end;
	}
	if (!PEM_read_bio(bio, &name, &header, &data, &len)) {
		oidc_jose_error_openssl(err, "PEM_read_bio");
		goto end;
	}

	/* "For every 3 bytes of input provided 4 bytes of output data will be produced." */
	b64_len = (((len + 2) / 3) * 4) + 1;

	*b64_encoded_certificate = (char *)apr_pcalloc(p, b64_len);
	if (!*b64_encoded_certificate) {
		oidc_jose_error_openssl(err, "apr_pcalloc");
		goto end;
	}

	rc = EVP_EncodeBlock((unsigned char *)*b64_encoded_certificate, data, (int)len);

end:
	if (bio) {
		BIO_free(bio);
	}
	if (name != NULL) {
		OPENSSL_free(name);
	}
	if (data != NULL) {
		OPENSSL_free(data);
	}
	if (header != NULL) {
		OPENSSL_free(header);
	}

	return rc;
}

/*
 * create a new JWK
 */
static oidc_jwk_t *oidc_jwk_new(apr_pool_t *pool) {
	oidc_jwk_t *jwk = apr_pcalloc(pool, sizeof(oidc_jwk_t));
	return jwk;
}

static apr_byte_t _oidc_jwk_parse_x5c(apr_pool_t *pool, const json_t *json, cjose_jwk_t **jwk, oidc_jose_error_t *err);

#define OIDC_JOSE_HDR_KTY "kty"
#define OIDC_JOSE_HDR_KTY_RSA "RSA"
#define OIDC_JOSE_HDR_KTY_EC "EC"
#define OIDC_JOSE_HDR_X5C "x5c"

/*
 * parse a JSON object with an "x5c" JWK representation into a cjose JWK object
 */
static cjose_jwk_t *_oidc_jwk_parse_x5c_spec(apr_pool_t *pool, const json_t *json, oidc_jose_error_t *err) {

	cjose_jwk_t *cjose_jwk = NULL;

	char *kty = NULL;
	oidc_jose_get_string(pool, json, OIDC_JOSE_HDR_KTY, FALSE, &kty, NULL);
	if (kty == NULL) {
		oidc_jose_error(err, "no key type \"" OIDC_JOSE_HDR_KTY "\" found in JWK JSON value");
		goto end;
	}

	if ((_oidc_strcmp(kty, OIDC_JOSE_HDR_KTY_RSA) != 0) && (_oidc_strcmp(kty, OIDC_JOSE_HDR_KTY_EC) != 0)) {
		oidc_jose_error(err, "no \"" OIDC_JOSE_HDR_KTY_RSA "\" or \"" OIDC_JOSE_HDR_KTY_EC
				     "\" key type found JWK JSON value");
		goto end;
	}

	const json_t *v = json_object_get(json, OIDC_JOSE_HDR_X5C);
	if (v == NULL) {
		oidc_jose_error(err, "no \"" OIDC_JOSE_HDR_X5C "\" key found in JWK JSON value");
		goto end;
	}

	_oidc_jwk_parse_x5c(pool, json, &cjose_jwk, err);

end:

	return cjose_jwk;
}

/*
 * create a JWK struct from a cjose_jwk object
 */
static oidc_jwk_t *oidc_jwk_from_cjose(apr_pool_t *pool, cjose_jwk_t *cjose_jwk, const char *use) {
	cjose_err cjose_err;
	oidc_jwk_t *jwk = oidc_jwk_new(pool);
	jwk->cjose_jwk = cjose_jwk;
	jwk->kid = apr_pstrdup(pool, cjose_jwk_get_kid(jwk->cjose_jwk, &cjose_err));
	jwk->kty = cjose_jwk_get_kty(jwk->cjose_jwk, &cjose_err);
	jwk->use = apr_pstrdup(pool, use);
	return jwk;
}

/*
 * parse a JSON string to a JWK struct
 */
oidc_jwk_t *oidc_jwk_parse(apr_pool_t *pool, const json_t *json, oidc_jose_error_t *err) {
	oidc_jwk_t *result = NULL;
	cjose_jwk_t *cjose_jwk = NULL;
	cjose_err cjose_err;
	oidc_jose_error_t x5c_err;
	char *use = NULL;
	const json_t *v = NULL;
	const json_t *e = NULL;

	const char *s_json = oidc_json_encode(pool, json, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT);
	if (s_json == NULL) {
		oidc_jose_error(err, "could not serialize JWK");
		goto end;
	}

	cjose_jwk = cjose_jwk_import(s_json, _oidc_strlen(s_json), &cjose_err);

	if (cjose_jwk == NULL) {
		// exception because x5c is not supported by cjose natively
		// ignore errors set by oidc_jwk_parse_x5c_spec
		cjose_jwk = _oidc_jwk_parse_x5c_spec(pool, json, &x5c_err);
		if (cjose_jwk == NULL) {
			oidc_jose_error(err, "JWK parsing failed: %s", oidc_cjose_e2s(pool, cjose_err));
			goto end;
		}
	}

	oidc_jose_get_string(pool, json, OIDC_JOSE_JWK_USE_STR, FALSE, &use, NULL);

	result = oidc_jwk_from_cjose(pool, cjose_jwk, use);

	// set alg
	oidc_jose_get_string(pool, json, OIDC_JOSE_JWK_ALG_STR, FALSE, &result->alg, NULL);

	// set x5c array
	v = json_object_get(json, OIDC_JOSE_JWK_X5C_STR);
	if (v && json_is_array(v)) {
		result->x5c = apr_array_make(pool, (int)json_array_size(v), sizeof(const char *));
		for (int i = 0; i < json_array_size(v); i++) {
			e = json_array_get(v, i);
			if (json_is_string(e))
				APR_ARRAY_PUSH(result->x5c, const char *) = apr_pstrdup(pool, json_string_value(e));
		}
	}

	// set x5t#256
	v = json_object_get(json, OIDC_JOSE_JWK_X5T256_STR);
	if (v)
		result->x5t_S256 = apr_pstrdup(pool, json_string_value(v));

	// set x5t
	v = json_object_get(json, OIDC_JOSE_JWK_X5T_STR);
	if (v)
		result->x5t = apr_pstrdup(pool, json_string_value(v));

end:

	return result;
}

/*
 * copy a JWK by converting oidc_jwk_t to JSON and parsing it back
 */
oidc_jwk_t *oidc_jwk_copy(apr_pool_t *pool, const oidc_jwk_t *src) {
	cjose_err err;
	oidc_jwk_t *dst = oidc_jwk_new(pool);
	dst->cjose_jwk = cjose_jwk_retain(src->cjose_jwk, &err);
	dst->kid = apr_pstrdup(pool, src->kid);
	dst->kty = src->kty;
	dst->use = apr_pstrdup(pool, src->use);
	dst->alg = apr_pstrdup(pool, src->alg);
	dst->x5c = NULL;
	if (src->x5c) {
		dst->x5c = apr_array_make(pool, src->x5c->nelts, sizeof(const char *));
		for (int i = 0; i < src->x5c->nelts; i++)
			APR_ARRAY_PUSH(dst->x5c, const char *) = APR_ARRAY_IDX(src->x5c, i, const char *);
	}
	dst->x5t = apr_pstrdup(pool, src->x5t);
	dst->x5t_S256 = apr_pstrdup(pool, src->x5t_S256);
	return dst;
}

/*
 * destroy resources allocated for a JWK struct
 */
void oidc_jwk_destroy(oidc_jwk_t *jwk) {
	if (jwk && jwk->cjose_jwk) {
		cjose_jwk_release(jwk->cjose_jwk);
		jwk->cjose_jwk = NULL;
	}
}

/*
 * destroy a list of JWKs structs
 */
void oidc_jwk_list_destroy_hash(apr_hash_t *keys) {
	const void *key = NULL;
	apr_ssize_t klen = 0;
	if (keys == NULL)
		return;
	for (apr_hash_index_t *hi = apr_hash_first(NULL, keys); hi; hi = apr_hash_next(hi)) {
		oidc_jwk_t *jwk = NULL;
		apr_hash_this(hi, &key, &klen, (void **)&jwk);
		oidc_jwk_destroy(jwk);
		apr_hash_set(keys, key, klen, NULL);
	}
}

/*
 * copy a list (array) of JWKs
 */
apr_array_header_t *oidc_jwk_list_copy(apr_pool_t *pool, apr_array_header_t *src) {
	apr_array_header_t *dst = NULL;

	if (src == NULL)
		return NULL;

	dst = apr_array_make(pool, src->nelts, sizeof(const oidc_jwk_t *));
	for (int i = 0; i < src->nelts; i++)
		APR_ARRAY_PUSH(dst, oidc_jwk_t *) = oidc_jwk_copy(pool, APR_ARRAY_IDX(src, i, const oidc_jwk_t *));

	return dst;
}

/*
 * destroy a list (array) of JWKs
 */
void oidc_jwk_list_destroy(apr_array_header_t *keys_list) {
	if (keys_list == NULL)
		return;
	oidc_jwk_t **jwk = NULL;
	while ((jwk = apr_array_pop(keys_list))) {
		oidc_jwk_destroy(*jwk);
	}
}

/*
 * parse a JSON object in to a JWK struct
 */
apr_byte_t oidc_jwk_parse_json(apr_pool_t *pool, const json_t *json, oidc_jwk_t **jwk, oidc_jose_error_t *err) {
	*jwk = oidc_jwk_parse(pool, json, err);
	return (*jwk != NULL);
}

/*
 * parse a set of JWKs into a list (array) of JWK structs
 */
apr_byte_t oidc_jwks_parse_json(apr_pool_t *pool, const json_t *json, apr_array_header_t **jwk_list,
				oidc_jose_error_t *err) {
	const json_t *keys = json_object_get(json, OIDC_JOSE_JWKS_KEYS_STR);
	if ((keys == NULL) || (!json_is_array(keys))) {
		oidc_jose_error(err, "JWKS did not contain \"" OIDC_JOSE_JWKS_KEYS_STR "\" array");
		return FALSE;
	}
	*jwk_list = apr_array_make(pool, (int)json_array_size(keys), sizeof(const oidc_jwk_t *));
	for (int i = 0; i < json_array_size(keys); i++) {
		const json_t *elem = json_array_get(keys, i);
		if (elem == NULL)
			continue;
		oidc_jwk_t *jwk;
		if (oidc_jwk_parse_json(pool, elem, &jwk, err) != TRUE) {
			return FALSE;
		}
		APR_ARRAY_PUSH(*jwk_list, const oidc_jwk_t *) = jwk;
	}
	return TRUE;
}

/*
 * check if a JSON object is a JWK
 */
apr_byte_t oidc_is_jwk(const json_t *json) {
	const json_t *kty = json_object_get(json, OIDC_JOSE_JWK_KTY_STR);
	if ((kty == NULL) || (!json_is_string(kty))) {
		return FALSE;
	}
	return TRUE;
}

/*
 * check if a JSON object is a set JWKs
 */
apr_byte_t oidc_is_jwks(const json_t *json) {
	const json_t *keys = json_object_get(json, OIDC_JOSE_JWKS_KEYS_STR);
	if ((keys == NULL) || (!json_is_array(keys))) {
		return FALSE;
	}
	return TRUE;
}

/*
 * produce the serialized JSON  JWK representation from an oidc_jwk_t structure
 */
apr_byte_t oidc_jwk_to_json(apr_pool_t *pool, const oidc_jwk_t *jwk, char **s_json, oidc_jose_error_t *oidc_err) {
	apr_byte_t rv = FALSE;
	char *s_cjose = NULL;
	cjose_err err;
	json_t *json = NULL;
	json_t *temp = NULL;
	json_error_t json_error;

	// input sanity checks
	if ((jwk == NULL) || (s_json == NULL))
		goto end;

	// get the JWK string representation from cjose
	s_cjose = cjose_jwk_to_json(jwk->cjose_jwk, TRUE, &err);
	if (s_cjose == NULL) {
		oidc_jose_error(oidc_err, "oidc_jwk_to_json: cjose_jwk_to_json failed: %s", oidc_cjose_e2s(pool, err));
		goto end;
	}

	json = json_loads(s_cjose, 0, &json_error);
	if (json == NULL) {
		oidc_jose_error(oidc_err, "oidc_jwk_to_json: json_loads failed");
		goto end;
	}

	if (jwk->use)
		json_object_set_new(json, OIDC_JOSE_JWK_USE_STR, json_string(jwk->use));

	// set alg (RFC 7517 section 4.4); lets an OP pick this key for the named algorithm
	if (jwk->alg)
		json_object_set_new(json, OIDC_JOSE_JWK_ALG_STR, json_string(jwk->alg));

	// set x5c
	if ((jwk->x5c != NULL) && (jwk->x5c->nelts > 0)) {
		temp = json_array();
		for (int i = 0; i < jwk->x5c->nelts; i++)
			json_array_append_new(temp, json_string(APR_ARRAY_IDX(jwk->x5c, i, const char *)));
		json_object_set_new(json, OIDC_JOSE_JWK_X5C_STR, temp);
	}

	// set x5t#256
	if (jwk->x5t_S256 != NULL)
		json_object_set_new(json, OIDC_JOSE_JWK_X5T256_STR, json_string(jwk->x5t_S256));

	// set x5t
	if (jwk->x5t != NULL)
		json_object_set_new(json, OIDC_JOSE_JWK_X5T_STR, json_string(jwk->x5t));

	// generate the string ...
	*s_json = oidc_json_encode(pool, json, OIDC_JSON_ENCODE_ANY | OIDC_JSON_COMPACT | OIDC_JSON_PRESERVE_ORDER);

	rv = (*s_json != NULL);

end:

	if (json)
		json_decref(json);
	if (s_cjose)
		cjose_get_dealloc()(s_cjose);

	return rv;
}

/*
 * convert the public part of a JWK struct to a (pool-allocated) JSON string; unlike oidc_jwk_to_json this
 * excludes private key material, which is required when publishing a key (e.g. the DPoP confirmation header)
 */
apr_byte_t oidc_jwk_to_public_json(apr_pool_t *pool, const oidc_jwk_t *jwk, char **s_json, oidc_jose_error_t *err) {
	cjose_err cjose_err;
	char *s_cjose = NULL;

	if ((jwk == NULL) || (s_json == NULL))
		return FALSE;

	s_cjose = cjose_jwk_to_json(jwk->cjose_jwk, FALSE /* public only */, &cjose_err);
	if (s_cjose == NULL) {
		oidc_jose_error(err, "cjose_jwk_to_json failed: %s", oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}
	*s_json = apr_pstrdup(pool, s_cjose);
	cjose_get_dealloc()(s_cjose);

	return TRUE;
}

/*
 * derive the default JWS signing algorithm for a key (RSA -> RS256; EC -> ES256/384/512 per curve);
 * returns NULL when the key type/curve is unsupported
 */
const char *oidc_jwk_default_jws_alg(const oidc_jwk_t *jwk) {
	if (jwk == NULL)
		return NULL;
	if (jwk->kty == OIDC_JOSE_JWK_KTY_RSA)
		return OIDC_JOSE_HDR_ALG_RS256;
	if (jwk->kty == OIDC_JOSE_JWK_KTY_EC) {
		if (cjose_jwk_EC_get_curve(jwk->cjose_jwk, NULL) == NID_X9_62_prime256v1)
			return OIDC_JOSE_HDR_ALG_ES256;
		if (cjose_jwk_EC_get_curve(jwk->cjose_jwk, NULL) == NID_secp384r1)
			return OIDC_JOSE_HDR_ALG_ES384;
		if (cjose_jwk_EC_get_curve(jwk->cjose_jwk, NULL) == NID_secp521r1)
			return OIDC_JOSE_HDR_ALG_ES512;
	}
	return NULL;
}

/*
 * set a specified key identifier or generate a key identifier and set it
 */
static apr_byte_t oidc_jwk_set_or_generate_kid(apr_pool_t *pool, cjose_jwk_t *cjose_jwk, const char *s_kid,
					       const char *key_params, int key_params_len, oidc_jose_error_t *err) {

	char *jwk_kid = NULL;

	if (s_kid != NULL) {
		jwk_kid = apr_pstrdup(pool, s_kid);
	} else {
		/* calculate a unique key identifier (kid) by fingerprinting the key params */
		if (oidc_jose_hash_and_base64url_encode(pool, OIDC_JOSE_ALG_SHA256, key_params, key_params_len,
							&jwk_kid, err) == FALSE) {
			return FALSE;
		}
	}

	cjose_err cjose_err;
	if (cjose_jwk_set_kid(cjose_jwk, jwk_kid, _oidc_strlen(jwk_kid), &cjose_err) == FALSE) {
		oidc_jose_error(err, "cjose_jwk_set_kid failed: %s", oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	return TRUE;
}

/*
 * create an "oct" symmetric JWK
 */
oidc_jwk_t *oidc_jwk_create_symmetric_key(apr_pool_t *pool, const char *skid, const unsigned char *key,
					  unsigned int key_len, apr_byte_t set_kid, oidc_jose_error_t *err) {

	cjose_err cjose_err;
	cjose_jwk_t *cjose_jwk = cjose_jwk_create_oct_spec(key, key_len, &cjose_err);
	if (cjose_jwk == NULL) {
		oidc_jose_error(err, "cjose_jwk_create_oct_spec failed: %s", oidc_cjose_e2s(pool, cjose_err));
		return NULL;
	}

	if ((set_kid == TRUE) &&
	    (oidc_jwk_set_or_generate_kid(pool, cjose_jwk, skid, (const char *)key, key_len, err) == FALSE)) {
		cjose_jwk_release(cjose_jwk);
		return NULL;
	}

	oidc_jwk_t *jwk = oidc_jwk_new(pool);
	jwk->cjose_jwk = cjose_jwk;
	jwk->kid = apr_pstrdup(pool, cjose_jwk_get_kid(jwk->cjose_jwk, &cjose_err));
	jwk->kty = cjose_jwk_get_kty(jwk->cjose_jwk, &cjose_err);
	return jwk;
}

/*
 * read an x509 certificate and its public key from the provided input
 */
static apr_byte_t oidc_jwk_x509_read(apr_pool_t *pool, BIO *input, char **encoded_certificate, EVP_PKEY **pkey,
				     X509 **rx509, oidc_jose_error_t *err) {
	apr_byte_t rv = FALSE;
	X509 *x509 = NULL;
	int encoded_cert_len = 0;

	/* read the X.509 struct - assume input is no public key */
	if ((x509 = PEM_read_bio_X509_AUX(input, NULL, NULL, NULL)) == NULL) {
		oidc_jose_error_openssl(err, "PEM_read_bio_X509_AUX");
		goto end;
	}

	if (pkey) {
		/* get the public key struct from the X.509 struct */
		*pkey = X509_get_pubkey(x509);
		if (*pkey == NULL) {
			oidc_jose_error_openssl(err, "X509_get_pubkey");
			goto end;
		}
	}

	/* populate x5c certificate */
	encoded_cert_len = oidc_jose_util_get_b64encoded_certificate_data(pool, x509, encoded_certificate, err);

	rv = (encoded_certificate != NULL) && (encoded_cert_len > 0);

end:
	if (x509) {
		if (rx509)
			*rx509 = x509;
		else
			X509_free(x509);
	}
	return rv;
}

/*
 * extract a JWK struct and a fingerprint from an OpenSSL RSA key
 */
static apr_byte_t _oidc_jwk_rsa_key_to_jwk(apr_pool_t *pool, const EVP_PKEY *pkey, oidc_jwk_t **oidc_jwk, char **fp,
					   int *fp_len, oidc_jose_error_t *err) {
	apr_byte_t rv = FALSE;
	cjose_err cjose_err;
	BIGNUM *rsa_n = NULL;
	BIGNUM *rsa_e = NULL;
	BIGNUM *rsa_d = NULL;
	cjose_jwk_rsa_keyspec key_spec;

	_oidc_memset(&key_spec, 0, sizeof(cjose_jwk_rsa_keyspec));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &rsa_n);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &rsa_e);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &rsa_d);
#else
	/* get the RSA key from the public key struct */
	RSA *rsa = (RSA *)EVP_PKEY_get1_RSA((EVP_PKEY *)pkey);
	if (rsa == NULL) {
		oidc_jose_error_openssl(err, "EVP_PKEY_get1_RSA");
		goto end;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	RSA_get0_key(rsa, (const BIGNUM **)&rsa_n, (const BIGNUM **)&rsa_e, (const BIGNUM **)&rsa_d);
#else
	rsa_n = rsa->n;
	rsa_e = rsa->e;
	rsa_d = rsa->d;
#endif

	RSA_free(rsa);
#endif

	/* convert the modulus bignum in to a key/len */
	key_spec.nlen = BN_num_bytes(rsa_n);
	key_spec.n = apr_pcalloc(pool, key_spec.nlen);
	BN_bn2bin(rsa_n, key_spec.n);

	/* convert the exponent bignum in to a key/len */
	key_spec.elen = BN_num_bytes(rsa_e);
	key_spec.e = apr_pcalloc(pool, key_spec.elen);
	BN_bn2bin(rsa_e, key_spec.e);

	/* convert the private exponent bignum in to a key/len */
	if (rsa_d != NULL) {
		key_spec.dlen = BN_num_bytes(rsa_d);
		key_spec.d = apr_pcalloc(pool, key_spec.dlen);
		BN_bn2bin(rsa_d, key_spec.d);
	}

	(*oidc_jwk)->cjose_jwk = cjose_jwk_create_RSA_spec(&key_spec, &cjose_err);
	if ((*oidc_jwk)->cjose_jwk == NULL) {
		oidc_jose_error(err, "cjose_jwk_create_RSA_spec failed: %s", oidc_cjose_e2s(pool, cjose_err));
		goto end;
	}

	*fp_len = (int)(key_spec.nlen + key_spec.elen);
	*fp = apr_pcalloc(pool, *fp_len);
	_oidc_memcpy(*fp, key_spec.n, key_spec.nlen);
	_oidc_memcpy(*fp + key_spec.nlen, key_spec.e, key_spec.elen);

	rv = TRUE;

end:

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (rsa_n)
		BN_clear_free(rsa_n);
	if (rsa_e)
		BN_clear_free(rsa_e);
	if (rsa_d)
		BN_clear_free(rsa_d);
#endif

	return rv;
}

#if (OIDC_JOSE_EC_SUPPORT)

/*
 * extract a JWK struct and a fingerprint from an OpenSSL Elliptic Curve key
 */
static apr_byte_t _oidc_jwk_ec_key_to_jwk(apr_pool_t *pool, const EVP_PKEY *pkey, oidc_jwk_t **oidc_jwk, char **fp,
					  int *fp_len, oidc_jose_error_t *err) {
	apr_byte_t rv = FALSE;
	cjose_err cjose_err;
	cjose_jwk_ec_keyspec ec_keyspec;
	int crv = 0;
	BIGNUM *ec_x = NULL;
	BIGNUM *ec_y = NULL;
	BIGNUM *ec_d = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	char curve_name[64];
	size_t curve_name_len = 0;

	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &ec_x);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &ec_y);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &ec_d);
	if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, sizeof(curve_name),
					    &curve_name_len)) {
		oidc_jose_error_openssl(err, "EVP_PKEY_get_utf8_string_param(OSSL_PKEY_PARAM_GROUP_NAME)");
		goto end;
	}
	crv = OBJ_sn2nid(curve_name);
#else
	EC_KEY *eckey = (EC_KEY *)EVP_PKEY_get1_EC_KEY((EVP_PKEY *)pkey);
	if (eckey == NULL) {
		oidc_jose_error_openssl(err, "EVP_PKEY_get1_EC_KEY");
		goto end;
	}
	const EC_GROUP *ec_group = EC_KEY_get0_group(eckey);
	const EC_POINT *ecpoint = EC_KEY_get0_public_key(eckey);
	crv = EC_GROUP_get_curve_name(ec_group);
	ec_x = BN_new();
	ec_y = BN_new();
	if (EC_POINT_get_affine_coordinates_GFp(ec_group, ecpoint, ec_x, ec_y, NULL) == 0) {
		oidc_jose_error_openssl(err, "EC_POINT_get_affine_coordinates_GFp");
		EC_KEY_free(eckey);
		goto end;
	}
	/* NB: ec_d borrows from eckey; releasing our get1 reference here is safe since pkey keeps it alive */
	ec_d = (BIGNUM *)EC_KEY_get0_private_key(eckey);
	if (crv == 0) {
		oidc_jose_error_openssl(err, "EC_GROUP_get_curve_name");
		EC_KEY_free(eckey);
		goto end;
	}
	EC_KEY_free(eckey);
#endif

	_oidc_memset(&ec_keyspec, 0, sizeof(cjose_jwk_ec_keyspec));

	ec_keyspec.crv = crv;

	ec_keyspec.xlen = BN_num_bytes(ec_x);
	ec_keyspec.x = apr_pcalloc(pool, ec_keyspec.xlen);
	BN_bn2bin(ec_x, ec_keyspec.x);

	ec_keyspec.ylen = BN_num_bytes(ec_y);
	ec_keyspec.y = apr_pcalloc(pool, ec_keyspec.ylen);
	BN_bn2bin(ec_y, ec_keyspec.y);

	if (ec_d != NULL) {
		ec_keyspec.dlen = BN_num_bytes(ec_d);
		ec_keyspec.d = apr_pcalloc(pool, ec_keyspec.dlen);
		BN_bn2bin(ec_d, ec_keyspec.d);
	}

	(*oidc_jwk)->cjose_jwk = cjose_jwk_create_EC_spec(&ec_keyspec, &cjose_err);
	if ((*oidc_jwk)->cjose_jwk == NULL) {
		oidc_jose_error(err, "cjose_jwk_create_EC_spec failed: %s", oidc_cjose_e2s(pool, cjose_err));
		goto end;
	}

	apr_uint32_t b = htonl(crv);
	*fp_len = (int)(sizeof(b) + ec_keyspec.xlen + ec_keyspec.ylen);
	*fp = apr_pcalloc(pool, *fp_len);
	_oidc_memcpy(*fp, &b, sizeof(b));
	_oidc_memcpy(*fp + sizeof(b), ec_keyspec.x, ec_keyspec.xlen);
	_oidc_memcpy(*fp + sizeof(b) + ec_keyspec.xlen, ec_keyspec.y, ec_keyspec.ylen);

	rv = TRUE;

end:

	if (ec_x)
		BN_clear_free(ec_x);
	if (ec_y)
		BN_clear_free(ec_y);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (ec_d)
		BN_clear_free(ec_d);
#endif
	return rv;
}

#endif

/*
 * convert the PEM public key - possibly in a X.509 certificate - in the BIO pointed to
 * by "input" to a JSON Web Key object
 */
/*
 * populate x5c (first cert plus any trailing chain entries) and the x5t/x5t#S256
 * thumbprints on jwk from a parsed X.509 certificate
 */
static apr_byte_t oidc_jwk_populate_cert_info(apr_pool_t *pool, BIO *input, oidc_jwk_t *jwk, const X509 *x509,
					      const char *first_pem, oidc_jose_error_t *err) {
	unsigned char *x509_bytes = NULL;
	int x509_cert_length = 0;
	char *next_pem = NULL;
	apr_byte_t rv = FALSE;

	jwk->x5c = apr_array_make(pool, 1, sizeof(const char *));
	if (jwk->x5c == NULL) {
		oidc_jose_error(err, "apr_array_make failed");
		return FALSE;
	}
	APR_ARRAY_PUSH(jwk->x5c, const char *) = first_pem;

#if OPENSSL_VERSION_NUMBER < 0x000907000L
	// openssl below 0.9.7 does not allocate memory for you :o
	x509_cert_length = i2d_X509((X509 *)x509, NULL);
	if (x509_cert_length <= 0) {
		oidc_jose_error_openssl(err, "i2d_X509");
		goto end;
	}
	x509_bytes = (unsigned char *)OPENSSL_malloc(pool, x509_cert_length + 1);
	const unsigned char *p = x509_bytes;
	x509_cert_length = i2d_X509((X509 *)x509, &p);
#else
	x509_cert_length = i2d_X509((X509 *)x509, &x509_bytes);
#endif
	if (x509_cert_length < 0) {
		oidc_jose_error_openssl(err, "i2d_X509");
		goto end;
	}

	oidc_jose_hash_and_base64url_encode(pool, OIDC_JOSE_ALG_SHA1, (const char *)x509_bytes, x509_cert_length,
					    &jwk->x5t, err);
	oidc_jose_hash_and_base64url_encode(pool, OIDC_JOSE_ALG_SHA256, (const char *)x509_bytes, x509_cert_length,
					    &jwk->x5t_S256, err);

	while (oidc_jwk_x509_read(pool, input, &next_pem, NULL, NULL, err) == TRUE)
		APR_ARRAY_PUSH(jwk->x5c, const char *) = next_pem;

	rv = TRUE;

end:
	if (x509_bytes)
		OPENSSL_free(x509_bytes);
	return rv;
}

/*
 * read a public key from the BIO, falling back to an X.509 certificate chain
 * when the BIO does not contain a bare PEM public key; on success, the
 * extracted EVP_PKEY is returned in *pkey (out_x509 carries the cert that must
 * be X509_free'd by the caller, when non-NULL)
 */
static apr_byte_t oidc_jwk_pem_bio_read_public(apr_pool_t *pool, BIO *input, oidc_jwk_t *jwk, EVP_PKEY **pkey,
					       X509 **out_x509, oidc_jose_error_t *err) {

	*pkey = PEM_read_bio_PUBKEY(input, NULL, NULL, NULL);
	if (*pkey != NULL)
		return TRUE;

	/* not a public key - reset the buffer and try as a certificate */
	BIO_reset(input);

	char *first_pem = NULL;
	if (oidc_jwk_x509_read(pool, input, &first_pem, pkey, out_x509, err) == FALSE)
		return FALSE;

	return oidc_jwk_populate_cert_info(pool, input, jwk, *out_x509, first_pem, err);
}

/*
 * return the OpenSSL key-type base id for the supplied EVP_PKEY, abstracting
 * over the different OpenSSL API versions
 */
static int oidc_jwk_pkey_base_id(const EVP_PKEY *pkey) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	return EVP_PKEY_get_base_id(pkey);
#elif (OPENSSL_VERSION_NUMBER > 0x10100000)
	return EVP_PKEY_base_id(pkey);
#else
	return EVP_PKEY_type(pkey->type);
#endif
}

/*
 * dispatch a parsed EVP_PKEY into the matching JWK builder, producing the
 * fingerprint bytes that drive kid generation
 */
static apr_byte_t oidc_jwk_pkey_to_jwk(apr_pool_t *pool, const EVP_PKEY *pkey, oidc_jwk_t **jwk, char **fp, int *fp_len,
				       oidc_jose_error_t *err) {
	switch (oidc_jwk_pkey_base_id(pkey)) {
	case EVP_PKEY_RSA:
		return _oidc_jwk_rsa_key_to_jwk(pool, pkey, jwk, fp, fp_len, err);
#if (OIDC_JOSE_EC_SUPPORT)
	case EVP_PKEY_EC:
		return _oidc_jwk_ec_key_to_jwk(pool, pkey, jwk, fp, fp_len, err);
#endif
	default:
		oidc_jose_error(err, "unhandled key type: %d", oidc_jwk_pkey_base_id(pkey));
		return FALSE;
	}
}

apr_byte_t oidc_jwk_pem_bio_to_jwk(apr_pool_t *pool, BIO *input, const char *kid, oidc_jwk_t **oidc_jwk,
				   apr_byte_t is_private_key, oidc_jose_error_t *err) {
	cjose_err cjose_err;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	apr_byte_t rv = FALSE;
	char *fp = NULL;
	int fp_len = 0;

	*oidc_jwk = oidc_jwk_new(pool);

	if (is_private_key == TRUE) {
		if ((pkey = PEM_read_bio_PrivateKey(input, NULL, NULL, NULL)) == NULL) {
			oidc_jose_error_openssl(err, "PEM_read_bio_PrivateKey");
			goto end;
		}
	} else if (oidc_jwk_pem_bio_read_public(pool, input, *oidc_jwk, &pkey, &x509, err) == FALSE) {
		goto end;
	}

	if (oidc_jwk_pkey_to_jwk(pool, pkey, oidc_jwk, &fp, &fp_len, err) == FALSE)
		goto end;

	if (oidc_jwk_set_or_generate_kid(pool, (*oidc_jwk)->cjose_jwk, kid, fp, fp_len, err) == FALSE)
		goto end;

	(*oidc_jwk)->kid = apr_pstrdup(pool, cjose_jwk_get_kid((*oidc_jwk)->cjose_jwk, &cjose_err));
	(*oidc_jwk)->kty = cjose_jwk_get_kty((*oidc_jwk)->cjose_jwk, &cjose_err);

	rv = TRUE;

end:

	if (pkey)
		EVP_PKEY_free(pkey);
	if (x509)
		X509_free(x509);

	return rv;
}

/*
 * parse a PEM-formatted public or private key from the specified file
 */
static apr_byte_t oidc_jwk_parse_pem_key(apr_pool_t *pool, apr_byte_t is_private_key, const char *kid,
					 const char *filename, oidc_jwk_t **jwk, oidc_jose_error_t *err) {
	BIO *input = NULL;
	apr_byte_t rv = FALSE;

	if ((input = BIO_new(BIO_s_file())) == NULL) {
		oidc_jose_error_openssl(err, "BIO_new/BIO_s_file");
		goto end;
	}

	if (BIO_read_filename(input, filename) <= 0) {
		oidc_jose_error_openssl(err, "BIO_read_filename");
		goto end;
	}

	if (oidc_jwk_pem_bio_to_jwk(pool, input, kid, jwk, is_private_key, err) == FALSE)
		goto end;

	rv = TRUE;

end:

	if (input)
		BIO_free(input);

	return rv;
}

#define OIDC_JOSE_CERT_BEGIN "-----BEGIN CERTIFICATE-----"
#define OIDC_JOSE_CERT_END "-----END CERTIFICATE-----"

/*
 * parse a PEM-formatted key from a JSON object in to a cjose JWK object
 */
static apr_byte_t _oidc_jwk_parse_x5c(apr_pool_t *pool, const json_t *json, cjose_jwk_t **jwk, oidc_jose_error_t *err) {

	apr_byte_t rv = FALSE;
	const char *kid = NULL;
	oidc_jwk_t *oidc_jwk = NULL;

	/* get the "x5c" array element from the JSON object */
	const json_t *v = json_object_get(json, OIDC_JOSE_HDR_X5C);
	if (v == NULL) {
		oidc_jose_error(err, "JSON key \"%s\" could not be found", OIDC_JOSE_HDR_X5C);
		return FALSE;
	}
	if (!json_is_array(v)) {
		oidc_jose_error(err, "JSON key \"%s\" was found but its value is not a JSON array", OIDC_JOSE_HDR_X5C);
		return FALSE;
	}

	/* take the first element of the array */
	v = json_array_get(v, 0);
	if (v == NULL) {
		oidc_jose_error(err, "first element in JSON array is \"null\"");
		return FALSE;
	}
	if (!json_is_string(v)) {
		oidc_jose_error(err, "first element in array is not a JSON string");
		return FALSE;
	}

	const char *s_x5c = json_string_value(v);

	/* PEM-format it */
	const int chunk = 75;
	int i = 0;
	char *s = apr_psprintf(pool, "%s\n", OIDC_JOSE_CERT_BEGIN);
	const int n = (int)_oidc_strlen(s_x5c);
	while (i < n) {
		s = apr_psprintf(pool, "%s%s\n", s, apr_pstrmemdup(pool, s_x5c + i, (i + chunk) > n ? (n - i) : chunk));
		i += chunk;
	}
	s = apr_psprintf(pool, "%s%s\n", s, OIDC_JOSE_CERT_END);

	/* put it in BIO memory */
	BIO *input = BIO_new_mem_buf(s, (int)_oidc_strlen(s));
	if (input == NULL) {
		oidc_jose_error_openssl(err, "BIO_new_mem_buf");
		return FALSE;
	}

	v = json_object_get(json, CJOSE_HDR_KID);
	if ((v != NULL) && json_is_string(v)) {
		kid = json_string_value(v);
	}

	/* do the actual parsing */

	rv = oidc_jwk_pem_bio_to_jwk(pool, input, kid, &oidc_jwk, FALSE, err);
	*jwk = oidc_jwk->cjose_jwk;

	BIO_free(input);

	return rv;
}

/*
 * parse a PEM formatted private key to a JWK
 */
apr_byte_t oidc_jwk_parse_pem_private_key(apr_pool_t *pool, const char *kid, const char *filename, oidc_jwk_t **jwk,
					  oidc_jose_error_t *err) {
	return oidc_jwk_parse_pem_key(pool, TRUE, kid, filename, jwk, err);
}

/*
 * parse a PEM formatted public key file to a JWK
 */
apr_byte_t oidc_jwk_parse_pem_public_key(apr_pool_t *pool, const char *kid, const char *filename, oidc_jwk_t **jwk,
					 oidc_jose_error_t *err) {
	return oidc_jwk_parse_pem_key(pool, FALSE, kid, filename, jwk, err);
}
