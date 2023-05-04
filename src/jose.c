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
 * Copyright (C) 2017-2023 ZmartZone Holding BV
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
 * JSON Web Token handling
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include <apr_base64.h>
#define APR_WANT_BYTEFUNC
#include <apr_want.h>

#ifdef USE_LIBBROTLI
#include <brotli/encode.h>
#include <brotli/decode.h>
#elif USE_ZLIB
#include <zlib.h>
#endif

#include "jose.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#ifdef WIN32
#define snprintf _snprintf
#endif

/* to extract a b64 encoded certificate representation as a single string */
static int oidc_jose_util_get_b64encoded_certificate_data(apr_pool_t *p,
		X509 *x509_cert, char **b64_encoded_certificate,
		oidc_jose_error_t *err) {
	int rc = 0;
	char *name = NULL, *header = NULL;
	long len = 0, b64_len = 0;
	BIO *bio = NULL;
	unsigned char *data = NULL;

	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		oidc_jose_error_openssl(err, "BIO_new");
		goto end;
	}

	if (!PEM_write_bio_X509(bio, x509_cert)) {
		oidc_jose_error_openssl(err, "PEM_write_bio_X509");
		goto end;
	}
	if (!PEM_read_bio(bio, &name, &header, &data, &len)) {
		oidc_jose_error_openssl(err, "PEM_read_bio");
		goto end;
	}

	/* "For every 3 bytes of input provided 4 bytes of output data will be produced." */
	b64_len = (((len + 2) / 3) * 4) + 1;

	*b64_encoded_certificate = (char*) apr_pcalloc(p, b64_len);
	if (!*b64_encoded_certificate) {
		oidc_jose_error_openssl(err, "apr_pcalloc");
		goto end;
	};

	rc = EVP_EncodeBlock((unsigned char *)*b64_encoded_certificate, data, len);

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

/* definition follows */
static char* internal_cjose_jwk_to_json(apr_pool_t *pool,
		const oidc_jwk_t *oidc_jwk, oidc_jose_error_t *oidc_err);

/*
 * assemble an error report
 */
void _oidc_jose_error_set(oidc_jose_error_t *error, const char *source,
		const int line, const char *function, const char *fmt, ...) {
	if (error == NULL)
		return;
	snprintf(error->source, OIDC_JOSE_ERROR_SOURCE_LENGTH, "%s", source);
	error->line = line;
	snprintf(error->function, OIDC_JOSE_ERROR_FUNCTION_LENGTH, "%s", function);
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(error->text, OIDC_JOSE_ERROR_TEXT_LENGTH, fmt ? fmt : "(null)",
			ap);
	va_end(ap);
}

/*
 * set a header value in a JWT
 */
static void oidc_jwt_hdr_set(oidc_jwt_t *jwt, const char *key,
		const char *value) {
	json_object_set_new(jwt->header.value.json, key, json_string(value));
}

/*
 * create a new JWT
 */
oidc_jwt_t* oidc_jwt_new(apr_pool_t *pool, int create_header,
		int create_payload) {
	oidc_jwt_t *jwt = apr_pcalloc(pool, sizeof(oidc_jwt_t));
	if (create_header) {
		jwt->header.value.json = json_object();
		//oidc_jwt_hdr_set(jwt, "typ", "JWT");
	}
	if (create_payload) {
		jwt->payload.value.json = json_object();
	}
	return jwt;
}

/*
 * get a header value from a JWT
 */
const char* oidc_jwt_hdr_get(oidc_jwt_t *jwt, const char *key) {
	cjose_err cjose_err;
	cjose_header_t *hdr = cjose_jws_get_protected(jwt->cjose_jws);
	return hdr ? cjose_header_get(hdr, key, &cjose_err) : NULL;
}

/*
 * {"alg":"none"}
 */
#define OIDC_JOSE_HDR_ALG_NONE "eyJhbGciOiJub25lIn0"

/*
 * perform compact serialization on a JWT and return the resulting string
 */
char* oidc_jwt_serialize(apr_pool_t *pool, oidc_jwt_t *jwt,
		oidc_jose_error_t *err) {
	cjose_err cjose_err;
	const char *cser = NULL;
	if (_oidc_strcmp(jwt->header.alg, CJOSE_HDR_ALG_NONE) != 0) {
		if (cjose_jws_export(jwt->cjose_jws, &cser, &cjose_err) == FALSE) {
			oidc_jose_error(err, "cjose_jws_export failed: %s",
					oidc_cjose_e2s(pool, cjose_err));
			return NULL;
		}
	} else {

		char *s_payload = json_dumps(jwt->payload.value.json,
				JSON_PRESERVE_ORDER | JSON_COMPACT);

		char *out = NULL;
		size_t out_len;
		if (cjose_base64url_encode((const uint8_t*) s_payload,
				_oidc_strlen(s_payload), &out, &out_len, &cjose_err) == FALSE)
			return NULL;
		cser = apr_pstrmemdup(pool, out, out_len);
		cjose_get_dealloc()(out);

		free(s_payload);

		cser = apr_psprintf(pool, "%s.%s.", OIDC_JOSE_HDR_ALG_NONE, cser);
	}
	return apr_pstrdup(pool, cser);
}

/*
 * return the key type for an algorithm
 */
static int oidc_alg2kty(const char *alg) {
	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_DIR) == 0)
		return CJOSE_JWK_KTY_OCT;
	if (_oidc_strncmp(alg, "RS", 2) == 0)
		return CJOSE_JWK_KTY_RSA;
	if (_oidc_strncmp(alg, "PS", 2) == 0)
		return CJOSE_JWK_KTY_RSA;
	if (_oidc_strncmp(alg, "HS", 2) == 0)
		return CJOSE_JWK_KTY_OCT;
#if (OIDC_JOSE_EC_SUPPORT)
	if (_oidc_strncmp(alg, "ES", 2) == 0)
		return CJOSE_JWK_KTY_EC;
#endif
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_A128KW) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_A192KW) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_A256KW) == 0))
		return CJOSE_JWK_KTY_OCT;
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RSA1_5) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_RSA_OAEP) == 0))
		return CJOSE_JWK_KTY_RSA;
	return -1;
}

/*
 * return the key type of a JWT
 */
int oidc_jwt_alg2kty(oidc_jwt_t *jwt) {
	return oidc_alg2kty(jwt->header.alg);
}

/*
 * return the key size for an algorithm
 */
unsigned int oidc_alg2keysize(const char *alg) {

	if (alg == NULL)
		return 0;

	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_A128KW) == 0)
		return 16;
	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_A192KW) == 0)
		return 24;
	if (_oidc_strcmp(alg, CJOSE_HDR_ALG_A256KW) == 0)
		return 32;

	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS256) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS256) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS256) == 0))
		return 32;
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS384) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS384) == 0))
		return 48;
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS512) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS512) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS512) == 0))
		return 64;

	return 0;
}

/*
 * create a new JWK
 */
static oidc_jwk_t* oidc_jwk_new(apr_pool_t *pool) {
	oidc_jwk_t *jwk = apr_pcalloc(pool, sizeof(oidc_jwk_t));
	return jwk;
}

static apr_byte_t _oidc_jwk_parse_x5c(apr_pool_t *pool, json_t *json,
		cjose_jwk_t **jwk, oidc_jose_error_t *err);

#define OIDC_JOSE_HDR_KTY      "kty"
#define OIDC_JOSE_HDR_KTY_RSA  "RSA"
#define OIDC_JOSE_HDR_KTY_EC   "EC"
#define OIDC_JOSE_HDR_X5C      "x5c"

/*
 * parse a JSON object with an "x5c" JWK representation into a cjose JWK object
 */
static cjose_jwk_t* _oidc_jwk_parse_x5c_spec(apr_pool_t *pool, json_t *json,
		oidc_jose_error_t *err) {

	cjose_jwk_t *cjose_jwk = NULL;

	char *kty = NULL;
	oidc_jose_get_string(pool, json, OIDC_JOSE_HDR_KTY, FALSE, &kty, NULL);
	if (kty == NULL) {
		oidc_jose_error(err,
				"no key type \"" OIDC_JOSE_HDR_KTY "\" found in JWK JSON value");
		goto end;
	}

	if ((_oidc_strcmp(kty, OIDC_JOSE_HDR_KTY_RSA) != 0)
			&& (_oidc_strcmp(kty, OIDC_JOSE_HDR_KTY_EC) != 0)) {
		oidc_jose_error(err,
				"no \"" OIDC_JOSE_HDR_KTY_RSA "\" or \"" OIDC_JOSE_HDR_KTY_EC "\" key type found JWK JSON value");
		goto end;
	}

	json_t *v = json_object_get(json, OIDC_JOSE_HDR_X5C);
	if (v == NULL) {
		oidc_jose_error(err,
				"no \"" OIDC_JOSE_HDR_X5C "\" key found in JWK JSON value");
		goto end;
	}

	_oidc_jwk_parse_x5c(pool, json, &cjose_jwk, err);

end:

	return cjose_jwk;
}

/*
 * create a JWK struct from a cjose_jwk object
 */
static oidc_jwk_t* oidc_jwk_from_cjose(apr_pool_t *pool, cjose_jwk_t *cjose_jwk,
		const char *use) {
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
oidc_jwk_t* oidc_jwk_parse(apr_pool_t *pool, const char *s_json,
		oidc_jose_error_t *err) {
	oidc_jwk_t *result = NULL;
	cjose_jwk_t *cjose_jwk = NULL;
	cjose_err cjose_err;
	json_error_t json_error;
	oidc_jose_error_t x5c_err;
	char *use = NULL;

	json_t *json = json_loads(s_json, 0, &json_error);
	if (json == NULL) {
		oidc_jose_error(err, "could not parse JWK: %s (%s)", json_error.text,
				s_json);
		goto end;
	}

	cjose_jwk = cjose_jwk_import(s_json, _oidc_strlen(s_json), &cjose_err);

	if (cjose_jwk == NULL) {
		// exception because x5c is not supported by cjose natively
		// ignore errors set by oidc_jwk_parse_x5c_spec
		cjose_jwk = _oidc_jwk_parse_x5c_spec(pool, json, &x5c_err);
		if (cjose_jwk == NULL) {
			oidc_jose_error(err, "JWK parsing failed: %s",
					oidc_cjose_e2s(pool, cjose_err));
			goto end;
		}
	}

	oidc_jose_get_string(pool, json, OIDC_JOSE_JWK_USE_STR, FALSE, &use, NULL);

	result = oidc_jwk_from_cjose(pool, cjose_jwk, use);

end:

	if (json)
		json_decref(json);

	return result;
}

oidc_jwk_t* oidc_jwk_copy(apr_pool_t *pool, const oidc_jwk_t *src) {
	char *s_json = NULL;
	oidc_jose_error_t err;
	if (oidc_jwk_to_json(pool, src, &s_json, &err) == FALSE)
		return NULL;
	return oidc_jwk_parse(pool, s_json, &err);
}

/*
 * destroy resources allocated for a JWK struct
 */
void oidc_jwk_destroy(oidc_jwk_t *jwk) {
	if (jwk) {
		if (jwk->cjose_jwk) {
			cjose_jwk_release(jwk->cjose_jwk);
			jwk->cjose_jwk = NULL;
		}
	}
}

/*
 * destroy a list of JWKs structs
 */
void oidc_jwk_list_destroy_hash(apr_hash_t *keys) {
	apr_hash_index_t *hi = NULL;
	const void *key = NULL;
	apr_ssize_t klen = 0;
	if (keys == NULL)
		return;
	for (hi = apr_hash_first(NULL, keys); hi; hi = apr_hash_next(hi)) {
		oidc_jwk_t *jwk = NULL;
		apr_hash_this(hi, &key, &klen, (void**) &jwk);
		oidc_jwk_destroy(jwk);
		apr_hash_set(keys, key, klen, NULL);
	}
}

apr_array_header_t* oidc_jwk_list_copy(apr_pool_t *pool,
		apr_array_header_t *src) {
	apr_array_header_t *dst = NULL;
	int i = 0;

	if (src == NULL)
		return NULL;

	dst = apr_array_make(pool, src->nelts, sizeof(oidc_jwk_t*));
	for (i = 0; i < src->nelts; i++)
		APR_ARRAY_PUSH(dst, oidc_jwk_t *) = oidc_jwk_copy(pool,
				APR_ARRAY_IDX(src, i, oidc_jwk_t *));

	return dst;
}

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
apr_byte_t oidc_jwk_parse_json(apr_pool_t *pool, json_t *json, oidc_jwk_t **jwk,
		oidc_jose_error_t *err) {
	char *s_json = json_dumps(json, 0);
	*jwk = oidc_jwk_parse(pool, s_json, err);
	free(s_json);
	return (*jwk != NULL);
}

/*
 * convert a JWK struct to a JSON string
 */
apr_byte_t oidc_jwk_to_json(apr_pool_t *pool, const oidc_jwk_t *jwk,
		char **s_json, oidc_jose_error_t *err) {
	char *s = internal_cjose_jwk_to_json(pool, jwk, err);
	if (s == NULL)
		return FALSE;
	*s_json = apr_pstrdup(pool, s);
	free(s);
	return TRUE;
}

/*
 * hash a sequence of bytes with a specific algorithm and return the result as a base64url-encoded \0 terminated string
 */
apr_byte_t oidc_jose_hash_and_base64url_encode(apr_pool_t *pool,
		const char *openssl_hash_algo, const char *input, int input_len,
		char **output, oidc_jose_error_t *err) {
	unsigned char *hashed = NULL;
	unsigned int hashed_len = 0;
	if (oidc_jose_hash_bytes(pool, openssl_hash_algo,
			(const unsigned char*) input, input_len, &hashed, &hashed_len,
			err) == FALSE)
		return FALSE;
	char *out = NULL;
	size_t out_len;
	cjose_err cjose_err;
	if (cjose_base64url_encode(hashed, hashed_len, &out, &out_len,
			&cjose_err) == FALSE) {
		oidc_jose_error(err, "cjose_base64url_encode failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}
	*output = apr_pstrmemdup(pool, out, out_len);
	cjose_get_dealloc()(out);
	return TRUE;
}

/*
 * set a specified key identifier or generate a key identifier and set it
 */
static apr_byte_t oidc_jwk_set_or_generate_kid(apr_pool_t *pool,
		cjose_jwk_t *cjose_jwk, const char *s_kid, const char *key_params,
		int key_params_len, oidc_jose_error_t *err) {

	char *jwk_kid = NULL;

	if (s_kid != NULL) {
		jwk_kid = apr_pstrdup(pool, s_kid);
	} else {
		/* calculate a unique key identifier (kid) by fingerprinting the key params */
		if (oidc_jose_hash_and_base64url_encode(pool, OIDC_JOSE_ALG_SHA256,
				key_params, key_params_len, &jwk_kid, err) == FALSE) {
			//oidc_jose_error(err, "oidc_jose_hash_and_base64urlencode failed");
			return FALSE;
		}
	}

	cjose_err cjose_err;
	if (cjose_jwk_set_kid(cjose_jwk, jwk_kid, _oidc_strlen(jwk_kid),
			&cjose_err) == FALSE) {
		oidc_jose_error(err, "cjose_jwk_set_kid failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	return TRUE;
}

/*
 * create an "oct" symmetric JWK
 */
oidc_jwk_t* oidc_jwk_create_symmetric_key(apr_pool_t *pool, const char *skid,
		const unsigned char *key, unsigned int key_len, apr_byte_t set_kid,
		oidc_jose_error_t *err) {

	cjose_err cjose_err;
	cjose_jwk_t *cjose_jwk = cjose_jwk_create_oct_spec(key, key_len,
			&cjose_err);
	if (cjose_jwk == NULL) {
		oidc_jose_error(err, "cjose_jwk_create_oct_spec failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		return NULL;
	}

	if (set_kid == TRUE) {
		if (oidc_jwk_set_or_generate_kid(pool, cjose_jwk, skid,
				(const char*) key, key_len, err) == FALSE) {
			cjose_jwk_release(cjose_jwk);
			return NULL;
		}
	}

	oidc_jwk_t *jwk = oidc_jwk_new(pool);
	jwk->cjose_jwk = cjose_jwk;
	jwk->kid = apr_pstrdup(pool, cjose_jwk_get_kid(jwk->cjose_jwk, &cjose_err));
	jwk->kty = cjose_jwk_get_kty(jwk->cjose_jwk, &cjose_err);
	return jwk;
}

/*
 * check if a string is an element of an array of strings
 */
static apr_byte_t oidc_jose_array_has_string(apr_array_header_t *haystack,
		const char *needle) {
	int i = 0;
	while (i < haystack->nelts) {
		if (_oidc_strcmp(APR_ARRAY_IDX(haystack, i, const char *), needle) == 0)
			return TRUE;
		i++;
	}
	return FALSE;
}

/*
 * return all supported signing algorithms
 */
apr_array_header_t* oidc_jose_jws_supported_algorithms(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 12, sizeof(const char*));
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RS256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RS384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RS512;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_PS256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_PS384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_PS512;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_HS256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_HS384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_HS512;
#if (OIDC_JOSE_EC_SUPPORT)
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_ES256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_ES384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_ES512;
#endif
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_NONE;
	return result;
}

/*
 * check if the provided signing algorithm is supported
 */
apr_byte_t oidc_jose_jws_algorithm_is_supported(apr_pool_t *pool,
		const char *alg) {
	return oidc_jose_array_has_string(oidc_jose_jws_supported_algorithms(pool),
			alg);
}

/*
 * return all supported content encryption key algorithms
 */
apr_array_header_t* oidc_jose_jwe_supported_algorithms(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 4, sizeof(const char*));
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RSA1_5;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_A128KW;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_A192KW;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_A256KW;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RSA_OAEP;
	return result;
}

/*
 * check if the provided content encryption key algorithm is supported
 */
apr_byte_t oidc_jose_jwe_algorithm_is_supported(apr_pool_t *pool,
		const char *alg) {
	return oidc_jose_array_has_string(oidc_jose_jwe_supported_algorithms(pool),
			alg);
}

/*
 * return all supported encryption algorithms
 */
apr_array_header_t* oidc_jose_jwe_supported_encryptions(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 5, sizeof(const char*));
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ENC_A128CBC_HS256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ENC_A192CBC_HS384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ENC_A256CBC_HS512;
#if (OIDC_JOSE_GCM_SUPPORT)
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ENC_A256GCM;
#endif
	return result;
}

/*
 * check if the provided encryption algorithm is supported
 */
apr_byte_t oidc_jose_jwe_encryption_is_supported(apr_pool_t *pool,
		const char *enc) {
	return oidc_jose_array_has_string(oidc_jose_jwe_supported_encryptions(pool),
			enc);
}

/*
 * get (optional) string from JWT
 */
apr_byte_t oidc_jose_get_string(apr_pool_t *pool, json_t *json,
		const char *claim_name, apr_byte_t is_mandatory, char **result,
		oidc_jose_error_t *err) {
	json_t *v = json_object_get(json, claim_name);
	if (v != NULL) {
		if (json_is_string(v)) {
			*result = apr_pstrdup(pool, json_string_value(v));
		} else if (is_mandatory) {
			oidc_jose_error(err,
					"mandatory JSON key \"%s\" was found but the type is not a string",
					claim_name);
			return FALSE;
		}
	} else if (is_mandatory) {
		oidc_jose_error(err, "mandatory JSON key \"%s\" could not be found",
				claim_name);
		return FALSE;
	}
	return TRUE;
}

/*
 * parse (optional) timestamp from payload
 */
static apr_byte_t oidc_jose_get_timestamp(apr_pool_t *pool, json_t *json,
		const char *claim_name, apr_byte_t is_mandatory, double *result,
		oidc_jose_error_t *err) {
	*result = OIDC_JWT_CLAIM_TIME_EMPTY;
	json_t *v = json_object_get(json, claim_name);
	if (v != NULL) {
		if (json_is_number(v)) {
			*result = json_number_value(v);
		} else if (is_mandatory) {
			oidc_jose_error(err,
					"mandatory JSON key \"%s\" was found but the type is not a number",
					claim_name);
			return FALSE;
		}
	} else if (is_mandatory) {
		oidc_jose_error(err, "mandatory JSON key \"%s\" could not be found",
				claim_name);
		return FALSE;
	}
	return TRUE;
}

#define OIDC_JOSE_JWT_ISS             "iss"
#define OIDC_JOSE_JWT_SUB             "sub"
#define OIDC_JOSE_JWT_EXP             "exp"
#define OIDC_JOSE_JWT_IAT             "iat"

/*
 * parse JWT payload
 */
static apr_byte_t oidc_jose_parse_payload(apr_pool_t *pool,
		const char *s_payload, size_t s_payload_len,
		oidc_jwt_payload_t *payload, oidc_jose_error_t *err) {

	/* decode the string in to a JSON structure into value->json */
	json_error_t json_error;
	payload->value.str = apr_pstrndup(pool, s_payload, s_payload_len);
	payload->value.json = json_loads(payload->value.str, 0, &json_error);

	/* check that we've actually got a JSON value back */
	if (payload->value.json == NULL) {
		oidc_jose_error(err, "JSON parsing (json_loads) failed: %s (%s)",
				json_error.text, s_payload);
		return FALSE;
	}

	/* check that the value is a JSON object */
	if (!json_is_object(payload->value.json)) {
		oidc_jose_error(err, "JSON value is not an object");
		return FALSE;
	}

	/* get the (optional) "iss" value from the JSON payload */
	oidc_jose_get_string(pool, payload->value.json, OIDC_JOSE_JWT_ISS, FALSE,
			&payload->iss,
			NULL);

	/* get the (optional) "exp" value from the JSON payload */
	oidc_jose_get_timestamp(pool, payload->value.json, OIDC_JOSE_JWT_EXP, FALSE,
			&payload->exp,
			NULL);

	/* get the (optional) "iat" value from the JSON payload */
	oidc_jose_get_timestamp(pool, payload->value.json, OIDC_JOSE_JWT_IAT, FALSE,
			&payload->iat,
			NULL);

	/* get the (optional) "sub" value from the JSON payload */
	oidc_jose_get_string(pool, payload->value.json, OIDC_JOSE_JWT_SUB, FALSE,
			&payload->sub,
			NULL);

	return TRUE;
}

/*
 * decrypt a JWT and return the plaintext
 */
static uint8_t* oidc_jwe_decrypt_impl(apr_pool_t *pool, cjose_jwe_t *jwe,
		apr_hash_t *keys, size_t *content_len, oidc_jose_error_t *err) {

	uint8_t *decrypted = NULL;
	oidc_jwk_t *jwk = NULL;
	apr_hash_index_t *hi;

	cjose_err cjose_err;
	cjose_header_t *hdr = cjose_jwe_get_protected(jwe);
	const char *kid = cjose_header_get(hdr, CJOSE_HDR_KID, &cjose_err);
	const char *alg = cjose_header_get(hdr, CJOSE_HDR_ALG, &cjose_err);

	if ((keys == NULL) || (apr_hash_count(keys) == 0)) {
		oidc_jose_error(err, "no decryption keys configured");
		return NULL;
	}

	if (kid != NULL) {

		jwk = apr_hash_get(keys, kid, APR_HASH_KEY_STRING);
		if (jwk != NULL) {
			if ((jwk->use == NULL)
					|| (_oidc_strcmp(jwk->use, OIDC_JOSE_JWK_ENC_STR) == 0)) {
				decrypted = cjose_jwe_decrypt(jwe, jwk->cjose_jwk, content_len,
						&cjose_err);
				if (decrypted == NULL)
					oidc_jose_error(err,
							"encrypted JWT could not be decrypted with kid %s: %s",
							kid, oidc_cjose_e2s(pool, cjose_err));
			} else {
				oidc_jose_error(err,
						"cannot use non-encryption (\"use=enc\") key with kid: %s",
						kid);
			}
		} else {
			oidc_jose_error(err, "could not find key with kid: %s", kid);
		}

	} else {

		for (hi = apr_hash_first(pool, keys); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, (void**) &jwk);

			if (jwk->kty != oidc_alg2kty(alg))
				continue;

			if ((jwk->use)
					&& (_oidc_strcmp(jwk->use, OIDC_JOSE_JWK_ENC_STR) != 0))
				continue;

			decrypted = cjose_jwe_decrypt(jwe, jwk->cjose_jwk, content_len,
					&cjose_err);
			if (decrypted != NULL)
				break;
		}

		if (decrypted == NULL)
			oidc_jose_error(err,
					"encrypted JWT could not be decrypted with any of the %d keys: error for last tried key is: %s",
					apr_hash_count(keys), oidc_cjose_e2s(pool, cjose_err));

	}

	return decrypted;
}

/*
 * decrypt a JSON Web Token
 */
apr_byte_t oidc_jwe_decrypt(apr_pool_t *pool, const char *input_json,
		apr_hash_t *keys, char **plaintext, int *plaintext_len,
		oidc_jose_error_t *err, apr_byte_t import_must_succeed) {
	cjose_err cjose_err;
	cjose_jwe_t *jwe = cjose_jwe_import(input_json, _oidc_strlen(input_json),
			&cjose_err);
	if (jwe != NULL) {
		size_t content_len = 0;
		uint8_t *decrypted = oidc_jwe_decrypt_impl(pool, jwe, keys,
				&content_len, err);
		if (decrypted != NULL) {
			*plaintext = apr_pcalloc(pool, content_len + 1);
			_oidc_memcpy(*plaintext, decrypted, content_len);
			(*plaintext)[content_len] = '\0';
			cjose_get_dealloc()(decrypted);
			if (plaintext_len)
				*plaintext_len = content_len;
		}
		cjose_jwe_release(jwe);
	} else if (import_must_succeed == FALSE) {
		*plaintext = apr_pstrdup(pool, input_json);
		if (plaintext_len)
			*plaintext_len = _oidc_strlen(input_json);
	} else {
		oidc_jose_error(err, "cjose_jwe_import failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
	}
	return (*plaintext != NULL);
}

#ifdef USE_LIBBROTLI

static apr_byte_t oidc_jose_brotli_compress(apr_pool_t *pool, const char *input,
		int input_len, char **output, int *output_len, oidc_jose_error_t *err) {
	size_t len = BrotliEncoderMaxCompressedSize(input_len);
	*output = apr_pcalloc(pool, len);
	if (BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
			BROTLI_MODE_TEXT, input_len, (const uint8_t*) input, &len,
			(uint8_t*) *output) != BROTLI_TRUE) {
		oidc_jose_error(err,
				"BrotliEncoderCompress failed: compression error or buffer too small");
		return FALSE;
	}
	*output_len = len;
	return TRUE;
}

static apr_byte_t oidc_jose_brotli_uncompress(apr_pool_t *pool,
		const char *input, int input_len, char **output, int *output_len,
		oidc_jose_error_t *err) {
	size_t len = 4 * input_len;
	*output = apr_pcalloc(pool, len);
	if (BrotliDecoderDecompress(input_len, (const uint8_t*) input, &len,
			(uint8_t*) *output) != BROTLI_DECODER_RESULT_SUCCESS) {
		oidc_jose_error(err,
				"BrotliDecoderDecompress failed: decompression error or buffer too small");
		return FALSE;
	}
	*output_len = len;
	return TRUE;
}

#elif USE_ZLIB

static apr_byte_t oidc_jose_zlib_compress(apr_pool_t *pool, const char *input,
		int input_len, char **output, int *output_len, oidc_jose_error_t *err) {
	z_stream zlib;
	zlib.zalloc = Z_NULL;
	zlib.zfree = Z_NULL;
	zlib.opaque = Z_NULL;
	zlib.next_in = (Bytef*) input;
	zlib.avail_in = input_len;
	*output = apr_pcalloc(pool, input_len * 2);
	zlib.next_out = (Bytef*) (*output);
	zlib.avail_out = input_len * 2;
	int deflate_status = Z_OK;

	deflateInit(&zlib, Z_BEST_COMPRESSION);

	deflate_status = deflate(&zlib, Z_FINISH);
	if (deflate_status != Z_STREAM_END) {
		oidc_jose_error(err, "deflate failed: %d", deflate_status);
		return FALSE;
	}

	if (deflateEnd(&zlib) != Z_OK) {
		oidc_jose_error(err, "deflateEnd failed");
		return FALSE;
	}

	*output_len = (int) zlib.total_out;

	return TRUE;
}

#define OIDC_CJOSE_UNCOMPRESS_CHUNK 8192

static apr_byte_t oidc_jose_zlib_uncompress(apr_pool_t *pool, const char *input,
		int input_len, char **output, int *output_len, oidc_jose_error_t *err) {
	z_stream zlib;
	zlib.zalloc = Z_NULL;
	zlib.zfree = Z_NULL;
	zlib.opaque = Z_NULL;
	zlib.avail_in = (uInt) input_len;
	zlib.next_in = (Bytef*) input;
	zlib.total_out = 0;
	size_t uncompLength = OIDC_CJOSE_UNCOMPRESS_CHUNK;
	char *uncomp = (char*) apr_pcalloc(pool, uncompLength + 1);

	inflateInit(&zlib);
	int done = 1;
	while (done) {
		int inflate_status;
		if (zlib.total_out >= OIDC_CJOSE_UNCOMPRESS_CHUNK) {
			char *uncomp2 = (char*) apr_pcalloc(pool,
					uncompLength + OIDC_CJOSE_UNCOMPRESS_CHUNK);
			_oidc_memcpy(uncomp2, uncomp, uncompLength);
			uncompLength += OIDC_CJOSE_UNCOMPRESS_CHUNK;
			uncomp = uncomp2;
		}
		zlib.next_out = (Bytef*) (uncomp + zlib.total_out);
		zlib.avail_out = (uInt) uncompLength - zlib.total_out;
		inflate_status = inflate(&zlib, Z_SYNC_FLUSH);
		if (inflate_status == Z_STREAM_END) {
			done = 0;
		} else if (inflate_status != Z_OK) {
			oidc_jose_error(err, "inflate failed: %d", inflate_status);
			inflateEnd(&zlib);
			return FALSE;
		}
	}

	if (inflateEnd(&zlib) != Z_OK) {
		oidc_jose_error(err, "inflateEnd failed");
		return FALSE;
	}

	*output_len = (int) zlib.total_out;
	*output = uncomp;

	return TRUE;
}

#endif

apr_byte_t oidc_jose_compress(apr_pool_t *pool, const char *input,
		int input_len, char **output, int *output_len, oidc_jose_error_t *err) {
#ifdef USE_LIBBROTLI
	return oidc_jose_brotli_compress(pool, input, input_len, output, output_len,
			err);
#elif USE_ZLIB
	return oidc_jose_zlib_compress(pool, input, input_len, output, output_len,
			err);
#else
	*output = apr_pmemdup(pool, input, input_len);
	*output_len = input_len;
	return TRUE;
#endif
}

apr_byte_t oidc_jose_uncompress(apr_pool_t *pool, const char *input,
		int input_len, char **output, int *output_len, oidc_jose_error_t *err) {
#ifdef USE_LIBBROTLI
	return oidc_jose_brotli_uncompress(pool, input, input_len, output,
			output_len, err);
#elif USE_ZLIB
	return oidc_jose_zlib_uncompress(pool, input, input_len, output, output_len,
			err);
#else
	*output = apr_pmemdup(pool, input, input_len);
	*output_len = input_len;
	return TRUE;
#endif
}

/*
 * parse and (optionally) decrypt a JSON Web Token
 */
apr_byte_t oidc_jwt_parse(apr_pool_t *pool, const char *input_json,
		oidc_jwt_t **j_jwt, apr_hash_t *keys, apr_byte_t compress,
		oidc_jose_error_t *err) {

	cjose_err cjose_err;
	char *s_json = NULL;

	if (oidc_jwe_decrypt(pool, input_json, keys, &s_json, NULL, err,
			FALSE) == FALSE)
		return FALSE;

	*j_jwt = oidc_jwt_new(pool, FALSE, FALSE);
	if (*j_jwt == NULL)
		return FALSE;
	oidc_jwt_t *jwt = *j_jwt;

	jwt->cjose_jws = cjose_jws_import(s_json, _oidc_strlen(s_json), &cjose_err);
	if (jwt->cjose_jws == NULL) {
		oidc_jose_error(err, "cjose_jws_import failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		oidc_jwt_destroy(jwt);
		*j_jwt = NULL;
		return FALSE;
	}

	cjose_header_t *hdr = cjose_jws_get_protected(jwt->cjose_jws);
	jwt->header.value.json = json_deep_copy((json_t*) hdr);
	char *str = json_dumps(jwt->header.value.json,
			JSON_PRESERVE_ORDER | JSON_COMPACT);
	jwt->header.value.str = apr_pstrdup(pool, str);
	free(str);

	jwt->header.alg = apr_pstrdup(pool,
			cjose_header_get(hdr, CJOSE_HDR_ALG, &cjose_err));
	jwt->header.enc = apr_pstrdup(pool,
			cjose_header_get(hdr, CJOSE_HDR_ENC, &cjose_err));
	jwt->header.kid = apr_pstrdup(pool,
			cjose_header_get(hdr, CJOSE_HDR_KID, &cjose_err));

	uint8_t *plaintext = NULL;
	size_t plaintext_len = 0;
	if (cjose_jws_get_plaintext(jwt->cjose_jws, &plaintext, &plaintext_len,
			&cjose_err) == FALSE) {
		oidc_jwt_destroy(jwt);
		*j_jwt = NULL;
		oidc_jose_error(err, "cjose_jws_get_plaintext failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	if (compress == TRUE) {
		char *payload = NULL;
		int payload_len = 0;
		if (oidc_jose_uncompress(pool, (char*) plaintext, plaintext_len,
				&payload, &payload_len, err) == FALSE) {
			oidc_jwt_destroy(jwt);
			*j_jwt = NULL;
			return FALSE;
		}
		plaintext = (uint8_t*) payload;
		plaintext_len = payload_len;
	}

	if (oidc_jose_parse_payload(pool, (const char*) plaintext, plaintext_len,
			&jwt->payload, err) == FALSE) {
		oidc_jwt_destroy(jwt);
		*j_jwt = NULL;
		return FALSE;
	}

	return TRUE;
}

/* destroy resources allocated for JWT */
void oidc_jwt_destroy(oidc_jwt_t *jwt) {
	if (jwt) {
		if (jwt->header.value.json) {
			json_decref(jwt->header.value.json);
			jwt->header.value.json = NULL;
			jwt->header.value.str = NULL;
		}
		if (jwt->payload.value.json) {
			json_decref(jwt->payload.value.json);
			jwt->payload.value.json = NULL;
			jwt->payload.value.str = NULL;
		}
		if (jwt->cjose_jws) {
			cjose_jws_release(jwt->cjose_jws);
			jwt->cjose_jws = NULL;
		}
	}
}

/*
 * sign JWT
 */
apr_byte_t oidc_jwt_sign(apr_pool_t *pool, oidc_jwt_t *jwt, oidc_jwk_t *jwk,
		apr_byte_t compress, oidc_jose_error_t *err) {

	cjose_header_t *hdr = (cjose_header_t*) jwt->header.value.json;

	if (jwt->header.alg)
		oidc_jwt_hdr_set(jwt, CJOSE_HDR_ALG, jwt->header.alg);
	if (jwt->header.kid)
		oidc_jwt_hdr_set(jwt, CJOSE_HDR_KID, jwt->header.kid);
	if (jwt->header.enc)
		oidc_jwt_hdr_set(jwt, CJOSE_HDR_ENC, jwt->header.enc);
	if (jwt->header.x5t)
		oidc_jwt_hdr_set(jwt, OIDC_JOSE_JWK_X5T_STR, jwt->header.x5t);

	if (jwt->cjose_jws)
		cjose_jws_release(jwt->cjose_jws);

	cjose_err cjose_err;
	char *plaintext = json_dumps(jwt->payload.value.json,
			JSON_PRESERVE_ORDER | JSON_COMPACT);

	char *s_payload = NULL;
	int payload_len = 0;
	if (compress == TRUE) {
		if (oidc_jose_compress(pool, (char*) plaintext, _oidc_strlen(plaintext),
				&s_payload, &payload_len, err) == FALSE) {
			free(plaintext);
			return FALSE;
		}
	} else {
		s_payload = plaintext;
		payload_len = _oidc_strlen(plaintext);
		jwt->payload.value.str = apr_pstrdup(pool, s_payload);
	}

	jwt->cjose_jws = cjose_jws_sign(jwk->cjose_jwk, hdr,
			(const uint8_t*) s_payload, payload_len, &cjose_err);
	free(plaintext);

	if (jwt->cjose_jws == NULL) {
		oidc_jose_error(err, "cjose_jws_sign failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	return TRUE;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000) || defined(LIBRESSL_VERSION_NUMBER)
EVP_MD_CTX * EVP_MD_CTX_new() {
	return malloc(sizeof(EVP_MD_CTX));
}
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
	if (ctx)
		free(ctx);
}
#endif

/*
 * encrypt JWT
 */
apr_byte_t oidc_jwt_encrypt(apr_pool_t *pool, oidc_jwt_t *jwe, oidc_jwk_t *jwk,
		const char *payload, int payload_len, char **serialized,
		oidc_jose_error_t *err) {

	cjose_header_t *hdr = (cjose_header_t*) jwe->header.value.json;

	if (jwe->header.alg)
		oidc_jwt_hdr_set(jwe, CJOSE_HDR_ALG, jwe->header.alg);
	if (jwe->header.kid)
		oidc_jwt_hdr_set(jwe, CJOSE_HDR_KID, jwe->header.kid);
	if (jwe->header.enc)
		oidc_jwt_hdr_set(jwe, CJOSE_HDR_ENC, jwe->header.enc);

	cjose_err cjose_err;
	cjose_jwe_t *cjose_jwe = cjose_jwe_encrypt(jwk->cjose_jwk, hdr,
			(const uint8_t*) payload, payload_len, &cjose_err);
	if (cjose_jwe == NULL) {
		oidc_jose_error(err, "cjose_jwe_encrypt failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	char *cser = cjose_jwe_export(cjose_jwe, &cjose_err);
	if (cser == NULL) {
		oidc_jose_error(err, "cjose_jwe_export failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}

	*serialized = apr_pstrdup(pool, cser);
	cjose_get_dealloc()(cser);
	cjose_jwe_release(cjose_jwe);

	return TRUE;
}

#define OIDC_JOSE_CJOSE_VERSION_DEPRECATED "0.4."

/*
 * check for a version of cjose < 0.5.0 that has a version of
 * cjose_jws_verify that resources after a verification failure
 */
apr_byte_t oidc_jose_version_deprecated(apr_pool_t *pool) {
	char *version = apr_pstrdup(pool, cjose_version());
	return (strstr(version, OIDC_JOSE_CJOSE_VERSION_DEPRECATED) == version);
}

/*
 * verify the signature on a JWT
 */
apr_byte_t oidc_jwt_verify(apr_pool_t *pool, oidc_jwt_t *jwt, apr_hash_t *keys,
		oidc_jose_error_t *err) {
	apr_byte_t rc = FALSE;

	oidc_jwk_t *jwk = NULL;
	apr_hash_index_t *hi;
	cjose_err cjose_err;

	if (jwt->header.kid != NULL) {

		jwk = apr_hash_get(keys, jwt->header.kid, APR_HASH_KEY_STRING);
		if (jwk != NULL) {
			rc = cjose_jws_verify(jwt->cjose_jws, jwk->cjose_jwk, &cjose_err);
			if (rc == FALSE) {
				oidc_jose_error(err, "cjose_jws_verify failed: %s",
						oidc_cjose_e2s(pool, cjose_err));
				if (oidc_jose_version_deprecated(pool))
					jwt->cjose_jws = NULL;
			}
		} else {
			oidc_jose_error(err, "could not find key with kid: %s",
					jwt->header.kid);
			rc = FALSE;
		}

	} else {

		for (hi = apr_hash_first(pool, keys); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, (void**) &jwk);
			if (jwk->kty == oidc_jwt_alg2kty(jwt)) {
				rc = cjose_jws_verify(jwt->cjose_jws, jwk->cjose_jwk,
						&cjose_err);
				if (rc == FALSE) {
					oidc_jose_error(err, "cjose_jws_verify failed: %s",
							oidc_cjose_e2s(pool, cjose_err));
					if (oidc_jose_version_deprecated(pool))
						jwt->cjose_jws = NULL;
				}
			}
			if ((rc == TRUE) || (jwt->cjose_jws == NULL))
				break;
		}

		if (rc == FALSE)
			oidc_jose_error(err,
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

/*
 * hash a byte sequence with the specified algorithm
 */
apr_byte_t oidc_jose_hash_bytes(apr_pool_t *pool, const char *s_digest,
		const unsigned char *input, unsigned int input_len,
		unsigned char **output, unsigned int *output_len,
		oidc_jose_error_t *err) {
	unsigned char md_value[EVP_MAX_MD_SIZE];

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_MD_CTX_init(ctx);

	const EVP_MD *evp_digest = NULL;
	if ((evp_digest = EVP_get_digestbyname(s_digest)) == NULL) {
		oidc_jose_error(err,
				"no OpenSSL digest algorithm found for algorithm \"%s\"",
				s_digest);
		return FALSE;
	}

	if (!EVP_DigestInit_ex(ctx, evp_digest, NULL)) {
		oidc_jose_error_openssl(err, "EVP_DigestInit_ex");
		return FALSE;
	}
	if (!EVP_DigestUpdate(ctx, input, input_len)) {
		oidc_jose_error_openssl(err, "EVP_DigestUpdate");
		return FALSE;
	}
	if (!EVP_DigestFinal(ctx, md_value, output_len)) {
		oidc_jose_error_openssl(err, "EVP_DigestFinal");
		return FALSE;
	}

	EVP_MD_CTX_free(ctx);

	*output = apr_pmemdup(pool, md_value, *output_len);

	return TRUE;
}

/*
 * return the OpenSSL hash algorithm associated with a specified JWT algorithm
 */
static char* oidc_jose_alg_to_openssl_digest(const char *alg) {
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS256) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS256) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS256) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES256) == 0)) {
		return LN_sha256;
	}
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS384) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS384) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)) {
		return LN_sha384;
	}
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS512) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS512) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS512) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES512) == 0)) {
		return LN_sha512;
	}
	return NULL;
}

/*
 * hash a string value with the specified algorithm
 */
apr_byte_t oidc_jose_hash_string(apr_pool_t *pool, const char *alg,
		const char *msg, char **hash, unsigned int *hash_len,
		oidc_jose_error_t *err) {

	char *s_digest = oidc_jose_alg_to_openssl_digest(alg);
	if (s_digest == NULL) {
		oidc_jose_error(err,
				"no OpenSSL digest algorithm name found for algorithm \"%s\"",
				alg);
		return FALSE;
	}

	return oidc_jose_hash_bytes(pool, s_digest, (const unsigned char*) msg,
			_oidc_strlen(msg), (unsigned char**) hash, hash_len, err);
}

/*
 * return hash length
 */
int oidc_jose_hash_length(const char *alg) {
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS256) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS256) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS256) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES256) == 0)) {
		return 32;
	}
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS384) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS384) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)) {
		return 48;
	}
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS512) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS512) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS512) == 0)
			|| (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES512) == 0)) {
		return 64;
	}
	return 0;
}

static apr_byte_t oidc_jwk_x509_read(apr_pool_t *pool, BIO *input, char **encoded_certificate, EVP_PKEY **pkey, X509 **rx509, oidc_jose_error_t *err) {
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
		if ((*pkey = X509_get_pubkey(x509)) == NULL) {
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

static apr_byte_t _oidc_jwk_rsa_key_to_jwk(apr_pool_t *pool, EVP_PKEY *pkey,
		oidc_jwk_t **oidc_jwk, char **fp, int *fp_len, oidc_jose_error_t *err) {
	apr_byte_t rv = FALSE;
	cjose_err cjose_err;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
	cjose_jwk_rsa_keyspec key_spec;

	_oidc_memset(&key_spec, 0, sizeof(cjose_jwk_rsa_keyspec));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &rsa_n);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &rsa_e);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &rsa_d);
#else
	/* get the RSA key from the public key struct */
	RSA *rsa = (RSA *)EVP_PKEY_get1_RSA(pkey);
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
		oidc_jose_error(err, "cjose_jwk_create_RSA_spec failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		goto end;
	}

	*fp_len = key_spec.nlen + key_spec.elen;
	*fp = apr_pcalloc(pool, *fp_len);
	memcpy(*fp, key_spec.n, key_spec.nlen);
	memcpy(*fp + key_spec.nlen, key_spec.e, key_spec.elen);

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

static apr_byte_t _oidc_jwk_ec_key_to_jwk(apr_pool_t *pool, EVP_PKEY *pkey,
		oidc_jwk_t **oidc_jwk, char **fp, int *fp_len, oidc_jose_error_t *err) {
	apr_byte_t rv = FALSE;
	cjose_err cjose_err;
	cjose_jwk_ec_keyspec ec_keyspec;
	int crv = 0;
	BIGNUM *ec_x = NULL, *ec_y = NULL, *ec_d = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	char curve_name[64];
	size_t curve_name_len = 0;

	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &ec_x);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &ec_y);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &ec_d);
	if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
			curve_name, sizeof(curve_name), &curve_name_len)) {
		oidc_jose_error_openssl(err,
				"EVP_PKEY_get_utf8_string_param(OSSL_PKEY_PARAM_GROUP_NAME)");
		goto end;
	}
	crv = OBJ_sn2nid(curve_name);
#else
	EC_KEY *eckey = (EC_KEY *)EVP_PKEY_get1_EC_KEY(pkey);
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
		goto end;
	}
	ec_d = (BIGNUM *)EC_KEY_get0_private_key(eckey);
	if (crv == 0) {
		oidc_jose_error_openssl(err, "EC_GROUP_get_curve_name");
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
		oidc_jose_error(err, "cjose_jwk_create_EC_spec failed: %s",
				oidc_cjose_e2s(pool, cjose_err));
		goto end;
	}

	apr_uint32_t b = htonl(crv);
	*fp_len = sizeof(b) + ec_keyspec.xlen + ec_keyspec.ylen;
	*fp = apr_pcalloc(pool, *fp_len);
	memcpy(*fp, &b, sizeof(b));
	memcpy(*fp + sizeof(b), ec_keyspec.x, ec_keyspec.xlen);
	memcpy(*fp + sizeof(b) + ec_keyspec.xlen, ec_keyspec.y,
			ec_keyspec.ylen);

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
apr_byte_t oidc_jwk_pem_bio_to_jwk(apr_pool_t *pool, BIO *input,
		const char *kid, oidc_jwk_t **oidc_jwk, int is_private_key,
		oidc_jose_error_t *err) {
	cjose_err cjose_err;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	int pkey_type = 0;
	apr_byte_t rv = FALSE;
	char *x509_pem_encoded_certificate = NULL;
	unsigned char *x509_bytes = NULL;
	int x509_cert_length = 0;
	char *fp = NULL;
	int fp_len = 0;

	*oidc_jwk = oidc_jwk_new(pool);

	if (is_private_key) {
		/* get the private key struct from the BIO */
		if ((pkey = PEM_read_bio_PrivateKey(input, NULL, NULL, NULL)) == NULL) {
			oidc_jose_error_openssl(err, "PEM_read_bio_PrivateKey");
			goto end;
		}
	} else {
		/* read public key */
		if ((pkey = PEM_read_bio_PUBKEY(input, NULL, NULL, NULL)) == NULL) {
			/* not a public key - reset the buffer */
			BIO_reset(input);

			if (oidc_jwk_x509_read(pool, input, &x509_pem_encoded_certificate,
					&pkey, &x509, err) == FALSE)
				goto end;

			/* certificate is present, fill the jwkset with certificate entries */
			/* populate first x5c certificate */
			(*oidc_jwk)->x5c = apr_array_make(pool, 1, sizeof(char*));
			if ((*oidc_jwk)->x5c == NULL) {
				oidc_jose_error(err, "apr_array_make failed");
				goto end;
			}
			APR_ARRAY_PUSH((*oidc_jwk)->x5c, char *) =
					x509_pem_encoded_certificate;

			/* populate thumbprints entries */
#if OPENSSL_VERSION_NUMBER < 0x000907000L
			// openssl below 0.9.7 does not allocate memory for you :o
			x509_cert_length = i2d_X509(x509, NULL);
			if (x509_cert_length <= 0){
				oidc_jose_error_openssl(err, "i2d_X509");
				goto end;
			}
			x509_bytes =  (unsigned char *)OPENSSL_malloc(pool, x509_cert_length + 1);
			const unsigned char *p = x509_bytes;
			x509_cert_length = i2d_X509(x509, &p);
#else
			x509_cert_length = i2d_X509(x509, &x509_bytes);
#endif
			if (x509_cert_length < 0) {
				oidc_jose_error_openssl(err, "i2d_X509");
				goto end;
			}

			/* populate x5t */
			oidc_jose_hash_and_base64url_encode(pool, OIDC_JOSE_ALG_SHA1,
					(const char*) x509_bytes, x509_cert_length,
					&(*oidc_jwk)->x5t, err);
			/* populate x5t_S256 */
			oidc_jose_hash_and_base64url_encode(pool, OIDC_JOSE_ALG_SHA256,
					(const char*) x509_bytes, x509_cert_length,
					&(*oidc_jwk)->x5t_S256, err);

			while (oidc_jwk_x509_read(pool, input,
					&x509_pem_encoded_certificate, NULL, NULL, err) == TRUE)
				APR_ARRAY_PUSH((*oidc_jwk)->x5c, char *) =
						x509_pem_encoded_certificate;
		}
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	pkey_type = EVP_PKEY_get_base_id(pkey);
#elif (OPENSSL_VERSION_NUMBER > 0x10100000)
	pkey_type = EVP_PKEY_base_id(pkey);
#else
	pkey_type = EVP_PKEY_type(pkey->type);
#endif

	switch (pkey_type) {
	case EVP_PKEY_RSA:
		if (_oidc_jwk_rsa_key_to_jwk(pool, pkey, oidc_jwk, &fp, &fp_len,
				err) == FALSE)
			goto end;
		break;
#if (OIDC_JOSE_EC_SUPPORT)
	case EVP_PKEY_EC:
		if (_oidc_jwk_ec_key_to_jwk(pool, pkey, oidc_jwk, &fp, &fp_len,
				err) == FALSE)
			goto end;
		break;
#endif
	default:
		oidc_jose_error(err, "unhandled key type: %d", pkey_type);
		break;
	}

	if (oidc_jwk_set_or_generate_kid(pool, (*oidc_jwk)->cjose_jwk, kid, fp,
			fp_len, err) == FALSE) {
		goto end;
	}

	(*oidc_jwk)->kid = apr_pstrdup(pool,
			cjose_jwk_get_kid((*oidc_jwk)->cjose_jwk, &cjose_err));
	(*oidc_jwk)->kty = cjose_jwk_get_kty((*oidc_jwk)->cjose_jwk, &cjose_err);

	rv = TRUE;

end:

	if (x509_bytes)
		OPENSSL_free(x509_bytes);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (x509)
		X509_free(x509);

	return rv;
}

/*
 * parse a PEM-formatted public or private key from the specified file
 */
static apr_byte_t oidc_jwk_parse_pem_key(apr_pool_t *pool, int is_private_key,
		const char *kid, const char *filename, oidc_jwk_t **jwk,
		oidc_jose_error_t *err) {
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

	if (oidc_jwk_pem_bio_to_jwk(pool, input, kid, jwk, is_private_key,
			err) == FALSE)
		goto end;

	rv = TRUE;

end:

	if (input)
		BIO_free(input);

	return rv;
}

#define OIDC_JOSE_CERT_BEGIN "-----BEGIN CERTIFICATE-----"
#define OIDC_JOSE_CERT_END   "-----END CERTIFICATE-----"

/*
 * parse a PEM-formatted key from a JSON object in to a cjose JWK object
 */
static apr_byte_t _oidc_jwk_parse_x5c(apr_pool_t *pool, json_t *json,
		cjose_jwk_t **jwk, oidc_jose_error_t *err) {

	apr_byte_t rv = FALSE;
	const char *kid = NULL;
	oidc_jwk_t *oidc_jwk = NULL;

	/* get the "x5c" array element from the JSON object */
	json_t *v = json_object_get(json, OIDC_JOSE_HDR_X5C);
	if (v == NULL) {
		oidc_jose_error(err, "JSON key \"%s\" could not be found",
				OIDC_JOSE_HDR_X5C);
		return FALSE;
	}
	if (!json_is_array(v)) {
		oidc_jose_error(err,
				"JSON key \"%s\" was found but its value is not a JSON array",
				OIDC_JOSE_HDR_X5C);
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
	const int len = 75;
	int i = 0;
	char *s = apr_psprintf(pool, "%s\n", OIDC_JOSE_CERT_BEGIN);
	while (i < _oidc_strlen(s_x5c)) {
		s = apr_psprintf(pool, "%s%s\n", s,
				apr_pstrmemdup(pool, s_x5c + i, len));
		i += len;
	}
	s = apr_psprintf(pool, "%s%s\n", s, OIDC_JOSE_CERT_END);

	BIO *input = NULL;

	/* put it in BIO memory */
	if ((input = BIO_new(BIO_s_mem())) == NULL) {
		oidc_jose_error_openssl(err, "memory allocation BIO_new/BIO_s_mem");
		return FALSE;
	}

	if (BIO_puts(input, s) <= 0) {
		BIO_free(input);
		oidc_jose_error_openssl(err, "BIO_puts");
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
apr_byte_t oidc_jwk_parse_pem_private_key(apr_pool_t *pool, const char *kid,
		const char *filename, oidc_jwk_t **jwk, oidc_jose_error_t *err) {
	return oidc_jwk_parse_pem_key(pool, TRUE, kid, filename, jwk, err);
}

/*
 * parse a PEM formatted public key file to a JWK
 */
apr_byte_t oidc_jwk_parse_pem_public_key(apr_pool_t *pool, const char *kid,
		const char *filename, oidc_jwk_t **jwk, oidc_jose_error_t *err) {
	return oidc_jwk_parse_pem_key(pool, FALSE, kid, filename, jwk, err);
}

/*
 * produce the string jwk representation from an oidc_jwk_t structure
 */
static char* internal_cjose_jwk_to_json(apr_pool_t *pool,
		const oidc_jwk_t *oidc_jwk, oidc_jose_error_t *oidc_err) {
	char *result = NULL, *cjose_jwk_json;
	cjose_err err;
	json_t *json = NULL, *temp = NULL;
	json_error_t json_error;
	int i = 0;
	void *iter = NULL;

	if (!oidc_jwk) {
		oidc_jose_error(oidc_err,
				"internal_cjose_jwk_to_json failed: NULL oidc_jwk");
		return NULL;
	}

	// get current 
	cjose_jwk_json = cjose_jwk_to_json(oidc_jwk->cjose_jwk, TRUE, &err);

	if (cjose_jwk_json == NULL) {
		oidc_jose_error(oidc_err, "cjose_jwk_to_json failed: %s",
				oidc_cjose_e2s(pool, err));
		goto to_json_cleanup;
	}

	temp = json_loads(cjose_jwk_json, 0, &json_error);
	if (!temp) {
		oidc_jose_error(oidc_err, "json_loads failed");
		goto to_json_cleanup;
	}

	json = json_object();

	if (oidc_jwk->use)
		json_object_set_new(json, OIDC_JOSE_JWK_USE_STR,
				json_string(oidc_jwk->use));

	iter = json_object_iter(temp);
	while (iter) {
		json_object_set(json, json_object_iter_key(iter),
				json_object_iter_value(iter));
		iter = json_object_iter_next(temp, iter);
	}
	json_decref(temp);
	temp = NULL;

	// set x5c
	if ((oidc_jwk->x5c != NULL) && (oidc_jwk->x5c->nelts > 0)) {
		temp = json_array();
		if (temp == NULL) {
			oidc_jose_error(oidc_err, "json_array failed");
			goto to_json_cleanup;
		}
		for (i = 0; i < oidc_jwk->x5c->nelts; i++) {
			if (json_array_append_new(temp,
					json_string(APR_ARRAY_IDX(oidc_jwk->x5c, i, const char *)))
					== -1) {
				oidc_jose_error(oidc_err, "json_array_append failed");
				goto to_json_cleanup;
			}
		}
		json_object_set_new(json, OIDC_JOSE_JWK_X5C_STR, temp);
	}

	// set x5t#256
	if (oidc_jwk->x5t_S256 != NULL)
		json_object_set_new(json, OIDC_JOSE_JWK_X5T256_STR,
				json_string(oidc_jwk->x5t_S256));

	// set x5t
	if (oidc_jwk->x5t != NULL)
		json_object_set_new(json, OIDC_JOSE_JWK_X5T_STR,
				json_string(oidc_jwk->x5t));

	// generate the string ...
	result = json_dumps(json,
			JSON_ENCODE_ANY | JSON_COMPACT | JSON_PRESERVE_ORDER);
	if (!result) {
		oidc_jose_error(oidc_err, "json_dumps failed");
		goto to_json_cleanup;
	}

to_json_cleanup:

	if (cjose_jwk_json)
		free(cjose_jwk_json);
	if (json)
		json_decref(json);

	return result;
}
