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
 * JSON Object Signing and Encryption
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#ifndef MOD_AUTH_OPENIDC_JOSE_H_
#define MOD_AUTH_OPENIDC_JOSE_H_

#include <stdint.h>
#include "apr_pools.h"
#include "apr_tables.h"
#include "apr_hash.h"
#include "apr_strings.h"

#include "jansson.h"

#include "cjose/cjose.h"

/* indicate support for OpenSSL version dependent features */
#define OIDC_JOSE_EC_SUPPORT  OPENSSL_VERSION_NUMBER >= 0x1000100f
#define OIDC_JOSE_GCM_SUPPORT OPENSSL_VERSION_NUMBER >= 0x1000100f

/* error message element sizes */
#define OIDC_JOSE_ERROR_TEXT_LENGTH    200
#define OIDC_JOSE_ERROR_SOURCE_LENGTH   80
#define OIDC_JOSE_ERROR_FUNCTION_LENGTH 80

/* struct for returning errors to the caller */
typedef struct {
	char source[OIDC_JOSE_ERROR_SOURCE_LENGTH];
	int line;
	char function[OIDC_JOSE_ERROR_FUNCTION_LENGTH];
	char text[OIDC_JOSE_ERROR_TEXT_LENGTH];
} oidc_jose_error_t;

/*
 * error handling functions
 */
void _oidc_jose_error_set(oidc_jose_error_t *, const char *, const int,
		const char *, const char *msg, ...);
#define oidc_jose_error(err, msg, ...) _oidc_jose_error_set(err, __FILE__, __LINE__, __FUNCTION__, msg, ##__VA_ARGS__)
#define oidc_jose_error_openssl(err, msg, ...) _oidc_jose_error_set(err, __FILE__, __LINE__, __FUNCTION__, "%s() failed: %s", msg, ERR_error_string(ERR_get_error(), NULL), ##__VA_ARGS__)
#define oidc_jose_e2s(pool, err) apr_psprintf(pool, "[%s:%d: %s]: %s\n", err.source, err.line, err.function, err.text)
#define oidc_cjose_e2s(pool, cjose_err) apr_psprintf(pool, "%s [file: %s, function: %s, line: %ld]\n", cjose_err.message, cjose_err.file, cjose_err.function, cjose_err.line)

/*
 * helper functions
 */

/* helpers to find out about the supported ala/enc algorithms */
apr_array_header_t *oidc_jose_jws_supported_algorithms(apr_pool_t *pool);
apr_byte_t oidc_jose_jws_algorithm_is_supported(apr_pool_t *pool,
		const char *alg);
apr_array_header_t *oidc_jose_jwe_supported_algorithms(apr_pool_t *pool);
apr_byte_t oidc_jose_jwe_algorithm_is_supported(apr_pool_t *pool,
		const char *alg);
apr_array_header_t *oidc_jose_jwe_supported_encryptions(apr_pool_t *pool);
apr_byte_t oidc_jose_jwe_encryption_is_supported(apr_pool_t *pool,
		const char *enc);

/* hash helpers */
apr_byte_t oidc_jose_hash_string(apr_pool_t *pool, const char *alg,
		const char *msg, char **hash, unsigned int *hash_len,
		oidc_jose_error_t *err);
int oidc_jose_hash_length(const char *alg);
apr_byte_t oidc_jose_hash_bytes(apr_pool_t *pool, const char *s_digest,
		const unsigned char *input, unsigned int input_len,
		unsigned char **output, unsigned int *output_len,
		oidc_jose_error_t *err);

/* return a string claim value from a JSON object */
apr_byte_t oidc_jose_get_string(apr_pool_t *pool, json_t *json,
		const char *claim_name, apr_byte_t is_mandatory, char **result,
		oidc_jose_error_t *err);

/* a parsed JWK/JWT JSON object */
typedef struct oidc_jose_json_t {
	/* parsed JSON struct representation */
	json_t *json;
	/* string representation */
	char *str;
} oidc_jose_json_t;

/*
 * JSON Web Key handling
 */

/* parsed JWK */
typedef struct oidc_jwk_t {
	/* key type */
	int kty;
	/* key identifier */
	char *kid;
	/* cjose JWK structure */
	cjose_jwk_t *cjose_jwk;
} oidc_jwk_t;

/* decrypt a JWT */
apr_byte_t oidc_jwe_decrypt(apr_pool_t *pool, const char *input_json,
		apr_hash_t *keys, char **s_json, oidc_jose_error_t *err, apr_byte_t import_must_succeed);
/* parse a JSON string to a JWK struct */
oidc_jwk_t *oidc_jwk_parse(apr_pool_t *pool, const char *s_json,
		oidc_jose_error_t *err);
/* parse a JSON object in to a JWK struct */
apr_byte_t oidc_jwk_parse_json(apr_pool_t *pool, json_t *json, oidc_jwk_t **jwk,
		oidc_jose_error_t *err);
/* convert a JWK struct to a JSON string */
apr_byte_t oidc_jwk_to_json(apr_pool_t *pool, oidc_jwk_t *jwk, char **s_json,
		oidc_jose_error_t *err);
/* destroy resources allocated for a JWK struct */
void oidc_jwk_destroy(oidc_jwk_t *jwk);
/* destroy a list of JWKs structs */
void oidc_jwk_list_destroy(apr_pool_t *pool, apr_hash_t *key);
/* create an "oct" symmetric JWK */
oidc_jwk_t *oidc_jwk_create_symmetric_key(apr_pool_t *pool, const char *kid,
		const unsigned char *key, unsigned int key_len, apr_byte_t set_kid, oidc_jose_error_t *err);

/* parse an X.509 PEM formatted certificate file with an RSA public key to a JWK struct */
apr_byte_t oidc_jwk_parse_rsa_public_key(apr_pool_t *pool, const char *kid,
		const char *filename, oidc_jwk_t **jwk, oidc_jose_error_t *err);
/* parse an X.509 PEM formatted RSA private key file to a JWK */
apr_byte_t oidc_jwk_parse_rsa_private_key(apr_pool_t *pool,
		const char *filename, oidc_jwk_t **jwk, oidc_jose_error_t *err);

/*
 * JSON Web Token handling
 */

/* represents NULL timestamp */
#define OIDC_JWT_CLAIM_TIME_EMPTY -1

/* a parsed JWT header */
typedef struct oidc_jwt_hdr_t {
	/* parsed header value */
	oidc_jose_json_t value;
	/* JWT "alg" claim value; signing algorithm */
	char *alg;
	/* JWT "kid" claim value; key identifier */
	char *kid;
	/* JWT "enc" claim value; encryption algorithm */
	char *enc;
} oidc_jwt_hdr_t;

/* parsed JWT payload */
typedef struct oidc_jwt_payload_t {
	/* parsed payload value */
	oidc_jose_json_t value;
	/* JWT "iss" claim value; JWT issuer */
	char *iss;
	/* JWT "sub" claim value; subject/principal */
	char *sub;
	/* parsed JWT "exp" claim value; token expiry */
	double exp;
	/* parsed JWT "iat" claim value; issued-at timestamp */
	double iat;
} oidc_jwt_payload_t;

/* parsed JWT */
typedef struct oidc_jwt_t {
	/* parsed JWT header */
	oidc_jwt_hdr_t header;
	/* parsed JWT payload */
	oidc_jwt_payload_t payload;
	/* cjose JWS structure */
	cjose_jws_t *cjose_jws;
} oidc_jwt_t;

/* parse a string into a JSON Web Token struct and (optionally) decrypt it */
apr_byte_t oidc_jwt_parse(apr_pool_t *pool, const char *s_json,
		oidc_jwt_t **j_jwt, apr_hash_t *keys, oidc_jose_error_t *err);
/* sign a JWT with a JWK */
apr_byte_t oidc_jwt_sign(apr_pool_t *pool, oidc_jwt_t *jwt, oidc_jwk_t *jwk,
		oidc_jose_error_t *err);
/* verify a JWT a key in a list of JWKs */
apr_byte_t oidc_jwt_verify(apr_pool_t *pool, oidc_jwt_t *jwt, apr_hash_t *keys,
		oidc_jose_error_t *err);
/* perform compact serialization on a JWT and return the resulting string */
char *oidc_jwt_serialize(apr_pool_t *pool, oidc_jwt_t *jwt,
		oidc_jose_error_t *err);
/* encrypt JWT */
apr_byte_t oidc_jwt_encrypt(apr_pool_t *pool, oidc_jwt_t *jwe, oidc_jwk_t *jwk,
		const char *payload, char **serialized, oidc_jose_error_t *err);

/* create a new JWT */
oidc_jwt_t *oidc_jwt_new(apr_pool_t *pool, int create_header,
		int create_payload);
/* destroy resources allocated for JWT */
void oidc_jwt_destroy(oidc_jwt_t *);

/* get a header value from a JWT */
const char *oidc_jwt_hdr_get(oidc_jwt_t *jwt, const char *key);
/* return the key type of a JWT */
int oidc_jwt_alg2kty(oidc_jwt_t *jwt);
/* return the key size for an algorithm */
int oidc_alg2keysize(const char *alg);

#endif /* MOD_AUTH_OPENIDC_JOSE_H_ */
