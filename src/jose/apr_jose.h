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
 * JSON Web Tokens Signing and Encryption
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#ifndef _APR_JWT_H_
#define _APR_JWT_H_

#include "apr_pools.h"

#include "../json/apr_json.h"

/*
 * JSON Web Token handling
 */

/* a parsed JWT "element", header or payload */
typedef struct apr_jwt_value_t {
	/* parsed JSON struct representation */
	apr_json_value_t *json;
	/* string representation */
	char *str;
} apr_jwt_value_t;

/* a parsed JWT header */
typedef struct apr_jwt_header_t {
	/* parsed header value */
	apr_jwt_value_t value;
	/* JWT "alg" claim value; signing algorithm */
	char *alg;
	/* JWT "kid" claim value; key identifier */
	char *kid;
} apr_jwt_header_t;

/* parsed JWT payload */
typedef struct apr_jwt_payload_t {
	/* parsed payload value */
	apr_jwt_value_t value;
	/* JWT "iss" claim value; JWT issuer */
	char *iss;
	/* JWT "sub" claim value; subject/principal */
	char *sub;
	/* parsed JWT "exp" claim value; token expiry */
	apr_time_t exp;
	/* parsed JWT "iat" claim value; issued-at timestamp */
	apr_time_t iat;
} apr_jwt_payload_t;

/* parsed JWT signature */
typedef struct apr_jwt_signature_t {
	/* raw (base64url-decoded) signature value */
	unsigned char *bytes;
	/* length of the raw signature value */
	int length;
} apr_jwt_signature_t;

/* parsed JWT */
typedef struct apr_jwt_t {
	/* parsed JWT header */
	apr_jwt_header_t header;
	/* parsed JWT payload */
	apr_jwt_payload_t payload;
	/* decoded JWT signature */
	apr_jwt_signature_t signature;
	/* base64url-encoded header+payload (for signature verification purposes) */
	char *message;
} apr_jwt_t;

/* helper */
int apr_jwt_base64url_decode(apr_pool_t *pool, char **dst, const char *src,
		int padding);

/* return a string claim value from a JSON Web Token */
apr_byte_t apr_jwt_get_string(apr_pool_t *pool, apr_jwt_value_t *value,
		const char *claim_name, char **result);
/* parse a string in to a JSON Web Token struct */
apr_byte_t apr_jwt_parse(apr_pool_t *pool, const char *s_json, apr_jwt_t **j_jwt);

/*
 * JSON Web Key handling
 */

/* JWK key type */
typedef enum apr_jwk_type_e {
	/* RSA JWT key type */
	APR_JWK_KEY_RSA,
} apr_jwk_type_e;

/* parsed RSA JWK key */
typedef struct apr_jwk_key_rsa_t {
	/* (binary) RSA modulus */
	unsigned char *modulus;
	/* length of the binary RSA modulus */
	int modulus_len;
	/* (binary) RSA exponent */
	unsigned char *exponent;
	/* length of the binary RSA exponent */
	int exponent_len;
} apr_jwk_key_rsa_t;

/* parsed JWK key */
typedef struct apr_jwk_t {
	/* parsed JWK/JSON value */
	apr_jwt_value_t value;
	/* type of JWK key */
	apr_jwk_type_e type;
	/* union/pointer to parsed JWK key */
	union {
		apr_jwk_key_rsa_t *rsa;
	} key;
} apr_jwk_t;

/* parse a JSON representation in to a JSON Web Key struct (also storing the string representation */
apr_byte_t apr_jwk_parse_json(apr_pool_t *pool, apr_json_value_t *j_json,
		const char *s_json, apr_jwk_t **j_jwk);
/* parse a string in to a JSON Web Key struct */
apr_byte_t apr_jwk_parse_string(apr_pool_t *pool, const char *s_json,
		apr_jwk_t **j_jwk);

/*
 * JSON Web Signature handling
 */

/* check if the signature on a JWT is of type HMAC */
apr_byte_t apr_jws_signature_is_hmac(apr_pool_t *pool, apr_jwt_t *jwt);
/* check if the signature on a JWT is of type RSA */
apr_byte_t apr_jws_signature_is_rsa(apr_pool_t *pool, apr_jwt_t *jwt);
/* verify the HMAC signature on a JWT */
apr_byte_t apr_jws_verify_hmac(apr_pool_t *pool, apr_jwt_t *jwt,
		const char *secret);
/* verify the RSA signature on a JWT */
apr_byte_t apr_jws_verify_rsa(apr_pool_t *pool, apr_jwt_t *jwt, apr_jwk_t *jwk);

#endif /* _APR_JWT_H_ */
