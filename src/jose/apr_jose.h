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

#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>

#include "../json/apr_json.h"

/* a parsed JWT "element", header or payload, JSON+raw*/
typedef struct apr_jwt_value_t {
	apr_json_value_t *json;
	char *str;
} apr_jwt_value_t;

/* a parsed JWT header */
typedef struct apr_jwt_header_t {
	apr_jwt_value_t value;
	char *alg;
	char *kid;
} apr_jwt_header_t;

/* parsed JWT payload */
typedef struct apr_jwt_payload_t {
	apr_jwt_value_t value;
	char *iss;
	char *sub;
	apr_time_t exp;
	apr_time_t iat;
} apr_jwt_payload_t;

/* parsed JWT signature */
typedef struct apr_jwt_signature_t {
	unsigned char *bytes;
	int length;
} apr_jwt_signature_t;

/* parsed JWT */
typedef struct apr_jwt_t {
	apr_jwt_header_t header;
	apr_jwt_payload_t payload;
	apr_jwt_signature_t signature;
	char *message;
} apr_jwt_t;

/* JWK key type */
typedef enum apr_jwk_type_e {
	APR_JWK_KEY_RSA,
} apr_jwk_type_e;

/* parsed RSA JWK key */
typedef struct apr_jwk_key_rsa_t {
	unsigned char *modulus;
	int modulus_len;
	unsigned char *exponent;
	int exponent_len;
} apr_jwk_key_rsa_t;

/* parsed JWK key */
typedef struct apr_jwk_t {
	apr_jwt_value_t value;
	apr_jwk_type_e type;
	union {
		apr_jwk_key_rsa_t *rsa;
	} key;
} apr_jwk_t;

/* helper */
int apr_jwt_base64url_decode(request_rec *r, char **dst, const char *src,
		int padding);

/* JWT */
apr_byte_t apr_jwt_parse_string(request_rec *r, apr_jwt_value_t *value,
		const char *claim_name, char **result);
apr_byte_t apr_jwt_parse(request_rec *r, const char *s_json, apr_jwt_t **j_jwk);

/* JWK */
apr_byte_t apr_jwk_parse_json(request_rec *r, apr_json_value_t *j_json,
		const char *s_json, apr_jwk_t **j_jwk);
apr_byte_t apr_jwk_parse_string(request_rec *r, const char *s_json,
		apr_jwk_t **j_jwk);

/* JWS */
apr_byte_t apr_jws_signature_is_hmac(request_rec *r, apr_jwt_t *jwt);
apr_byte_t apr_jws_signature_is_rsa(request_rec *r, apr_jwt_t *jwt);
apr_byte_t apr_jws_verify_hmac(request_rec *r, apr_jwt_t *jwt,
		const char *secret);
apr_byte_t apr_jws_verify_rsa(request_rec *r, apr_jwt_t *jwt,
		apr_jwk_t *jwk);

#endif /* _APR_JWT_H_ */
