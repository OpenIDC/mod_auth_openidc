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
 * JSON Web Token handling
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <apr_base64.h>

#include "apr_jose.h"

/*
 * check if a string is an element of an array of strings
 */
apr_byte_t apr_jwt_array_has_string(apr_array_header_t *haystack,
		const char *needle) {
	int i;
	for (i = 0; i < haystack->nelts; i++) {
		if (apr_strnatcmp(((const char**) haystack->elts)[i], needle) == 0)
			return TRUE;
	}
	return FALSE;
}

/*
 * base64url encode a string
 */
int apr_jwt_base64url_encode(apr_pool_t *pool, char **dst, const char *src,
		int src_len, int padding) {
	if ((src == NULL) || (src_len <= 0))
		return -1;
	int enc_len = apr_base64_encode_len(src_len);
	char *enc = apr_palloc(pool, enc_len);
	apr_base64_encode(enc, (const char *) src, src_len);
	int i = 0;
	while (enc[i] != '\0') {
		if (enc[i] == '+')
			enc[i] = '-';
		if (enc[i] == '/')
			enc[i] = '_';
		if (enc[i] == '=') {
			if (padding == 1) {
				enc[i] = ',';
			} else {
				enc[i] = '\0';
				enc_len--;
			}
		}
		i++;
	}
	*dst = enc;
	return enc_len;
}

/*
 * base64url decode a string
 */
int apr_jwt_base64url_decode(apr_pool_t *pool, char **dst, const char *src,
		int padding) {
	if (src == NULL)
		return -1;
	char *dec = apr_pstrdup(pool, src);
	int i = 0;
	while (dec[i] != '\0') {
		if (dec[i] == '-')
			dec[i] = '+';
		if (dec[i] == '_')
			dec[i] = '/';
		if (dec[i] == ',')
			dec[i] = '=';
		i++;
	}
	if (padding == 1) {
		switch (strlen(dec) % 4) {
		case 0:
			break;
		case 2:
			dec = apr_pstrcat(pool, dec, "==", NULL);
			break;
		case 3:
			dec = apr_pstrcat(pool, dec, "=", NULL);
			break;
		default:
			return 0;
		}
	}
	int dlen = apr_base64_decode_len(dec);
	*dst = apr_palloc(pool, dlen);
	return apr_base64_decode(*dst, dec);
}

/*
 * parse JSON object from string in to JWT value
 */
static apr_byte_t apr_jwt_base64url_decode_object(apr_pool_t *pool,
		const char *str, apr_jwt_value_t *value) {

	/* base64url-decode the string representation into value->str */
	if (apr_jwt_base64url_decode(pool, &value->str, str, 1) < 0)
		return FALSE;

	/* decode the string in to a JSON structure into value->json */
	if (apr_json_decode(&value->json, value->str, strlen(value->str),
			pool) != APR_SUCCESS)
		return FALSE;

	/* check that we've actually got a JSON value back */
	if (value->json == NULL)
		return FALSE;

	/* check that the value is a JSON object */
	if (value->json->type != APR_JSON_OBJECT)
		return FALSE;

	return TRUE;
}

/*
 * get (optional) string from JWT
 */
apr_byte_t apr_jwt_get_string(apr_pool_t *pool, apr_jwt_value_t *value,
		const char *claim_name, char **result) {
	apr_json_value_t *v = apr_hash_get(value->json->value.object, claim_name,
			APR_HASH_KEY_STRING);
	if ((v != NULL) && (v->type == APR_JSON_STRING)) {
		*result = apr_pstrdup(pool, v->value.string.p);
	} else {
		*result = NULL;
	}
	return TRUE;
}

/*
 * parse (optional) timestamp from payload
 */
static apr_byte_t apr_jwt_parse_timestamp(apr_pool_t *pool,
		apr_jwt_value_t *value, const char *claim_name, apr_time_t *result) {
	apr_json_value_t *v = apr_hash_get(value->json->value.object, claim_name,
	APR_HASH_KEY_STRING);
	if ((v != NULL) && (v->type == APR_JSON_LONG)) {
		*result = apr_time_from_sec(v->value.lnumber);
	} else {
		*result = -1;
	}
	return TRUE;
}

/*
 * parse a JWT header
 */
static apr_byte_t apr_jwt_parse_header(apr_pool_t *pool, const char *s_header,
		apr_jwt_header_t *header) {

	/* decode the JWT JSON header */
	if (apr_jwt_base64url_decode_object(pool, s_header, &header->value) == FALSE)
		return FALSE;

	/* parse the (optional) signing algorithm */
	apr_jwt_get_string(pool, &header->value, "alg", &header->alg);

	/* check that the mandatory algorithm was set */
	if (header->alg == NULL)
		return FALSE;

	/* parse the (optional) kid */
	apr_jwt_get_string(pool, &header->value, "kid", &header->kid);

	/* parse the (optional) enc */
	apr_jwt_get_string(pool, &header->value, "enc", &header->enc);

	return TRUE;
}

/*
 * parse JWT payload
 */
static apr_byte_t apr_jwt_parse_payload(apr_pool_t *pool, const char *s_payload,
		apr_jwt_payload_t *payload) {

	/* decode the JWT JSON payload */
	if (apr_jwt_base64url_decode_object(pool, s_payload,
			&payload->value) == FALSE)
		return FALSE;

	/* get the (optional) "issuer" value from the JSON payload */
	apr_jwt_get_string(pool, &payload->value, "iss", &payload->iss);

	/* get the (optional) "exp" value from the JSON payload */
	apr_jwt_parse_timestamp(pool, &payload->value, "exp", &payload->exp);

	/* get the (optional) "iat" value from the JSON payload */
	apr_jwt_parse_timestamp(pool, &payload->value, "iat", &payload->iat);

	/* get the (optional) "sub" value from the JSON payload */
	apr_jwt_get_string(pool, &payload->value, "sub", &payload->sub);

	return TRUE;
}

/*
 * parse JWT signature
 */
static apr_byte_t apr_jwt_parse_signature(apr_pool_t *pool,
		const char *s_signature, apr_jwt_signature_t *signature) {

	signature->length = apr_jwt_base64url_decode(pool,
			(char **) &signature->bytes, s_signature, 1);

	return (signature->length > 0);
}

/*
 * parse a JWT that uses compact serialization (i.e. elements separated by dots) in to an array of strings
 */
static apr_array_header_t *apr_jwt_compact_deserialize(apr_pool_t *pool,
		const char *str) {
	apr_array_header_t *result = apr_array_make(pool, 6, sizeof(const char*));
	char *s = apr_pstrdup(pool, str);
	while (s) {
		char *p = strchr(s, '.');
		if (p != NULL) *p = '\0';
		*(const char**) apr_array_push(result) = apr_pstrdup(pool, s);
		if (p == NULL) break;
		s = ++p;
	}
	return result;
}

/*
 * parse a JSON Web Token
 */
apr_byte_t apr_jwt_parse(apr_pool_t *pool, const char *s_json,
		apr_jwt_t **j_jwt, apr_hash_t *private_keys) {

	*j_jwt = apr_pcalloc(pool, sizeof(apr_jwt_t));
	apr_jwt_t *jwt = *j_jwt;

	apr_array_header_t *unpacked = apr_jwt_compact_deserialize(pool, s_json);

	/* parse the header fields */
	if (apr_jwt_parse_header(pool, ((const char**) unpacked->elts)[0],
			&jwt->header) == FALSE)
		return FALSE;

	if (apr_jwe_is_encrypted_jwt(pool, &jwt->header)) {
		char *decrypted = NULL;
		if ((apr_jwe_decrypt_jwt(pool, &jwt->header, unpacked, private_keys,
				&decrypted) == TRUE) && (decrypted != NULL)) {
			apr_array_clear(unpacked);
			unpacked = apr_jwt_compact_deserialize(pool,
					(const char *) decrypted);
			/* parse the nested header fields */
			if (apr_jwt_parse_header(pool, ((const char**) unpacked->elts)[0],
					&jwt->header) == FALSE)
				return FALSE;
		}
	}

	/* concat the base64url-encoded payload to the base64url-encoded header for signature verification purposes */
	jwt->message = apr_pstrcat(pool, ((const char**) unpacked->elts)[0], ".",
			((const char**) unpacked->elts)[1], NULL);

	/* parse the payload fields */
	if (apr_jwt_parse_payload(pool, ((const char**) unpacked->elts)[1],
			&jwt->payload) == FALSE)
		return FALSE;

	/* remainder is the signature */
	if (apr_jwt_parse_signature(pool, ((const char**) unpacked->elts)[2],
			&jwt->signature) == FALSE)
		return FALSE;

	return TRUE;
}
