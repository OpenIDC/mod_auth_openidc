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

// TODO: complete separation
//       a) remove references to OIDC_DEBUG
//       b) remove references to request_rec (use only pool), so no printouts (comparable to apr_json_decode/encode)

#ifndef OIDC_DEBUG
#define OIDC_DEBUG APLOG_DEBUG
#endif

/*
 * base64url decode a string
 * TODO: sort out with oidc_util function
 */
int apr_jwt_base64url_decode(request_rec *r, char **dst, const char *src,
		int padding) {
	if (src == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_base64url_decode: not decoding anything; src=NULL");
		return -1;
	}
	char *dec = apr_pstrdup(r->pool, src);
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
			dec = apr_pstrcat(r->pool, dec, "==", NULL);
			break;
		case 3:
			dec = apr_pstrcat(r->pool, dec, "=", NULL);
			break;
		default:
			return 0;
		}
	}
	int dlen = apr_base64_decode_len(dec);
	*dst = apr_palloc(r->pool, dlen);
	return apr_base64_decode(*dst, dec);
}

/*
 * parse object from string from
 */
static apr_byte_t apr_jwt_base64url_decode_object(request_rec *r,
		const char *str, apr_jwt_value_t *value) {

	// TODO: error checking/handling
	apr_jwt_base64url_decode(r, &value->str, str, 1);

	/* decode the string in to a JSON structure */
	if (apr_json_decode(&value->json, value->str, strlen(value->str),
			r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwt_decode_object: apr_json_decode on JWT failed: %s",
				value->str);
		return FALSE;
	}

	/* check that we've actually got a JSON value back */
	if (value->json == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwt_decode_object: apr_json_decode on JWT did not return valid JSON: %s",
				value->str);
		return FALSE;

	}

	/* check that the value is a JSON object */
	if (value->json->type != APR_JSON_OBJECT) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwt_decode_object: JWT value did not contain a JSON object: %s",
				value->str);
		return FALSE;
	}

	return TRUE;
}

/*
 * parse (optional) string from JWT
 */
apr_byte_t apr_jwt_parse_string(request_rec *r, apr_jwt_value_t *value,
		const char *claim_name, char **result) {
	*result = NULL;
	apr_json_value_t *v = apr_hash_get(value->json->value.object, claim_name,
	APR_HASH_KEY_STRING);
	if (v != NULL) {
		if (v->type == APR_JSON_STRING) {
			*result = apr_pstrdup(r->pool, v->value.string.p);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"apr_jwt_parse_string: JWT value contains a \"%s\" value but it is not a string: %s",
					claim_name, value->str);
		}
	}
	return TRUE;
}

/*
 * parse (optional) timestamp from payload
 */
static apr_byte_t apr_jwt_parse_timestamp(request_rec *r,
		apr_jwt_value_t *value, const char *claim_name, apr_time_t *result) {
	*result = -1;
	apr_json_value_t *v = apr_hash_get(value->json->value.object, claim_name,
	APR_HASH_KEY_STRING);
	if (v != NULL) {
		if (v->type == APR_JSON_LONG) {
			*result = apr_time_from_sec(v->value.lnumber);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"apr_jwt_parse_timestamp: JWT value contains a \"%s\" value but it is not a long: %s",
					claim_name, value->str);
		}
	}
	return TRUE;
}

/*
 * parse a JWT header
 */
static apr_byte_t apr_jwt_parse_header(request_rec *r, const char *s_header,
		apr_jwt_header_t *header) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"apr_jwt_parse_header: entering (%s)", s_header);

	/* decode the JWT JSON header */
	if (apr_jwt_base64url_decode_object(r, s_header, &header->value) == FALSE)
		return FALSE;

	/* parse the (optional) signing algorithm */
	apr_jwt_parse_string(r, &header->value, "alg", &header->alg);

	/* check that the mandatory algorithm was set */
	// TODO: do supported algorithm check here?
	if (header->alg == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwt_parse_header: JWT header did not contain an \"alg\" string: %s",
				header->value.str);
		return FALSE;
	}

	/* parse the (optional) kid */
	apr_jwt_parse_string(r, &header->value, "kid", &header->kid);

	return TRUE;
}

/*
 * parse JWT payload
 */
static apr_byte_t apr_jwt_parse_payload(request_rec *r, const char *s_payload,
		apr_jwt_payload_t *payload) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"apr_jwt_parse_payload: entering: %s", s_payload);

	/* decode the JWT JSON payload */
	if (apr_jwt_base64url_decode_object(r, s_payload, &payload->value) == FALSE)
		return FALSE;

	/* get the (optional) "issuer" value from the JSON payload */
	if (apr_jwt_parse_string(r, &payload->value, "iss", &payload->iss) == FALSE)
		return FALSE;

	/* get the (optional) "exp" value from the JSON payload */
	if (apr_jwt_parse_timestamp(r, &payload->value, "exp",
			&payload->exp) == FALSE)
		return FALSE;

	/* get the (optional) "iat" value from the JSON payload */
	if (apr_jwt_parse_timestamp(r, &payload->value, "iat",
			&payload->iat) == FALSE)
		return FALSE;

	/* get the (optional) "sub" value from the JSON payload */
	if (apr_jwt_parse_string(r, &payload->value, "sub", &payload->sub) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * parse JWT signature
 */
static apr_byte_t apr_jwt_parse_signature(request_rec *r,
		const char *s_signature, apr_jwt_signature_t *signature) {

	// TODO: error checking/handling
	signature->length = apr_jwt_base64url_decode(r, (char **) &signature->bytes,
			s_signature, 1);

	return TRUE;
}

/*
 * parse a JSON Web Token
 */
apr_byte_t apr_jwt_parse(request_rec *r, const char *s_json, apr_jwt_t **j_jwt) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "apr_jwt_parse: entering");

	*j_jwt = apr_pcalloc(r->pool, sizeof(apr_jwt_t));
	apr_jwt_t *jwt = *j_jwt;

	/* find the header */
	char *s = apr_pstrdup(r->pool, s_json);
	char *p = strchr(s, '.');
	if (p == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwt_parse: could not find first \".\" in JWT: %s", s_json);
		return FALSE;
	}
	*p = '\0';

	/* store the base64url-encoded header for signature verification purposes */
	jwt->message = s;

	/* parse the header fields */
	if (apr_jwt_parse_header(r, s, &jwt->header) == FALSE)
		return FALSE;

	/* find the payload */
	s = ++p;
	p = strchr(s, '.');
	if (p == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwt_parse: could not find second \".\" in JWT: %s",
				s_json);
		return FALSE;
	}
	*p = '\0';

	/* concat the base64url-encoded payload to the base64url-encoded header for signature verification purposes */
	jwt->message = apr_pstrcat(r->pool, jwt->message, ".", s, NULL);

	/* parse the payload fields */
	if (apr_jwt_parse_payload(r, s, &jwt->payload) == FALSE)
		return FALSE;

	/* remainder is the signature */
	s = ++p;
	if (apr_jwt_parse_signature(r, s, &jwt->signature) == FALSE)
		return FALSE;

	return TRUE;
}
