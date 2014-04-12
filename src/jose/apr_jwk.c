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

#include "apr_jose.h"

// TODO: complete separation
//       a) remove references to OIDC_DEBUG
//       b) remove references to request_rec (use only pool), so no printouts (comparable to apr_json_decode/encode)

#ifndef OIDC_DEBUG
#define OIDC_DEBUG APLOG_DEBUG
#endif

/*
 * parse an RSA JWK
 */
static apr_byte_t apr_jwk_parse_rsa(request_rec *r, apr_jwk_t *jwk) {

	/* allocated space and set key type */
	jwk->type = APR_JWK_KEY_RSA;
	jwk->key.rsa = apr_pcalloc(r->pool, sizeof(apr_jwk_key_rsa_t));

	/* parse the modulus */
	char *s_modulus = NULL;
	apr_jwt_get_string(r, &jwk->value, "n", &s_modulus);
	if (s_modulus == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwk_parse_rsa: JWK object did not contain an \"n\" string");
		return FALSE;
	}
	jwk->key.rsa->modulus_len = apr_jwt_base64url_decode(r,
			(char **) &jwk->key.rsa->modulus, s_modulus, 1);

	/* parse the exponent */
	char *s_exponent = NULL;
	apr_jwt_get_string(r, &jwk->value, "e", &s_exponent);
	if (s_exponent == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwk_parse_rsa: JWK object did not contain an \"e\" string");
		return FALSE;
	}
	jwk->key.rsa->exponent_len = apr_jwt_base64url_decode(r,
			(char **) &jwk->key.rsa->exponent, s_exponent, 1);

	/* that went well */
	return TRUE;
}

/*
 * parse JSON JWK
 */
apr_byte_t apr_jwk_parse_json(request_rec *r, apr_json_value_t *j_json,
		const char *s_json, apr_jwk_t **j_jwk) {

	/* check that we've actually got a JSON value back */
	if (j_json == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwk_parse: JWK JSON value is NULL, abort parsing");
		return FALSE;
	}

	/* check that the value is a JSON object */
	if (j_json->type != APR_JSON_OBJECT) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwk_parse: JWK JSON value did not contain a JSON object, abort parsing");
		return FALSE;
	}

	/* allocate memory for the JWK */
	*j_jwk = apr_pcalloc(r->pool, sizeof(apr_jwk_t));
	apr_jwk_t *jwk = *j_jwk;

	/* set the raw JSON/string representations */
	jwk->value.json = j_json;
	jwk->value.str = (char *) s_json;

	/* get the (optional) key type */
	char *kty = NULL;
	if (apr_jwt_get_string(r, &jwk->value, "kty", &kty) == FALSE)
		return FALSE;

	/* kty is mandatory */
	if (kty == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwk_parse: JWK JSON value did not contain a \"kty\" string, abort parsing");
		return FALSE;
	}

	/* parse the key */
	if (apr_strnatcmp(kty, "RSA") == 0) {
		return apr_jwk_parse_rsa(r, jwk);
	}

	/* no known key type found */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"apr_jwk_parse: unsupported key type (%s)", kty);
	return FALSE;
}

/*
 * parse (JSON) string representation of JWK
 */
apr_byte_t apr_jwk_parse_string(request_rec *r, const char *s_json,
		apr_jwk_t **j_jwk) {

	apr_json_value_t *j_value = NULL;

	/* decode the string in to a JSON structure */
	if (apr_json_decode(&j_value, s_json, strlen(s_json),
			r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"apr_jwk_parse: apr_json_decode on JWK failed: %s", s_json);
		return FALSE;
	}

	return apr_jwk_parse_json(r, j_value, s_json, j_jwk);
}
