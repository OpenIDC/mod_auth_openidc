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
 * Copyright (C) 2017-2024 ZmartZone Holding BV
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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"

#define OIDC_PROTO_DPOP_JWT_TYP "dpop+jwt"

apr_byte_t oidc_proto_dpop_use_nonce(request_rec *r, oidc_cfg_t *cfg, json_t *j_result, apr_hash_t *response_hdrs,
				     const char *url, const char *method, const char *access_token, char **dpop) {
	apr_byte_t rv = FALSE;
	char *dpop_nonce = NULL;

	json_t *j_error = json_object_get(j_result, OIDC_PROTO_ERROR);
	if ((j_error == NULL) || (!json_is_string(j_error)) ||
	    (_oidc_strcmp(json_string_value(j_error), OIDC_PROTO_DPOP_USE_NONCE) != 0))
		goto end;

	/* try again with a DPoP nonce provided by the server */
	dpop_nonce = (char *)apr_hash_get(response_hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING);
	if (dpop_nonce == NULL) {
		oidc_error(r, "error is \"%s\" but no \"%s\" header found", OIDC_PROTO_DPOP_USE_NONCE,
			   OIDC_HTTP_HDR_DPOP_NONCE);
		goto end;
	}

	rv = oidc_proto_dpop_create(r, cfg, url, method, access_token, dpop_nonce, dpop);

end:

	oidc_debug(r, "leave: %d, dpop=%s", rv, *dpop ? "true" : "false");

	return rv;
}

/*
 * generate a DPoP proof for the specified URL/method/access_token
 */
apr_byte_t oidc_proto_dpop_create(request_rec *r, oidc_cfg_t *cfg, const char *url, const char *method,
				  const char *access_token, const char *nonce, char **dpop) {
	apr_byte_t rv = FALSE;
	oidc_jwt_t *jwt = NULL;
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	char *jti = NULL;
	cjose_err cjose_err;
	char *s_jwk = NULL;
	char *ath = NULL;

	oidc_debug(r, "enter");

	if (oidc_proto_jwt_create_from_first_pkey(r, cfg, &jwk, &jwt, TRUE) == FALSE)
		goto end;

	json_object_set_new(jwt->header.value.json, OIDC_CLAIM_TYP, json_string(OIDC_PROTO_DPOP_JWT_TYP));
	s_jwk = cjose_jwk_to_json(jwk->cjose_jwk, 0, &cjose_err);
	cjose_header_set_raw(jwt->header.value.json, OIDC_CLAIM_JWK, s_jwk, &cjose_err);

	oidc_util_generate_random_string(r, &jti, OIDC_PROTO_JWT_JTI_LEN);
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_JTI, json_string(jti));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_HTM, json_string(method));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_HTU, json_string(url));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_IAT, json_integer(apr_time_sec(apr_time_now())));

	if (access_token != NULL) {
		if (oidc_jose_hash_and_base64url_encode(r->pool, OIDC_JOSE_ALG_SHA256, access_token,
							_oidc_strlen(access_token), &ath, &err) == FALSE) {
			oidc_error(r, "oidc_jose_hash_and_base64url_encode failed: %s", oidc_jose_e2s(r->pool, err));
			goto end;
		}
		json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_ATH, json_string(ath));
	}

	if (nonce != NULL)
		json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_NONCE, json_string(nonce));

	if (oidc_proto_jwt_sign_and_serialize(r, jwk, jwt, dpop) == FALSE)
		goto end;

	rv = TRUE;

end:

	if (s_jwk)
		cjose_get_dealloc()(s_jwk);

	if (jwt)
		oidc_jwt_destroy(jwt);

	return rv;
}
