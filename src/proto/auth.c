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

#include "cfg/parse.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"

/*
 * setup for an endpoint call without authentication
 */
static apr_byte_t oidc_proto_endpoint_auth_none(request_rec *r, const char *client_id, apr_table_t *params) {
	apr_table_set(params, OIDC_PROTO_CLIENT_ID, client_id);
	return TRUE;
}

/*
 * setup for an endpoint call with OIDC client_secret_basic authentication
 */
static apr_byte_t oidc_proto_endpoint_client_secret_basic(request_rec *r, const char *client_id,
							  const char *client_secret, char **basic_auth_str) {
	oidc_debug(r, "enter");
	if (client_secret == NULL) {
		oidc_error(r, "no client secret is configured");
		return FALSE;
	}
	*basic_auth_str =
	    apr_psprintf(r->pool, "%s:%s", oidc_http_url_encode(r, client_id), oidc_http_url_encode(r, client_secret));

	return TRUE;
}

/*
 * setup for an endpoint call with OIDC client_secret_post authentication
 */
static apr_byte_t oidc_proto_endpoint_client_secret_post(request_rec *r, const char *client_id,
							 const char *client_secret, apr_table_t *params) {
	oidc_debug(r, "enter");
	if (client_secret == NULL) {
		oidc_error(r, "no client secret is configured");
		return FALSE;
	}
	apr_table_set(params, OIDC_PROTO_CLIENT_ID, client_id);
	apr_table_set(params, OIDC_PROTO_CLIENT_SECRET, client_secret);
	return TRUE;
}

/*
 * helper function to create a JWT assertion for endpoint authentication
 */
static apr_byte_t oidc_proto_jwt_create(request_rec *r, const char *client_id, const char *audience, oidc_jwt_t **out) {

	*out = oidc_jwt_new(r->pool, TRUE, TRUE);
	oidc_jwt_t *jwt = *out;

	char *jti = NULL;
	oidc_util_generate_random_string(r, &jti, OIDC_PROTO_JWT_JTI_LEN);

	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_ISS, json_string(client_id));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_SUB, json_string(client_id));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_AUD, json_string(audience));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_JTI, json_string(jti));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_EXP, json_integer(apr_time_sec(apr_time_now()) + 60));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_IAT, json_integer(apr_time_sec(apr_time_now())));

	return TRUE;
}

/*
 * helper function to add a JWT assertion to the HTTP request as endpoint authentication
 */
static apr_byte_t oidc_proto_jwt_sign_and_add(request_rec *r, apr_table_t *params, oidc_jwt_t *jwt, oidc_jwk_t *jwk) {
	char *cser = NULL;

	if (oidc_proto_jwt_sign_and_serialize(r, jwk, jwt, &cser) == FALSE)
		return FALSE;

	apr_table_setn(params, OIDC_PROTO_CLIENT_ASSERTION_TYPE, OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER);
	apr_table_set(params, OIDC_PROTO_CLIENT_ASSERTION, cser);

	return TRUE;
}

#define OIDC_PROTO_JWT_ASSERTION_SYMMETRIC_ALG CJOSE_HDR_ALG_HS256

/*
 * create a JWT assertion signed with the client secret and add it to the HTTP request as endpoint authentication
 */
static apr_byte_t oidc_proto_endpoint_auth_client_secret_jwt(request_rec *r, const char *client_id,
							     const char *client_secret, const char *audience,
							     apr_table_t *params) {
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;

	oidc_debug(r, "enter");

	if (oidc_proto_jwt_create(r, client_id, audience, &jwt) == FALSE)
		return FALSE;

	oidc_jwk_t *jwk = oidc_jwk_create_symmetric_key(r->pool, NULL, (const unsigned char *)client_secret,
							_oidc_strlen(client_secret), FALSE, &err);
	if (jwk == NULL) {
		oidc_error(r, "parsing of client secret into JWK failed: %s", oidc_jose_e2s(r->pool, err));
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	jwt->header.alg = apr_pstrdup(r->pool, OIDC_PROTO_JWT_ASSERTION_SYMMETRIC_ALG);

	oidc_proto_jwt_sign_and_add(r, params, jwt, jwk);

	oidc_jwt_destroy(jwt);
	oidc_jwk_destroy(jwk);

	return TRUE;
}

/*
 * helper function that returns the bearer access token as the endpoint authentication method if configured
 */
static apr_byte_t oidc_proto_endpoint_access_token_bearer(request_rec *r, oidc_cfg_t *cfg,
							  const char *bearer_access_token, char **bearer_auth_str) {

	apr_byte_t rv = TRUE;

	if (bearer_access_token != NULL) {
		*bearer_auth_str = apr_psprintf(r->pool, "%s", bearer_access_token);
	} else {
		oidc_error(r, "endpoint auth method set to bearer access token but no token is provided");
		rv = FALSE;
	}

	return rv;
}

#define OIDC_PROTO_JWT_ASSERTION_ASYMMETRIC_ALG CJOSE_HDR_ALG_RS256

/*
 * create a JWT assertion signed with the configured private key and add it to the HTTP request as endpoint
 * authentication
 */
static apr_byte_t oidc_proto_endpoint_auth_private_key_jwt(request_rec *r, oidc_cfg_t *cfg, const char *client_id,
							   const apr_array_header_t *client_keys, const char *audience,
							   apr_table_t *params) {
	oidc_jwt_t *jwt = NULL;
	oidc_jwk_t *jwk = NULL;
	const oidc_jwk_t *jwk_pub = NULL;

	oidc_debug(r, "enter");

	if (oidc_proto_jwt_create(r, client_id, audience, &jwt) == FALSE)
		return FALSE;

	if ((client_keys != NULL) && (client_keys->nelts > 0)) {
		jwk = oidc_util_key_list_first(client_keys, CJOSE_JWK_KTY_RSA, OIDC_JOSE_JWK_SIG_STR);
		if (jwk && jwk->x5t)
			jwt->header.x5t = apr_pstrdup(r->pool, jwk->x5t);
	} else if ((oidc_cfg_private_keys_get(cfg) != NULL) && (oidc_cfg_private_keys_get(cfg)->nelts > 0)) {
		jwk =
		    oidc_util_key_list_first(oidc_cfg_private_keys_get(cfg), CJOSE_JWK_KTY_RSA, OIDC_JOSE_JWK_SIG_STR);
		jwk_pub =
		    oidc_util_key_list_first(oidc_cfg_public_keys_get(cfg), CJOSE_JWK_KTY_RSA, OIDC_JOSE_JWK_SIG_STR);
		if (jwk_pub && jwk_pub->x5t)
			// populate x5t; at least required for Microsoft Entra ID / Azure AD
			jwt->header.x5t = apr_pstrdup(r->pool, jwk_pub->x5t);
	}

	if (jwk == NULL) {
		oidc_error(r, "no private signing keys have been configured to use for private_key_jwt client "
			      "authentication (" OIDCPrivateKeyFiles ")");
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	jwt->header.kid = apr_pstrdup(r->pool, jwk->kid);
	jwt->header.alg = apr_pstrdup(r->pool, CJOSE_HDR_ALG_RS256);

	oidc_proto_jwt_sign_and_add(r, params, jwt, jwk);

	oidc_jwt_destroy(jwt);

	return TRUE;
}

/*
 * add the configured token endpoint authentication method to the request (or return it in the *_auth_str parameters)
 */
apr_byte_t oidc_proto_token_endpoint_auth(request_rec *r, oidc_cfg_t *cfg, const char *token_endpoint_auth,
					  const char *client_id, const char *client_secret,
					  const apr_array_header_t *client_keys, const char *audience,
					  apr_table_t *params, const char *bearer_access_token, char **basic_auth_str,
					  char **bearer_auth_str) {

	oidc_debug(r, "token_endpoint_auth=%s", token_endpoint_auth);

	if (client_id == NULL) {
		oidc_debug(r, "no client ID set: assume we don't need to authenticate");
		return TRUE;
	}

	// default is client_secret_basic, but only if a client_secret is set,
	// otherwise we are a public client
	if ((token_endpoint_auth == NULL) && (client_secret != NULL))
		token_endpoint_auth = OIDC_PROTO_CLIENT_SECRET_BASIC;

	if ((token_endpoint_auth == NULL) || (_oidc_strcmp(token_endpoint_auth, OIDC_PROTO_ENDPOINT_AUTH_NONE) == 0)) {
		oidc_debug(
		    r,
		    "no client secret is configured or the token endpoint auth method was set to \"%s\"; calling the "
		    "token endpoint without client authentication; only public clients are supported",
		    OIDC_PROTO_ENDPOINT_AUTH_NONE);
		return oidc_proto_endpoint_auth_none(r, client_id, params);
	}

	// if no client_secret is set and we don't authenticate using private_key_jwt,
	// we can only be a public client since the other methods require a client_secret
	if ((client_secret == NULL) && (_oidc_strcmp(token_endpoint_auth, OIDC_PROTO_PRIVATE_KEY_JWT) != 0)) {
		oidc_debug(r, "no client secret set and not using private_key_jwt, assume we are a public client");
		return oidc_proto_endpoint_auth_none(r, client_id, params);
	}

	if (_oidc_strcmp(token_endpoint_auth, OIDC_PROTO_CLIENT_SECRET_BASIC) == 0)
		return oidc_proto_endpoint_client_secret_basic(r, client_id, client_secret, basic_auth_str);

	if (_oidc_strcmp(token_endpoint_auth, OIDC_PROTO_CLIENT_SECRET_POST) == 0)
		return oidc_proto_endpoint_client_secret_post(r, client_id, client_secret, params);

	if (_oidc_strcmp(token_endpoint_auth, OIDC_PROTO_CLIENT_SECRET_JWT) == 0)
		return oidc_proto_endpoint_auth_client_secret_jwt(r, client_id, client_secret, audience, params);

	if (_oidc_strcmp(token_endpoint_auth, OIDC_PROTO_PRIVATE_KEY_JWT) == 0)
		return oidc_proto_endpoint_auth_private_key_jwt(r, cfg, client_id, client_keys, audience, params);

	if (_oidc_strcmp(token_endpoint_auth, OIDC_PROTO_BEARER_ACCESS_TOKEN) == 0) {
		return oidc_proto_endpoint_access_token_bearer(r, cfg, bearer_access_token, bearer_auth_str);
	}

	oidc_error(r, "uhm, shouldn't be here...");

	return FALSE;
}
