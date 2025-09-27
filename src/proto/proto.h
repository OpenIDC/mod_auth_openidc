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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
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

#ifndef _MOD_AUTH_OPENIDC_PROTO_H_
#define _MOD_AUTH_OPENIDC_PROTO_H_

#include "cfg/provider.h"
#include "jose.h"

#define OIDC_PROTO_ISS "iss"
#define OIDC_PROTO_CODE "code"
#define OIDC_PROTO_CLIENT_ID "client_id"
#define OIDC_PROTO_CLIENT_SECRET "client_secret"
#define OIDC_PROTO_CLIENT_ASSERTION "client_assertion"
#define OIDC_PROTO_CLIENT_ASSERTION_TYPE "client_assertion_type"
#define OIDC_PROTO_ACCESS_TOKEN "access_token"
#define OIDC_PROTO_ID_TOKEN "id_token"
#define OIDC_PROTO_STATE "state"
#define OIDC_PROTO_GRANT_TYPE "grant_type"
#define OIDC_PROTO_REDIRECT_URI "redirect_uri"
#define OIDC_PROTO_CODE_VERIFIER "code_verifier"
#define OIDC_PROTO_CODE_CHALLENGE "code_challenge"
#define OIDC_PROTO_CODE_CHALLENGE_METHOD "code_challenge_method"
#define OIDC_PROTO_SCOPE "scope"
#define OIDC_PROTO_REFRESH_TOKEN "refresh_token"
#define OIDC_PROTO_TOKEN_TYPE "token_type"
#define OIDC_PROTO_TOKEN_TYPE_HINT "token_type_hint"
#define OIDC_PROTO_TOKEN "token"
#define OIDC_PROTO_EXPIRES_IN "expires_in"
#define OIDC_PROTO_RESPONSE_TYPE "response_type"
#define OIDC_PROTO_RESPONSE_MODE "response_mode"
#define OIDC_PROTO_NONCE "nonce"
#define OIDC_PROTO_PROMPT "prompt"
#define OIDC_PROTO_LOGIN_HINT "login_hint"
#define OIDC_PROTO_ID_TOKEN_HINT "id_token_hint"
#define OIDC_PROTO_REQUEST_URI "request_uri"
#define OIDC_PROTO_REQUEST_OBJECT "request"
#define OIDC_PROTO_SESSION_STATE "session_state"
#define OIDC_PROTO_ACTIVE "active"
#define OIDC_PROTO_LOGOUT_TOKEN "logout_token"

#define OIDC_PROTO_RESPONSE_TYPE_CODE "code"
#define OIDC_PROTO_RESPONSE_TYPE_IDTOKEN "id_token"
#define OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN "id_token token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN "code id_token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN "code token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN "code id_token token"
#define OIDC_PROTO_RESPONSE_TYPE_TOKEN "token"

#define OIDC_PROTO_RESPONSE_MODE_QUERY "query"
#define OIDC_PROTO_RESPONSE_MODE_FRAGMENT "fragment"
#define OIDC_PROTO_RESPONSE_MODE_FORM_POST "form_post"

#define OIDC_PROTO_SCOPE_OPENID "openid"
#define OIDC_PROTO_PROMPT_NONE "none"
#define OIDC_PROTO_ERROR "error"
#define OIDC_PROTO_ERROR_DESCRIPTION "error_description"
#define OIDC_PROTO_REALM "realm"

#define OIDC_PROTO_ERR_INVALID_TOKEN "invalid_token"
#define OIDC_PROTO_ERR_INVALID_REQUEST "invalid_request"

#define OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE "authorization_code"
#define OIDC_PROTO_GRANT_TYPE_REFRESH_TOKEN "refresh_token"

#define OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#define OIDC_PROTO_CLIENT_SECRET_BASIC "client_secret_basic"
#define OIDC_PROTO_CLIENT_SECRET_POST "client_secret_post"
#define OIDC_PROTO_CLIENT_SECRET_JWT "client_secret_jwt"
#define OIDC_PROTO_PRIVATE_KEY_JWT "private_key_jwt"
#define OIDC_PROTO_BEARER_ACCESS_TOKEN "bearer_access_token"
#define OIDC_PROTO_ENDPOINT_AUTH_NONE "none"

#define OIDC_PROTO_BEARER "Bearer"
#define OIDC_PROTO_BASIC "Basic"
#define OIDC_PROTO_DPOP "DPoP"
#define OIDC_PROTO_DPOP_USE_NONCE "use_dpop_nonce"

/* nonce bytes length */
#define OIDC_PROTO_NONCE_LENGTH 32

typedef json_t oidc_proto_state_t;

// profile.c
oidc_auth_request_method_t oidc_proto_profile_auth_request_method_get(oidc_provider_t *provider);
const char *oidc_proto_profile_token_endpoint_auth_aud(oidc_provider_t *provider);
const char *oidc_proto_profile_revocation_endpoint_auth_aud(oidc_provider_t *provider, const char *val);
const apr_array_header_t *oidc_proto_profile_id_token_aud_values_get(apr_pool_t *pool, oidc_provider_t *provider);
const oidc_proto_pkce_t *oidc_proto_profile_pkce_get(oidc_provider_t *provider);
oidc_dpop_mode_t oidc_proto_profile_dpop_mode_get(oidc_provider_t *provider);
int oidc_proto_profile_response_require_iss_get(oidc_provider_t *provider);

// auth.c
apr_byte_t oidc_proto_token_endpoint_auth(request_rec *r, oidc_cfg_t *cfg, const char *token_endpoint_auth,
					  const char *token_endpoint_auth_alg, const char *client_id,
					  const char *client_secret, const apr_array_header_t *client_keys,
					  const char *audience, apr_table_t *params, const char *bearer_access_token,
					  char **basic_auth_str, char **bearer_auth_str);

// discovery.c
apr_byte_t oidc_proto_discovery_account_based(request_rec *r, oidc_cfg_t *cfg, const char *acct, char **issuer);
apr_byte_t oidc_proto_discovery_url_based(request_rec *r, oidc_cfg_t *cfg, const char *url, char **issuer);

// dpop.c
apr_byte_t oidc_proto_dpop_create(request_rec *r, oidc_cfg_t *cfg, const char *url, const char *method,
				  const char *access_token, const char *nonce, char **dpop);
apr_byte_t oidc_proto_dpop_use_nonce(request_rec *r, oidc_cfg_t *cfg, json_t *j_result, apr_hash_t *response_hdrs,
				     const char *url, const char *method, const char *access_token, char **dpop);

// id_token.c
apr_byte_t oidc_proto_idtoken_parse(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider, const char *id_token,
				    const char *nonce, oidc_jwt_t **jwt, apr_byte_t is_code_flow);
apr_byte_t oidc_proto_idtoken_validate_aud_and_azp(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
						   oidc_jwt_payload_t *id_token_payload);
// non-static for test.c
apr_byte_t oidc_proto_idtoken_validate_access_token(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
						    const char *response_type, const char *access_token);
apr_byte_t oidc_proto_idtoken_validate_code(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
					    const char *response_type, const char *code);
apr_byte_t oidc_proto_idtoken_validate_nonce(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
					     const char *nonce, oidc_jwt_t *jwt);

// jwks.c
apr_byte_t oidc_proto_jwks_uri_keys(request_rec *r, oidc_cfg_t *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri,
				    int ssl_validate_server, apr_hash_t *keys, apr_byte_t *force_refresh);

// jwt.c

#define OIDC_PROTO_JWT_JTI_LEN 16

apr_byte_t oidc_proto_jwt_verify(request_rec *r, oidc_cfg_t *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri,
				 int ssl_validate_server, apr_hash_t *symmetric_keys, const char *alg);
apr_byte_t oidc_proto_jwt_validate(request_rec *r, oidc_jwt_t *jwt, const char *iss, apr_byte_t exp_is_mandatory,
				   apr_byte_t iat_is_mandatory, int iat_slack);
char *oidc_proto_jwt_header_peek(request_rec *r, const char *jwt, char **alg, char **enc, char **kid);
apr_byte_t oidc_proto_jwt_create_from_first_pkey(request_rec *r, oidc_cfg_t *cfg, oidc_jwk_t **jwk, oidc_jwt_t **jwt,
						 apr_byte_t use_psa_for_rsa);
apr_byte_t oidc_proto_jwt_sign_and_serialize(request_rec *r, oidc_jwk_t *jwk, oidc_jwt_t *jwt, char **cser);

// pkce.c
#define OIDC_PKCE_METHOD_PLAIN "plain"
#define OIDC_PKCE_METHOD_S256 "S256"
#define OIDC_PKCE_METHOD_NONE "none"

/* code verifier length */
#define OIDC_PROTO_CODE_VERIFIER_LENGTH 32

extern oidc_proto_pkce_t oidc_pkce_plain;
extern oidc_proto_pkce_t oidc_pkce_s256;
extern oidc_proto_pkce_t oidc_pkce_none;

const char *oidc_proto_state_get_pkce_state(oidc_proto_state_t *proto_state);
void oidc_proto_state_set_pkce_state(oidc_proto_state_t *proto_state, const char *pkce_state);

// proto.c
apr_byte_t oidc_proto_generate_nonce(request_rec *r, char **nonce, int len);
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool);
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow);
int oidc_proto_return_www_authenticate(request_rec *r, const char *error, const char *error_description);

// request.c
int oidc_proto_request_auth(request_rec *r, struct oidc_provider_t *provider, const char *login_hint,
			    const char *redirect_uri, const char *state, oidc_proto_state_t *proto_state,
			    const char *id_token_hint, const char *code_challenge, const char *auth_request_params,
			    const char *path_scope);

// response.c
apr_byte_t oidc_proto_response_is_post(request_rec *r, oidc_cfg_t *cfg);
apr_byte_t oidc_proto_response_is_redirect(request_rec *r, oidc_cfg_t *cfg);
apr_byte_t oidc_proto_response_code_idtoken_token(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
						  oidc_provider_t *provider, apr_table_t *params,
						  const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_response_code_idtoken(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
					    oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
					    oidc_jwt_t **jwt);
apr_byte_t oidc_proto_response_code_token(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
					  oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
					  oidc_jwt_t **jwt);
apr_byte_t oidc_proto_response_code(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
				    oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
				    oidc_jwt_t **jwt);
apr_byte_t oidc_proto_response_idtoken_token(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
					     oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
					     oidc_jwt_t **jwt);
apr_byte_t oidc_proto_response_idtoken(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
				       oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
				       oidc_jwt_t **jwt);

// state.c
oidc_proto_state_t *oidc_proto_state_new();
void oidc_proto_state_destroy(oidc_proto_state_t *proto_state);
oidc_proto_state_t *oidc_proto_state_from_cookie(request_rec *r, oidc_cfg_t *c, const char *cookieValue);
char *oidc_proto_state_to_cookie(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state);
char *oidc_proto_state_to_string(request_rec *r, oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_issuer(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_nonce(oidc_proto_state_t *proto_state);
apr_time_t oidc_proto_state_get_timestamp(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_state(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_original_url(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_prompt(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_response_type(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_response_mode(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_original_url(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_original_method(oidc_proto_state_t *proto_state);
void oidc_proto_state_set_state(oidc_proto_state_t *proto_state, const char *state);
void oidc_proto_state_set_issuer(oidc_proto_state_t *proto_state, const char *issuer);
void oidc_proto_state_set_original_url(oidc_proto_state_t *proto_state, const char *original_url);
void oidc_proto_state_set_original_method(oidc_proto_state_t *proto_state, const char *original_method);
void oidc_proto_state_set_response_mode(oidc_proto_state_t *proto_state, const char *response_mode);
void oidc_proto_state_set_response_type(oidc_proto_state_t *proto_state, const char *response_type);
void oidc_proto_state_set_nonce(oidc_proto_state_t *proto_state, const char *nonce);
void oidc_proto_state_set_prompt(oidc_proto_state_t *proto_state, const char *prompt);
void oidc_proto_state_set_timestamp_now(oidc_proto_state_t *proto_state);

// token.c
apr_byte_t oidc_proto_token_endpoint_request(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
					     apr_table_t *params, char **id_token, char **access_token,
					     char **token_type, int *expires_in, char **refresh_token, char **scope);
apr_byte_t oidc_proto_token_refresh_request(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
					    const char *rtoken, char **id_token, char **access_token, char **token_type,
					    int *expires_in, char **refresh_token, char **scope);

// userinfo.c
apr_byte_t oidc_proto_userinfo_request(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
				       const char *id_token_sub, const char *access_token,
				       const char *access_token_type, char **response, char **userinfo_jwt,
				       long *response_code);

#endif /* _MOD_AUTH_OPENIDC_PROTO_H_ */
