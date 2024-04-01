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

#ifndef _MOD_AUTH_OPENIDC_CFG_PROVIDER_H_
#define _MOD_AUTH_OPENIDC_CFG_PROVIDER_H_

#include "cfg/cfg.h"

typedef apr_byte_t (*oidc_proto_pkce_state)(request_rec *r, char **state);
typedef apr_byte_t (*oidc_proto_pkce_challenge)(request_rec *r, const char *state, char **code_challenge);
typedef apr_byte_t (*oidc_proto_pkce_verifier)(request_rec *r, const char *state, char **code_verifier);

typedef struct oidc_proto_pkce_t {
	const char *method;
	oidc_proto_pkce_state state;
	oidc_proto_pkce_verifier verifier;
	oidc_proto_pkce_challenge challenge;
} oidc_proto_pkce_t;

#define OIDC_PKCE_METHOD_PLAIN "plain"
#define OIDC_PKCE_METHOD_S256 "S256"
#define OIDC_PKCE_METHOD_NONE "none"

#define OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC "client_secret_basic"
#define OIDC_ENDPOINT_AUTH_CLIENT_SECRET_POST "client_secret_post"
#define OIDC_ENDPOINT_AUTH_CLIENT_SECRET_JWT "client_secret_jwt"
#define OIDC_ENDPOINT_AUTH_PRIVATE_KEY_JWT "private_key_jwt"
#define OIDC_ENDPOINT_AUTH_BEARER_ACCESS_TOKEN "bearer_access_token"
#define OIDC_ENDPOINT_AUTH_NONE "none"

/* HTTP methods to send authentication requests */
typedef enum {
	OIDC_AUTH_REQUEST_METHOD_GET = 1,
	OIDC_AUTH_REQUEST_METHOD_POST = 2,
} oidc_auth_request_method_t;

typedef enum {
	OIDC_USER_INFO_TOKEN_METHOD_HEADER = 1,
	OIDC_USER_INFO_TOKEN_METHOD_POST = 2,
} oidc_userinfo_token_method_t;

typedef struct oidc_jwks_uri_t {
	const char *uri;
	int refresh_interval;
	const char *signed_uri;
	apr_array_header_t *jwk_list;
} oidc_jwks_uri_t;

// NB: need the primitive strings and the declarations of the custom
//     set routines here because the commands are included in config.c.
//     via include "cmds.inc"

#define OIDCProviderMetadataURL "OIDCProviderMetadataURL"
#define OIDCProviderIssuer "OIDCProviderIssuer"
#define OIDCProviderAuthorizationEndpoint "OIDCProviderAuthorizationEndpoint"
#define OIDCProviderTokenEndpoint "OIDCProviderTokenEndpoint"
#define OIDCProviderTokenEndpointAuth "OIDCProviderTokenEndpointAuth"
#define OIDCProviderTokenEndpointParams "OIDCProviderTokenEndpointParams"
#define OIDCProviderRegistrationEndpointJson "OIDCProviderRegistrationEndpointJson"
#define OIDCProviderUserInfoEndpoint "OIDCProviderUserInfoEndpoint"
#define OIDCProviderRevocationEndpoint "OIDCProviderRevocationEndpoint"
#define OIDCProviderCheckSessionIFrame "OIDCProviderCheckSessionIFrame"
#define OIDCProviderEndSessionEndpoint "OIDCProviderEndSessionEndpoint"
#define OIDCProviderBackChannelLogoutSupported "OIDCProviderBackChannelLogoutSupported"
#define OIDCProviderJwksUri "OIDCProviderJwksUri"
#define OIDCProviderSignedJwksUri "OIDCProviderSignedJwksUri"
#define OIDCProviderVerifyCertFiles "OIDCProviderVerifyCertFiles"
#define OIDCResponseType "OIDCResponseType"
#define OIDCProviderAuthRequestMethod "OIDCProviderAuthRequestMethod"
#define OIDCPKCEMethod "OIDCPKCEMethod"
#define OIDCResponseMode "OIDCResponseMode"
#define OIDCClientJwksUri "OIDCClientJwksUri"
#define OIDCIDTokenSignedResponseAlg "OIDCIDTokenSignedResponseAlg"
#define OIDCIDTokenEncryptedResponseAlg "OIDCIDTokenEncryptedResponseAlg"
#define OIDCIDTokenEncryptedResponseEnc "OIDCIDTokenEncryptedResponseEnc"
#define OIDCUserInfoSignedResponseAlg "OIDCUserInfoSignedResponseAlg"
#define OIDCUserInfoEncryptedResponseAlg "OIDCUserInfoEncryptedResponseAlg"
#define OIDCUserInfoEncryptedResponseEnc "OIDCUserInfoEncryptedResponseEnc"
#define OIDCUserInfoTokenMethod "OIDCUserInfoTokenMethod"
#define OIDCSSLValidateServer "OIDCSSLValidateServer"
#define OIDCValidateIssuer "OIDCValidateIssuer"
#define OIDCClientName "OIDCClientName"
#define OIDCClientContact "OIDCClientContact"
#define OIDCScope "OIDCScope"
#define OIDCJWKSRefreshInterval "OIDCJWKSRefreshInterval"
#define OIDCIDTokenIatSlack "OIDCIDTokenIatSlack"
#define OIDCSessionMaxDuration "OIDCSessionMaxDuration"
#define OIDCAuthRequestParams "OIDCAuthRequestParams"
#define OIDCLogoutRequestParams "OIDCLogoutRequestParams"
#define OIDCClientID "OIDCClientID"
#define OIDCClientSecret "OIDCClientSecret"
#define OIDCClientTokenEndpointCert "OIDCClientTokenEndpointCert"
#define OIDCClientTokenEndpointKey "OIDCClientTokenEndpointKey"
#define OIDCClientTokenEndpointKeyPassword "OIDCClientTokenEndpointKeyPassword"
#define OIDCUserInfoRefreshInterval "OIDCUserInfoRefreshInterval"
#define OIDCRequestObject "OIDCRequestObject"

#define OIDC_CMD_PROVIDER_MEMBER_FUNC_DECL(member, ...)                                                                \
	const char *OIDC_CFG_MEMBER_FUNC_NAME(member, cmd_provider, set)(cmd_parms *, void *, const char *,            \
									 ##__VA_ARGS__);

#define OIDC_CFG_PROVIDER_MEMBER_FUNC_SET_DECL(member, type, ...)                                                      \
	const char *OIDC_CFG_MEMBER_FUNC_NAME(member, cfg_provider, set)(apr_pool_t *, oidc_provider_t *, type,        \
									 ##__VA_ARGS__);

#define OIDC_CFG_PROVIDER_MEMBER_FUNC_GET_DECL(member, type)                                                           \
	type OIDC_CFG_MEMBER_FUNC_NAME(member, cfg_provider, get)(oidc_provider_t *);

#define OIDC_CFG_PROVIDER_MEMBER_FUNCS_DECL(member, itype, rtype, ...)                                                 \
	OIDC_CMD_PROVIDER_MEMBER_FUNC_DECL(member, ##__VA_ARGS__)                                                      \
	OIDC_CFG_PROVIDER_MEMBER_FUNC_SET_DECL(member, itype)                                                          \
	OIDC_CFG_PROVIDER_MEMBER_FUNC_GET_DECL(member, rtype)

#define OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(member, ...)                                                           \
	OIDC_CFG_PROVIDER_MEMBER_FUNCS_DECL(member, int, int, ##__VA_ARGS__)

#define OIDC_CFG_PROVIDER_MEMBER_FUNCS_TYPE_DECL(member, type, ...)                                                    \
	OIDC_CFG_PROVIDER_MEMBER_FUNCS_DECL(member, const char *, type, ##__VA_ARGS__)

#define OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(member, ...)                                                           \
	OIDC_CFG_PROVIDER_MEMBER_FUNCS_TYPE_DECL(member, const char *, ##__VA_ARGS__)

#define OIDC_CFG_PROVIDER_MEMBER_FUNCS_KEYS_DECL(member)                                                               \
	OIDC_CFG_PROVIDER_MEMBER_FUNCS_TYPE_DECL(member, const apr_array_header_t *)                                   \
	const char *OIDC_CFG_MEMBER_FUNC_NAME(member, cfg_provider, set_keys)(apr_pool_t *, oidc_provider_t *,         \
									      apr_array_header_t *);

#define OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_INT_DECL(member, type)                                                      \
	OIDC_CFG_PROVIDER_MEMBER_FUNCS_TYPE_DECL(member, type)                                                         \
	void OIDC_CFG_MEMBER_FUNC_NAME(member, cfg_provider, int_set)(oidc_provider_t * provider, type arg);

OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(metadata_url)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(issuer)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(authorization_endpoint_url);
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(token_endpoint_url)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(token_endpoint_params)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(userinfo_endpoint_url)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(revocation_endpoint_url)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(registration_endpoint_url)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(check_session_iframe)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(end_session_endpoint)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(client_id)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(client_secret)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(token_endpoint_tls_client_key)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(token_endpoint_tls_client_key_pwd)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(token_endpoint_tls_client_cert)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(client_name)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(client_contact)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(registration_token)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(registration_endpoint_json)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(scope)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(response_type)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(response_mode)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(auth_request_params)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(logout_request_params)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(client_jwks_uri)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(id_token_signed_response_alg)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(id_token_encrypted_response_alg)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(id_token_encrypted_response_enc)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(userinfo_signed_response_alg)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(userinfo_encrypted_response_alg)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(userinfo_encrypted_response_enc)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_STR_DECL(request_object)

// keys
OIDC_CFG_PROVIDER_MEMBER_FUNCS_KEYS_DECL(verify_public_keys)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_KEYS_DECL(client_keys)

// ints
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(jwks_uri_refresh_interval)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(backchannel_logout_supported)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(ssl_validate_server)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(validate_issuer)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(idtoken_iat_slack)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(session_max_duration)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(issuer_specific_redirect_uri)
// ints with 2 args
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_DECL(userinfo_refresh_interval, const char *)

// for metadata.c
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_INT_DECL(userinfo_token_method, oidc_userinfo_token_method_t)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_INT_INT_DECL(auth_request_method, oidc_auth_request_method_t)

// types
OIDC_CFG_PROVIDER_MEMBER_FUNCS_TYPE_DECL(pkce, const oidc_proto_pkce_t *)
OIDC_CFG_PROVIDER_MEMBER_FUNCS_TYPE_DECL(jwks_uri, const oidc_jwks_uri_t *)

// getters
OIDC_CFG_PROVIDER_MEMBER_FUNC_GET_DECL(jwks_uri_uri, const char *)

// specials for signed_jwks_uri and signed_jwks_uri_keys
OIDC_CMD_PROVIDER_MEMBER_FUNC_DECL(signed_jwks_uri, const char *)
OIDC_CFG_PROVIDER_MEMBER_FUNC_SET_DECL(signed_jwks_uri, const char *, const char *)
OIDC_CFG_PROVIDER_MEMBER_FUNC_GET_DECL(signed_jwks_uri, const char *)
OIDC_CFG_PROVIDER_MEMBER_FUNC_SET_DECL(signed_jwks_uri_keys, json_t *, apr_array_header_t *)
OIDC_CFG_PROVIDER_MEMBER_FUNC_GET_DECL(signed_jwks_uri_keys, apr_array_header_t *)

// specials for token_endpoint_auth
const char *OIDC_CFG_MEMBER_FUNC_NAME(token_endpoint_auth, cfg_provider, set)(apr_pool_t *pool, oidc_cfg_t *cfg,
									      oidc_provider_t *provider,
									      const char *arg);
OIDC_CMD_PROVIDER_MEMBER_FUNC_DECL(token_endpoint_auth)
OIDC_CFG_PROVIDER_MEMBER_FUNC_GET_DECL(token_endpoint_auth, const char *)

oidc_provider_t *oidc_cfg_provider_create(apr_pool_t *pool);
void oidc_cfg_provider_merge(apr_pool_t *pool, oidc_provider_t *dst, const oidc_provider_t *base,
			     const oidc_provider_t *add);
oidc_provider_t *oidc_cfg_provider_copy(apr_pool_t *pool, const oidc_provider_t *src);
void oidc_cfg_provider_destroy(oidc_provider_t *provider);

#endif // _MOD_AUTH_OPENIDC_CFG_PROVIDER_H_
