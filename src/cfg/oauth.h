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
 * Copyright (C) 2017-2026 ZmartZone Holding BV
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

#ifndef _MOD_AUTH_OPENIDC_CFG_OAUTH_H_
#define _MOD_AUTH_OPENIDC_CFG_OAUTH_H_

#include "cfg/cfg.h"

#define OIDCOAuthServerMetadataURL "OIDCOAuthServerMetadataURL"
#define OIDCOAuthClientID "OIDCOAuthClientID"
#define OIDCOAuthClientSecret "OIDCOAuthClientSecret"
#define OIDCOAuthIntrospectionClientAuthBearerToken "OIDCOAuthIntrospectionClientAuthBearerToken"
#define OIDCOAuthIntrospectionEndpoint "OIDCOAuthIntrospectionEndpoint"
#define OIDCOAuthIntrospectionEndpointMethod "OIDCOAuthIntrospectionEndpointMethod"
#define OIDCOAuthIntrospectionEndpointParams "OIDCOAuthIntrospectionEndpointParams"
#define OIDCOAuthIntrospectionEndpointAuth "OIDCOAuthIntrospectionEndpointAuth"
#define OIDCOAuthIntrospectionEndpointCert "OIDCOAuthIntrospectionEndpointCert"
#define OIDCOAuthIntrospectionEndpointKey "OIDCOAuthIntrospectionEndpointKey"
#define OIDCOAuthIntrospectionEndpointKeyPassword "OIDCOAuthIntrospectionEndpointKeyPassword"
#define OIDCOAuthIntrospectionTokenParamName "OIDCOAuthIntrospectionTokenParamName"
#define OIDCOAuthTokenExpiryClaim "OIDCOAuthTokenExpiryClaim"
#define OIDCOAuthSSLValidateServer "OIDCOAuthSSLValidateServer"
#define OIDCOAuthVerifyCertFiles "OIDCOAuthVerifyCertFiles"
#define OIDCOAuthVerifySharedKeys "OIDCOAuthVerifySharedKeys"
#define OIDCOAuthVerifyJwksUri "OIDCOAuthVerifyJwksUri"

typedef enum {
	OIDC_TOKEN_EXPIRY_CLAIM_FORMAT_RELATIVE = 1,
	OIDC_TOKEN_EXPIRY_CLAIM_FORMAT_ABSOLUTE = 2
} oidc_oauth_introspection_token_expiry_claim_format_t;

typedef enum {
	OIDC_TOKEN_EXPIRY_CLAIM_REQUIRED_MANDATORY = 1,
	OIDC_TOKEN_EXPIRY_CLAIM_REQUIRED_OPTIONAL = 2
} oidc_oauth_introspection_token_expiry_claim_required_t;

typedef enum {
	OIDC_INTROSPECTION_METHOD_GET = 1,
	OIDC_INTROSPECTION_METHOD_POST = 2
} oidc_oauth_introspection_endpoint_method_t;

#define OIDC_CFG_OAUTH_MEMBER_FUNC_GET_DECL(member, type)                                                              \
	type OIDC_CFG_MEMBER_FUNC_NAME(member, cfg_oauth, get)(oidc_cfg_t * cfg);

#define OIDC_CMD_OAUTH_MEMBER_FUNC_DECL(member, ...)                                                                   \
	const char *OIDC_CFG_MEMBER_FUNC_NAME(member, cmd_oauth, set)(cmd_parms *, void *, ##__VA_ARGS__);

#define OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(member, type, ...)                                                            \
	OIDC_CMD_OAUTH_MEMBER_FUNC_DECL(member, const char *, ##__VA_ARGS__);                                          \
	OIDC_CFG_OAUTH_MEMBER_FUNC_GET_DECL(member, type)

#define OIDC_CFG_OAUTH_MEMBER_FUNC_SET_DECL(member)                                                                    \
	const char *OIDC_CFG_MEMBER_FUNC_NAME(member, cfg_oauth, set)(apr_pool_t *, oidc_cfg_t *, const char *);

OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(ssl_validate_server, int)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(metadata_url, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_endpoint_url, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_endpoint_params, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_endpoint_auth, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_endpoint_auth_alg, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_endpoint_method, oidc_oauth_introspection_endpoint_method_t)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_token_param_name, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_endpoint_tls_client_cert, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_endpoint_tls_client_key, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_endpoint_tls_client_key_pwd, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(client_id, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(client_secret, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(verify_jwks_uri, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(verify_shared_keys, apr_hash_t *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(verify_public_keys, const apr_array_header_t *)
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(introspection_client_auth_bearer_token, const char *)

// remote user claim, 3 args, 1 getter
OIDC_CFG_OAUTH_MEMBER_FUNCS_DECL(remote_user_claim, oidc_remote_user_claim_t *, const char *, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNC_GET_DECL(remote_user_claim_name, const char *)

// token expiry claim, 3 args, 3 getters
OIDC_CMD_OAUTH_MEMBER_FUNC_DECL(token_expiry_claim, const char *, const char *, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNC_GET_DECL(introspection_token_expiry_claim_name, const char *)
OIDC_CFG_OAUTH_MEMBER_FUNC_GET_DECL(introspection_token_expiry_claim_format,
				    oidc_oauth_introspection_token_expiry_claim_format_t)
OIDC_CFG_OAUTH_MEMBER_FUNC_GET_DECL(introspection_token_expiry_claim_required,
				    oidc_oauth_introspection_token_expiry_claim_required_t)

// needed in metadata.c
OIDC_CFG_OAUTH_MEMBER_FUNC_SET_DECL(introspection_endpoint_url)
OIDC_CFG_OAUTH_MEMBER_FUNC_SET_DECL(verify_jwks_uri)
OIDC_CFG_OAUTH_MEMBER_FUNC_SET_DECL(introspection_endpoint_auth)
OIDC_CFG_OAUTH_MEMBER_FUNC_GET_DECL(introspection_endpoint_auth_alg, const char *)

typedef struct oidc_oauth_t oidc_oauth_t;

oidc_oauth_t *oidc_cfg_oauth_create(apr_pool_t *pool);
void oidc_cfg_oauth_merge(apr_pool_t *pool, oidc_oauth_t *dst, const oidc_oauth_t *base, const oidc_oauth_t *add);
void oidc_cfg_oauth_destroy(oidc_oauth_t *o);

#endif // _MOD_AUTH_OPENIDC_CFG_OAUTH_H_
