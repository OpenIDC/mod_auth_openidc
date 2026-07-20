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

#include "proto/proto.h"

/*
 * per-profile overrides of provider settings: each callback returns the effective value of a
 * setting under its profile; the plain OIDC 1.0 entries pass the provider configuration
 * through, the FAPI 2.0 entries enforce the FAPI 2.0 Security Profile requirements; adding a
 * profile means adding one ops instance here rather than a branch in every getter
 */
typedef struct oidc_proto_profile_ops_t {
	const char *(*token_endpoint_auth_aud)(const oidc_provider_t *provider);
	const char *(*revocation_endpoint_auth_aud)(const oidc_provider_t *provider, const char *val);
	oidc_auth_request_method_t (*auth_request_method)(const oidc_provider_t *provider);
	const apr_array_header_t *(*id_token_aud_values)(apr_pool_t *pool, const oidc_provider_t *provider);
	const oidc_proto_pkce_t *(*pkce)(const oidc_provider_t *provider);
	oidc_dpop_mode_t (*dpop_mode)(const oidc_provider_t *provider);
	int (*response_require_iss)(const oidc_provider_t *provider);
} oidc_proto_profile_ops_t;

/*
 * plain OpenID Connect 1.0: the configured provider settings apply as-is
 */

static const char *oidc_profile_oidc10_token_endpoint_auth_aud(const oidc_provider_t *provider) {
	return oidc_cfg_provider_token_endpoint_url_get(provider);
}

static const char *oidc_profile_oidc10_revocation_endpoint_auth_aud(const oidc_provider_t *provider, const char *val) {
	const char *aud = oidc_cfg_provider_revocation_endpoint_url_get(provider);
	if (val != NULL) {
		if (_oidc_strcmp(val, "token") == 0) {
			aud = oidc_cfg_provider_token_endpoint_url_get(provider);
		} else {
			aud = val;
		}
	}
	return aud;
}

static oidc_auth_request_method_t oidc_profile_oidc10_auth_request_method(const oidc_provider_t *provider) {
	return oidc_cfg_provider_auth_request_method_get(provider);
}

static const apr_array_header_t *oidc_profile_oidc10_id_token_aud_values(apr_pool_t *pool,
									 const oidc_provider_t *provider) {
	return oidc_cfg_provider_id_token_aud_values_get(provider);
}

static const oidc_proto_pkce_t *oidc_profile_oidc10_pkce(const oidc_provider_t *provider) {
	return oidc_cfg_provider_pkce_get(provider);
}

static oidc_dpop_mode_t oidc_profile_oidc10_dpop_mode(const oidc_provider_t *provider) {
	return oidc_cfg_provider_dpop_mode_get(provider);
}

static int oidc_profile_oidc10_response_require_iss(const oidc_provider_t *provider) {
	return oidc_cfg_provider_response_require_iss_get(provider);
}

static const oidc_proto_profile_ops_t _oidc_profile_oidc10_ops = {
    oidc_profile_oidc10_token_endpoint_auth_aud,
    oidc_profile_oidc10_revocation_endpoint_auth_aud,
    oidc_profile_oidc10_auth_request_method,
    oidc_profile_oidc10_id_token_aud_values,
    oidc_profile_oidc10_pkce,
    oidc_profile_oidc10_dpop_mode,
    oidc_profile_oidc10_response_require_iss,
};

/*
 * FAPI 2.0 Security Profile: harden the settings the profile mandates
 */

static const char *oidc_profile_fapi20_token_endpoint_auth_aud(const oidc_provider_t *provider) {
	return oidc_cfg_provider_issuer_get(provider);
}

static const char *oidc_profile_fapi20_revocation_endpoint_auth_aud(const oidc_provider_t *provider, const char *val) {
	return oidc_cfg_provider_issuer_get(provider);
}

static oidc_auth_request_method_t oidc_profile_fapi20_auth_request_method(const oidc_provider_t *provider) {
	return OIDC_AUTH_REQUEST_METHOD_PAR;
}

static const apr_array_header_t *oidc_profile_fapi20_id_token_aud_values(apr_pool_t *pool,
									 const oidc_provider_t *provider) {
	// NB: the acceptable "aud" values may be overridden; when they are, the client_id is assumed (but not
	//     enforced, even for FAPI20) to be among them
	const apr_array_header_t *values = oidc_cfg_provider_id_token_aud_values_get(provider);
	if (values == NULL) {
		apr_array_header_t *list = NULL;
		oidc_cfg_string_list_add(pool, &list, oidc_cfg_provider_client_id_get(provider));
		return list;
	}
	return values;
}

static const oidc_proto_pkce_t *oidc_profile_fapi20_pkce(const oidc_provider_t *provider) {
	return &oidc_pkce_s256;
}

static oidc_dpop_mode_t oidc_profile_fapi20_dpop_mode(const oidc_provider_t *provider) {
	return OIDC_DPOP_MODE_REQUIRED;
}

static int oidc_profile_fapi20_response_require_iss(const oidc_provider_t *provider) {
	return 1;
}

static const oidc_proto_profile_ops_t _oidc_profile_fapi20_ops = {
    oidc_profile_fapi20_token_endpoint_auth_aud,
    oidc_profile_fapi20_revocation_endpoint_auth_aud,
    oidc_profile_fapi20_auth_request_method,
    oidc_profile_fapi20_id_token_aud_values,
    oidc_profile_fapi20_pkce,
    oidc_profile_fapi20_dpop_mode,
    oidc_profile_fapi20_response_require_iss,
};

/*
 * return the ops for the provider's configured profile
 */
static const oidc_proto_profile_ops_t *oidc_proto_profile_ops(const oidc_provider_t *provider) {
	switch (oidc_cfg_provider_profile_get(provider)) {
	case OIDC_PROFILE_FAPI20:
		return &_oidc_profile_fapi20_ops;
	case OIDC_PROFILE_OIDC10:
	default:
		return &_oidc_profile_oidc10_ops;
	}
}

/*
 * returns the "aud" claim to insert into the JWT used for client
 * authentication towards the token endpoint using private_key_jwt/client_secret_jwt
 */
const char *oidc_proto_profile_token_endpoint_auth_aud(const oidc_provider_t *provider) {
	return oidc_proto_profile_ops(provider)->token_endpoint_auth_aud(provider);
}

/*
 * returns the "aud" claim to insert into the JWT used for client
 * authentication towards the revocation endpoint using private_key_jwt/client_secret_jwt
 */
const char *oidc_proto_profile_revocation_endpoint_auth_aud(const oidc_provider_t *provider, const char *val) {
	return oidc_proto_profile_ops(provider)->revocation_endpoint_auth_aud(provider, val);
}

/*
 * returns the method to be used when sending the authorization request to the Provider
 */
oidc_auth_request_method_t oidc_proto_profile_auth_request_method_get(const oidc_provider_t *provider) {
	return oidc_proto_profile_ops(provider)->auth_request_method(provider);
}

/*
 * returns the acceptable "aud" values in the ID token
 */
const apr_array_header_t *oidc_proto_profile_id_token_aud_values_get(apr_pool_t *pool,
								     const oidc_provider_t *provider) {
	return oidc_proto_profile_ops(provider)->id_token_aud_values(pool, provider);
}

/*
 * returns the PKCE mode
 */
const oidc_proto_pkce_t *oidc_proto_profile_pkce_get(const oidc_provider_t *provider) {
	return oidc_proto_profile_ops(provider)->pkce(provider);
}

/*
 * returns the DPoP mode
 */
oidc_dpop_mode_t oidc_proto_profile_dpop_mode_get(const oidc_provider_t *provider) {
	return oidc_proto_profile_ops(provider)->dpop_mode(provider);
}

/*
 * returns whether the Provider is required to pass back an "iss" parameter
 * together with the authorization response sent to the Redirect URI
 */
int oidc_proto_profile_response_require_iss_get(const oidc_provider_t *provider) {
	return oidc_proto_profile_ops(provider)->response_require_iss(provider);
}
