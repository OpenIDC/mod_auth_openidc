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

#include "proto/proto.h"

/*
 * returns the "aud" claim to insert into the JWT used for client
 * authentication towards the token endpoint using private_key_jwt/client_secret_jwt
 */
const char *oidc_proto_profile_token_endpoint_auth_aud(oidc_provider_t *provider) {
	if (oidc_cfg_provider_profile_get(provider) == OIDC_PROFILE_FAPI20) {
		return oidc_cfg_provider_issuer_get(provider);
	}
	return oidc_cfg_provider_token_endpoint_url_get(provider);
}

/*
 * returns the "aud" claim to insert into the JWT used for client
 * authentication towards the revocation endpoint using private_key_jwt/client_secret_jwt
 */
const char *oidc_proto_profile_revocation_endpoint_auth_aud(oidc_provider_t *provider, const char *val) {
	if (oidc_cfg_provider_profile_get(provider) == OIDC_PROFILE_FAPI20) {
		return oidc_cfg_provider_issuer_get(provider);
	}
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

/*
 * returns the method to be used when sending the authorization request to the Provider
 */
oidc_auth_request_method_t oidc_proto_profile_auth_request_method_get(oidc_provider_t *provider) {
	if (oidc_cfg_provider_profile_get(provider) == OIDC_PROFILE_FAPI20)
		return OIDC_AUTH_REQUEST_METHOD_PAR;
	return oidc_cfg_provider_auth_request_method_get(provider);
}

/*
 * returns the acceptable "aud" values in the ID token
 */
const apr_array_header_t *oidc_proto_profile_id_token_aud_values_get(apr_pool_t *pool, oidc_provider_t *provider) {
	const apr_array_header_t *values = oidc_cfg_provider_id_token_aud_values_get(provider);
	// TODO: so we actually do allow overriding the acceptable "aud" values but we sort of assume the client_id
	//       is in there in that case; perhaps check that - in the config check? - for FAPI20
	if (values == NULL) {
		if (oidc_cfg_provider_profile_get(provider) == OIDC_PROFILE_FAPI20) {
			apr_array_header_t *list = NULL;
			oidc_cfg_string_list_add(pool, &list, oidc_cfg_provider_client_id_get(provider));
			return list;
		}
	}
	return values;
}

/*
 * returns the PKCE mode
 */
const oidc_proto_pkce_t *oidc_proto_profile_pkce_get(oidc_provider_t *provider) {
	if (oidc_cfg_provider_profile_get(provider) == OIDC_PROFILE_FAPI20)
		return &oidc_pkce_s256;
	return oidc_cfg_provider_pkce_get(provider);
}

/*
 * returns the DPoP mode
 */
oidc_dpop_mode_t oidc_proto_profile_dpop_mode_get(oidc_provider_t *provider) {
	if (oidc_cfg_provider_profile_get(provider) == OIDC_PROFILE_FAPI20)
		return OIDC_DPOP_MODE_REQUIRED;
	return oidc_cfg_provider_dpop_mode_get(provider);
}

/*
 * returns whether the Provider is required to pass back an "iss" parameter
 * together with the authorization response sent to the Redirect URI
 */
int oidc_proto_profile_response_require_iss_get(oidc_provider_t *provider) {
	if (oidc_cfg_provider_profile_get(provider) == OIDC_PROFILE_FAPI20)
		return 1;
	return oidc_cfg_provider_response_require_iss_get(provider);
}
