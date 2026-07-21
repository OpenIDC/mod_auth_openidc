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

#include <limits.h>

#include "metrics.h"
#include "proto/proto.h"
#include "util/util.h"

/*
 * check that the access_token type is supported
 */
static apr_byte_t oidc_proto_validate_token_type(request_rec *r, const oidc_provider_t *provider,
						 const char *token_type) {
	/*  we only support bearer/Bearer and DPoP/dpop */
	if ((token_type != NULL) && (_oidc_strnatcasecmp(token_type, OIDC_PROTO_BEARER) != 0) &&
	    (_oidc_strnatcasecmp(token_type, OIDC_PROTO_DPOP) != 0) &&
	    (oidc_cfg_provider_userinfo_endpoint_url_get(provider) != NULL) &&
	    (_oidc_strcmp(oidc_cfg_provider_userinfo_endpoint_url_get(provider), "") != 0)) {
		oidc_error(r,
			   "token_type is \"%s\" and UserInfo endpoint (%s) for issuer \"%s\" is set: can only deal "
			   "with \"%s\" or \"%s\" authentication against a UserInfo endpoint!",
			   token_type, oidc_cfg_provider_userinfo_endpoint_url_get(provider),
			   oidc_cfg_provider_issuer_get(provider), OIDC_PROTO_BEARER, OIDC_PROTO_DPOP);
		return FALSE;
	}

	return TRUE;
}

/*
 * send the request to the token endpoint
 */
static apr_byte_t oidc_proto_token_endpoint_call(request_rec *r, oidc_cfg_t *cfg, const oidc_provider_t *provider,
						 const apr_table_t *params, const char *basic_auth,
						 const char *bearer_auth, const char *dpop, char **response,
						 apr_hash_t *response_hdrs) {

	OIDC_METRICS_TIMING_START(r, cfg);

	if (oidc_http_post_form(r, oidc_cfg_provider_token_endpoint_url_get(provider), params, basic_auth, bearer_auth,
				dpop, oidc_cfg_provider_ssl_validate_server_get(provider), response, NULL,
				response_hdrs, oidc_cfg_http_timeout_long_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
				oidc_cfg_dir_pass_cookies_get(r),
				oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider),
				oidc_cfg_provider_token_endpoint_tls_client_key_get(provider),
				oidc_cfg_provider_token_endpoint_tls_client_key_pwd_get(provider)) == FALSE) {
		oidc_error(r, "error when calling the token endpoint (%s)",
			   oidc_cfg_provider_token_endpoint_url_get(provider));
		return FALSE;
	}

	OIDC_METRICS_TIMING_ADD(r, cfg, OM_PROVIDER_TOKEN);

	return TRUE;
}

/*
 * set up the DPoP request header and response header tracking for the initial token endpoint call
 */
static apr_byte_t oidc_proto_token_endpoint_dpop_prepare(request_rec *r, const oidc_cfg_t *cfg,
							 const oidc_provider_t *provider, apr_hash_t **response_hdrs,
							 char **dpop) {

	if (oidc_proto_profile_dpop_mode_get(provider) == OIDC_DPOP_MODE_OFF)
		return TRUE;

	*response_hdrs = apr_hash_make(r->pool);
	apr_hash_set(*response_hdrs, OIDC_HTTP_HDR_AUTHORIZATION, APR_HASH_KEY_STRING, "");
	apr_hash_set(*response_hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING, "");
	apr_hash_set(*response_hdrs, OIDC_HTTP_HDR_CONTENT_TYPE, APR_HASH_KEY_STRING, "");

	if ((oidc_proto_dpop_create(r, cfg, oidc_cfg_provider_token_endpoint_url_get(provider), "POST", NULL, NULL,
				    dpop) == FALSE) &&
	    (oidc_proto_profile_dpop_mode_get(provider) == OIDC_DPOP_MODE_REQUIRED))
		return FALSE;

	return TRUE;
}

/*
 * retry the token endpoint call with a new DPoP header that carries the server-provided nonce;
 * on success, replaces *j_result with the freshly decoded response
 */
static apr_byte_t oidc_proto_token_endpoint_dpop_retry(request_rec *r, oidc_cfg_t *cfg, const oidc_provider_t *provider,
						       const apr_table_t *params, const char *basic_auth,
						       const char *bearer_auth, apr_hash_t *response_hdrs,
						       char **response, oidc_json_t **j_result) {

	char *dpop = NULL;

	/* without response headers there is no server-provided DPoP nonce to pick up (DPoP is disabled) */
	if (response_hdrs == NULL)
		return FALSE;

	if (oidc_proto_dpop_use_nonce(r, cfg, *j_result, response_hdrs,
				      oidc_cfg_provider_token_endpoint_url_get(provider), "POST", NULL, &dpop) == FALSE)
		return FALSE;

	if (oidc_proto_token_endpoint_call(r, cfg, provider, params, basic_auth, bearer_auth, dpop, response,
					   response_hdrs) == FALSE)
		return FALSE;

	oidc_json_decref(*j_result);
	*j_result = NULL;

	return oidc_json_decode_and_check_error(r, *response, j_result);
}

/*
 * parse a successful token endpoint response and validate the returned token type against the DPoP mode
 */
static apr_byte_t oidc_proto_token_endpoint_response_parse(request_rec *r, const oidc_provider_t *provider,
							   const oidc_json_t *j_result, char **id_token,
							   char **access_token, char **token_type, int *expires_in,
							   char **refresh_token, char **scope) {

	const oidc_json_t *j_expires_in = NULL;

	oidc_json_object_get_string(r->pool, j_result, OIDC_PROTO_ID_TOKEN, id_token, NULL);
	oidc_json_object_get_string(r->pool, j_result, OIDC_PROTO_ACCESS_TOKEN, access_token, NULL);
	oidc_json_object_get_string(r->pool, j_result, OIDC_PROTO_TOKEN_TYPE, token_type, NULL);

	/* check if DPoP is required */
	if ((oidc_proto_profile_dpop_mode_get(provider) == OIDC_DPOP_MODE_REQUIRED) &&
	    (_oidc_strnatcasecmp(*token_type, OIDC_PROTO_DPOP) != 0)) {
		oidc_error(r, "access token type is \"%s\" but \"%s\" is required", *token_type, OIDC_PROTO_DPOP);
		return FALSE;
	}

	/* check the new token type */
	if ((*token_type != NULL) && (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE)) {
		oidc_warn(r, "access token type \"%s\" did not validate, dropping it", *token_type);
		*access_token = NULL;
		*token_type = NULL;
	}

	/* get the access token expires_in value; cater for string values (old Microsoft Entra ID / Azure AD) */
	*expires_in = -1;
	j_expires_in = oidc_json_object_get(j_result, OIDC_PROTO_EXPIRES_IN);
	if (oidc_json_is_string(j_expires_in)) {
		*expires_in = _oidc_str_to_int(oidc_json_string_value(j_expires_in), -1);
	} else if (oidc_json_is_integer(j_expires_in)) {
		/* clamp into int range so a maliciously huge OP value can't silently truncate to a small/negative TTL
		 */
		oidc_json_int_t v = oidc_json_integer_value(j_expires_in);
		if (v > INT_MAX)
			*expires_in = INT_MAX;
		else if (v < INT_MIN)
			*expires_in = INT_MIN;
		else
			*expires_in = (int)v;
	}

	oidc_json_object_get_string(r->pool, j_result, OIDC_PROTO_REFRESH_TOKEN, refresh_token, NULL);
	oidc_json_object_get_string(r->pool, j_result, OIDC_PROTO_SCOPE, scope, NULL);

	return TRUE;
}

/*
 * send a code/refresh request to the token endpoint and return the parsed contents
 */
apr_byte_t oidc_proto_token_endpoint_request(request_rec *r, oidc_cfg_t *cfg, const oidc_provider_t *provider,
					     apr_table_t *params, char **id_token, char **access_token,
					     char **token_type, int *expires_in, char **refresh_token, char **scope) {

	apr_byte_t rv = FALSE;
	char *basic_auth = NULL;
	char *bearer_auth = NULL;
	char *response = NULL;
	char *dpop = NULL;
	apr_hash_t *response_hdrs = NULL;
	oidc_json_t *j_result = NULL;

	/* add the token endpoint authentication credentials */
	if (oidc_proto_token_endpoint_auth(
		r, cfg, oidc_cfg_provider_token_endpoint_auth_get(provider),
		oidc_cfg_provider_token_endpoint_auth_alg_get(provider), oidc_cfg_provider_client_id_get(provider),
		oidc_cfg_provider_client_secret_get(provider), oidc_cfg_provider_client_keys_get(provider),
		oidc_proto_profile_token_endpoint_auth_aud(provider), params, NULL, &basic_auth, &bearer_auth) == FALSE)
		goto end;

	/* add any configured extra static parameters to the token endpoint */
	oidc_util_table_add_query_encoded_params(r->pool, params,
						 oidc_cfg_provider_token_endpoint_params_get(provider));

	/* set up the DPoP header for the initial request if DPoP is enabled */
	if (oidc_proto_token_endpoint_dpop_prepare(r, cfg, provider, &response_hdrs, &dpop) == FALSE)
		goto end;

	/* send the request to the token endpoint */
	if (oidc_proto_token_endpoint_call(r, cfg, provider, params, basic_auth, bearer_auth, dpop, &response,
					   response_hdrs) == FALSE)
		goto end;

	/* decode the response into a JSON object */
	if (oidc_json_decode_object_err(r, response, &j_result, TRUE) == FALSE)
		goto end;

	/* on a DPoP nonce error retry the call with a fresh nonce-bound DPoP header */
	if ((oidc_json_check_error(r, j_result) == TRUE) &&
	    (oidc_proto_token_endpoint_dpop_retry(r, cfg, provider, params, basic_auth, bearer_auth, response_hdrs,
						  &response, &j_result) == FALSE))
		goto end;

	if (oidc_proto_token_endpoint_response_parse(r, provider, j_result, id_token, access_token, token_type,
						     expires_in, refresh_token, scope) == FALSE)
		goto end;

	rv = TRUE;

end:

	if (j_result)
		oidc_json_decref(j_result);

	return rv;
}

/*
 * refreshes the access_token/id_token /refresh_token received from the OP using the refresh_token
 */
apr_byte_t oidc_proto_token_refresh_request(request_rec *r, oidc_cfg_t *cfg, const oidc_provider_t *provider,
					    const char *rtoken, char **id_token, char **access_token, char **token_type,
					    int *expires_in, char **refresh_token, char **scope) {

	oidc_debug(r, "enter");

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_REFRESH_TOKEN);
	apr_table_setn(params, OIDC_PROTO_REFRESH_TOKEN, rtoken);
	apr_table_setn(params, OIDC_PROTO_SCOPE, oidc_cfg_provider_scope_get(provider));

	return oidc_proto_token_endpoint_request(r, cfg, provider, params, id_token, access_token, token_type,
						 expires_in, refresh_token, scope);
}
