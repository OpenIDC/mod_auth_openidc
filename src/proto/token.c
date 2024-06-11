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

#include "proto/proto.h"
#include "util.h"

/*
 * check that the access_token type is supported
 */
static apr_byte_t oidc_proto_validate_token_type(request_rec *r, oidc_provider_t *provider, const char *token_type) {
	/*  we only support bearer/Bearer and DPoP/dpop */
	if ((token_type != NULL) && (_oidc_strnatcasecmp(token_type, OIDC_PROTO_BEARER) != 0) &&
	    (_oidc_strnatcasecmp(token_type, OIDC_PROTO_DPOP) != 0) &&
	    (oidc_cfg_provider_userinfo_endpoint_url_get(provider) != NULL)) {
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
static apr_byte_t oidc_proto_token_endpoint_call(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
						 apr_table_t *params, const char *basic_auth, const char *bearer_auth,
						 const char *dpop, char **response, apr_hash_t *response_hdrs) {
	// oidc_debug(r, "cert=%s, key=%s, pwd=%s", oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider),
	// oidc_cfg_provider_token_endpoint_tls_client_key_get(provider),
	// oidc_cfg_provider_token_endpoint_tls_client_key_pwd_get(provider));
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
	return TRUE;
}

/*
 * send a code/refresh request to the token endpoint and return the parsed contents
 */
apr_byte_t oidc_proto_token_endpoint_request(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
					     apr_table_t *params, char **id_token, char **access_token,
					     char **token_type, int *expires_in, char **refresh_token) {

	apr_byte_t rv = FALSE;
	char *basic_auth = NULL;
	char *bearer_auth = NULL;
	char *response = NULL;
	char *dpop = NULL;
	apr_hash_t *response_hdrs = NULL;
	json_t *j_result = NULL, *j_expires_in = NULL;

	/* add the token endpoint authentication credentials */
	if (oidc_proto_token_endpoint_auth(
		r, cfg, oidc_cfg_provider_token_endpoint_auth_get(provider), oidc_cfg_provider_client_id_get(provider),
		oidc_cfg_provider_client_secret_get(provider), oidc_cfg_provider_client_keys_get(provider),
		oidc_cfg_provider_token_endpoint_url_get(provider), params, NULL, &basic_auth, &bearer_auth) == FALSE)
		goto end;

	/* add any configured extra static parameters to the token endpoint */
	oidc_util_table_add_query_encoded_params(r->pool, params,
						 oidc_cfg_provider_token_endpoint_params_get(provider));

	if (oidc_cfg_provider_dpop_mode_get(provider) != OIDC_DPOP_MODE_OFF) {

		response_hdrs = apr_hash_make(r->pool);
		apr_hash_set(response_hdrs, OIDC_HTTP_HDR_AUTHORIZATION, APR_HASH_KEY_STRING, "");
		apr_hash_set(response_hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING, "");
		apr_hash_set(response_hdrs, OIDC_HTTP_HDR_CONTENT_TYPE, APR_HASH_KEY_STRING, "");

		if ((oidc_proto_dpop_create(r, cfg, oidc_cfg_provider_token_endpoint_url_get(provider), "POST", NULL,
					    NULL, &dpop) == FALSE) &&
		    (oidc_cfg_provider_dpop_mode_get(provider) == OIDC_DPOP_MODE_REQUIRED))
			goto end;
	}

	/* send the request to the token endpoint */
	if (oidc_proto_token_endpoint_call(r, cfg, provider, params, basic_auth, bearer_auth, dpop, &response,
					   response_hdrs) == FALSE)
		goto end;

	/* decode the response into a JSON object */
	if (oidc_util_decode_json_object_err(r, response, &j_result, TRUE) == FALSE)
		goto end;

	/* check for errors, the response itself will have been logged already */
	if (oidc_util_check_json_error(r, j_result) == TRUE) {

		dpop = NULL;
		if (oidc_proto_dpop_use_nonce(r, cfg, j_result, response_hdrs,
					      oidc_cfg_provider_token_endpoint_url_get(provider), "POST", NULL,
					      &dpop) == FALSE)
			goto end;

		if (oidc_proto_token_endpoint_call(r, cfg, provider, params, basic_auth, bearer_auth, dpop, &response,
						   response_hdrs) == FALSE)
			goto end;

		json_decref(j_result);

		if (oidc_util_decode_json_and_check_error(r, response, &j_result) == FALSE)
			goto end;
	}

	/* get the id_token from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_ID_TOKEN, id_token, NULL);

	/* get the access_token from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_ACCESS_TOKEN, access_token, NULL);

	/* get the token type from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_TOKEN_TYPE, token_type, NULL);

	/* check if DPoP is required */
	if ((oidc_cfg_provider_dpop_mode_get(provider) == OIDC_DPOP_MODE_REQUIRED) &&
	    (_oidc_strnatcasecmp(*token_type, OIDC_PROTO_DPOP) != 0)) {
		oidc_error(r, "access token type is \"%s\" but \"%s\" is required", *token_type, OIDC_PROTO_DPOP);
		goto end;
	}

	/* check the new token type */
	if (token_type != NULL) {
		if (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE) {
			oidc_warn(r, "access token type \"%s\" did not validate, dropping it", *token_type);
			*access_token = NULL;
			*token_type = NULL;
		}
	}

	/* get the access token expires_in value */
	*expires_in = -1;
	j_expires_in = json_object_get(j_result, OIDC_PROTO_EXPIRES_IN);
	if (j_expires_in != NULL) {
		/* cater for string values (old Azure AD) */
		if (json_is_string(j_expires_in))
			*expires_in = _oidc_str_to_int(json_string_value(j_expires_in), -1);
		else if (json_is_integer(j_expires_in))
			*expires_in = json_integer_value(j_expires_in);
	}

	/* get the refresh_token from the parsed response */
	oidc_util_json_object_get_string(r->pool, j_result, OIDC_PROTO_REFRESH_TOKEN, refresh_token, NULL);

	rv = TRUE;

end:

	if (j_result)
		json_decref(j_result);

	return rv;
}

/*
 * refreshes the access_token/id_token /refresh_token received from the OP using the refresh_token
 */
apr_byte_t oidc_proto_token_refresh_request(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider,
					    const char *rtoken, char **id_token, char **access_token, char **token_type,
					    int *expires_in, char **refresh_token) {

	oidc_debug(r, "enter");

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_REFRESH_TOKEN);
	apr_table_setn(params, OIDC_PROTO_REFRESH_TOKEN, rtoken);
	apr_table_setn(params, OIDC_PROTO_SCOPE, oidc_cfg_provider_scope_get(provider));

	return oidc_proto_token_endpoint_request(r, cfg, provider, params, id_token, access_token, token_type,
						 expires_in, refresh_token);
}
