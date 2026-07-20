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

#include "cfg/dir.h"
#include "metadata.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

/*
 * add extra configured authentication request parameters (global or per-path)
 */
static void oidc_proto_request_auth_params_add(request_rec *r, apr_table_t *params, const char *auth_request_params) {
	char *key = NULL;
	char *val = NULL;

	if (auth_request_params == NULL)
		return;

	while (*auth_request_params) {
		val = ap_getword(r->pool, &auth_request_params, OIDC_CHAR_AMP);
		if (val == NULL)
			break;
		key = ap_getword(r->pool, (const char **)&val, OIDC_CHAR_EQUAL);
		ap_unescape_url(key);
		ap_unescape_url(val);
		if (_oidc_strcmp(val, OIDC_STR_HASH) != 0) {
			apr_table_add(params, key, val);
			continue;
		}
		if (oidc_util_url_has_parameter(r, key) == TRUE) {
			oidc_util_url_parameter_get(r, key, &val);
			apr_table_add(params, key, val);
		}
	}
}

/*
 * send a Pushed Authorization Request (PAR) to the Provider
 */
int oidc_proto_request_auth_push(request_rec *r, const struct oidc_provider_t *provider, apr_table_t *params) {
	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	char *response = NULL;
	char *basic_auth = NULL;
	char *bearer_auth = NULL;
	char *request_uri = NULL;
	int expires_in = 0;
	const char *authorization_request = NULL;
	oidc_json_t *j_result = NULL;
	int rv = HTTP_INTERNAL_SERVER_ERROR;
	const char *endpoint_url = oidc_cfg_provider_pushed_authorization_request_endpoint_url_get(provider);

	oidc_debug(r, "enter");

	if (endpoint_url == NULL) {
		oidc_error(r, "the Provider's OAuth 2.0 Pushed Authorization Request endpoint URL is not set, PAR "
			      "cannot be used");
		rv = oidc_util_html_send_error(
		    r, "Pushed Authorization Request Endpoint not set",
		    "the Provider's OAuth 2.0 Pushed Authorization Request endpoint URL is not set, PAR cannot be used",
		    HTTP_INTERNAL_SERVER_ERROR);
		goto out;
	}

	/* add the token endpoint authentication credentials to the pushed authorization request */
	if (oidc_proto_token_endpoint_auth(
		r, cfg, oidc_cfg_provider_token_endpoint_auth_get(provider),
		oidc_cfg_provider_token_endpoint_auth_alg_get(provider), oidc_cfg_provider_client_id_get(provider),
		oidc_cfg_provider_client_secret_get(provider), oidc_cfg_provider_client_keys_get(provider),
		oidc_proto_profile_token_endpoint_auth_aud(provider), params, NULL, &basic_auth, &bearer_auth) == FALSE)
		goto out;

	if (oidc_http_post_form(r, endpoint_url, params, basic_auth, bearer_auth, NULL,
				oidc_cfg_provider_ssl_validate_server_get(provider), &response, NULL, NULL,
				oidc_cfg_http_timeout_long_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
				oidc_cfg_dir_pass_cookies_get(r),
				oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider),
				oidc_cfg_provider_token_endpoint_tls_client_key_get(provider),
				oidc_cfg_provider_token_endpoint_tls_client_key_pwd_get(provider)) == FALSE)
		goto out;

	/* check for errors, the response itself will have been logged already */
	if (oidc_json_decode_and_check_error(r, response, &j_result) == FALSE)
		goto out;

	/* get the request_uri from the parsed response */
	oidc_json_object_get_string(r->pool, j_result, OIDC_PROTO_REQUEST_URI, &request_uri, NULL);

	/* get the expires_in value from the parsed response */
	oidc_json_object_get_int(j_result, OIDC_PROTO_EXPIRES_IN, &expires_in, 60);

	/* assemble the resulting authentication request and redirect */
	apr_table_clear(params);
	apr_table_setn(params, OIDC_PROTO_CLIENT_ID, oidc_cfg_provider_client_id_get(provider));
	apr_table_setn(params, OIDC_PROTO_REQUEST_URI, request_uri);
	/* OpenID Connect Core 1.0 incorporating errata set 2 requires scope=openid on the front-channel
	 * authorization request; this overrides RFC 9126 §4 which would otherwise restrict the redirect
	 * to client_id and request_uri only */
	apr_table_setn(params, OIDC_PROTO_SCOPE, OIDC_PROTO_SCOPE_OPENID);
	authorization_request =
	    oidc_http_query_encoded_url(r, oidc_cfg_provider_authorization_endpoint_url_get(provider), params);
	oidc_http_hdr_out_location_set(r, authorization_request);
	rv = HTTP_MOVED_TEMPORARILY;

out:

	if (j_result)
		oidc_json_decref(j_result);

	return rv;
}

/*
 * concatenate per-path scopes with per-provider scopes, warn if "openid" is missing, and add the result to params
 */
static void oidc_proto_request_auth_scope_set(request_rec *r, const struct oidc_provider_t *provider,
					      const char *path_scope, apr_table_t *params) {
	const char *scope = oidc_cfg_provider_scope_get(provider);
	if (path_scope != NULL)
		scope = ((scope != NULL) && (_oidc_strcmp(scope, "") != 0))
			    ? apr_pstrcat(r->pool, scope, OIDC_STR_SPACE, path_scope, NULL)
			    : path_scope;

	if (scope == NULL)
		return;

	if (!oidc_util_spaced_string_contains(r->pool, scope, OIDC_PROTO_SCOPE_OPENID))
		oidc_warn(r,
			  "the configuration for the \"%s\" parameter does not include the \"%s\" scope, your "
			  "provider may not return an \"id_token\": %s",
			  OIDC_PROTO_SCOPE, OIDC_PROTO_SCOPE_OPENID, scope);

	apr_table_setn(params, OIDC_PROTO_SCOPE, scope);
}

/*
 * assemble all parameters that go into the authentication request
 */
void oidc_proto_request_auth_params_set(request_rec *r, const struct oidc_provider_t *provider, const char *login_hint,
					const char *redirect_uri, const char *state,
					const oidc_proto_state_t *proto_state, const char *id_token_hint,
					const char *code_challenge, const char *auth_request_params,
					const char *path_scope, apr_table_t *params) {

	/* add the response type */
	apr_table_setn(params, OIDC_PROTO_RESPONSE_TYPE, oidc_proto_state_get_response_type(proto_state));

	/* concat the per-path scopes with the per-provider scopes */
	oidc_proto_request_auth_scope_set(r, provider, path_scope, params);

	/* add the client ID */
	apr_table_setn(params, OIDC_PROTO_CLIENT_ID, oidc_cfg_provider_client_id_get(provider));

	/* add the state */
	apr_table_setn(params, OIDC_PROTO_STATE, state);

	/* add the redirect uri */
	apr_table_setn(params, OIDC_PROTO_REDIRECT_URI, redirect_uri);

	/* add the nonce if set */
	const char *nonce = oidc_proto_state_get_nonce(proto_state);
	if (nonce != NULL)
		apr_table_setn(params, OIDC_PROTO_NONCE, nonce);

	/* add PKCE code challenge if set */
	if ((code_challenge != NULL) && (oidc_proto_profile_pkce_get(provider) != &oidc_pkce_none)) {
		apr_table_setn(params, OIDC_PROTO_CODE_CHALLENGE, code_challenge);
		apr_table_setn(params, OIDC_PROTO_CODE_CHALLENGE_METHOD, oidc_proto_profile_pkce_get(provider)->method);
	}

	/* add the response_mode if explicitly set */
	const char *response_mode = oidc_proto_state_get_response_mode(proto_state);
	if (response_mode != NULL)
		apr_table_setn(params, OIDC_PROTO_RESPONSE_MODE, response_mode);

	/* add the login_hint if provided */
	if (login_hint != NULL)
		apr_table_setn(params, OIDC_PROTO_LOGIN_HINT, login_hint);

	/* add the id_token_hint if provided */
	if (id_token_hint != NULL)
		apr_table_setn(params, OIDC_PROTO_ID_TOKEN_HINT, id_token_hint);

	/* add the prompt setting if provided (e.g. "none" for no-GUI checks) */
	const char *prompt = oidc_proto_state_get_prompt(proto_state);
	if (prompt != NULL)
		apr_table_setn(params, OIDC_PROTO_PROMPT, prompt);

	/* add any statically configured custom authorization request parameters */
	oidc_proto_request_auth_params_add(r, params, oidc_cfg_provider_auth_request_params_get(provider));

	/* add any dynamically configured custom authorization request parameters */
	oidc_proto_request_auth_params_add(r, params, auth_request_params);

	/* add request parameter (request or request_uri) if set */
	if (oidc_cfg_provider_request_object_get(provider) != NULL)
		oidc_proto_request_object_param_add(r, provider, redirect_uri, params);
}
