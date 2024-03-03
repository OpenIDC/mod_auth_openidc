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

#include "handle/handle.h"
#include "metrics.h"

static int oidc_request_check_cookie_domain(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state,
					    const char *original_url) {
	/*
	 * printout errors if Cookie settings are not going to work
	 * TODO: separate this code out into its own function
	 */
	apr_uri_t o_uri;
	_oidc_memset(&o_uri, 0, sizeof(apr_uri_t));
	apr_uri_t r_uri;
	_oidc_memset(&r_uri, 0, sizeof(apr_uri_t));
	apr_uri_parse(r->pool, original_url, &o_uri);
	apr_uri_parse(r->pool, oidc_get_redirect_uri(r, c), &r_uri);
	if ((_oidc_strcmp(o_uri.scheme, r_uri.scheme) != 0) && (_oidc_strcmp(r_uri.scheme, "https") == 0)) {
		oidc_error(r,
			   "the URL scheme (%s) of the configured " OIDCRedirectURI
			   " does not match the URL scheme of the URL being accessed (%s): the \"state\" and "
			   "\"session\" cookies will not be shared between the two!",
			   r_uri.scheme, o_uri.scheme);
		oidc_proto_state_destroy(proto_state);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (c->cookie_domain == NULL) {
		if (_oidc_strcmp(o_uri.hostname, r_uri.hostname) != 0) {
			char *p = _oidc_strstr(o_uri.hostname, r_uri.hostname);
			if ((p == NULL) || (_oidc_strcmp(r_uri.hostname, p) != 0)) {
				oidc_error(r,
					   "the URL hostname (%s) of the configured " OIDCRedirectURI
					   " does not match the URL hostname of the URL being accessed (%s): the "
					   "\"state\" and \"session\" cookies will not be shared between the two!",
					   r_uri.hostname, o_uri.hostname);
				oidc_proto_state_destroy(proto_state);
				OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_REQUEST_ERROR_URL);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
	} else {
		if (!oidc_util_cookie_domain_valid(r_uri.hostname, c->cookie_domain)) {
			oidc_error(r,
				   "the domain (%s) configured in " OIDCCookieDomain
				   " does not match the URL hostname (%s) of the URL being accessed (%s): setting "
				   "\"state\" and \"session\" cookies will not work!!",
				   c->cookie_domain, o_uri.hostname, original_url);
			oidc_proto_state_destroy(proto_state);
			OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_REQUEST_ERROR_URL);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	return OK;
}

/*
 * set the state that is maintained between an authorization request and an authorization response
 * in a cookie in the browser that is cryptographically bound to that state
 */
static int oidc_request_authorization_set_cookie(request_rec *r, oidc_cfg *c, const char *state,
						 oidc_proto_state_t *proto_state) {
	/*
	 * create a cookie consisting of 8 elements:
	 * random value, original URL, original method, issuer, response_type, response_mod, prompt and timestamp
	 * encoded as JSON, encrypting the resulting JSON value
	 */
	char *cookieValue = oidc_proto_state_to_cookie(r, c, proto_state);
	if (cookieValue == NULL)
		return HTTP_INTERNAL_SERVER_ERROR;

	/*
	 * clean expired state cookies to avoid pollution and optionally
	 * try to avoid the number of state cookies exceeding a max
	 */
	int number_of_cookies = oidc_clean_expired_state_cookies(r, c, NULL, oidc_cfg_delete_oldest_state_cookies(c));
	int max_number_of_cookies = oidc_cfg_max_number_of_state_cookies(c);
	if ((max_number_of_cookies > 0) && (number_of_cookies >= max_number_of_cookies)) {

		oidc_warn(r,
			  "the number of existing, valid state cookies (%d) has exceeded the limit (%d), no additional "
			  "authorization request + state cookie can be generated, aborting the request",
			  number_of_cookies, max_number_of_cookies);
		/*
		 * TODO: the html_send code below caters for the case that there's a user behind a
		 * browser generating this request, rather than a piece of XHR code; how would an
		 * XHR client handle this?
		 */

		/*
		 * it appears that sending content with a 503 turns the HTTP status code
		 * into a 200 so we'll avoid that for now: the user will see Apache specific
		 * readable text anyway
		 *
		 return oidc_util_html_send_error(r, c->error_template,
		 "Too Many Outstanding Requests",
		 apr_psprintf(r->pool,
		 "No authentication request could be generated since there are too many outstanding authentication
		 requests already; you may have to wait up to %d seconds to be able to create a new request",
		 c->state_timeout),
		 HTTP_SERVICE_UNAVAILABLE);
		 */

		return HTTP_SERVICE_UNAVAILABLE;
	}

	/* assemble the cookie name for the state cookie */
	const char *cookieName = oidc_get_state_cookie_name(r, state);

	/* set it as a cookie */
	oidc_http_set_cookie(r, cookieName, cookieValue, -1, OIDC_COOKIE_SAMESITE_LAX(c, r));

	return OK;
}

/*
 * authenticate the user to the selected OP, if the OP is not selected yet perform discovery first
 */
int oidc_request_authenticate_user(request_rec *r, oidc_cfg *c, oidc_provider_t *provider, const char *original_url,
				   const char *login_hint, const char *id_token_hint, const char *prompt,
				   const char *auth_request_params, const char *path_scope) {

	int rc;

	OIDC_METRICS_TIMING_START(r, c);

	oidc_debug(r, "enter");

	if (provider == NULL) {

		// TODO: should we use an explicit redirect to the discovery endpoint (maybe a "discovery" param to the
		// redirect_uri)?
		if (c->metadata_dir != NULL) {
			/*
			 * No authentication done but request not allowed without authentication
			 * by setting r->user
			 */
			oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_DISCOVERY, "");
			oidc_debug(r, "defer discovery to the content handler, setting r->user=\"\"");
			r->user = "";

			return OK;
		}

		/* we're not using multiple OP's configured in a metadata directory, pick the statically configured OP
		 */
		if (oidc_provider_static_config(r, c, &provider) == FALSE) {
			OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_PROVIDER);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	/* generate the random nonce value that correlates requests and responses */
	char *nonce = NULL;
	if (oidc_proto_generate_nonce(r, &nonce, OIDC_PROTO_NONCE_LENGTH) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	char *pkce_state = NULL;
	char *code_challenge = NULL;

	if ((oidc_util_spaced_string_contains(r->pool, provider->response_type, OIDC_PROTO_CODE) == TRUE) &&
	    (provider->pkce != NULL)) {

		/* generate the code verifier value that correlates authorization requests and code exchange requests */
		if (provider->pkce->state(r, &pkce_state) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;

		/* generate the PKCE code challenge */
		if (provider->pkce->challenge(r, pkce_state, &code_challenge) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* create the state between request/response */
	oidc_proto_state_t *proto_state = oidc_proto_state_new();
	oidc_proto_state_set_original_url(proto_state, original_url);

	if (oidc_proto_state_get_original_url(proto_state) == NULL) {
		oidc_error(
		    r, "could not store the current URL in the state: most probably you need to ensure that it does "
		       "not contain unencoded Unicode characters e.g. by forcing IE 11 to encode all URL characters");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	oidc_proto_state_set_original_method(proto_state, oidc_original_request_method(r, c, TRUE));
	oidc_proto_state_set_issuer(proto_state, provider->issuer);
	oidc_proto_state_set_response_type(proto_state, provider->response_type);
	oidc_proto_state_set_nonce(proto_state, nonce);
	oidc_proto_state_set_timestamp_now(proto_state);
	if (provider->response_mode)
		oidc_proto_state_set_response_mode(proto_state, provider->response_mode);
	if (prompt)
		oidc_proto_state_set_prompt(proto_state, prompt);
	if (pkce_state)
		oidc_proto_state_set_pkce_state(proto_state, pkce_state);

	/* get a hash value that fingerprints the browser concatenated with the random input */
	const char *state = oidc_get_browser_state_hash(r, c, nonce);

	/*
	 * create state that restores the context when the authorization response comes in
	 * and cryptographically bind it to the browser
	 */
	rc = oidc_request_authorization_set_cookie(r, c, state, proto_state);
	if (rc != OK) {
		oidc_proto_state_destroy(proto_state);
		return rc;
	}

	rc = oidc_request_check_cookie_domain(r, c, proto_state, original_url);
	if (rc != OK) {
		oidc_proto_state_destroy(proto_state);
		return rc;
	}

	/* send off to the OpenID Connect Provider */
	// TODO: maybe show intermediate/progress screen "redirecting to"
	rc = oidc_proto_authorization_request(r, provider, login_hint, oidc_get_redirect_uri_iss(r, c, provider), state,
					      proto_state, id_token_hint, code_challenge, auth_request_params,
					      path_scope);

	OIDC_METRICS_TIMING_ADD(r, c, OM_AUTHN_REQUEST);

	return rc;
}
