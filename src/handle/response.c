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

/*
 * redirect the browser to the session logout endpoint
 */
static int oidc_response_redirect_parent_window_to_logout(request_rec *r, oidc_cfg *c) {

	oidc_debug(r, "enter");

	char *java_script = apr_psprintf(r->pool,
					 "    <script type=\"text/javascript\">\n"
					 "      window.top.location.href = '%s?session=logout';\n"
					 "    </script>\n",
					 oidc_util_javascript_escape(r->pool, oidc_get_redirect_uri(r, c)));

	return oidc_util_html_send(r, "Redirecting...", java_script, NULL, NULL, OK);
}

/*
 * handle an error returned by the OP
 */
static int oidc_response_authorization_error(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state,
					     const char *error, const char *error_description) {
	const char *prompt = oidc_proto_state_get_prompt(proto_state);
	if (prompt != NULL)
		prompt = apr_pstrdup(r->pool, prompt);
	oidc_proto_state_destroy(proto_state);
	if ((prompt != NULL) && (_oidc_strcmp(prompt, OIDC_PROTO_PROMPT_NONE) == 0)) {
		return oidc_response_redirect_parent_window_to_logout(r, c);
	}
	return oidc_util_html_send_error(r, c->error_template,
					 apr_psprintf(r->pool, "OpenID Connect Provider error: %s", error),
					 error_description, c->error_template ? OK : HTTP_BAD_REQUEST);
}

/* handle the browser back on an authorization response */
static apr_byte_t oidc_response_browser_back(request_rec *r, const char *r_state, oidc_session_t *session) {

	/*  see if we have an existing session and browser-back was used */
	const char *s_state = NULL, *o_url = NULL;

	if (session->remote_user != NULL) {

		s_state = oidc_session_get_request_state(r, session);
		o_url = oidc_session_get_original_url(r, session);

		if ((r_state != NULL) && (s_state != NULL) && (_oidc_strcmp(r_state, s_state) == 0)) {

			/* log the browser back event detection */
			oidc_warn(r, "browser back detected, redirecting to original URL: %s", o_url);

			/* go back to the URL that he originally tried to access */
			oidc_http_hdr_out_location_set(r, o_url);

			return TRUE;
		}
	}

	return FALSE;
}

static char *_oidc_response_post_preserve_template_contents = NULL;

/*
 * send an OpenID Connect authorization request to the specified provider preserving POST parameters using HTML5 storage
 */
apr_byte_t oidc_response_post_preserve_javascript(request_rec *r, const char *location, char **javascript,
						  char **javascript_method) {

	if (oidc_cfg_dir_preserve_post(r) == 0)
		return FALSE;

	oidc_debug(r, "enter");

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	const char *method = oidc_original_request_method(r, cfg, FALSE);

	if (_oidc_strcmp(method, OIDC_METHOD_FORM_POST) != 0)
		return FALSE;

	/* read the parameters that are POST-ed to us */
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_http_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r, "something went wrong when reading the POST parameters");
		return FALSE;
	}

	const apr_array_header_t *arr = apr_table_elts(params);
	const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
	int i;
	char *json = "";
	for (i = 0; i < arr->nelts; i++) {
		json = apr_psprintf(r->pool, "%s'%s': '%s'%s", json, oidc_http_escape_string(r, elts[i].key),
				    oidc_http_escape_string(r, elts[i].val), i < arr->nelts - 1 ? "," : "");
	}
	json = apr_psprintf(r->pool, "{ %s }", json);

	if (cfg->post_preserve_template != NULL)
		if (oidc_util_html_send_in_template(
			r, cfg->post_preserve_template, &_oidc_response_post_preserve_template_contents, json,
			OIDC_POST_PRESERVE_ESCAPE_NONE, location, OIDC_POST_PRESERVE_ESCAPE_JAVASCRIPT, OK) == OK)
			return TRUE;

	const char *jmethod = "preserveOnLoad";
	const char *jscript = apr_psprintf(
	    r->pool,
	    "    <script type=\"text/javascript\">\n"
	    "      function %s() {\n"
	    "        sessionStorage.setItem('mod_auth_openidc_preserve_post_params', JSON.stringify(%s));\n"
	    "        %s"
	    "      }\n"
	    "    </script>\n",
	    jmethod, json,
	    location ? apr_psprintf(r->pool, "window.location='%s';\n", oidc_util_javascript_escape(r->pool, location))
		     : "");
	if (location == NULL) {
		if (javascript_method)
			*javascript_method = apr_pstrdup(r->pool, jmethod);
		if (javascript)
			*javascript = apr_pstrdup(r->pool, jscript);
	} else {
		oidc_util_html_send(r, "Preserving...", jscript, jmethod, "<p>Preserving...</p>", OK);
	}

	return TRUE;
}

/*
 * restore POST parameters on original_url from HTML5 session storage
 */
static int oidc_response_post_preserved_restore(request_rec *r, const char *original_url) {

	oidc_debug(r, "enter: original_url=%s", original_url);

	const char *method = "postOnLoad";
	const char *script =
	    apr_psprintf(r->pool,
			 "    <script type=\"text/javascript\">\n"
			 "      function str_decode(string) {\n"
			 "        try {\n"
			 "          result = decodeURIComponent(string);\n"
			 "        } catch (e) {\n"
			 "          result =  unescape(string);\n"
			 "        }\n"
			 "        return result;\n"
			 "      }\n"
			 "      function %s() {\n"
			 "        var mod_auth_openidc_preserve_post_params = "
			 "JSON.parse(sessionStorage.getItem('mod_auth_openidc_preserve_post_params'));\n"
			 "		 sessionStorage.removeItem('mod_auth_openidc_preserve_post_params');\n"
			 "        for (var key in mod_auth_openidc_preserve_post_params) {\n"
			 "          var input = document.createElement(\"input\");\n"
			 "          input.type = \"hidden\";\n"
			 "          input.name = str_decode(key);\n"
			 "          input.value = str_decode(mod_auth_openidc_preserve_post_params[key]);\n"
			 "          document.forms[0].appendChild(input);\n"
			 "        }\n"
			 "        document.forms[0].action = \"%s\";\n"
			 "        document.forms[0].submit();\n"
			 "      }\n"
			 "    </script>\n",
			 method, oidc_util_javascript_escape(r->pool, original_url));

	const char *body = "    <p>Restoring...</p>\n"
			   "    <form method=\"post\"></form>\n";

	return oidc_util_html_send(r, "Restoring...", script, method, body, OK);
}

char *oidc_response_make_sid_iss_unique(request_rec *r, const char *sid, const char *issuer) {
	return apr_psprintf(r->pool, "%s@%s", sid, issuer);
}

/*
 * store resolved information in the session
 */
apr_byte_t oidc_response_save_in_session(request_rec *r, oidc_cfg *c, oidc_session_t *session,
					 oidc_provider_t *provider, const char *remoteUser, const char *id_token,
					 oidc_jwt_t *id_token_jwt, const char *claims, const char *access_token,
					 const int expires_in, const char *refresh_token, const char *session_state,
					 const char *state, const char *original_url, const char *userinfo_jwt) {

	/* store the user in the session */
	session->remote_user = apr_pstrdup(r->pool, remoteUser);

	/* set the session expiry to the inactivity timeout */
	session->expiry = apr_time_now() + apr_time_from_sec(c->session_inactivity_timeout);

	/* store the claims payload in the id_token for later reference */
	oidc_session_set_idtoken_claims(r, session, id_token_jwt->payload.value.str);

	if (c->store_id_token == TRUE) {
		/* store the compact serialized representation of the id_token for later reference  */
		oidc_session_set_idtoken(r, session, id_token);
	}

	/* store the issuer in the session (at least needed for session mgmt and token refresh */
	oidc_session_set_issuer(r, session, provider->issuer);

	/* store the state and original URL in the session for handling browser-back more elegantly */
	oidc_session_set_request_state(r, session, state);
	oidc_session_set_original_url(r, session, original_url);

	if ((session_state != NULL) && (provider->check_session_iframe != NULL)) {
		/* store the session state and required parameters session management  */
		oidc_session_set_session_state(r, session, session_state);
		oidc_debug(r,
			   "session management enabled: stored session_state (%s), check_session_iframe (%s) and "
			   "client_id (%s) in the session",
			   session_state, provider->check_session_iframe, provider->client_id);
	} else if (provider->check_session_iframe == NULL) {
		oidc_debug(
		    r, "session management disabled: \"check_session_iframe\" is not set in provider configuration");
	} else {
		oidc_debug(r,
			   "session management disabled: no \"session_state\" value is provided in the authentication "
			   "response even though \"check_session_iframe\" (%s) is set in the provider configuration",
			   provider->check_session_iframe);
	}

	/* store the, possibly, provider specific userinfo_refresh_interval for performance reasons */
	oidc_session_set_userinfo_refresh_interval(r, session, provider->userinfo_refresh_interval);

	/* store claims resolved from userinfo endpoint */
	oidc_userinfo_store_claims(r, c, session, provider, claims, userinfo_jwt);

	/* see if we have an access_token */
	if (access_token != NULL) {
		/* store the access_token in the session context */
		oidc_session_set_access_token(r, session, access_token);
		/* store the associated expires_in value */
		oidc_session_set_access_token_expires(r, session, expires_in);
		/* reset the access token refresh timestamp */
		oidc_session_set_access_token_last_refresh(r, session, apr_time_now());
	}

	/* see if we have a refresh_token */
	if (refresh_token != NULL) {
		/* store the refresh_token in the session context */
		oidc_session_set_refresh_token(r, session, refresh_token);
	}

	/* store max session duration in the session as a hard cut-off expiry timestamp */
	apr_time_t session_expires = (provider->session_max_duration == 0)
					 ? apr_time_from_sec(id_token_jwt->payload.exp)
					 : (apr_time_now() + apr_time_from_sec(provider->session_max_duration));
	oidc_session_set_session_expires(r, session, session_expires);

	oidc_debug(r, "provider->session_max_duration = %d, session_expires=%" APR_TIME_T_FMT,
		   provider->session_max_duration, session_expires);

	/* log message about max session duration */
	oidc_log_session_expires(r, "session max lifetime", session_expires);

	/* store the domain for which this session is valid */
	oidc_session_set_cookie_domain(
	    r, session, c->cookie_domain ? c->cookie_domain : oidc_get_current_url_host(r, c->x_forwarded_headers));

	char *sid = NULL;
	oidc_debug(r, "provider->backchannel_logout_supported=%d", provider->backchannel_logout_supported);
	/*
	 * Storing the sid in the session makes sense even if no backchannel logout
	 * is supported as the front channel logout as specified in
	 * "OpenID Connect Front-Channel Logout 1.0 - draft 05" at
	 * https://openid.net/specs/openid-connect-frontchannel-1_0.html
	 * might deliver a sid during front channel logout.
	 */
	oidc_jose_get_string(r->pool, id_token_jwt->payload.value.json, OIDC_CLAIM_SID, FALSE, &sid, NULL);
	if (sid == NULL)
		sid = id_token_jwt->payload.sub;
	session->sid = oidc_response_make_sid_iss_unique(r, sid, provider->issuer);

	/* store the session */
	return oidc_session_save(r, session, TRUE);
}

/*
 * restore the state that was maintained between authorization request and response in an encrypted cookie
 */
static apr_byte_t oidc_response_proto_state_restore(request_rec *r, oidc_cfg *c, const char *state,
						    oidc_proto_state_t **proto_state) {

	oidc_debug(r, "enter");

	const char *cookieName = oidc_get_state_cookie_name(r, state);

	/* clean expired state cookies to avoid pollution */
	oidc_clean_expired_state_cookies(r, c, cookieName, FALSE);

	/* get the state cookie value first */
	char *cookieValue = oidc_http_get_cookie(r, cookieName);
	if (cookieValue == NULL) {
		oidc_error(r, "no \"%s\" state cookie found: check domain and samesite cookie settings", cookieName);
		return FALSE;
	}

	/* clear state cookie because we don't need it anymore */
	oidc_http_set_cookie(r, cookieName, "", 0, OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r));

	*proto_state = oidc_proto_state_from_cookie(r, c, cookieValue);
	if (*proto_state == NULL)
		return FALSE;

	const char *nonce = oidc_proto_state_get_nonce(*proto_state);

	/* calculate the hash of the browser fingerprint concatenated with the nonce */
	char *calc = oidc_get_browser_state_hash(r, c, nonce);
	/* compare the calculated hash with the value provided in the authorization response */
	if (_oidc_strcmp(calc, state) != 0) {
		oidc_error(
		    r,
		    "calculated state from cookie does not match state parameter passed back in URL: \"%s\" != \"%s\"",
		    state, calc);
		oidc_proto_state_destroy(*proto_state);
		return FALSE;
	}

	apr_time_t ts = oidc_proto_state_get_timestamp(*proto_state);

	/* check that the timestamp is not beyond the valid interval */
	if (apr_time_now() > ts + apr_time_from_sec(c->state_timeout)) {
		oidc_error(r, "state has expired");
		if ((c->default_sso_url == NULL) ||
		    (apr_table_get(r->subprocess_env, "OIDC_NO_DEFAULT_URL_ON_STATE_TIMEOUT") != NULL)) {
			oidc_util_html_send_error(
			    r, c->error_template, "Invalid Authentication Response",
			    apr_psprintf(r->pool,
					 "This is due to a timeout; please restart your authentication session by "
					 "re-entering the URL/bookmark you originally wanted to access: %s",
					 oidc_proto_state_get_original_url(*proto_state)),
			    OK);
		}
		oidc_proto_state_destroy(*proto_state);
		return FALSE;
	}

	/* add the state */
	oidc_proto_state_set_state(*proto_state, state);

	/* log the restored state object */
	oidc_debug(r, "restored state: %s", oidc_proto_state_to_string(r, *proto_state));

	/* we've made it */
	return TRUE;
}

/*
 * helper function for basic/implicit client flows upon receiving an authorization response:
 * check that it matches the state stored in the browser and return the variables associated
 * with the state, such as original_url and OP oidc_provider_t pointer.
 */
static apr_byte_t oidc_response_match_state(request_rec *r, oidc_cfg *c, const char *state,
					    struct oidc_provider_t **provider, oidc_proto_state_t **proto_state) {

	oidc_debug(r, "enter (state=%s)", state);

	if ((state == NULL) || (_oidc_strcmp(state, "") == 0)) {
		oidc_error(r, "state parameter is not set");
		return FALSE;
	}

	/* check the state parameter against what we stored in a cookie */
	if (oidc_response_proto_state_restore(r, c, state, proto_state) == FALSE) {
		oidc_error(r, "unable to restore state");
		return FALSE;
	}

	*provider = oidc_get_provider_for_issuer(r, c, oidc_proto_state_get_issuer(*proto_state), FALSE);

	if (*provider == NULL) {
		oidc_proto_state_destroy(*proto_state);
		*proto_state = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * handle the different flows (hybrid, implicit, Authorization Code)
 */
static apr_byte_t oidc_response_flows(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state,
				      oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
				      oidc_jwt_t **jwt) {

	apr_byte_t rc = FALSE;

	const char *requested_response_type = oidc_proto_state_get_response_type(proto_state);

	/* handle the requested response type/mode */
	if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
					   OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN)) {
		rc = oidc_proto_authorization_response_code_idtoken_token(r, c, proto_state, provider, params,
									  response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
						  OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN)) {
		rc = oidc_proto_authorization_response_code_idtoken(r, c, proto_state, provider, params, response_mode,
								    jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
						  OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN)) {
		rc = oidc_proto_handle_authorization_response_code_token(r, c, proto_state, provider, params,
									 response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_CODE)) {
		rc = oidc_proto_handle_authorization_response_code(r, c, proto_state, provider, params, response_mode,
								   jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
						  OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN)) {
		rc = oidc_proto_handle_authorization_response_idtoken_token(r, c, proto_state, provider, params,
									    response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN)) {
		rc = oidc_proto_handle_authorization_response_idtoken(r, c, proto_state, provider, params,
								      response_mode, jwt);
	} else {
		oidc_error(r, "unsupported response type: \"%s\"", requested_response_type);
	}

	if ((rc == FALSE) && (*jwt != NULL)) {
		oidc_jwt_destroy(*jwt);
		*jwt = NULL;
	}

	return rc;
}

/*
 * set the unique user identifier that will be propagated in the Apache r->user and REMOTE_USER variables
 */
static apr_byte_t oidc_response_set_request_user(request_rec *r, oidc_cfg *c, oidc_provider_t *provider,
						 oidc_jwt_t *jwt, const char *s_claims) {

	char *issuer = provider->issuer;
	char *claim_name = apr_pstrdup(r->pool, c->remote_user_claim.claim_name);
	int n = _oidc_strlen(claim_name);
	apr_byte_t post_fix_with_issuer = (claim_name[n - 1] == OIDC_CHAR_AT);
	if (post_fix_with_issuer == TRUE) {
		claim_name[n - 1] = '\0';
		issuer = (_oidc_strstr(issuer, "https://") == NULL)
			     ? apr_pstrdup(r->pool, issuer)
			     : apr_pstrdup(r->pool, issuer + _oidc_strlen("https://"));
	}

	/* extract the username claim (default: "sub") from the id_token payload or user claims */
	apr_byte_t rc = FALSE;
	char *remote_user = NULL;
	json_t *claims = NULL;
	oidc_util_decode_json_object(r, s_claims, &claims);
	if (claims == NULL) {
		rc = oidc_get_remote_user(r, claim_name, c->remote_user_claim.reg_exp, c->remote_user_claim.replace,
					  jwt->payload.value.json, &remote_user);
	} else {
		oidc_util_json_merge(r, jwt->payload.value.json, claims);
		rc = oidc_get_remote_user(r, claim_name, c->remote_user_claim.reg_exp, c->remote_user_claim.replace,
					  claims, &remote_user);
		json_decref(claims);
	}

	if ((rc == FALSE) || (remote_user == NULL)) {
		oidc_error(r,
			   "" OIDCRemoteUserClaim " is set to \"%s\", but could not set the remote user based on the "
			   "requested claim \"%s\" and the available claims for the user",
			   c->remote_user_claim.claim_name, claim_name);
		return FALSE;
	}

	if (post_fix_with_issuer == TRUE)
		remote_user = apr_psprintf(r->pool, "%s%s%s", remote_user, OIDC_STR_AT, issuer);

	r->user = apr_pstrdup(r->pool, remote_user);

	oidc_debug(r, "set remote_user to \"%s\" based on claim: \"%s\"%s", r->user, c->remote_user_claim.claim_name,
		   c->remote_user_claim.reg_exp
		       ? apr_psprintf(r->pool, " and expression: \"%s\" and replace string: \"%s\"",
				      c->remote_user_claim.reg_exp, c->remote_user_claim.replace)
		       : "");

	return TRUE;
}

static char *_oidc_response_post_restore_template_contents = NULL;

/*
 * complete the handling of an authorization response by obtaining, parsing and verifying the
 * id_token and storing the authenticated user state in the session
 */
static int oidc_response_process(request_rec *r, oidc_cfg *c, oidc_session_t *session, apr_table_t *params,
				 const char *response_mode) {

	oidc_debug(r, "enter, response_mode=%s", response_mode);

	oidc_provider_t *provider = NULL;
	oidc_proto_state_t *proto_state = NULL;
	oidc_jwt_t *jwt = NULL;

	/* see if this response came from a browser-back event */
	if (oidc_response_browser_back(r, apr_table_get(params, OIDC_PROTO_STATE), session) == TRUE)
		return HTTP_MOVED_TEMPORARILY;

	/* match the returned state parameter against the state stored in the browser */
	if (oidc_response_match_state(r, c, apr_table_get(params, OIDC_PROTO_STATE), &provider, &proto_state) ==
	    FALSE) {
		if (c->default_sso_url != NULL) {
			oidc_warn(r,
				  "invalid authorization response state; a default SSO URL is set, sending the user "
				  "there: %s",
				  c->default_sso_url);
			oidc_http_hdr_out_location_set(r, oidc_get_absolute_url(r, c, c->default_sso_url));
			OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_STATE_MISMATCH);
			return HTTP_MOVED_TEMPORARILY;
		}
		oidc_error(r,
			   "invalid authorization response state and no default SSO URL is set, sending an error...");

		if (c->error_template) {
			// retain backwards compatibility
			int rc = HTTP_BAD_REQUEST;
			if ((r->user) && (_oidc_strncmp(r->user, "", 1) == 0)) {
				r->header_only = 1;
				r->user = NULL;
				rc = OK;
			}
			OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_STATE_MISMATCH);
			return rc;
		}

		// if error text was already produced (e.g. state timeout) then just return with a 400
		if (apr_table_get(r->subprocess_env, OIDC_ERROR_ENVVAR) != NULL) {
			OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_STATE_EXPIRED);
			return HTTP_BAD_REQUEST;
		}

		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_STATE_MISMATCH);

		return oidc_util_html_send_error(r, c->error_template, "Invalid Authorization Response",
						 "Could not match the authorization response to an earlier request via "
						 "the state parameter and corresponding state cookie",
						 HTTP_BAD_REQUEST);
	}

	/* see if the response is an error response */
	if (apr_table_get(params, OIDC_PROTO_ERROR) != NULL) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_PROVIDER);
		return oidc_response_authorization_error(r, c, proto_state, apr_table_get(params, OIDC_PROTO_ERROR),
							 apr_table_get(params, OIDC_PROTO_ERROR_DESCRIPTION));
	}

	/* handle the code, implicit or hybrid flow */
	if (oidc_response_flows(r, c, proto_state, provider, params, response_mode, &jwt) == FALSE) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_PROTOCOL);
		return oidc_response_authorization_error(r, c, proto_state, "Error in handling response type.", NULL);
	}

	if (jwt == NULL) {
		oidc_error(r, "no id_token was provided");
		return oidc_response_authorization_error(r, c, proto_state, "No id_token was provided.", NULL);
	}

	int expires_in = _oidc_str_to_int(apr_table_get(params, OIDC_PROTO_EXPIRES_IN), -1);
	char *userinfo_jwt = NULL;

	/*
	 * optionally resolve additional claims against the userinfo endpoint
	 * parsed claims are not actually used here but need to be parsed anyway for error checking purposes
	 */
	const char *claims = oidc_userinfo_retrieve_claims(
	    r, c, provider, apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN), NULL, jwt->payload.sub, &userinfo_jwt);

	/* restore the original protected URL that the user was trying to access */
	const char *original_url = oidc_proto_state_get_original_url(proto_state);
	if (original_url != NULL)
		original_url = apr_pstrdup(r->pool, original_url);
	const char *original_method = oidc_proto_state_get_original_method(proto_state);
	if (original_method != NULL)
		original_method = apr_pstrdup(r->pool, original_method);
	const char *prompt = oidc_proto_state_get_prompt(proto_state);

	/* set the user */
	if (oidc_response_set_request_user(r, c, provider, jwt, claims) == TRUE) {

		/* session management: if the user in the new response is not equal to the old one, error out */
		if ((prompt != NULL) && (_oidc_strcmp(prompt, OIDC_PROTO_PROMPT_NONE) == 0)) {
			// TOOD: actually need to compare sub? (need to store it in the session separately then
			// const char *sub = NULL;
			// oidc_session_get(r, session, "sub", &sub);
			// if (_oidc_strcmp(sub, jwt->payload.sub) != 0) {
			if (_oidc_strcmp(session->remote_user, r->user) != 0) {
				oidc_warn(r, "user set from new id_token is different from current one");
				oidc_jwt_destroy(jwt);
				return oidc_response_authorization_error(r, c, proto_state, "User changed!", NULL);
			}
		}

		/* store resolved information in the session */
		if (oidc_response_save_in_session(
			r, c, session, provider, r->user, apr_table_get(params, OIDC_PROTO_ID_TOKEN), jwt, claims,
			apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN), expires_in,
			apr_table_get(params, OIDC_PROTO_REFRESH_TOKEN),
			apr_table_get(params, OIDC_PROTO_SESSION_STATE), apr_table_get(params, OIDC_PROTO_STATE),
			original_url, userinfo_jwt) == FALSE) {
			oidc_proto_state_destroy(proto_state);
			oidc_jwt_destroy(jwt);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		oidc_debug(r, "set remote_user to \"%s\" in new session \"%s\"", r->user, session->uuid);

	} else {
		oidc_error(r, "remote user could not be set");
		oidc_jwt_destroy(jwt);
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_REMOTE_USER);
		return oidc_response_authorization_error(
		    r, c, proto_state, "Remote user could not be set: contact the website administrator", NULL);
	}

	/* cleanup */
	oidc_proto_state_destroy(proto_state);
	oidc_jwt_destroy(jwt);

	/* check that we've actually authenticated a user; functions as error handling for oidc_get_remote_user */
	if (r->user == NULL) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHN_RESPONSE_ERROR_REMOTE_USER);
		return HTTP_UNAUTHORIZED;
	}

	/* log the successful response */
	oidc_debug(r, "session created and stored, returning to original URL: %s, original method: %s", original_url,
		   original_method);

	/* check whether form post data was preserved; if so restore it */
	if (_oidc_strcmp(original_method, OIDC_METHOD_FORM_POST) == 0) {
		if (c->post_restore_template != NULL)
			if (oidc_util_html_send_in_template(r, c->post_restore_template,
							    &_oidc_response_post_restore_template_contents,
							    original_url, OIDC_POST_PRESERVE_ESCAPE_JAVASCRIPT, "",
							    OIDC_POST_PRESERVE_ESCAPE_NONE, OK) == OK)
				return TRUE;
		return oidc_response_post_preserved_restore(r, original_url);
	}

	/* now we've authenticated the user so go back to the URL that he originally tried to access */
	oidc_http_hdr_out_location_set(r, original_url);

	/* do the actual redirect to the original URL */
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * handle an OpenID Connect Authorization Response using the POST (+fragment->POST) response_mode
 */
int oidc_response_authorization_post(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	oidc_debug(r, "enter");

	/* initialize local variables */
	const char *response_mode = NULL;

	/* read the parameters that are POST-ed to us */
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_http_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r, "something went wrong when reading the POST parameters");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* see if we've got any POST-ed data at all */
	if ((apr_table_elts(params)->nelts < 1) ||
	    ((apr_table_elts(params)->nelts == 1) && apr_table_get(params, OIDC_PROTO_RESPONSE_MODE) &&
	     (_oidc_strcmp(apr_table_get(params, OIDC_PROTO_RESPONSE_MODE), OIDC_PROTO_RESPONSE_MODE_FRAGMENT) == 0))) {
		return oidc_util_html_send_error(
		    r, c->error_template, "Invalid Request",
		    "You've hit an OpenID Connect Redirect URI with no parameters, this is an invalid request; you "
		    "should not open this URL in your browser directly, or have the server administrator use a "
		    "different " OIDCRedirectURI " setting.",
		    HTTP_INTERNAL_SERVER_ERROR);
	}

	/* get the parameters */
	response_mode = (char *)apr_table_get(params, OIDC_PROTO_RESPONSE_MODE);

	/* do the actual implicit work */
	return oidc_response_process(r, c, session, params,
				     response_mode ? response_mode : OIDC_PROTO_RESPONSE_MODE_FORM_POST);
}

/*
 * handle an OpenID Connect Authorization Response using the redirect response_mode
 */
int oidc_response_authorization_redirect(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	oidc_debug(r, "enter");

	/* read the parameters from the query string */
	apr_table_t *params = apr_table_make(r->pool, 8);
	oidc_http_read_form_encoded_params(r, params, r->args);

	/* do the actual work */
	return oidc_response_process(r, c, session, params, OIDC_PROTO_RESPONSE_MODE_QUERY);
}
