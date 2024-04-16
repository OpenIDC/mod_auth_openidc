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

/*
 * find out whether the request is a response from an IDP discovery page
 */
apr_byte_t oidc_is_discovery_response(request_rec *r, oidc_cfg *cfg) {
	/*
	 * prereq: this is a call to the configured redirect_uri, now see if:
	 * the OIDC_DISC_OP_PARAM is present
	 */
	return oidc_http_request_has_parameter(r, OIDC_DISC_OP_PARAM) ||
	       oidc_http_request_has_parameter(r, OIDC_DISC_USER_PARAM);
}

/*
 * present the user with an OP selection screen
 */
int oidc_discovery_request(request_rec *r, oidc_cfg *cfg) {

	oidc_debug(r, "enter");

	/* obtain the URL we're currently accessing, to be stored in the state/session */
	char *current_url = oidc_get_current_url(r, cfg->x_forwarded_headers);
	const char *method = oidc_original_request_method(r, cfg, FALSE);

	/* generate CSRF token */
	char *csrf = NULL;
	if (oidc_proto_generate_nonce(r, &csrf, 8) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	const char *path_scopes = oidc_dir_cfg_path_scope(r);
	const char *path_auth_request_params = oidc_dir_cfg_path_auth_request_params(r);

	char *discover_url = oidc_cfg_dir_discover_url(r);
	/* see if there's an external discovery page configured */
	if (discover_url != NULL) {

		/* yes, assemble the parameters for external discovery */
		char *url =
		    apr_psprintf(r->pool, "%s%s%s=%s&%s=%s&%s=%s&%s=%s", discover_url,
				 strchr(discover_url, OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP : OIDC_STR_QUERY,
				 OIDC_DISC_RT_PARAM, oidc_http_escape_string(r, current_url), OIDC_DISC_RM_PARAM,
				 method, OIDC_DISC_CB_PARAM, oidc_http_escape_string(r, oidc_get_redirect_uri(r, cfg)),
				 OIDC_CSRF_NAME, oidc_http_escape_string(r, csrf));

		if (path_scopes != NULL)
			url = apr_psprintf(r->pool, "%s&%s=%s", url, OIDC_DISC_SC_PARAM,
					   oidc_http_escape_string(r, path_scopes));
		if (path_auth_request_params != NULL)
			url = apr_psprintf(r->pool, "%s&%s=%s", url, OIDC_DISC_AR_PARAM,
					   oidc_http_escape_string(r, path_auth_request_params));

		/* log what we're about to do */
		oidc_debug(r, "redirecting to external discovery page: %s", url);

		/* set CSRF cookie */
		oidc_http_set_cookie(r, OIDC_CSRF_NAME, csrf, -1, OIDC_COOKIE_SAMESITE_STRICT(cfg, r));

		/* see if we need to preserve POST parameters through Javascript/HTML5 storage */
		if (oidc_response_post_preserve_javascript(r, url, NULL, NULL) == TRUE)
			return OK;

		/* do the actual redirect to an external discovery page */
		oidc_http_hdr_out_location_set(r, url);

		return HTTP_MOVED_TEMPORARILY;
	}

	/* get a list of all providers configured in the metadata directory */
	apr_array_header_t *arr = NULL;
	if (oidc_metadata_list(r, cfg, &arr) == FALSE)
		return oidc_util_html_send_error(r, cfg->error_template, "Configuration Error",
						 "No configured providers found, contact your administrator",
						 HTTP_UNAUTHORIZED);

	/* assemble a where-are-you-from IDP discovery HTML page */
	const char *s = "			<h3>Select your OpenID Connect Identity Provider</h3>\n";

	/* list all configured providers in there */
	int i;
	for (i = 0; i < arr->nelts; i++) {

		const char *issuer = APR_ARRAY_IDX(arr, i, const char *);
		// TODO: html escape (especially & character)

		char *href = apr_psprintf(
		    r->pool, "%s?%s=%s&amp;%s=%s&amp;%s=%s&amp;%s=%s", oidc_get_redirect_uri(r, cfg),
		    OIDC_DISC_OP_PARAM, oidc_http_escape_string(r, issuer), OIDC_DISC_RT_PARAM,
		    oidc_http_escape_string(r, current_url), OIDC_DISC_RM_PARAM, method, OIDC_CSRF_NAME, csrf);

		if (path_scopes != NULL)
			href = apr_psprintf(r->pool, "%s&amp;%s=%s", href, OIDC_DISC_SC_PARAM,
					    oidc_http_escape_string(r, path_scopes));
		if (path_auth_request_params != NULL)
			href = apr_psprintf(r->pool, "%s&amp;%s=%s", href, OIDC_DISC_AR_PARAM,
					    oidc_http_escape_string(r, path_auth_request_params));

		char *display = (_oidc_strstr(issuer, "https://") == NULL)
				    ? apr_pstrdup(r->pool, issuer)
				    : apr_pstrdup(r->pool, issuer + _oidc_strlen("https://"));

		/* strip port number */
		// char *p = _oidc_strstr(display, ":");
		// if (p != NULL) *p = '\0';
		/* point back to the redirect_uri, where the selection is handled, with an IDP selection and return_to
		 * URL */
		s = apr_psprintf(r->pool, "%s<p><a href=\"%s\">%s</a></p>\n", s, href, display);
	}

	/* add an option to enter an account or issuer name for dynamic OP discovery */
	s = apr_psprintf(r->pool, "%s<form method=\"get\" action=\"%s\">\n", s, oidc_get_redirect_uri(r, cfg));
	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_DISC_RT_PARAM,
			 current_url);
	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_DISC_RM_PARAM,
			 method);
	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_CSRF_NAME,
			 csrf);

	if (path_scopes != NULL)
		s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
				 OIDC_DISC_SC_PARAM, path_scopes);
	if (path_auth_request_params != NULL)
		s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
				 OIDC_DISC_AR_PARAM, path_auth_request_params);

	s = apr_psprintf(r->pool,
			 "%s<p>Or enter your account name (eg. &quot;mike@seed.gluu.org&quot;, or an IDP identifier "
			 "(eg. &quot;mitreid.org&quot;):</p>\n",
			 s);
	s = apr_psprintf(r->pool, "%s<p><input type=\"text\" name=\"%s\" value=\"%s\"></p>\n", s, OIDC_DISC_OP_PARAM,
			 "");
	s = apr_psprintf(r->pool, "%s<p><input type=\"submit\" value=\"Submit\"></p>\n", s);
	s = apr_psprintf(r->pool, "%s</form>\n", s);

	oidc_http_set_cookie(r, OIDC_CSRF_NAME, csrf, -1, OIDC_COOKIE_SAMESITE_STRICT(cfg, r));

	char *javascript = NULL, *javascript_method = NULL;
	char *html_head = "<style type=\"text/css\">body {text-align: center}</style>";
	if (oidc_response_post_preserve_javascript(r, NULL, &javascript, &javascript_method) == TRUE)
		html_head = apr_psprintf(r->pool, "%s%s", html_head, javascript);

	/* now send the HTML contents to the user agent */
	return oidc_util_html_send(r, "OpenID Connect Provider Discovery", html_head, javascript_method, s, OK);
}

/*
 * check if the target_link_uri matches to configuration settings to prevent an open redirect
 */
static int oidc_discovery_target_link_uri_match(request_rec *r, oidc_cfg *cfg, const char *target_link_uri) {

	apr_uri_t o_uri;
	apr_uri_parse(r->pool, target_link_uri, &o_uri);
	if (o_uri.hostname == NULL) {
		oidc_error(r, "could not parse the \"target_link_uri\" (%s) in to a valid URL: aborting.",
			   target_link_uri);
		return FALSE;
	}

	apr_uri_t r_uri;
	apr_uri_parse(r->pool, oidc_get_redirect_uri(r, cfg), &r_uri);

	if (cfg->cookie_domain == NULL) {
		/* cookie_domain set: see if the target_link_uri matches the redirect_uri host (because the session
		 * cookie will be set host-wide) */
		if (_oidc_strcmp(o_uri.hostname, r_uri.hostname) != 0) {
			char *p = _oidc_strstr(o_uri.hostname, r_uri.hostname);
			if ((p == NULL) || (_oidc_strcmp(r_uri.hostname, p) != 0)) {
				oidc_error(r,
					   "the URL hostname (%s) of the configured " OIDCRedirectURI
					   " does not match the URL hostname of the \"target_link_uri\" (%s): aborting "
					   "to prevent an open redirect.",
					   r_uri.hostname, o_uri.hostname);
				return FALSE;
			}
		}
	} else {
		/* cookie_domain set: see if the target_link_uri is within the cookie_domain */
		char *p = _oidc_strstr(o_uri.hostname, cfg->cookie_domain);
		if ((p == NULL) || (_oidc_strcmp(cfg->cookie_domain, p) != 0)) {
			oidc_error(r,
				   "the domain (%s) configured in " OIDCCookieDomain
				   " does not match the URL hostname (%s) of the \"target_link_uri\" (%s): aborting to "
				   "prevent an open redirect.",
				   cfg->cookie_domain, o_uri.hostname, target_link_uri);
			return FALSE;
		}
	}

	/* see if the cookie_path setting matches the target_link_uri path */
	char *cookie_path = oidc_cfg_dir_cookie_path(r);
	if (cookie_path != NULL) {
		char *p = (o_uri.path != NULL) ? _oidc_strstr(o_uri.path, cookie_path) : NULL;
		if (p != o_uri.path) {
			oidc_error(r,
				   "the path (%s) configured in " OIDCCookiePath
				   " does not match the URL path (%s) of the \"target_link_uri\" (%s): aborting to "
				   "prevent an open redirect.",
				   cookie_path, o_uri.path, target_link_uri);
			return FALSE;
		} else if (_oidc_strlen(o_uri.path) > _oidc_strlen(cookie_path)) {
			int n = _oidc_strlen(cookie_path);
			if (cookie_path[n - 1] == OIDC_CHAR_FORWARD_SLASH)
				n--;
			if (o_uri.path[n] != OIDC_CHAR_FORWARD_SLASH) {
				oidc_error(r,
					   "the path (%s) configured in " OIDCCookiePath
					   " does not match the URL path (%s) of the \"target_link_uri\" (%s): "
					   "aborting to prevent an open redirect.",
					   cookie_path, o_uri.path, target_link_uri);
				return FALSE;
			}
		}
	}
	return TRUE;
}

/*
 * handle a response from an IDP discovery page and/or handle 3rd-party initiated SSO
 */
int oidc_discovery_response(request_rec *r, oidc_cfg *c) {

	/* variables to hold the values returned in the response */
	char *issuer = NULL, *target_link_uri = NULL, *login_hint = NULL, *auth_request_params = NULL, *csrf_cookie,
	     *csrf_query = NULL, *user = NULL, *path_scopes;
	oidc_provider_t *provider = NULL;
	char *error_str = NULL;
	char *error_description = NULL;

	oidc_http_request_parameter_get(r, OIDC_DISC_OP_PARAM, &issuer);
	oidc_http_request_parameter_get(r, OIDC_DISC_USER_PARAM, &user);
	oidc_http_request_parameter_get(r, OIDC_DISC_RT_PARAM, &target_link_uri);
	oidc_http_request_parameter_get(r, OIDC_DISC_LH_PARAM, &login_hint);
	oidc_http_request_parameter_get(r, OIDC_DISC_SC_PARAM, &path_scopes);
	oidc_http_request_parameter_get(r, OIDC_DISC_AR_PARAM, &auth_request_params);
	oidc_http_request_parameter_get(r, OIDC_CSRF_NAME, &csrf_query);
	csrf_cookie = oidc_http_get_cookie(r, OIDC_CSRF_NAME);

	/* do CSRF protection if not 3rd party initiated SSO */
	if (csrf_cookie) {

		/* clean CSRF cookie */
		oidc_http_set_cookie(r, OIDC_CSRF_NAME, "", 0, OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r));

		/* compare CSRF cookie value with query parameter value */
		if ((csrf_query == NULL) || _oidc_strcmp(csrf_query, csrf_cookie) != 0) {
			oidc_warn(
			    r, "CSRF protection failed, no Discovery and dynamic client registration will be allowed");
			csrf_cookie = NULL;
		}
	}

	// TODO: trim issuer/accountname/domain input and do more input validation

	oidc_debug(r, "issuer=\"%s\", target_link_uri=\"%s\", login_hint=\"%s\", user=\"%s\"", issuer, target_link_uri,
		   login_hint, user);

	if (target_link_uri == NULL) {
		if (c->default_sso_url == NULL) {
			return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
							 "SSO to this module without specifying a \"target_link_uri\" "
							 "parameter is not possible because " OIDCDefaultURL
							 " is not set.",
							 HTTP_INTERNAL_SERVER_ERROR);
		}
		target_link_uri = apr_pstrdup(r->pool, oidc_get_absolute_url(r, c, c->default_sso_url));
	}

	/* do open redirect prevention, step 1 */
	if (oidc_discovery_target_link_uri_match(r, c, target_link_uri) == FALSE) {
		return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
						 "\"target_link_uri\" parameter does not match configuration settings, "
						 "aborting to prevent an open redirect.",
						 HTTP_UNAUTHORIZED);
	}

	/* do input validation on the target_link_uri parameter value, step 2 */
	if (oidc_validate_redirect_url(r, c, target_link_uri, TRUE, &error_str, &error_description) == FALSE) {
		return oidc_util_html_send_error(r, c->error_template, error_str, error_description, HTTP_UNAUTHORIZED);
	}

	/* see if this is a static setup */
	if (c->metadata_dir == NULL) {
		if ((oidc_provider_static_config(r, c, &provider) == TRUE) && (issuer != NULL)) {
			if (_oidc_strcmp(provider->issuer, issuer) != 0) {
				return oidc_util_html_send_error(
				    r, c->error_template, "Invalid Request",
				    apr_psprintf(
					r->pool,
					"The \"iss\" value must match the configured providers' one (%s != %s).",
					issuer, c->provider.issuer),
				    HTTP_INTERNAL_SERVER_ERROR);
			}
		}
		return oidc_request_authenticate_user(r, c, NULL, target_link_uri, login_hint, NULL, NULL,
						      auth_request_params, path_scopes);
	}

	/* find out if the user entered an account name or selected an OP manually */
	if (user != NULL) {

		if (login_hint == NULL)
			login_hint = apr_pstrdup(r->pool, user);

		/* normalize the user identifier */
		if (_oidc_strstr(user, "https://") != user)
			user = apr_psprintf(r->pool, "https://%s", user);

		/* got an user identifier as input, perform OP discovery with that */
		if (oidc_proto_url_based_discovery(r, c, user, &issuer) == FALSE) {

			/* something did not work out, show a user facing error */
			return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
							 "Could not resolve the provided user identifier to an OpenID "
							 "Connect provider; check your syntax.",
							 HTTP_NOT_FOUND);
		}

		/* issuer is set now, so let's continue as planned */

	} else if (_oidc_strstr(issuer, OIDC_STR_AT) != NULL) {

		if (login_hint == NULL) {
			login_hint = apr_pstrdup(r->pool, issuer);
			// char *p = _oidc_strstr(issuer, OIDC_STR_AT);
			//*p = '\0';
		}

		/* got an account name as input, perform OP discovery with that */
		if (oidc_proto_account_based_discovery(r, c, issuer, &issuer) == FALSE) {

			/* something did not work out, show a user facing error */
			return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
							 "Could not resolve the provided account name to an OpenID "
							 "Connect provider; check your syntax.",
							 HTTP_NOT_FOUND);
		}

		/* issuer is set now, so let's continue as planned */
	}

	/* strip trailing '/' */
	int n = _oidc_strlen(issuer);
	if (issuer[n - 1] == OIDC_CHAR_FORWARD_SLASH)
		issuer[n - 1] = '\0';

	if (oidc_http_request_has_parameter(r, "test-config")) {
		json_t *j_provider = NULL;
		oidc_metadata_provider_get(r, c, issuer, &j_provider, csrf_cookie != NULL);
		if (j_provider)
			json_decref(j_provider);
		return OK;
	}

	/* try and get metadata from the metadata directories for the selected OP */
	if ((oidc_metadata_get(r, c, issuer, &provider, csrf_cookie != NULL) == TRUE) && (provider != NULL)) {

		if (oidc_http_request_has_parameter(r, "test-jwks-uri")) {
			json_t *j_jwks = NULL;
			apr_byte_t force_refresh = TRUE;
			oidc_metadata_jwks_get(r, c, &provider->jwks_uri, provider->ssl_validate_server, &j_jwks,
					       &force_refresh);
			json_decref(j_jwks);
			return OK;
		} else {
			/* now we've got a selected OP, send the user there to authenticate */
			return oidc_request_authenticate_user(r, c, provider, target_link_uri, login_hint, NULL, NULL,
							      auth_request_params, path_scopes);
		}
	}

	/* something went wrong */
	return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
					 "Could not find valid provider metadata for the selected OpenID Connect "
					 "provider; contact the administrator",
					 HTTP_NOT_FOUND);
}
