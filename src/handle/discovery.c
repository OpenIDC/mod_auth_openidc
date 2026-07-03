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
#include "handle/handle.h"
#include "metadata.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

/* parameter name of the callback URL in the discovery response */
#define OIDC_DISC_CB_PARAM "oidc_callback"
/* parameter name of the OP provider selection in the discovery response */
#define OIDC_DISC_OP_PARAM "iss"
/* parameter name of the user URL in the discovery response */
#define OIDC_DISC_USER_PARAM "disc_user"
/* parameter name of the original URL in the discovery response */
#define OIDC_DISC_RT_PARAM "target_link_uri"
/* parameter name of login hint in the discovery response */
#define OIDC_DISC_LH_PARAM "login_hint"
/* parameter name of parameters that need to be passed in the authentication request */
#define OIDC_DISC_AR_PARAM "auth_request_params"
/* parameter name of the scopes required in the discovery response */
#define OIDC_DISC_SC_PARAM "scopes"

/*
 * find out whether the request is a response from an IDP discovery page
 */
apr_byte_t oidc_is_discovery_response(request_rec *r, oidc_cfg_t *cfg) {
	/*
	 * prereq: this is a call to the configured redirect_uri, now see if:
	 * the OIDC_DISC_OP_PARAM is present
	 */
	return oidc_util_url_has_parameter(r, OIDC_DISC_OP_PARAM) ||
	       oidc_util_url_has_parameter(r, OIDC_DISC_USER_PARAM);
}

static const char *oidc_discovery_csrf_cookie_samesite(const request_rec *r, const oidc_cfg_t *c) {
	const char *rv = NULL;
	switch (oidc_cfg_cookie_same_site_discovery_csrf_get(c)) {
	case OIDC_SAMESITE_COOKIE_STRICT:
		rv = OIDC_HTTP_COOKIE_SAMESITE_STRICT;
		break;
	case OIDC_SAMESITE_COOKIE_LAX:
		rv = OIDC_HTTP_COOKIE_SAMESITE_LAX;
		break;
	case OIDC_SAMESITE_COOKIE_NONE:
		rv = OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r);
		break;
	case OIDC_SAMESITE_COOKIE_DISABLED:
		break;
	default:
		break;
	}
	return rv;
}

/* define the name of the cookie/parameter for CSRF protection */
#define OIDC_CSRF_NAME "x_csrf"

/*
 * present the user with an OP selection screen
 */
int oidc_discovery_request(request_rec *r, oidc_cfg_t *cfg) {

	oidc_debug(r, "enter");

	/* obtain the URL we're currently accessing, to be stored in the state/session */
	const char *current_url = oidc_util_url_cur(r, oidc_cfg_x_forwarded_headers_get(cfg));
	const char *method = oidc_original_request_method(r, cfg, FALSE);

	/* generate CSRF token; 16 bytes (128 bits) of entropy */
	char *csrf = NULL;
	if (oidc_util_rand_str(r, &csrf, 16) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	const char *path_scopes = oidc_cfg_dir_path_scope_get(r);
	const char *path_auth_request_params = oidc_cfg_dir_path_auth_request_params_get(r);

	const char *discover_url = oidc_cfg_dir_discover_url_get(r);
	/* see if there's an external discovery page configured */
	if (discover_url != NULL) {

		/* yes, assemble the parameters for external discovery */
		char *url =
		    apr_psprintf(r->pool, "%s%s%s=%s&%s=%s&%s=%s&%s=%s", discover_url,
				 strchr(discover_url, OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP : OIDC_STR_QUERY,
				 OIDC_DISC_RT_PARAM, oidc_http_url_encode(r, current_url), OIDC_DISC_RM_PARAM, method,
				 OIDC_DISC_CB_PARAM, oidc_http_url_encode(r, oidc_util_url_redirect_uri(r, cfg)),
				 OIDC_CSRF_NAME, oidc_http_url_encode(r, csrf));

		if (path_scopes != NULL)
			url = apr_psprintf(r->pool, "%s&%s=%s", url, OIDC_DISC_SC_PARAM,
					   oidc_http_url_encode(r, path_scopes));
		if (path_auth_request_params != NULL)
			url = apr_psprintf(r->pool, "%s&%s=%s", url, OIDC_DISC_AR_PARAM,
					   oidc_http_url_encode(r, path_auth_request_params));

		/* log what we're about to do */
		oidc_debug(r, "redirecting to external discovery page: %s", url);

		/* set CSRF cookie */
		oidc_http_set_cookie(r, OIDC_CSRF_NAME, csrf, -1, oidc_discovery_csrf_cookie_samesite(r, cfg));

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
		return oidc_util_html_send_error(r, "Configuration Error",
						 "No configured providers found, contact your administrator",
						 HTTP_UNAUTHORIZED);

	/* assemble a where-are-you-from IDP discovery HTML page */
	const char *s = "\t\t\t<h3>Select your OpenID Connect Identity Provider</h3>\n";

	/* list all configured providers in there */
	for (int i = 0; i < arr->nelts; i++) {

		const char *issuer = APR_ARRAY_IDX(arr, i, const char *);

		char *href = apr_psprintf(
		    r->pool, "%s?%s=%s&amp;%s=%s&amp;%s=%s&amp;%s=%s", oidc_util_url_redirect_uri(r, cfg),
		    OIDC_DISC_OP_PARAM, oidc_http_url_encode(r, issuer), OIDC_DISC_RT_PARAM,
		    oidc_http_url_encode(r, current_url), OIDC_DISC_RM_PARAM, method, OIDC_CSRF_NAME, csrf);

		if (path_scopes != NULL)
			href = apr_psprintf(r->pool, "%s&amp;%s=%s", href, OIDC_DISC_SC_PARAM,
					    oidc_http_url_encode(r, path_scopes));
		if (path_auth_request_params != NULL)
			href = apr_psprintf(r->pool, "%s&amp;%s=%s", href, OIDC_DISC_AR_PARAM,
					    oidc_http_url_encode(r, path_auth_request_params));

		const char *display = (_oidc_strstr(issuer, "https://") == NULL)
					  ? apr_pstrdup(r->pool, issuer)
					  : apr_pstrdup(r->pool, issuer + _oidc_strlen("https://"));

		/* strip port number */
		/* point back to the redirect_uri, where the selection is handled, with an IDP selection and return_to
		 * URL */
		s = apr_psprintf(r->pool, "%s<p><a href=\"%s\">%s</a></p>\n", s, href,
				 oidc_util_html_escape(r->pool, display));
	}

	/* add an option to enter an account or issuer name for dynamic OP discovery */
	s = apr_psprintf(r->pool, "%s<form method=\"get\" action=\"%s\">\n", s, oidc_util_url_redirect_uri(r, cfg));
	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_DISC_RT_PARAM,
			 oidc_util_html_escape(r->pool, current_url));
	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_DISC_RM_PARAM,
			 oidc_util_html_escape(r->pool, method));
	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_CSRF_NAME,
			 oidc_util_html_escape(r->pool, csrf));

	if (path_scopes != NULL)
		s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
				 OIDC_DISC_SC_PARAM, oidc_util_html_escape(r->pool, path_scopes));
	if (path_auth_request_params != NULL)
		s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
				 OIDC_DISC_AR_PARAM, oidc_util_html_escape(r->pool, path_auth_request_params));

	s = apr_psprintf(r->pool,
			 "%s<p>Or enter your account name (eg. &quot;mike@seed.gluu.org&quot;, or an IDP identifier "
			 "(eg. &quot;mitreid.org&quot;):</p>\n",
			 s);
	s = apr_psprintf(r->pool, "%s<p><input type=\"text\" name=\"%s\" value=\"%s\"></p>\n", s, OIDC_DISC_OP_PARAM,
			 "");
	s = apr_psprintf(r->pool, "%s<p><input type=\"submit\" value=\"Submit\"></p>\n", s);
	s = apr_psprintf(r->pool, "%s</form>\n", s);

	oidc_http_set_cookie(r, OIDC_CSRF_NAME, csrf, -1, oidc_discovery_csrf_cookie_samesite(r, cfg));

	char *javascript = NULL;
	char *javascript_method = NULL;
	char *html_head = "<style type=\"text/css\">body {text-align: center}</style>";
	if (oidc_response_post_preserve_javascript(r, NULL, &javascript, &javascript_method) == TRUE)
		html_head = apr_psprintf(r->pool, "%s%s", html_head, javascript);

	/* now send the HTML contents to the user agent */
	return oidc_util_html_send(r, "OpenID Connect Provider Discovery", html_head, javascript_method, s, OK);
}

/*
 * check if the target_link_uri matches to configuration settings to prevent an open redirect
 */
static int oidc_discovery_target_link_uri_match(request_rec *r, const oidc_cfg_t *cfg, const char *target_link_uri) {

	apr_uri_t o_uri;
	apr_uri_parse(r->pool, target_link_uri, &o_uri);
	if (o_uri.hostname == NULL) {
		oidc_error(r, "could not parse the \"target_link_uri\" (%s) in to a valid URL: aborting.",
			   target_link_uri);
		return FALSE;
	}

	apr_uri_t r_uri;
	apr_uri_parse(r->pool, oidc_util_url_redirect_uri(r, cfg), &r_uri);

	if (oidc_cfg_cookie_domain_get(cfg) == NULL) {
		/* no cookie_domain set: target_link_uri host must be equal to, or a subdomain of, the redirect_uri host
		 * (because that's where the session cookie will be set) */
		if (oidc_util_hostname_endswith(o_uri.hostname, r_uri.hostname) == FALSE) {
			oidc_error(r,
				   "the URL hostname (%s) of the configured " OIDCRedirectURI
				   " does not match the URL hostname of the \"target_link_uri\" (%s): aborting "
				   "to prevent an open redirect.",
				   r_uri.hostname, o_uri.hostname);
			return FALSE;
		}
	} else {
		/* cookie_domain set: see if the target_link_uri is within the cookie_domain */
		if (oidc_util_cookie_domain_valid(o_uri.hostname, oidc_cfg_cookie_domain_get(cfg)) == FALSE) {
			oidc_error(r,
				   "the domain (%s) configured in " OIDCCookieDomain
				   " does not match the URL hostname (%s) of the \"target_link_uri\" (%s): aborting to "
				   "prevent an open redirect.",
				   oidc_cfg_cookie_domain_get(cfg), o_uri.hostname, target_link_uri);
			return FALSE;
		}
	}

	/* see if the cookie_path setting matches the target_link_uri path */
	const char *cookie_path = oidc_cfg_dir_cookie_path_get(r);
	if (cookie_path != NULL) {
		const char *p = (o_uri.path != NULL) ? _oidc_strstr(o_uri.path, cookie_path) : NULL;
		if (p != o_uri.path) {
			oidc_error(r,
				   "the path (%s) configured in " OIDCCookiePath
				   " does not match the URL path (%s) of the \"target_link_uri\" (%s): aborting to "
				   "prevent an open redirect.",
				   cookie_path, o_uri.path, target_link_uri);
			return FALSE;
		} else if (_oidc_strlen(o_uri.path) > _oidc_strlen(cookie_path)) {
			int n = (int)_oidc_strlen(cookie_path);
			if ((n > 0) && (cookie_path[n - 1] == OIDC_CHAR_FORWARD_SLASH))
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
 * verify CSRF protection for the discovery response; returns TRUE when a
 * valid CSRF cookie/query pair was found (user-initiated discovery, dynamic
 * client registration allowed), FALSE for 3rd-party initiated SSO or when
 * the CSRF check fails
 */
static apr_byte_t oidc_discovery_response_csrf_check(request_rec *r, const oidc_cfg_t *c) {

	const char *csrf_cookie = oidc_http_get_cookie(r, OIDC_CSRF_NAME);
	char *csrf_query = NULL;

	/* no CSRF cookie means this is 3rd party initiated SSO */
	if (csrf_cookie == NULL)
		return FALSE;

	/* clean CSRF cookie */
	oidc_http_set_cookie(r, OIDC_CSRF_NAME, "", 0, OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r));

	/* compare CSRF cookie value with query parameter value */
	oidc_util_url_parameter_get(r, OIDC_CSRF_NAME, &csrf_query);
	if (oidc_util_strcmp_const_time(csrf_query, csrf_cookie) == FALSE) {
		oidc_warn(r, "CSRF protection failed, no Discovery and dynamic client registration will be allowed");
		return FALSE;
	}

	return TRUE;
}

/*
 * apply the default and validate the target_link_uri; on failure sets
 * *rv to the HTTP status the caller should return
 */
static apr_byte_t oidc_discovery_response_target_link_uri_validate(request_rec *r, const oidc_cfg_t *c,
								   char **target_link_uri, int *rv) {

	char *error_str = NULL;
	char *error_description = NULL;

	if (*target_link_uri == NULL) {
		if (oidc_cfg_default_sso_url_get(c) == NULL) {
			*rv = oidc_util_html_send_error(r, "Invalid Request",
							"SSO to this module without specifying a \"target_link_uri\" "
							"parameter is not possible because " OIDCDefaultURL
							" is not set.",
							HTTP_INTERNAL_SERVER_ERROR);
			return FALSE;
		}
		*target_link_uri = apr_pstrdup(r->pool, oidc_util_url_abs(r, c, oidc_cfg_default_sso_url_get(c)));
	}

	/* do open redirect prevention, step 1 */
	if (oidc_discovery_target_link_uri_match(r, c, *target_link_uri) == FALSE) {
		*rv = oidc_util_html_send_error(r, "Invalid Request",
						"\"target_link_uri\" parameter does not match configuration settings, "
						"aborting to prevent an open redirect.",
						HTTP_UNAUTHORIZED);
		return FALSE;
	}

	/* do input validation on the target_link_uri parameter value, step 2 */
	if (oidc_validate_redirect_url(r, c, *target_link_uri, TRUE, &error_str, &error_description) == FALSE) {
		*rv = oidc_util_html_send_error(r, error_str, error_description, HTTP_UNAUTHORIZED);
		return FALSE;
	}

	return TRUE;
}

/*
 * handle a static (single-OP) configuration: optionally validate that the
 * supplied issuer matches the configured one, then trigger authentication
 */
static int oidc_discovery_response_static(request_rec *r, oidc_cfg_t *c, const char *issuer,
					  const char *target_link_uri, const char *login_hint,
					  const char *auth_request_params, const char *path_scopes) {

	oidc_provider_t *provider = NULL;
	if ((oidc_provider_static_config(r, c, &provider) == TRUE) && (issuer != NULL) &&
	    (_oidc_strcmp(oidc_cfg_provider_issuer_get(provider), issuer) != 0)) {
		return oidc_util_html_send_error(
		    r, "Invalid Request",
		    apr_psprintf(r->pool, "The \"iss\" value must match the configured providers' one (%s != %s).",
				 issuer, oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c))),
		    HTTP_INTERNAL_SERVER_ERROR);
	}

	return oidc_request_authenticate_user(r, c, NULL, target_link_uri, login_hint, NULL, NULL, auth_request_params,
					      path_scopes);
}

/*
 * verify the issuer matches one of the OIDCDiscoverIssuersAllowed regexes, when configured;
 * this bounds the set of hosts that a client-driven Discovery request (webfinger/URL-based,
 * account-based, or direct issuer selection) can cause the server to make outbound requests to
 */
static apr_byte_t oidc_discovery_issuer_allowed(request_rec *r, const oidc_cfg_t *c, const char *issuer) {
	apr_hash_t *allowed = oidc_cfg_discover_issuers_allowed_get(c);
	const char *pattern = NULL;
	char *error_str = NULL;

	if (allowed == NULL)
		return TRUE;

	for (apr_hash_index_t *hi = apr_hash_first(NULL, allowed); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, (const void **)&pattern, NULL, NULL);
		if (oidc_util_regexp_first_match(r->pool, issuer, pattern, NULL, &error_str) == TRUE)
			return TRUE;
	}

	oidc_warn(r, "issuer (%s) does not match the list of allowed Discovery issuers", issuer);
	return FALSE;
}

/*
 * resolve the issuer for user-identifier or account-name based discovery;
 * on failure sets *rv to the HTTP status the caller should return
 */
static apr_byte_t oidc_discovery_response_resolve_issuer(request_rec *r, oidc_cfg_t *c, char *user, char **issuer,
							 char **login_hint, int *rv) {

	if (user != NULL) {

		if (*login_hint == NULL)
			*login_hint = apr_pstrdup(r->pool, user);

		/* normalize the user identifier */
		if (_oidc_strstr(user, "https://") != user)
			user = apr_psprintf(r->pool, "https://%s", user);

		/* enforce the issuer allow-list *before* the webfinger discovery HTTP call itself
		 * (rather than only against the issuer it resolves to): otherwise a disallowed host
		 * could still be probed with an outbound request even though the response would
		 * ultimately be rejected */
		if (oidc_discovery_issuer_allowed(r, c, user) == FALSE) {
			*rv = oidc_util_html_send_error(
			    r, "Invalid Request",
			    "The provided user identifier is not in the list of allowed issuers; contact the "
			    "administrator",
			    HTTP_UNAUTHORIZED);
			return FALSE;
		}

		/* got a user identifier as input, perform OP discovery with that */
		if (oidc_proto_discovery_url_based(r, c, user, issuer) == FALSE) {
			*rv = oidc_util_html_send_error(r, "Invalid Request",
							"Could not resolve the provided user identifier to an OpenID "
							"Connect provider; check your syntax.",
							HTTP_NOT_FOUND);
			return FALSE;
		}

		return TRUE;
	}

	if (_oidc_strstr(*issuer, OIDC_STR_AT) != NULL) {

		if (*login_hint == NULL)
			*login_hint = apr_pstrdup(r->pool, *issuer);

		/* same reasoning as above: gate the domain that account-based (webfinger) discovery
		 * would otherwise probe, before the outbound HTTP call is made */
		const char *domain = strrchr(*issuer, OIDC_CHAR_AT);
		const char *domain_issuer = apr_psprintf(r->pool, "https://%s", domain ? domain + 1 : *issuer);
		if (oidc_discovery_issuer_allowed(r, c, domain_issuer) == FALSE) {
			*rv = oidc_util_html_send_error(
			    r, "Invalid Request",
			    "The provided account name is not in the list of allowed issuers; contact the "
			    "administrator",
			    HTTP_UNAUTHORIZED);
			return FALSE;
		}

		/* got an account name as input, perform OP discovery with that */
		if (oidc_proto_discovery_account_based(r, c, *issuer, issuer) == FALSE) {
			*rv = oidc_util_html_send_error(r, "Invalid Request",
							"Could not resolve the provided account name to an OpenID "
							"Connect provider; check your syntax.",
							HTTP_NOT_FOUND);
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * post-discovery: handle the test-config / test-jwks-uri short-circuits or
 * trigger authentication with the resolved provider
 */
static int oidc_discovery_response_authenticate(request_rec *r, oidc_cfg_t *c, char *issuer,
						const char *target_link_uri, const char *login_hint,
						const char *auth_request_params, const char *path_scopes,
						apr_byte_t allow_dyn_reg) {

	/* strip trailing '/' */
	int n = (int)_oidc_strlen(issuer);
	if ((n > 0) && (issuer[n - 1] == OIDC_CHAR_FORWARD_SLASH))
		issuer[n - 1] = '\0';

	if (oidc_discovery_issuer_allowed(r, c, issuer) == FALSE)
		return oidc_util_html_send_error(
		    r, "Invalid Request",
		    "The selected OpenID Connect provider issuer is not in the list of allowed issuers; "
		    "contact the administrator",
		    HTTP_UNAUTHORIZED);

	if (oidc_util_url_has_parameter(r, "test-config")) {
		oidc_json_t *j_provider = NULL;
		oidc_metadata_provider_get(r, c, issuer, &j_provider, allow_dyn_reg);
		if (j_provider)
			oidc_json_decref(j_provider);
		return OK;
	}

	/* try and get metadata from the metadata directories for the selected OP */
	oidc_provider_t *provider = NULL;
	if ((oidc_metadata_get(r, c, issuer, &provider, allow_dyn_reg) == FALSE) || (provider == NULL))
		return oidc_util_html_send_error(
		    r, "Invalid Request",
		    "Could not find valid provider metadata for the selected OpenID Connect "
		    "provider; contact the administrator",
		    HTTP_NOT_FOUND);

	if (oidc_util_url_has_parameter(r, "test-jwks-uri")) {
		oidc_json_t *j_jwks = NULL;
		apr_byte_t force_refresh = TRUE;
		oidc_metadata_jwks_get(r, c, oidc_cfg_provider_jwks_uri_get(provider),
				       oidc_cfg_provider_ssl_validate_server_get(provider), &j_jwks, &force_refresh);
		oidc_json_decref(j_jwks);
		return OK;
	}

	/* now we've got a selected OP, send the user there to authenticate */
	return oidc_request_authenticate_user(r, c, provider, target_link_uri, login_hint, NULL, NULL,
					      auth_request_params, path_scopes);
}

/*
 * handle a response from an IDP discovery page and/or handle 3rd-party initiated SSO
 */
int oidc_discovery_response(request_rec *r, oidc_cfg_t *c) {

	char *issuer = NULL;
	char *target_link_uri = NULL;
	char *login_hint = NULL;
	char *auth_request_params = NULL;
	char *user = NULL;
	char *path_scopes = NULL;
	int rv = OK;

	oidc_util_url_parameter_get(r, OIDC_DISC_OP_PARAM, &issuer);
	oidc_util_url_parameter_get(r, OIDC_DISC_USER_PARAM, &user);
	oidc_util_url_parameter_get(r, OIDC_DISC_RT_PARAM, &target_link_uri);
	oidc_util_url_parameter_get(r, OIDC_DISC_LH_PARAM, &login_hint);
	oidc_util_url_parameter_get(r, OIDC_DISC_SC_PARAM, &path_scopes);
	oidc_util_url_parameter_get(r, OIDC_DISC_AR_PARAM, &auth_request_params);

	/* do CSRF protection if not 3rd party initiated SSO */
	apr_byte_t csrf_valid = oidc_discovery_response_csrf_check(r, c);

	// TODO: trim issuer/accountname/domain input and do more input validation

	oidc_debug(r, "issuer=\"%s\", target_link_uri=\"%s\", login_hint=\"%s\", user=\"%s\"", issuer, target_link_uri,
		   login_hint, user);

	if (oidc_discovery_response_target_link_uri_validate(r, c, &target_link_uri, &rv) == FALSE)
		return rv;

	/* see if this is a static setup */
	if (oidc_cfg_metadata_dir_get(c) == NULL)
		return oidc_discovery_response_static(r, c, issuer, target_link_uri, login_hint, auth_request_params,
						      path_scopes);

	/* find out if the user entered an account name or selected an OP manually */
	if (oidc_discovery_response_resolve_issuer(r, c, user, &issuer, &login_hint, &rv) == FALSE)
		return rv;

	return oidc_discovery_response_authenticate(r, c, issuer, target_link_uri, login_hint, auth_request_params,
						    path_scopes, csrf_valid);
}
