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

static int oidc_session_management_iframe_op(request_rec *r, oidc_cfg *c, oidc_session_t *session,
					     const char *check_session_iframe) {
	oidc_debug(r, "enter");
	oidc_http_hdr_out_location_set(r, check_session_iframe);
	return HTTP_MOVED_TEMPORARILY;
}

static int oidc_session_management_iframe_rp(request_rec *r, oidc_cfg *c, oidc_session_t *session,
					     const char *client_id, const char *check_session_iframe) {

	oidc_debug(r, "enter");

	const char *java_script =
	    "    <script type=\"text/javascript\">\n"
	    "      var targetOrigin  = '%s';\n"
	    "      var clientId  = '%s';\n"
	    "      var sessionId  = '%s';\n"
	    "      var loginUrl  = '%s';\n"
	    "      var message = clientId + ' ' + sessionId;\n"
	    "	   var timerID;\n"
	    "\n"
	    "      function checkSession() {\n"
	    "        console.debug('checkSession: posting ' + message + ' to ' + targetOrigin);\n"
	    "        var win = window.parent.document.getElementById('%s').contentWindow;\n"
	    "        win.postMessage( message, targetOrigin);\n"
	    "      }\n"
	    "\n"
	    "      function setTimer() {\n"
	    "        checkSession();\n"
	    "        timerID = setInterval('checkSession()', %d);\n"
	    "      }\n"
	    "\n"
	    "      function receiveMessage(e) {\n"
	    "        console.debug('receiveMessage: ' + e.data + ' from ' + e.origin);\n"
	    "        if (e.origin !== targetOrigin ) {\n"
	    "          console.debug('receiveMessage: cross-site scripting attack?');\n"
	    "          return;\n"
	    "        }\n"
	    "        if (e.data != 'unchanged') {\n"
	    "          clearInterval(timerID);\n"
	    "          if (e.data == 'changed' && sessionId == '' ) {\n"
	    "			 // 'changed' + no session: enforce a login (if we have a login url...)\n"
	    "            if (loginUrl != '') {\n"
	    "              window.top.location.replace(loginUrl);\n"
	    "            }\n"
	    "		   } else {\n"
	    "              // either 'changed' + active session, or 'error': enforce a logout\n"
	    "              window.top.location.replace('%s?logout=' + encodeURIComponent(window.top.location.href));\n"
	    "          }\n"
	    "        }\n"
	    "      }\n"
	    "\n"
	    "      window.addEventListener('message', receiveMessage, false);\n"
	    "\n"
	    "    </script>\n";

	/* determine the origin for the check_session_iframe endpoint */
	char *origin = apr_pstrdup(r->pool, check_session_iframe);
	apr_uri_t uri;
	apr_uri_parse(r->pool, check_session_iframe, &uri);
	char *p = _oidc_strstr(origin, uri.path);
	*p = '\0';

	/* the element identifier for the OP iframe */
	const char *op_iframe_id = "openidc-op";

	/* restore the OP session_state from the session */
	const char *session_state = oidc_session_get_session_state(r, session);
	if (session_state == NULL) {
		oidc_warn(
		    r, "no session_state found in the session; the OP does probably not support session management!?");
		// return OK;
	}

	char *s_poll_interval = NULL;
	oidc_http_request_parameter_get(r, "poll", &s_poll_interval);
	int poll_interval = _oidc_str_to_int(s_poll_interval, 0);
	if ((poll_interval <= 0) || (poll_interval > 3600 * 24))
		poll_interval = 3000;

	char *login_uri = NULL, *error_str = NULL, *error_description = NULL;
	oidc_http_request_parameter_get(r, "login_uri", &login_uri);
	if ((login_uri != NULL) &&
	    (oidc_validate_redirect_url(r, c, login_uri, FALSE, &error_str, &error_description) == FALSE)) {
		return HTTP_BAD_REQUEST;
	}

	const char *redirect_uri = oidc_get_redirect_uri(r, c);

	java_script = apr_psprintf(r->pool, java_script, origin, client_id, session_state ? session_state : "",
				   login_uri ? login_uri : "", op_iframe_id, poll_interval, redirect_uri, redirect_uri);

	return oidc_util_html_send(r, NULL, java_script, "setTimer", NULL, OK);
}

/*
 * handle session management request
 */
int oidc_session_management(request_rec *r, oidc_cfg *c, oidc_session_t *session) {
	char *cmd = NULL;
	const char *id_token_hint = NULL;
	oidc_provider_t *provider = NULL;

	/* get the command passed to the session management handler */
	oidc_http_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_SESSION, &cmd);
	if (cmd == NULL) {
		oidc_error(r, "session management handler called with no command");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* see if this is a local logout during session management */
	if (_oidc_strcmp("logout", cmd) == 0) {
		oidc_debug(
		    r,
		    "[session=logout] calling oidc_handle_logout_request because of session mgmt local logout call.");
		return oidc_logout_request(r, c, session, oidc_get_absolute_url(r, c, c->default_slo_url), TRUE);
	}

	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE) {
		if ((oidc_provider_static_config(r, c, &provider) == FALSE) || (provider == NULL))
			return HTTP_NOT_FOUND;
	}

	/* see if this is a request for the OP iframe */
	if (_oidc_strcmp("iframe_op", cmd) == 0) {
		if (provider->check_session_iframe != NULL) {
			return oidc_session_management_iframe_op(r, c, session, provider->check_session_iframe);
		}
		return HTTP_NOT_FOUND;
	}

	/* see if this is a request for the RP iframe */
	if (_oidc_strcmp("iframe_rp", cmd) == 0) {
		if ((provider->client_id != NULL) && (provider->check_session_iframe != NULL)) {
			return oidc_session_management_iframe_rp(r, c, session, provider->client_id,
								 provider->check_session_iframe);
		}
		oidc_debug(r, "iframe_rp command issued but no client (%s) and/or no check_session_iframe (%s) set",
			   provider->client_id, provider->check_session_iframe);
		return HTTP_NOT_FOUND;
	}

	/* see if this is a request check the login state with the OP */
	if (_oidc_strcmp("check", cmd) == 0) {
		id_token_hint = oidc_session_get_idtoken(r, session);
		/*
		 * TODO: this doesn't work with per-path provided auth_request_params and scopes
		 *       as oidc_dir_cfg_path_auth_request_params and oidc_dir_cfg_path_scope will pick
		 *       those for the redirect_uri itself; do we need to store those as part of the
		 *       session now?
		 */
		return oidc_request_authenticate_user(
		    r, c, provider,
		    apr_psprintf(r->pool, "%s?session=iframe_rp", oidc_get_redirect_uri_iss(r, c, provider)), NULL,
		    id_token_hint, "none", oidc_dir_cfg_path_auth_request_params(r), oidc_dir_cfg_path_scope(r));
	}

	/* handle failure in fallthrough */
	oidc_error(r, "unknown command: %s", cmd);

	return HTTP_INTERNAL_SERVER_ERROR;
}
