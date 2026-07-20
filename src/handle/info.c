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

#include "handle/handle.h"
#include "mod_auth_openidc.h"
#include "util/util.h"

#define OIDC_INFO_PARAM_ACCESS_TOKEN_REFRESH_INTERVAL "access_token_refresh_interval"

#define OIDC_HOOK_INFO_FORMAT_JSON "json"
#define OIDC_HOOK_INFO_FORMAT_HTML "html"

/*
 * see if we can and need to refresh the access token
 */
static int oidc_info_refresh_access_token(request_rec *r, oidc_cfg_t *c, oidc_session_t *session,
					  const char *s_interval, apr_byte_t *needs_save) {
	apr_time_t t_interval = -1;
	apr_time_t last_refresh = 0;
	oidc_provider_t *provider = NULL;

	if ((s_interval == NULL) || (oidc_session_get_refresh_token(r, session) == NULL))
		return OK;

	t_interval = _oidc_str_to_time(s_interval, -1);
	if (t_interval <= -1)
		return OK;

	t_interval = apr_time_from_sec(t_interval);
	last_refresh = oidc_session_get_access_token_last_refresh(r, session);
	oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds",
		   apr_time_sec(last_refresh + t_interval - apr_time_now()));

	if (last_refresh + t_interval >= apr_time_now())
		return OK;

	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	if (oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, NULL) == FALSE) {
		oidc_warn(r, "access_token could not be refreshed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	*needs_save = TRUE;
	return OK;
}

/*
 * include the access token and its type in the session info
 */
static void oidc_info_add_access_token(request_rec *r, const oidc_session_t *session, oidc_json_t *json) {
	const char *access_token = oidc_session_get_access_token(r, session);
	if (access_token != NULL)
		oidc_json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN, oidc_json_string(access_token));
	const char *access_token_type = oidc_session_get_access_token_type(r, session);
	if (access_token_type != NULL)
		oidc_json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN_TYPE, oidc_json_string(access_token_type));
}

/*
 * include the session state and uuid in the session info
 */
static void oidc_info_add_session(oidc_session_t *session, oidc_json_t *json) {
	oidc_json_t *j_session = oidc_json_object();
	oidc_json_object_set(j_session, OIDC_HOOK_INFO_SESSION_STATE, session->state);
	oidc_json_object_set_new(j_session, OIDC_HOOK_INFO_SESSION_UUID, oidc_json_string(session->uuid));
	oidc_json_object_set_new(json, OIDC_HOOK_INFO_SESSION, j_session);
}

/*
 * build the JSON object that is returned to the caller based on the configured info hook data
 */
static void oidc_info_build_json(request_rec *r, const oidc_cfg_t *c, oidc_session_t *session, oidc_json_t *json) {
	apr_hash_t *data = oidc_cfg_info_hook_data_get(c);

	/* add a timestamp of creation in there for the caller */
	if (apr_hash_get(data, OIDC_HOOK_INFO_TIMESTAMP, APR_HASH_KEY_STRING))
		oidc_json_object_set_new(json, OIDC_HOOK_INFO_TIMESTAMP,
					 oidc_json_integer(apr_time_sec(apr_time_now())));

	/* include the access token in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_ACCES_TOKEN, APR_HASH_KEY_STRING))
		oidc_info_add_access_token(r, session, json);

	/* include the access token expiry timestamp in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_ACCES_TOKEN_EXP, APR_HASH_KEY_STRING)) {
		const char *access_token_expires = oidc_session_get_access_token_expires2str(r, session);
		if (access_token_expires != NULL)
			oidc_json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN_EXP,
						 oidc_json_string(access_token_expires));
	}

	/* include the serialized id_token (id_token_hint) in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_ID_TOKEN_HINT, APR_HASH_KEY_STRING)) {
		const char *s_id_token = oidc_session_get_idtoken(r, session);
		if (s_id_token != NULL)
			oidc_json_object_set_new(json, OIDC_HOOK_INFO_ID_TOKEN_HINT, oidc_json_string(s_id_token));
	}

	/* include the id_token claims in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_ID_TOKEN, APR_HASH_KEY_STRING)) {
		oidc_json_t *id_token = oidc_session_get_idtoken_claims(r, session);
		if (id_token)
			oidc_json_object_set(json, OIDC_HOOK_INFO_ID_TOKEN, id_token);
	}

	/* include the claims from the userinfo endpoint in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_USER_INFO, APR_HASH_KEY_STRING)) {
		oidc_json_t *claims = oidc_session_get_userinfo_claims(r, session);
		if (claims)
			oidc_json_object_set(json, OIDC_HOOK_INFO_USER_INFO, claims);
	}

	/* include the maximum session lifetime in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_SESSION_EXP, APR_HASH_KEY_STRING)) {
		apr_time_t session_expires = oidc_session_get_session_expires(r, session);
		oidc_json_object_set_new(json, OIDC_HOOK_INFO_SESSION_EXP,
					 oidc_json_integer(apr_time_sec(session_expires)));
	}

	/* include the inactivity timeout in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_SESSION_TIMEOUT, APR_HASH_KEY_STRING))
		oidc_json_object_set_new(json, OIDC_HOOK_INFO_SESSION_TIMEOUT,
					 oidc_json_integer(apr_time_sec(session->expiry)));

	/* include the remote_user in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_SESSION_REMOTE_USER, APR_HASH_KEY_STRING))
		oidc_json_object_set_new(json, OIDC_HOOK_INFO_SESSION_REMOTE_USER,
					 oidc_json_string(session->remote_user));

	if (apr_hash_get(data, OIDC_HOOK_INFO_SESSION, APR_HASH_KEY_STRING))
		oidc_info_add_session(session, json);

	/* include the refresh token in the session info */
	if (apr_hash_get(data, OIDC_HOOK_INFO_REFRESH_TOKEN, APR_HASH_KEY_STRING)) {
		const char *refresh_token = oidc_session_get_refresh_token(r, session);
		if (refresh_token != NULL)
			oidc_json_object_set_new(json, OIDC_HOOK_INFO_REFRESH_TOKEN, oidc_json_string(refresh_token));
	}
}

/*
 * send the session info to the caller in the requested format (JSON or HTML)
 */
static int oidc_info_send_response(request_rec *r, const oidc_json_t *json, const char *s_format) {
	const char *r_value = NULL;

	/* the response may carry the access/refresh/id token and session claims; prevent it from being
	 * stored by the browser or any intermediary cache */
	oidc_http_set_no_cache_headers(r);

	if (_oidc_strcmp(OIDC_HOOK_INFO_FORMAT_JSON, s_format) == 0) {
		r_value = oidc_json_encode(r->pool, json, OIDC_JSON_PRESERVE_ORDER);
		return oidc_util_http_send(r, r_value, _oidc_strlen(r_value), OIDC_HTTP_CONTENT_TYPE_JSON, OK);
	}

	r_value = oidc_json_encode(r->pool, json, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_INDENT(2));
	return oidc_util_html_send(r, "Session Info", NULL, NULL,
				   apr_psprintf(r->pool, "<pre>%s</pre>", oidc_util_html_escape(r->pool, r_value)), OK);
}

/*
 * handle request for session info
 */
int oidc_info_request(request_rec *r, oidc_cfg_t *c, oidc_session_t *session, apr_byte_t needs_save) {
	int rc = HTTP_UNAUTHORIZED;
	char *s_format = NULL;
	char *s_interval = NULL;
	char *s_extend_session = NULL;
	apr_byte_t b_extend_session = TRUE;
	oidc_json_t *json = NULL;

	oidc_util_url_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_INFO, &s_format);
	oidc_util_url_parameter_get(r, OIDC_INFO_PARAM_ACCESS_TOKEN_REFRESH_INTERVAL, &s_interval);
	oidc_util_url_parameter_get(r, OIDC_INFO_PARAM_EXTEND_SESSION, &s_extend_session);
	if (s_extend_session && (_oidc_strcmp(s_extend_session, "false") == 0))
		b_extend_session = FALSE;

	/* see if this is a request for a format that is supported */
	if ((_oidc_strcmp(OIDC_HOOK_INFO_FORMAT_JSON, s_format) != 0) &&
	    (_oidc_strcmp(OIDC_HOOK_INFO_FORMAT_HTML, s_format) != 0)) {
		oidc_warn(r, "request for unknown format: %s", s_format);
		return HTTP_UNSUPPORTED_MEDIA_TYPE;
	}

	/* check that we actually have a user session and this is someone calling with a proper session cookie */
	if (session->remote_user == NULL) {
		oidc_warn(r, "no user session found");
		return HTTP_UNAUTHORIZED;
	}

	/* set the user in the main request for further (incl. sub-request and authz) processing */
	r->user = apr_pstrdup(r->pool, session->remote_user);

	if (oidc_cfg_info_hook_data_get(c) == NULL) {
		oidc_warn(r, "no data configured to return in " OIDCInfoHook);
		return HTTP_NOT_FOUND;
	}

	rc = oidc_info_refresh_access_token(r, c, session, s_interval, &needs_save);
	if (rc != OK)
		return rc;

	/* create the JSON object */
	json = oidc_json_object();

	/*
	 * refresh the claims from the userinfo endpoint
	 * side-effect is that this may refresh the access token if not already done
	 * note that OIDCUserInfoRefreshInterval should be set to control the refresh policy
	 */
	if (b_extend_session && (oidc_userinfo_refresh_claims(r, c, session, &needs_save) == FALSE)) {
		rc = HTTP_INTERNAL_SERVER_ERROR;
		goto end;
	}

	oidc_info_build_json(r, c, session, json);

	/* pass the tokens to the application and save the session, possibly updating the expiry */
	oidc_session_pass_tokens(r, c, session, b_extend_session, &needs_save);

	/* check if something was updated in the session and we need to save it again */
	if (b_extend_session && needs_save && (oidc_session_save(r, session, FALSE) == FALSE)) {
		oidc_warn(r, "error saving session");
		rc = HTTP_INTERNAL_SERVER_ERROR;
		goto end;
	}

	rc = oidc_info_send_response(r, json, s_format);

end:

	/* free the allocated resources */
	oidc_json_decref(json);

	return rc;
}
