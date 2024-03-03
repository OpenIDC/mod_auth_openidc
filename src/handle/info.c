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

#define OIDC_INFO_PARAM_ACCESS_TOKEN_REFRESH_INTERVAL "access_token_refresh_interval"
#define OIDC_INFO_PARAM_EXTEND_SESSION "extend_session"

/*
 * handle request for session info
 */
int oidc_info_request(request_rec *r, oidc_cfg *c, oidc_session_t *session, apr_byte_t needs_save) {
	int rc = HTTP_UNAUTHORIZED;
	char *s_format = NULL;
	char *s_interval = NULL;
	char *s_extend_session = NULL;
	char *r_value = NULL;
	apr_byte_t b_extend_session = TRUE;
	apr_time_t t_interval = -1;

	oidc_http_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_INFO, &s_format);
	oidc_http_request_parameter_get(r, OIDC_INFO_PARAM_ACCESS_TOKEN_REFRESH_INTERVAL, &s_interval);
	oidc_http_request_parameter_get(r, OIDC_INFO_PARAM_EXTEND_SESSION, &s_extend_session);
	if ((s_extend_session) && (_oidc_strcmp(s_extend_session, "false") == 0))
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

	if (c->info_hook_data == NULL) {
		oidc_warn(r, "no data configured to return in " OIDCInfoHook);
		return HTTP_NOT_FOUND;
	}

	/* see if we can and need to refresh the access token */
	if ((s_interval != NULL) && (oidc_session_get_refresh_token(r, session) != NULL)) {

		t_interval = _oidc_str_to_time(s_interval, -1);
		if (t_interval > -1) {
			t_interval = apr_time_from_sec(t_interval);

			/* get the last refresh timestamp from the session info */
			apr_time_t last_refresh = oidc_session_get_access_token_last_refresh(r, session);

			oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds",
				   apr_time_sec(last_refresh + t_interval - apr_time_now()));

			/* see if we need to refresh again */
			if (last_refresh + t_interval < apr_time_now()) {

				/* get the current provider info */
				oidc_provider_t *provider = NULL;
				if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE)
					return HTTP_INTERNAL_SERVER_ERROR;

				/* execute the actual refresh grant */
				if (oidc_refresh_token_grant(r, c, session, provider, NULL, NULL) == FALSE) {
					oidc_warn(r, "access_token could not be refreshed");
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				needs_save = TRUE;
			}
		}
	}

	/* create the JSON object */
	json_t *json = json_object();

	/* add a timestamp of creation in there for the caller */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_TIMESTAMP, APR_HASH_KEY_STRING)) {
		json_object_set_new(json, OIDC_HOOK_INFO_TIMESTAMP, json_integer(apr_time_sec(apr_time_now())));
	}

	/*
	 * refresh the claims from the userinfo endpoint
	 * side-effect is that this may refresh the access token if not already done
	 * note that OIDCUserInfoRefreshInterval should be set to control the refresh policy
	 */
	if (b_extend_session) {
		if (oidc_userinfo_refresh_claims(r, c, session, &needs_save) == FALSE) {
			rc = HTTP_INTERNAL_SERVER_ERROR;
			goto end;
		}
	}

	/* include the access token in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ACCES_TOKEN, APR_HASH_KEY_STRING)) {
		const char *access_token = oidc_session_get_access_token(r, session);
		if (access_token != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN, json_string(access_token));
	}

	/* include the access token expiry timestamp in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ACCES_TOKEN_EXP, APR_HASH_KEY_STRING)) {
		const char *access_token_expires = oidc_session_get_access_token_expires2str(r, session);
		if (access_token_expires != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN_EXP, json_string(access_token_expires));
	}

	/* include the serialized id_token (id_token_hint) in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ID_TOKEN_HINT, APR_HASH_KEY_STRING)) {
		const char *s_id_token = oidc_session_get_idtoken(r, session);
		if (s_id_token != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_ID_TOKEN_HINT, json_string(s_id_token));
	}

	/* include the id_token claims in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ID_TOKEN, APR_HASH_KEY_STRING)) {
		json_t *id_token = oidc_session_get_idtoken_claims_json(r, session);
		if (id_token)
			json_object_set_new(json, OIDC_HOOK_INFO_ID_TOKEN, id_token);
	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_USER_INFO, APR_HASH_KEY_STRING)) {
		/* include the claims from the userinfo endpoint the session info */
		json_t *claims = oidc_session_get_userinfo_claims_json(r, session);
		if (claims)
			json_object_set_new(json, OIDC_HOOK_INFO_USER_INFO, claims);
	}

	/* include the maximum session lifetime in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION_EXP, APR_HASH_KEY_STRING)) {
		apr_time_t session_expires = oidc_session_get_session_expires(r, session);
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION_EXP, json_integer(apr_time_sec(session_expires)));
	}

	/* include the inactivity timeout in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION_TIMEOUT, APR_HASH_KEY_STRING)) {
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION_TIMEOUT, json_integer(apr_time_sec(session->expiry)));
	}

	/* include the remote_user in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION_REMOTE_USER, APR_HASH_KEY_STRING)) {
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION_REMOTE_USER, json_string(session->remote_user));
	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION, APR_HASH_KEY_STRING)) {
		json_t *j_session = json_object();
		json_object_set(j_session, OIDC_HOOK_INFO_SESSION_STATE, session->state);
		json_object_set_new(j_session, OIDC_HOOK_INFO_SESSION_UUID, json_string(session->uuid));
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION, j_session);
	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_REFRESH_TOKEN, APR_HASH_KEY_STRING)) {
		/* include the refresh token in the session info */
		const char *refresh_token = oidc_session_get_refresh_token(r, session);
		if (refresh_token != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_REFRESH_TOKEN, json_string(refresh_token));
	}

	/* pass the tokens to the application and save the session, possibly updating the expiry */
	if (b_extend_session)
		if (oidc_session_pass_tokens(r, c, session, &needs_save) == FALSE)
			oidc_warn(r, "error passing tokens");

	/* check if something was updated in the session and we need to save it again */
	if (b_extend_session && needs_save) {
		if (oidc_session_save(r, session, FALSE) == FALSE) {
			oidc_warn(r, "error saving session");
			rc = HTTP_INTERNAL_SERVER_ERROR;
			goto end;
		}
	}

	if (_oidc_strcmp(OIDC_HOOK_INFO_FORMAT_JSON, s_format) == 0) {
		/* JSON-encode the result */
		r_value = oidc_util_encode_json_object(r, json, JSON_PRESERVE_ORDER);
		/* return the stringified JSON result */
		rc = oidc_http_send(r, r_value, _oidc_strlen(r_value), OIDC_HTTP_CONTENT_TYPE_JSON, OK);
	} else if (_oidc_strcmp(OIDC_HOOK_INFO_FORMAT_HTML, s_format) == 0) {
		/* JSON-encode the result */
		r_value = oidc_util_encode_json_object(r, json, JSON_PRESERVE_ORDER | JSON_INDENT(2));
		rc = oidc_util_html_send(r, "Session Info", NULL, NULL, apr_psprintf(r->pool, "<pre>%s</pre>", r_value),
					 OK);
	}

end:

	/* free the allocated resources */
	json_decref(json);

	return rc;
}
