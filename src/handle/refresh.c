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

/* JSON object key for the value that holds the refresh token's refresh timestamp */
#define OIDC_REFRESH_TIMESTAMP "ts"

/*
 * time-to-live (seconds) for the lock that prevents parallel callers to execute
 * a refresh grant for the same refresh token; this also presents the maximum time
 * that callers will be blocked, waiting for another process to finish the refresh
 * and populate the cache with the results
 */
#define OIDC_REFRESH_LOCK_TTL 5

/*
 *  time-to-live (seconds) for the refresh token cache results
 *  during that time other callers trying to execute a refresh grant with the same
 *  refresh token will obtain their results from the cache rather than an actual refresh
 *  request
 */
#define OIDC_REFRESH_CACHE_TTL 30

/* needs to be larger than a few characters for cache compression to work... */
#define OIDC_REFRESH_LOCK_VALUE "needstobelargerthanafewcharacters"

/*
 * cache refresh token grant results for a while to avoid (almost) parallel requests
 */
static void oidc_refresh_token_cache_set(request_rec *r, oidc_cfg *c, const char *refresh_token,
					 const char *s_access_token, const char *s_token_type, int expires_in,
					 const char *s_id_token, const char *s_refresh_token, apr_time_t *ts) {
	char *s_json = NULL;

	/* create the JSON representation of the refresh grant results + timestamp */
	json_t *json = json_object();
	if (s_access_token)
		json_object_set_new(json, OIDC_PROTO_ACCESS_TOKEN, json_string(s_access_token));
	if (s_token_type)
		json_object_set_new(json, OIDC_PROTO_TOKEN_TYPE, json_string(s_token_type));
	json_object_set_new(json, OIDC_PROTO_EXPIRES_IN, json_integer(expires_in));
	if (s_id_token)
		json_object_set_new(json, OIDC_PROTO_ID_TOKEN, json_string(s_id_token));
	if (s_refresh_token)
		json_object_set_new(json, OIDC_PROTO_REFRESH_TOKEN, json_string(s_refresh_token));
	*ts = apr_time_now();
	json_object_set_new(json, OIDC_REFRESH_TIMESTAMP, json_integer(apr_time_sec(*ts)));

	/* stringify the JSON object and store it in the cache */
	s_json = oidc_util_encode_json_object(r, json, JSON_COMPACT);
	oidc_debug(r, "caching refresh_token (%s) grant results for %d seconds: %s", refresh_token,
		   OIDC_REFRESH_CACHE_TTL, s_json);

	oidc_cache_set_refresh_token(r, refresh_token, s_json,
				     apr_time_now() + apr_time_from_sec(OIDC_REFRESH_CACHE_TTL));

	/* cleanup */
	json_decref(json);
}

/*
 * obtain recent refresh token grant results from the cache
 */
static apr_byte_t oidc_refresh_token_cache_get(request_rec *r, oidc_cfg *c, const char *refresh_token,
					       char **s_access_token, char **s_token_type, int *expires_in,
					       char **s_id_token, char **s_refresh_token, apr_time_t *ts) {

	char *s_json = NULL;
	json_t *json = NULL, *v = NULL;
	apr_byte_t rv = FALSE;

	oidc_cache_mutex_lock(r->pool, r->server, c->refresh_mutex);

	/* see if this token was already refreshed recently or is being refreshed */
	oidc_cache_get_refresh_token(r, refresh_token, &s_json);
	if (s_json == NULL)
		goto no_cache_found;

	/* wait for the "other" caller to populate the refresh token response cache results */
	while ((s_json != NULL) && (_oidc_strcmp(s_json, OIDC_REFRESH_LOCK_VALUE) == 0)) {
		oidc_warn(r, "existing refresh in progress for %s, back off for 0.5s before re-trying the cache",
			  refresh_token);
		apr_sleep(apr_time_from_msec(500));
		s_json = NULL;
		oidc_cache_get_refresh_token(r, refresh_token, &s_json);
	}

	/* check if we have run into a timeout */
	if ((s_json == NULL) || (_oidc_strcmp(s_json, OIDC_REFRESH_LOCK_VALUE) == 0)) {
		oidc_warn(r, "timeout waiting for refresh grant cache results");
		// TODO: now we are going to refresh ourselves with a refresh token that has already been
		// tried before; that is not great in rolling refresh token setups but I guess we have no
		// other choice anyhow...
		goto no_cache_found;
	}

	/* we should have valid cache results by now */
	if (oidc_util_decode_json_object(r, s_json, &json) == FALSE)
		goto no_cache_found;

	oidc_debug(r, "using cached refresh_token (%s) grant results: %s", refresh_token, s_json);

	/* parse the results from the cache into the output parameters */
	if ((v = json_object_get(json, OIDC_PROTO_ACCESS_TOKEN)))
		*s_access_token = apr_pstrdup(r->pool, json_string_value(v));
	if ((v = json_object_get(json, OIDC_PROTO_TOKEN_TYPE)))
		*s_token_type = apr_pstrdup(r->pool, json_string_value(v));
	if ((v = json_object_get(json, OIDC_PROTO_EXPIRES_IN)))
		*expires_in = json_integer_value(v);
	if ((v = json_object_get(json, OIDC_PROTO_ID_TOKEN)))
		*s_id_token = apr_pstrdup(r->pool, json_string_value(v));
	if ((v = json_object_get(json, OIDC_PROTO_REFRESH_TOKEN)))
		*s_refresh_token = apr_pstrdup(r->pool, json_string_value(v));
	if ((v = json_object_get(json, OIDC_REFRESH_TIMESTAMP)))
		*ts = apr_time_from_sec(json_integer_value(v));

	/* cleanup */
	json_decref(json);

	rv = TRUE;

	goto end;

no_cache_found:

	oidc_debug(r, "locking cache and refreshing %s...", refresh_token);

	/*
	 * best-effort distributed locking during our upcoming refresh grant execution
	 *
	 * note that a small chance/race-condition remains that in a parallel request on
	 * another server in the same cluster another process just did the same in between
	 * i.e. calling oidc_cache_get_refresh_token (on entry) and calling
	 * oidc_cache_set_refresh_token (on exit) hereafter
	 *
	 * a process lock (refresh_mutex) in the calling function prevents this at least on the same machine
	 */
	oidc_cache_set_refresh_token(r, refresh_token, OIDC_REFRESH_LOCK_VALUE,
				     apr_time_now() + apr_time_from_sec(OIDC_REFRESH_LOCK_TTL));

end:

	oidc_cache_mutex_unlock(r->pool, r->server, c->refresh_mutex);

	return rv;
}

/*
 * execute refresh token grant to refresh the existing access token
 */
apr_byte_t oidc_refresh_token_grant(request_rec *r, oidc_cfg *c, oidc_session_t *session, oidc_provider_t *provider,
				    char **new_access_token, char **new_id_token) {

	apr_byte_t rc = FALSE;
	char *s_id_token = NULL;
	int expires_in = -1;
	char *s_token_type = NULL;
	char *s_access_token = NULL;
	char *s_refresh_token = NULL;
	oidc_jwt_t *id_token_jwt = NULL;
	oidc_jose_error_t err;
	const char *refresh_token = NULL;
	apr_time_t ts = 0;

	oidc_debug(r, "enter");

	/* get the refresh token that was stored in the session */
	refresh_token = oidc_session_get_refresh_token(r, session);
	if (refresh_token == NULL) {
		oidc_warn(r, "refresh token routine called but no refresh_token found in the session");
		goto end;
	}

	/* see if it was refreshed very recently and we can re-use the results from the cache */
	if (oidc_refresh_token_cache_get(r, c, refresh_token, &s_access_token, &s_token_type, &expires_in, &s_id_token,
					 &s_refresh_token, &ts) == TRUE)
		goto process;

	oidc_debug(r, "refreshing refresh_token: %s", refresh_token);

	OIDC_METRICS_TIMING_START(r, c);

	/* refresh the tokens by calling the token endpoint */
	if (oidc_proto_refresh_request(r, c, provider, refresh_token, &s_id_token, &s_access_token, &s_token_type,
				       &expires_in, &s_refresh_token) == FALSE) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_PROVIDER_REFRESH_ERROR);
		oidc_error(r, "access_token could not be refreshed with refresh_token: %s", refresh_token);
		goto end;
	}

	OIDC_METRICS_TIMING_ADD(r, c, OM_PROVIDER_REFRESH);

	/* cache the results for other callers */
	oidc_refresh_token_cache_set(r, c, refresh_token, s_access_token, s_token_type, expires_in, s_id_token,
				     s_refresh_token, &ts);

process:

	/* store the new access_token in the session and discard the old one */
	oidc_session_set_access_token(r, session, s_access_token);
	oidc_session_set_access_token_expires(r, session, expires_in);

	/* reset the access token refresh timestamp */
	oidc_session_set_access_token_last_refresh(r, session, ts);

	/* see if we need to return it as a parameter */
	if (new_access_token != NULL)
		*new_access_token = s_access_token;

	/* if we have a new refresh token (rolling refresh), store it in the session and overwrite the old one */
	if (s_refresh_token != NULL)
		oidc_session_set_refresh_token(r, session, s_refresh_token);

	/* if we have a new id_token, store it in the session and update the session max lifetime if required */
	if (s_id_token != NULL) {

		/* only store the serialized representation when configured so */
		if (c->store_id_token == TRUE)
			oidc_session_set_idtoken(r, session, s_id_token);

		if (oidc_jwt_parse(r->pool, s_id_token, &id_token_jwt, NULL, FALSE, &err) == TRUE) {
			/* store the claims payload in the id_token for later reference */
			oidc_session_set_idtoken_claims(r, session, id_token_jwt->payload.value.str);

			if (provider->session_max_duration == 0) {
				/* update the session expiry to match the expiry of the id_token */
				apr_time_t session_expires = apr_time_from_sec(id_token_jwt->payload.exp);
				oidc_session_set_session_expires(r, session, session_expires);

				/* log message about the updated max session duration */
				oidc_log_session_expires(r, "session max lifetime", session_expires);
			}

			/* see if we need to return it as a parameter */
			if (new_id_token != NULL)
				*new_id_token = s_id_token;

		} else {
			oidc_warn(r, "parsing of id_token failed");
		}

		if (id_token_jwt != NULL)
			oidc_jwt_destroy(id_token_jwt);
	}

	oidc_debug(r, "replaced refresh_token: %s with %s", refresh_token, s_refresh_token);

	rc = TRUE;

end:

	return rc;
}

/*
 * handle refresh token request
 */
int oidc_refresh_token_request(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	char *return_to = NULL;
	char *r_access_token = NULL;
	char *error_code = NULL;
	char *error_str = NULL;
	char *error_description = NULL;
	apr_byte_t needs_save = TRUE;

	/* get the command passed to the session management handler */
	oidc_http_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_REFRESH, &return_to);
	oidc_http_request_parameter_get(r, OIDC_PROTO_ACCESS_TOKEN, &r_access_token);

	/* check the input parameters */
	if (return_to == NULL) {
		oidc_error(r, "refresh token request handler called with no URL to return to");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* do input validation on the return to parameter value */
	if (oidc_validate_redirect_url(r, c, return_to, TRUE, &error_str, &error_description) == FALSE) {
		oidc_error(r, "return_to URL validation failed: %s: %s", error_str, error_description);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (r_access_token == NULL) {
		oidc_error(r, "refresh token request handler called with no access_token parameter");
		error_code = "no_access_token";
		goto end;
	}

	const char *s_access_token = oidc_session_get_access_token(r, session);
	if (s_access_token == NULL) {
		oidc_error(r, "no existing access_token found in the session, nothing to refresh");
		error_code = "no_access_token_exists";
		goto end;
	}

	/* compare the access_token parameter used for XSRF protection */
	if (_oidc_strcmp(s_access_token, r_access_token) != 0) {
		oidc_error(r, "access_token passed in refresh request does not match the one stored in the session");
		error_code = "no_access_token_match";
		goto end;
	}

	/* get a handle to the provider configuration */
	oidc_provider_t *provider = NULL;
	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE) {
		error_code = "session_corruption";
		goto end;
	}

	/* execute the actual refresh grant */
	if (oidc_refresh_token_grant(r, c, session, provider, NULL, NULL) == FALSE) {
		oidc_error(r, "access_token could not be refreshed");
		error_code = "refresh_failed";
		goto end;
	}

	/* pass the tokens to the application, possibly updating the expiry */
	if (oidc_session_pass_tokens(r, c, session, &needs_save) == FALSE) {
		error_code = "session_corruption";
		goto end;
	}

	if (oidc_session_save(r, session, FALSE) == FALSE) {
		error_code = "error saving session";
		goto end;
	}

end:

	/* pass optional error message to the return URL */
	if (error_code != NULL)
		return_to =
		    apr_psprintf(r->pool, "%s%serror_code=%s", return_to,
				 strchr(return_to ? return_to : "", OIDC_CHAR_QUERY) ? OIDC_STR_AMP : OIDC_STR_QUERY,
				 oidc_http_escape_string(r, error_code));

	/* add the redirect location header */
	oidc_http_hdr_out_location_set(r, return_to);

	return HTTP_MOVED_TEMPORARILY;
}

apr_byte_t oidc_refresh_access_token_before_expiry(request_rec *r, oidc_cfg *cfg, oidc_session_t *session,
						   int ttl_minimum, apr_byte_t *needs_save) {

	apr_time_t t_expires = -1;
	oidc_provider_t *provider = NULL;

	oidc_debug(r, "ttl_minimum=%d", ttl_minimum);

	if (ttl_minimum < 0)
		return TRUE;

	t_expires = oidc_session_get_access_token_expires(r, session);
	if (t_expires <= 0) {
		oidc_debug(r, "no access token expires_in stored in the session (i.e. returned from in the "
			      "authorization response), so cannot refresh the access token based on TTL requirement");
		return FALSE;
	}

	if (oidc_session_get_refresh_token(r, session) == NULL) {
		oidc_debug(r, "no refresh token stored in the session, so cannot refresh the access token based on TTL "
			      "requirement");
		return FALSE;
	}

	t_expires = t_expires - apr_time_from_sec(ttl_minimum);

	oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds", apr_time_sec(t_expires - apr_time_now()));

	if (t_expires > apr_time_now())
		return TRUE;

	if (oidc_get_provider_from_session(r, cfg, session, &provider) == FALSE)
		return FALSE;

	if (oidc_refresh_token_grant(r, cfg, session, provider, NULL, NULL) == FALSE) {
		oidc_warn(r, "access_token could not be refreshed");
		*needs_save = FALSE;
		return FALSE;
	}

	*needs_save = TRUE;

	return TRUE;
}
