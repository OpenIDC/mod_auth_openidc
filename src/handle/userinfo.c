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
 * store claims resolved from the userinfo endpoint in the session
 */
void oidc_userinfo_store_claims(request_rec *r, oidc_cfg *c, oidc_session_t *session, oidc_provider_t *provider,
				const char *claims, const char *userinfo_jwt) {

	oidc_debug(r, "enter");

	/* see if we've resolved any claims */
	if (claims != NULL) {
		/*
		 * Successfully decoded a set claims from the response so we can store them
		 * (well actually the stringified representation in the response)
		 * in the session context safely now
		 */
		oidc_session_set_userinfo_claims(r, session, claims);

		if (c->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
			/* this will also clear the entry if a JWT was not returned at this point */
			oidc_session_set_userinfo_jwt(r, session, userinfo_jwt);
		}

	} else {
		/*
		 * clear the existing claims because we could not refresh them
		 */
		oidc_session_set_userinfo_claims(r, session, NULL);

		oidc_session_set_userinfo_jwt(r, session, NULL);
	}

	/* store the last refresh time if we've configured a userinfo refresh interval */
	if (provider->userinfo_refresh_interval > 0)
		oidc_session_reset_userinfo_last_refresh(r, session);
}

/*
 * retrieve claims from the userinfo endpoint and return the stringified response
 */
const char *oidc_userinfo_retrieve_claims(request_rec *r, oidc_cfg *c, oidc_provider_t *provider,
					  const char *access_token, oidc_session_t *session, char *id_token_sub,
					  char **userinfo_jwt) {

	char *result = NULL;
	char *refreshed_access_token = NULL;
	json_t *id_token_claims = NULL;
	long response_code = 0;

	oidc_debug(r, "enter");

	/* see if a userinfo endpoint is set, otherwise there's nothing to do for us */
	if (provider->userinfo_endpoint_url == NULL) {
		oidc_debug(r, "not retrieving userinfo claims because userinfo_endpoint is not set");
		goto end;
	}

	/* see if there's an access token, otherwise we can't call the userinfo endpoint at all */
	if (access_token == NULL) {
		oidc_debug(r, "not retrieving userinfo claims because access_token is not provided");
		goto end;
	}

	if ((id_token_sub == NULL) && (session != NULL)) {
		// when refreshing claims from the userinfo endpoint
		id_token_claims = oidc_session_get_idtoken_claims_json(r, session);
		if (id_token_claims != NULL) {
			oidc_jose_get_string(r->pool, id_token_claims, OIDC_CLAIM_SUB, FALSE, &id_token_sub, NULL);
		} else {
			oidc_debug(r, "no id_token_claims found in session");
		}
	}

	// TODO: return code should indicate whether the token expired or some other error occurred
	// TODO: long-term: session storage should be JSON (with explicit types and less conversion, using standard
	// routines)

	/* try to get claims from the userinfo endpoint using the provided access token */
	if (oidc_proto_resolve_userinfo(r, c, provider, id_token_sub, access_token, &result, userinfo_jwt,
					&response_code) == TRUE)
		goto end;

	/* see if this is the initial call to the user info endpoint upon receiving the authorization response */
	if (session == NULL) {
		oidc_error(r, "resolving user info claims with the provided access token failed, nothing will be "
			      "stored in the session");
		result = NULL;
		goto end;
	}

	// a connectivity error rather than a HTTP error; may want to check for anything != 401
	if (response_code == 0) {
		oidc_error(r, "resolving user info claims failed with a connectivity error, no attempt will be made to "
			      "refresh the access token and try again");
		result = NULL;
		goto end;
	}

	/* first call to user info endpoint failed, but this is for an existing session and the access token may have
	 * just expired, so refresh it */
	if (oidc_refresh_token_grant(r, c, session, provider, &refreshed_access_token, NULL) == FALSE) {
		oidc_error(r, "refreshing access token failed, claims will not be retrieved/refreshed from the "
			      "userinfo endpoint");
		result = NULL;
		goto end;
	}

	/* try again with the new access token */
	if (oidc_proto_resolve_userinfo(r, c, provider, id_token_sub, refreshed_access_token, &result, userinfo_jwt,
					NULL) == FALSE) {

		oidc_error(r, "resolving user info claims with the refreshed access token failed, nothing will be "
			      "stored in the session");
		result = NULL;
		goto end;
	}

end:

	if (id_token_claims)
		json_decref(id_token_claims);

	oidc_debug(r, "return (%d)", result != NULL);

	return result;
}

/*
 * get (new) claims from the userinfo endpoint
 */
apr_byte_t oidc_userinfo_refresh_claims(request_rec *r, oidc_cfg *cfg, oidc_session_t *session,
					apr_byte_t *needs_save) {

	apr_byte_t rc = TRUE;
	oidc_provider_t *provider = NULL;
	const char *claims = NULL;
	const char *access_token = NULL;
	char *userinfo_jwt = NULL;

	/* see if we can do anything here, i.e. a refresh interval is configured */
	apr_time_t interval = oidc_session_get_userinfo_refresh_interval(r, session);

	oidc_debug(r, "interval=%" APR_TIME_T_FMT, apr_time_sec(interval));

	if (interval > -1) {

		/* get the current provider info */
		if (oidc_get_provider_from_session(r, cfg, session, &provider) == FALSE) {
			*needs_save = TRUE;
			return FALSE;
		}

		if (provider->userinfo_endpoint_url != NULL) {

			/* get the last refresh timestamp from the session info */
			apr_time_t last_refresh = oidc_session_get_userinfo_last_refresh(r, session);

			oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds",
				   apr_time_sec(last_refresh + interval - apr_time_now()));

			/* see if we need to refresh again */
			if (last_refresh + interval < apr_time_now()) {

				/* get the current access token */
				access_token = oidc_session_get_access_token(r, session);

				/* retrieve the current claims */
				claims = oidc_userinfo_retrieve_claims(r, cfg, provider, access_token, session, NULL,
								       &userinfo_jwt);

				/* store claims resolved from userinfo endpoint */
				oidc_userinfo_store_claims(r, cfg, session, provider, claims, userinfo_jwt);

				if (claims == NULL) {
					*needs_save = FALSE;
					rc = FALSE;
				} else {
					/* indicated something changed */
					*needs_save = TRUE;
				}
			}
		}
	}

	oidc_debug(r, "return: %d", rc);

	return rc;
}
