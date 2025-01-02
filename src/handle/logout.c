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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
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
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"

#define OIDC_DONT_REVOKE_TOKENS_BEFORE_LOGOUT_ENVVAR "OIDC_DONT_REVOKE_TOKENS_BEFORE_LOGOUT"

/*
 * revoke refresh token and access token stored in the session if the
 * OP has an RFC 7009 compliant token revocation endpoint
 */
static void oidc_logout_revoke_tokens(request_rec *r, oidc_cfg_t *c, oidc_session_t *session) {

	char *response = NULL;
	char *basic_auth = NULL;
	char *bearer_auth = NULL;
	apr_table_t *params = NULL;
	const char *token = NULL;
	oidc_provider_t *provider = NULL;

	oidc_debug(r, "enter");

	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE)
		goto out;

	if (apr_table_get(r->subprocess_env, OIDC_DONT_REVOKE_TOKENS_BEFORE_LOGOUT_ENVVAR) != NULL)
		goto out;

	oidc_debug(r, "revocation_endpoint=%s",
		   oidc_cfg_provider_revocation_endpoint_url_get(provider)
		       ? oidc_cfg_provider_revocation_endpoint_url_get(provider)
		       : "(null)");

	if ((oidc_cfg_provider_revocation_endpoint_url_get(provider) == NULL) ||
	    (_oidc_strcmp(oidc_cfg_provider_revocation_endpoint_url_get(provider), "") == 0))
		goto out;

	params = apr_table_make(r->pool, 4);

	// add the token endpoint authentication credentials to the revocation endpoint call...
	if (oidc_proto_token_endpoint_auth(
		r, c, oidc_cfg_provider_token_endpoint_auth_get(provider), oidc_cfg_provider_client_id_get(provider),
		oidc_cfg_provider_client_secret_get(provider), oidc_cfg_provider_client_keys_get(provider),
		oidc_cfg_provider_token_endpoint_url_get(provider), params, NULL, &basic_auth, &bearer_auth) == FALSE)
		goto out;

	token = oidc_session_get_refresh_token(r, session);
	if (token != NULL) {
		apr_table_setn(params, OIDC_PROTO_TOKEN_TYPE_HINT, OIDC_PROTO_REFRESH_TOKEN);
		apr_table_setn(params, OIDC_PROTO_TOKEN, token);

		if (oidc_http_post_form(r, oidc_cfg_provider_revocation_endpoint_url_get(provider), params, basic_auth,
					bearer_auth, NULL, oidc_cfg_provider_ssl_validate_server_get(provider),
					&response, NULL, NULL, oidc_cfg_http_timeout_long_get(c),
					oidc_cfg_outgoing_proxy_get(c), oidc_cfg_dir_pass_cookies_get(r), NULL, NULL,
					NULL) == FALSE) {
			oidc_warn(r, "revoking refresh token failed");
		}
		apr_table_unset(params, OIDC_PROTO_TOKEN_TYPE_HINT);
		apr_table_unset(params, OIDC_PROTO_TOKEN);
	}

	token = oidc_session_get_access_token(r, session);
	if (token != NULL) {
		apr_table_setn(params, OIDC_PROTO_TOKEN_TYPE_HINT, OIDC_PROTO_ACCESS_TOKEN);
		apr_table_setn(params, OIDC_PROTO_TOKEN, token);

		if (oidc_http_post_form(r, oidc_cfg_provider_revocation_endpoint_url_get(provider), params, basic_auth,
					bearer_auth, NULL, oidc_cfg_provider_ssl_validate_server_get(provider),
					&response, NULL, NULL, oidc_cfg_http_timeout_long_get(c),
					oidc_cfg_outgoing_proxy_get(c), oidc_cfg_dir_pass_cookies_get(r), NULL, NULL,
					NULL) == FALSE) {
			oidc_warn(r, "revoking access token failed");
		}
	}

out:

	oidc_debug(r, "leave");
}

static apr_byte_t oidc_logout_cleanup_by_sid(request_rec *r, char *sid, oidc_cfg_t *cfg, oidc_provider_t *provider,
					     apr_byte_t revoke_tokens) {

	char *uuid = NULL;
	oidc_session_t session;

	oidc_debug(r, "enter (sid=%s,iss=%s)", sid, oidc_cfg_provider_issuer_get(provider));

	// TODO: when dealing with sub instead of a true sid, we'll be killing all sessions for
	//	   a specific user, across hosts that share the *same* cache backend
	//	   if those hosts haven't been configured with a different OIDCCryptoPassphrase
	//	   - perhaps that's even acceptable since non-memory caching is encrypted by default
	//	     and memory-based caching doesn't suffer from this (different shm segments)?
	//	   - it will result in 400 errors returned from backchannel logout calls to the other hosts...

	sid = oidc_response_make_sid_iss_unique(r, sid, oidc_cfg_provider_issuer_get(provider));
	oidc_cache_get_sid(r, sid, &uuid);
	if (uuid == NULL) {
		// this may happen when we are the caller
		oidc_warn(
		    r,
		    "could not (or no longer) find a session based on sid/sub provided in logout token / parameter: %s",
		    sid);
		r->user = "";
		return TRUE;
	}

	// revoke tokens if we can get a handle on those
	if (oidc_cfg_session_type_get(cfg) != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
		if ((oidc_session_load_cache_by_uuid(r, cfg, uuid, &session) != FALSE) && (revoke_tokens == TRUE))
			if (oidc_session_extract(r, &session) != FALSE)
				oidc_logout_revoke_tokens(r, cfg, &session);
	}

	// clear the session cache
	oidc_cache_set_sid(r, sid, NULL, 0);
	oidc_cache_set_session(r, uuid, NULL, 0);

	r->user = "";
	return FALSE;
}

static apr_uint32_t oidc_logout_transparent_pixel[17] = {
    0x474e5089, 0x0a1a0a0d, 0x0d000000, 0x52444849, 0x01000000, 0x01000000, 0x00000408, 0x0c1cb500, 0x00000002,
    0x4144490b, 0x639c7854, 0x0000cffa, 0x02010702, 0x71311c9a, 0x00000000, 0x444e4549, 0x826042ae};

static apr_byte_t oidc_logout_is_front_channel(const char *logout_param_value) {
	return ((logout_param_value != NULL) &&
		((_oidc_strcmp(logout_param_value, OIDC_GET_STYLE_LOGOUT_PARAM_VALUE) == 0) ||
		 (_oidc_strcmp(logout_param_value, OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE) == 0)));
}

static apr_byte_t oidc_logout_is_back_channel(const char *logout_param_value) {
	return ((logout_param_value != NULL) &&
		(_oidc_strcmp(logout_param_value, OIDC_BACKCHANNEL_STYLE_LOGOUT_PARAM_VALUE) == 0));
}

/*
 * handle a local logout
 */
int oidc_logout_request(request_rec *r, oidc_cfg_t *c, oidc_session_t *session, const char *url,
			apr_byte_t revoke_tokens) {

	int no_session_provided = 1;

	oidc_debug(r, "enter (url=%s)", url);

	/* if there's no remote_user then there's no (stored) session to kill */
	if (session->remote_user != NULL) {
		no_session_provided = 0;
		if (revoke_tokens)
			oidc_logout_revoke_tokens(r, c, session);
	}

	/*
	 * remove session state (cq. cache entry and cookie)
	 * always clear the session cookie because the cookie may be not sent (but still in the browser)
	 * due to SameSite policies
	 */
	oidc_session_kill(r, session);

	/* see if this is the OP calling us */
	if (oidc_logout_is_front_channel(url)) {

		/*
		 * If no session was provided look for the sid and iss parameters in
		 * the request as specified in
		 * "OpenID Connect Front-Channel Logout 1.0 - draft 05" at
		 * https://openid.net/specs/openid-connect-frontchannel-1_0.html
		 * and try to clear the session based on sid / iss like in the
		 * backchannel logout case.
		 */
		if (no_session_provided) {
			char *sid, *iss;
			oidc_provider_t *provider = NULL;

			if (oidc_util_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_SID, &sid) != FALSE) {

				if (oidc_util_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_ISS, &iss) != FALSE) {
					provider = oidc_get_provider_for_issuer(r, c, iss, FALSE);
				} else {
					/*
					 * Microsoft Entra ID / Azure AD seems to such a non spec compliant provider.
					 * In this case try our luck with the static config if possible.
					 */
					oidc_debug(r, "OP did not provide an iss as parameter");
					if (oidc_provider_static_config(r, c, &provider) == FALSE)
						provider = NULL;
				}
				if (provider) {
					oidc_logout_cleanup_by_sid(r, sid, c, provider, revoke_tokens);
				} else {
					oidc_info(r, "No provider for front channel logout found");
				}
			}
		}

		/* set recommended cache control headers */
		oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_CACHE_CONTROL, "no-cache, no-store");
		oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_PRAGMA, "no-cache");
		oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_P3P, "CAO PSA OUR");
		oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_EXPIRES, "0");
		oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_X_FRAME_OPTIONS, oidc_cfg_logout_x_frame_options_get(c));

		/* see if this is PF-PA style logout in which case we return a transparent pixel */
		const char *accept = oidc_http_hdr_in_accept_get(r);
		if ((_oidc_strcmp(url, OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE) == 0) ||
		    ((accept) && _oidc_strstr(accept, OIDC_HTTP_CONTENT_TYPE_IMAGE_PNG))) {
			return oidc_util_http_send(r, (const char *)&oidc_logout_transparent_pixel,
						   sizeof(oidc_logout_transparent_pixel),
						   OIDC_HTTP_CONTENT_TYPE_IMAGE_PNG, OK);
		}

		/* standard HTTP based logout: should be called in an iframe from the OP */
		return oidc_util_html_send(r, "Logged Out", NULL, NULL, "<p>Logged Out</p>", OK);
	}

	oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_CACHE_CONTROL, "no-cache, no-store");
	oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_PRAGMA, "no-cache");

	/* see if we don't need to go somewhere special after killing the session locally */
	if (url == NULL)
		return oidc_util_html_send(r, "Logged Out", NULL, NULL, "<p>Logged Out</p>", OK);

	/* send the user to the specified where-to-go-after-logout URL */
	oidc_http_hdr_out_location_set(r, url);

	return HTTP_MOVED_TEMPORARILY;
}

/*
 * handle a backchannel logout
 */
#define OIDC_EVENTS_BLOGOUT_KEY "http://schemas.openid.net/event/backchannel-logout"

static int oidc_logout_backchannel(request_rec *r, oidc_cfg_t *cfg) {

	oidc_debug(r, "enter");

	const char *logout_token = NULL;
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	oidc_provider_t *provider = NULL;
	char *sid = NULL;
	int rc = HTTP_BAD_REQUEST;

	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r, "could not read POST-ed parameters to the logout endpoint");
		goto out;
	}

	logout_token = apr_table_get(params, OIDC_PROTO_LOGOUT_TOKEN);
	if (logout_token == NULL) {
		oidc_error(r, "backchannel lggout endpoint was called but could not find a parameter named \"%s\"",
			   OIDC_PROTO_LOGOUT_TOKEN);
		goto out;
	}

	// TODO: jwk symmetric key based on provider

	if (oidc_jwt_parse(r->pool, logout_token, &jwt,
			   oidc_util_merge_symmetric_key(r->pool, oidc_cfg_private_keys_get(cfg), NULL), FALSE,
			   &err) == FALSE) {
		oidc_error(r, "oidc_jwt_parse failed: %s", oidc_jose_e2s(r->pool, err));
		goto out;
	}

	if ((jwt->header.alg == NULL) || (_oidc_strcmp(jwt->header.alg, "none") == 0)) {
		oidc_error(r, "logout token is not signed");
		goto out;
	}

	provider = oidc_get_provider_for_issuer(r, cfg, jwt->payload.iss, FALSE);
	if (provider == NULL) {
		oidc_error(r, "no provider found for issuer: %s", jwt->payload.iss);
		goto out;
	}

	if ((oidc_cfg_provider_id_token_signed_response_alg_get(provider) != NULL) &&
	    (_oidc_strcmp(oidc_cfg_provider_id_token_signed_response_alg_get(provider), jwt->header.alg) != 0)) {
		oidc_error(r, "logout token is signed using wrong algorithm: %s != %s", jwt->header.alg,
			   oidc_cfg_provider_id_token_signed_response_alg_get(provider));
		goto out;
	}

	// TODO: destroy the JWK used for decryption

	jwk = NULL;
	if (oidc_util_create_symmetric_key(r, oidc_cfg_provider_client_secret_get(provider), 0, NULL, TRUE, &jwk) ==
	    FALSE)
		return FALSE;

	if (oidc_proto_jwt_verify(
		r, cfg, jwt, oidc_cfg_provider_jwks_uri_get(provider),
		oidc_cfg_provider_ssl_validate_server_get(provider),
		oidc_util_merge_symmetric_key(r->pool, oidc_cfg_provider_verify_public_keys_get(provider), jwk),
		oidc_cfg_provider_id_token_signed_response_alg_get(provider)) == FALSE) {

		oidc_error(r, "id_token signature could not be validated, aborting");
		goto out;
	}

	if (oidc_proto_jwt_validate(
		r, jwt, oidc_cfg_provider_validate_issuer_get(provider) ? oidc_cfg_provider_issuer_get(provider) : NULL,
		FALSE, FALSE, oidc_cfg_provider_idtoken_iat_slack_get(provider)) == FALSE)
		goto out;

	/* verify the "aud" and "azp" values */
	if (oidc_proto_idtoken_validate_aud_and_azp(r, cfg, provider, &jwt->payload) == FALSE)
		goto out;

	json_t *events = json_object_get(jwt->payload.value.json, OIDC_CLAIM_EVENTS);
	if (events == NULL) {
		oidc_error(r, "\"%s\" claim could not be found in logout token", OIDC_CLAIM_EVENTS);
		goto out;
	}

	json_t *blogout = json_object_get(events, OIDC_EVENTS_BLOGOUT_KEY);
	if (!json_is_object(blogout)) {
		oidc_error(r, "\"%s\" object could not be found in \"%s\" claim", OIDC_EVENTS_BLOGOUT_KEY,
			   OIDC_CLAIM_EVENTS);
		goto out;
	}

	char *nonce = NULL;
	oidc_util_json_object_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_NONCE, &nonce, NULL);
	if (nonce != NULL) {
		oidc_error(r, "rejecting logout request/token since it contains a \"%s\" claim", OIDC_CLAIM_NONCE);
		goto out;
	}

	char *jti = NULL;
	oidc_util_json_object_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_JTI, &jti, NULL);
	if (jti != NULL) {
		char *replay = NULL;
		oidc_cache_get_jti(r, jti, &replay);
		if (replay != NULL) {
			oidc_error(r,
				   "the \"%s\" value (%s) passed in logout token was found in the cache already; "
				   "possible replay attack!?",
				   OIDC_CLAIM_JTI, jti);
			goto out;
		}
	}

	/* jti cache duration is the configured replay prevention window for token issuance plus 10 seconds for safety
	 */
	apr_time_t jti_cache_duration = apr_time_from_sec(oidc_cfg_provider_idtoken_iat_slack_get(provider) * 2 + 10);

	/* store it in the cache for the calculated duration */
	oidc_cache_set_jti(r, jti, jti, apr_time_now() + jti_cache_duration);

	oidc_util_json_object_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_EVENTS, &sid, NULL);

	// TODO: by-spec we should cater for the fact that "sid" has been provided
	//       in the id_token returned in the authentication request, but "sub"
	//       is used in the logout token but that requires a 2nd entry in the
	//       cache and a separate session "sub" member, ugh; we'll just assume
	//       that is "sid" is specified in the id_token, the OP will actually use
	//       this for logout
	//       (and probably call us multiple times or the same sub if needed)

	oidc_util_json_object_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_SID, &sid, NULL);
	if (sid == NULL)
		sid = jwt->payload.sub;

	if (sid == NULL) {
		oidc_error(r, "no \"sub\" and no \"sid\" claim found in logout token");
		goto out;
	}

	// a backchannel logout comes from the provider, so no need to revoke the tokens
	oidc_logout_cleanup_by_sid(r, sid, cfg, provider, FALSE);

	rc = OK;

out:

	if (jwk != NULL) {
		oidc_jwk_destroy(jwk);
		jwk = NULL;
	}
	if (jwt != NULL) {
		oidc_jwt_destroy(jwt);
		jwt = NULL;
	}

	oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_CACHE_CONTROL, "no-cache, no-store");
	oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_PRAGMA, "no-cache");

	return rc;
}

#define OIDC_REFRESH_TOKENS_BEFORE_LOGOUT_ENVVAR "OIDC_REFRESH_TOKENS_BEFORE_LOGOUT"

/*
 * perform (single) logout
 */
int oidc_logout(request_rec *r, oidc_cfg_t *c, oidc_session_t *session) {

	oidc_provider_t *provider = NULL;
	/* pickup the command or URL where the user wants to go after logout */
	char *url = NULL;
	char *error_str = NULL;
	char *error_description = NULL;
	char *id_token_hint = NULL;
	char *s_logout_request = NULL;

	oidc_util_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_LOGOUT, &url);

	oidc_debug(r, "enter (url=%s)", url);

	if (oidc_logout_is_front_channel(url)) {
		return oidc_logout_request(r, c, session, url, TRUE);
	} else if (oidc_logout_is_back_channel(url)) {
		return oidc_logout_backchannel(r, c);
	}

	if ((url == NULL) || (_oidc_strcmp(url, "") == 0)) {

		url = apr_pstrdup(r->pool, oidc_util_absolute_url(r, c, oidc_cfg_default_slo_url_get(c)));

	} else {

		/* do input validation on the logout parameter value */
		if (oidc_validate_redirect_url(r, c, url, TRUE, &error_str, &error_description) == FALSE) {
			return oidc_util_html_send_error(r, error_str, error_description, HTTP_BAD_REQUEST);
		}
	}

	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE)
		oidc_warn(r, "oidc_get_provider_from_session failed");

	if ((provider != NULL) && (oidc_cfg_provider_end_session_endpoint_get(provider) != NULL)) {

		if (apr_table_get(r->subprocess_env, OIDC_REFRESH_TOKENS_BEFORE_LOGOUT_ENVVAR) != NULL) {
			if (oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, &id_token_hint) == FALSE)
				oidc_warn(r, "id_token_hint could not be refreshed before logout");
		} else {
			id_token_hint = apr_pstrdup(r->pool, oidc_session_get_idtoken(r, session));
		}

		s_logout_request = apr_pstrdup(r->pool, oidc_cfg_provider_end_session_endpoint_get(provider));
		if (id_token_hint != NULL) {
			s_logout_request = apr_psprintf(
			    r->pool, "%s%s" OIDC_PROTO_ID_TOKEN_HINT "=%s", s_logout_request,
			    strchr(s_logout_request ? s_logout_request : "", OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP
												      : OIDC_STR_QUERY,
			    oidc_http_url_encode(r, id_token_hint));
		}

		if (url != NULL) {
			s_logout_request = apr_psprintf(
			    r->pool, "%s%spost_logout_redirect_uri=%s", s_logout_request,
			    strchr(s_logout_request ? s_logout_request : "", OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP
												      : OIDC_STR_QUERY,
			    oidc_http_url_encode(r, url));
		}

		if (oidc_cfg_provider_logout_request_params_get(provider) != NULL) {
			s_logout_request = apr_psprintf(
			    r->pool, "%s%s%s", s_logout_request,
			    strchr(s_logout_request ? s_logout_request : "", OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP
												      : OIDC_STR_QUERY,
			    oidc_cfg_provider_logout_request_params_get(provider));
		}
		// char *state = NULL;
		// oidc_proto_generate_nonce(r, &state, 8);
		// url = apr_psprintf(r->pool, "%s&state=%s", logout_request, state);
		url = s_logout_request;
	}

	return oidc_logout_request(r, c, session, url, TRUE);
}
