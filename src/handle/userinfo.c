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

#include "cfg/provider.h"
#include "handle/handle.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"

/*
 * store claims resolved from the userinfo endpoint in the session
 */
void oidc_userinfo_store_claims(request_rec *r, oidc_cfg_t *c, oidc_session_t *session, oidc_provider_t *provider,
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

		if (oidc_cfg_session_type_get(c) != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
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
	if (oidc_cfg_provider_userinfo_refresh_interval_get(provider) > -1)
		oidc_session_reset_userinfo_last_refresh(r, session);
}

/*
 * retrieve claims from the userinfo endpoint and return the stringified response
 */
const char *oidc_userinfo_retrieve_claims(request_rec *r, oidc_cfg_t *c, oidc_provider_t *provider,
					  const char *access_token, const char *access_token_type,
					  oidc_session_t *session, char *id_token_sub, char **userinfo_jwt) {

	char *result = NULL;
	char *refreshed_access_token = NULL;
	char *refreshed_access_token_type = NULL;
	json_t *id_token_claims = NULL;
	long response_code = 0;

	oidc_debug(r, "enter");

	/* see if a userinfo endpoint is set, otherwise there's nothing to do for us */
	if (oidc_cfg_provider_userinfo_endpoint_url_get(provider) == NULL) {
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
	if (oidc_proto_userinfo_request(r, c, provider, id_token_sub, access_token, access_token_type, &result,
					userinfo_jwt, &response_code) == TRUE)
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
	if (oidc_refresh_token_grant(r, c, session, provider, &refreshed_access_token, &refreshed_access_token_type,
				     NULL) == FALSE) {
		oidc_error(r, "refreshing access token failed, claims will not be retrieved/refreshed from the "
			      "userinfo endpoint");
		result = NULL;
		goto end;
	}

	/* try again with the new access token */
	if (oidc_proto_userinfo_request(r, c, provider, id_token_sub, refreshed_access_token,
					refreshed_access_token_type, &result, userinfo_jwt, NULL) == FALSE) {

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
apr_byte_t oidc_userinfo_refresh_claims(request_rec *r, oidc_cfg_t *cfg, oidc_session_t *session,
					apr_byte_t *needs_save) {

	apr_byte_t rc = TRUE;
	oidc_provider_t *provider = NULL;
	const char *claims = NULL;
	const char *access_token = NULL;
	const char *access_token_type = NULL;
	char *userinfo_jwt = NULL;

	/* see int we can do anything here, i.e. a refresh interval is configured */
	int interval = oidc_session_get_userinfo_refresh_interval(r, session);

	oidc_debug(r, "interval=%d", interval);

	if (interval > -1) {

		/* get the current provider info */
		if (oidc_get_provider_from_session(r, cfg, session, &provider) == FALSE) {
			*needs_save = TRUE;
			oidc_cfg_provider_destroy(provider);
			return FALSE;
		}

		if (oidc_cfg_provider_userinfo_endpoint_url_get(provider) != NULL) {

			/* get the last refresh timestamp from the session info */
			apr_time_t last_refresh = oidc_session_get_userinfo_last_refresh(r, session);

			oidc_debug(r,
				   "refresh needed in: %" APR_TIME_T_FMT " seconds (last_refresh=%" APR_TIME_T_FMT
				   ", interval=%d, now=%" APR_TIME_T_FMT ")",
				   apr_time_sec(last_refresh + apr_time_from_sec(interval) - apr_time_now()),
				   apr_time_sec(last_refresh), interval, apr_time_sec(apr_time_now()));

			/* see if we need to refresh again */
			if (last_refresh + apr_time_from_sec(interval) < apr_time_now()) {

				/* get the current access token */
				access_token = oidc_session_get_access_token(r, session);
				access_token_type = oidc_session_get_access_token_type(r, session);

				/* retrieve the current claims */
				claims = oidc_userinfo_retrieve_claims(r, cfg, provider, access_token,
								       access_token_type, session, NULL, &userinfo_jwt);

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

	oidc_cfg_provider_destroy(provider);

	return rc;
}

#define OIDC_USERINFO_SIGNED_JWT_EXP_DEFAULT 60
#define OIDC_USERINFO_SIGNED_JWT_CACHE_TTL_DEFAULT -1
#define OIDC_USERINFO_SIGNED_JWT_CACHE_TTL_ENVVAR "OIDC_USERINFO_SIGNED_JWT_CACHE_TTL"

/*
 * obtain the signed JWT cache TTL from the environment variables
 */
static int oidc_userinfo_signed_jwt_cache_ttl(request_rec *r) {
	const char *s_ttl = apr_table_get(r->subprocess_env, OIDC_USERINFO_SIGNED_JWT_CACHE_TTL_ENVVAR);
	return _oidc_str_to_int(s_ttl, OIDC_USERINFO_SIGNED_JWT_CACHE_TTL_DEFAULT);
}

/*
 * create a signed JWT with s_claims payload and return the serialized form in cser
 */
static apr_byte_t oidc_userinfo_create_signed_jwt(request_rec *r, oidc_cfg_t *cfg, oidc_session_t *session,
						  const char *s_claims, char **cser) {
	apr_byte_t rv = FALSE;
	oidc_jwt_t *jwt = NULL;
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	apr_time_t access_token_expires = -1;
	char *jti = NULL;
	char *key = NULL;
	json_t *json = NULL;
	int ttl = 0;
	int exp = 0;
	apr_time_t expiry = 0;

	oidc_debug(r, "enter: %s", s_claims);

	if (oidc_proto_jwt_create_from_first_pkey(r, cfg, &jwk, &jwt, FALSE) == FALSE)
		goto end;

	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_AUD,
			    json_string(oidc_util_current_url(r, oidc_cfg_x_forwarded_headers_get(cfg))));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_ISS,
			    json_string(oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(cfg))));

	oidc_util_decode_json_object(r, s_claims, &json);
	if (json == NULL)
		goto end;
	if (oidc_util_json_merge(r, json, jwt->payload.value.json) == FALSE)
		goto end;
	s_claims = oidc_util_encode_json(r->pool, jwt->payload.value.json, JSON_PRESERVE_ORDER | JSON_COMPACT);
	if (oidc_jose_hash_and_base64url_encode(r->pool, OIDC_JOSE_ALG_SHA256, s_claims, _oidc_strlen(s_claims) + 1,
						&key, &err) == FALSE) {
		oidc_error(r, "oidc_jose_hash_and_base64url_encode failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	ttl = oidc_userinfo_signed_jwt_cache_ttl(r);
	if (ttl > -1)
		oidc_cache_get_signed_jwt(r, key, cser);

	if (*cser != NULL) {
		oidc_debug(r, "signed JWT found in cache");
		rv = TRUE;
		goto end;
	}

	if (json_object_get(jwt->payload.value.json, OIDC_CLAIM_JTI) == NULL) {
		oidc_util_generate_random_string(r, &jti, OIDC_PROTO_JWT_JTI_LEN);
		json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_JTI, json_string(jti));
	}
	if (json_object_get(jwt->payload.value.json, OIDC_CLAIM_IAT) == NULL) {
		json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_IAT,
				    json_integer(apr_time_sec(apr_time_now())));
	}
	if (json_object_get(jwt->payload.value.json, OIDC_CLAIM_EXP) == NULL) {
		access_token_expires = oidc_session_get_access_token_expires(r, session);
		json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_EXP,
				    json_integer(access_token_expires > 0 ? apr_time_sec(access_token_expires)
									  : apr_time_sec(apr_time_now()) +
										OIDC_USERINFO_SIGNED_JWT_EXP_DEFAULT));
	}

	if (oidc_proto_jwt_sign_and_serialize(r, jwk, jwt, cser) == FALSE)
		goto end;

	rv = TRUE;

	if (ttl < 0)
		goto end;

	if (ttl == 0) {
		// need to get the cache ttl from the exp claim
		oidc_util_json_object_get_int(jwt->payload.value.json, OIDC_CLAIM_EXP, &exp, 0);
		// actually the exp claim always exists by now
		expiry = (exp > 0) ? apr_time_from_sec(exp)
				   : apr_time_now() + apr_time_from_sec(OIDC_USERINFO_SIGNED_JWT_EXP_DEFAULT);
	} else {
		// ttl > 0
		expiry = apr_time_now() + apr_time_from_sec(ttl);
	}

	oidc_debug(r, "caching signed JWT with ~ttl(%ld)", apr_time_sec(expiry - apr_time_now()));
	oidc_cache_set_signed_jwt(r, key, *cser, expiry);

end:

	if (json)
		json_decref(json);

	if (jwt)
		oidc_jwt_destroy(jwt);

	return rv;
}

/*
 * pass the userinfo claims to headers and/or environment variables, encoded as configured
 */
void oidc_userinfo_pass_as(request_rec *r, oidc_cfg_t *cfg, oidc_session_t *session, const char *s_claims,
			   oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding) {
	const apr_array_header_t *pass_userinfo_as = NULL;
	oidc_pass_user_info_as_t *p = NULL;
	int i = 0;
	char *cser = NULL;

	pass_userinfo_as = oidc_cfg_dir_pass_userinfo_as_get(r);

#ifdef USE_LIBJQ
	s_claims = oidc_util_jq_filter(r, s_claims, oidc_cfg_dir_userinfo_claims_expr_get(r));
#endif

	for (i = 0; (pass_userinfo_as != NULL) && (i < pass_userinfo_as->nelts); i++) {

		p = APR_ARRAY_IDX(pass_userinfo_as, i, oidc_pass_user_info_as_t *);

		switch (p->type) {

		case OIDC_PASS_USERINFO_AS_CLAIMS:
			/* set the userinfo claims in the app headers */
			oidc_set_app_claims(r, cfg, s_claims);
			break;

		case OIDC_PASS_USERINFO_AS_JSON_OBJECT:
			/* pass the userinfo JSON object to the app in a header or environment variable */
			oidc_util_set_app_info(r, p->name ? p->name : OIDC_APP_INFO_USERINFO_JSON, s_claims,
					       p->name ? "" : OIDC_DEFAULT_HEADER_PREFIX, pass_in, encoding);
			break;

		case OIDC_PASS_USERINFO_AS_JWT:
			if (oidc_cfg_session_type_get(cfg) != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
				/* get the compact serialized JWT from the session */
				const char *s_userinfo_jwt = oidc_session_get_userinfo_jwt(r, session);
				if (s_userinfo_jwt != NULL) {
					/* pass the compact serialized JWT to the app in a header or environment
					 * variable */
					oidc_util_set_app_info(
					    r, p->name ? p->name : OIDC_APP_INFO_USERINFO_JWT, s_userinfo_jwt,
					    p->name ? "" : OIDC_DEFAULT_HEADER_PREFIX, pass_in, encoding);
				} else {
					oidc_debug(
					    r,
					    "configured to pass userinfo in a JWT, but no such JWT was found in the "
					    "session (probably no such JWT was returned from the userinfo endpoint)");
				}
			} else {
				oidc_error(r, "session type \"client-cookie\" does not allow storing/passing a "
					      "userinfo JWT; use \"" OIDCSessionType " server-cache\" for that");
			}
			break;

		case OIDC_PASS_USERINFO_AS_SIGNED_JWT:

			if (oidc_userinfo_create_signed_jwt(r, cfg, session, s_claims, &cser) == TRUE) {
				oidc_util_set_app_info(r, p->name ? p->name : OIDC_APP_INFO_SIGNED_JWT, cser,
						       p->name ? "" : OIDC_DEFAULT_HEADER_PREFIX, pass_in, encoding);
			}
			break;

		default:
			break;
		}
	}
}
