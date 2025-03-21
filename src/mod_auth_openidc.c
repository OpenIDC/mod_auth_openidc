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
 * Copyright (C) 2013-2017 Ping Identity Corporation
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
 * Initially based on mod_auth_cas.c:
 * https://github.com/Jasig/mod_auth_cas
 *
 * Other code copied/borrowed/adapted:
 * shared memory caching: mod_auth_mellon
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include "mod_auth_openidc.h"
#include "cfg/cache.h"
#include "cfg/dir.h"
#include "cfg/oauth.h"
#include "handle/handle.h"
#include "metadata.h"
#include "metrics.h"
#include "oauth.h"
#include "proto/proto.h"
#include "util.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x01000000)
#define OPENSSL_NO_THREADID
#endif

#include <apr_portable.h>

/*
 * clean any suspicious headers in the HTTP request sent by the user agent
 */
static void oidc_scrub_request_headers(request_rec *r, const char *claim_prefix, apr_hash_t *scrub) {

	const int prefix_len = claim_prefix ? _oidc_strlen(claim_prefix) : 0;

	/* get an array representation of the incoming HTTP headers */
	const apr_array_header_t *const h = apr_table_elts(r->headers_in);

	/* table to keep the non-suspicious headers */
	apr_table_t *clean_headers = apr_table_make(r->pool, h->nelts);

	/* loop over the incoming HTTP headers */
	const apr_table_entry_t *const e = (const apr_table_entry_t *)h->elts;
	int i;
	for (i = 0; i < h->nelts; i++) {
		const char *const k = e[i].key;

		/* is this header's name equivalent to a header that needs scrubbing? */
		const char *hdr = (k != NULL) && (scrub != NULL) ? apr_hash_get(scrub, k, APR_HASH_KEY_STRING) : NULL;
		const int header_matches = (hdr != NULL) && (oidc_util_strnenvcmp(k, hdr, -1) == 0);

		/*
		 * would this header be interpreted as a mod_auth_openidc attribute? Note
		 * that prefix_len will be zero if no attr_prefix is defined,
		 * so this will always be false. Also note that we do not
		 * scrub headers if the prefix is empty because every header
		 * would match.
		 */
		const int prefix_matches =
		    (k != NULL) && prefix_len && (oidc_util_strnenvcmp(k, claim_prefix, prefix_len) == 0);

		/* add to the clean_headers if non-suspicious, skip and report otherwise */
		if (!prefix_matches && !header_matches) {
			apr_table_addn(clean_headers, k, e[i].val);
		} else {
			oidc_warn(r, "scrubbed suspicious request header (%s: %.32s)", k, e[i].val);
		}
	}

	/* overwrite the incoming headers with the cleaned result */
	r->headers_in = clean_headers;
}

/*
 * scrub all mod_auth_openidc related headers
 */
void oidc_scrub_headers(request_rec *r) {
	oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	const char *prefix = oidc_cfg_claim_prefix_get(cfg);
	apr_hash_t *hdrs = apr_hash_make(r->pool);

	if (_oidc_strcmp(prefix, "") == 0) {
		if ((oidc_cfg_white_listed_claims_get(cfg) != NULL) &&
		    (apr_hash_count(oidc_cfg_white_listed_claims_get(cfg)) > 0))
			hdrs = apr_hash_overlay(r->pool, oidc_cfg_white_listed_claims_get(cfg), hdrs);
		else
			oidc_warn(r, "both " OIDCClaimPrefix " and " OIDCWhiteListedClaims
				     " are empty: this renders an insecure setup!");
	}

	const char *authn_hdr = oidc_cfg_dir_authn_header_get(r);
	if (authn_hdr != NULL)
		apr_hash_set(hdrs, authn_hdr, APR_HASH_KEY_STRING, authn_hdr);

	/*
	 * scrub all headers starting with OIDC_ first
	 */
	oidc_scrub_request_headers(r, OIDC_DEFAULT_HEADER_PREFIX, hdrs);

	/*
	 * then see if the claim headers need to be removed on top of that
	 * (i.e. the prefix does not start with the default OIDC_)
	 */
	if ((_oidc_strstr(prefix, OIDC_DEFAULT_HEADER_PREFIX) != prefix)) {
		oidc_scrub_request_headers(r, prefix, NULL);
	}
}

/*
 * strip the session cookie from the headers sent to the application/backend
 */
void oidc_strip_cookies(request_rec *r) {

	char *cookie, *ctx, *result = NULL;
	const char *name = NULL;
	int i;

	const apr_array_header_t *strip = oidc_cfg_dir_strip_cookies_get(r);

	char *cookies = apr_pstrdup(r->pool, oidc_http_hdr_in_cookie_get(r));

	if ((cookies != NULL) && (strip != NULL)) {

		oidc_debug(r, "looking for the following cookies to strip from cookie header: %s",
			   apr_array_pstrcat(r->pool, strip, OIDC_CHAR_COMMA));

		cookie = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &ctx);

		do {
			while (cookie != NULL && *cookie == OIDC_CHAR_SPACE)
				cookie++;
			if (cookie == NULL)
				break;

			for (i = 0; i < strip->nelts; i++) {
				name = APR_ARRAY_IDX(strip, i, const char *);
				if ((_oidc_strncmp(cookie, name, _oidc_strlen(name)) == 0) &&
				    (cookie[_oidc_strlen(name)] == OIDC_CHAR_EQUAL)) {
					oidc_debug(r, "stripping: %s", name);
					break;
				}
			}

			if (i == strip->nelts) {
				result = result ? apr_psprintf(r->pool, "%s%s %s", result, OIDC_STR_SEMI_COLON, cookie)
						: cookie;
			}

			cookie = apr_strtok(NULL, OIDC_STR_SEMI_COLON, &ctx);
		} while (cookie != NULL);

		oidc_http_hdr_in_cookie_set(r, result);
	}
}

/*
 * check if s_json is valid provider metadata
 */
static apr_byte_t oidc_provider_validate_metadata_str(request_rec *r, oidc_cfg_t *c, const char *s_json,
						      json_t **j_provider, apr_byte_t decode_only) {

	if (oidc_util_decode_json_object(r, s_json, j_provider) == FALSE)
		return FALSE;

	if (decode_only == TRUE)
		return TRUE;

	/* check to see if it is valid metadata */
	if (oidc_metadata_provider_is_valid(r, c, *j_provider, NULL) == FALSE) {
		oidc_warn(r, "cache corruption detected: invalid metadata from url: %s",
			  oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)));
		json_decref(*j_provider);
		return FALSE;
	}

	return TRUE;
}

/*
 * return the static provider configuration, i.e. from a metadata URL or configuration primitives
 */
apr_byte_t oidc_provider_static_config(request_rec *r, oidc_cfg_t *c, oidc_provider_t **provider) {

	json_t *j_provider = NULL;
	char *s_json = NULL;

	/* see if we should configure a static provider based on external (cached) metadata */
	if ((oidc_cfg_metadata_dir_get(c) != NULL) ||
	    (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)) == NULL)) {
		*provider = oidc_cfg_provider_get(c);
		return TRUE;
	}

	oidc_cache_get_provider(r, oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)), &s_json);

	if (s_json != NULL)
		oidc_provider_validate_metadata_str(r, c, s_json, &j_provider, TRUE);

	if (j_provider == NULL) {

		if (oidc_metadata_provider_retrieve(r, c, NULL,
						    oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)),
						    &j_provider, &s_json) == FALSE) {
			oidc_error(r, "could not retrieve metadata from url: %s",
				   oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)));
			return FALSE;
		}
		json_decref(j_provider);

		if (oidc_provider_validate_metadata_str(r, c, s_json, &j_provider, FALSE) == FALSE)
			return FALSE;

		oidc_cache_set_provider(
		    r, oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)), s_json,
		    apr_time_now() + apr_time_from_sec(oidc_cfg_provider_metadata_refresh_interval_get(c) <= 0
							   ? OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT
							   : oidc_cfg_provider_metadata_refresh_interval_get(c)));
	}

	*provider = oidc_cfg_provider_copy(r->pool, oidc_cfg_provider_get(c));

	if (oidc_metadata_provider_parse(r, c, j_provider, *provider) == FALSE) {
		oidc_error(r, "could not parse metadata from url: %s",
			   oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)));
		json_decref(j_provider);
		return FALSE;
	}

	json_decref(j_provider);

	return TRUE;
}

/*
 * return the oidc_provider_t struct for the specified issuer
 */
oidc_provider_t *oidc_get_provider_for_issuer(request_rec *r, oidc_cfg_t *c, const char *issuer,
					      apr_byte_t allow_discovery) {

	/* by default we'll assume that we're dealing with a single statically configured OP */
	oidc_provider_t *provider = NULL;
	if (oidc_provider_static_config(r, c, &provider) == FALSE)
		return NULL;

	/* unless a metadata directory was configured, so we'll try and get the provider settings from there */
	if (oidc_cfg_metadata_dir_get(c) != NULL) {

		/* try and get metadata from the metadata directory for the OP that sent this response */
		if ((oidc_metadata_get(r, c, issuer, &provider, allow_discovery) == FALSE) || (provider == NULL)) {

			/* don't know nothing about this OP/issuer */
			oidc_error(r, "no provider metadata found for issuer \"%s\"", issuer);

			return NULL;
		}
	}

	return provider;
}

/*
 * return the HTTP method being called: only for POST data persistence purposes
 */
const char *oidc_original_request_method(request_rec *r, oidc_cfg_t *cfg, apr_byte_t handle_discovery_response) {
	const char *method = OIDC_METHOD_GET;

	char *m = NULL;
	if ((handle_discovery_response == TRUE) && (oidc_util_request_matches_url(r, oidc_util_redirect_uri(r, cfg))) &&
	    (oidc_is_discovery_response(r, cfg))) {
		oidc_util_request_parameter_get(r, OIDC_DISC_RM_PARAM, &m);
		if (m != NULL)
			method = apr_pstrdup(r->pool, m);
	} else {

		/*
		 * if POST preserve is not enabled for this location, there's no point in preserving
		 * the method either which would result in POSTing empty data on return;
		 * so we revert to legacy behavior
		 */
		if (oidc_cfg_dir_preserve_post_get(r) == 0)
			return OIDC_METHOD_GET;

		const char *content_type = oidc_http_hdr_in_content_type_get(r);
		if ((r->method_number == M_POST) &&
		    (_oidc_strcmp(content_type, OIDC_HTTP_CONTENT_TYPE_FORM_ENCODED) == 0))
			method = OIDC_METHOD_FORM_POST;
	}

	oidc_debug(r, "return: %s", method);

	return method;
}

/*
 * get the mod_auth_openidc related context from the (userdata in the) request
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
static apr_table_t *oidc_request_state(request_rec *rr) {

	/* our state is always stored in the main request */
	request_rec *r = (rr->main != NULL) ? rr->main : rr;

	/* our state is a table, get it */
	apr_table_t *state = NULL;
	apr_pool_userdata_get((void **)&state, OIDC_USERDATA_KEY, r->pool);

	/* if it does not exist, we'll create a new table */
	if (state == NULL) {
		state = apr_table_make(r->pool, 5);
		apr_pool_userdata_set(state, OIDC_USERDATA_KEY, NULL, r->pool);
	}

	/* return the resulting table, always non-null now */
	return state;
}

/*
 * set a name/value pair in the mod_auth_openidc-specific request context
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
void oidc_request_state_set(request_rec *r, const char *key, const char *value) {

	/* get a handle to the global state, which is a table */
	apr_table_t *state = oidc_request_state(r);

	/* put the name/value pair in that table */
	apr_table_set(state, key, value);
}

/*
 * get a name/value pair from the mod_auth_openidc-specific request context
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
const char *oidc_request_state_get(request_rec *r, const char *key) {

	/* get a handle to the global state, which is a table */
	apr_table_t *state = oidc_request_state(r);

	/* return the value from the table */
	return apr_table_get(state, key);
}

/*
 * set the claims from a JSON object (c.q. id_token or user_info response) stored
 * in the session in to HTTP headers passed on to the application
 */
apr_byte_t oidc_set_app_claims(request_rec *r, oidc_cfg_t *cfg, const char *s_claims) {

	json_t *j_claims = NULL;

	oidc_appinfo_pass_in_t pass_in = oidc_cfg_dir_pass_info_in_get(r);

	// optimize performance when `OIDCPassClaimsAs none` is set
	if (pass_in == OIDC_APPINFO_PASS_NONE)
		return TRUE;

	/* decode the string-encoded attributes in to a JSON structure */
	if (s_claims != NULL) {
		if (oidc_util_decode_json_object(r, s_claims, &j_claims) == FALSE)
			return FALSE;
	}

	/* set the resolved claims a HTTP headers for the application */
	if (j_claims != NULL) {
		oidc_util_set_app_infos(r, j_claims, oidc_cfg_claim_prefix_get(cfg), oidc_cfg_claim_delimiter_get(cfg),
					pass_in, oidc_cfg_dir_pass_info_encoding_get(r));

		/* release resources */
		json_decref(j_claims);
	}

	return TRUE;
}

/*
 * log message about max session duration
 */
void oidc_log_session_expires(request_rec *r, const char *msg, apr_time_t session_expires) {
	char buf[APR_RFC822_DATE_LEN + 1];
	apr_rfc822_date(buf, session_expires);
	oidc_debug(r, "%s: %s (in %" APR_TIME_T_FMT " secs from now)", msg, buf,
		   apr_time_sec(session_expires - apr_time_now()));
}

/*
 * see if this is a request that is capable of completing an authentication round trip to the Provider
 */
apr_byte_t oidc_is_auth_capable_request(request_rec *r) {

	if ((oidc_http_hdr_in_x_requested_with_get(r) != NULL) &&
	    (_oidc_strnatcasecmp(oidc_http_hdr_in_x_requested_with_get(r), OIDC_HTTP_HDR_VAL_XML_HTTP_REQUEST) == 0))
		return FALSE;

	if ((oidc_http_hdr_in_sec_fetch_mode_get(r) != NULL) &&
	    (_oidc_strnatcasecmp(oidc_http_hdr_in_sec_fetch_mode_get(r), OIDC_HTTP_HDR_VAL_NAVIGATE) != 0))
		return FALSE;

	if ((oidc_http_hdr_in_sec_fetch_dest_get(r) != NULL) &&
	    (_oidc_strnatcasecmp(oidc_http_hdr_in_sec_fetch_dest_get(r), OIDC_HTTP_HDR_VAL_DOCUMENT) != 0))
		return FALSE;

	if ((oidc_http_hdr_in_accept_contains(r, OIDC_HTTP_CONTENT_TYPE_TEXT_HTML) == FALSE) &&
	    (oidc_http_hdr_in_accept_contains(r, OIDC_HTTP_CONTENT_TYPE_APP_XHTML_XML) == FALSE) &&
	    (oidc_http_hdr_in_accept_contains(r, OIDC_HTTP_CONTENT_TYPE_ANY) == FALSE))
		return FALSE;

	return TRUE;
}

/*
 * find out which action we need to take when encountering an unauthenticated request
 */
static int oidc_handle_unauthenticated_user(request_rec *r, oidc_cfg_t *c) {

	/* see if we've configured OIDCUnAuthAction for this path */
	switch (oidc_cfg_dir_unauth_action_get(r)) {
	case OIDC_UNAUTH_RETURN410:
		return HTTP_GONE;
	case OIDC_UNAUTH_RETURN407:
		return HTTP_PROXY_AUTHENTICATION_REQUIRED;
	case OIDC_UNAUTH_RETURN401:
		return HTTP_UNAUTHORIZED;
	case OIDC_UNAUTH_PASS:
		r->user = "";

		/*
		 * we're not going to pass information about an authenticated user to the application,
		 * but we do need to scrub the headers that mod_auth_openidc would set for security reasons
		 */
		oidc_scrub_headers(r);

		return OK;

	case OIDC_UNAUTH_AUTHENTICATE:

		/*
		 * exception handling: if this looks like a XMLHttpRequest call we
		 * won't redirect the user and thus avoid creating a state cookie
		 * for a non-browser (= Javascript) call that will never return from the OP
		 */
		if ((oidc_cfg_dir_unauth_expr_is_set(r) == FALSE) && (oidc_is_auth_capable_request(r) == FALSE))
			return HTTP_UNAUTHORIZED;
	}

	/*
	 * else: no session (regardless of whether it is main or sub-request),
	 * and we need to authenticate the user
	 */
	return oidc_request_authenticate_user(r, c, NULL, oidc_util_current_url(r, oidc_cfg_x_forwarded_headers_get(c)),
					      NULL, NULL, NULL, oidc_cfg_dir_path_auth_request_params_get(r),
					      oidc_cfg_dir_path_scope_get(r));
}

/*
 * check if maximum session duration was exceeded
 */
static apr_byte_t oidc_check_max_session_duration(request_rec *r, oidc_cfg_t *cfg, oidc_session_t *session, int *rc) {

	/* get the session expiry from the session data */
	apr_time_t session_expires = oidc_session_get_session_expires(r, session);

	/* check the expire timestamp against the current time */
	if (apr_time_now() > session_expires) {
		oidc_warn(r, "maximum session duration exceeded for user: %s", session->remote_user);
		oidc_session_kill(r, session);
		*rc = oidc_handle_unauthenticated_user(r, cfg);
		return FALSE;
	}

	/* log message about max session duration */
	oidc_log_session_expires(r, "session max lifetime", session_expires);

	*rc = OK;

	return TRUE;
}

/*
 * validate received session cookie against the domain it was issued for:
 *
 * this handles the case where the cache configured is a the same single memcache, Redis, or file
 * backend for different (virtual) hosts, or a client-side cookie protected with the same secret
 *
 * it also handles the case that a cookie is unexpectedly shared across multiple hosts in
 * name-based virtual hosting even though the OP(s) would be the same
 */
apr_byte_t oidc_check_cookie_domain(request_rec *r, oidc_cfg_t *cfg, oidc_session_t *session) {
	const char *c_cookie_domain = oidc_cfg_cookie_domain_get(cfg)
					  ? oidc_cfg_cookie_domain_get(cfg)
					  : oidc_util_current_url_host(r, oidc_cfg_x_forwarded_headers_get(cfg));
	const char *s_cookie_domain = oidc_session_get_cookie_domain(r, session);
	if ((s_cookie_domain == NULL) || (_oidc_strnatcasecmp(c_cookie_domain, s_cookie_domain) != 0)) {
		oidc_warn(r,
			  "aborting: detected attempt to play cookie against a different domain/host than issued for! "
			  "(issued=%s, current=%s)",
			  s_cookie_domain, c_cookie_domain);
		return FALSE;
	}

	return TRUE;
}

/*
 * get a handle to the provider configuration via the "issuer" stored in the session
 */
apr_byte_t oidc_get_provider_from_session(request_rec *r, oidc_cfg_t *c, oidc_session_t *session,
					  oidc_provider_t **provider) {

	oidc_debug(r, "enter");

	/* get the issuer value from the session state */
	const char *issuer = oidc_session_get_issuer(r, session);
	if (issuer == NULL) {
		oidc_warn(r, "empty or invalid session: no issuer found");
		return FALSE;
	}

	/* get the provider info associated with the issuer value */
	oidc_provider_t *p = oidc_get_provider_for_issuer(r, c, issuer, FALSE);
	if (p == NULL) {
		oidc_error(r, "session corrupted: no provider found for issuer: %s", issuer);
		return FALSE;
	}

	*provider = p;

	return TRUE;
}

/*
 * copy the claims and id_token from the session to the request state and optionally return them
 */
static void oidc_copy_tokens_to_request_state(request_rec *r, oidc_session_t *session, const char **s_id_token,
					      const char **s_claims) {

	const char *id_token = oidc_session_get_idtoken_claims(r, session);
	const char *claims = oidc_session_get_userinfo_claims(r, session);

	oidc_debug(r, "id_token=%s claims=%s", id_token, claims);

	if (id_token != NULL) {
		oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_IDTOKEN, id_token);
		if (s_id_token != NULL)
			*s_id_token = id_token;
	}

	if (claims != NULL) {
		oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_CLAIMS, claims);
		if (s_claims != NULL)
			*s_claims = claims;
	}
}

/*
 * pass refresh_token, access_token and access_token_expires as headers/environment variables to the application
 */
apr_byte_t oidc_session_pass_tokens(request_rec *r, oidc_cfg_t *cfg, oidc_session_t *session, apr_byte_t extend_session,
				    apr_byte_t *needs_save) {

	oidc_appinfo_pass_in_t pass_in = oidc_cfg_dir_pass_info_in_get(r);
	oidc_appinfo_encoding_t encoding = oidc_cfg_dir_pass_info_encoding_get(r);

	/* set the refresh_token in the app headers/variables, if enabled for this location/directory */
	const char *refresh_token = oidc_session_get_refresh_token(r, session);
	if ((oidc_cfg_dir_pass_refresh_token_get(r) != 0) && (refresh_token != NULL)) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_REFRESH_TOKEN, refresh_token, OIDC_DEFAULT_HEADER_PREFIX,
				       pass_in, encoding);
	}

	/* set the access_token in the app headers/variables */
	const char *access_token = oidc_session_get_access_token(r, session);
	if ((oidc_cfg_dir_pass_access_token_get(r) != 0) && access_token != NULL) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN, access_token, OIDC_DEFAULT_HEADER_PREFIX, pass_in,
				       encoding);
	}

	/* set the access_token type in the app headers/variables */
	const char *access_token_type = oidc_session_get_access_token_type(r, session);
	if ((oidc_cfg_dir_pass_access_token_get(r) != 0) && access_token_type != NULL) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN_TYPE, access_token_type,
				       OIDC_DEFAULT_HEADER_PREFIX, pass_in, encoding);
	}

	/* set the expiry timestamp in the app headers/variables */
	const char *access_token_expires = oidc_session_get_access_token_expires2str(r, session);
	if ((oidc_cfg_dir_pass_access_token_get(r) != 0) && access_token_expires != NULL) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN_EXP, access_token_expires,
				       OIDC_DEFAULT_HEADER_PREFIX, pass_in, encoding);
	}

	if (extend_session) {
		/*
		 * reset the session inactivity timer
		 * but only do this once per 10% of the inactivity timeout interval (with a max to 60 seconds)
		 * for performance reasons
		 *
		 * now there's a small chance that the session ends 10% (or a minute) earlier than configured/expected
		 * cq. when there's a request after a recent save (so no update) and then no activity happens until
		 * a request comes in just before the session should expire
		 * ("recent" and "just before" refer to 10%-with-a-max-of-60-seconds of the inactivity interval after
		 * the start/last-update and before the expiry of the session respectively)
		 *
		 * this is be deemed acceptable here because of performance gain
		 */
		apr_time_t interval = apr_time_from_sec(oidc_cfg_session_inactivity_timeout_get(cfg));
		apr_time_t now = apr_time_now();
		apr_time_t slack = interval / 10;
		if (slack > apr_time_from_sec(60))
			slack = apr_time_from_sec(60);
		if (session->expiry - now < interval - slack) {
			session->expiry = now + interval;
			*needs_save = TRUE;
		}
	}

	// if this is a newly created session, we'll write it again to update the samesite setting on the session cookie
	if (oidc_session_get_session_new(r, session)) {
		*needs_save = TRUE;
		oidc_session_set_session_new(r, session, 0);
	}

	/* log message about session expiry */
	oidc_log_session_expires(r, "session inactivity timeout", session->expiry);

	return TRUE;
}

/*
 * handle the case where we have identified an existing authentication session for a user
 */
static int oidc_handle_existing_session(request_rec *r, oidc_cfg_t *cfg, oidc_session_t *session,
					apr_byte_t extend_session, apr_byte_t *needs_save) {

	apr_byte_t rv = FALSE;
	int rc = OK;
	const char *s_claims = NULL;
	const char *s_id_token = NULL;

	oidc_debug(r, "enter");

	/* set the user in the main request for further (incl. sub-request) processing */
	r->user = apr_pstrdup(r->pool, session->remote_user);
	oidc_debug(r, "set remote_user to \"%s\" in existing session \"%s\"", r->user, session->uuid);

	/* get the header name in which the remote user name needs to be passed */
	const char *authn_header = oidc_cfg_dir_authn_header_get(r);

	oidc_appinfo_pass_in_t pass_in = oidc_cfg_dir_pass_info_in_get(r);
	oidc_appinfo_encoding_t encoding = oidc_cfg_dir_pass_info_encoding_get(r);

	/* verify current cookie domain against issued cookie domain */
	if (oidc_check_cookie_domain(r, cfg, session) == FALSE) {
		*needs_save = FALSE;
		OIDC_METRICS_COUNTER_INC(r, cfg, OM_SESSION_ERROR_COOKIE_DOMAIN);
		return HTTP_UNAUTHORIZED;
	}

	/*
	 * we're going to pass the information that we have to the application,
	 * but first we need to scrub the headers that we're going to use for security reasons
	 * NB: need it before oidc_check_max_session_duration since OIDCUnAuthAction pass may be set
	 */
	oidc_scrub_headers(r);

	/* check if the maximum session duration was exceeded */
	if (oidc_check_max_session_duration(r, cfg, session, &rc) == FALSE) {
		*needs_save = FALSE;
		OIDC_METRICS_COUNTER_INC(r, cfg, OM_SESSION_ERROR_EXPIRED);
		// NB: rc was set (e.g. to a 302 auth redirect) by the call to oidc_check_max_session_duration
		return rc;
	}

	if (extend_session) {

		/* if needed, refresh the access token */
		rv = oidc_refresh_access_token_before_expiry(
		    r, cfg, session, oidc_cfg_dir_refresh_access_token_before_expiry_get(r), needs_save);
		if (rv == FALSE) {
			*needs_save = FALSE;
			oidc_debug(r, "dir_action_on_error_refresh: %d", oidc_cfg_dir_action_on_error_refresh_get(r));
			OIDC_METRICS_COUNTER_INC(r, cfg, OM_SESSION_ERROR_REFRESH_ACCESS_TOKEN);
			if (oidc_cfg_dir_action_on_error_refresh_get(r) == OIDC_ON_ERROR_LOGOUT) {
				return oidc_logout_request(
				    r, cfg, session, oidc_util_absolute_url(r, cfg, oidc_cfg_default_slo_url_get(cfg)),
				    FALSE);
			}
			if (oidc_cfg_dir_action_on_error_refresh_get(r) == OIDC_ON_ERROR_AUTH) {
				oidc_session_kill(r, session);
				return oidc_handle_unauthenticated_user(r, cfg);
			}
			return HTTP_BAD_GATEWAY;
		}

		/* if needed, refresh claims from the user info endpoint */
		rv = oidc_userinfo_refresh_claims(r, cfg, session, needs_save);
		if (rv == FALSE) {
			*needs_save = FALSE;
			oidc_debug(r, "action_on_userinfo_error: %d", oidc_cfg_action_on_userinfo_error_get(cfg));
			OIDC_METRICS_COUNTER_INC(r, cfg, OM_SESSION_ERROR_REFRESH_USERINFO);
			if (oidc_cfg_action_on_userinfo_error_get(cfg) == OIDC_ON_ERROR_LOGOUT) {
				return oidc_logout_request(
				    r, cfg, session, oidc_util_absolute_url(r, cfg, oidc_cfg_default_slo_url_get(cfg)),
				    FALSE);
			}
			if (oidc_cfg_action_on_userinfo_error_get(cfg) == OIDC_ON_ERROR_AUTH) {
				oidc_session_kill(r, session);
				return oidc_handle_unauthenticated_user(r, cfg);
			}
			return HTTP_BAD_GATEWAY;
		}
	}

	/* set the user authentication HTTP header if set and required */
	if ((r->user != NULL) && (authn_header != NULL))
		oidc_http_hdr_in_set(r, authn_header, r->user);

	/* copy id_token and claims from session to request state and obtain their values */
	oidc_copy_tokens_to_request_state(r, session, &s_id_token, &s_claims);

	if ((oidc_cfg_dir_pass_idtoken_as_get(r) & OIDC_PASS_IDTOKEN_AS_CLAIMS)) {
		/* set the id_token in the app headers */
		if (oidc_set_app_claims(r, cfg, s_id_token) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((oidc_cfg_dir_pass_idtoken_as_get(r) & OIDC_PASS_IDTOKEN_AS_PAYLOAD)) {
		/* pass the id_token JSON object to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ID_TOKEN_PAYLOAD, s_id_token, OIDC_DEFAULT_HEADER_PREFIX,
				       pass_in, encoding);
	}

	if ((oidc_cfg_dir_pass_idtoken_as_get(r) & OIDC_PASS_IDTOKEN_AS_SERIALIZED)) {
		/* get the compact serialized JWT from the session */
		s_id_token = oidc_session_get_idtoken(r, session);
		if (s_id_token) {
			/* pass the compact serialized JWT to the app in a header or environment variable */
			oidc_util_set_app_info(r, OIDC_APP_INFO_ID_TOKEN, s_id_token, OIDC_DEFAULT_HEADER_PREFIX,
					       pass_in, encoding);
		} else {
			oidc_warn(r, "id_token was not found in the session so it cannot be passed on");
		}
	}

	/* pass the at, rt and at expiry to the application, possibly update the session expiry */
	if (oidc_session_pass_tokens(r, cfg, session, extend_session, needs_save) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	oidc_userinfo_pass_as(r, cfg, session, s_claims, pass_in, encoding);

	/* return "user authenticated" status */
	return OK;
}

/*
 * get the r->user for this request based on the configuration for OIDC/OAuth
 */
apr_byte_t oidc_get_remote_user(request_rec *r, const char *claim_name, const char *reg_exp, const char *replace,
				json_t *json, char **request_user) {

	/* get the claim value from the JSON object */
	json_t *username = json_object_get(json, claim_name);
	if ((username == NULL) || (!json_is_string(username))) {
		oidc_warn(r, "JSON object did not contain a \"%s\" string", claim_name);
		return FALSE;
	}

	*request_user = apr_pstrdup(r->pool, json_string_value(username));

	if (reg_exp != NULL) {

		char *error_str = NULL;

		if (replace == NULL) {

			if (oidc_util_regexp_first_match(r->pool, *request_user, reg_exp, request_user, &error_str) ==
			    FALSE) {
				oidc_error(r, "oidc_util_regexp_first_match failed: %s", error_str);
				*request_user = NULL;
				return FALSE;
			}

		} else if (oidc_util_regexp_substitute(r->pool, *request_user, reg_exp, replace, request_user,
						       &error_str) == FALSE) {

			oidc_error(r, "oidc_util_regexp_substitute failed: %s", error_str);
			*request_user = NULL;
			return FALSE;
		}
	}

	return TRUE;
}

#define OIDC_MAX_URL_LENGTH 8192 * 2

/*
 * avoid cross site request forgery on the redirect_to_url
 */
apr_byte_t oidc_validate_redirect_url(request_rec *r, oidc_cfg_t *c, const char *redirect_to_url,
				      apr_byte_t restrict_to_host, char **err_str, char **err_desc) {
	apr_uri_t uri;
	const char *c_host = NULL;
	apr_hash_index_t *hi = NULL;
	size_t i = 0;
	char *url = apr_pstrndup(r->pool, redirect_to_url, OIDC_MAX_URL_LENGTH);
	char *url_ipv6_aware = NULL;

	// replace potentially harmful backslashes with forward slashes
	for (i = 0; i < _oidc_strlen(url); i++)
		if (url[i] == '\\')
			url[i] = '/';

	if (apr_uri_parse(r->pool, url, &uri) != APR_SUCCESS) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(r->pool, "not a valid URL value: %s", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	if (oidc_cfg_redirect_urls_allowed_get(c) != NULL) {
		for (hi = apr_hash_first(NULL, oidc_cfg_redirect_urls_allowed_get(c)); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, (const void **)&c_host, NULL, NULL);
			if (oidc_util_regexp_first_match(r->pool, url, c_host, NULL, err_str) == TRUE)
				break;
		}
		if (hi == NULL) {
			*err_str = apr_pstrdup(r->pool, "URL not allowed");
			*err_desc =
			    apr_psprintf(r->pool, "value does not match the list of allowed redirect URLs: %s", url);
			oidc_error(r, "%s: %s", *err_str, *err_desc);
			return FALSE;
		}
	} else if ((uri.hostname != NULL) && (restrict_to_host == TRUE)) {
		c_host = oidc_util_current_url_host(r, oidc_cfg_x_forwarded_headers_get(c));

		if (strchr(uri.hostname, ':')) { /* v6 literal */
			url_ipv6_aware = apr_pstrcat(r->pool, "[", uri.hostname, "]", NULL);
		} else {
			url_ipv6_aware = uri.hostname;
		}

		if ((oidc_util_strcasestr(c_host, url_ipv6_aware) == NULL) ||
		    (oidc_util_strcasestr(url_ipv6_aware, c_host) == NULL)) {
			*err_str = apr_pstrdup(r->pool, "Invalid Request");
			*err_desc = apr_psprintf(
			    r->pool, "URL value \"%s\" does not match the hostname of the current request \"%s\"",
			    apr_uri_unparse(r->pool, &uri, 0), c_host);
			oidc_error(r, "%s: %s", *err_str, *err_desc);
			return FALSE;
		}
	}

	if ((uri.hostname == NULL) && (_oidc_strstr(url, "/") != url)) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(
		    r->pool, "No hostname was parsed and it does not seem to be relative, i.e starting with '/': %s",
		    url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	} else if ((uri.hostname == NULL) && (_oidc_strstr(url, "//") == url)) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(r->pool, "No hostname was parsed and starting with '//': %s", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	} else if ((uri.hostname == NULL) && (_oidc_strstr(url, "/\\") == url)) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(r->pool, "No hostname was parsed and starting with '/\\': %s", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	/* validate the URL to prevent HTTP header splitting */
	if (((_oidc_strstr(url, "\n") != NULL) || _oidc_strstr(url, "\r") != NULL)) {
		*err_str = apr_pstrdup(r->pool, "Invalid URL");
		*err_desc =
		    apr_psprintf(r->pool, "URL value \"%s\" contains illegal \"\n\" or \"\r\" character(s)", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}
	if ((_oidc_strstr(url, "/%09") != NULL) || (oidc_util_strcasestr(url, "/%2f") != NULL) ||
	    (_oidc_strstr(url, "/\t") != NULL) || (_oidc_strstr(url, "/%68") != NULL) ||
	    (oidc_util_strcasestr(url, "/http:") != NULL) || (oidc_util_strcasestr(url, "/https:") != NULL) ||
	    (oidc_util_strcasestr(url, "/javascript:") != NULL) || (_oidc_strstr(url, "/〱") != NULL) ||
	    (_oidc_strstr(url, "/〵") != NULL) || (_oidc_strstr(url, "/ゝ") != NULL) ||
	    (_oidc_strstr(url, "/ー") != NULL) || (_oidc_strstr(url, "/ｰ") != NULL) ||
	    (_oidc_strstr(url, "/<") != NULL) || (oidc_util_strcasestr(url, "%01javascript:") != NULL) ||
	    (_oidc_strstr(url, "/%5c") != NULL) || (_oidc_strstr(url, "/\\") != NULL)) {
		*err_str = apr_pstrdup(r->pool, "Invalid URL");
		*err_desc = apr_psprintf(r->pool, "URL value \"%s\" contains illegal character(s)", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	return TRUE;
}

/*
 * return the Javascript code used to handle an Implicit grant type
 * i.e. that posts the data returned by the OP in the URL fragment to the OIDCRedirectURI
 */
static int oidc_javascript_implicit(request_rec *r, oidc_cfg_t *c) {

	oidc_debug(r, "enter");

	const char *java_script =
	    "    <script type=\"text/javascript\">\n"
	    "      function postOnLoad() {\n"
	    "        encoded = location.hash.substring(1).split('&');\n"
	    "        for (i = 0; i < encoded.length; i++) {\n"
	    "          encoded[i].replace(/\\+/g, ' ');\n"
	    "          var n = encoded[i].indexOf('=');\n"
	    "          var input = document.createElement('input');\n"
	    "          input.type = 'hidden';\n"
	    "          input.name = decodeURIComponent(encoded[i].substring(0, n));\n"
	    "          input.value = decodeURIComponent(encoded[i].substring(n+1));\n"
	    "          document.forms[0].appendChild(input);\n"
	    "        }\n"
	    "        document.forms[0].action = window.location.href.substr(0, window.location.href.indexOf('#'));\n"
	    "        document.forms[0].submit();\n"
	    "      }\n"
	    "    </script>\n";

	const char *html_body = "    <p>Submitting...</p>\n"
				"    <form method=\"post\" action=\"\">\n"
				"      <p>\n"
				"        <input type=\"hidden\" name=\"" OIDC_PROTO_RESPONSE_MODE
				"\" value=\"" OIDC_PROTO_RESPONSE_MODE_FRAGMENT "\">\n"
				"      </p>\n"
				"    </form>\n";

	return oidc_util_html_send(r, "Submitting...", java_script, "postOnLoad", html_body, OK);
}

/*
 * handle all requests to the redirect_uri
 */
int oidc_handle_redirect_uri_request(request_rec *r, oidc_cfg_t *c, oidc_session_t *session) {

	apr_byte_t needs_save = FALSE;
	char *s_extend_session = NULL;
	int rc = OK;

	OIDC_METRICS_TIMING_START(r, c);

	if (oidc_proto_response_is_redirect(r, c)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_AUTHN_RESPONSE_REDIRECT);

		/* this is an authorization response from the OP using the Basic Client profile or a Hybrid flow*/
		rc = oidc_response_authorization_redirect(r, c, session);

		OIDC_METRICS_TIMING_ADD(r, c, OM_AUTHN_RESPONSE);

		return rc;

		/*
		 *
		 * Note that we are checking for logout *before* checking for a POST authorization response
		 * to handle backchannel POST-based logout
		 *
		 * so any POST to the Redirect URI that does not have a logout query parameter will be handled
		 * as an authorization response; alternatively we could assume that a POST response has no
		 * parameters
		 */
	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_LOGOUT)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_LOGOUT);

		/* handle logout */
		rc = oidc_logout(r, c, session);

		return rc;

	} else if (oidc_proto_response_is_post(r, c)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_AUTHN_RESPONSE_POST);

		/* this is an authorization response using the fragment(+POST) response_mode with the Implicit Client
		 * profile */
		rc = oidc_response_authorization_post(r, c, session);

		OIDC_METRICS_TIMING_ADD(r, c, OM_AUTHN_RESPONSE);

		return rc;

	} else if (oidc_is_discovery_response(r, c)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_DISCOVERY_RESPONSE);

		/* this is response from the OP discovery page */
		rc = oidc_discovery_response(r, c);

		return rc;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_JWKS)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_JWKS);

		/*
		 * Will be handled in the content handler; avoid:
		 * No authentication done but request not allowed without authentication
		 * by setting r->user
		 */
		r->user = "";

		return OK;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_SESSION)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_SESSION);

		/* handle session management request */
		rc = oidc_session_management(r, c, session);

		return rc;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REFRESH)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_REFRESH);

		/* handle refresh token request */
		rc = oidc_refresh_token_request(r, c, session);

		return rc;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REQUEST_URI)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_REQUEST_URI);

		/* handle request object by reference request */
		rc = oidc_request_uri(r, c);

		return rc;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE);

		/* handle request to invalidate access token cache */
		rc = oidc_revoke_at_cache_remove(r, c);

		return rc;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REVOKE_SESSION)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_REVOKE_SESSION);

		/* handle request to revoke a user session */
		rc = oidc_revoke_session(r, c);

		return rc;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_DPOP)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_DPOP);

		r->user = "";

		return OK;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_INFO)) {

		if (session->remote_user == NULL)
			return HTTP_UNAUTHORIZED;

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_INFO);

		oidc_util_request_parameter_get(r, OIDC_INFO_PARAM_EXTEND_SESSION, &s_extend_session);

		// need to establish user/claims for authorization purposes
		rc = oidc_handle_existing_session(
		    r, c, session, (s_extend_session == NULL) || (_oidc_strcmp(s_extend_session, "false") != 0),
		    &needs_save);

		// retain this session across the authentication and content handler phases
		// by storing it in the request state
		apr_pool_userdata_set(session, OIDC_USERDATA_SESSION, NULL, r->pool);

		// record whether the session was modified and needs to be saved in the cache
		if (needs_save)
			oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_SAVE, "");

		return rc;

	} else if ((r->args == NULL) || (_oidc_strcmp(r->args, "") == 0)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_AUTHN_RESPONSE_IMPLICIT);

		/* this is a "bare" request to the redirect URI, indicating implicit flow using the fragment
		 * response_mode */
		rc = oidc_javascript_implicit(r, c);

		return rc;
	}

	/* this is not an authorization response or logout request */

	/* check for "error" response */
	if (oidc_util_request_has_parameter(r, OIDC_PROTO_ERROR)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_ERROR_PROVIDER);

		//		char *error = NULL, *descr = NULL;
		//		oidc_util_get_request_parameter(r, "error", &error);
		//		oidc_util_get_request_parameter(r, "error_description", &descr);
		//
		//		/* send user facing error to browser */
		//		return oidc_util_html_send_error(r, error, descr, OK);
		rc = oidc_response_authorization_redirect(r, c, session);

		return rc;
	}

	OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_ERROR_INVALID);

	oidc_error(
	    r, "The OpenID Connect callback URL received an invalid request: %s; returning HTTP_INTERNAL_SERVER_ERROR",
	    r->args);

	/* something went wrong */
	return oidc_util_html_send_error(
	    r, "Invalid Request", apr_psprintf(r->pool, "The OpenID Connect callback URL received an invalid request"),
	    HTTP_INTERNAL_SERVER_ERROR);
}

/*
 * main routine: handle OpenID Connect authentication
 */
static int oidc_check_userid_openidc(request_rec *r, oidc_cfg_t *c) {

	OIDC_METRICS_TIMING_START(r, c);

	if (oidc_util_redirect_uri(r, c) == NULL) {
		oidc_error(r, "configuration error: the authentication type is set to \"" OIDC_AUTH_TYPE_OPENID_CONNECT
			      "\" but " OIDCRedirectURI " has not been set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* check if this is a sub-request or an initial request */
	if (!ap_is_initial_req(r)) {

		/* not an initial request, try to recycle what we've already established in the main request */
		if (r->main != NULL)
			r->user = r->main->user;
		else if (r->prev != NULL)
			r->user = r->prev->user;

		if (r->user != NULL) {

			/* this is a sub-request and we have a session (headers will have been scrubbed and set already)
			 */
			oidc_debug(r, "recycling user '%s' from initial request for sub-request", r->user);

			/*
			 * apparently request state can get lost in sub-requests, so let's see
			 * if we need to restore id_token and/or claims from the session cache
			 */
			const char *s_id_token = oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_IDTOKEN);
			if (s_id_token == NULL) {

				oidc_session_t *session = NULL;
				oidc_session_load(r, &session);

				oidc_copy_tokens_to_request_state(r, session, NULL, NULL);

				/* free resources allocated for the session */
				oidc_session_free(r, session);
			}

			/* strip any cookies that we need to */
			oidc_strip_cookies(r);

			return OK;
		}
		/*
		 * else: not initial request, but we could not find a session, so:
		 * try to load a new session as if this were the initial request
		 */
	}

	int rc = OK;
	apr_byte_t needs_save = FALSE;

	/* load the session from the request state; this will be a new "empty" session if no state exists */
	oidc_session_t *session = NULL, *retain = NULL;
	oidc_session_load(r, &session);

	/* see if the initial request is to the redirect URI; this handles potential logout too */
	if (oidc_util_request_matches_url(r, oidc_util_redirect_uri(r, c))) {

		/* handle request to the redirect_uri */
		rc = oidc_handle_redirect_uri_request(r, c, session);

		/* see if the session needs to be retained for the content handler phase */
		apr_pool_userdata_get((void **)&retain, OIDC_USERDATA_SESSION, r->pool);

		/* free resources allocated for the session */
		if (retain == NULL)
			oidc_session_free(r, session);

		return rc;

		/* initial request to non-redirect URI, check if we have an existing session */
	} else if (session->remote_user != NULL) {

		/* this is initial request and we already have a session */
		rc = oidc_handle_existing_session(r, c, session, TRUE, &needs_save);
		if (rc == OK) {

			/* check if something was updated in the session and we need to save it again */
			if (needs_save) {
				if (oidc_session_save(r, session, FALSE) == FALSE) {
					oidc_warn(r, "error saving session");
					rc = HTTP_INTERNAL_SERVER_ERROR;
				}
			}
		}

		/* free resources allocated for the session */
		oidc_session_free(r, session);

		/* strip any cookies that we need to */
		oidc_strip_cookies(r);

		if (rc == OK) {
			OIDC_METRICS_TIMING_ADD(r, c, OM_SESSION_VALID);
		} else {
			OIDC_METRICS_COUNTER_INC(r, c, OM_SESSION_ERROR_GENERAL);
		}

		return rc;
	}

	/* free resources allocated for the session */
	oidc_session_free(r, session);

	/*
	 * else: we have no session and it is not an authorization or
	 *       discovery response: just hit the default flow for unauthenticated users
	 */

	return oidc_handle_unauthenticated_user(r, c);
}

/*
 * main routine: handle "mixed" OIDC/OAuth authentication
 */
static int oidc_check_mixed_userid_oauth(request_rec *r, oidc_cfg_t *c) {

	/* get the bearer access token from the Authorization header */
	const char *access_token = NULL;
	if (oidc_oauth_get_bearer_token(r, &access_token) == TRUE) {

		r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_OAUTH20);
		return oidc_oauth_check_userid(r, c, access_token);
	}

	if (r->method_number == M_OPTIONS) {
		r->user = "";
		return OK;
	}

	/* no bearer token found: then treat this as a regular OIDC browser request */
	r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_CONNECT);
	return oidc_check_userid_openidc(r, c);
}

int oidc_fixups(request_rec *r) {
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	if (oidc_enabled(r) == TRUE) {
		OIDC_METRICS_TIMING_REQUEST_ADD(r, c, OM_MOD_AUTH_OPENIDC);
		return OK;
	}
	return DECLINED;
}

/*
 * generic Apache authentication hook for this module: dispatches to OpenID Connect or OAuth 2.0 specific routines
 */
int oidc_check_user_id(request_rec *r) {

	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	int rv = DECLINED;

	OIDC_METRICS_TIMING_REQUEST_START(r, c);

	/* log some stuff about the incoming HTTP request */
	oidc_debug(r, "incoming request: \"%s?%s\", ap_is_initial_req(r)=%d", r->parsed_uri.path, r->args,
		   ap_is_initial_req(r));

	if (oidc_enabled(r) == FALSE) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHTYPE_DECLINED);
		return DECLINED;
	}

	oidc_util_set_trace_parent(r, c, NULL);

	OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHTYPE_MOD_AUTH_OPENIDC);

	/* see if we've configured OpenID Connect user authentication for this request */
	if (_oidc_strnatcasecmp(ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_CONNECT) == 0) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHTYPE_OPENID_CONNECT);
		r->ap_auth_type = apr_pstrdup(r->pool, ap_auth_type(r));
		rv = oidc_check_userid_openidc(r, c);

		/* see if we've configured OAuth 2.0 access control for this request */
	} else if (_oidc_strnatcasecmp(ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHTYPE_OAUTH20);
		r->ap_auth_type = apr_pstrdup(r->pool, ap_auth_type(r));
		rv = oidc_oauth_check_userid(r, c, NULL);

		/* see if we've configured "mixed mode" for this request */
	} else if (_oidc_strnatcasecmp(ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_BOTH) == 0) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHTYPE_AUTH_OPENIDC);
		rv = oidc_check_mixed_userid_oauth(r, c);
	}

	return rv;
}

/*
 * check of mod_auth_openidc needs to handle this request
 */
apr_byte_t oidc_enabled(request_rec *r) {
	if (ap_auth_type(r) == NULL)
		return FALSE;

	if (_oidc_strnatcasecmp((const char *)ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_CONNECT) == 0)
		return TRUE;

	if (_oidc_strnatcasecmp((const char *)ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0)
		return TRUE;

	if (_oidc_strnatcasecmp((const char *)ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_BOTH) == 0)
		return TRUE;

	return FALSE;
}

/*
 * report a config error
 */
static int oidc_check_config_error(server_rec *s, const char *config_str) {
	oidc_serror(s, "mandatory parameter '%s' is not set", config_str);
	return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * check the config required for the OpenID Connect RP role
 */
static int oidc_check_config_openid_openidc(server_rec *s, oidc_cfg_t *c) {

	apr_uri_t r_uri;
	apr_byte_t redirect_uri_is_relative;

	if ((oidc_cfg_metadata_dir_get(c) == NULL) &&
	    (oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)) == NULL) &&
	    (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)) == NULL)) {
		oidc_serror(s, "one of '" OIDCProviderIssuer "', '" OIDCProviderMetadataURL "' or '" OIDCMetadataDir
			       "' must be set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (oidc_cfg_redirect_uri_get(c) == NULL)
		return oidc_check_config_error(s, OIDCRedirectURI);
	redirect_uri_is_relative = (oidc_cfg_redirect_uri_get(c)[0] == OIDC_CHAR_FORWARD_SLASH);

	if (oidc_cfg_crypto_passphrase_secret1_get(c) == NULL)
		return oidc_check_config_error(s, OIDCCryptoPassphrase);

	if (oidc_cfg_metadata_dir_get(c) == NULL) {
		if (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)) == NULL) {
			if (oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)) == NULL)
				return oidc_check_config_error(s, OIDCProviderIssuer);
			if (oidc_cfg_provider_authorization_endpoint_url_get(oidc_cfg_provider_get(c)) == NULL)
				return oidc_check_config_error(s, OIDCProviderAuthorizationEndpoint);
		} else {
			apr_uri_parse(s->process->pconf, oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)),
				      &r_uri);
			if ((r_uri.scheme == NULL) || (_oidc_strnatcasecmp(r_uri.scheme, "https") != 0)) {
				oidc_swarn(s,
					   "the URL scheme (%s) of the configured " OIDCProviderMetadataURL
					   " SHOULD be \"https\" for security reasons!",
					   r_uri.scheme);
			}
		}
		if (oidc_cfg_provider_client_id_get(oidc_cfg_provider_get(c)) == NULL)
			return oidc_check_config_error(s, OIDCClientID);
	} else {
		if (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)) != NULL) {
			oidc_serror(s,
				    "only one of '" OIDCProviderMetadataURL "' or '" OIDCMetadataDir "' should be set");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	apr_uri_parse(s->process->pconf, oidc_cfg_redirect_uri_get(c), &r_uri);
	if (!redirect_uri_is_relative) {
		if (_oidc_strnatcasecmp(r_uri.scheme, "https") != 0) {
			oidc_swarn(s,
				   "the URL scheme (%s) of the configured " OIDCRedirectURI
				   " SHOULD be \"https\" for security reasons (moreover: some Providers may reject "
				   "non-HTTPS URLs)",
				   r_uri.scheme);
		}
	}

	if (oidc_cfg_cookie_domain_get(c) != NULL) {
		if (redirect_uri_is_relative) {
			oidc_swarn(s, "if the configured " OIDCRedirectURI " is relative, " OIDCCookieDomain
				      " SHOULD be empty");
		} else if (!oidc_util_cookie_domain_valid(r_uri.hostname, oidc_cfg_cookie_domain_get(c))) {
			oidc_serror(s,
				    "the domain (%s) configured in " OIDCCookieDomain
				    " does not match the URL hostname (%s) of the configured " OIDCRedirectURI
				    " (%s): setting \"state\" and \"session\" cookies will not work!",
				    oidc_cfg_cookie_domain_get(c), r_uri.hostname, oidc_cfg_redirect_uri_get(c));
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	if (oidc_proto_profile_dpop_mode_get(oidc_cfg_provider_get(c)) != OIDC_DPOP_MODE_OFF) {
		if (oidc_util_key_list_first(oidc_cfg_private_keys_get(c), -1, OIDC_JOSE_JWK_SIG_STR) == NULL) {
			oidc_serror(s, "'" OIDCDPoPMode "' is configured but the required signing keys have not been "
				       "provided in '" OIDCPrivateKeyFiles "'/'" OIDCPublicKeyFiles "'");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	return OK;
}

/*
 * check the config required for the OAuth 2.0 RS role
 */
static int oidc_check_config_oauth(server_rec *s, oidc_cfg_t *c) {

	apr_uri_t r_uri;

	oidc_swarn(s, "The OAuth 2.0 Resource Server functionality is deprecated and superseded by a new module, see: "
		      "https://github.com/OpenIDC/mod_oauth2!");

	if (oidc_cfg_oauth_metadata_url_get(c) != NULL) {
		apr_uri_parse(s->process->pconf, oidc_cfg_oauth_metadata_url_get(c), &r_uri);
		if ((r_uri.scheme == NULL) || (_oidc_strnatcasecmp(r_uri.scheme, "https") != 0)) {
			oidc_swarn(s,
				   "the URL scheme (%s) of the configured " OIDCOAuthServerMetadataURL
				   " SHOULD be \"https\" for security reasons!",
				   r_uri.scheme);
		}
		return OK;
	}

	if (oidc_cfg_oauth_introspection_endpoint_url_get(c) == NULL) {

		if ((oidc_cfg_oauth_verify_jwks_uri_get(c) == NULL) &&
		    (oidc_cfg_oauth_verify_public_keys_get(c) == NULL) &&
		    (oidc_cfg_oauth_verify_shared_keys_get(c) == NULL)) {
			oidc_serror(s, "one of '" OIDCOAuthServerMetadataURL "', '" OIDCOAuthIntrospectionEndpoint
				       "', '" OIDCOAuthVerifyJwksUri "', '" OIDCOAuthVerifySharedKeys
				       "' or '" OIDCOAuthVerifyCertFiles "' must be set");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

	} else if ((oidc_cfg_oauth_verify_jwks_uri_get(c) != NULL) ||
		   (oidc_cfg_oauth_verify_public_keys_get(c) != NULL) ||
		   (oidc_cfg_oauth_verify_shared_keys_get(c) != NULL)) {
		oidc_serror(s, "only '" OIDCOAuthIntrospectionEndpoint
			       "' OR one (or more) out of ('" OIDCOAuthVerifyJwksUri "', '" OIDCOAuthVerifySharedKeys
			       "' or '" OIDCOAuthVerifyCertFiles "') must be set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((oidc_cfg_cache_encrypt_get(c) == 1) && (oidc_cfg_crypto_passphrase_secret1_get(c) == NULL))
		return oidc_check_config_error(s, OIDCCryptoPassphrase);

	return OK;
}

/*
 * check the config of a vhost
 */
static int oidc_config_check_vhost_config(apr_pool_t *pool, server_rec *s) {
	oidc_cfg_t *cfg = ap_get_module_config(s->module_config, &auth_openidc_module);

	oidc_sdebug(s, "enter");

	if ((oidc_cfg_metadata_dir_get(cfg) != NULL) ||
	    (oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(cfg)) != NULL) ||
	    (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(cfg)) != NULL)) {
		if (oidc_check_config_openid_openidc(s, cfg) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((oidc_cfg_oauth_metadata_url_get(cfg) != NULL) || (oidc_cfg_oauth_client_id_get(cfg) != NULL) ||
	    (oidc_cfg_oauth_client_secret_get(cfg) != NULL) ||
	    (oidc_cfg_oauth_introspection_endpoint_url_get(cfg) != NULL) ||
	    (oidc_cfg_oauth_verify_jwks_uri_get(cfg) != NULL) || (oidc_cfg_oauth_verify_public_keys_get(cfg) != NULL) ||
	    (oidc_cfg_oauth_verify_shared_keys_get(cfg) != NULL)) {
		if (oidc_check_config_oauth(s, cfg) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * check the config of a merged vhost
 */
static int oidc_config_check_merged_vhost_configs(apr_pool_t *pool, server_rec *s) {
	int status = OK;
	while (s != NULL && status == OK) {
		oidc_cfg_t *cfg = ap_get_module_config(s->module_config, &auth_openidc_module);
		if (oidc_cfg_merged_get(cfg)) {
			status = oidc_config_check_vhost_config(pool, s);
		}
		s = s->next;
	}
	return status;
}

/*
 * check if any merged vhost configs exist
 */
static int oidc_config_merged_vhost_configs_exist(server_rec *s) {
	while (s != NULL) {
		oidc_cfg_t *cfg = ap_get_module_config(s->module_config, &auth_openidc_module);
		if (oidc_cfg_merged_get(cfg)) {
			return TRUE;
		}
		s = s->next;
	}
	return FALSE;
}

/*
 * SSL initialization magic copied from mod_auth_cas
 */
#if ((OPENSSL_VERSION_NUMBER < 0x10100000) && defined(OPENSSL_THREADS) && APR_HAS_THREADS)

static apr_thread_mutex_t **ssl_locks;
static int ssl_num_locks;

static void oidc_ssl_locking_callback(int mode, int type, const char *file, int line) {
	if (type < ssl_num_locks) {
		if (mode & CRYPTO_LOCK)
			apr_thread_mutex_lock(ssl_locks[type]);
		else
			apr_thread_mutex_unlock(ssl_locks[type]);
	}
}

#ifdef OPENSSL_NO_THREADID
static unsigned long oidc_ssl_id_callback(void) {
	return (unsigned long)apr_os_thread_current();
}
#else
static void oidc_ssl_id_callback(CRYPTO_THREADID *id) {
	CRYPTO_THREADID_set_numeric(id, (unsigned long)apr_os_thread_current());
}
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */

/*
 * cleanup resources allocated in a child process
 */
static apr_status_t oidc_cleanup_child(void *data) {
	server_rec *sp = (server_rec *)data;
	while (sp != NULL) {
		oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(sp->module_config, &auth_openidc_module);
		oidc_cfg_cleanup_child(cfg, sp);
		sp = sp->next;
	}

	return APR_SUCCESS;
}

/*
 * cleanup resources allocated in a parent process
 */
static apr_status_t oidc_cleanup_parent(void *data) {

	oidc_cleanup_child(data);

#if ((OPENSSL_VERSION_NUMBER < 0x10100000) && defined(OPENSSL_THREADS) && APR_HAS_THREADS)
	if (CRYPTO_get_locking_callback() == oidc_ssl_locking_callback)
		CRYPTO_set_locking_callback(NULL);
#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_id_callback() == oidc_ssl_id_callback)
		CRYPTO_set_id_callback(NULL);
#else
	if (CRYPTO_THREADID_get_callback() == oidc_ssl_id_callback)
		CRYPTO_THREADID_set_callback(NULL);
#endif /* OPENSSL_NO_THREADID */

#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000) && defined (OPENSSL_THREADS) && APR_HAS_THREADS */

	EVP_cleanup();
	oidc_http_cleanup();

	ap_log_error(APLOG_MARK, APLOG_INFO, 0, (server_rec *)data, "%s - shutdown", NAMEVERSION);

	return APR_SUCCESS;
}

/*
 * handler that is called (twice) after the configuration phase; check if everything is OK
 */
static int oidc_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s) {
	const char *userdata_key = "oidc_post_config";
	void *data = NULL;

	/* Since the post_config hook is invoked twice (once
	 * for 'sanity checking' of the config and once for
	 * the actual server launch, we have to use a hack
	 * to not run twice
	 */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (data == NULL) {
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

#ifdef USE_MEMCACHE
#define _OIDC_USE_MEMCACHE "yes"
#else
#define _OIDC_USE_MEMCACHE "no"
#endif

#ifdef USE_LIBHIREDIS
#define _OIDC_USE_REDIS "yes"
#else
#define _OIDC_USE_REDIS "no"
#endif

#ifdef USE_LIBJQ
#define _OIDC_USE_JQ "yes"
#else
#define _OIDC_USE_JQ "no"
#endif

	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
		     "%s - init - cjose %s, %s, EC=%s, GCM=%s, Memcache=%s, Redis=%s, JQ=%s", NAMEVERSION,
		     cjose_version(), oidc_util_openssl_version(s->process->pool), OIDC_JOSE_EC_SUPPORT ? "yes" : "no",
		     OIDC_JOSE_GCM_SUPPORT ? "yes" : "no", _OIDC_USE_MEMCACHE, _OIDC_USE_REDIS, _OIDC_USE_JQ);

	oidc_http_init();

#if ((OPENSSL_VERSION_NUMBER < 0x10100000) && defined(OPENSSL_THREADS) && APR_HAS_THREADS)
	ssl_num_locks = CRYPTO_num_locks();
	ssl_locks = apr_pcalloc(s->process->pool, ssl_num_locks * sizeof(*ssl_locks));

	int i;
	for (i = 0; i < ssl_num_locks; i++)
		apr_thread_mutex_create(&(ssl_locks[i]), APR_THREAD_MUTEX_DEFAULT, s->process->pool);

#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_locking_callback() == NULL && CRYPTO_get_id_callback() == NULL) {
		CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
		CRYPTO_set_id_callback(oidc_ssl_id_callback);
	}
#else
	if (CRYPTO_get_locking_callback() == NULL && CRYPTO_THREADID_get_callback() == NULL) {
		CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
		CRYPTO_THREADID_set_callback(oidc_ssl_id_callback);
	}
#endif /* OPENSSL_NO_THREADID */

#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000) && defined (OPENSSL_THREADS) && APR_HAS_THREADS */

	apr_pool_cleanup_register(pool, s, oidc_cleanup_parent, apr_pool_cleanup_null);

	server_rec *sp = s;
	while (sp != NULL) {
		oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(sp->module_config, &auth_openidc_module);
		if (oidc_cfg_post_config(cfg, sp) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
		sp = sp->next;
	}

	/*
	 * Apache has a base vhost that true vhosts derive from.
	 * There are two startup scenarios:
	 *
	 * 1. Only the base vhost contains OIDC settings.
	 *    No server configs have been merged.
	 *    Only the base vhost needs to be checked.
	 *
	 * 2. The base vhost contains zero or more OIDC settings.
	 *    One or more vhosts override these.
	 *    These vhosts have a merged config.
	 *    All merged configs need to be checked.
	 */
	if (!oidc_config_merged_vhost_configs_exist(s)) {
		/* nothing merged, only check the base vhost */
		return oidc_config_check_vhost_config(pool, s);
	}
	return oidc_config_check_merged_vhost_configs(pool, s);
}

#if HAVE_APACHE_24

/*
 * parse an Apache expression in the configured require value
 */
static const char *oidc_parse_config(cmd_parms *cmd, const char *require_line, const void **parsed_require_line) {
	const char *expr_err = NULL;
	ap_expr_info_t *expr;

	expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT, &expr_err, NULL);

	if (expr_err)
		return apr_pstrcat(cmd->temp_pool, "Cannot parse expression in require line: ", expr_err, NULL);

	*parsed_require_line = expr;

	return NULL;
}

static const authz_provider oidc_authz_claim_provider = {
    &oidc_authz_24_checker_claim,
    &oidc_parse_config,
};
#ifdef USE_LIBJQ
static const authz_provider oidc_authz_claims_expr_provider = {
    &oidc_authz_24_checker_claims_expr,
    NULL,
};
#endif

#endif

/*
 * initialize cache context in child process if required
 */
static void oidc_child_init(apr_pool_t *p, server_rec *s) {
	server_rec *sp = s;
	while (sp != NULL) {
		oidc_cfg_t *cfg = (oidc_cfg_t *)ap_get_module_config(sp->module_config, &auth_openidc_module);
		oidc_cfg_child_init(p, cfg, sp);
		sp = sp->next;
	}
	/*
	 * NB: don't pass oidc_cleanup_child as the child cleanup routine parameter
	 *     because that does not actually get called upon child cleanup...
	 */
	apr_pool_cleanup_register(p, s, oidc_cleanup_child, apr_pool_cleanup_null);
}

static const char oidcFilterName[] = "oidc_filter_in_filter";

/*
 * add filter for inserting POST data
 */
static void oidc_filter_in_insert_filter(request_rec *r) {

	if (oidc_enabled(r) == FALSE)
		return;

	if (ap_is_initial_req(r) == 0)
		return;

	apr_table_t *userdata_post_params = NULL;
	apr_pool_userdata_get((void **)&userdata_post_params, OIDC_USERDATA_POST_PARAMS_KEY, r->pool);
	if (userdata_post_params == NULL)
		return;

	ap_add_input_filter(oidcFilterName, NULL, r, r->connection);
}

typedef struct oidc_filter_in_context {
	apr_bucket_brigade *pbbTmp;
	apr_size_t nbytes;
} oidc_filter_in_context;

/*
 * execute filter for inserting POST data
 */
static apr_status_t oidc_filter_in_filter(ap_filter_t *f, apr_bucket_brigade *brigade, ap_input_mode_t mode,
					  apr_read_type_e block, apr_off_t nbytes) {
	oidc_filter_in_context *ctx = NULL;
	apr_bucket *b_in = NULL, *b_out = NULL;
	char *buf = NULL;
	apr_table_t *userdata_post_params = NULL;
	apr_status_t rc = APR_SUCCESS;

	if (!(ctx = f->ctx)) {
		f->ctx = ctx = apr_palloc(f->r->pool, sizeof *ctx);
		ctx->pbbTmp = apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
		ctx->nbytes = 0;
	}

	if (APR_BRIGADE_EMPTY(ctx->pbbTmp)) {
		rc = ap_get_brigade(f->next, ctx->pbbTmp, mode, block, nbytes);

		if (mode == AP_MODE_EATCRLF || rc != APR_SUCCESS)
			return rc;
	}

	while (!APR_BRIGADE_EMPTY(ctx->pbbTmp)) {

		b_in = APR_BRIGADE_FIRST(ctx->pbbTmp);

		if (APR_BUCKET_IS_EOS(b_in)) {

			APR_BUCKET_REMOVE(b_in);

			apr_pool_userdata_get((void **)&userdata_post_params, OIDC_USERDATA_POST_PARAMS_KEY,
					      f->r->pool);

			if (userdata_post_params != NULL) {
				buf = apr_psprintf(f->r->pool, "%s%s", ctx->nbytes > 0 ? "&" : "",
						   oidc_http_form_encoded_data(f->r, userdata_post_params));
				b_out =
				    apr_bucket_heap_create(buf, _oidc_strlen(buf), 0, f->r->connection->bucket_alloc);

				APR_BRIGADE_INSERT_TAIL(brigade, b_out);

				ctx->nbytes += _oidc_strlen(buf);

				if (oidc_http_hdr_in_content_length_get(f->r) != NULL)
					oidc_http_hdr_in_set(f->r, OIDC_HTTP_HDR_CONTENT_LENGTH,
							     apr_psprintf(f->r->pool, "%ld", (long)ctx->nbytes));

				apr_pool_userdata_set(NULL, OIDC_USERDATA_POST_PARAMS_KEY, NULL, f->r->pool);
			}

			APR_BRIGADE_INSERT_TAIL(brigade, b_in);

			break;
		}

		APR_BUCKET_REMOVE(b_in);
		APR_BRIGADE_INSERT_TAIL(brigade, b_in);
		ctx->nbytes += b_in->length;
	}

	return rc;
}

/*
 * register our authentication and authorization functions
 */
static void oidc_register_hooks(apr_pool_t *pool) {
	oidc_pre_config_init();
	ap_hook_post_config(oidc_post_config, NULL, NULL, APR_HOOK_LAST);
	ap_hook_child_init(oidc_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_fixups(oidc_fixups, NULL, NULL, APR_HOOK_MIDDLE);
	static const char *const proxySucc[] = {"mod_proxy.c", NULL};
	ap_hook_handler(oidc_content_handler, NULL, proxySucc, APR_HOOK_FIRST);
	ap_hook_insert_filter(oidc_filter_in_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
	ap_register_input_filter(oidcFilterName, oidc_filter_in_filter, NULL, AP_FTYPE_RESOURCE);
#if HAVE_APACHE_24
	ap_hook_check_authn(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP, OIDC_REQUIRE_CLAIM_NAME, "0", &oidc_authz_claim_provider,
				  AP_AUTH_INTERNAL_PER_CONF);
#ifdef USE_LIBJQ
	ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP, OIDC_REQUIRE_CLAIMS_EXPR_NAME, "0",
				  &oidc_authz_claims_expr_provider, AP_AUTH_INTERNAL_PER_CONF);
#endif
#else
	static const char *const authzSucc[] = {"mod_authz_user.c", NULL};
	ap_hook_check_user_id(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(oidc_authz_22_checker, NULL, authzSucc, APR_HOOK_MIDDLE);
#endif
}

// clang-format off
module AP_MODULE_DECLARE_DATA auth_openidc_module = {
    STANDARD20_MODULE_STUFF,
	oidc_cfg_dir_config_create,
	oidc_cfg_dir_config_merge,
	oidc_cfg_server_create,
	oidc_cfg_server_merge,
	oidc_cfg_cmds,
	oidc_register_hooks
};
// clang-format on
