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
#include "handle/handle.h"
#include "metrics.h"

// TODO:
// - sort out oidc_cfg vs. oidc_dir_cfg stuff
// - rigid input checking on discovery responses
// - check self-issued support
// - README.quickstart
// - refresh metadata once-per too? (for non-signing key changes)

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

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
		const int header_matches = (hdr != NULL) && (oidc_strnenvcmp(k, hdr, -1) == 0);

		/*
		 * would this header be interpreted as a mod_auth_openidc attribute? Note
		 * that prefix_len will be zero if no attr_prefix is defined,
		 * so this will always be false. Also note that we do not
		 * scrub headers if the prefix is empty because every header
		 * would match.
		 */
		const int prefix_matches =
		    (k != NULL) && prefix_len && (oidc_strnenvcmp(k, claim_prefix, prefix_len) == 0);

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
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	const char *prefix = oidc_cfg_claim_prefix(r);
	apr_hash_t *hdrs = apr_hash_make(r->pool);

	if (_oidc_strcmp(prefix, "") == 0) {
		if ((cfg->white_listed_claims != NULL) && (apr_hash_count(cfg->white_listed_claims) > 0))
			hdrs = apr_hash_overlay(r->pool, cfg->white_listed_claims, hdrs);
		else
			oidc_warn(r, "both " OIDCClaimPrefix " and " OIDCWhiteListedClaims
				     " are empty: this renders an insecure setup!");
	}

	const char *authn_hdr = oidc_cfg_dir_authn_header(r);
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

	apr_array_header_t *strip = oidc_dir_cfg_strip_cookies(r);

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

#define OIDC_SHA1_LEN 20

/*
 * calculates a hash value based on request fingerprint plus a provided nonce string.
 */
char *oidc_get_browser_state_hash(request_rec *r, oidc_cfg *c, const char *nonce) {

	oidc_debug(r, "enter");

	/* helper to hold to header values */
	const char *value = NULL;
	/* the hash context */
	apr_sha1_ctx_t sha1;

	/* Initialize the hash context */
	apr_sha1_init(&sha1);

	if (c->state_input_headers & OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR) {
		/* get the X-FORWARDED-FOR header value  */
		value = oidc_http_hdr_in_x_forwarded_for_get(r);
		/* if we have a value for this header, concat it to the hash input */
		if (value != NULL)
			apr_sha1_update(&sha1, value, _oidc_strlen(value));
	}

	if (c->state_input_headers & OIDC_STATE_INPUT_HEADERS_USER_AGENT) {
		/* get the USER-AGENT header value  */
		value = oidc_http_hdr_in_user_agent_get(r);
		/* if we have a value for this header, concat it to the hash input */
		if (value != NULL)
			apr_sha1_update(&sha1, value, _oidc_strlen(value));
	}

	/* get the remote client IP address or host name */
	/*
	 int remotehost_is_ip;
	 value = ap_get_remote_host(r->connection, r->per_dir_config,
	 REMOTE_NOLOOKUP, &remotehost_is_ip);
	 apr_sha1_update(&sha1, value, _oidc_strlen(value));
	 */

	/* concat the nonce parameter to the hash input */
	apr_sha1_update(&sha1, nonce, _oidc_strlen(nonce));

	/* finalize the hash input and calculate the resulting hash output */
	unsigned char hash[OIDC_SHA1_LEN];
	apr_sha1_final(hash, &sha1);

	/* base64url-encode the resulting hash and return it */
	char *result = NULL;
	oidc_base64url_encode(r, &result, (const char *)hash, OIDC_SHA1_LEN, TRUE);
	return result;
}

/*
 * return the name for the state cookie
 */
char *oidc_get_state_cookie_name(request_rec *r, const char *state) {
	return apr_psprintf(r->pool, "%s%s", oidc_cfg_dir_state_cookie_prefix(r), state);
}

/*
 * check if s_json is valid provider metadata
 */
static apr_byte_t oidc_provider_validate_metadata_str(request_rec *r, oidc_cfg *c, const char *s_json,
						      json_t **j_provider, apr_byte_t decode_only) {

	if (oidc_util_decode_json_object(r, s_json, j_provider) == FALSE)
		return FALSE;

	if (decode_only == TRUE)
		return TRUE;

	/* check to see if it is valid metadata */
	if (oidc_metadata_provider_is_valid(r, c, *j_provider, NULL) == FALSE) {
		oidc_warn(r, "cache corruption detected: invalid metadata from url: %s", c->provider.metadata_url);
		json_decref(*j_provider);
		return FALSE;
	}

	return TRUE;
}

/*
 * return the static provider configuration, i.e. from a metadata URL or configuration primitives
 */
apr_byte_t oidc_provider_static_config(request_rec *r, oidc_cfg *c, oidc_provider_t **provider) {

	json_t *j_provider = NULL;
	char *s_json = NULL;

	/* see if we should configure a static provider based on external (cached) metadata */
	if ((c->metadata_dir != NULL) || (c->provider.metadata_url == NULL)) {
		*provider = &c->provider;
		return TRUE;
	}

	oidc_cache_get_provider(r, c->provider.metadata_url, &s_json);

	if (s_json != NULL)
		oidc_provider_validate_metadata_str(r, c, s_json, &j_provider, TRUE);

	if (j_provider == NULL) {

		if (oidc_metadata_provider_retrieve(r, c, NULL, c->provider.metadata_url, &j_provider, &s_json) ==
		    FALSE) {
			oidc_error(r, "could not retrieve metadata from url: %s", c->provider.metadata_url);
			return FALSE;
		}
		json_decref(j_provider);

		if (oidc_provider_validate_metadata_str(r, c, s_json, &j_provider, FALSE) == FALSE)
			return FALSE;

		oidc_cache_set_provider(r, c->provider.metadata_url, s_json,
					apr_time_now() +
					    apr_time_from_sec(c->provider_metadata_refresh_interval <= 0
								  ? OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT
								  : c->provider_metadata_refresh_interval));
	}

	*provider = oidc_cfg_provider_copy(r->pool, &c->provider);

	if (oidc_metadata_provider_parse(r, c, j_provider, *provider) == FALSE) {
		oidc_error(r, "could not parse metadata from url: %s", c->provider.metadata_url);
		json_decref(j_provider);
		return FALSE;
	}

	json_decref(j_provider);

	return TRUE;
}

/*
 * return the oidc_provider_t struct for the specified issuer
 */
oidc_provider_t *oidc_get_provider_for_issuer(request_rec *r, oidc_cfg *c, const char *issuer,
					      apr_byte_t allow_discovery) {

	/* by default we'll assume that we're dealing with a single statically configured OP */
	oidc_provider_t *provider = NULL;
	if (oidc_provider_static_config(r, c, &provider) == FALSE)
		return NULL;

	/* unless a metadata directory was configured, so we'll try and get the provider settings from there */
	if (c->metadata_dir != NULL) {

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
const char *oidc_original_request_method(request_rec *r, oidc_cfg *cfg, apr_byte_t handle_discovery_response) {
	const char *method = OIDC_METHOD_GET;

	char *m = NULL;
	if ((handle_discovery_response == TRUE) && (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, cfg))) &&
	    (oidc_is_discovery_response(r, cfg))) {
		oidc_http_request_parameter_get(r, OIDC_DISC_RM_PARAM, &m);
		if (m != NULL)
			method = apr_pstrdup(r->pool, m);
	} else {

		/*
		 * if POST preserve is not enabled for this location, there's no point in preserving
		 * the method either which would result in POSTing empty data on return;
		 * so we revert to legacy behavior
		 */
		if (oidc_cfg_dir_preserve_post(r) == 0)
			return OIDC_METHOD_GET;

		const char *content_type = oidc_http_hdr_in_content_type_get(r);
		if ((r->method_number == M_POST) &&
		    (_oidc_strcmp(content_type, OIDC_HTTP_CONTENT_TYPE_FORM_ENCODED) == 0))
			method = OIDC_METHOD_FORM_POST;
	}

	oidc_debug(r, "return: %s", method);

	return method;
}

typedef struct oidc_state_cookies_t {
	char *name;
	apr_time_t timestamp;
	struct oidc_state_cookies_t *next;
} oidc_state_cookies_t;

static int oidc_delete_oldest_state_cookies(request_rec *r, oidc_cfg *c, int number_of_valid_state_cookies,
					    int max_number_of_state_cookies, oidc_state_cookies_t *first) {
	oidc_state_cookies_t *cur = NULL, *prev = NULL, *prev_oldest = NULL, *oldest = NULL;
	while (number_of_valid_state_cookies >= max_number_of_state_cookies) {
		oldest = first;
		prev_oldest = NULL;
		prev = first;
		cur = first ? first->next : NULL;
		while (cur) {
			if ((cur->timestamp < oldest->timestamp)) {
				oldest = cur;
				prev_oldest = prev;
			}
			prev = cur;
			cur = cur->next;
		}
		oidc_warn(r, "deleting oldest state cookie: %s (time until expiry %" APR_TIME_T_FMT " seconds)",
			  oldest->name, apr_time_sec(oldest->timestamp - apr_time_now()));
		oidc_http_set_cookie(r, oldest->name, "", 0, OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r));
		if (prev_oldest)
			prev_oldest->next = oldest->next;
		else
			first = first ? first->next : NULL;
		number_of_valid_state_cookies--;
	}
	return number_of_valid_state_cookies;
}

/*
 * clean state cookies that have expired i.e. for outstanding requests that will never return
 * successfully and return the number of remaining valid cookies/outstanding-requests while
 * doing so
 */
int oidc_clean_expired_state_cookies(request_rec *r, oidc_cfg *c, const char *currentCookieName, int delete_oldest) {
	int number_of_valid_state_cookies = 0;
	oidc_state_cookies_t *first = NULL, *last = NULL;
	char *cookie, *tokenizerCtx = NULL;
	char *cookies = apr_pstrdup(r->pool, oidc_http_hdr_in_cookie_get(r));
	if (cookies != NULL) {
		cookie = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &tokenizerCtx);
		while (cookie != NULL) {
			while (*cookie == OIDC_CHAR_SPACE)
				cookie++;
			if (_oidc_strstr(cookie, oidc_cfg_dir_state_cookie_prefix(r)) == cookie) {
				char *cookieName = cookie;
				while (cookie != NULL && *cookie != OIDC_CHAR_EQUAL)
					cookie++;
				if (*cookie == OIDC_CHAR_EQUAL) {
					*cookie = '\0';
					cookie++;
					if ((currentCookieName == NULL) ||
					    (_oidc_strcmp(cookieName, currentCookieName) != 0)) {
						oidc_proto_state_t *proto_state =
						    oidc_proto_state_from_cookie(r, c, cookie);
						if (proto_state != NULL) {
							json_int_t ts = oidc_proto_state_get_timestamp(proto_state);
							if (apr_time_now() > ts + apr_time_from_sec(c->state_timeout)) {
								oidc_warn(
								    r, "state (%s) has expired (original_url=%s)",
								    cookieName,
								    oidc_proto_state_get_original_url(proto_state));
								oidc_http_set_cookie(
								    r, cookieName, "", 0,
								    OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r));
							} else {
								if (first == NULL) {
									first = apr_pcalloc(
									    r->pool, sizeof(oidc_state_cookies_t));
									last = first;
								} else {
									last->next = apr_pcalloc(
									    r->pool, sizeof(oidc_state_cookies_t));
									last = last->next;
								}
								last->name = cookieName;
								last->timestamp = ts;
								last->next = NULL;
								number_of_valid_state_cookies++;
							}
							oidc_proto_state_destroy(proto_state);
						} else {
							oidc_warn(
							    r,
							    "state cookie could not be retrieved/decoded, deleting: %s",
							    cookieName);
							oidc_http_set_cookie(r, cookieName, "", 0,
									     OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r));
						}
					}
				}
			}
			cookie = apr_strtok(NULL, OIDC_STR_SEMI_COLON, &tokenizerCtx);
		}
	}

	if (delete_oldest > 0)
		number_of_valid_state_cookies = oidc_delete_oldest_state_cookies(r, c, number_of_valid_state_cookies,
										 c->max_number_of_state_cookies, first);

	return number_of_valid_state_cookies;
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
static apr_byte_t oidc_set_app_claims(request_rec *r, const oidc_cfg *const cfg, const char *s_claims) {

	json_t *j_claims = NULL;

	apr_byte_t pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	apr_byte_t pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);

	// optimize performance when `OIDCPassClaimsAs none` is set
	if ((pass_headers == FALSE) && (pass_envvars == FALSE))
		return TRUE;

	/* decode the string-encoded attributes in to a JSON structure */
	if (s_claims != NULL) {
		if (oidc_util_decode_json_object(r, s_claims, &j_claims) == FALSE)
			return FALSE;
	}

	/* set the resolved claims a HTTP headers for the application */
	if (j_claims != NULL) {
		oidc_util_set_app_infos(r, j_claims, oidc_cfg_claim_prefix(r), cfg->claim_delimiter, pass_headers,
					pass_envvars, oidc_cfg_dir_pass_info_encoding(r));

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
static int oidc_handle_unauthenticated_user(request_rec *r, oidc_cfg *c) {

	/* see if we've configured OIDCUnAuthAction for this path */
	switch (oidc_dir_cfg_unauth_action(r)) {
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
		if ((oidc_dir_cfg_unauth_expr_is_set(r) == FALSE) && (oidc_is_auth_capable_request(r) == FALSE))
			return HTTP_UNAUTHORIZED;
	}

	/*
	 * else: no session (regardless of whether it is main or sub-request),
	 * and we need to authenticate the user
	 */
	return oidc_request_authenticate_user(r, c, NULL, oidc_get_current_url(r, c->x_forwarded_headers), NULL, NULL,
					      NULL, oidc_dir_cfg_path_auth_request_params(r),
					      oidc_dir_cfg_path_scope(r));
}

/*
 * check if maximum session duration was exceeded
 */
static apr_byte_t oidc_check_max_session_duration(request_rec *r, oidc_cfg *cfg, oidc_session_t *session, int *rc) {

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
static apr_byte_t oidc_check_cookie_domain(request_rec *r, oidc_cfg *cfg, oidc_session_t *session) {
	const char *c_cookie_domain =
	    cfg->cookie_domain ? cfg->cookie_domain : oidc_get_current_url_host(r, cfg->x_forwarded_headers);
	const char *s_cookie_domain = oidc_session_get_cookie_domain(r, session);
	if ((s_cookie_domain == NULL) || (_oidc_strcmp(c_cookie_domain, s_cookie_domain) != 0)) {
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
apr_byte_t oidc_get_provider_from_session(request_rec *r, oidc_cfg *c, oidc_session_t *session,
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
apr_byte_t oidc_session_pass_tokens(request_rec *r, oidc_cfg *cfg, oidc_session_t *session, apr_byte_t *needs_save) {

	apr_byte_t pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	apr_byte_t pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);
	int pass_hdr_as = oidc_cfg_dir_pass_info_encoding(r);

	/* set the refresh_token in the app headers/variables, if enabled for this location/directory */
	const char *refresh_token = oidc_session_get_refresh_token(r, session);
	if ((oidc_cfg_dir_pass_refresh_token(r) != 0) && (refresh_token != NULL)) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_REFRESH_TOKEN, refresh_token, OIDC_DEFAULT_HEADER_PREFIX,
				       pass_headers, pass_envvars, pass_hdr_as);
	}

	/* set the access_token in the app headers/variables */
	const char *access_token = oidc_session_get_access_token(r, session);
	if ((oidc_cfg_dir_pass_access_token(r) != 0) && access_token != NULL) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN, access_token, OIDC_DEFAULT_HEADER_PREFIX,
				       pass_headers, pass_envvars, pass_hdr_as);
	}

	/* set the expiry timestamp in the app headers/variables */
	const char *access_token_expires = oidc_session_get_access_token_expires2str(r, session);
	if ((oidc_cfg_dir_pass_access_token(r) != 0) && access_token_expires != NULL) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN_EXP, access_token_expires,
				       OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars, pass_hdr_as);
	}

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
	apr_time_t interval = apr_time_from_sec(cfg->session_inactivity_timeout);
	apr_time_t now = apr_time_now();
	apr_time_t slack = interval / 10;
	if (slack > apr_time_from_sec(60))
		slack = apr_time_from_sec(60);
	if (session->expiry - now < interval - slack) {
		session->expiry = now + interval;
		*needs_save = TRUE;
	}

	/* log message about session expiry */
	oidc_log_session_expires(r, "session inactivity timeout", session->expiry);

	return TRUE;
}

#define OIDC_USERINFO_SIGNED_JWT_EXP_DEFAULT 60
#define OIDC_USERINFO_SIGNED_JWT_CACHE_TTL_DEFAULT -1
#define OIDC_USERINFO_SIGNED_JWT_CACHE_TTL_ENVVAR "OIDC_USERINFO_SIGNED_JWT_CACHE_TTL"

static int oidc_userinfo_signed_jwt_cache_ttl(request_rec *r) {
	const char *s_ttl = apr_table_get(r->subprocess_env, OIDC_USERINFO_SIGNED_JWT_CACHE_TTL_ENVVAR);
	return _oidc_str_to_int(s_ttl, OIDC_USERINFO_SIGNED_JWT_CACHE_TTL_DEFAULT);
}

static apr_byte_t oidc_userinfo_create_signed_jwt(request_rec *r, oidc_cfg *cfg, oidc_session_t *session,
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

	jwk = oidc_util_key_list_first(cfg->private_keys, -1, OIDC_JOSE_JWK_SIG_STR);
	// TODO: detect at config time
	if (jwk == NULL) {
		oidc_error(r, "no RSA/EC private signing keys have been configured (in " OIDCPrivateKeyFiles ")");
		goto end;
	}

	jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	if (jwt == NULL)
		goto end;

	jwt->header.kid = apr_pstrdup(r->pool, jwk->kid);

	if (jwk->kty == CJOSE_JWK_KTY_RSA)
		jwt->header.alg = apr_pstrdup(r->pool, CJOSE_HDR_ALG_RS256);
	else if (jwk->kty == CJOSE_JWK_KTY_EC)
		jwt->header.alg = apr_pstrdup(r->pool, CJOSE_HDR_ALG_ES256);
	else {
		oidc_error(r, "no usable RSA/EC signing keys has been configured (in " OIDCPrivateKeyFiles ")");
		goto end;
	}

	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_AUD,
			    json_string(oidc_get_current_url(r, cfg->x_forwarded_headers)));
	json_object_set_new(jwt->payload.value.json, OIDC_CLAIM_ISS, json_string(cfg->provider.issuer));

	oidc_util_decode_json_object(r, s_claims, &json);
	if (json == NULL)
		goto end;
	if (oidc_util_json_merge(r, json, jwt->payload.value.json) == FALSE)
		goto end;
	s_claims = oidc_util_encode_json_object(r, jwt->payload.value.json, JSON_PRESERVE_ORDER | JSON_COMPACT);
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
		oidc_proto_generate_random_string(r, &jti, 16);
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

	if (oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err) == FALSE) {
		oidc_error(r, "oidc_jwt_sign failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	*cser = oidc_jwt_serialize(r->pool, jwt, &err);
	if (*cser == NULL) {
		oidc_error(r, "oidc_jwt_serialize failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	rv = TRUE;

	if (ttl < 0)
		goto end;

	if (ttl == 0) {
		// need to get the cache ttl from the exp claim
		oidc_json_object_get_int(jwt->payload.value.json, OIDC_CLAIM_EXP, &exp, 0);
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

static void oidc_pass_userinfo_as(request_rec *r, oidc_cfg *cfg, oidc_session_t *session, const char *s_claims,
				  apr_byte_t pass_headers, apr_byte_t pass_envvars, int pass_hdr_as) {
	apr_array_header_t *pass_userinfo_as = NULL;
	oidc_pass_user_info_as_t *p = NULL;
	int i = 0;
	char *cser = NULL;

	pass_userinfo_as = oidc_dir_cfg_pass_user_info_as(r);

#ifdef USE_LIBJQ
	s_claims = oidc_util_jq_filter(r, s_claims, oidc_dir_cfg_userinfo_claims_expr(r));
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
					       p->name ? "" : OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars,
					       pass_hdr_as);
			break;

		case OIDC_PASS_USERINFO_AS_JWT:
			if (cfg->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
				/* get the compact serialized JWT from the session */
				const char *s_userinfo_jwt = oidc_session_get_userinfo_jwt(r, session);
				if (s_userinfo_jwt != NULL) {
					/* pass the compact serialized JWT to the app in a header or environment
					 * variable */
					oidc_util_set_app_info(r, p->name ? p->name : OIDC_APP_INFO_USERINFO_JWT,
							       s_userinfo_jwt,
							       p->name ? "" : OIDC_DEFAULT_HEADER_PREFIX, pass_headers,
							       pass_envvars, pass_hdr_as);
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
						       p->name ? "" : OIDC_DEFAULT_HEADER_PREFIX, pass_headers,
						       pass_envvars, pass_hdr_as);
			}
			break;

		default:
			break;
		}
	}
}

/*
 * handle the case where we have identified an existing authentication session for a user
 */
static int oidc_handle_existing_session(request_rec *r, oidc_cfg *cfg, oidc_session_t *session,
					apr_byte_t *needs_save) {

	apr_byte_t rv = FALSE;
	int rc = OK;
	const char *s_claims = NULL;
	const char *s_id_token = NULL;

	oidc_debug(r, "enter");

	/* set the user in the main request for further (incl. sub-request) processing */
	r->user = apr_pstrdup(r->pool, session->remote_user);
	oidc_debug(r, "set remote_user to \"%s\" in existing session \"%s\"", r->user, session->uuid);

	/* get the header name in which the remote user name needs to be passed */
	char *authn_header = oidc_cfg_dir_authn_header(r);
	apr_byte_t pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	apr_byte_t pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);
	int pass_hdr_as = oidc_cfg_dir_pass_info_encoding(r);

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

	/* if needed, refresh the access token */
	rv = oidc_refresh_access_token_before_expiry(r, cfg, session,
						     oidc_cfg_dir_refresh_access_token_before_expiry(r), needs_save);
	if (rv == FALSE) {
		*needs_save = FALSE;
		oidc_debug(r, "dir_action_on_error_refresh: %d", oidc_cfg_dir_action_on_error_refresh(r));
		OIDC_METRICS_COUNTER_INC(r, cfg, OM_SESSION_ERROR_REFRESH_ACCESS_TOKEN);
		if (oidc_cfg_dir_action_on_error_refresh(r) == OIDC_ON_ERROR_LOGOUT) {
			return oidc_logout_request(r, cfg, session, oidc_get_absolute_url(r, cfg, cfg->default_slo_url),
						   FALSE);
		}
		if (oidc_cfg_dir_action_on_error_refresh(r) == OIDC_ON_ERROR_AUTHENTICATE) {
			oidc_session_kill(r, session);
			return oidc_handle_unauthenticated_user(r, cfg);
		}
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* if needed, refresh claims from the user info endpoint */
	rv = oidc_userinfo_refresh_claims(r, cfg, session, needs_save);
	if (rv == FALSE) {
		*needs_save = FALSE;
		oidc_debug(r, "action_on_userinfo_error: %d", cfg->action_on_userinfo_error);
		OIDC_METRICS_COUNTER_INC(r, cfg, OM_SESSION_ERROR_REFRESH_USERINFO);
		if (cfg->action_on_userinfo_error == OIDC_ON_ERROR_LOGOUT) {
			return oidc_logout_request(r, cfg, session, oidc_get_absolute_url(r, cfg, cfg->default_slo_url),
						   FALSE);
		}
		if (cfg->action_on_userinfo_error == OIDC_ON_ERROR_AUTHENTICATE) {
			oidc_session_kill(r, session);
			return oidc_handle_unauthenticated_user(r, cfg);
		}
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* set the user authentication HTTP header if set and required */
	if ((r->user != NULL) && (authn_header != NULL))
		oidc_http_hdr_in_set(r, authn_header, r->user);

	/* copy id_token and claims from session to request state and obtain their values */
	oidc_copy_tokens_to_request_state(r, session, &s_id_token, &s_claims);

	if ((oidc_dir_cfg_pass_id_token_as(r) & OIDC_PASS_IDTOKEN_AS_CLAIMS)) {
		/* set the id_token in the app headers */
		if (oidc_set_app_claims(r, cfg, s_id_token) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((oidc_dir_cfg_pass_id_token_as(r) & OIDC_PASS_IDTOKEN_AS_PAYLOAD)) {
		/* pass the id_token JSON object to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ID_TOKEN_PAYLOAD, s_id_token, OIDC_DEFAULT_HEADER_PREFIX,
				       pass_headers, pass_envvars, pass_hdr_as);
	}

	if ((oidc_dir_cfg_pass_id_token_as(r) & OIDC_PASS_IDTOKEN_AS_SERIALIZED)) {
		/* get the compact serialized JWT from the session */
		s_id_token = oidc_session_get_idtoken(r, session);
		if (s_id_token) {
			/* pass the compact serialized JWT to the app in a header or environment variable */
			oidc_util_set_app_info(r, OIDC_APP_INFO_ID_TOKEN, s_id_token, OIDC_DEFAULT_HEADER_PREFIX,
					       pass_headers, pass_envvars, pass_hdr_as);
		} else {
			oidc_warn(r, "id_token was not found in the session so it cannot be passed on");
		}
	}

	/* pass the at, rt and at expiry to the application, possibly update the session expiry */
	if (oidc_session_pass_tokens(r, cfg, session, needs_save) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	oidc_pass_userinfo_as(r, cfg, session, s_claims, pass_headers, pass_envvars, pass_hdr_as);

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

apr_byte_t oidc_validate_redirect_url(request_rec *r, oidc_cfg *c, const char *redirect_to_url,
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

	if (c->redirect_urls_allowed != NULL) {
		for (hi = apr_hash_first(NULL, c->redirect_urls_allowed); hi; hi = apr_hash_next(hi)) {
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
		c_host = oidc_get_current_url_host(r, c->x_forwarded_headers);

		if (strchr(uri.hostname, ':')) { /* v6 literal */
			url_ipv6_aware = apr_pstrcat(r->pool, "[", uri.hostname, "]", NULL);
		} else {
			url_ipv6_aware = uri.hostname;
		}

		if ((_oidc_strstr(c_host, url_ipv6_aware) == NULL) || (_oidc_strstr(url_ipv6_aware, c_host) == NULL)) {
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
 * handle all requests to the redirect_uri
 */
int oidc_handle_redirect_uri_request(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	apr_byte_t needs_save = FALSE;
	int rc = OK;

	OIDC_METRICS_TIMING_START(r, c);

	if (oidc_proto_is_redirect_authorization_response(r, c)) {

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
	} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_LOGOUT)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_LOGOUT);

		/* handle logout */
		rc = oidc_logout(r, c, session);

		return rc;

	} else if (oidc_proto_is_post_authorization_response(r, c)) {

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

	} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_JWKS)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_JWKS);

		/*
		 * Will be handled in the content handler; avoid:
		 * No authentication done but request not allowed without authentication
		 * by setting r->user
		 */
		r->user = "";

		return OK;

	} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_SESSION)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_SESSION);

		/* handle session management request */
		rc = oidc_session_management(r, c, session);

		return rc;

	} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REFRESH)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_REFRESH);

		/* handle refresh token request */
		rc = oidc_refresh_token_request(r, c, session);

		return rc;

	} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REQUEST_URI)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_REQUEST_URI);

		/* handle request object by reference request */
		rc = oidc_request_uri(r, c);

		return rc;

	} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE);

		/* handle request to invalidate access token cache */
		rc = oidc_revoke_at_cache_remove(r, c);

		return rc;

	} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REVOKE_SESSION)) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_REVOKE_SESSION);

		/* handle request to revoke a user session */
		rc = oidc_revoke_session(r, c);

		return rc;

	} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_INFO)) {

		if (session->remote_user == NULL)
			return HTTP_UNAUTHORIZED;

		OIDC_METRICS_COUNTER_INC(r, c, OM_REDIRECT_URI_REQUEST_INFO);

		// need to establish user/claims for authorization purposes
		rc = oidc_handle_existing_session(r, c, session, &needs_save);

		// retain this session across the authentication hand content handler phases
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
		rc = oidc_proto_javascript_implicit(r, c);

		return rc;
	}

	/* this is not an authorization response or logout request */

	/* check for "error" response */
	if (oidc_http_request_has_parameter(r, OIDC_PROTO_ERROR)) {

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
	    r, c->error_template, "Invalid Request",
	    apr_psprintf(r->pool, "The OpenID Connect callback URL received an invalid request"),
	    HTTP_INTERNAL_SERVER_ERROR);
}

/*
 * main routine: handle OpenID Connect authentication
 */
static int oidc_check_userid_openidc(request_rec *r, oidc_cfg *c) {

	OIDC_METRICS_TIMING_START(r, c);

	if (oidc_get_redirect_uri(r, c) == NULL) {
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
	if (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, c))) {

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
		rc = oidc_handle_existing_session(r, c, session, &needs_save);
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
static int oidc_check_mixed_userid_oauth(request_rec *r, oidc_cfg *c) {

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
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
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

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
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

extern const command_rec oidc_config_cmds[];

// clang-format off

module AP_MODULE_DECLARE_DATA auth_openidc_module = {
    STANDARD20_MODULE_STUFF,
	oidc_create_dir_config,
	oidc_merge_dir_config,
	oidc_create_server_config,
	oidc_merge_server_config,
	oidc_config_cmds,
	oidc_register_hooks
};

// clang-format on
