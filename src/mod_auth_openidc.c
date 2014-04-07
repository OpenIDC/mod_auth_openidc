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
 * Copyright (C) 2013-2014 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * JSON decoding: apr_json.h apr_json_decode.c: https://github.com/moriyoshi/apr-json/
 * AES crypto: http://saju.net.in/code/misc/openssl_aes.c.txt
 * session handling: Apache 2.4 mod_session.c
 * session handling backport: http://contribsoft.caixamagica.pt/browser/internals/2012/apachecc/trunk/mod_session-port/src/util_port_compat.c
 * shared memory caching: mod_auth_mellon
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

#include "apr_hash.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "apr_lib.h"
#include "apr_file_io.h"
#include "apr_sha1.h"
#include "apr_base64.h"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth_openidc.h"

// TODO: use set_remote user claim logic on OAuth 2.0 code path as well

// TODO: documentation:
//       - write a README.quickstart
//       - include AUTHORS and contributions
// TODO: sort out oidc_cfg vs. oidc_dir_cfg stuff
// TODO: rigid input checking on discovery responses and authorization responses

// TODO: use oidc_get_current_url + configured RedirectURIPath to determine the RedirectURI more dynamically
// TODO: support more hybrid flows ("code id_token" (for MS), "code token" etc.)
// TODO: support PS??? and EC??? algorithms
// TODO: override more stuff (eg. client_name, id_token_signed_response_alg) using client metadata

// TODO: do we always want to refresh keys when signature does not validate? (risking DOS attacks, or does the nonce help against that?)
//       do we now still want to refresh jkws once per hour (it helps to reduce the number of failed verifications, at the cost of too-many-downloads overhead)
//       refresh metadata once-per too? (for non-signing key changes)
// TODO: check the Apache 2.4 compilation/#defines

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/*
 * clean any suspicious headers in the HTTP request sent by the user agent
 */
static void oidc_scrub_request_headers(request_rec *r, const char *claim_prefix,
		const char *authn_header) {

	const int prefix_len = claim_prefix ? strlen(claim_prefix) : 0;

	/* get an array representation of the incoming HTTP headers */
	const apr_array_header_t * const h = apr_table_elts(r->headers_in);

	/* table to keep the non-suspicious headers */
	apr_table_t *clean_headers = apr_table_make(r->pool, h->nelts);

	/* loop over the incoming HTTP headers */
	const apr_table_entry_t * const e = (const apr_table_entry_t *) h->elts;
	int i;
	for (i = 0; i < h->nelts; i++) {
		const char * const k = e[i].key;

		/* is this header's name equivalent to the header that mod_auth_openidc would set for the authenticated user? */
		const int authn_header_matches = (k != NULL) && authn_header
				&& (oidc_strnenvcmp(k, authn_header, -1) == 0);

		/*
		 * would this header be interpreted as a mod_auth_openidc attribute? Note
		 * that prefix_len will be zero if no attr_prefix is defined,
		 * so this will always be false. Also note that we do not
		 * scrub headers if the prefix is empty because every header
		 * would match.
		 */
		const int prefix_matches = (k != NULL) && prefix_len
				&& (oidc_strnenvcmp(k, claim_prefix, prefix_len) == 0);

		/* add to the clean_headers if non-suspicious, skip and report otherwise */
		if (!prefix_matches && !authn_header_matches) {
			apr_table_addn(clean_headers, k, e[i].val);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_scrub_request_headers: scrubbed suspicious request header (%s: %.32s)",
					k, e[i].val);
		}
	}

	/* overwrite the incoming headers with the cleaned result */
	r->headers_in = clean_headers;
}

/*
 * calculates a hash value based on request fingerprint plus a provided state string.
 */
static char *oidc_get_browser_state_hash(request_rec *r, const char *state) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_get_browser_state_hash: entering");

	/* helper to hold to header values */
	const char *value = NULL;
	/* the hash context */
	apr_sha1_ctx_t sha1;

	/* Initialize the hash context */
	apr_sha1_init(&sha1);

	/* get the X_FORWARDED_FOR header value  */
	value = (char *) apr_table_get(r->headers_in, "X_FORWARDED_FOR");
	/* if we have a value for this header, concat it to the hash input */
	if (value != NULL)
		apr_sha1_update(&sha1, value, strlen(value));

	/* get the USER_AGENT header value  */
	value = (char *) apr_table_get(r->headers_in, "USER_AGENT");
	/* if we have a value for this header, concat it to the hash input */
	if (value != NULL)
		apr_sha1_update(&sha1, value, strlen(value));

	/* get the remote client IP address or host name */
	int remotehost_is_ip;
	value = ap_get_remote_host(r->connection, r->per_dir_config,
			REMOTE_NOLOOKUP, &remotehost_is_ip);
	/* concat the remote IP address/hostname to the hash input */
	apr_sha1_update(&sha1, value, strlen(value));

	/* concat the state parameter to the hash input */
	apr_sha1_update(&sha1, state, strlen(state));

	/* finalize the hash input and calculate the resulting hash output */
	const int sha1_len = 20;
	unsigned char hash[sha1_len];
	apr_sha1_final(hash, &sha1);

	/* base64 encode the resulting hash and return it */
	char *result = apr_palloc(r->pool, apr_base64_encode_len(sha1_len) + 1);
	apr_base64_encode(result, (const char *) hash, sha1_len);
	return result;
}

/*
 * see if the state that came back from the OP matches what we've stored in the cookie
 */
static int oidc_check_state(request_rec *r, oidc_cfg *c, const char *state,
		char **original_url, char **issuer, char **nonce) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_check_state: entering");

	/* get the state cookie value first */
	char *cookieValue = oidc_get_cookie(r, OIDCStateCookieName);
	if (cookieValue == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_check_state: no \"%s\" state cookie found",
				OIDCStateCookieName);
		return FALSE;
	}

	/* clear state cookie because we don't need it anymore */
	oidc_set_cookie(r, OIDCStateCookieName, "");

	/* decrypt the state obtained from the cookie */
	char *svalue;
	if (oidc_base64url_decode_decrypt_string(r, &svalue, cookieValue) <= 0)
		return FALSE;

	/* context to iterate over the entries in the decrypted state cookie value */
	char *ctx = NULL;

	/* first get the base64-encoded random value */
	*nonce = apr_strtok(svalue, OIDCStateCookieSep, &ctx);
	if (*nonce == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_check_state: no nonce element found in \"%s\" cookie (%s)",
				OIDCStateCookieName, cookieValue);
		return FALSE;
	}

	/* calculate the hash of the browser fingerprint concatenated with the nonce */
	char *calc = oidc_get_browser_state_hash(r, *nonce);

	/* compare the calculated hash with the value provided in the authorization response */
	if (apr_strnatcmp(calc, state) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_check_state: calculated state from cookie does not match state parameter passed back in URL: \"%s\" != \"%s\"",
				state, calc);
		return FALSE;
	}

	/* since we're OK, get the original URL as the next value in the decrypted cookie */
	*original_url = apr_strtok(NULL, OIDCStateCookieSep, &ctx);
	if (*original_url == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_check_state: no separator (%s) found in \"%s\" cookie (%s)",
				OIDCStateCookieSep, OIDCStateCookieName, cookieValue);
		return FALSE;
	}
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_check_state: \"original_url\" restored from cookie: %s",
			*original_url);

	/* thirdly, get the issuer value stored in the cookie */
	*issuer = apr_strtok(NULL, OIDCStateCookieSep, &ctx);
	if (*issuer == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_check_state: no second separator (%s) found in \"%s\" cookie (%s)",
				OIDCStateCookieSep, OIDCStateCookieName, cookieValue);
		return FALSE;
	}
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_check_state: \"issuer\" restored from cookie: %s", *issuer);

	/* lastly, get the timestamp value stored in the cookie */
	char *timestamp = apr_strtok(NULL, OIDCStateCookieSep, &ctx);
	if (timestamp == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_check_state: no third separator (%s) found in \"%s\" cookie (%s)",
				OIDCStateCookieSep, OIDCStateCookieName, cookieValue);
		return FALSE;
	}
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_check_state: \"timestamp\" restored from cookie: %s",
			timestamp);

	apr_time_t then;
	if (sscanf(timestamp, "%" APR_TIME_T_FMT, &then) != 1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_check_state: could not parse timestamp restored from state cookie (%s)",
				timestamp);
		return FALSE;
	}

	apr_time_t now = apr_time_sec(apr_time_now());
	if (now > then + c->state_timeout) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_check_state: state has expired");
		return FALSE;
	}

	/* we've made it */
	return TRUE;
}

/*
 * create a state parameter to be passed in an authorization request to an OP
 * and set a cookie in the browser that is cryptographically bound to that
 */
static char *oidc_create_state_and_set_cookie(request_rec *r, const char *url,
		const char *issuer, const char *nonce) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_create_state_and_set_cookie: entering");

	char *cookieValue = NULL;

	/*
	 * create a cookie consisting of 4 elements:
	 * random value, original URL, issuer and timestamp separated by a defined separator
	 */
	apr_time_t now = apr_time_sec(apr_time_now());
	char *rvalue = apr_psprintf(r->pool, "%s%s%s%s%s%s%" APR_TIME_T_FMT "",
			nonce,
			OIDCStateCookieSep, url, OIDCStateCookieSep, issuer,
			OIDCStateCookieSep, now);

	/* encrypt the resulting value and set it as a cookie */
	oidc_encrypt_base64url_encode_string(r, &cookieValue, rvalue);
	oidc_set_cookie(r, OIDCStateCookieName, cookieValue);

	/* return a hash value that fingerprints the browser concatenated with the random input */
	return oidc_get_browser_state_hash(r, nonce);
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
	apr_pool_userdata_get((void **) &state, OIDC_USERDATA_KEY, r->pool);

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
	apr_table_setn(state, key, value);
}

/*
 * get a name/value pair from the mod_auth_openidc-specific request context
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
const char*oidc_request_state_get(request_rec *r, const char *key) {

	/* get a handle to the global state, which is a table */
	apr_table_t *state = oidc_request_state(r);

	/* return the value from the table */
	return apr_table_get(state, key);
}

/*
 * set an HTTP header to pass information to the application
 */
static void oidc_set_app_header(request_rec *r, const char *s_key,
		const char *s_value, const char *claim_prefix) {

	/* construct the header name, cq. put the prefix in front of a normalized key name */
	const char *s_name = apr_psprintf(r->pool, "%s%s", claim_prefix,
			oidc_normalize_header_name(r, s_key));

	/* do some logging about this event */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_set_app_header: setting header \"%s: %s\"", s_name, s_value);

	/* now set the actual header name/value */
	apr_table_set(r->headers_in, s_name, s_value);
}

/*
 * set the user/claims information from the session in HTTP headers passed on to the application
 */
static void oidc_set_app_headers(request_rec *r,
		const apr_json_value_t *j_attrs, const char *authn_header,
		const char *claim_prefix, const char *claim_delimiter) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_set_app_headers: entering");

	apr_json_value_t *j_value = NULL;
	apr_hash_index_t *hi = NULL;
	const char *s_key = NULL;

	/* set the user authentication HTTP header if set and required */
	if ((r->user != NULL) && (authn_header != NULL))
		apr_table_set(r->headers_in, authn_header, r->user);

	/* if not attributes are set, nothing needs to be done */
	if (j_attrs == NULL) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_set_app_headers: no attributes to set (j_attrs=NULL)");
		return;
	}

	/* loop over the claims in the JSON structure */
	for (hi = apr_hash_first(r->pool, j_attrs->value.object); hi; hi =
			apr_hash_next(hi)) {

		/* get the next key/value entry */
		apr_hash_this(hi, (const void**) &s_key, NULL, (void**) &j_value);

		/* check if it is a single value string */
		if (j_value->type == APR_JSON_STRING) {

			/* set the single string in the application header whose name is based on the key and the prefix */
			oidc_set_app_header(r, s_key, j_value->value.string.p,
					claim_prefix);

		} else if (j_value->type == APR_JSON_BOOLEAN) {

			/* set boolean value in the application header whose name is based on the key and the prefix */
			oidc_set_app_header(r, s_key, j_value->value.boolean ? "1" : "0",
					claim_prefix);

		} else if (j_value->type == APR_JSON_LONG) {

			/* set long value in the application header whose name is based on the key and the prefix */
			oidc_set_app_header(r, s_key,
					apr_psprintf(r->pool, "%ld", j_value->value.lnumber),
					claim_prefix);

		} else if (j_value->type == APR_JSON_DOUBLE) {

			/* set float value in the application header whose name is based on the key and the prefix */
			oidc_set_app_header(r, s_key,
					apr_psprintf(r->pool, "%lf", j_value->value.dnumber),
					claim_prefix);

			/* check if it is a multi-value string */
		} else if (j_value->type == APR_JSON_ARRAY) {

			/* some logging about what we're going to do */
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_set_app_headers: parsing attribute array for key \"%s\" (#nr-of-elems: %d)",
					s_key, j_value->value.array->nelts);

			/* string to hold the concatenated array string values */
			char *s_concat = apr_pstrdup(r->pool, "");
			int i = 0;

			/* loop over the array */
			for (i = 0; i < j_value->value.array->nelts; i++) {

				/* get the current element */
				apr_json_value_t *elem = APR_ARRAY_IDX(j_value->value.array, i,
						apr_json_value_t *);

				/* check if it is a string */
				if (elem->type == APR_JSON_STRING) {

					/* concatenate the string to the s_concat value using the configured separator char */
					// TODO: escape the delimiter in the values (maybe reuse/extract url-formatted code from oidc_session_identity_encode)
					if (apr_strnatcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat,
								claim_delimiter, elem->value.string.p);
					} else {
						s_concat = apr_psprintf(r->pool, "%s",
								elem->value.string.p);
					}

				} else if (elem->type == APR_JSON_BOOLEAN) {

					if (apr_strnatcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat,
								claim_delimiter,
								j_value->value.boolean ? "1" : "0");
					} else {
						s_concat = apr_psprintf(r->pool, "%s",
								j_value->value.boolean ? "1" : "0");
					}

				} else {

					/* don't know how to handle a non-string array element */
					ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
							"oidc_set_app_headers: unhandled in-array JSON object type [%d] for key \"%s\" when parsing claims array elements",
							elem->type, s_key);
				}
			}

			/* set the concatenated string */
			oidc_set_app_header(r, s_key, s_concat, claim_prefix);

		} else {

			/* no string and no array, so unclear how to handle this */
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_set_app_headers: unhandled JSON object type [%d] for key \"%s\" when parsing claims",
					j_value->type, s_key);
		}
	}
}

static apr_byte_t oidc_set_app_claims(request_rec *r,
		const oidc_cfg * const cfg, session_rec *session,
		const char *session_key, const char *authn_header) {

	const char *s_attrs = NULL;
	apr_json_value_t *j_attrs = NULL;

	/* get the string-encoded id_token from the session */
	oidc_session_get(r, session, session_key, &s_attrs);

	/* decode the string-encoded attributes in to a JSON structure */
	if ((s_attrs != NULL)
			&& (apr_json_decode(&j_attrs, s_attrs, strlen(s_attrs), r->pool)
					!= APR_SUCCESS)) {

		/* whoops, attributes have been corrupted */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_handle_existing_session: unable to parse \"%s\" stored in the session, returning internal server error",
				session_key);

		return FALSE;
	}

	if (j_attrs != NULL) {
		oidc_set_app_headers(r, j_attrs, authn_header, cfg->claim_prefix,
				cfg->claim_delimiter);

		/* set the attributes JSON structure in the request state so it is available for authz purposes later on */
		oidc_request_state_set(r, session_key, (const char *) j_attrs);
	}

	return TRUE;
}

/*
 * handle the case where we have identified an existing authentication session for a user
 */
static int oidc_handle_existing_session(request_rec *r,
		const oidc_cfg * const cfg, session_rec *session) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_existing_session: entering");

	/* get a handle to the director config */
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);

	/*
	 * we're going to pass the information that we have to the application,
	 * but first we need to scrub the headers that we're going to use for security reasons
	 */
	if (cfg->scrub_request_headers != 0) {
		oidc_scrub_request_headers(r, cfg->claim_prefix, dir_cfg->authn_header);
	}

	/* set the claims in the app headers + request state */
	if (oidc_set_app_claims(r, cfg, session, OIDC_CLAIMS_SESSION_KEY,
			NULL) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	/* set the id_token in the app headers + request state */
	if (oidc_set_app_claims(r, cfg, session, OIDC_IDTOKEN_SESSION_KEY,
			NULL) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	/* return "user authenticated" status */
	return OK;
}

/*
 * helper function for basic/implicit client flows upon receiving an authorization response:
 * check that it matches the state stored in the browser and return the variables associated
 * with the state, such as original_url and OP oidc_provider_t pointer.
 */
static apr_byte_t oidc_authorization_response_match_state(request_rec *r,
		oidc_cfg *c, const char *state, char **original_url,
		struct oidc_provider_t **provider, char **nonce) {
	char *issuer = NULL;

	/* check the state parameter against what we stored in a cookie */
	if (oidc_check_state(r, c, state, original_url, &issuer, nonce) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_authorization_response_match_state: unable to restore state");
		return FALSE;
	}

	/* by default we'll assume that we're dealing with a single statically configured OP */
	*provider = &c->provider;

	/* unless a metadata directory was configured, so we'll try and get the provider settings from there */
	if (c->metadata_dir != NULL) {

		/* try and get metadata from the metadata directory for the OP that sent this response */
		if ((oidc_metadata_get(r, c, issuer, provider) == FALSE)
				|| (provider == NULL)) {

			// something went wrong here between sending the request and receiving the response
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_authorization_response_match_state: no provider metadata found for provider \"%s\"",
					issuer);
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * helper function for basic/implicit client flows:
 * complete the handling of an authorization response by storing the
 * authenticated user state in the session
 */
static int oidc_authorization_response_finalize(request_rec *r, oidc_cfg *c,
		session_rec *session, const char *id_token, const char *claims,
		char *remoteUser, apr_time_t expires, const char *original_url) {

	/* set the resolved stuff in the session */
	session->remote_user = remoteUser;

	/* expires is the value from the id_token */
	session->expiry = expires;

	/* store the whole contents of the id_token for later reference too */
	oidc_session_set(r, session, OIDC_IDTOKEN_SESSION_KEY, id_token);

	/* see if we've resolved any claims */
	if (claims != NULL) {
		/*
		 * Successfully decoded a set claims from the response so we can store them
		 * (well actually the stringified representation in the response)
		 * in the session context safely now
		 */
		oidc_session_set(r, session, OIDC_CLAIMS_SESSION_KEY, claims);
	}

	/* store the session */
	oidc_session_save(r, session);

	/* not sure whether this is required, but it won't hurt */
	r->user = remoteUser;

	/* now we've authenticated the user so go back to the URL that he originally tried to access */
	apr_table_add(r->headers_out, "Location", original_url);

	/* log the successful response */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_authorization_response_finalize: session created and stored, redirecting to original url: %s",
			original_url);

	/* do the actual redirect to the original URL */
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * handle an OpenID Connect Authorization Response using the Basic Client profile from the OP
 */
static int oidc_handle_basic_authorization_response(request_rec *r, oidc_cfg *c,
		session_rec *session) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_basic_authorization_response: entering");

	/* initialize local variables */
	char *code = NULL, *state = NULL;

	/* by now we're pretty sure the code & state parameters exist */
	oidc_util_get_request_parameter(r, "code", &code);
	oidc_util_get_request_parameter(r, "state", &state);

	/* match the returned state parameter against the state stored in the browser */
	struct oidc_provider_t *provider = NULL;
	char *original_url = NULL;
	char *nonce = NULL;
	if (oidc_authorization_response_match_state(r, c, state, &original_url,
			&provider, &nonce) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	/* now we've got the metadata for the provider that sent the response to us */
	char *access_token = NULL;
	const char *response = NULL;
	char *remoteUser = NULL;
	apr_jwt_t *jwt = NULL;

	/*
	 * resolve the code against the token endpoint of the OP
	 * TODO: now I'm setting the nonce to NULL since google does not allow using a nonce in the "code" flow...
	 */
	nonce = NULL;
	if (oidc_proto_resolve_code(r, c, provider, code, nonce, &remoteUser, &jwt,
			&access_token) == FALSE) {
		/* errors have already been reported */
		return HTTP_UNAUTHORIZED;
	}

	/*
	 * optionally resolve additional claims against the userinfo endpoint
	 * parsed claims are not actually used here but need to be parsed anyway for error checking purposes
	 */
	apr_json_value_t *claims = NULL;
	if (oidc_proto_resolve_userinfo(r, c, provider, access_token, &response,
			&claims) == FALSE) {
		response = NULL;
	}

	/* complete handling of the response by storing stuff in the session and redirecting to the original URL */
	return oidc_authorization_response_finalize(r, c, session,
			jwt->payload.value.str, response, remoteUser, jwt->payload.exp,
			original_url);
}

/*
 * handle an OpenID Connect Authorization Response using the Implicit Client profile from the OP
 */
static int oidc_handle_implicit_authorization_response(request_rec *r,
		oidc_cfg *c, session_rec *session, const char *state,
		const char *id_token, const char *access_token, const char *token_type) {

	/* log what we've received */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_implicit_authorization_response: state = \"%s\", id_token= \"%s\", access_token=\"%s\", token_type=\"%s\"",
			state, id_token, access_token, token_type);

	/* match the returned state parameter against the state stored in the browser */
	struct oidc_provider_t *provider = NULL;
	char *original_url = NULL;
	char *nonce = NULL;
	if (oidc_authorization_response_match_state(r, c, state, &original_url,
			&provider, &nonce) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	/* initialize local variables for the id_token contents */
	char *remoteUser = NULL;
	apr_jwt_t *jwt = NULL;

	/* parse and validate the id_token */
	if (oidc_proto_parse_idtoken(r, c, provider, id_token, nonce, &remoteUser,
			&jwt) != TRUE) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_handle_implicit_authorization_response: could not verify the id_token contents, return HTTP_UNAUTHORIZED");
		return HTTP_UNAUTHORIZED;
	}

	/* strip empty parameters (eg. connect.openid4.us on response on "id_token" flow) */
	if ((access_token != NULL) && (strcmp(access_token, "") == 0))
		access_token = NULL;

	/* assert that the token_type is Bearer before using it */
	if ((token_type != NULL) && (strcmp(token_type, "") != 0)) {
		if (apr_strnatcasecmp(token_type, "Bearer") != 0) {
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
					"oidc_handle_implicit_authorization_response: dropping unsupported (cq. non \"Bearer\") token_type: \"%s\"",
					token_type);
			access_token = NULL;
		}
	}

	const char *s_claims = NULL;
	/*
	 * if we (still) have an access_token, let's use to resolve claims from the user_info endpoint
	 * we don't do anything with the optional expires_in, since we don't cache the access_token or re-use
	 * it in any way after this initial call that should happen right after issuing the access_token
	 * (and it is optional anyway)
	 */
	if (access_token != NULL) {

		/* parsed claims are not actually used here but need to be parsed anyway for error checking purposes */
		apr_json_value_t *claims = NULL;
		if (oidc_proto_resolve_userinfo(r, c, provider, access_token, &s_claims,
				&claims) == FALSE) {
			s_claims = NULL;
		}
	}

	/* complete handling of the response by storing stuff in the session and redirecting to the original URL */
	return oidc_authorization_response_finalize(r, c, session, jwt->payload.value.str,
			s_claims, remoteUser, jwt->payload.exp, original_url);
}

/*
 * handle an OpenID Connect Authorization Response using the fragment(+POST) response_mode with the Implicit Client profile from the OP
 */
static int oidc_handle_implicit_post(request_rec *r, oidc_cfg *c,
		session_rec *session) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_implicit_post: entering");

	/* read the parameters that are POST-ed to us */
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post(r, params) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_handle_implicit_post: something went wrong when reading the POST parameters");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* see if we've got any POST-ed data at all */
	if (apr_is_empty_table(params)) {
		return oidc_util_http_sendstring(r,
				apr_psprintf(r->pool,
						"mod_auth_openidc: you've hit an OpenID Connect callback URL with no parameters; this is an invalid request (you should not open this URL in your browser directly)"),
						HTTP_INTERNAL_SERVER_ERROR);
	}

	/* see if the response is an error response */
	char *error = (char *) apr_table_get(params, "error");
	char *error_description = (char *) apr_table_get(params,
			"error_description");
	if (error != NULL)
		return oidc_util_html_send_error(r, error, error_description, OK);

	/* get the state */
	char *state = (char *) apr_table_get(params, "state");
	if (state == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_handle_implicit_post: no state parameter found in the POST, returning internal server error");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get the id_token */
	char *id_token = (char *) apr_table_get(params, "id_token");
	if (id_token == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_handle_implicit_post: no id_token parameter found in the POST, returning internal server error");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get the (optional) access_token */
	char *access_token = (char *) apr_table_get(params, "access_token");

	/* get the (optional) token_type */
	char *token_type = (char *) apr_table_get(params, "token_type");

	/* do the actual implicit work */
	return oidc_handle_implicit_authorization_response(r, c, session, state,
			id_token, access_token, token_type);
}

/*
 * handle an OpenID Connect Authorization Response using the redirect response_mode with the Implicit Client profile from the OP
 */
static int oidc_handle_implicit_redirect(request_rec *r, oidc_cfg *c,
		session_rec *session) {

	ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
			"oidc_handle_implicit_redirect: handling non-spec-compliant authorization response since the default response_mode when using the Implicit Client flow must be \"fragment\"");

	/* initialize local variables */
	char *state = NULL, *id_token = NULL, *access_token = NULL, *token_type =
			NULL;

	/* by now we're pretty sure the state & id_token parameters exist */
	oidc_util_get_request_parameter(r, "state", &state);
	oidc_util_get_request_parameter(r, "id_token", &id_token);
	oidc_util_get_request_parameter(r, "access_token", &access_token);
	oidc_util_get_request_parameter(r, "token_type", &token_type);

	/* do the actual implicit work */
	return oidc_handle_implicit_authorization_response(r, c, session, state,
			id_token, access_token, token_type);
}

/*
 * present the user with an OP selection screen
 */
static int oidc_discovery(request_rec *r, oidc_cfg *cfg) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_discovery: entering");

	/* obtain the URL we're currently accessing, to be stored in the state/session */
	char *current_url = oidc_get_current_url(r, cfg);

	/* see if there's an external discovery page configured */
	if (cfg->discover_url != NULL) {

		/* yes, assemble the parameters for external discovery */
		char *url = apr_psprintf(r->pool, "%s%s%s=%s&%s=%s", cfg->discover_url,
				strchr(cfg->discover_url, '?') != NULL ? "&" : "?",
						OIDC_DISC_RT_PARAM, oidc_util_escape_string(r, current_url),
						OIDC_DISC_CB_PARAM,
						oidc_util_escape_string(r, cfg->redirect_uri));

		/* log what we're about to do */
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_discovery: redirecting to external discovery page: %s",
				url);

		/* do the actual redirect to an external discovery page */
		apr_table_add(r->headers_out, "Location", url);
		return HTTP_MOVED_TEMPORARILY;
	}

	/* get a list of all providers configured in the metadata directory */
	apr_array_header_t *arr = NULL;
	if (oidc_metadata_list(r, cfg, &arr) == FALSE)
		return oidc_util_http_sendstring(r,
				"mod_auth_openidc: no configured providers found, contact your administrator",
				HTTP_UNAUTHORIZED);

	/* assemble a where-are-you-from IDP discovery HTML page */
	// TODO: yes, we could use some templating here...
	const char *s =
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">"
			"<html>\n"
			"	<head>\n"
			"		<meta http-equiv=\"Content-Type\" content=\"text/html;charset=UTF-8\"/>\n"
			"		<title>OpenID Connect Provider Discovery</title>\n"
			"	</head>\n"
			"	<body>\n"
			"		<center>\n"
			"			<h3>Select your OpenID Connect Identity Provider</h3>\n";

	/* list all configured providers in there */
	int i;
	for (i = 0; i < arr->nelts; i++) {
		const char *issuer = ((const char**) arr->elts)[i];
		// TODO: html escape (especially & character)

		char *display =
				(strstr(issuer, "https://") == NULL) ?
						apr_pstrdup(r->pool, issuer) :
						apr_pstrdup(r->pool, issuer + strlen("https://"));

		/* strip port number */
		//char *p = strstr(display, ":");
		//if (p != NULL) *p = '\0';
		/* point back to the redirect_uri, where the selection is handled, with an IDP selection and return_to URL */
		s = apr_psprintf(r->pool,
				"%s<p><a href=\"%s?%s=%s&amp;%s=%s\">%s</a></p>\n", s,
				cfg->redirect_uri, OIDC_DISC_OP_PARAM,
				oidc_util_escape_string(r, issuer), OIDC_DISC_RT_PARAM,
				oidc_util_escape_string(r, current_url), display);
	}

	/* add an option to enter an account or issuer name for dynamic OP discovery */
	s = apr_psprintf(r->pool, "%s<form method=\"get\" action=\"%s\">\n", s,
			cfg->redirect_uri);
	s = apr_psprintf(r->pool,
			"%s<input type=\"hidden\" name=\"%s\" value=\"%s\"><br>\n", s,
			OIDC_DISC_RT_PARAM, current_url);
	s =
			apr_psprintf(r->pool,
					"%sOr enter your account name (eg. \"mike@seed.gluu.org\", or an IDP identifier (eg. \"mitreid.org\"):<br>\n",
					s);
	s = apr_psprintf(r->pool,
			"%s<p><input type=\"text\" name=\"%s\" value=\"%s\"></p>\n", s,
			OIDC_DISC_OP_PARAM, "");
	s = apr_psprintf(r->pool, "%s<input type=\"submit\" value=\"Submit\">\n",
			s);
	s = apr_psprintf(r->pool, "%s</form>\n", s);

	/* footer */
	s = apr_psprintf(r->pool, "%s"
			"		</center>\n"
			"	</body>\n"
			"</html>\n", s);

	/* now send the HTML contents to the user agent */
	return oidc_util_http_sendstring(r, s, HTTP_UNAUTHORIZED);
}

/*
 * authenticate the user to the selected OP, if the OP is not selected yet perform discovery first
 */
static int oidc_authenticate_user(request_rec *r, oidc_cfg *c,
		oidc_provider_t *provider, const char *original_url) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_authenticate_user: entering");

	if (provider == NULL) {

		// TODO: should we use an explicit redirect to the discovery endpoint (maybe a "discovery" param to the redirect_uri)?
		if (c->metadata_dir != NULL)
			return oidc_discovery(r, c);

		/* we're not using multiple OP's configured in a metadata directory, pick the statically configured OP */
		provider = &c->provider;
	}

	char *nonce = NULL;
	oidc_util_generate_random_base64url_encoded_value(r, 32, &nonce);

	/* create state that restores the context when the authorization response comes in; cryptographically bind it to the browser */
	const char *state = oidc_create_state_and_set_cookie(r, original_url,
			provider->issuer, nonce);

	// TODO: maybe show intermediate/progress screen "redirecting to"

	/* send off to the OpenID Connect Provider */
	return oidc_proto_authorization_request(r, provider, c->redirect_uri, state,
			original_url, nonce);
}

/*
 * find out whether the request is a response from an IDP discovery page
 */
static apr_byte_t oidc_is_discovery_response(request_rec *r, oidc_cfg *cfg) {
	/*
	 * see if this is a call to the configured redirect_uri and
	 * the OIDC_RT_PARAM_NAME parameter is present and
	 * the OIDC_DISC_ACCT_PARAM or OIDC_DISC_OP_PARAM is present
	 */
	return ((oidc_util_request_matches_url(r, cfg->redirect_uri) == TRUE)
			&& oidc_util_request_has_parameter(r, OIDC_DISC_RT_PARAM)
			&& (oidc_util_request_has_parameter(r, OIDC_DISC_OP_PARAM)));
}

/*
 * handle a response from an IDP discovery page
 */
static int oidc_handle_discovery_response(request_rec *r, oidc_cfg *c) {

	/* variables to hold the values (original_url+issuer or original_url+acct) returned in the response */
	char *issuer = NULL, *original_url = NULL;
	oidc_provider_t *provider = NULL;

	oidc_util_get_request_parameter(r, OIDC_DISC_OP_PARAM, &issuer);
	oidc_util_get_request_parameter(r, OIDC_DISC_RT_PARAM, &original_url);

	// TODO: trim issuer/accountname/domain input and do more input validation

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_discovery_response: issuer=\"%s\", original_url=\"%s\"",
			issuer, original_url);

	if ((issuer == NULL) || (original_url == NULL)) {
		return oidc_util_http_sendstring(r,
				"mod_auth_openidc: wherever you came from, it sent you here with the wrong parameters...",
				HTTP_INTERNAL_SERVER_ERROR);
	}

	/* find out if the user entered an account name or selected an OP manually */
	if (strstr(issuer, "@") != NULL) {

		/* got an account name as input, perform OP discovery with that */
		if (oidc_proto_account_based_discovery(r, c, issuer, &issuer) == FALSE) {

			/* something did not work out, show a user facing error */
			return oidc_util_http_sendstring(r,
					"mod_auth_openidc: could not resolve the provided account name to an OpenID Connect provider; check your syntax",
					HTTP_NOT_FOUND);
		}

		/* issuer is set now, so let's continue as planned */

	} else if (strcmp(issuer, "accounts.google.com") != 0) {

		/* allow issuer/domain entries that don't start with https */
		issuer = apr_psprintf(r->pool, "%s",
				((strstr(issuer, "http://") == issuer)
						|| (strstr(issuer, "https://") == issuer)) ?
								issuer : apr_psprintf(r->pool, "https://%s", issuer));
	}

	/* strip trailing '/' */
	int n = strlen(issuer);
	if (issuer[n - 1] == '/')
		issuer[n - 1] = '\0';

	/* try and get metadata from the metadata directories for the selected OP */
	if ((oidc_metadata_get(r, c, issuer, &provider) == TRUE)
			&& (provider != NULL)) {

		/* now we've got a selected OP, send the user there to authenticate */
		return oidc_authenticate_user(r, c, provider, original_url);
	}

	/* something went wrong */
	return oidc_util_http_sendstring(r,
			"mod_auth_openidc: could not find valid provider metadata for the selected OpenID Connect provider; contact the administrator",
			HTTP_NOT_FOUND);
}

/*
 * handle "all other" requests to the redirect_uri
 */
int oidc_handle_redirect_uri_request(request_rec *r, oidc_cfg *c) {
	if (r->args == NULL)
		/* this is a "bare" request to the redirect URI, indicating implicit flow using the fragment response_mode */
		return oidc_proto_javascript_implicit(r, c);

	/* TODO: check for "error" response */
	if (oidc_util_request_has_parameter(r, "error")) {

		char *error = NULL, *descr = NULL;
		oidc_util_get_request_parameter(r, "error", &error);
		oidc_util_get_request_parameter(r, "error_description", &descr);

		return oidc_util_html_send_error(r, error, descr, OK);
	}

	/* something went wrong */
	return oidc_util_http_sendstring(r,
			apr_psprintf(r->pool,
					"mod_auth_openidc: the OpenID Connect callback URL received an invalid request: %s",
					r->args), HTTP_INTERNAL_SERVER_ERROR);
}

/*
 * kill session
 */
int oidc_handle_logout(request_rec *r, session_rec *session) {
	char *url = NULL;

	/* if there's no remote_user then there's no (stored) session to kill */
	if (session->remote_user != NULL) {

		/* remove session state (cq. cache entry and cookie) */
		oidc_session_kill(r, session);
	}

	/* pickup the URL where the user wants to go after logout */
	oidc_util_get_request_parameter(r, "logout", &url);

	/* send him there */
	apr_table_add(r->headers_out, "Location", url);
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * main routine: handle OpenID Connect authentication
 */
static int oidc_check_userid_openidc(request_rec *r, oidc_cfg *c) {

	/* check if this is a sub-request or an initial request */
	if (ap_is_initial_req(r)) {

		/* load the session from the request state; this will be a new "empty" session if no state exists */
		session_rec *session = NULL;
		oidc_session_load(r, &session);

		/* see if this is a logout trigger */
		if ((oidc_util_request_matches_url(r, c->redirect_uri) == TRUE)
				&& (oidc_util_request_has_parameter(r, "logout") == TRUE)) {

			/* handle logout */
			return oidc_handle_logout(r, session);
		}

		/* initial request, first check if we have an existing session */
		if (session->remote_user != NULL) {

			/* set the user in the main request for further (incl. sub-request) processing */
			r->user = (char *) session->remote_user;

			/* this is initial request and we already have a session */
			return oidc_handle_existing_session(r, c, session);

		} else if (oidc_is_discovery_response(r, c)) {

			/* this is response from the OP discovery page */
			return oidc_handle_discovery_response(r, c);

		} else if (oidc_proto_is_basic_authorization_response(r, c)) {

			/* this is an authorization response from the OP using the Basic Client profile */
			return oidc_handle_basic_authorization_response(r, c, session);

		} else if (oidc_proto_is_implicit_post(r, c)) {

			/* this is an authorization response using the fragment(+POST) response_mode with the Implicit Client profile */
			return oidc_handle_implicit_post(r, c, session);

		} else if (oidc_proto_is_implicit_redirect(r, c)) {

			/* this is an authorization response using the redirect response_mode with the Implicit Client profile */
			return oidc_handle_implicit_redirect(r, c, session);

		} else if (oidc_util_request_matches_url(r, c->redirect_uri) == TRUE) {

			/* some other request to the redirect_uri */
			return oidc_handle_redirect_uri_request(r, c);
		}
		/*
		 * else: initial request, we have no session and it is not an authorization or
		 *       discovery response: just hit the default flow for unauthenticated users
		 */
	} else {

		/* not an initial request, try to recycle what we've already established in the main request */
		if (r->main != NULL)
			r->user = r->main->user;
		else if (r->prev != NULL)
			r->user = r->prev->user;

		if (r->user != NULL) {

			/* this is a sub-request and we have a session (headers will have been scrubbed and set already) */
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_check_userid_openid_openidc: recycling user '%s' from initial request for sub-request",
					r->user);

			return OK;
		}
		/*
		 * else: not initial request, but we could not find a session, so:
		 * just hit the default flow for unauthenticated users
		 */
	}

	/* no session (regardless of whether it is main or sub-request), go and authenticate the user */
	return oidc_authenticate_user(r, c, NULL, oidc_get_current_url(r, c));
}

/*
 * generic Apache authentication hook for this module: dispatches to OpenID Connect or OAuth 2.0 specific routines
 */
int oidc_check_user_id(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	/* log some stuff about the incoming HTTP request */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_check_user_id: incoming request: \"%s?%s\", ap_is_initial_req(r)=%d",
			r->parsed_uri.path, r->args, ap_is_initial_req(r));

	/* see if any authentication has been defined at all */
	if (ap_auth_type(r) == NULL)
		return DECLINED;

	/* see if we've configured OpenID Connect user authentication for this request */
	if (apr_strnatcasecmp((const char *) ap_auth_type(r), "openid-connect")
			== 0)
		return oidc_check_userid_openidc(r, c);

	/* see if we've configured OAuth 2.0 access control for this request */
	if (apr_strnatcasecmp((const char *) ap_auth_type(r), "oauth20") == 0)
		return oidc_oauth_check_userid(r, c);

	/* this is not for us but for some other handler */
	return DECLINED;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
/*
 * generic Apache >=2.4 authorization hook for this module
 * handles both OpenID Connect or OAuth 2.0 in the same way, based on the claims stored in the session
 */
authz_status oidc_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args) {

	/* get the set of claims from the request state (they've been set in the authentication part earlier */
	apr_json_value_t *attrs = (apr_json_value_t *)oidc_request_state_get(r, OIDC_CLAIMS_SESSION_KEY);

	/* if no claims, use the id_token itself */
	if (attrs == NULL) attrs = (apr_json_value_t *)oidc_request_state_get(r, OIDC_IDTOKEN_SESSION_KEY);

	/* dispatch to the >=2.4 specific authz routine */
	return oidc_authz_worker24(r, attrs, require_args);
}
#else
/*
 * generic Apache <2.4 authorization hook for this module
 * handles both OpenID Connect and OAuth 2.0 in the same way, based on the claims stored in the request context
 */
int oidc_auth_checker(request_rec *r) {

	/* get the set of claims from the request state (they've been set in the authentication part earlier) */
	apr_json_value_t *attrs = (apr_json_value_t *) oidc_request_state_get(r,
			OIDC_CLAIMS_SESSION_KEY);

	/* if no claims, use the id_token itself */
	if (attrs == NULL)
		attrs = (apr_json_value_t *) oidc_request_state_get(r,
				OIDC_IDTOKEN_SESSION_KEY);

	/* get the Require statements */
	const apr_array_header_t * const reqs_arr = ap_requires(r);

	/* see if we have any */
	const require_line * const reqs =
			reqs_arr ? (require_line *) reqs_arr->elts : NULL;
	if (!reqs_arr) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"No require statements found, "
				"so declining to perform authorization.");
		return DECLINED;
	}

	/* dispatch to the <2.4 specific authz routine */
	return oidc_authz_worker(r, attrs, reqs, reqs_arr->nelts);
}
#endif

extern const command_rec oidc_config_cmds[];

module AP_MODULE_DECLARE_DATA auth_openidc_module = {
		STANDARD20_MODULE_STUFF,
		oidc_create_dir_config,
		oidc_merge_dir_config,
		oidc_create_server_config,
		oidc_merge_server_config,
		oidc_config_cmds,
		oidc_register_hooks
};
