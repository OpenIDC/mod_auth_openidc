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

// TODO: harmonize user facing error handling

// TODO: documentation:
//       - write a README.quickstart
//       - include AUTHORS and contributions
// TODO: sort out oidc_cfg vs. oidc_dir_cfg stuff
// TODO: rigid input checking on discovery responses and authorization responses

// TODO: use oidc_get_current_url + configured RedirectURIPath to determine the RedirectURI more dynamically
// TODO: support EC algorithms
// TODO: override more stuff (eg. client_name) using client metadata

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

typedef struct oidc_authrr_state {
	const char *nonce;
	const char *original_url;
	const char *issuer;
	const char *response_type;
	apr_time_t timestamp;
} oidc_authrr_state;

/*
 * restore the state that was maintained between authorization request and response in an encrypted cookie
 */
static apr_byte_t oidc_restore_authrr_state(request_rec *r, oidc_cfg *c,
		const char *state, oidc_authrr_state **auth_rr_state) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_restore_authrr_state: entering");

	apr_json_value_t *v = NULL;

	/* get the state cookie value first */
	char *cookieValue = oidc_get_cookie(r, OIDCStateCookieName);
	if (cookieValue == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_restore_authrr_state: no \"%s\" state cookie found",
				OIDCStateCookieName);
		return FALSE;
	}

	/* clear state cookie because we don't need it anymore */
	oidc_set_cookie(r, OIDCStateCookieName, "");

	/* decrypt the state obtained from the cookie */
	char *svalue = NULL;
	if (oidc_base64url_decode_decrypt_string(r, &svalue, cookieValue) <= 0)
		return FALSE;

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_restore_authrr_state: restored JSON state cookie value: %s",
			svalue);

	apr_json_value_t *json = NULL;
	/* decode the string in to a JSON structure into value->json */
	if (apr_json_decode(&json, svalue, strlen(svalue), r->pool) != APR_SUCCESS)
		return FALSE;

	*auth_rr_state = apr_pcalloc(r->pool, sizeof(oidc_authrr_state));
	oidc_authrr_state *res = *auth_rr_state;

	/* 1. restore the nonce from the cookie */
	v = apr_hash_get(json->value.object, "nonce", APR_HASH_KEY_STRING);
	res->nonce = apr_pstrdup(r->pool, v->value.string.p);

	/* calculate the hash of the browser fingerprint concatenated with the nonce */
	char *calc = oidc_get_browser_state_hash(r, res->nonce);
	/* compare the calculated hash with the value provided in the authorization response */
	if (apr_strnatcmp(calc, state) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_restore_authrr_state: calculated state from cookie does not match state parameter passed back in URL: \"%s\" != \"%s\"",
				state, calc);
		return FALSE;
	}

	/* 2. since we're OK, get the original URL as the next value in the decrypted cookie */
	v = apr_hash_get(json->value.object, "original_url", APR_HASH_KEY_STRING);
	res->original_url = apr_pstrdup(r->pool, v->value.string.p);

	/* 3. get the issuer value stored in the cookie */
	v = apr_hash_get(json->value.object, "issuer", APR_HASH_KEY_STRING);
	res->issuer = apr_pstrdup(r->pool, v->value.string.p);

	/* 4. get the response_type value stored in the cookie */
	v = apr_hash_get(json->value.object, "response_type", APR_HASH_KEY_STRING);
	res->response_type = apr_pstrdup(r->pool, v->value.string.p);

	/* 5. get the timestamp value stored in the cookie */
	v = apr_hash_get(json->value.object, "timestamp", APR_HASH_KEY_STRING);
	res->timestamp = v->value.lnumber;

	/* check that the timestamp is not beyond the valid interval */
	apr_time_t now = apr_time_sec(apr_time_now());
	if (now > res->timestamp + c->state_timeout) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_restore_authrr_state: state has expired");
		return FALSE;
	}

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_restore_authrr_state: restored state: nonce=\"%s\", original_url=\"%s\", issuer=\"%s\", response_type=\%s\", timestamp=%" APR_TIME_T_FMT,
			res->nonce, res->original_url, res->issuer, res->response_type,
			res->timestamp);

	/* we've made it */
	return TRUE;
}

/*
 * set the state that is maintained between an authorization request and an authorization response
 * in a cookie in the browser that is cryptographically bound to that state
 */
static apr_byte_t oidc_authorization_request_set_cookie(request_rec *r,
		oidc_authrr_state *authz_rr_state) {
	/*
	 * create a cookie consisting of 5 elements:
	 * random value, original URL, issuer, response_type and timestamp
	 * encoded as JSON
	 */
	char *plainText = apr_psprintf(r->pool, "{"
			"\"nonce\": \"%s\","
			"\"original_url\": \"%s\","
			"\"issuer\": \"%s\","
			"\"response_type\": \"%s\","
			"\"timestamp\": %" APR_TIME_T_FMT "}", authz_rr_state->nonce,
			authz_rr_state->original_url, authz_rr_state->issuer,
			authz_rr_state->response_type, authz_rr_state->timestamp);

	/* encrypt the resulting JSON value  */
	char *cookieValue = NULL;
	if (oidc_encrypt_base64url_encode_string(r, &cookieValue, plainText) <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_authorization_request_set_cookie: oidc_encrypt_base64url_encode_string failed");
		return FALSE;
	}

	/* set it as a cookie */
	oidc_set_cookie(r, OIDCStateCookieName, cookieValue);

	return TRUE;
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
				"oidc_set_app_claims: unable to parse \"%s\" stored in the session, returning internal server error",
				session_key);

		return FALSE;
	}

	/* set the resolved claims a HTTP headers for the application */
	if (j_attrs != NULL) {
		oidc_util_set_app_headers(r, j_attrs, authn_header, cfg->claim_prefix,
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
		oidc_session_save(r, session);
	}

	/* return "user authenticated" status */
	return OK;
}

/*
 * helper function for basic/implicit client flows upon receiving an authorization response:
 * check that it matches the state stored in the browser and return the variables associated
 * with the state, such as original_url and OP oidc_provider_t pointer.
 */
static apr_byte_t oidc_authorization_response_match_state(request_rec *r,
		oidc_cfg *c, const char *state, struct oidc_provider_t **provider,
		oidc_authrr_state **auth_rr_state) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_authorization_response_match_state: entering (state=%s)",
			state);

	if ((state == NULL) || (apr_strnatcmp(state, "") == 0)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_authorization_response_match_state: state parameter is not set");
		return FALSE;
	}

	/* check the state parameter against what we stored in a cookie */
	if (oidc_restore_authrr_state(r, c, state, auth_rr_state) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_authorization_response_match_state: unable to restore state");
		return FALSE;
	}

	/* by default we'll assume that we're dealing with a single statically configured OP */
	*provider = &c->provider;

	/* unless a metadata directory was configured, so we'll try and get the provider settings from there */
	if (c->metadata_dir != NULL) {

		/* try and get metadata from the metadata directory for the OP that sent this response */
		if ((oidc_metadata_get(r, c, (*auth_rr_state)->issuer, provider)
				== FALSE) || (provider == NULL)) {

			// something went wrong here between sending the request and receiving the response
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_authorization_response_match_state: no provider metadata found for provider \"%s\"",
					(*auth_rr_state)->issuer);
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * check the required parameters for the various flows on receipt of the authorization response
 */
static apr_byte_t oidc_check_authorization_response_parameters(request_rec *r,
		const char *response_type, char **code, char **id_token,
		char **access_token, char **token_type) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_check_authorization_response_parameters: entering, response_type=%s, code=%s, id_token=%s, access_token=%s, token_type=%s",
			response_type, *code, *id_token, *access_token, *token_type);

	/*
	 * check code parameter
	 */
	if (oidc_util_spaced_string_contains(r->pool, response_type, "code")) {

		if (*code == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_check_authorization_response_parameters: requested flow is \"%s\" but no \"code\" parameter found in the authorization response",
					response_type);
			return FALSE;
		}

	} else {

		if (*code != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_check_authorization_response_parameters: requested flow is \"%s\" but there is a \"code\" parameter in the authorization response that will be dropped",
					response_type);
			*code = NULL;
		}
	}

	/*
	 * check id_token parameter
	 */
	if (oidc_util_spaced_string_contains(r->pool, response_type, "id_token")) {

		if (*id_token == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_check_authorization_response_parameters: requested flow is \"%s\" but no \"id_token\" parameter found in the authorization response",
					response_type);
			return FALSE;
		}

	} else {

		if (*id_token != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_check_authorization_response_parameters: requested flow is \"%s\" but there is an \"id_token\" parameter in the authorization response that will be dropped",
					response_type);
			*id_token = NULL;
		}

	}

	/*
	 * check access_token parameter
	 */
	if (oidc_util_spaced_string_contains(r->pool, response_type, "token")) {

		if (*access_token == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_check_authorization_response_parameters: requested flow is \"%s\" but no \"access_token\" parameter found in the authorization response",
					response_type);
			return FALSE;
		}

		if (*token_type == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_check_authorization_response_parameters: requested flow is \"%s\" but no \"token_type\" parameter found in the authorization response",
					response_type);
			return FALSE;
		}

	} else {

		if (*access_token != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_check_authorization_response_parameters: requested flow is \"%s\" but there is an \"access_token\" parameter in the authorization response that will be dropped",
					response_type);
			*access_token = NULL;
		}

		if (*token_type != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_check_authorization_response_parameters: requested flow is \"%s\" but there is a \"token_type\" parameter in the authorization response that will be dropped",
					response_type);
			*token_type = NULL;
		}

	}

	return TRUE;
}

/*
 * check the required parameters for the various flows after resolving the authorization code
 */
static apr_byte_t oidc_check_code_response_parameters(request_rec *r,
		const char *response_type, char **id_token, char **access_token,
		char **token_type) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_check_code_response_parameters: entering");

	/*
	 * check id_token parameter
	 */
	if (!oidc_util_spaced_string_contains(r->pool, response_type, "id_token")) {

		if (*id_token == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_check_code_response_parameters: requested flow is \"%s\" but no \"id_token\" parameter found in the code response",
					response_type);
			return FALSE;
		}

	} else {

		if (*id_token != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_check_code_response_parameters: requested flow is \"%s\" but there is an \"id_token\" parameter in the code response that will be dropped",
					response_type);
			*id_token = NULL;
		}

	}

	/*
	 * check access_token parameter
	 */
	if (!oidc_util_spaced_string_contains(r->pool, response_type, "token")) {

		if (*access_token == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_check_code_response_parameters: requested flow is \"%s\" but no \"access_token\" parameter found in the code response",
					response_type);
			return FALSE;
		}

		if (*token_type == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_check_code_response_parameters: requested flow is \"%s\" but no \"token_type\" parameter found in the code response",
					response_type);
			return FALSE;
		}

	} else {

		if (*access_token != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_check_code_response_parameters: requested flow is \"%s\" but there is an \"access_token\" parameter in the authorization response that will be dropped",
					response_type);
			*access_token = NULL;
		}

		if (*token_type != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_check_code_response_parameters: requested flow is \"%s\" but there is a \"token_type\" parameter in the authorization response that will be dropped",
					response_type);
			*token_type = NULL;
		}

	}

	return TRUE;
}

/*
 * complete the handling of an authorization response by obtaining, parsing and verifying the
 * id_token and storing the authenticated user state in the session
 */
static int oidc_handle_authorization_response(request_rec *r, oidc_cfg *c,
		session_rec *session, const char *state, char *code, char *id_token,
		char *access_token, char *token_type) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_authorization_response: entering");

	struct oidc_provider_t *provider = NULL;
	oidc_authrr_state *authz_rr_state = NULL;

	/* match the returned state parameter against the state stored in the browser */
	if (oidc_authorization_response_match_state(r, c, state, &provider,
			&authz_rr_state) == FALSE) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* check the required response parameters for the requested flow */
	if (oidc_check_authorization_response_parameters(r,
			authz_rr_state->response_type, &code, &id_token, &access_token,
			&token_type) == FALSE) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char *remoteUser = NULL;
	apr_jwt_t *jwt = NULL;

	/* parse and validate the obtained id_token */
	if (id_token != NULL) {
		if (oidc_proto_parse_idtoken(r, c, provider, id_token,
				authz_rr_state->nonce, &remoteUser, &jwt) == FALSE) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_handle_authorization_response: could not verify the id_token contents, return HTTP_UNAUTHORIZED");
			return HTTP_UNAUTHORIZED;
		}
	}

	/* resolve the code against the token endpoint of the OP */
	if (code != NULL) {

		if (jwt != NULL) {
			if (oidc_proto_validate_code(r, provider, jwt,
					authz_rr_state->response_type, code) == FALSE) {
				return HTTP_UNAUTHORIZED;
			}
		}

		char *c_id_token = NULL, *c_access_token = NULL, *c_token_type = NULL;

		if (oidc_proto_resolve_code(r, c, provider, code, &c_id_token,
				&c_access_token, &c_token_type) == FALSE) {
			return HTTP_UNAUTHORIZED;
		}

		if (oidc_check_code_response_parameters(r,
				authz_rr_state->response_type, &c_id_token, &c_access_token,
				&c_token_type) == FALSE) {
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (c_id_token != NULL) {
			id_token = c_id_token;
		}
		if (c_access_token != NULL) {
			access_token = c_access_token;
			token_type = c_token_type;
		}

		if (jwt == NULL) {
			/* TODO: now I'm setting the nonce to NULL since google does not allow using a nonce in the "code" flow... */
			if (oidc_proto_parse_idtoken(r, c, provider, id_token, NULL,
					&remoteUser, &jwt) == FALSE) {
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
						"oidc_handle_authorization_response: could not verify the id_token contents, return HTTP_UNAUTHORIZED");
				return HTTP_UNAUTHORIZED;
			}
		}
	}

	/* validate the access token */
	if (access_token != NULL) {
		if (oidc_proto_validate_access_token(r, provider, jwt,
				authz_rr_state->response_type, access_token,
				token_type) == FALSE) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_handle_authorization_response: access_token did not validate, dropping it");
			access_token = NULL;
		}
	}

	/*
	 * optionally resolve additional claims against the userinfo endpoint
	 * parsed claims are not actually used here but need to be parsed anyway for error checking purposes
	 */
	const char *claims = NULL;
	apr_json_value_t *j_claims = NULL;
	if (oidc_proto_resolve_userinfo(r, c, provider, access_token, &claims,
			&j_claims) == FALSE) {
		claims = NULL;
	}

	/* set the resolved stuff in the session */
	session->remote_user = remoteUser;

	/* expires is the value from the id_token */
	session->expiry =
			apr_time_now() + apr_time_from_sec(c->session_inactivity_timeout);

	/* store the whole contents of the id_token for later reference too */
	oidc_session_set(r, session, OIDC_IDTOKEN_SESSION_KEY,
			jwt->payload.value.str);

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
	apr_table_add(r->headers_out, "Location", authz_rr_state->original_url);

	/* log the successful response */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_authorization_response: session created and stored, redirecting to original url: %s",
			authz_rr_state->original_url);

	/* do the actual redirect to the original URL */
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * handle an OpenID Connect Authorization Response using the POST (+fragment->POST) response_mode
 */
static int oidc_handle_post_authorization_response(request_rec *r, oidc_cfg *c,
		session_rec *session) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_post_authorization_response: entering");

	/* initialize local variables */
	char *code = NULL, *state = NULL, *id_token = NULL, *access_token = NULL,
			*token_type =
			NULL;

	/* read the parameters that are POST-ed to us */
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post(r, params) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_handle_post_authorization_response: something went wrong when reading the POST parameters");
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
		return oidc_util_html_send_error(r, error, error_description, DONE);

	/* get the parameters */
	code = (char *) apr_table_get(params, "code");
	state = (char *) apr_table_get(params, "state");
	id_token = (char *) apr_table_get(params, "id_token");
	access_token = (char *) apr_table_get(params, "access_token");
	token_type = (char *) apr_table_get(params, "token_type");

	/* do the actual implicit work */
	return oidc_handle_authorization_response(r, c, session, state, code,
			id_token, access_token, token_type);
}

/*
 * handle an OpenID Connect Authorization Response using the redirect response_mode
 */
static int oidc_handle_redirect_authorization_response(request_rec *r,
		oidc_cfg *c, session_rec *session) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_handle_redirect_authorization_response: entering");

	/* initialize local variables */
	char *code = NULL, *state = NULL, *id_token = NULL, *access_token = NULL,
			*token_type =
			NULL;

	/* get the parameters */
	oidc_util_get_request_parameter(r, "code", &code);
	oidc_util_get_request_parameter(r, "state", &state);
	oidc_util_get_request_parameter(r, "id_token", &id_token);
	oidc_util_get_request_parameter(r, "access_token", &access_token);
	oidc_util_get_request_parameter(r, "token_type", &token_type);

	/* do the actual work */
	return oidc_handle_authorization_response(r, c, session, state, code,
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

	/* generate a nonce */
	char *nonce = NULL;
	oidc_util_generate_random_base64url_encoded_value(r, 32, &nonce);

	/* create the state between request/response */
	oidc_authrr_state authz_rr_state = { nonce, original_url, provider->issuer,
			provider->response_type, apr_time_sec(apr_time_now()) };

	/* create state that restores the context when the authorization response comes in; cryptographically bind it to the browser */
	oidc_authorization_request_set_cookie(r, &authz_rr_state);

	/* get a hash value that fingerprints the browser concatenated with the random input */
	char *state = oidc_get_browser_state_hash(r, authz_rr_state.nonce);

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
	return (oidc_util_request_has_parameter(r, OIDC_DISC_RT_PARAM)
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

	} else if (apr_strnatcmp(issuer, "accounts.google.com") != 0) {

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
 * handle all requests to the redirect_uri
 */
int oidc_handle_redirect_uri_request(request_rec *r, oidc_cfg *c,
		session_rec *session) {

	if (oidc_proto_is_redirect_authorization_response(r, c)) {

		/* this is an authorization response from the OP using the Basic Client profile or a Hybrid flow*/
		return oidc_handle_redirect_authorization_response(r, c, session);

	} else if (oidc_proto_is_post_authorization_response(r, c)) {

		/* this is an authorization response using the fragment(+POST) response_mode with the Implicit Client profile */
		return oidc_handle_post_authorization_response(r, c, session);

	} else if (oidc_is_discovery_response(r, c)) {

		/* this is response from the OP discovery page */
		return oidc_handle_discovery_response(r, c);

	} else if (oidc_util_request_has_parameter(r, "logout")) {

		/* handle logout */
		return oidc_handle_logout(r, session);
	}

	/* this is not an authorization response  or logout request */

	if ((r->args == NULL) || (apr_strnatcmp(r->args, "") == 0))
		/* this is a "bare" request to the redirect URI, indicating implicit flow using the fragment response_mode */
		return oidc_proto_javascript_implicit(r, c);

	/* TODO: check for "error" response */
	if (oidc_util_request_has_parameter(r, "error")) {

		char *error = NULL, *descr = NULL;
		oidc_util_get_request_parameter(r, "error", &error);
		oidc_util_get_request_parameter(r, "error_description", &descr);

		return oidc_util_html_send_error(r, error, descr, DONE);
	}

	/* something went wrong */
	return oidc_util_http_sendstring(r,
			apr_psprintf(r->pool,
					"mod_auth_openidc: the OpenID Connect callback URL received an invalid request: %s",
					r->args), HTTP_INTERNAL_SERVER_ERROR);
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

		/* see if the initial request is to the redirect URI */
		if (oidc_util_request_matches_url(r, c->redirect_uri)) {

			/* handle request to the redirect_uri */
			return oidc_handle_redirect_uri_request(r, c, session);

			/* initial request to non-redirect URI, check if we have an existing session */
		} else if (session->remote_user != NULL) {

			/* set the user in the main request for further (incl. sub-request) processing */
			r->user = (char *) session->remote_user;

			/* this is initial request and we already have a session */
			return oidc_handle_existing_session(r, c, session);

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
