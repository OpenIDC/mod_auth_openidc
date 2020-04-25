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
 * Copyright (C) 2017-2020 ZmartZone IAM
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
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
 * shared memory caching: mod_auth_mellon
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
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

#define ERROR 2

static int oidc_handle_logout_request(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, const char *url);

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
static void oidc_scrub_request_headers(request_rec *r, const char *claim_prefix,
		apr_hash_t *scrub) {

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

		/* is this header's name equivalent to a header that needs scrubbing? */
		const char *hdr =
				(k != NULL) && (scrub != NULL) ?
						apr_hash_get(scrub, k, APR_HASH_KEY_STRING) : NULL;
		const int header_matches = (hdr != NULL)
						&& (oidc_strnenvcmp(k, hdr, -1) == 0);

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
		if (!prefix_matches && !header_matches) {
			apr_table_addn(clean_headers, k, e[i].val);
		} else {
			oidc_warn(r, "scrubbed suspicious request header (%s: %.32s)", k,
					e[i].val);
		}
	}

	/* overwrite the incoming headers with the cleaned result */
	r->headers_in = clean_headers;
}

/*
 * scrub all mod_auth_openidc related headers
 */
void oidc_scrub_headers(request_rec *r) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	const char *prefix = oidc_cfg_claim_prefix(r);
	apr_hash_t *hdrs = apr_hash_make(r->pool);

	if (apr_strnatcmp(prefix, "") == 0) {
		if ((cfg->white_listed_claims != NULL)
				&& (apr_hash_count(cfg->white_listed_claims) > 0))
			hdrs = apr_hash_overlay(r->pool, cfg->white_listed_claims, hdrs);
		else
			oidc_warn(r,
					"both " OIDCClaimPrefix " and " OIDCWhiteListedClaims " are empty: this renders an insecure setup!");
	}

	char *authn_hdr = oidc_cfg_dir_authn_header(r);
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
	if ((strstr(prefix, OIDC_DEFAULT_HEADER_PREFIX) != prefix)) {
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

	char *cookies = apr_pstrdup(r->pool, oidc_util_hdr_in_cookie_get(r));

	if ((cookies != NULL) && (strip != NULL)) {

		oidc_debug(r,
				"looking for the following cookies to strip from cookie header: %s",
				apr_array_pstrcat(r->pool, strip, OIDC_CHAR_COMMA));

		cookie = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &ctx);

		do {
			while (cookie != NULL && *cookie == OIDC_CHAR_SPACE)
				cookie++;

			for (i = 0; i < strip->nelts; i++) {
				name = ((const char**) strip->elts)[i];
				if ((strncmp(cookie, name, strlen(name)) == 0)
						&& (cookie[strlen(name)] == OIDC_CHAR_EQUAL)) {
					oidc_debug(r, "stripping: %s", name);
					break;
				}
			}

			if (i == strip->nelts) {
				result = result ? apr_psprintf(r->pool, "%s%s%s", result,
						OIDC_STR_SEMI_COLON, cookie) :
						cookie;
			}

			cookie = apr_strtok(NULL, OIDC_STR_SEMI_COLON, &ctx);
		} while (cookie != NULL);

		oidc_util_hdr_in_cookie_set(r, result);
	}
}

#define OIDC_SHA1_LEN 20

/*
 * calculates a hash value based on request fingerprint plus a provided nonce string.
 */
static char *oidc_get_browser_state_hash(request_rec *r, oidc_cfg *c, const char *nonce) {

	oidc_debug(r, "enter");

	/* helper to hold to header values */
	const char *value = NULL;
	/* the hash context */
	apr_sha1_ctx_t sha1;

	/* Initialize the hash context */
	apr_sha1_init(&sha1);

	if (c->state_input_headers & OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR) {
		/* get the X-FORWARDED-FOR header value  */
		value = oidc_util_hdr_in_x_forwarded_for_get(r);
		/* if we have a value for this header, concat it to the hash input */
		if (value != NULL)
			apr_sha1_update(&sha1, value, strlen(value));
	}

	if (c->state_input_headers & OIDC_STATE_INPUT_HEADERS_USER_AGENT) {
		/* get the USER-AGENT header value  */
		value = oidc_util_hdr_in_user_agent_get(r);
		/* if we have a value for this header, concat it to the hash input */
		if (value != NULL)
			apr_sha1_update(&sha1, value, strlen(value));
	}

	/* get the remote client IP address or host name */
	/*
	int remotehost_is_ip;
	value = ap_get_remote_host(r->connection, r->per_dir_config,
			REMOTE_NOLOOKUP, &remotehost_is_ip);
	apr_sha1_update(&sha1, value, strlen(value));
	*/

	/* concat the nonce parameter to the hash input */
	apr_sha1_update(&sha1, nonce, strlen(nonce));

	/* concat the token binding ID if present */
	value = oidc_util_get_provided_token_binding_id(r);
	if (value != NULL) {
		oidc_debug(r,
				"Provided Token Binding ID environment variable found; adding its value to the state");
		apr_sha1_update(&sha1, value, strlen(value));
	}

	/* finalize the hash input and calculate the resulting hash output */
	unsigned char hash[OIDC_SHA1_LEN];
	apr_sha1_final(hash, &sha1);

	/* base64url-encode the resulting hash and return it */
	char *result = NULL;
	oidc_base64url_encode(r, &result, (const char *) hash, OIDC_SHA1_LEN, TRUE);
	return result;
}

/*
 * return the name for the state cookie
 */
static char *oidc_get_state_cookie_name(request_rec *r, const char *state) {
	return apr_psprintf(r->pool, "%s%s", OIDC_STATE_COOKIE_PREFIX, state);
}

/*
 * return the static provider configuration, i.e. from a metadata URL or configuration primitives
 */
static apr_byte_t oidc_provider_static_config(request_rec *r, oidc_cfg *c,
		oidc_provider_t **provider) {

	json_t *j_provider = NULL;
	char *s_json = NULL;

	/* see if we should configure a static provider based on external (cached) metadata */
	if ((c->metadata_dir != NULL) || (c->provider.metadata_url == NULL)) {
		*provider = &c->provider;
		return TRUE;
	}

	oidc_cache_get_provider(r, c->provider.metadata_url, &s_json);

	if (s_json == NULL) {

		if (oidc_metadata_provider_retrieve(r, c, NULL,
				c->provider.metadata_url, &j_provider, &s_json) == FALSE) {
			oidc_error(r, "could not retrieve metadata from url: %s",
					c->provider.metadata_url);
			return FALSE;
		}

		oidc_cache_set_provider(r, c->provider.metadata_url, s_json,
				apr_time_now() + (c->provider_metadata_refresh_interval <= 0 ? apr_time_from_sec( OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT) : c->provider_metadata_refresh_interval));

	} else {

		oidc_util_decode_json_object(r, s_json, &j_provider);

		/* check to see if it is valid metadata */
		if (oidc_metadata_provider_is_valid(r, c, j_provider, NULL) == FALSE) {
			oidc_error(r,
					"cache corruption detected: invalid metadata from url: %s",
					c->provider.metadata_url);
			return FALSE;
		}
	}

	*provider = apr_pcalloc(r->pool, sizeof(oidc_provider_t));
	memcpy(*provider, &c->provider, sizeof(oidc_provider_t));

	if (oidc_metadata_provider_parse(r, c, j_provider, *provider) == FALSE) {
		oidc_error(r, "could not parse metadata from url: %s",
				c->provider.metadata_url);
		if (j_provider)
			json_decref(j_provider);
		return FALSE;
	}

	json_decref(j_provider);

	return TRUE;
}

/*
 * return the oidc_provider_t struct for the specified issuer
 */
static oidc_provider_t *oidc_get_provider_for_issuer(request_rec *r,
		oidc_cfg *c, const char *issuer, apr_byte_t allow_discovery) {

	/* by default we'll assume that we're dealing with a single statically configured OP */
	oidc_provider_t *provider = NULL;
	if (oidc_provider_static_config(r, c, &provider) == FALSE)
		return NULL;

	/* unless a metadata directory was configured, so we'll try and get the provider settings from there */
	if (c->metadata_dir != NULL) {

		/* try and get metadata from the metadata directory for the OP that sent this response */
		if ((oidc_metadata_get(r, c, issuer, &provider, allow_discovery)
				== FALSE) || (provider == NULL)) {

			/* don't know nothing about this OP/issuer */
			oidc_error(r, "no provider metadata found for issuer \"%s\"",
					issuer);

			return NULL;
		}
	}

	return provider;
}

/*
 * find out whether the request is a response from an IDP discovery page
 */
static apr_byte_t oidc_is_discovery_response(request_rec *r, oidc_cfg *cfg) {
	/*
	 * prereq: this is a call to the configured redirect_uri, now see if:
	 * the OIDC_DISC_OP_PARAM is present
	 */
	return oidc_util_request_has_parameter(r, OIDC_DISC_OP_PARAM)
			|| oidc_util_request_has_parameter(r, OIDC_DISC_USER_PARAM);
}

/*
 * return the HTTP method being called: only for POST data persistence purposes
 */
static const char *oidc_original_request_method(request_rec *r, oidc_cfg *cfg,
		apr_byte_t handle_discovery_response) {
	const char *method = OIDC_METHOD_GET;

	char *m = NULL;
	if ((handle_discovery_response == TRUE)
			&& (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, cfg)))
			&& (oidc_is_discovery_response(r, cfg))) {
		oidc_util_get_request_parameter(r, OIDC_DISC_RM_PARAM, &m);
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

		const char *content_type = oidc_util_hdr_in_content_type_get(r);
		if ((r->method_number == M_POST) && (apr_strnatcmp(content_type,
				OIDC_CONTENT_TYPE_FORM_ENCODED) == 0))
			method = OIDC_METHOD_FORM_POST;
	}

	oidc_debug(r, "return: %s", method);

	return method;
}

/*
 * send an OpenID Connect authorization request to the specified provider preserving POST parameters using HTML5 storage
 */
apr_byte_t oidc_post_preserve_javascript(request_rec *r, const char *location,
		char **javascript, char **javascript_method) {

	if (oidc_cfg_dir_preserve_post(r) == 0)
		return FALSE;

	oidc_debug(r, "enter");

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	const char *method = oidc_original_request_method(r, cfg, FALSE);

	if (apr_strnatcmp(method, OIDC_METHOD_FORM_POST) != 0)
		return FALSE;

	/* read the parameters that are POST-ed to us */
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r, "something went wrong when reading the POST parameters");
		return FALSE;
	}

	const apr_array_header_t *arr = apr_table_elts(params);
	const apr_table_entry_t *elts = (const apr_table_entry_t*) arr->elts;
	int i;
	char *json = "";
	for (i = 0; i < arr->nelts; i++) {
		json = apr_psprintf(r->pool, "%s'%s': '%s'%s", json,
				oidc_util_escape_string(r, elts[i].key),
				oidc_util_escape_string(r, elts[i].val),
				i < arr->nelts - 1 ? "," : "");
	}
	json = apr_psprintf(r->pool, "{ %s }", json);

	const char *jmethod = "preserveOnLoad";
	const char *jscript =
			apr_psprintf(r->pool,
					"    <script type=\"text/javascript\">\n"
					"      function %s() {\n"
					"        sessionStorage.setItem('mod_auth_openidc_preserve_post_params', JSON.stringify(%s));\n"
					"        %s"
					"      }\n"
					"    </script>\n", jmethod, json,
					location ?
							apr_psprintf(r->pool, "window.location='%s';\n",
									location) :
									"");
	if (location == NULL) {
		if (javascript_method)
			*javascript_method = apr_pstrdup(r->pool, jmethod);
		if (javascript)
			*javascript = apr_pstrdup(r->pool, jscript);
	} else {
		oidc_util_html_send(r, "Preserving...", jscript, jmethod,
				"<p>Preserving...</p>", OK);
	}

	return TRUE;
}

/*
 * restore POST parameters on original_url from HTML5 local storage
 */
static int oidc_request_post_preserved_restore(request_rec *r,
		const char *original_url) {

	oidc_debug(r, "enter: original_url=%s", original_url);

	const char *method = "postOnLoad";
	const char *script =
			apr_psprintf(r->pool,
					"    <script type=\"text/javascript\">\n"
					"      function str_decode(string) {\n"
					"        try {\n"
					"          result = decodeURIComponent(string);\n"
					"        } catch (e) {\n"
					"          result =  unescape(string);\n"
					"        }\n"
					"        return result;\n"
					"      }\n"
					"      function %s() {\n"
					"        var mod_auth_openidc_preserve_post_params = JSON.parse(sessionStorage.getItem('mod_auth_openidc_preserve_post_params'));\n"
					"		 sessionStorage.removeItem('mod_auth_openidc_preserve_post_params');\n"
					"        for (var key in mod_auth_openidc_preserve_post_params) {\n"
					"          var input = document.createElement(\"input\");\n"
					"          input.name = str_decode(key);\n"
					"          input.value = str_decode(mod_auth_openidc_preserve_post_params[key]);\n"
					"          input.type = \"hidden\";\n"
					"          document.forms[0].appendChild(input);\n"
					"        }\n"
					"        document.forms[0].action = '%s';\n"
					"        document.forms[0].submit();\n"
					"      }\n"
					"    </script>\n", method, original_url);

	const char *body = "    <p>Restoring...</p>\n"
			"    <form method=\"post\"></form>\n";

	return oidc_util_html_send(r, "Restoring...", script, method, body,
			OK);
}

/*
 * parse state that was sent to us by the issuer
 */
static apr_byte_t oidc_unsolicited_proto_state(request_rec *r, oidc_cfg *c,
		const char *state, oidc_proto_state_t **proto_state) {

	char *alg = NULL;
	oidc_debug(r, "enter: state header=%s",
			oidc_proto_peek_jwt_header(r, state, &alg));

	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	if (oidc_util_create_symmetric_key(r, c->provider.client_secret,
			oidc_alg2keysize(alg), OIDC_JOSE_ALG_SHA256,
			TRUE, &jwk) == FALSE)
		return FALSE;

	oidc_jwt_t *jwt = NULL;
	if (oidc_jwt_parse(r->pool, state, &jwt,
			oidc_util_merge_symmetric_key(r->pool, c->private_keys, jwk),
			&err) == FALSE) {
		oidc_error(r,
				"could not parse JWT from state: invalid unsolicited response: %s",
				oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	oidc_jwk_destroy(jwk);
	oidc_debug(r, "successfully parsed JWT from state");

	if (jwt->payload.iss == NULL) {
		oidc_error(r, "no \"%s\" could be retrieved from JWT state, aborting",
				OIDC_CLAIM_ISS);
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	oidc_provider_t *provider = oidc_get_provider_for_issuer(r, c,
			jwt->payload.iss, FALSE);
	if (provider == NULL) {
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	/* validate the state JWT, validating optional exp + iat */
	if (oidc_proto_validate_jwt(r, jwt, provider->issuer, FALSE, FALSE,
			provider->idtoken_iat_slack,
			OIDC_TOKEN_BINDING_POLICY_DISABLED) == FALSE) {
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	char *rfp = NULL;
	if (oidc_jose_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_RFP,
			TRUE, &rfp, &err) == FALSE) {
		oidc_error(r,
				"no \"%s\" claim could be retrieved from JWT state, aborting: %s",
				OIDC_CLAIM_RFP, oidc_jose_e2s(r->pool, err));
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	if (apr_strnatcmp(rfp, OIDC_PROTO_ISS) != 0) {
		oidc_error(r, "\"%s\" (%s) does not match \"%s\", aborting",
				OIDC_CLAIM_RFP, rfp, OIDC_PROTO_ISS);
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	char *target_link_uri = NULL;
	oidc_jose_get_string(r->pool, jwt->payload.value.json,
			OIDC_CLAIM_TARGET_LINK_URI,
			FALSE, &target_link_uri, NULL);
	if (target_link_uri == NULL) {
		if (c->default_sso_url == NULL) {
			oidc_error(r,
					"no \"%s\" claim could be retrieved from JWT state and no " OIDCDefaultURL " is set, aborting",
					OIDC_CLAIM_TARGET_LINK_URI);
			oidc_jwt_destroy(jwt);
			return FALSE;
		}
		target_link_uri = c->default_sso_url;
	}

	if (c->metadata_dir != NULL) {
		if ((oidc_metadata_get(r, c, jwt->payload.iss, &provider, FALSE)
				== FALSE) || (provider == NULL)) {
			oidc_error(r, "no provider metadata found for provider \"%s\"",
					jwt->payload.iss);
			oidc_jwt_destroy(jwt);
			return FALSE;
		}
	}

	char *jti = NULL;
	oidc_jose_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_JTI,
			FALSE, &jti,
			NULL);
	if (jti == NULL) {
		char *cser = oidc_jwt_serialize(r->pool, jwt, &err);
		if (cser == NULL)
			return FALSE;
		if (oidc_util_hash_string_and_base64url_encode(r, OIDC_JOSE_ALG_SHA256,
				cser, &jti) == FALSE) {
			oidc_error(r,
					"oidc_util_hash_string_and_base64url_encode returned an error");
			return FALSE;
		}
	}

	char *replay = NULL;
	oidc_cache_get_jti(r, jti, &replay);
	if (replay != NULL) {
		oidc_error(r,
				"the \"%s\" value (%s) passed in the browser state was found in the cache already; possible replay attack!?",
				OIDC_CLAIM_JTI, jti);
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	/* jti cache duration is the configured replay prevention window for token issuance plus 10 seconds for safety */
	apr_time_t jti_cache_duration = apr_time_from_sec(
			provider->idtoken_iat_slack * 2 + 10);

	/* store it in the cache for the calculated duration */
	oidc_cache_set_jti(r, jti, jti, apr_time_now() + jti_cache_duration);

	oidc_debug(r,
			"jti \"%s\" validated successfully and is now cached for %" APR_TIME_T_FMT " seconds",
			jti, apr_time_sec(jti_cache_duration));

	jwk = NULL;
	if (oidc_util_create_symmetric_key(r, c->provider.client_secret, 0,
			NULL, TRUE, &jwk) == FALSE)
		return FALSE;

	oidc_jwks_uri_t jwks_uri = { provider->jwks_uri,
			provider->jwks_refresh_interval, provider->ssl_validate_server };
	if (oidc_proto_jwt_verify(r, c, jwt, &jwks_uri,
			oidc_util_merge_symmetric_key(r->pool, NULL, jwk), NULL) == FALSE) {
		oidc_error(r, "state JWT could not be validated, aborting");
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	oidc_jwk_destroy(jwk);
	oidc_debug(r, "successfully verified state JWT");

	*proto_state = oidc_proto_state_new();
	oidc_proto_state_set_issuer(*proto_state, jwt->payload.iss);
	oidc_proto_state_set_original_url(*proto_state, target_link_uri);
	oidc_proto_state_set_original_method(*proto_state, OIDC_METHOD_GET);
	oidc_proto_state_set_response_mode(*proto_state, provider->response_mode);
	oidc_proto_state_set_response_type(*proto_state, provider->response_type);
	oidc_proto_state_set_timestamp_now(*proto_state);

	oidc_jwt_destroy(jwt);

	return TRUE;
}

typedef struct oidc_state_cookies_t {
	char *name;
	apr_time_t timestamp;
	struct oidc_state_cookies_t *next;
} oidc_state_cookies_t;

static int oidc_delete_oldest_state_cookies(request_rec *r,
		int number_of_valid_state_cookies, int max_number_of_state_cookies,
		oidc_state_cookies_t *first) {
	oidc_state_cookies_t *cur = NULL, *prev = NULL, *prev_oldest = NULL,
			*oldest = NULL;
	while (number_of_valid_state_cookies >= max_number_of_state_cookies) {
		oldest = first;
		prev_oldest = NULL;
		prev = first;
		cur = first->next;
		while (cur) {
			if ((cur->timestamp < oldest->timestamp)) {
				oldest = cur;
				prev_oldest = prev;
			}
			prev = cur;
			cur = cur->next;
		}
		oidc_warn(r,
				"deleting oldest state cookie: %s (time until expiry %" APR_TIME_T_FMT " seconds)",
				oldest->name, apr_time_sec(oldest->timestamp - apr_time_now()));
		oidc_util_set_cookie(r, oldest->name, "", 0, NULL);
		if (prev_oldest)
			prev_oldest->next = oldest->next;
		else
			first = first->next;
		number_of_valid_state_cookies--;
	}
	return number_of_valid_state_cookies;
}

/*
 * clean state cookies that have expired i.e. for outstanding requests that will never return
 * successfully and return the number of remaining valid cookies/outstanding-requests while
 * doing so
 */
static int oidc_clean_expired_state_cookies(request_rec *r, oidc_cfg *c,
		const char *currentCookieName, int delete_oldest) {
	int number_of_valid_state_cookies = 0;
	oidc_state_cookies_t *first = NULL, *last = NULL;
	char *cookie, *tokenizerCtx = NULL;
	char *cookies = apr_pstrdup(r->pool, oidc_util_hdr_in_cookie_get(r));
	if (cookies != NULL) {
		cookie = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &tokenizerCtx);
		while (cookie != NULL) {
			while (*cookie == OIDC_CHAR_SPACE)
				cookie++;
			if (strstr(cookie, OIDC_STATE_COOKIE_PREFIX) == cookie) {
				char *cookieName = cookie;
				while (cookie != NULL && *cookie != OIDC_CHAR_EQUAL)
					cookie++;
				if (*cookie == OIDC_CHAR_EQUAL) {
					*cookie = '\0';
					cookie++;
					if ((currentCookieName == NULL)
							|| (apr_strnatcmp(cookieName, currentCookieName)
									!= 0)) {
						oidc_proto_state_t *proto_state =
								oidc_proto_state_from_cookie(r, c, cookie);
						if (proto_state != NULL) {
							json_int_t ts = oidc_proto_state_get_timestamp(
									proto_state);
							if (apr_time_now() > ts + apr_time_from_sec(c->state_timeout)) {
								oidc_warn(r,
										"state (%s) has expired (original_url=%s)",
										cookieName,
										oidc_proto_state_get_original_url(
												proto_state));
								oidc_util_set_cookie(r, cookieName, "", 0,
										NULL);
							} else {
								if (first == NULL) {
									first = apr_pcalloc(r->pool,
											sizeof(oidc_state_cookies_t));
									last = first;
								} else {
									last->next = apr_pcalloc(r->pool,
											sizeof(oidc_state_cookies_t));
									last = last->next;
								}
								last->name = cookieName;
								last->timestamp = ts;
								last->next = NULL;
								number_of_valid_state_cookies++;
							}
							oidc_proto_state_destroy(proto_state);
						}
					}
				}
			}
			cookie = apr_strtok(NULL, OIDC_STR_SEMI_COLON, &tokenizerCtx);
		}
	}

	if (delete_oldest > 0)
		number_of_valid_state_cookies = oidc_delete_oldest_state_cookies(r,
				number_of_valid_state_cookies, c->max_number_of_state_cookies,
				first);

	return number_of_valid_state_cookies;
}

/*
 * restore the state that was maintained between authorization request and response in an encrypted cookie
 */
static apr_byte_t oidc_restore_proto_state(request_rec *r, oidc_cfg *c,
		const char *state, oidc_proto_state_t **proto_state) {

	oidc_debug(r, "enter");

	const char *cookieName = oidc_get_state_cookie_name(r, state);

	/* clean expired state cookies to avoid pollution */
	oidc_clean_expired_state_cookies(r, c, cookieName, FALSE);

	/* get the state cookie value first */
	char *cookieValue = oidc_util_get_cookie(r, cookieName);
	if (cookieValue == NULL) {
		oidc_error(r, "no \"%s\" state cookie found", cookieName);
		return oidc_unsolicited_proto_state(r, c, state, proto_state);
	}

	/* clear state cookie because we don't need it anymore */
	oidc_util_set_cookie(r, cookieName, "", 0, NULL);

	*proto_state = oidc_proto_state_from_cookie(r, c, cookieValue);
	if (*proto_state == NULL)
		return FALSE;

	const char *nonce = oidc_proto_state_get_nonce(*proto_state);

	/* calculate the hash of the browser fingerprint concatenated with the nonce */
	char *calc = oidc_get_browser_state_hash(r, c, nonce);
	/* compare the calculated hash with the value provided in the authorization response */
	if (apr_strnatcmp(calc, state) != 0) {
		oidc_error(r,
				"calculated state from cookie does not match state parameter passed back in URL: \"%s\" != \"%s\"",
				state, calc);
		oidc_proto_state_destroy(*proto_state);
		return FALSE;
	}

	apr_time_t ts = oidc_proto_state_get_timestamp(*proto_state);

	/* check that the timestamp is not beyond the valid interval */
	if (apr_time_now() > ts + apr_time_from_sec(c->state_timeout)) {
		oidc_error(r, "state has expired");
		/*
		 * note that this overrides redirection to the OIDCDefaultURL as done later...
		 * see: https://groups.google.com/forum/?utm_medium=email&utm_source=footer#!msg/mod_auth_openidc/L4JFBw-XCNU/BWi2Fmk2AwAJ
		 */
		oidc_util_html_send_error(r, c->error_template,
				"Invalid Authentication Response",
				apr_psprintf(r->pool,
						"This is due to a timeout; please restart your authentication session by re-entering the URL/bookmark you originally wanted to access: %s",
						oidc_proto_state_get_original_url(*proto_state)),
						OK);
		oidc_proto_state_destroy(*proto_state);
		return FALSE;
	}

	/* add the state */
	oidc_proto_state_set_state(*proto_state, state);

	/* log the restored state object */
	oidc_debug(r, "restored state: %s",
			oidc_proto_state_to_string(r, *proto_state));

	/* we've made it */
	return TRUE;
}

/*
 * set the state that is maintained between an authorization request and an authorization response
 * in a cookie in the browser that is cryptographically bound to that state
 */
static int oidc_authorization_request_set_cookie(request_rec *r, oidc_cfg *c,
		const char *state, oidc_proto_state_t *proto_state) {
	/*
	 * create a cookie consisting of 8 elements:
	 * random value, original URL, original method, issuer, response_type, response_mod, prompt and timestamp
	 * encoded as JSON, encrypting the resulting JSON value
	 */
	char *cookieValue = oidc_proto_state_to_cookie(r, c, proto_state);
	if (cookieValue == NULL)
		return HTTP_INTERNAL_SERVER_ERROR;

	/*
	 * clean expired state cookies to avoid pollution and optionally
	 * try to avoid the number of state cookies exceeding a max
	 */
	int number_of_cookies = oidc_clean_expired_state_cookies(r, c, NULL,
			oidc_cfg_delete_oldest_state_cookies(c));
	int max_number_of_cookies = oidc_cfg_max_number_of_state_cookies(c);
	if ((max_number_of_cookies > 0)
			&& (number_of_cookies >= max_number_of_cookies)) {

		oidc_warn(r,
				"the number of existing, valid state cookies (%d) has exceeded the limit (%d), no additional authorization request + state cookie can be generated, aborting the request",
				number_of_cookies, max_number_of_cookies);
		/*
		 * TODO: the html_send code below caters for the case that there's a user behind a
		 * browser generating this request, rather than a piece of XHR code; how would an
		 * XHR client handle this?
		 */

		/*
		 * it appears that sending content with a 503 turns the HTTP status code
		 * into a 200 so we'll avoid that for now: the user will see Apache specific
		 * readable text anyway
		 *
		return oidc_util_html_send_error(r, c->error_template,
				"Too Many Outstanding Requests",
				apr_psprintf(r->pool,
						"No authentication request could be generated since there are too many outstanding authentication requests already; you may have to wait up to %d seconds to be able to create a new request",
						c->state_timeout),
						HTTP_SERVICE_UNAVAILABLE);
		*/

		return HTTP_SERVICE_UNAVAILABLE;
	}

	/* assemble the cookie name for the state cookie */
	const char *cookieName = oidc_get_state_cookie_name(r, state);

	/* set it as a cookie */
	oidc_util_set_cookie(r, cookieName, cookieValue, -1,
			c->cookie_same_site ?
					OIDC_COOKIE_EXT_SAME_SITE_LAX :
					OIDC_COOKIE_EXT_SAME_SITE_NONE);

	return HTTP_OK;
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
	apr_table_set(state, key, value);
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
 * set the claims from a JSON object (c.q. id_token or user_info response) stored
 * in the session in to HTTP headers passed on to the application
 */
static apr_byte_t oidc_set_app_claims(request_rec *r,
		const oidc_cfg * const cfg, oidc_session_t *session,
		const char *s_claims) {

	json_t *j_claims = NULL;

	/* decode the string-encoded attributes in to a JSON structure */
	if (s_claims != NULL) {
		if (oidc_util_decode_json_object(r, s_claims, &j_claims) == FALSE)
			return FALSE;
	}

	/* set the resolved claims a HTTP headers for the application */
	if (j_claims != NULL) {
		oidc_util_set_app_infos(r, j_claims, oidc_cfg_claim_prefix(r),
				cfg->claim_delimiter, oidc_cfg_dir_pass_info_in_headers(r),
				oidc_cfg_dir_pass_info_in_envvars(r));

		/* release resources */
		json_decref(j_claims);
	}

	return TRUE;
}

static int oidc_authenticate_user(request_rec *r, oidc_cfg *c,
		oidc_provider_t *provider, const char *original_url,
		const char *login_hint, const char *id_token_hint, const char *prompt,
		const char *auth_request_params, const char *path_scope);

/*
 * log message about max session duration
 */
static void oidc_log_session_expires(request_rec *r, const char *msg,
		apr_time_t session_expires) {
	char buf[APR_RFC822_DATE_LEN + 1];
	apr_rfc822_date(buf, session_expires);
	oidc_debug(r, "%s: %s (in %" APR_TIME_T_FMT " secs from now)", msg, buf,
			apr_time_sec(session_expires - apr_time_now()));
}

/*
 * see if this is a non-browser request
 */
static apr_byte_t oidc_is_xml_http_request(request_rec *r) {

	if ((oidc_util_hdr_in_x_requested_with_get(r) != NULL)
			&& (apr_strnatcasecmp(oidc_util_hdr_in_x_requested_with_get(r),
					OIDC_HTTP_HDR_VAL_XML_HTTP_REQUEST) == 0))
		return TRUE;

	if ((oidc_util_hdr_in_accept_contains(r, OIDC_CONTENT_TYPE_TEXT_HTML)
			== FALSE) && (oidc_util_hdr_in_accept_contains(r,
					OIDC_CONTENT_TYPE_APP_XHTML_XML) == FALSE)
					&& (oidc_util_hdr_in_accept_contains(r,
							OIDC_CONTENT_TYPE_ANY) == FALSE))
		return TRUE;

	return FALSE;
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
		if (oidc_is_xml_http_request(r) == TRUE)
			return HTTP_UNAUTHORIZED;
	}

	/*
	 * else: no session (regardless of whether it is main or sub-request),
	 * and we need to authenticate the user
	 */
	return oidc_authenticate_user(r, c, NULL, oidc_get_current_url(r), NULL,
			NULL, NULL, oidc_dir_cfg_path_auth_request_params(r),
			oidc_dir_cfg_path_scope(r));
}

/*
 * check if maximum session duration was exceeded
 */
static int oidc_check_max_session_duration(request_rec *r, oidc_cfg *cfg,
		oidc_session_t *session) {

	/* get the session expiry from the session data */
	apr_time_t session_expires = oidc_session_get_session_expires(r, session);

	/* check the expire timestamp against the current time */
	if (apr_time_now() > session_expires) {
		oidc_warn(r, "maximum session duration exceeded for user: %s",
				session->remote_user);
		oidc_session_kill(r, session);
		return oidc_handle_unauthenticated_user(r, cfg);
	}

	/* log message about max session duration */
	oidc_log_session_expires(r, "session max lifetime", session_expires);

	return OK;
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
static apr_byte_t oidc_check_cookie_domain(request_rec *r, oidc_cfg *cfg,
		oidc_session_t *session) {
	const char *c_cookie_domain =
			cfg->cookie_domain ?
					cfg->cookie_domain : oidc_get_current_url_host(r);
	const char *s_cookie_domain = oidc_session_get_cookie_domain(r, session);
	if ((s_cookie_domain == NULL)
			|| (apr_strnatcmp(c_cookie_domain, s_cookie_domain) != 0)) {
		oidc_warn(r,
				"aborting: detected attempt to play cookie against a different domain/host than issued for! (issued=%s, current=%s)",
				s_cookie_domain, c_cookie_domain);
		return FALSE;
	}

	return TRUE;
}

/*
 * get a handle to the provider configuration via the "issuer" stored in the session
 */
apr_byte_t oidc_get_provider_from_session(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, oidc_provider_t **provider) {

	oidc_debug(r, "enter");

	/* get the issuer value from the session state */
	const char *issuer = oidc_session_get_issuer(r, session);
	if (issuer == NULL) {
		oidc_error(r, "session corrupted: no issuer found in session");
		return FALSE;
	}

	/* get the provider info associated with the issuer value */
	oidc_provider_t *p = oidc_get_provider_for_issuer(r, c, issuer, FALSE);
	if (p == NULL) {
		oidc_error(r, "session corrupted: no provider found for issuer: %s",
				issuer);
		return FALSE;
	}

	*provider = p;

	return TRUE;
}

/*
 * store claims resolved from the userinfo endpoint in the session
 */
static void oidc_store_userinfo_claims(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, oidc_provider_t *provider, const char *claims,
		const char *userinfo_jwt) {

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
 * execute refresh token grant to refresh the existing access token
 */
static apr_byte_t oidc_refresh_access_token(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, oidc_provider_t *provider,
		char **new_access_token) {

	oidc_debug(r, "enter");

	/* get the refresh token that was stored in the session */
	const char *refresh_token = oidc_session_get_refresh_token(r, session);
	if (refresh_token == NULL) {
		oidc_warn(r,
				"refresh token routine called but no refresh_token found in the session");
		return FALSE;
	}

	/* elements returned in the refresh response */
	char *s_id_token = NULL;
	int expires_in = -1;
	char *s_token_type = NULL;
	char *s_access_token = NULL;
	char *s_refresh_token = NULL;

	/* refresh the tokens by calling the token endpoint */
	if (oidc_proto_refresh_request(r, c, provider, refresh_token, &s_id_token,
			&s_access_token, &s_token_type, &expires_in,
			&s_refresh_token) == FALSE) {
		oidc_error(r, "access_token could not be refreshed");
		return FALSE;
	}

	/* store the new access_token in the session and discard the old one */
	oidc_session_set_access_token(r, session, s_access_token);
	oidc_session_set_access_token_expires(r, session, expires_in);

	/* reset the access token refresh timestamp */
	oidc_session_reset_access_token_last_refresh(r, session);

	/* see if we need to return it as a parameter */
	if (new_access_token != NULL)
		*new_access_token = s_access_token;

	/* if we have a new refresh token (rolling refresh), store it in the session and overwrite the old one */
	if (s_refresh_token != NULL)
		oidc_session_set_refresh_token(r, session, s_refresh_token);

	return TRUE;
}

/*
 * retrieve claims from the userinfo endpoint and return the stringified response
 */
static const char *oidc_retrieve_claims_from_userinfo_endpoint(request_rec *r,
		oidc_cfg *c, oidc_provider_t *provider, const char *access_token,
		oidc_session_t *session, char *id_token_sub, char **userinfo_jwt) {

	oidc_debug(r, "enter");

	char *result = NULL;
	char *refreshed_access_token = NULL;

	/* see if a userinfo endpoint is set, otherwise there's nothing to do for us */
	if (provider->userinfo_endpoint_url == NULL) {
		oidc_debug(r,
				"not retrieving userinfo claims because userinfo_endpoint is not set");
		return NULL;
	}

	/* see if there's an access token, otherwise we can't call the userinfo endpoint at all */
	if (access_token == NULL) {
		oidc_debug(r,
				"not retrieving userinfo claims because access_token is not provided");
		return NULL;
	}

	if ((id_token_sub == NULL) && (session != NULL)) {

		// when refreshing claims from the userinfo endpoint
		json_t *id_token_claims = oidc_session_get_idtoken_claims_json(r,
				session);
		if (id_token_claims == NULL) {
			oidc_error(r, "no id_token_claims found in session");
			return NULL;
		}

		oidc_jose_get_string(r->pool, id_token_claims, OIDC_CLAIM_SUB, FALSE,
				&id_token_sub, NULL);
	}

	// TODO: return code should indicate whether the token expired or some other error occurred
	// TODO: long-term: session storage should be JSON (with explicit types and less conversion, using standard routines)

	/* try to get claims from the userinfo endpoint using the provided access token */
	if (oidc_proto_resolve_userinfo(r, c, provider, id_token_sub, access_token,
			&result, userinfo_jwt) == FALSE) {

		/* see if we have an existing session and we are refreshing the user info claims */
		if (session != NULL) {

			/* first call to user info endpoint failed, but the access token may have just expired, so refresh it */
			if (oidc_refresh_access_token(r, c, session, provider,
					&refreshed_access_token) == TRUE) {

				/* try again with the new access token */
				if (oidc_proto_resolve_userinfo(r, c, provider, id_token_sub,
						refreshed_access_token, &result, userinfo_jwt) == FALSE) {

					oidc_error(r,
							"resolving user info claims with the refreshed access token failed, nothing will be stored in the session");
					result = NULL;

				}

			} else {

				oidc_warn(r,
						"refreshing access token failed, claims will not be retrieved/refreshed from the userinfo endpoint");
				result = NULL;

			}

		} else {

			oidc_error(r,
					"resolving user info claims with the existing/provided access token failed, nothing will be stored in the session");
			result = NULL;

		}
	}

	return result;
}

/*
 * get (new) claims from the userinfo endpoint
 */
static apr_byte_t oidc_refresh_claims_from_userinfo_endpoint(request_rec *r,
		oidc_cfg *cfg, oidc_session_t *session) {

	oidc_provider_t *provider = NULL;
	const char *claims = NULL;
	const char *access_token = NULL;
	char *userinfo_jwt = NULL;

	/* get the current provider info */
	if (oidc_get_provider_from_session(r, cfg, session, &provider) == FALSE)
		return FALSE;

	/* see if we can do anything here, i.e. we have a userinfo endpoint and a refresh interval is configured */
	apr_time_t interval = apr_time_from_sec(
			provider->userinfo_refresh_interval);

	oidc_debug(r, "userinfo_endpoint=%s, interval=%d",
			provider->userinfo_endpoint_url,
			provider->userinfo_refresh_interval);

	if ((provider->userinfo_endpoint_url != NULL) && (interval > 0)) {

		/* get the last refresh timestamp from the session info */
		apr_time_t last_refresh = oidc_session_get_userinfo_last_refresh(r,
				session);

		oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds",
				apr_time_sec(last_refresh + interval - apr_time_now()));

		/* see if we need to refresh again */
		if (last_refresh + interval < apr_time_now()) {

			/* get the current access token */
			access_token = oidc_session_get_access_token(r, session);

			/* retrieve the current claims */
			claims = oidc_retrieve_claims_from_userinfo_endpoint(r, cfg,
					provider, access_token, session, NULL, &userinfo_jwt);

			/* store claims resolved from userinfo endpoint */
			oidc_store_userinfo_claims(r, cfg, session, provider, claims,
					userinfo_jwt);

			/* indicated something changed */
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * copy the claims and id_token from the session to the request state and optionally return them
 */
static void oidc_copy_tokens_to_request_state(request_rec *r,
		oidc_session_t *session, const char **s_id_token, const char **s_claims) {

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
static apr_byte_t oidc_session_pass_tokens_and_save(request_rec *r,
		oidc_cfg *cfg, oidc_session_t *session, apr_byte_t needs_save) {

	apr_byte_t pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	apr_byte_t pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);

	/* set the refresh_token in the app headers/variables, if enabled for this location/directory */
	const char *refresh_token = oidc_session_get_refresh_token(r, session);
	if ((oidc_cfg_dir_pass_refresh_token(r) != 0) && (refresh_token != NULL)) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_REFRESH_TOKEN, refresh_token,
				OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
	}

	/* set the access_token in the app headers/variables */
	const char *access_token = oidc_session_get_access_token(r, session);
	if (access_token != NULL) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN, access_token,
				OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
	}

	/* set the expiry timestamp in the app headers/variables */
	const char *access_token_expires = oidc_session_get_access_token_expires(r,
			session);
	if (access_token_expires != NULL) {
		/* pass it to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN_EXP,
				access_token_expires,
				OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
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
		needs_save = TRUE;
	}

	/* log message about session expiry */
	oidc_log_session_expires(r, "session inactivity timeout", session->expiry);

	/* check if something was updated in the session and we need to save it again */
	if (needs_save)
		if (oidc_session_save(r, session, FALSE) == FALSE)
			return FALSE;

	return TRUE;
}

static apr_byte_t oidc_refresh_access_token_before_expiry(request_rec *r,
		oidc_cfg *cfg, oidc_session_t *session, int ttl_minimum, int logout_on_error) {

	const char *s_access_token_expires = NULL;
	apr_time_t t_expires = -1;
	oidc_provider_t *provider = NULL;

	oidc_debug(r, "ttl_minimum=%d", ttl_minimum);

	if (ttl_minimum < 0)
		return FALSE;

	s_access_token_expires = oidc_session_get_access_token_expires(r, session);
	if (s_access_token_expires == NULL) {
		oidc_debug(r,
				"no access token expires_in stored in the session (i.e. returned from in the authorization response), so cannot refresh the access token based on TTL requirement");
		return FALSE;
	}

	if (oidc_session_get_refresh_token(r, session) == NULL) {
		oidc_debug(r,
				"no refresh token stored in the session, so cannot refresh the access token based on TTL requirement");
		return FALSE;
	}

	if (sscanf(s_access_token_expires, "%" APR_TIME_T_FMT, &t_expires) != 1) {
		oidc_error(r, "could not parse s_access_token_expires %s",
				s_access_token_expires);
		return FALSE;
	}

	t_expires = apr_time_from_sec(t_expires - ttl_minimum);

	oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds",
			apr_time_sec(t_expires - apr_time_now()));

	if (t_expires > apr_time_now())
		return FALSE;

	if (oidc_get_provider_from_session(r, cfg, session, &provider) == FALSE)
		return FALSE;

	if (oidc_refresh_access_token(r, cfg, session, provider,
			NULL) == FALSE) {
		oidc_warn(r, "access_token could not be refreshed, logout=%d", logout_on_error & OIDC_LOGOUT_ON_ERROR_REFRESH);
		if (logout_on_error & OIDC_LOGOUT_ON_ERROR_REFRESH)
			return ERROR;
		else
			return FALSE;
	}

	return TRUE;
}

/*
 * handle the case where we have identified an existing authentication session for a user
 */
static int oidc_handle_existing_session(request_rec *r, oidc_cfg *cfg,
		oidc_session_t *session) {

	oidc_debug(r, "enter");

	/* track if the session needs to be updated/saved into the cache */
	apr_byte_t needs_save = FALSE;

	/* set the user in the main request for further (incl. sub-request) processing */
	r->user = apr_pstrdup(r->pool, session->remote_user);
	oidc_debug(r, "set remote_user to \"%s\"", r->user);

	/* get the header name in which the remote user name needs to be passed */
	char *authn_header = oidc_cfg_dir_authn_header(r);
	apr_byte_t pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	apr_byte_t pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);

	/* verify current cookie domain against issued cookie domain */
	if (oidc_check_cookie_domain(r, cfg, session) == FALSE)
		return HTTP_UNAUTHORIZED;

	/* check if the maximum session duration was exceeded */
	int rc = oidc_check_max_session_duration(r, cfg, session);
	if (rc != OK)
		return rc;

	/* if needed, refresh the access token */
	needs_save = oidc_refresh_access_token_before_expiry(r, cfg, session,
			oidc_cfg_dir_refresh_access_token_before_expiry(r),
			oidc_cfg_dir_logout_on_error_refresh(r));
	if (needs_save == ERROR)
		return oidc_handle_logout_request(r, cfg, session, cfg->default_slo_url);

	/* if needed, refresh claims from the user info endpoint */
	if (oidc_refresh_claims_from_userinfo_endpoint(r, cfg, session) == TRUE)
		needs_save = TRUE;

	/*
	 * we're going to pass the information that we have to the application,
	 * but first we need to scrub the headers that we're going to use for security reasons
	 */
	oidc_scrub_headers(r);

	/* set the user authentication HTTP header if set and required */
	if ((r->user != NULL) && (authn_header != NULL))
		oidc_util_hdr_in_set(r, authn_header, r->user);

	const char *s_claims = NULL;
	const char *s_id_token = NULL;

	/* copy id_token and claims from session to request state and obtain their values */
	oidc_copy_tokens_to_request_state(r, session, &s_id_token, &s_claims);

	if ((cfg->pass_userinfo_as & OIDC_PASS_USERINFO_AS_CLAIMS)) {
		/* set the userinfo claims in the app headers */
		if (oidc_set_app_claims(r, cfg, session, s_claims) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((cfg->pass_userinfo_as & OIDC_PASS_USERINFO_AS_JSON_OBJECT)) {
		/* pass the userinfo JSON object to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_USERINFO_JSON, s_claims,
				OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
	}

	if ((cfg->pass_userinfo_as & OIDC_PASS_USERINFO_AS_JWT)) {
		if (cfg->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
			/* get the compact serialized JWT from the session */
			const char *s_userinfo_jwt = oidc_session_get_userinfo_jwt(r,
					session);
			if (s_userinfo_jwt != NULL) {
				/* pass the compact serialized JWT to the app in a header or environment variable */
				oidc_util_set_app_info(r, OIDC_APP_INFO_USERINFO_JWT,
						s_userinfo_jwt,
						OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
			} else {
				oidc_debug(r,
						"configured to pass userinfo in a JWT, but no such JWT was found in the session (probably no such JWT was returned from the userinfo endpoint)");
			}
		} else {
			oidc_error(r,
					"session type \"client-cookie\" does not allow storing/passing a userinfo JWT; use \"" OIDCSessionType " server-cache\" for that");
		}
	}

	if ((cfg->pass_idtoken_as & OIDC_PASS_IDTOKEN_AS_CLAIMS)) {
		/* set the id_token in the app headers */
		if (oidc_set_app_claims(r, cfg, session, s_id_token) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((cfg->pass_idtoken_as & OIDC_PASS_IDTOKEN_AS_PAYLOAD)) {
		/* pass the id_token JSON object to the app in a header or environment variable */
		oidc_util_set_app_info(r, OIDC_APP_INFO_ID_TOKEN_PAYLOAD, s_id_token,
				OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
	}

	if ((cfg->pass_idtoken_as & OIDC_PASS_IDTOKEN_AS_SERIALIZED)) {
		if (cfg->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
			/* get the compact serialized JWT from the session */
			const char *s_id_token = oidc_session_get_idtoken(r, session);
			/* pass the compact serialized JWT to the app in a header or environment variable */
			oidc_util_set_app_info(r, OIDC_APP_INFO_ID_TOKEN, s_id_token,
					OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
		} else {
			oidc_error(r,
					"session type \"client-cookie\" does not allow storing/passing the id_token; use \"" OIDCSessionType " server-cache\" for that");
		}
	}

	/* pass the at, rt and at expiry to the application, possibly update the session expiry and save the session */
	if (oidc_session_pass_tokens_and_save(r, cfg, session, needs_save) == FALSE)
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
		oidc_cfg *c, const char *state, struct oidc_provider_t **provider,
		oidc_proto_state_t **proto_state) {

	oidc_debug(r, "enter (state=%s)", state);

	if ((state == NULL) || (apr_strnatcmp(state, "") == 0)) {
		oidc_error(r, "state parameter is not set");
		return FALSE;
	}

	/* check the state parameter against what we stored in a cookie */
	if (oidc_restore_proto_state(r, c, state, proto_state) == FALSE) {
		oidc_error(r, "unable to restore state");
		return FALSE;
	}

	*provider = oidc_get_provider_for_issuer(r, c,
			oidc_proto_state_get_issuer(*proto_state), FALSE);

	return (*provider != NULL);
}

/*
 * redirect the browser to the session logout endpoint
 */
static int oidc_session_redirect_parent_window_to_logout(request_rec *r,
		oidc_cfg *c) {

	oidc_debug(r, "enter");

	char *java_script = apr_psprintf(r->pool,
			"    <script type=\"text/javascript\">\n"
			"      window.top.location.href = '%s?session=logout';\n"
			"    </script>\n", oidc_get_redirect_uri(r, c));

	return oidc_util_html_send(r, "Redirecting...", java_script, NULL, NULL,
			OK);
}

/*
 * handle an error returned by the OP
 */
static int oidc_authorization_response_error(request_rec *r, oidc_cfg *c,
		oidc_proto_state_t *proto_state, const char *error,
		const char *error_description) {
	const char *prompt = oidc_proto_state_get_prompt(proto_state);
	if (prompt != NULL)
		prompt = apr_pstrdup(r->pool, prompt);
	oidc_proto_state_destroy(proto_state);
	if ((prompt != NULL)
			&& (apr_strnatcmp(prompt, OIDC_PROTO_PROMPT_NONE) == 0)) {
		return oidc_session_redirect_parent_window_to_logout(r, c);
	}
	return oidc_util_html_send_error(r, c->error_template,
			apr_psprintf(r->pool, "OpenID Connect Provider error: %s", error),
			error_description, OK);
}

/*
 * get the r->user for this request based on the configuration for OIDC/OAuth
 */
apr_byte_t oidc_get_remote_user(request_rec *r, const char *claim_name,
		const char *reg_exp, const char *replace, json_t *json,
		char **request_user) {

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

			if (oidc_util_regexp_first_match(r->pool, *request_user, reg_exp,
					request_user, &error_str) == FALSE) {
				oidc_error(r, "oidc_util_regexp_first_match failed: %s",
						error_str);
				*request_user = NULL;
				return FALSE;
			}

		} else if (oidc_util_regexp_substitute(r->pool, *request_user, reg_exp,
				replace, request_user, &error_str) == FALSE) {

			oidc_error(r, "oidc_util_regexp_substitute failed: %s", error_str);
			*request_user = NULL;
			return FALSE;
		}

	}

	return TRUE;
}

/*
 * set the unique user identifier that will be propagated in the Apache r->user and REMOTE_USER variables
 */
static apr_byte_t oidc_set_request_user(request_rec *r, oidc_cfg *c,
		oidc_provider_t *provider, oidc_jwt_t *jwt, const char *s_claims) {

	char *issuer = provider->issuer;
	char *claim_name = apr_pstrdup(r->pool, c->remote_user_claim.claim_name);
	int n = strlen(claim_name);
	apr_byte_t post_fix_with_issuer = (claim_name[n - 1] == OIDC_CHAR_AT);
	if (post_fix_with_issuer == TRUE) {
		claim_name[n - 1] = '\0';
		issuer =
				(strstr(issuer, "https://") == NULL) ?
						apr_pstrdup(r->pool, issuer) :
						apr_pstrdup(r->pool, issuer + strlen("https://"));
	}

	/* extract the username claim (default: "sub") from the id_token payload or user claims */
	apr_byte_t rc = FALSE;
	char *remote_user = NULL;
	json_t *claims = NULL;
	oidc_util_decode_json_object(r, s_claims, &claims);
	if (claims == NULL) {
		rc = oidc_get_remote_user(r, claim_name, c->remote_user_claim.reg_exp,
				c->remote_user_claim.replace, jwt->payload.value.json,
				&remote_user);
	} else {
		oidc_util_json_merge(r, jwt->payload.value.json, claims);
		rc = oidc_get_remote_user(r, claim_name, c->remote_user_claim.reg_exp,
				c->remote_user_claim.replace, claims, &remote_user);
		json_decref(claims);
	}

	if ((rc == FALSE) || (remote_user == NULL)) {
		oidc_error(r,
				"" OIDCRemoteUserClaim "is set to \"%s\", but could not set the remote user based on the requested claim \"%s\" and the available claims for the user",
				c->remote_user_claim.claim_name, claim_name);
		return FALSE;
	}

	if (post_fix_with_issuer == TRUE)
		remote_user = apr_psprintf(r->pool, "%s%s%s", remote_user, OIDC_STR_AT,
				issuer);

	r->user = apr_pstrdup(r->pool, remote_user);

	oidc_debug(r, "set remote_user to \"%s\" based on claim: \"%s\"%s", r->user,
			c->remote_user_claim.claim_name,
			c->remote_user_claim.reg_exp ?
					apr_psprintf(r->pool,
							" and expression: \"%s\" and replace string: \"%s\"",
							c->remote_user_claim.reg_exp,
							c->remote_user_claim.replace) :
							"");

	return TRUE;
}

static char *oidc_make_sid_iss_unique(request_rec *r, const char *sid,
		const char *issuer) {
	return apr_psprintf(r->pool, "%s@%s", sid, issuer);
}

/*
 * store resolved information in the session
 */
static apr_byte_t oidc_save_in_session(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, oidc_provider_t *provider,
		const char *remoteUser, const char *id_token, oidc_jwt_t *id_token_jwt,
		const char *claims, const char *access_token, const int expires_in,
		const char *refresh_token, const char *session_state, const char *state,
		const char *original_url, const char *userinfo_jwt) {

	/* store the user in the session */
	session->remote_user = remoteUser;

	/* set the session expiry to the inactivity timeout */
	session->expiry =
			apr_time_now() + apr_time_from_sec(c->session_inactivity_timeout);

	/* store the claims payload in the id_token for later reference */
	oidc_session_set_idtoken_claims(r, session,
			id_token_jwt->payload.value.str);

	if (c->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
		/* store the compact serialized representation of the id_token for later reference  */
		oidc_session_set_idtoken(r, session, id_token);
	}

	/* store the issuer in the session (at least needed for session mgmt and token refresh */
	oidc_session_set_issuer(r, session, provider->issuer);

	/* store the state and original URL in the session for handling browser-back more elegantly */
	oidc_session_set_request_state(r, session, state);
	oidc_session_set_original_url(r, session, original_url);

	if ((session_state != NULL) && (provider->check_session_iframe != NULL)) {
		/* store the session state and required parameters session management  */
		oidc_session_set_session_state(r, session, session_state);
		oidc_debug(r,
				"session management enabled: stored session_state (%s), check_session_iframe (%s) and client_id (%s) in the session",
				session_state, provider->check_session_iframe,
				provider->client_id);
	} else if (provider->check_session_iframe == NULL) {
		oidc_debug(r,
				"session management disabled: \"check_session_iframe\" is not set in provider configuration");
	} else {
		oidc_debug(r,
				"session management disabled: no \"session_state\" value is provided in the authentication response even though \"check_session_iframe\" (%s) is set in the provider configuration",
				provider->check_session_iframe);
	}

	/* store claims resolved from userinfo endpoint */
	oidc_store_userinfo_claims(r, c, session, provider, claims, userinfo_jwt);

	/* see if we have an access_token */
	if (access_token != NULL) {
		/* store the access_token in the session context */
		oidc_session_set_access_token(r, session, access_token);
		/* store the associated expires_in value */
		oidc_session_set_access_token_expires(r, session, expires_in);
		/* reset the access token refresh timestamp */
		oidc_session_reset_access_token_last_refresh(r, session);
	}

	/* see if we have a refresh_token */
	if (refresh_token != NULL) {
		/* store the refresh_token in the session context */
		oidc_session_set_refresh_token(r, session, refresh_token);
	}

	/* store max session duration in the session as a hard cut-off expiry timestamp */
	apr_time_t session_expires =
			(provider->session_max_duration == 0) ?
					apr_time_from_sec(id_token_jwt->payload.exp) :
					(apr_time_now()
							+ apr_time_from_sec(provider->session_max_duration));
	oidc_session_set_session_expires(r, session, session_expires);

	oidc_debug(r,
			"provider->session_max_duration = %d, session_expires=%" APR_TIME_T_FMT,
			provider->session_max_duration, session_expires);

	/* log message about max session duration */
	oidc_log_session_expires(r, "session max lifetime", session_expires);

	/* store the domain for which this session is valid */
	oidc_session_set_cookie_domain(r, session,
			c->cookie_domain ? c->cookie_domain : oidc_get_current_url_host(r));

	char *sid = NULL;
	oidc_debug(r, "provider->backchannel_logout_supported=%d",
			provider->backchannel_logout_supported);
	if (provider->backchannel_logout_supported > 0) {
		oidc_jose_get_string(r->pool, id_token_jwt->payload.value.json,
				OIDC_CLAIM_SID, FALSE, &sid, NULL);
		if (sid == NULL)
			sid = id_token_jwt->payload.sub;
		session->sid = oidc_make_sid_iss_unique(r, sid, provider->issuer);
	}

	/* store the session */
	return oidc_session_save(r, session, TRUE);
}

/*
 * parse the expiry for the access token
 */
static int oidc_parse_expires_in(request_rec *r, const char *expires_in) {
	if (expires_in != NULL) {
		char *ptr = NULL;
		long number = strtol(expires_in, &ptr, 10);
		if (number <= 0) {
			oidc_warn(r,
					"could not convert \"expires_in\" value (%s) to a number",
					expires_in);
			return -1;
		}
		return number;
	}
	return -1;
}

/*
 * handle the different flows (hybrid, implicit, Authorization Code)
 */
static apr_byte_t oidc_handle_flows(request_rec *r, oidc_cfg *c,
		oidc_proto_state_t *proto_state, oidc_provider_t *provider,
		apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt) {

	apr_byte_t rc = FALSE;

	const char *requested_response_type = oidc_proto_state_get_response_type(
			proto_state);

	/* handle the requested response type/mode */
	if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN)) {
		rc = oidc_proto_authorization_response_code_idtoken_token(r, c,
				proto_state, provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN)) {
		rc = oidc_proto_authorization_response_code_idtoken(r, c, proto_state,
				provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN)) {
		rc = oidc_proto_handle_authorization_response_code_token(r, c,
				proto_state, provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_CODE)) {
		rc = oidc_proto_handle_authorization_response_code(r, c, proto_state,
				provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN)) {
		rc = oidc_proto_handle_authorization_response_idtoken_token(r, c,
				proto_state, provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type,
			OIDC_PROTO_RESPONSE_TYPE_IDTOKEN)) {
		rc = oidc_proto_handle_authorization_response_idtoken(r, c, proto_state,
				provider, params, response_mode, jwt);
	} else {
		oidc_error(r, "unsupported response type: \"%s\"",
				requested_response_type);
	}

	if ((rc == FALSE) && (*jwt != NULL)) {
		oidc_jwt_destroy(*jwt);
		*jwt = NULL;
	}

	return rc;
}

/* handle the browser back on an authorization response */
static apr_byte_t oidc_handle_browser_back(request_rec *r, const char *r_state,
		oidc_session_t *session) {

	/*  see if we have an existing session and browser-back was used */
	const char *s_state = NULL, *o_url = NULL;

	if (session->remote_user != NULL) {

		s_state = oidc_session_get_request_state(r, session);
		o_url = oidc_session_get_original_url(r, session);

		if ((r_state != NULL) && (s_state != NULL)
				&& (apr_strnatcmp(r_state, s_state) == 0)) {

			/* log the browser back event detection */
			oidc_warn(r,
					"browser back detected, redirecting to original URL: %s",
					o_url);

			/* go back to the URL that he originally tried to access */
			oidc_util_hdr_out_location_set(r, o_url);

			return TRUE;
		}
	}

	return FALSE;
}

/*
 * complete the handling of an authorization response by obtaining, parsing and verifying the
 * id_token and storing the authenticated user state in the session
 */
static int oidc_handle_authorization_response(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, apr_table_t *params, const char *response_mode) {

	oidc_debug(r, "enter, response_mode=%s", response_mode);

	oidc_provider_t *provider = NULL;
	oidc_proto_state_t *proto_state = NULL;
	oidc_jwt_t *jwt = NULL;

	/* see if this response came from a browser-back event */
	if (oidc_handle_browser_back(r, apr_table_get(params, OIDC_PROTO_STATE),
			session) == TRUE)
		return HTTP_MOVED_TEMPORARILY;

	/* match the returned state parameter against the state stored in the browser */
	if (oidc_authorization_response_match_state(r, c,
			apr_table_get(params, OIDC_PROTO_STATE), &provider, &proto_state)
			== FALSE) {
		if (c->default_sso_url != NULL) {
			oidc_warn(r,
					"invalid authorization response state; a default SSO URL is set, sending the user there: %s",
					c->default_sso_url);
			oidc_util_hdr_out_location_set(r, c->default_sso_url);
			return HTTP_MOVED_TEMPORARILY;
		}
		oidc_error(r,
				"invalid authorization response state and no default SSO URL is set, sending an error...");
		// if content was already returned via html/http send then don't return 500
		// but send 200 to avoid extraneous internal error document text to be sent
		return ((r->user) && (strncmp(r->user, "", 1) == 0)) ?
				OK : HTTP_INTERNAL_SERVER_ERROR;
	}

	/* see if the response is an error response */
	if (apr_table_get(params, OIDC_PROTO_ERROR) != NULL)
		return oidc_authorization_response_error(r, c, proto_state,
				apr_table_get(params, OIDC_PROTO_ERROR),
				apr_table_get(params, OIDC_PROTO_ERROR_DESCRIPTION));

	/* handle the code, implicit or hybrid flow */
	if (oidc_handle_flows(r, c, proto_state, provider, params, response_mode,
			&jwt) == FALSE)
		return oidc_authorization_response_error(r, c, proto_state,
				"Error in handling response type.", NULL);

	if (jwt == NULL) {
		oidc_error(r, "no id_token was provided");
		return oidc_authorization_response_error(r, c, proto_state,
				"No id_token was provided.", NULL);
	}

	int expires_in = oidc_parse_expires_in(r,
			apr_table_get(params, OIDC_PROTO_EXPIRES_IN));
	char *userinfo_jwt = NULL;

	/*
	 * optionally resolve additional claims against the userinfo endpoint
	 * parsed claims are not actually used here but need to be parsed anyway for error checking purposes
	 */
	const char *claims = oidc_retrieve_claims_from_userinfo_endpoint(r, c,
			provider, apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN), NULL,
			jwt->payload.sub, &userinfo_jwt);

	/* restore the original protected URL that the user was trying to access */
	const char *original_url = oidc_proto_state_get_original_url(proto_state);
	if (original_url != NULL)
		original_url = apr_pstrdup(r->pool, original_url);
	const char *original_method = oidc_proto_state_get_original_method(
			proto_state);
	if (original_method != NULL)
		original_method = apr_pstrdup(r->pool, original_method);
	const char *prompt = oidc_proto_state_get_prompt(proto_state);

	/* set the user */
	if (oidc_set_request_user(r, c, provider, jwt, claims) == TRUE) {

		/* session management: if the user in the new response is not equal to the old one, error out */
		if ((prompt != NULL)
				&& (apr_strnatcmp(prompt, OIDC_PROTO_PROMPT_NONE) == 0)) {
			// TOOD: actually need to compare sub? (need to store it in the session separately then
			//const char *sub = NULL;
			//oidc_session_get(r, session, "sub", &sub);
			//if (apr_strnatcmp(sub, jwt->payload.sub) != 0) {
			if (apr_strnatcmp(session->remote_user, r->user) != 0) {
				oidc_warn(r,
						"user set from new id_token is different from current one");
				oidc_jwt_destroy(jwt);
				return oidc_authorization_response_error(r, c, proto_state,
						"User changed!", NULL);
			}
		}

		/* store resolved information in the session */
		if (oidc_save_in_session(r, c, session, provider, r->user,
				apr_table_get(params, OIDC_PROTO_ID_TOKEN), jwt, claims,
				apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN), expires_in,
				apr_table_get(params, OIDC_PROTO_REFRESH_TOKEN),
				apr_table_get(params, OIDC_PROTO_SESSION_STATE),
				apr_table_get(params, OIDC_PROTO_STATE), original_url,
				userinfo_jwt) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;

	} else {
		oidc_error(r, "remote user could not be set");
		return oidc_authorization_response_error(r, c, proto_state,
				"Remote user could not be set: contact the website administrator",
				NULL);
	}

	/* cleanup */
	oidc_proto_state_destroy(proto_state);
	oidc_jwt_destroy(jwt);

	/* check that we've actually authenticated a user; functions as error handling for oidc_get_remote_user */
	if (r->user == NULL)
		return HTTP_UNAUTHORIZED;

	/* log the successful response */
	oidc_debug(r,
			"session created and stored, returning to original URL: %s, original method: %s",
			original_url, original_method);

	/* check whether form post data was preserved; if so restore it */
	if (apr_strnatcmp(original_method, OIDC_METHOD_FORM_POST) == 0) {
		return oidc_request_post_preserved_restore(r, original_url);
	}

	/* now we've authenticated the user so go back to the URL that he originally tried to access */
	oidc_util_hdr_out_location_set(r, original_url);

	/* do the actual redirect to the original URL */
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * handle an OpenID Connect Authorization Response using the POST (+fragment->POST) response_mode
 */
static int oidc_handle_post_authorization_response(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {

	oidc_debug(r, "enter");

	/* initialize local variables */
	char *response_mode = NULL;

	/* read the parameters that are POST-ed to us */
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r, "something went wrong when reading the POST parameters");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* see if we've got any POST-ed data at all */
	if ((apr_table_elts(params)->nelts < 1)
			|| ((apr_table_elts(params)->nelts == 1)
					&& apr_table_get(params, OIDC_PROTO_RESPONSE_MODE)
					&& (apr_strnatcmp(
							apr_table_get(params, OIDC_PROTO_RESPONSE_MODE),
							OIDC_PROTO_RESPONSE_MODE_FRAGMENT) == 0))) {
		return oidc_util_html_send_error(r, c->error_template,
				"Invalid Request",
				"You've hit an OpenID Connect Redirect URI with no parameters, this is an invalid request; you should not open this URL in your browser directly, or have the server administrator use a different " OIDCRedirectURI " setting.",
				HTTP_INTERNAL_SERVER_ERROR);
	}

	/* get the parameters */
	response_mode = (char *) apr_table_get(params, OIDC_PROTO_RESPONSE_MODE);

	/* do the actual implicit work */
	return oidc_handle_authorization_response(r, c, session, params,
			response_mode ? response_mode : OIDC_PROTO_RESPONSE_MODE_FORM_POST);
}

/*
 * handle an OpenID Connect Authorization Response using the redirect response_mode
 */
static int oidc_handle_redirect_authorization_response(request_rec *r,
		oidc_cfg *c, oidc_session_t *session) {

	oidc_debug(r, "enter");

	/* read the parameters from the query string */
	apr_table_t *params = apr_table_make(r->pool, 8);
	oidc_util_read_form_encoded_params(r, params, r->args);

	/* do the actual work */
	return oidc_handle_authorization_response(r, c, session, params,
			OIDC_PROTO_RESPONSE_MODE_QUERY);
}

/*
 * present the user with an OP selection screen
 */
static int oidc_discovery(request_rec *r, oidc_cfg *cfg) {

	oidc_debug(r, "enter");

	/* obtain the URL we're currently accessing, to be stored in the state/session */
	char *current_url = oidc_get_current_url(r);
	const char *method = oidc_original_request_method(r, cfg, FALSE);

	/* generate CSRF token */
	char *csrf = NULL;
	if (oidc_proto_generate_nonce(r, &csrf, 8) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	char *path_scopes = oidc_dir_cfg_path_scope(r);
	char *path_auth_request_params = oidc_dir_cfg_path_auth_request_params(r);

	char *discover_url = oidc_cfg_dir_discover_url(r);
	/* see if there's an external discovery page configured */
	if (discover_url != NULL) {

		/* yes, assemble the parameters for external discovery */
		char *url = apr_psprintf(r->pool, "%s%s%s=%s&%s=%s&%s=%s&%s=%s",
				discover_url,
				strchr(discover_url, OIDC_CHAR_QUERY) != NULL ?
						OIDC_STR_AMP :
						OIDC_STR_QUERY,
						OIDC_DISC_RT_PARAM, oidc_util_escape_string(r, current_url),
						OIDC_DISC_RM_PARAM, method,
						OIDC_DISC_CB_PARAM,
						oidc_util_escape_string(r, oidc_get_redirect_uri(r, cfg)),
						OIDC_CSRF_NAME, oidc_util_escape_string(r, csrf));

		if (path_scopes != NULL)
			url = apr_psprintf(r->pool, "%s&%s=%s", url, OIDC_DISC_SC_PARAM,
					oidc_util_escape_string(r, path_scopes));
		if (path_auth_request_params != NULL)
			url = apr_psprintf(r->pool, "%s&%s=%s", url, OIDC_DISC_AR_PARAM,
					oidc_util_escape_string(r, path_auth_request_params));

		/* log what we're about to do */
		oidc_debug(r, "redirecting to external discovery page: %s", url);

		/* set CSRF cookie */
		oidc_util_set_cookie(r, OIDC_CSRF_NAME, csrf, -1,
				cfg->cookie_same_site ?
						OIDC_COOKIE_EXT_SAME_SITE_STRICT :
						OIDC_COOKIE_EXT_SAME_SITE_NONE);

		/* see if we need to preserve POST parameters through Javascript/HTML5 storage */
		if (oidc_post_preserve_javascript(r, url, NULL, NULL) == TRUE)
			return OK;

		/* do the actual redirect to an external discovery page */
		oidc_util_hdr_out_location_set(r, url);

		return HTTP_MOVED_TEMPORARILY;
	}

	/* get a list of all providers configured in the metadata directory */
	apr_array_header_t *arr = NULL;
	if (oidc_metadata_list(r, cfg, &arr) == FALSE)
		return oidc_util_html_send_error(r, cfg->error_template,
				"Configuration Error",
				"No configured providers found, contact your administrator",
				HTTP_UNAUTHORIZED);

	/* assemble a where-are-you-from IDP discovery HTML page */
	const char *s = "			<h3>Select your OpenID Connect Identity Provider</h3>\n";

	/* list all configured providers in there */
	int i;
	for (i = 0; i < arr->nelts; i++) {

		const char *issuer = ((const char**) arr->elts)[i];
		// TODO: html escape (especially & character)

		char *href = apr_psprintf(r->pool,
				"%s?%s=%s&amp;%s=%s&amp;%s=%s&amp;%s=%s",
				oidc_get_redirect_uri(r, cfg), OIDC_DISC_OP_PARAM,
				oidc_util_escape_string(r, issuer),
				OIDC_DISC_RT_PARAM, oidc_util_escape_string(r, current_url),
				OIDC_DISC_RM_PARAM, method,
				OIDC_CSRF_NAME, csrf);

		if (path_scopes != NULL)
			href = apr_psprintf(r->pool, "%s&amp;%s=%s", href,
					OIDC_DISC_SC_PARAM, oidc_util_escape_string(r, path_scopes));
		if (path_auth_request_params != NULL)
			href = apr_psprintf(r->pool, "%s&amp;%s=%s", href,
					OIDC_DISC_AR_PARAM,
					oidc_util_escape_string(r, path_auth_request_params));

		char *display =
				(strstr(issuer, "https://") == NULL) ?
						apr_pstrdup(r->pool, issuer) :
						apr_pstrdup(r->pool, issuer + strlen("https://"));

		/* strip port number */
		//char *p = strstr(display, ":");
		//if (p != NULL) *p = '\0';
		/* point back to the redirect_uri, where the selection is handled, with an IDP selection and return_to URL */
		s = apr_psprintf(r->pool, "%s<p><a href=\"%s\">%s</a></p>\n", s, href,
				display);
	}

	/* add an option to enter an account or issuer name for dynamic OP discovery */
	s = apr_psprintf(r->pool, "%s<form method=\"get\" action=\"%s\">\n", s,
			oidc_get_redirect_uri(r, cfg));
	s = apr_psprintf(r->pool,
			"%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
			OIDC_DISC_RT_PARAM, current_url);
	s = apr_psprintf(r->pool,
			"%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
			OIDC_DISC_RM_PARAM, method);
	s = apr_psprintf(r->pool,
			"%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
			OIDC_CSRF_NAME, csrf);

	if (path_scopes != NULL)
		s = apr_psprintf(r->pool,
				"%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
				OIDC_DISC_SC_PARAM, path_scopes);
	if (path_auth_request_params != NULL)
		s = apr_psprintf(r->pool,
				"%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s,
				OIDC_DISC_AR_PARAM, path_auth_request_params);

	s =
			apr_psprintf(r->pool,
					"%s<p>Or enter your account name (eg. &quot;mike@seed.gluu.org&quot;, or an IDP identifier (eg. &quot;mitreid.org&quot;):</p>\n",
					s);
	s = apr_psprintf(r->pool,
			"%s<p><input type=\"text\" name=\"%s\" value=\"%s\"></p>\n", s,
			OIDC_DISC_OP_PARAM, "");
	s = apr_psprintf(r->pool,
			"%s<p><input type=\"submit\" value=\"Submit\"></p>\n", s);
	s = apr_psprintf(r->pool, "%s</form>\n", s);

	oidc_util_set_cookie(r, OIDC_CSRF_NAME, csrf, -1,
			cfg->cookie_same_site ?
					OIDC_COOKIE_EXT_SAME_SITE_STRICT :
					OIDC_COOKIE_EXT_SAME_SITE_NONE);

	char *javascript = NULL, *javascript_method = NULL;
	char *html_head =
			"<style type=\"text/css\">body {text-align: center}</style>";
	if (oidc_post_preserve_javascript(r, NULL, &javascript,
			&javascript_method) == TRUE)
		html_head = apr_psprintf(r->pool, "%s%s", html_head, javascript);

	/* now send the HTML contents to the user agent */
	return oidc_util_html_send(r, "OpenID Connect Provider Discovery",
			html_head, javascript_method, s, OK);
}

/*
 * authenticate the user to the selected OP, if the OP is not selected yet perform discovery first
 */
static int oidc_authenticate_user(request_rec *r, oidc_cfg *c,
		oidc_provider_t *provider, const char *original_url,
		const char *login_hint, const char *id_token_hint, const char *prompt,
		const char *auth_request_params, const char *path_scope) {

	oidc_debug(r, "enter");

	if (provider == NULL) {

		// TODO: should we use an explicit redirect to the discovery endpoint (maybe a "discovery" param to the redirect_uri)?
		if (c->metadata_dir != NULL)
			return oidc_discovery(r, c);

		/* we're not using multiple OP's configured in a metadata directory, pick the statically configured OP */
		if (oidc_provider_static_config(r, c, &provider) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* generate the random nonce value that correlates requests and responses */
	char *nonce = NULL;
	if (oidc_proto_generate_nonce(r, &nonce, OIDC_PROTO_NONCE_LENGTH) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	char *pkce_state = NULL;
	char *code_challenge = NULL;

	if ((oidc_util_spaced_string_contains(r->pool, provider->response_type,
			OIDC_PROTO_CODE) == TRUE) && (provider->pkce != NULL)) {

		/* generate the code verifier value that correlates authorization requests and code exchange requests */
		if (provider->pkce->state(r, &pkce_state) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;

		/* generate the PKCE code challenge */
		if (provider->pkce->challenge(r, pkce_state, &code_challenge) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* create the state between request/response */
	oidc_proto_state_t *proto_state = oidc_proto_state_new();
	oidc_proto_state_set_original_url(proto_state, original_url);
	oidc_proto_state_set_original_method(proto_state,
			oidc_original_request_method(r, c, TRUE));
	oidc_proto_state_set_issuer(proto_state, provider->issuer);
	oidc_proto_state_set_response_type(proto_state, provider->response_type);
	oidc_proto_state_set_nonce(proto_state, nonce);
	oidc_proto_state_set_timestamp_now(proto_state);
	if (provider->response_mode)
		oidc_proto_state_set_response_mode(proto_state,
				provider->response_mode);
	if (prompt)
		oidc_proto_state_set_prompt(proto_state, prompt);
	if (pkce_state)
		oidc_proto_state_set_pkce_state(proto_state, pkce_state);

	/* get a hash value that fingerprints the browser concatenated with the random input */
	char *state = oidc_get_browser_state_hash(r, c, nonce);

	/*
	 * create state that restores the context when the authorization response comes in
	 * and cryptographically bind it to the browser
	 */
	int rc = oidc_authorization_request_set_cookie(r, c, state, proto_state);
	if (rc != HTTP_OK) {
		oidc_proto_state_destroy(proto_state);
		return rc;
	}

	/*
	 * printout errors if Cookie settings are not going to work
	 * TODO: separate this code out into its own function
	 */
	apr_uri_t o_uri;
	memset(&o_uri, 0, sizeof(apr_uri_t));
	apr_uri_t r_uri;
	memset(&r_uri, 0, sizeof(apr_uri_t));
	apr_uri_parse(r->pool, original_url, &o_uri);
	apr_uri_parse(r->pool, oidc_get_redirect_uri(r, c), &r_uri);
	if ((apr_strnatcmp(o_uri.scheme, r_uri.scheme) != 0)
			&& (apr_strnatcmp(r_uri.scheme, "https") == 0)) {
		oidc_error(r,
				"the URL scheme (%s) of the configured " OIDCRedirectURI " does not match the URL scheme of the URL being accessed (%s): the \"state\" and \"session\" cookies will not be shared between the two!",
				r_uri.scheme, o_uri.scheme);
		oidc_proto_state_destroy(proto_state);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (c->cookie_domain == NULL) {
		if (apr_strnatcmp(o_uri.hostname, r_uri.hostname) != 0) {
			char *p = strstr(o_uri.hostname, r_uri.hostname);
			if ((p == NULL) || (apr_strnatcmp(r_uri.hostname, p) != 0)) {
				oidc_error(r,
						"the URL hostname (%s) of the configured " OIDCRedirectURI " does not match the URL hostname of the URL being accessed (%s): the \"state\" and \"session\" cookies will not be shared between the two!",
						r_uri.hostname, o_uri.hostname);
				oidc_proto_state_destroy(proto_state);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
	} else {
		if (!oidc_util_cookie_domain_valid(r_uri.hostname, c->cookie_domain)) {
			oidc_error(r,
					"the domain (%s) configured in " OIDCCookieDomain " does not match the URL hostname (%s) of the URL being accessed (%s): setting \"state\" and \"session\" cookies will not work!!",
					c->cookie_domain, o_uri.hostname, original_url);
			oidc_proto_state_destroy(proto_state);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	/* send off to the OpenID Connect Provider */
	// TODO: maybe show intermediate/progress screen "redirecting to"
	return oidc_proto_authorization_request(r, provider, login_hint,
			oidc_get_redirect_uri_iss(r, c, provider), state, proto_state,
			id_token_hint, code_challenge, auth_request_params, path_scope);
}

/*
 * check if the target_link_uri matches to configuration settings to prevent an open redirect
 */
static int oidc_target_link_uri_matches_configuration(request_rec *r,
		oidc_cfg *cfg, const char *target_link_uri) {

	apr_uri_t o_uri;
	apr_uri_parse(r->pool, target_link_uri, &o_uri);
	if (o_uri.hostname == NULL) {
		oidc_error(r,
				"could not parse the \"target_link_uri\" (%s) in to a valid URL: aborting.",
				target_link_uri);
		return FALSE;
	}

	apr_uri_t r_uri;
	apr_uri_parse(r->pool, oidc_get_redirect_uri(r, cfg), &r_uri);

	if (cfg->cookie_domain == NULL) {
		/* cookie_domain set: see if the target_link_uri matches the redirect_uri host (because the session cookie will be set host-wide) */
		if (apr_strnatcmp(o_uri.hostname, r_uri.hostname) != 0) {
			char *p = strstr(o_uri.hostname, r_uri.hostname);
			if ((p == NULL) || (apr_strnatcmp(r_uri.hostname, p) != 0)) {
				oidc_error(r,
						"the URL hostname (%s) of the configured " OIDCRedirectURI " does not match the URL hostname of the \"target_link_uri\" (%s): aborting to prevent an open redirect.",
						r_uri.hostname, o_uri.hostname);
				return FALSE;
			}
		}
	} else {
		/* cookie_domain set: see if the target_link_uri is within the cookie_domain */
		char *p = strstr(o_uri.hostname, cfg->cookie_domain);
		if ((p == NULL) || (apr_strnatcmp(cfg->cookie_domain, p) != 0)) {
			oidc_error(r,
					"the domain (%s) configured in " OIDCCookieDomain " does not match the URL hostname (%s) of the \"target_link_uri\" (%s): aborting to prevent an open redirect.",
					cfg->cookie_domain, o_uri.hostname, target_link_uri);
			return FALSE;
		}
	}

	/* see if the cookie_path setting matches the target_link_uri path */
	char *cookie_path = oidc_cfg_dir_cookie_path(r);
	if (cookie_path != NULL) {
		char *p = (o_uri.path != NULL) ? strstr(o_uri.path, cookie_path) : NULL;
		if ((p == NULL) || (p != o_uri.path)) {
			oidc_error(r,
					"the path (%s) configured in " OIDCCookiePath " does not match the URL path (%s) of the \"target_link_uri\" (%s): aborting to prevent an open redirect.",
					cfg->cookie_domain, o_uri.path, target_link_uri);
			return FALSE;
		} else if (strlen(o_uri.path) > strlen(cookie_path)) {
			int n = strlen(cookie_path);
			if (cookie_path[n - 1] == OIDC_CHAR_FORWARD_SLASH)
				n--;
			if (o_uri.path[n] != OIDC_CHAR_FORWARD_SLASH) {
				oidc_error(r,
						"the path (%s) configured in " OIDCCookiePath " does not match the URL path (%s) of the \"target_link_uri\" (%s): aborting to prevent an open redirect.",
						cfg->cookie_domain, o_uri.path, target_link_uri);
				return FALSE;
			}
		}
	}
	return TRUE;
}

/*
 * handle a response from an IDP discovery page and/or handle 3rd-party initiated SSO
 */
static int oidc_handle_discovery_response(request_rec *r, oidc_cfg *c) {

	/* variables to hold the values returned in the response */
	char *issuer = NULL, *target_link_uri = NULL, *login_hint = NULL,
			*auth_request_params = NULL, *csrf_cookie, *csrf_query = NULL,
			*user = NULL, *path_scopes;
	oidc_provider_t *provider = NULL;

	oidc_util_get_request_parameter(r, OIDC_DISC_OP_PARAM, &issuer);
	oidc_util_get_request_parameter(r, OIDC_DISC_USER_PARAM, &user);
	oidc_util_get_request_parameter(r, OIDC_DISC_RT_PARAM, &target_link_uri);
	oidc_util_get_request_parameter(r, OIDC_DISC_LH_PARAM, &login_hint);
	oidc_util_get_request_parameter(r, OIDC_DISC_SC_PARAM, &path_scopes);
	oidc_util_get_request_parameter(r, OIDC_DISC_AR_PARAM,
			&auth_request_params);
	oidc_util_get_request_parameter(r, OIDC_CSRF_NAME, &csrf_query);
	csrf_cookie = oidc_util_get_cookie(r, OIDC_CSRF_NAME);

	/* do CSRF protection if not 3rd party initiated SSO */
	if (csrf_cookie) {

		/* clean CSRF cookie */
		oidc_util_set_cookie(r, OIDC_CSRF_NAME, "", 0, NULL);

		/* compare CSRF cookie value with query parameter value */
		if ((csrf_query == NULL)
				|| apr_strnatcmp(csrf_query, csrf_cookie) != 0) {
			oidc_warn(r,
					"CSRF protection failed, no Discovery and dynamic client registration will be allowed");
			csrf_cookie = NULL;
		}
	}

	// TODO: trim issuer/accountname/domain input and do more input validation

	oidc_debug(r,
			"issuer=\"%s\", target_link_uri=\"%s\", login_hint=\"%s\", user=\"%s\"",
			issuer, target_link_uri, login_hint, user);

	if (target_link_uri == NULL) {
		if (c->default_sso_url == NULL) {
			return oidc_util_html_send_error(r, c->error_template,
					"Invalid Request",
					"SSO to this module without specifying a \"target_link_uri\" parameter is not possible because " OIDCDefaultURL " is not set.",
					HTTP_INTERNAL_SERVER_ERROR);
		}
		target_link_uri = c->default_sso_url;
	}

	/* do open redirect prevention */
	if (oidc_target_link_uri_matches_configuration(r, c,
			target_link_uri) == FALSE) {
		return oidc_util_html_send_error(r, c->error_template,
				"Invalid Request",
				"\"target_link_uri\" parameter does not match configuration settings, aborting to prevent an open redirect.",
				HTTP_UNAUTHORIZED);
	}

	/* see if this is a static setup */
	if (c->metadata_dir == NULL) {
		if ((oidc_provider_static_config(r, c, &provider) == TRUE)
				&& (issuer != NULL)) {
			if (apr_strnatcmp(provider->issuer, issuer) != 0) {
				return oidc_util_html_send_error(r, c->error_template,
						"Invalid Request",
						apr_psprintf(r->pool,
								"The \"iss\" value must match the configured providers' one (%s != %s).",
								issuer, c->provider.issuer),
								HTTP_INTERNAL_SERVER_ERROR);
			}
		}
		return oidc_authenticate_user(r, c, NULL, target_link_uri, login_hint,
				NULL, NULL, auth_request_params, path_scopes);
	}

	/* find out if the user entered an account name or selected an OP manually */
	if (user != NULL) {

		if (login_hint == NULL)
			login_hint = apr_pstrdup(r->pool, user);

		/* normalize the user identifier */
		if (strstr(user, "https://") != user)
			user = apr_psprintf(r->pool, "https://%s", user);

		/* got an user identifier as input, perform OP discovery with that */
		if (oidc_proto_url_based_discovery(r, c, user, &issuer) == FALSE) {

			/* something did not work out, show a user facing error */
			return oidc_util_html_send_error(r, c->error_template,
					"Invalid Request",
					"Could not resolve the provided user identifier to an OpenID Connect provider; check your syntax.",
					HTTP_NOT_FOUND);
		}

		/* issuer is set now, so let's continue as planned */

	} else if (strstr(issuer, OIDC_STR_AT) != NULL) {

		if (login_hint == NULL) {
			login_hint = apr_pstrdup(r->pool, issuer);
			//char *p = strstr(issuer, OIDC_STR_AT);
			//*p = '\0';
		}

		/* got an account name as input, perform OP discovery with that */
		if (oidc_proto_account_based_discovery(r, c, issuer, &issuer) == FALSE) {

			/* something did not work out, show a user facing error */
			return oidc_util_html_send_error(r, c->error_template,
					"Invalid Request",
					"Could not resolve the provided account name to an OpenID Connect provider; check your syntax.",
					HTTP_NOT_FOUND);
		}

		/* issuer is set now, so let's continue as planned */

	}

	/* strip trailing '/' */
	int n = strlen(issuer);
	if (issuer[n - 1] == OIDC_CHAR_FORWARD_SLASH)
		issuer[n - 1] = '\0';

	/* try and get metadata from the metadata directories for the selected OP */
	if ((oidc_metadata_get(r, c, issuer, &provider, csrf_cookie != NULL) == TRUE)
			&& (provider != NULL)) {

		/* now we've got a selected OP, send the user there to authenticate */
		return oidc_authenticate_user(r, c, provider, target_link_uri,
				login_hint, NULL, NULL, auth_request_params, path_scopes);
	}

	/* something went wrong */
	return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
			"Could not find valid provider metadata for the selected OpenID Connect provider; contact the administrator",
			HTTP_NOT_FOUND);
}

static apr_uint32_t oidc_transparent_pixel[17] = { 0x474e5089, 0x0a1a0a0d,
		0x0d000000, 0x52444849, 0x01000000, 0x01000000, 0x00000408, 0x0c1cb500,
		0x00000002, 0x4144490b, 0x639c7854, 0x0000cffa, 0x02010702, 0x71311c9a,
		0x00000000, 0x444e4549, 0x826042ae };

static apr_byte_t oidc_is_front_channel_logout(const char *logout_param_value) {
	return ((logout_param_value != NULL)
			&& ((apr_strnatcmp(logout_param_value,
					OIDC_GET_STYLE_LOGOUT_PARAM_VALUE) == 0)
					|| (apr_strnatcmp(logout_param_value,
							OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE) == 0)));
}

static apr_byte_t oidc_is_back_channel_logout(const char *logout_param_value) {
	return ((logout_param_value != NULL) && (apr_strnatcmp(logout_param_value,
			OIDC_BACKCHANNEL_STYLE_LOGOUT_PARAM_VALUE) == 0));
}

/*
 * revoke refresh token and access token stored in the session if the
 * OP has an RFC 7009 compliant token revocation endpoint
 */
static void oidc_revoke_tokens(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {

	char *response = NULL;
	char *basic_auth = NULL;
	char *bearer_auth = NULL;
	apr_table_t *params = NULL;
	const char *token = NULL;
	oidc_provider_t *provider = NULL;

	oidc_debug(r, "enter");

	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE)
		goto out;

	oidc_debug(r, "revocation_endpoint=%s",
			provider->revocation_endpoint_url ?
					provider->revocation_endpoint_url : "(null)");

	if (provider->revocation_endpoint_url == NULL)
		goto out;

	params = apr_table_make(r->pool, 4);

	// add the token endpoint authentication credentials to the revocation endpoint call...
	if (oidc_proto_token_endpoint_auth(r, c, provider->token_endpoint_auth,
			provider->client_id, provider->client_secret,
			provider->client_signing_keys, provider->token_endpoint_url, params,
			NULL, &basic_auth, &bearer_auth) == FALSE)
		goto out;

	// TODO: use oauth.ssl_validate_server ...
	token = oidc_session_get_refresh_token(r, session);
	if (token != NULL) {
		apr_table_addn(params, "token_type_hint", "refresh_token");
		apr_table_addn(params, "token", token);

		if (oidc_util_http_post_form(r, provider->revocation_endpoint_url,
				params, basic_auth, bearer_auth, c->oauth.ssl_validate_server,
				&response, c->http_timeout_long, c->outgoing_proxy,
				oidc_dir_cfg_pass_cookies(r), NULL,
				NULL) == FALSE) {
			oidc_warn(r, "revoking refresh token failed");
		}
		apr_table_clear(params);
	}

	token = oidc_session_get_access_token(r, session);
	if (token != NULL) {
		apr_table_addn(params, "token_type_hint", "access_token");
		apr_table_addn(params, "token", token);

		if (oidc_util_http_post_form(r, provider->revocation_endpoint_url,
				params, basic_auth, bearer_auth, c->oauth.ssl_validate_server,
				&response, c->http_timeout_long, c->outgoing_proxy,
				oidc_dir_cfg_pass_cookies(r), NULL,
				NULL) == FALSE) {
			oidc_warn(r, "revoking access token failed");
		}
	}

out:

	oidc_debug(r, "leave");
}

/*
 * handle a local logout
 */
static int oidc_handle_logout_request(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, const char *url) {

	oidc_debug(r, "enter (url=%s)", url);

	/* if there's no remote_user then there's no (stored) session to kill */
	if (session->remote_user != NULL) {

		oidc_revoke_tokens(r, c, session);

		/* remove session state (cq. cache entry and cookie) */
		oidc_session_kill(r, session);
	}

	/* see if this is the OP calling us */
	if (oidc_is_front_channel_logout(url)) {

		/* set recommended cache control headers */
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_CACHE_CONTROL,
				"no-cache, no-store");
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_PRAGMA, "no-cache");
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_P3P, "CAO PSA OUR");
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_EXPIRES, "0");
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_X_FRAME_OPTIONS, "DENY");

		/* see if this is PF-PA style logout in which case we return a transparent pixel */
		const char *accept = oidc_util_hdr_in_accept_get(r);
		if ((apr_strnatcmp(url, OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE) == 0)
				|| ((accept) && strstr(accept, OIDC_CONTENT_TYPE_IMAGE_PNG))) {
			return oidc_util_http_send(r,
					(const char *) &oidc_transparent_pixel,
					sizeof(oidc_transparent_pixel), OIDC_CONTENT_TYPE_IMAGE_PNG,
					OK);
		}

		/* standard HTTP based logout: should be called in an iframe from the OP */
		return oidc_util_html_send(r, "Logged Out", NULL, NULL,
				"<p>Logged Out</p>", OK);
	}

	/* see if we don't need to go somewhere special after killing the session locally */
	if (url == NULL)
		return oidc_util_html_send(r, "Logged Out", NULL, NULL,
				"<p>Logged Out</p>", OK);

	/* send the user to the specified where-to-go-after-logout URL */
	oidc_util_hdr_out_location_set(r, url);

	return HTTP_MOVED_TEMPORARILY;
}

/*
 * handle a backchannel logout
 */
#define OIDC_EVENTS_BLOGOUT_KEY "http://schemas.openid.net/event/backchannel-logout"

static int oidc_handle_logout_backchannel(request_rec *r, oidc_cfg *cfg) {

	oidc_debug(r, "enter");

	const char *logout_token = NULL;
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	oidc_provider_t *provider = NULL;
	char *sid = NULL, *uuid = NULL;
	oidc_session_t session;
	int rc = HTTP_BAD_REQUEST;

	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r,
				"could not read POST-ed parameters to the logout endpoint");
		goto out;
	}

	logout_token = apr_table_get(params, OIDC_PROTO_LOGOUT_TOKEN);
	if (logout_token == NULL) {
		oidc_error(r,
				"backchannel lggout endpoint was called but could not find a parameter named \"%s\"",
				OIDC_PROTO_LOGOUT_TOKEN);
		goto out;
	}

	// TODO: jwk symmetric key based on provider
	// TODO: share more code with regular id_token validation and unsolicited state

	if (oidc_jwt_parse(r->pool, logout_token, &jwt,
			oidc_util_merge_symmetric_key(r->pool, cfg->private_keys, NULL),
			&err) == FALSE) {
		oidc_error(r, "oidc_jwt_parse failed: %s", oidc_jose_e2s(r->pool, err));
		goto out;
	}

	provider = oidc_get_provider_for_issuer(r, cfg, jwt->payload.iss, FALSE);
	if (provider == NULL) {
		oidc_error(r, "no provider found for issuer: %s", jwt->payload.iss);
		goto out;
	}

	// TODO: destroy the JWK used for decryption

	jwk = NULL;
	if (oidc_util_create_symmetric_key(r, provider->client_secret, 0,
			NULL, TRUE, &jwk) == FALSE)
		return FALSE;

	oidc_jwks_uri_t jwks_uri = { provider->jwks_uri,
			provider->jwks_refresh_interval, provider->ssl_validate_server };
	if (oidc_proto_jwt_verify(r, cfg, jwt, &jwks_uri,
			oidc_util_merge_symmetric_key(r->pool, NULL, jwk),
			provider->id_token_signed_response_alg) == FALSE) {

		oidc_error(r, "id_token signature could not be validated, aborting");
		goto out;
	}

	// oidc_proto_validate_idtoken would try and require a token binding cnf
	// if the policy is set to "required", so don't use that here

	if (oidc_proto_validate_jwt(r, jwt, provider->issuer, FALSE, FALSE,
			provider->idtoken_iat_slack,
			OIDC_TOKEN_BINDING_POLICY_DISABLED) == FALSE)
		goto out;

	/* verify the "aud" and "azp" values */
	if (oidc_proto_validate_aud_and_azp(r, cfg, provider,
			&jwt->payload) == FALSE)
		goto out;

	json_t *events = json_object_get(jwt->payload.value.json,
			OIDC_CLAIM_EVENTS);
	if (events == NULL) {
		oidc_error(r, "\"%s\" claim could not be found in logout token",
				OIDC_CLAIM_EVENTS);
		goto out;
	}

	json_t *blogout = json_object_get(events, OIDC_EVENTS_BLOGOUT_KEY);
	if (!json_is_object(blogout)) {
		oidc_error(r, "\"%s\" object could not be found in \"%s\" claim",
				OIDC_EVENTS_BLOGOUT_KEY, OIDC_CLAIM_EVENTS);
		goto out;
	}

	char *nonce = NULL;
	oidc_json_object_get_string(r->pool, jwt->payload.value.json,
			OIDC_CLAIM_NONCE, &nonce, NULL);
	if (nonce != NULL) {
		oidc_error(r,
				"rejecting logout request/token since it contains a \"%s\" claim",
				OIDC_CLAIM_NONCE);
		goto out;
	}

	char *jti = NULL;
	oidc_json_object_get_string(r->pool, jwt->payload.value.json,
			OIDC_CLAIM_JTI, &jti, NULL);
	if (jti != NULL) {
		char *replay = NULL;
		oidc_cache_get_jti(r, jti, &replay);
		if (replay != NULL) {
			oidc_error(r,
					"the \"%s\" value (%s) passed in logout token was found in the cache already; possible replay attack!?",
					OIDC_CLAIM_JTI, jti);
			goto out;
		}
	}

	/* jti cache duration is the configured replay prevention window for token issuance plus 10 seconds for safety */
	apr_time_t jti_cache_duration = apr_time_from_sec(
			provider->idtoken_iat_slack * 2 + 10);

	/* store it in the cache for the calculated duration */
	oidc_cache_set_jti(r, jti, jti, apr_time_now() + jti_cache_duration);

	oidc_json_object_get_string(r->pool, jwt->payload.value.json,
			OIDC_CLAIM_EVENTS, &sid, NULL);

	// TODO: by-spec we should cater for the fact that "sid" has been provided
	//       in the id_token returned in the authentication request, but "sub"
	//       is used in the logout token but that requires a 2nd entry in the
	//       cache and a separate session "sub" member, ugh; we'll just assume
	//       that is "sid" is specified in the id_token, the OP will actually use
	//       this for logout
	//       (and probably call us multiple times or the same sub if needed)

	oidc_json_object_get_string(r->pool, jwt->payload.value.json,
			OIDC_CLAIM_SID, &sid, NULL);
	if (sid == NULL)
		sid = jwt->payload.sub;

	if (sid == NULL) {
		oidc_error(r, "no \"sub\" and no \"sid\" claim found in logout token");
		goto out;
	}

	// TODO: when dealing with sub instead of a true sid, we'll be killing all sessions for
	//       a specific user, across hosts that share the *same* cache backend
	//       if those hosts haven't been configured with a different OIDCCryptoPassphrase
	//       - perhaps that's even acceptable since non-memory caching is encrypted by default
	//         and memory-based caching doesn't suffer from this (different shm segments)?
	//       - it will result in 400 errors returned from backchannel logout calls to the other hosts...

	sid = oidc_make_sid_iss_unique(r, sid, provider->issuer);
	oidc_cache_get_sid(r, sid, &uuid);
	if (uuid == NULL) {
		oidc_error(r,
				"could not find session based on sid/sub provided in logout token: %s",
				sid);
		// return HTTP 200 according to (new?) spec and terminate early
		// to avoid Apache returning auth/authz error 500 for the redirect URI
		rc = DONE;
		goto out;
	}

	// revoke tokens if we can get a handle on those
	if (cfg->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
		if (oidc_session_load_cache_by_uuid(r, cfg, uuid, &session) != FALSE)
			if (oidc_session_extract(r, &session) != FALSE)
				oidc_revoke_tokens(r, cfg, &session);
	}

	// clear the session cache
	oidc_cache_set_sid(r, sid, NULL, 0);
	oidc_cache_set_session(r, uuid, NULL, 0);

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

	return rc;
}

static apr_byte_t oidc_validate_post_logout_url(request_rec *r, const char *url,
		char **err_str, char **err_desc) {
	apr_uri_t uri;
	const char *c_host = NULL;

	if (apr_uri_parse(r->pool, url, &uri) != APR_SUCCESS) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(r->pool, "Logout URL malformed: %s", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	c_host = oidc_get_current_url_host(r);
	if ((uri.hostname != NULL)
			&& ((strstr(c_host, uri.hostname) == NULL)
					|| (strstr(uri.hostname, c_host) == NULL))) {
		*err_str = apr_pstrdup(r->pool, "Invalid Request");
		*err_desc =
				apr_psprintf(r->pool,
						"logout value \"%s\" does not match the hostname of the current request \"%s\"",
						apr_uri_unparse(r->pool, &uri, 0), c_host);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	} else if ((uri.hostname == NULL) && (strstr(url, "/") != url)) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc =
				apr_psprintf(r->pool,
						"No hostname was parsed and it does not seem to be relative, i.e starting with '/': %s",
						url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
        } else if ((uri.hostname == NULL) && (strstr(url, "//") == url)) {
                *err_str = apr_pstrdup(r->pool, "Malformed URL");
                *err_desc =
                                apr_psprintf(r->pool,
                                                "No hostname was parsed and starting with '//': %s",
                                                url);
                oidc_error(r, "%s: %s", *err_str, *err_desc);
                return FALSE;
        } else if ((uri.hostname == NULL) && (strstr(url, "/\\") == url)) {
                *err_str = apr_pstrdup(r->pool, "Malformed URL");
                *err_desc =
                                apr_psprintf(r->pool,
                                                "No hostname was parsed and starting with '/\\': %s",
                                                url);
                oidc_error(r, "%s: %s", *err_str, *err_desc);
                return FALSE;
	}

	/* validate the URL to prevent HTTP header splitting */
	if (((strstr(url, "\n") != NULL) || strstr(url, "\r") != NULL)) {
		*err_str = apr_pstrdup(r->pool, "Invalid Request");
		*err_desc =
				apr_psprintf(r->pool,
						"logout value \"%s\" contains illegal \"\n\" or \"\r\" character(s)",
						url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	return TRUE;
}

/*
 * perform (single) logout
 */
static int oidc_handle_logout(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {

	oidc_provider_t *provider = NULL;
	/* pickup the command or URL where the user wants to go after logout */
	char *url = NULL;
	char *error_str = NULL;
	char *error_description = NULL;

	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_LOGOUT, &url);

	oidc_debug(r, "enter (url=%s)", url);

	if (oidc_is_front_channel_logout(url)) {
		return oidc_handle_logout_request(r, c, session, url);
	} else if (oidc_is_back_channel_logout(url)) {
		return oidc_handle_logout_backchannel(r, c);
	}

	if ((url == NULL) || (apr_strnatcmp(url, "") == 0)) {

		url = c->default_slo_url;

	} else {

		/* do input validation on the logout parameter value */
		if (oidc_validate_post_logout_url(r, url, &error_str,
				&error_description) == FALSE) {
			return oidc_util_html_send_error(r, c->error_template, error_str,
					error_description,
					HTTP_BAD_REQUEST);
		}
	}

	oidc_get_provider_from_session(r, c, session, &provider);

	if ((provider != NULL) && (provider->end_session_endpoint != NULL)) {

		const char *id_token_hint = oidc_session_get_idtoken(r, session);

		char *logout_request = apr_pstrdup(r->pool,
				provider->end_session_endpoint);
		if (id_token_hint != NULL) {
			logout_request = apr_psprintf(r->pool, "%s%sid_token_hint=%s",
					logout_request, strchr(logout_request ? logout_request : "",
							OIDC_CHAR_QUERY) != NULL ?
									OIDC_STR_AMP :
									OIDC_STR_QUERY,
									oidc_util_escape_string(r, id_token_hint));
		}

		if (url != NULL) {
			logout_request = apr_psprintf(r->pool,
					"%s%spost_logout_redirect_uri=%s", logout_request,
					strchr(logout_request ? logout_request : "",
							OIDC_CHAR_QUERY) != NULL ?
									OIDC_STR_AMP :
									OIDC_STR_QUERY,
									oidc_util_escape_string(r, url));
		}
		url = logout_request;
	}

	return oidc_handle_logout_request(r, c, session, url);
}

/*
 * handle request for JWKs
 */
int oidc_handle_jwks(request_rec *r, oidc_cfg *c) {

	/* pickup requested JWKs type */
	//	char *jwks_type = NULL;
	//	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_JWKS, &jwks_type);
	char *jwks = apr_pstrdup(r->pool, "{ \"keys\" : [");
	apr_hash_index_t *hi = NULL;
	apr_byte_t first = TRUE;
	oidc_jose_error_t err;

	if (c->public_keys != NULL) {

		/* loop over the RSA public keys */
		for (hi = apr_hash_first(r->pool, c->public_keys); hi; hi =
				apr_hash_next(hi)) {

			const char *s_kid = NULL;
			oidc_jwk_t *jwk = NULL;
			char *s_json = NULL;

			apr_hash_this(hi, (const void**) &s_kid, NULL, (void**) &jwk);

			if (oidc_jwk_to_json(r->pool, jwk, &s_json, &err) == TRUE) {
				jwks = apr_psprintf(r->pool, "%s%s %s ", jwks, first ? "" : ",",
						s_json);
				first = FALSE;
			} else {
				oidc_error(r,
						"could not convert RSA JWK to JSON using oidc_jwk_to_json: %s",
						oidc_jose_e2s(r->pool, err));
			}
		}
	}

	// TODO: send stuff if first == FALSE?
	jwks = apr_psprintf(r->pool, "%s ] }", jwks);

	return oidc_util_http_send(r, jwks, strlen(jwks), OIDC_CONTENT_TYPE_JSON,
			OK);
}

static int oidc_handle_session_management_iframe_op(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, const char *check_session_iframe) {
	oidc_debug(r, "enter");
	oidc_util_hdr_out_location_set(r, check_session_iframe);
	return HTTP_MOVED_TEMPORARILY;
}

static int oidc_handle_session_management_iframe_rp(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, const char *client_id,
		const char *check_session_iframe) {

	oidc_debug(r, "enter");

	const char *java_script =
			"    <script type=\"text/javascript\">\n"
			"      var targetOrigin  = '%s';\n"
			"      var clientId  = '%s';\n"
			"      var sessionId  = '%s';\n"
			"      var loginUrl  = '%s';\n"
			"      var message = clientId + ' ' + sessionId;\n"
			"	   var timerID;\n"
			"\n"
			"      function checkSession() {\n"
			"        console.debug('checkSession: posting ' + message + ' to ' + targetOrigin);\n"
			"        var win = window.parent.document.getElementById('%s').contentWindow;\n"
			"        win.postMessage( message, targetOrigin);\n"
			"      }\n"
			"\n"
			"      function setTimer() {\n"
			"        checkSession();\n"
			"        timerID = setInterval('checkSession()', %d);\n"
			"      }\n"
			"\n"
			"      function receiveMessage(e) {\n"
			"        console.debug('receiveMessage: ' + e.data + ' from ' + e.origin);\n"
			"        if (e.origin !== targetOrigin ) {\n"
			"          console.debug('receiveMessage: cross-site scripting attack?');\n"
			"          return;\n"
			"        }\n"
			"        if (e.data != 'unchanged') {\n"
			"          clearInterval(timerID);\n"
			"          if (e.data == 'changed' && sessionId == '' ) {\n"
			"			 // 'changed' + no session: enforce a login (if we have a login url...)\n"
			"            if (loginUrl != '') {\n"
			"              window.top.location.replace(loginUrl);\n"
			"            }\n"
			"		   } else {\n"
			"              // either 'changed' + active session, or 'error': enforce a logout\n"
			"              window.top.location.replace('%s?logout=' + encodeURIComponent(window.top.location.href));\n"
			"          }\n"
			"        }\n"
			"      }\n"
			"\n"
			"      window.addEventListener('message', receiveMessage, false);\n"
			"\n"
			"    </script>\n";

	/* determine the origin for the check_session_iframe endpoint */
	char *origin = apr_pstrdup(r->pool, check_session_iframe);
	apr_uri_t uri;
	apr_uri_parse(r->pool, check_session_iframe, &uri);
	char *p = strstr(origin, uri.path);
	*p = '\0';

	/* the element identifier for the OP iframe */
	const char *op_iframe_id = "openidc-op";

	/* restore the OP session_state from the session */
	const char *session_state = oidc_session_get_session_state(r, session);
	if (session_state == NULL) {
		oidc_warn(r,
				"no session_state found in the session; the OP does probably not support session management!?");
		//return OK;
	}

	char *s_poll_interval = NULL;
	oidc_util_get_request_parameter(r, "poll", &s_poll_interval);
	int poll_interval = s_poll_interval ? strtol(s_poll_interval, NULL, 10) : 0;
	if ((poll_interval <= 0) || (poll_interval > 3600 * 24))
		poll_interval = 3000;

	char *login_uri = NULL;
	oidc_util_get_request_parameter(r, "login_uri", &login_uri);

	const char *redirect_uri = oidc_get_redirect_uri(r, c);

	java_script = apr_psprintf(r->pool, java_script, origin, client_id,
			session_state ? session_state : "", login_uri ? login_uri : "",
					op_iframe_id, poll_interval, redirect_uri, redirect_uri);

	return oidc_util_html_send(r, NULL, java_script, "setTimer", NULL, OK);
}

/*
 * handle session management request
 */
static int oidc_handle_session_management(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {
	char *cmd = NULL;
	const char *id_token_hint = NULL;
	oidc_provider_t *provider = NULL;

	/* get the command passed to the session management handler */
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_SESSION, &cmd);
	if (cmd == NULL) {
		oidc_error(r, "session management handler called with no command");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* see if this is a local logout during session management */
	if (apr_strnatcmp("logout", cmd) == 0) {
		oidc_debug(r,
				"[session=logout] calling oidc_handle_logout_request because of session mgmt local logout call.");
		return oidc_handle_logout_request(r, c, session, c->default_slo_url);
	}

	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE) {
		if ((oidc_provider_static_config(r, c, &provider) == FALSE)
				|| (provider == NULL))
			return HTTP_NOT_FOUND;
	}

	/* see if this is a request for the OP iframe */
	if (apr_strnatcmp("iframe_op", cmd) == 0) {
		if (provider->check_session_iframe != NULL) {
			return oidc_handle_session_management_iframe_op(r, c, session,
					provider->check_session_iframe);
		}
		return HTTP_NOT_FOUND;
	}

	/* see if this is a request for the RP iframe */
	if (apr_strnatcmp("iframe_rp", cmd) == 0) {
		if ((provider->client_id != NULL)
				&& (provider->check_session_iframe != NULL)) {
			return oidc_handle_session_management_iframe_rp(r, c, session,
					provider->client_id, provider->check_session_iframe);
		}
		oidc_debug(r,
				"iframe_rp command issued but no client (%s) and/or no check_session_iframe (%s) set",
				provider->client_id, provider->check_session_iframe);
		return HTTP_NOT_FOUND;
	}

	/* see if this is a request check the login state with the OP */
	if (apr_strnatcmp("check", cmd) == 0) {
		id_token_hint = oidc_session_get_idtoken(r, session);
		/*
		 * TODO: this doesn't work with per-path provided auth_request_params and scopes
		 *       as oidc_dir_cfg_path_auth_request_params and oidc_dir_cfg_path_scope will pick
		 *       those for the redirect_uri itself; do we need to store those as part of the
		 *       session now?
		 */
		return oidc_authenticate_user(r, c, provider,
				apr_psprintf(r->pool, "%s?session=iframe_rp",
						oidc_get_redirect_uri_iss(r, c, provider)), NULL,
						id_token_hint, "none", oidc_dir_cfg_path_auth_request_params(r),
						oidc_dir_cfg_path_scope(r));
	}

	/* handle failure in fallthrough */
	oidc_error(r, "unknown command: %s", cmd);

	return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * handle refresh token request
 */
static int oidc_handle_refresh_token_request(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {

	char *return_to = NULL;
	char *r_access_token = NULL;
	char *error_code = NULL;

	/* get the command passed to the session management handler */
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_REFRESH,
			&return_to);
	oidc_util_get_request_parameter(r, OIDC_PROTO_ACCESS_TOKEN,
			&r_access_token);

	/* check the input parameters */
	if (return_to == NULL) {
		oidc_error(r,
				"refresh token request handler called with no URL to return to");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (r_access_token == NULL) {
		oidc_error(r,
				"refresh token request handler called with no access_token parameter");
		error_code = "no_access_token";
		goto end;
	}

	const char *s_access_token = oidc_session_get_access_token(r, session);
	if (s_access_token == NULL) {
		oidc_error(r,
				"no existing access_token found in the session, nothing to refresh");
		error_code = "no_access_token_exists";
		goto end;
	}

	/* compare the access_token parameter used for XSRF protection */
	if (apr_strnatcmp(s_access_token, r_access_token) != 0) {
		oidc_error(r,
				"access_token passed in refresh request does not match the one stored in the session");
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
	if (oidc_refresh_access_token(r, c, session, provider, NULL) == FALSE) {
		oidc_error(r, "access_token could not be refreshed");
		error_code = "refresh_failed";
		goto end;
	}

	/* pass the tokens to the application and save the session, possibly updating the expiry */
	if (oidc_session_pass_tokens_and_save(r, c, session, TRUE) == FALSE) {
		error_code = "session_corruption";
		goto end;
	}

end:

	/* pass optional error message to the return URL */
	if (error_code != NULL)
		return_to = apr_psprintf(r->pool, "%s%serror_code=%s", return_to,
				strchr(return_to ? return_to : "", OIDC_CHAR_QUERY) ?
						OIDC_STR_AMP :
						OIDC_STR_QUERY, oidc_util_escape_string(r, error_code));

	/* add the redirect location header */
	oidc_util_hdr_out_location_set(r, return_to);

	return HTTP_MOVED_TEMPORARILY;
}

/*
 * handle request object by reference request
 */
static int oidc_handle_request_uri(request_rec *r, oidc_cfg *c) {

	char *request_ref = NULL;
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_REQUEST_URI,
			&request_ref);
	if (request_ref == NULL) {
		oidc_error(r, "no \"%s\" parameter found",
				OIDC_REDIRECT_URI_REQUEST_REQUEST_URI);
		return HTTP_BAD_REQUEST;
	}

	char *jwt = NULL;
	oidc_cache_get_request_uri(r, request_ref, &jwt);
	if (jwt == NULL) {
		oidc_error(r, "no cached JWT found for %s reference: %s",
				OIDC_REDIRECT_URI_REQUEST_REQUEST_URI, request_ref);
		return HTTP_NOT_FOUND;
	}

	oidc_cache_set_request_uri(r, request_ref, NULL, 0);

	return oidc_util_http_send(r, jwt, strlen(jwt), OIDC_CONTENT_TYPE_JWT, OK);
}

/*
 * handle a request to invalidate a cached access token introspection result
 */
int oidc_handle_remove_at_cache(request_rec *r, oidc_cfg *c) {
	char *access_token = NULL;
	oidc_util_get_request_parameter(r,
			OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE, &access_token);

	char *cache_entry = NULL;
	oidc_cache_get_access_token(r, access_token, &cache_entry);
	if (cache_entry == NULL) {
		oidc_error(r, "no cached access token found for value: %s",
				access_token);
		return HTTP_NOT_FOUND;
	}

	oidc_cache_set_access_token(r, access_token, NULL, 0);

	return OK;
}

#define OIDC_INFO_PARAM_ACCESS_TOKEN_REFRESH_INTERVAL "access_token_refresh_interval"

/*
 * handle request for session info
 */
static int oidc_handle_info_request(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {
	int rc = HTTP_UNAUTHORIZED;
	apr_byte_t needs_save = FALSE;
	char *s_format = NULL, *s_interval = NULL, *r_value = NULL;
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_INFO,
			&s_format);
	oidc_util_get_request_parameter(r,
			OIDC_INFO_PARAM_ACCESS_TOKEN_REFRESH_INTERVAL, &s_interval);

	/* see if this is a request for a format that is supported */
	if ((apr_strnatcmp(OIDC_HOOK_INFO_FORMAT_JSON, s_format) != 0)
			&& (apr_strnatcmp(OIDC_HOOK_INFO_FORMAT_HTML, s_format) != 0)) {
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
	if ((s_interval != NULL)
			&& (oidc_session_get_refresh_token(r, session) != NULL)) {

		apr_time_t t_interval;
		if (sscanf(s_interval, "%" APR_TIME_T_FMT, &t_interval) == 1) {
			t_interval = apr_time_from_sec(t_interval);

			/* get the last refresh timestamp from the session info */
			apr_time_t last_refresh =
					oidc_session_get_access_token_last_refresh(r, session);

			oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds",
					apr_time_sec(last_refresh + t_interval - apr_time_now()));

			/* see if we need to refresh again */
			if (last_refresh + t_interval < apr_time_now()) {

				/* get the current provider info */
				oidc_provider_t *provider = NULL;
				if (oidc_get_provider_from_session(r, c, session,
						&provider) == FALSE)
					return HTTP_INTERNAL_SERVER_ERROR;

				/* execute the actual refresh grant */
				if (oidc_refresh_access_token(r, c, session, provider,
						NULL) == FALSE)
					oidc_warn(r, "access_token could not be refreshed");
				else
					needs_save = TRUE;
			}
		}
	}

	/* create the JSON object */
	json_t *json = json_object();

	/* add a timestamp of creation in there for the caller */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_TIMESTAMP,
			APR_HASH_KEY_STRING)) {
		json_object_set_new(json, OIDC_HOOK_INFO_TIMESTAMP,
				json_integer(apr_time_sec(apr_time_now())));
	}

	/*
	 * refresh the claims from the userinfo endpoint
	 * side-effect is that this may refresh the access token if not already done
	 * note that OIDCUserInfoRefreshInterval should be set to control the refresh policy
	 */
	needs_save |= oidc_refresh_claims_from_userinfo_endpoint(r, c, session);

	/* include the access token in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ACCES_TOKEN,
			APR_HASH_KEY_STRING)) {
		const char *access_token = oidc_session_get_access_token(r, session);
		if (access_token != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN,
					json_string(access_token));
	}

	/* include the access token expiry timestamp in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ACCES_TOKEN_EXP,
			APR_HASH_KEY_STRING)) {
		const char *access_token_expires =
				oidc_session_get_access_token_expires(r, session);
		if (access_token_expires != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN_EXP,
					json_string(access_token_expires));
	}

	/* include the id_token claims in the session info */
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ID_TOKEN,
			APR_HASH_KEY_STRING)) {
		json_t *id_token = oidc_session_get_idtoken_claims_json(r, session);
		if (id_token)
			json_object_set_new(json, OIDC_HOOK_INFO_ID_TOKEN, id_token);
	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_USER_INFO,
			APR_HASH_KEY_STRING)) {
		/* include the claims from the userinfo endpoint the session info */
		json_t *claims = oidc_session_get_userinfo_claims_json(r, session);
		if (claims)
			json_object_set_new(json, OIDC_HOOK_INFO_USER_INFO, claims);
	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION,
			APR_HASH_KEY_STRING)) {
		json_t *j_session = json_object();
		json_object_set(j_session, OIDC_HOOK_INFO_SESSION_STATE,
				session->state);
		json_object_set_new(j_session, OIDC_HOOK_INFO_SESSION_UUID,
				json_string(session->uuid));
		json_object_set_new(j_session, OIDC_HOOK_INFO_SESSION_TIMEOUT,
				json_integer(apr_time_sec(session->expiry)));
		apr_time_t session_expires = oidc_session_get_session_expires(r,
				session);
		json_object_set_new(j_session, OIDC_HOOK_INFO_SESSION_EXP,
				json_integer(apr_time_sec(session_expires)));
		json_object_set_new(j_session, OIDC_HOOK_INFO_SESSION_REMOTE_USER,
				json_string(session->remote_user));
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION, j_session);

	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_REFRESH_TOKEN,
			APR_HASH_KEY_STRING)) {
		/* include the refresh token in the session info */
		const char *refresh_token = oidc_session_get_refresh_token(r, session);
		if (refresh_token != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_REFRESH_TOKEN,
					json_string(refresh_token));
	}

	if (apr_strnatcmp(OIDC_HOOK_INFO_FORMAT_JSON, s_format) == 0) {
		/* JSON-encode the result */
		r_value = oidc_util_encode_json_object(r, json, 0);
		/* return the stringified JSON result */
		rc = oidc_util_http_send(r, r_value, strlen(r_value),
				OIDC_CONTENT_TYPE_JSON, OK);
	} else if (apr_strnatcmp(OIDC_HOOK_INFO_FORMAT_HTML, s_format) == 0) {
		/* JSON-encode the result */
		r_value = oidc_util_encode_json_object(r, json, JSON_INDENT(2));
		rc = oidc_util_html_send(r, "Session Info", NULL, NULL,
				apr_psprintf(r->pool, "<pre>%s</pre>", r_value), OK);
	}

	/* free the allocated resources */
	json_decref(json);

	/* pass the tokens to the application and save the session, possibly updating the expiry */
	if (oidc_session_pass_tokens_and_save(r, c, session, needs_save) == FALSE) {
		oidc_warn(r, "error saving session");
		rc = HTTP_INTERNAL_SERVER_ERROR;
	}

	return rc;
}

/*
 * handle all requests to the redirect_uri
 */
int oidc_handle_redirect_uri_request(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {

	if (oidc_proto_is_redirect_authorization_response(r, c)) {

		/* this is an authorization response from the OP using the Basic Client profile or a Hybrid flow*/
		return oidc_handle_redirect_authorization_response(r, c, session);
	/*
	 *
	 * Note that we are checking for logout *before* checking for a POST authorization response
	 * to handle backchannel POST-based logout
	 *
	 * so any POST to the Redirect URI that does not have a logout query parameter will be handled
	 * as an authorization response; alternatively we could assume that a POST response has no
	 * parameters
	 */
	} else if (oidc_util_request_has_parameter(r,
			OIDC_REDIRECT_URI_REQUEST_LOGOUT)) {
		/* handle logout */
		return oidc_handle_logout(r, c, session);

	} else if (oidc_proto_is_post_authorization_response(r, c)) {

		/* this is an authorization response using the fragment(+POST) response_mode with the Implicit Client profile */
		return oidc_handle_post_authorization_response(r, c, session);

	} else if (oidc_is_discovery_response(r, c)) {

		/* this is response from the OP discovery page */
		return oidc_handle_discovery_response(r, c);

	} else if (oidc_util_request_has_parameter(r,
			OIDC_REDIRECT_URI_REQUEST_JWKS)) {

		/* handle JWKs request */
		return oidc_handle_jwks(r, c);

	} else if (oidc_util_request_has_parameter(r,
			OIDC_REDIRECT_URI_REQUEST_SESSION)) {

		/* handle session management request */
		return oidc_handle_session_management(r, c, session);

	} else if (oidc_util_request_has_parameter(r,
			OIDC_REDIRECT_URI_REQUEST_REFRESH)) {

		/* handle refresh token request */
		return oidc_handle_refresh_token_request(r, c, session);

	} else if (oidc_util_request_has_parameter(r,
			OIDC_REDIRECT_URI_REQUEST_REQUEST_URI)) {

		/* handle request object by reference request */
		return oidc_handle_request_uri(r, c);

	} else if (oidc_util_request_has_parameter(r,
			OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE)) {

		/* handle request to invalidate access token cache */
		return oidc_handle_remove_at_cache(r, c);

	} else if (oidc_util_request_has_parameter(r,
			OIDC_REDIRECT_URI_REQUEST_INFO)) {

		if (session->remote_user == NULL)
			return HTTP_UNAUTHORIZED;

		/* set r->user, set headers/env-vars, update expiry, update userinfo + AT */
		int rc = oidc_handle_existing_session(r, c, session);
		if (rc != OK)
			return rc;

		return oidc_handle_info_request(r, c, session);

	} else if ((r->args == NULL) || (apr_strnatcmp(r->args, "") == 0)) {

		/* this is a "bare" request to the redirect URI, indicating implicit flow using the fragment response_mode */
		return oidc_proto_javascript_implicit(r, c);
	}

	/* this is not an authorization response or logout request */

	/* check for "error" response */
	if (oidc_util_request_has_parameter(r, OIDC_PROTO_ERROR)) {

		//		char *error = NULL, *descr = NULL;
		//		oidc_util_get_request_parameter(r, "error", &error);
		//		oidc_util_get_request_parameter(r, "error_description", &descr);
		//
		//		/* send user facing error to browser */
		//		return oidc_util_html_send_error(r, error, descr, DONE);
		return oidc_handle_redirect_authorization_response(r, c, session);
	}

	oidc_error(r,
			"The OpenID Connect callback URL received an invalid request: %s; returning HTTP_INTERNAL_SERVER_ERROR",
			r->args);

	/* something went wrong */
	return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
			apr_psprintf(r->pool,
					"The OpenID Connect callback URL received an invalid request"),
					HTTP_INTERNAL_SERVER_ERROR);
}

#define OIDC_AUTH_TYPE_OPENID_CONNECT "openid-connect"
#define OIDC_AUTH_TYPE_OPENID_OAUTH20 "oauth20"
#define OIDC_AUTH_TYPE_OPENID_BOTH    "auth-openidc"

/*
 * main routine: handle OpenID Connect authentication
 */
static int oidc_check_userid_openidc(request_rec *r, oidc_cfg *c) {

	if (oidc_get_redirect_uri(r, c) == NULL) {
		oidc_error(r,
				"configuration error: the authentication type is set to \"" OIDC_AUTH_TYPE_OPENID_CONNECT "\" but " OIDCRedirectURI " has not been set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* check if this is a sub-request or an initial request */
	if (ap_is_initial_req(r)) {

		int rc = OK;

		/* load the session from the request state; this will be a new "empty" session if no state exists */
		oidc_session_t *session = NULL;
		oidc_session_load(r, &session);

		/* see if the initial request is to the redirect URI; this handles potential logout too */
		if (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, c))) {

			/* handle request to the redirect_uri */
			rc = oidc_handle_redirect_uri_request(r, c, session);

			/* free resources allocated for the session */
			oidc_session_free(r, session);

			return rc;

			/* initial request to non-redirect URI, check if we have an existing session */
		} else if (session->remote_user != NULL) {

			/* this is initial request and we already have a session */
			rc = oidc_handle_existing_session(r, c, session);

			/* free resources allocated for the session */
			oidc_session_free(r, session);

			/* strip any cookies that we need to */
			oidc_strip_cookies(r);

			return rc;
		}

		/* free resources allocated for the session */
		oidc_session_free(r, session);

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
			oidc_debug(r,
					"recycling user '%s' from initial request for sub-request",
					r->user);

			/*
			 * apparently request state can get lost in sub-requests, so let's see
			 * if we need to restore id_token and/or claims from the session cache
			 */
			const char *s_id_token = oidc_request_state_get(r,
					OIDC_REQUEST_STATE_KEY_IDTOKEN);
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
		 * just hit the default flow for unauthenticated users
		 */
	}

	return oidc_handle_unauthenticated_user(r, c);
}

/*
 * main routine: handle "mixed" OIDC/OAuth authentication
 */
static int oidc_check_mixed_userid_oauth(request_rec *r, oidc_cfg *c) {

	/* get the bearer access token from the Authorization header */
	const char *access_token = NULL;
	if (oidc_oauth_get_bearer_token(r, &access_token) == TRUE)
		return oidc_oauth_check_userid(r, c, access_token);

	/* no bearer token found: then treat this as a regular OIDC browser request */
	return oidc_check_userid_openidc(r, c);
}

/*
 * generic Apache authentication hook for this module: dispatches to OpenID Connect or OAuth 2.0 specific routines
 */
int oidc_check_user_id(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	/* log some stuff about the incoming HTTP request */
	oidc_debug(r, "incoming request: \"%s?%s\", ap_is_initial_req(r)=%d",
			r->parsed_uri.path, r->args, ap_is_initial_req(r));

	/* see if any authentication has been defined at all */
	if (ap_auth_type(r) == NULL)
		return DECLINED;

	/* see if we've configured OpenID Connect user authentication for this request */
	if (apr_strnatcasecmp((const char *) ap_auth_type(r),
			OIDC_AUTH_TYPE_OPENID_CONNECT) == 0)
		return oidc_check_userid_openidc(r, c);

	/* see if we've configured OAuth 2.0 access control for this request */
	if (apr_strnatcasecmp((const char *) ap_auth_type(r),
			OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0)
		return oidc_oauth_check_userid(r, c, NULL);

	/* see if we've configured "mixed mode" for this request */
	if (apr_strnatcasecmp((const char *) ap_auth_type(r),
			OIDC_AUTH_TYPE_OPENID_BOTH) == 0)
		return oidc_check_mixed_userid_oauth(r, c);

	/* this is not for us but for some other handler */
	return DECLINED;
}

/*
 * get the claims and id_token from request state
 */
static void oidc_authz_get_claims_and_idtoken(request_rec *r, json_t **claims,
		json_t **id_token) {

	const char *s_claims = oidc_request_state_get(r,
			OIDC_REQUEST_STATE_KEY_CLAIMS);
	if (s_claims != NULL)
		oidc_util_decode_json_object(r, s_claims, claims);

	const char *s_id_token = oidc_request_state_get(r,
			OIDC_REQUEST_STATE_KEY_IDTOKEN);
	if (s_id_token != NULL)
		oidc_util_decode_json_object(r, s_id_token, id_token);
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714

/*
 * find out which action we need to take when encountering an unauthorized request
 */
static authz_status oidc_handle_unauthorized_user24(request_rec *r) {

	oidc_debug(r, "enter");

	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	if (apr_strnatcasecmp((const char *) ap_auth_type(r),
			OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {
		oidc_oauth_return_www_authenticate(r, "insufficient_scope",
				"Different scope(s) or other claims required");
		return AUTHZ_DENIED;
	}

	/* see if we've configured OIDCUnAutzAction for this path */
	switch (oidc_dir_cfg_unautz_action(r)) {
	// TODO: document that AuthzSendForbiddenOnFailure is required to return 403 FORBIDDEN
	case OIDC_UNAUTZ_RETURN403:
	case OIDC_UNAUTZ_RETURN401:
		return AUTHZ_DENIED;
		break;
	case OIDC_UNAUTZ_AUTHENTICATE:
		/*
		 * exception handling: if this looks like a XMLHttpRequest call we
		 * won't redirect the user and thus avoid creating a state cookie
		 * for a non-browser (= Javascript) call that will never return from the OP
		 */
		if (oidc_is_xml_http_request(r) == TRUE)
			return AUTHZ_DENIED;
		break;
	}

	oidc_authenticate_user(r, c, NULL, oidc_get_current_url(r), NULL,
			NULL, NULL, oidc_dir_cfg_path_auth_request_params(r),
			oidc_dir_cfg_path_scope(r));

	const char *location = oidc_util_hdr_out_location_get(r);
	if (location != NULL) {
		oidc_debug(r, "send HTML refresh with authorization redirect: %s",
				location);

		char *html_head = apr_psprintf(r->pool,
				"<meta http-equiv=\"refresh\" content=\"0; url=%s\">",
				location);
		oidc_util_html_send(r, "Stepup Authentication", html_head, NULL, NULL,
				HTTP_UNAUTHORIZED);
	}

	return AUTHZ_DENIED;
}

/*
 * generic Apache >=2.4 authorization hook for this module
 * handles both OpenID Connect or OAuth 2.0 in the same way, based on the claims stored in the session
 */
authz_status oidc_authz_checker(request_rec *r, const char *require_args,
		const void *parsed_require_args,
		oidc_authz_match_claim_fn_type match_claim_fn) {

	oidc_debug(r, "enter");

	/* check for anonymous access and PASS mode */
	if (r->user != NULL && strlen(r->user) == 0) {
		r->user = NULL;
		if (oidc_dir_cfg_unauth_action(r) == OIDC_UNAUTH_PASS)
			return AUTHZ_GRANTED;
	}

	/* get the set of claims from the request state (they've been set in the authentication part earlier */
	json_t *claims = NULL, *id_token = NULL;
	oidc_authz_get_claims_and_idtoken(r, &claims, &id_token);

	/* merge id_token claims (e.g. "iss") in to claims json object */
	if (claims)
		oidc_util_json_merge(r, id_token, claims);

	/* dispatch to the >=2.4 specific authz routine */
	authz_status rc = oidc_authz_worker24(r, claims ? claims : id_token,
			require_args, parsed_require_args, match_claim_fn);

	/* cleanup */
	if (claims)
		json_decref(claims);
	if (id_token)
		json_decref(id_token);

	if ((rc == AUTHZ_DENIED) && ap_auth_type(r))
		rc = oidc_handle_unauthorized_user24(r);

	return rc;
}

authz_status oidc_authz_checker_claim(request_rec *r, const char *require_args,
		const void *parsed_require_args) {
	return oidc_authz_checker(r, require_args, parsed_require_args,
			oidc_authz_match_claim);
}

#ifdef USE_LIBJQ
authz_status oidc_authz_checker_claims_expr(request_rec *r, const char *require_args, const void *parsed_require_args) {
	return oidc_authz_checker(r, require_args, parsed_require_args, oidc_authz_match_claims_expr);
}
#endif

#else

/*
 * find out which action we need to take when encountering an unauthorized request
 */
static int oidc_handle_unauthorized_user22(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	if (apr_strnatcasecmp((const char *) ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {
		oidc_oauth_return_www_authenticate(r, "insufficient_scope", "Different scope(s) or other claims required");
		return HTTP_UNAUTHORIZED;
	}

	/* see if we've configured OIDCUnAutzAction for this path */
	switch (oidc_dir_cfg_unautz_action(r)) {
	case OIDC_UNAUTZ_RETURN403:
		return HTTP_FORBIDDEN;
	case OIDC_UNAUTZ_RETURN401:
		return HTTP_UNAUTHORIZED;
	case OIDC_UNAUTZ_AUTHENTICATE:
		/*
		 * exception handling: if this looks like a XMLHttpRequest call we
		 * won't redirect the user and thus avoid creating a state cookie
		 * for a non-browser (= Javascript) call that will never return from the OP
		 */
		if (oidc_is_xml_http_request(r) == TRUE)
			return HTTP_UNAUTHORIZED;
	}

	return oidc_authenticate_user(r, c, NULL, oidc_get_current_url(r), NULL,
			NULL, NULL, oidc_dir_cfg_path_auth_request_params(r), oidc_dir_cfg_path_scope(r));
}

/*
 * generic Apache <2.4 authorization hook for this module
 * handles both OpenID Connect and OAuth 2.0 in the same way, based on the claims stored in the request context
 */
int oidc_auth_checker(request_rec *r) {

	/* check for anonymous access and PASS mode */
	if (r->user != NULL && strlen(r->user) == 0) {
		r->user = NULL;
		if (oidc_dir_cfg_unauth_action(r) == OIDC_UNAUTH_PASS)
			return OK;
	}

	/* get the set of claims from the request state (they've been set in the authentication part earlier */
	json_t *claims = NULL, *id_token = NULL;
	oidc_authz_get_claims_and_idtoken(r, &claims, &id_token);

	/* get the Require statements */
	const apr_array_header_t * const reqs_arr = ap_requires(r);

	/* see if we have any */
	const require_line * const reqs =
			reqs_arr ? (require_line *) reqs_arr->elts : NULL;
	if (!reqs_arr) {
		oidc_debug(r,
				"no require statements found, so declining to perform authorization.");
		return DECLINED;
	}

	/* merge id_token claims (e.g. "iss") in to claims json object */
	if (claims)
		oidc_util_json_merge(r, id_token, claims);

	/* dispatch to the <2.4 specific authz routine */
	int rc = oidc_authz_worker22(r, claims ? claims : id_token, reqs,
			reqs_arr->nelts);

	/* cleanup */
	if (claims)
		json_decref(claims);
	if (id_token)
		json_decref(id_token);

	if ((rc == HTTP_UNAUTHORIZED) && ap_auth_type(r))
		rc = oidc_handle_unauthorized_user22(r);

	return rc;
}

#endif

apr_byte_t oidc_enabled(request_rec *r) {
	if (ap_auth_type(r) == NULL)
		return FALSE;

	if (apr_strnatcasecmp((const char *) ap_auth_type(r),
			OIDC_AUTH_TYPE_OPENID_CONNECT) == 0)
		return TRUE;

	if (apr_strnatcasecmp((const char *) ap_auth_type(r),
			OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0)
		return TRUE;

	if (apr_strnatcasecmp((const char *) ap_auth_type(r),
			OIDC_AUTH_TYPE_OPENID_BOTH) == 0)
		return TRUE;

	return FALSE;
}
/*
 * handle content generating requests
 */
int oidc_content_handler(request_rec *r) {
	if (oidc_enabled(r) == FALSE)
		return DECLINED;
	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	return oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, c)) ?
			OK : DECLINED;
}

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
