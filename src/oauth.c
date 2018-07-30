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
 * Copyright (C) 2017-2018 ZmartZone IAM
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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#include <apr_lib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include "mod_auth_openidc.h"
#include "parse.h"

apr_byte_t oidc_oauth_metadata_provider_retrieve(request_rec *r, oidc_cfg *cfg,
		const char *issuer, const char *url, json_t **j_metadata,
		char **response) {

	/* get provider metadata from the specified URL with the specified parameters */
	if (oidc_util_http_get(r, url, NULL, NULL, NULL,
			cfg->oauth.ssl_validate_server, response, cfg->http_timeout_short,
			cfg->outgoing_proxy, oidc_dir_cfg_pass_cookies(r),
			NULL, NULL) == FALSE)
		return FALSE;

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, *response, j_metadata) == FALSE) {
		oidc_error(r, "JSON parsing of retrieved Discovery document failed");
		return FALSE;
	}

	/* check to see if it is valid metadata */
	// TODO:
	/*
	 if (oidc_oauth_metadata_provider_is_valid(r, cfg, *j_metadata, issuer) == FALSE)
	 return FALSE;
	 */

	/* all OK */
	return TRUE;
}

static apr_byte_t oidc_oauth_provider_config(request_rec *r, oidc_cfg *c) {

	json_t *j_provider = NULL;
	char *s_json = NULL;

	/* see if we should configure a static provider based on external (cached) metadata */
	if (c->oauth.metadata_url == NULL)
		return TRUE;

	oidc_cache_get_oauth_provider(r, c->oauth.metadata_url, &s_json);

	if (s_json == NULL) {

		if (oidc_oauth_metadata_provider_retrieve(r, c, NULL,
				c->oauth.metadata_url, &j_provider, &s_json) == FALSE) {
			oidc_error(r, "could not retrieve metadata from url: %s",
					c->oauth.metadata_url);
			return FALSE;
		}

		oidc_cache_set_provider(r, c->oauth.metadata_url, s_json,
				apr_time_now() + (c->provider_metadata_refresh_interval <= 0 ? apr_time_from_sec( OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT) : c->provider_metadata_refresh_interval));

	} else {

		oidc_util_decode_json_object(r, s_json, &j_provider);

		/* check to see if it is valid metadata */
		/*
		 if (oidc_oauth_metadata_provider_is_valid(r, c, j_provider, NULL) == FALSE) {
		 oidc_error(r,
		 "cache corruption detected: invalid metadata from url: %s",
		 c->provider.metadata_url);
		 return FALSE;
		 }
		 */
	}

	if (oidc_oauth_metadata_provider_parse(r, c, j_provider) == FALSE) {
		oidc_error(r, "could not parse metadata from url: %s",
				c->oauth.metadata_url);
		if (j_provider)
			json_decref(j_provider);
		return FALSE;
	}

	json_decref(j_provider);

	return TRUE;
}

/*
 * validate an access token against the validation endpoint of the Authorization server and gets a response back
 */
static apr_byte_t oidc_oauth_validate_access_token(request_rec *r, oidc_cfg *c,
		const char *token, char **response) {

	oidc_debug(r, "enter");

	char *basic_auth = NULL;
	char *bearer_auth = NULL;

	/* assemble parameters to call the token endpoint for validation */
	apr_table_t *params = apr_table_make(r->pool, 4);

	/* add any configured extra static parameters to the introspection endpoint */
	oidc_util_table_add_query_encoded_params(r->pool, params,
			c->oauth.introspection_endpoint_params);

	/* add the access_token itself */
	apr_table_addn(params, c->oauth.introspection_token_param_name, token);

	const char *bearer_access_token_auth =
			((c->oauth.introspection_client_auth_bearer_token != NULL)
					&& strcmp(c->oauth.introspection_client_auth_bearer_token,
							"") == 0) ?
									token : c->oauth.introspection_client_auth_bearer_token;

	/* add the token endpoint authentication credentials */
	if (oidc_proto_token_endpoint_auth(r, c,
			c->oauth.introspection_endpoint_auth, c->oauth.client_id,
			c->oauth.client_secret, c->oauth.introspection_endpoint_url, params,
			bearer_access_token_auth, &basic_auth, &bearer_auth) == FALSE)
		return FALSE;

	/* call the endpoint with the constructed parameter set and return the resulting response */
	return apr_strnatcmp(c->oauth.introspection_endpoint_method,
			OIDC_INTROSPECTION_METHOD_GET) == 0 ?
					oidc_util_http_get(r, c->oauth.introspection_endpoint_url, params,
							basic_auth, bearer_auth, c->oauth.ssl_validate_server, response,
							c->http_timeout_long, c->outgoing_proxy,
							oidc_dir_cfg_pass_cookies(r),
							oidc_util_get_full_path(r->pool, c->oauth.introspection_endpoint_tls_client_cert),
							oidc_util_get_full_path(r->pool, c->oauth.introspection_endpoint_tls_client_key)) :
							oidc_util_http_post_form(r, c->oauth.introspection_endpoint_url,
									params, basic_auth, bearer_auth, c->oauth.ssl_validate_server,
									response, c->http_timeout_long, c->outgoing_proxy,
									oidc_dir_cfg_pass_cookies(r),
									oidc_util_get_full_path(r->pool, c->oauth.introspection_endpoint_tls_client_cert),
									oidc_util_get_full_path(r->pool, c->oauth.introspection_endpoint_tls_client_key));
}

/*
 * get the authorization header that should contain a bearer token
 */
apr_byte_t oidc_oauth_get_bearer_token(request_rec *r,
		const char **access_token) {

	/* get the directory specific setting on how the token can be passed in */
	apr_byte_t accept_token_in = oidc_cfg_dir_accept_token_in(r);
	const char *cookie_name = oidc_cfg_dir_accept_token_in_option(r,
			OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME);

	oidc_debug(r, "accept_token_in=%d", accept_token_in);

	*access_token = NULL;

	const apr_byte_t accept_header = (accept_token_in
			& OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER)
					|| (accept_token_in == OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT);

	if ((accept_header)
			|| (accept_token_in & OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC)) {

		/* get the authorization header */
		const char *auth_line = oidc_util_hdr_in_authorization_get(r);
		if (auth_line) {
			oidc_debug(r, "authorization header found");

			apr_byte_t known_scheme = 0;

			/* look for the Bearer keyword */
			if ((apr_strnatcasecmp(
					ap_getword(r->pool, &auth_line, OIDC_CHAR_SPACE),
					OIDC_PROTO_BEARER) == 0) && accept_header) {

				/* skip any spaces after the Bearer keyword */
				while (apr_isspace(*auth_line)) {
					auth_line++;
				}

				/* copy the result in to the access_token */
				*access_token = apr_pstrdup(r->pool, auth_line);

				known_scheme = 1;

			} else if (accept_token_in & OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC) {

				char *decoded_line;
				int decoded_len;
				if (oidc_parse_base64(r->pool, auth_line, &decoded_line,
						&decoded_len) == NULL) {
					decoded_line[decoded_len] = '\0';

					if (strchr(decoded_line, ':') != NULL) {
						/* Strip the username and colon and take just the password */
						ap_getword_nulls(r->pool, (const char**) &decoded_line,
								':');
						*access_token = decoded_line;

						known_scheme = 1;
					}
				}
			}

			if (known_scheme == 0) {
				oidc_warn(r,
						"client used unsupported authentication scheme: %s",
						r->uri);
			}
		}
	}

	if ((*access_token == NULL) && (r->method_number == M_POST)
			&& (accept_token_in & OIDC_OAUTH_ACCEPT_TOKEN_IN_POST)) {
		apr_table_t *params = apr_table_make(r->pool, 8);
		if (oidc_util_read_post_params(r, params) == TRUE) {
			*access_token = apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN);
		}
	}

	if ((*access_token == NULL)
			&& (accept_token_in & OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY)) {
		apr_table_t *params = apr_table_make(r->pool, 8);
		oidc_util_read_form_encoded_params(r, params, r->args);
		*access_token = apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN);
	}

	if ((*access_token == NULL)
			&& (accept_token_in & OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE)) {
		const char *auth_line = oidc_util_get_cookie(r, cookie_name);
		if (auth_line != NULL) {

			/* copy the result in to the access_token */
			*access_token = apr_pstrdup(r->pool, auth_line);

		} else {
			oidc_warn(r, "no cookie found with name: %s", cookie_name);
		}
	}

	if (*access_token == NULL) {
		oidc_debug(r, "no bearer token found in the allowed methods: %s",
				oidc_accept_oauth_token_in2str(r->pool, accept_token_in));
		return FALSE;
	}

	/* log some stuff */
	oidc_debug(r, "bearer token: %s", *access_token);
	return TRUE;
}

/*
 * copy over space separated scope value but do it in an array for authorization purposes
 */
/*
static void oidc_oauth_spaced_string_to_array(request_rec *r, json_t *src,
		const char *src_key, json_t *dst, const char *dst_key) {
	apr_hash_t *ht = NULL;
	apr_hash_index_t *hi = NULL;
	json_t *arr = NULL;

	json_t *src_val = json_object_get(src, src_key);

	if (src_val != NULL)
		ht = oidc_util_spaced_string_to_hashtable(r->pool,
				json_string_value(src_val));

	if (ht != NULL) {
		arr = json_array();
		for (hi = apr_hash_first(NULL, ht); hi; hi = apr_hash_next(hi)) {
			const char *k;
			const char *v;
			apr_hash_this(hi, (const void**) &k, NULL, (void**) &v);
			json_array_append_new(arr, json_string(v));
		}
		json_object_set_new(dst, dst_key, arr);
	}
}
*/

/*
 * parse (custom/configurable) token expiry claim in introspection result
 */
static apr_byte_t oidc_oauth_parse_and_cache_token_expiry(request_rec *r,
		oidc_cfg *c, json_t *introspection_response,
		const char *expiry_claim_name, int expiry_format_absolute,
		int expiry_claim_is_mandatory, apr_time_t *cache_until) {

	oidc_debug(r,
			"expiry_claim_name=%s, expiry_format_absolute=%d, expiry_claim_is_mandatory=%d",
			expiry_claim_name, expiry_format_absolute,
			expiry_claim_is_mandatory);

	json_t *expiry = json_object_get(introspection_response, expiry_claim_name);

	if (expiry == NULL) {
		if (expiry_claim_is_mandatory) {
			oidc_error(r,
					"introspection response JSON object did not contain an \"%s\" claim",
					expiry_claim_name);
			return FALSE;
		}
		return TRUE;
	}

	if (!json_is_integer(expiry)) {
		if (expiry_claim_is_mandatory) {
			oidc_error(r,
					"introspection response JSON object contains a \"%s\" claim but it is not a JSON integer",
					expiry_claim_name);
			return FALSE;
		}
		oidc_warn(r,
				"introspection response JSON object contains a \"%s\" claim that is not an (optional) JSON integer: the introspection result will NOT be cached",
				expiry_claim_name);
		return TRUE;
	}

	json_int_t value = json_integer_value(expiry);
	if (value <= 0) {
		oidc_warn(r,
				"introspection response JSON object integer number value <= 0 (%ld); introspection result will not be cached",
				(long )value);
		return TRUE;
	}

	*cache_until = apr_time_from_sec(value);
	if (expiry_format_absolute == FALSE)
		(*cache_until) += apr_time_now();

	return TRUE;
}

#define OIDC_OAUTH_CACHE_KEY_RESPONSE  "r"
#define OIDC_OAUTH_CACHE_KEY_TIMESTAMP "t"

static apr_byte_t oidc_oauth_cache_access_token(request_rec *r, oidc_cfg *c,
		apr_time_t cache_until, const char *access_token, json_t *json) {

	oidc_debug(r, "caching introspection result");

	json_t *cache_entry = json_object();
	json_object_set(cache_entry, OIDC_OAUTH_CACHE_KEY_RESPONSE, json);
	json_object_set_new(cache_entry, OIDC_OAUTH_CACHE_KEY_TIMESTAMP,
			json_integer(apr_time_sec(apr_time_now())));
	char *cache_value = oidc_util_encode_json_object(r, cache_entry,
			JSON_COMPACT);

	/* set it in the cache so subsequent request don't need to validate the access_token and get the claims anymore */
	oidc_cache_set_access_token(r, access_token, cache_value, cache_until);

	json_decref(cache_entry);

	return TRUE;
}

static apr_byte_t oidc_oauth_get_cached_access_token(request_rec *r,
		oidc_cfg *c, const char *access_token, json_t **json) {
	json_t *cache_entry = NULL;
	char *s_cache_entry = NULL;

	/* see if we've got the claims for this access_token cached already */
	oidc_cache_get_access_token(r, access_token, &s_cache_entry);

	if (s_cache_entry == NULL)
		return FALSE;

	/* json decode the cache entry */
	if (oidc_util_decode_json_object(r, s_cache_entry, &cache_entry) == FALSE) {
		*json = NULL;
		return FALSE;
	}

	/* compare the timestamp against the freshness requirement */
	json_t *v = json_object_get(cache_entry, OIDC_OAUTH_CACHE_KEY_TIMESTAMP);
	apr_time_t now = apr_time_sec(apr_time_now());
	int token_introspection_interval = oidc_cfg_token_introspection_interval(r);
	if ((token_introspection_interval > 0)
			&& (now > json_integer_value(v) + token_introspection_interval)) {

		/* printout info about the event */
		char buf[APR_RFC822_DATE_LEN + 1];
		apr_rfc822_date(buf, apr_time_from_sec(json_integer_value(v)));
		oidc_debug(r,
				"token that was validated/cached at: [%s], does not meet token freshness requirement: %d)",
				buf, token_introspection_interval);

		/* invalidate the cache entry */
		*json = NULL;
		json_decref(cache_entry);
		return FALSE;
	}

	oidc_debug(r,
			"returning cached introspection result that meets freshness requirements: %s",
			s_cache_entry);

	/* we've got a cached introspection result that is still valid for this path's requirements */
	*json = json_deep_copy(
			json_object_get(cache_entry, OIDC_OAUTH_CACHE_KEY_RESPONSE));

	json_decref(cache_entry);
	return TRUE;
}

/*
 * resolve and validate an access_token against the configured Authorization Server
 */
static apr_byte_t oidc_oauth_resolve_access_token(request_rec *r, oidc_cfg *c,
		const char *access_token, json_t **token, char **response) {

	json_t *result = NULL;

	/* see if we've got the claims for this access_token cached already */
	oidc_oauth_get_cached_access_token(r, c, access_token, &result);

	if (result == NULL) {

		char *s_json = NULL;

		/* not cached, go out and validate the access_token against the Authorization server and get the JSON claims back */
		if (oidc_oauth_validate_access_token(r, c, access_token,
				&s_json) == FALSE) {
			oidc_error(r,
					"could not get a validation response from the Authorization server");
			return FALSE;
		}

		/* decode and see if it is not an error response somehow */
		if (oidc_util_decode_json_and_check_error(r, s_json, &result) == FALSE)
			return FALSE;

		json_t *active = json_object_get(result, OIDC_PROTO_ACTIVE);
		apr_time_t cache_until;
		if (active != NULL) {

			if (json_is_boolean(active)) {
				if (!json_is_true(active)) {
					oidc_debug(r,
							"\"%s\" boolean object with value \"false\" found in response JSON object",
							OIDC_PROTO_ACTIVE);
					json_decref(result);
					return FALSE;
				}
			} else if (json_is_string(active)) {
				if (apr_strnatcasecmp(json_string_value(active), "true") != 0) {
					oidc_debug(r,
							"\"%s\" string object with value that is not equal to \"true\" found in response JSON object: %s",
							OIDC_PROTO_ACTIVE, json_string_value(active));
					json_decref(result);
					return FALSE;
				}
			} else {
				oidc_debug(r,
						"no \"%s\" boolean or string object found in response JSON object",
						OIDC_PROTO_ACTIVE);
				json_decref(result);
				return FALSE;
			}

			if (oidc_oauth_parse_and_cache_token_expiry(r, c, result,
					OIDC_CLAIM_EXP,
					TRUE, FALSE, &cache_until) == FALSE) {
				json_decref(result);
				return FALSE;
			}

			/* set it in the cache so subsequent request don't need to validate the access_token and get the claims anymore */
			oidc_oauth_cache_access_token(r, c, cache_until, access_token,
					result);

		} else {

			if (oidc_oauth_parse_and_cache_token_expiry(r, c, result,
					c->oauth.introspection_token_expiry_claim_name,
					apr_strnatcmp(
							c->oauth.introspection_token_expiry_claim_format,
							OIDC_CLAIM_FORMAT_ABSOLUTE) == 0,
							c->oauth.introspection_token_expiry_claim_required,
							&cache_until) == FALSE) {
				json_decref(result);
				return FALSE;
			}

			/* set it in the cache so subsequent request don't need to validate the access_token and get the claims anymore */
			oidc_oauth_cache_access_token(r, c, cache_until, access_token,
					result);

		}

	}

	/* return the access_token JSON object */
	json_t *tkn = json_object_get(result, OIDC_PROTO_ACCESS_TOKEN);
	if ((tkn != NULL) && (json_is_object(tkn))) {

		/*
		 * assume PingFederate validation: copy over those claims from the access_token
		 * that are relevant for authorization purposes
		 */
		json_object_set(tkn, OIDC_PROTO_CLIENT_ID,
				json_object_get(result, OIDC_PROTO_CLIENT_ID));
		json_object_set(tkn, OIDC_PROTO_SCOPE,
				json_object_get(result, OIDC_PROTO_SCOPE));

		//oidc_oauth_spaced_string_to_array(r, result, OIDC_PROTO_SCOPE, tkn, "scopes");

		/* return only the pimped access_token results */
		*token = json_deep_copy(tkn);

		json_decref(result);

	} else {

		//oidc_oauth_spaced_string_to_array(r, result, OIDC_PROTO_SCOPE, result, "scopes");

		/* assume spec compliant introspection */
		*token = result;

	}

	/* stringify the response */
	*response = oidc_util_encode_json_object(r, *token, JSON_COMPACT);

	return TRUE;
}

/*
 * validate a JWT access token (locally)
 *
 * TODO: document that we're reusing the following settings from the OIDC config section:
 *       - JWKs URI refresh interval
 *       - encryption key material (OIDCPrivateKeyFiles)
 *
 * OIDCOAuthRemoteUserClaim client_id
 * # 32x 61 hex
 * OIDCOAuthVerifySharedKeys aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 */
static apr_byte_t oidc_oauth_validate_jwt_access_token(request_rec *r,
		oidc_cfg *c, const char *access_token, json_t **token, char **response) {

	oidc_debug(r, "enter: JWT access_token header=%s",
			oidc_proto_peek_jwt_header(r, access_token, NULL));

	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	if (oidc_util_create_symmetric_key(r, c->provider.client_secret, 0, NULL,
			TRUE, &jwk) == FALSE)
		return FALSE;

	oidc_jwt_t *jwt = NULL;
	if (oidc_jwt_parse(r->pool, access_token, &jwt,
			oidc_util_merge_symmetric_key(r->pool, c->private_keys, jwk),
			&err) == FALSE) {
		oidc_error(r, "could not parse JWT from access_token: %s",
				oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	oidc_jwk_destroy(jwk);
	oidc_debug(r, "successfully parsed JWT with header: %s",
			jwt->header.value.str);

	/*
	 * validate the access token JWT by validating the (optional) exp claim
	 * don't enforce anything around iat since it doesn't make much sense for access tokens
	 */
	if (oidc_proto_validate_jwt(r, jwt, NULL, FALSE, FALSE, -1) == FALSE) {
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	oidc_debug(r,
			"verify JWT against %d statically configured public keys and %d shared keys, with JWKs URI set to %s",
			c->oauth.verify_public_keys ?
					apr_hash_count(c->oauth.verify_public_keys) : 0,
					c->oauth.verify_shared_keys ?
							apr_hash_count(c->oauth.verify_shared_keys) : 0,
							c->oauth.verify_jwks_uri);

	oidc_jwks_uri_t jwks_uri = { c->oauth.verify_jwks_uri,
			c->provider.jwks_refresh_interval, c->oauth.ssl_validate_server };
	if (oidc_proto_jwt_verify(r, c, jwt, &jwks_uri,
			oidc_util_merge_key_sets(r->pool, c->oauth.verify_public_keys,
					c->oauth.verify_shared_keys)) == FALSE) {
		oidc_error(r,
				"JWT access token signature could not be validated, aborting");
		oidc_jwt_destroy(jwt);
		return FALSE;
	}

	oidc_debug(r, "successfully verified JWT access token: %s",
			jwt->payload.value.str);

	*token = jwt->payload.value.json;
	*response = jwt->payload.value.str;

	return TRUE;
}

/*
 * set the WWW-Authenticate response header according to https://tools.ietf.org/html/rfc6750#section-3
 */
int oidc_oauth_return_www_authenticate(request_rec *r, const char *error,
		const char *error_description) {
	apr_byte_t accept_token_in = oidc_cfg_dir_accept_token_in(r);
	char *hdr;
	if (accept_token_in == OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC) {
		hdr = apr_psprintf(r->pool, "%s", OIDC_PROTO_BASIC);
	} else {
		hdr = apr_psprintf(r->pool, "%s", OIDC_PROTO_BEARER);
	}

	if (ap_auth_name(r) != NULL)
		hdr = apr_psprintf(r->pool, "%s %s=\"%s\"", hdr, OIDC_PROTO_REALM,
				ap_auth_name(r));
	if (error != NULL)
		hdr = apr_psprintf(r->pool, "%s%s %s=\"%s\"", hdr,
				(ap_auth_name(r) ? "," : ""), OIDC_PROTO_ERROR, error);
	if (error_description != NULL)
		hdr = apr_psprintf(r->pool, "%s, %s=\"%s\"", hdr,
				OIDC_PROTO_ERROR_DESCRIPTION, error_description);
	oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_WWW_AUTHENTICATE, hdr);
	return HTTP_UNAUTHORIZED;
}

/*
 * set the unique user identifier that will be propagated in the Apache r->user and REMOTE_USER variables
 */
static apr_byte_t oidc_oauth_set_request_user(request_rec *r, oidc_cfg *c,
		json_t *token) {
	char *remote_user = NULL;

	if (oidc_get_remote_user(r, c->oauth.remote_user_claim.claim_name,
			c->oauth.remote_user_claim.reg_exp,
			c->oauth.remote_user_claim.replace, token, &remote_user) == FALSE) {
		oidc_error(r,
				"" OIDCOAuthRemoteUserClaim " is set to \"%s\", but could not set the remote user based the available claims for the user",
				c->oauth.remote_user_claim.claim_name);
		return FALSE;
	}

	r->user = apr_pstrdup(r->pool, remote_user);
	oidc_debug(r, "set user to \"%s\" based on claim: \"%s\"%s", r->user,
			c->oauth.remote_user_claim.claim_name,
			c->oauth.remote_user_claim.reg_exp ?
					apr_psprintf(r->pool,
							" and expression: \"%s\" and replace string: \"%s\"",
							c->oauth.remote_user_claim.reg_exp,
							c->oauth.remote_user_claim.replace) :
							"");
	return TRUE;
}

/*
 * main routine: handle OAuth 2.0 authentication/authorization
 */
int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c, const char *access_token) {

	/* check if this is a sub-request or an initial request */
	if (!ap_is_initial_req(r)) {

		if (r->main != NULL)
			r->user = r->main->user;
		else if (r->prev != NULL)
			r->user = r->prev->user;

		if (r->user != NULL) {

			/* this is a sub-request and we have a session */
			oidc_debug(r,
					"recycling user '%s' from initial request for sub-request",
					r->user);

			/* strip any cookies that we need to */
			oidc_strip_cookies(r);

			return OK;
		}

		/* check if this is a request for the public (encryption) keys */
	} else if (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, c))) {

		if (oidc_util_request_has_parameter(r,
				OIDC_REDIRECT_URI_REQUEST_JWKS)) {

			return oidc_handle_jwks(r, c);

		}

	}

	/* we don't have a session yet */

	/* obtain/refresh metadata from OAuth metadata document URL if configured */
	oidc_oauth_provider_config(r, c);

	/* get the bearer access token from the Authorization header */
	if (access_token == NULL) {
		if (oidc_oauth_get_bearer_token(r, &access_token) == FALSE) {
			if (r->method_number == M_OPTIONS) {
				r->user = "";
				return OK;
			}
			return oidc_oauth_return_www_authenticate(r,
					OIDC_PROTO_ERR_INVALID_REQUEST, "No bearer token found in the request");
		}
	}

	/* validate the obtained access token against the OAuth AS validation endpoint */
	json_t *token = NULL;
	char *s_token = NULL;

	/* check if an introspection endpoint is set */
	if (c->oauth.introspection_endpoint_url != NULL) {
		/* we'll validate the token remotely */
		if (oidc_oauth_resolve_access_token(r, c, access_token, &token,
				&s_token) == FALSE)
			return oidc_oauth_return_www_authenticate(r,
					OIDC_PROTO_ERR_INVALID_TOKEN,
					"Reference token could not be introspected");
	} else {
		/* no introspection endpoint is set, assume the token is a JWT and validate it locally */
		if (oidc_oauth_validate_jwt_access_token(r, c, access_token, &token,
				&s_token) == FALSE)
			return oidc_oauth_return_www_authenticate(r,
					OIDC_PROTO_ERR_INVALID_TOKEN, "JWT token could not be validated");
	}

	/* check that we've got something back */
	if (token == NULL) {
		oidc_error(r, "could not resolve claims (token == NULL)");
		return oidc_oauth_return_www_authenticate(r,
				OIDC_PROTO_ERR_INVALID_TOKEN,
				"No claims could be parsed from the token");
	}

	/* store the parsed token (cq. the claims from the response) in the request state so it can be accessed by the authz routines */
	oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_CLAIMS,
			(const char *) s_token);

	/* set the request user */
	if (oidc_oauth_set_request_user(r, c, token) == FALSE) {
		json_decref(token);
		oidc_error(r,
				"remote user could not be set, aborting with HTTP_UNAUTHORIZED");
		return oidc_oauth_return_www_authenticate(r,
				OIDC_PROTO_ERR_INVALID_TOKEN, "Could not set remote user");
	}

	/*
	 * we're going to pass the information that we have to the application,
	 * but first we need to scrub the headers that we're going to use for security reasons
	 */
	oidc_scrub_headers(r);

	/* set the user authentication HTTP header if set and required */
	char *authn_header = oidc_cfg_dir_authn_header(r);
	apr_byte_t pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	apr_byte_t pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);

	if ((r->user != NULL) && (authn_header != NULL))
		oidc_util_hdr_in_set(r, authn_header, r->user);

	/* set the resolved claims in the HTTP headers for the target application */
	oidc_util_set_app_infos(r, token, oidc_cfg_claim_prefix(r),
			c->claim_delimiter, pass_headers, pass_envvars);

	/* set the access_token in the app headers */
	if (access_token != NULL) {
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN, access_token,
				OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
	}

	/* free JSON resources */
	json_decref(token);

	/* strip any cookies that we need to */
	oidc_strip_cookies(r);

	return OK;
}
