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
 * Copyright (C) 2013-2015 Ping Identity Corporation
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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include "mod_auth_openidc.h"

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/*
 * send an OpenID Connect authorization request to the specified provider preserving POST parameters using HTML5 storage
 */
int oidc_proto_authorization_request_post_preserve(request_rec *r,
		const char *authorization_request) {
	/* read the parameters that are POST-ed to us */
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post(r, params) == FALSE) {
		oidc_error(r, "something went wrong when reading the POST parameters");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	const apr_array_header_t *arr = apr_table_elts(params);
	const apr_table_entry_t *elts = (const apr_table_entry_t*) arr->elts;
	int i;
	char *json = "";
	for (i = 0; i < arr->nelts; i++) {
		json = apr_psprintf(r->pool, "%s'%s': '%s'%s", json,
				oidc_util_html_escape(r->pool, elts[i].key),
				oidc_util_html_escape(r->pool, elts[i].val),
				i < arr->nelts - 1 ? "," : "");
	}
	json = apr_psprintf(r->pool, "{ %s }", json);

	char *java_script =
			apr_psprintf(r->pool,
					"    <script type=\"text/javascript\">\n"
					"      function preserveOnLoad() {\n"
					"        localStorage.setItem('mod_auth_openidc_preserve_post_params', JSON.stringify(%s));\n"
					"        window.location='%s';\n"
					"      }\n"
					"    </script>\n", json, authorization_request);

	return oidc_util_html_send(r, "Preserving...", java_script,
			"preserveOnLoad", "<p>Preserving...</p>", DONE);
}

/*
 * send an OpenID Connect authorization request to the specified provider
 */
int oidc_proto_authorization_request(request_rec *r,
		struct oidc_provider_t *provider, const char *login_hint,
		const char *redirect_uri, const char *state,
		oidc_proto_state *proto_state, const char *id_token_hint,
		const char *auth_request_params) {

	/* log some stuff */
	oidc_debug(r,
			"enter, issuer=%s, redirect_uri=%s, original_url=%s, state=%s, nonce=%s",
			provider->issuer, redirect_uri, proto_state->original_url, state,
			proto_state->nonce);

	/* assemble the full URL as the authorization request to the OP where we want to redirect to */
	char *authorization_request = apr_psprintf(r->pool, "%s%s",
			provider->authorization_endpoint_url,
			strchr(provider->authorization_endpoint_url, '?') != NULL ?
					"&" : "?");
	authorization_request = apr_psprintf(r->pool, "%sresponse_type=%s",
			authorization_request,
			oidc_util_escape_string(r, proto_state->response_type));
	authorization_request = apr_psprintf(r->pool, "%s&scope=%s",
			authorization_request, oidc_util_escape_string(r, provider->scope));
	authorization_request = apr_psprintf(r->pool, "%s&client_id=%s",
			authorization_request,
			oidc_util_escape_string(r, provider->client_id));
	authorization_request = apr_psprintf(r->pool, "%s&state=%s",
			authorization_request, oidc_util_escape_string(r, state));
	authorization_request = apr_psprintf(r->pool, "%s&redirect_uri=%s",
			authorization_request, oidc_util_escape_string(r, redirect_uri));

	/* add the nonce if set */
	if (proto_state->nonce != NULL)
		authorization_request = apr_psprintf(r->pool, "%s&nonce=%s",
				authorization_request,
				oidc_util_escape_string(r, proto_state->nonce));

	/* add the response_mode if explicitly set */
	if (proto_state->response_mode != NULL)
		authorization_request = apr_psprintf(r->pool, "%s&response_mode=%s",
				authorization_request,
				oidc_util_escape_string(r, proto_state->response_mode));

	/* add the login_hint if provided */
	if (login_hint != NULL)
		authorization_request = apr_psprintf(r->pool, "%s&login_hint=%s",
				authorization_request, oidc_util_escape_string(r, login_hint));

	/* add the id_token_hint if provided */
	if (id_token_hint != NULL)
		authorization_request = apr_psprintf(r->pool, "%s&id_token_hint=%s",
				authorization_request,
				oidc_util_escape_string(r, id_token_hint));

	/* add the prompt setting if provided (e.g. "none" for no-GUI checks) */
	if (proto_state->prompt != NULL)
		authorization_request = apr_psprintf(r->pool, "%s&prompt=%s",
				authorization_request,
				oidc_util_escape_string(r, proto_state->prompt));

	/* add any statically configured custom authorization request parameters */
	if (provider->auth_request_params != NULL) {
		authorization_request = apr_psprintf(r->pool, "%s&%s",
				authorization_request, provider->auth_request_params);
	}

	/* add any dynamically configured custom authorization request parameters */
	if (auth_request_params != NULL) {
		authorization_request = apr_psprintf(r->pool, "%s&%s",
				authorization_request, auth_request_params);
	}

	/* preserve POSTed form parameters if enabled */
	if (apr_strnatcmp(proto_state->original_method, "form_post") == 0)
		return oidc_proto_authorization_request_post_preserve(r,
				authorization_request);

	/* add the redirect location header */
	apr_table_add(r->headers_out, "Location", authorization_request);

	/* some more logging */
	oidc_debug(r, "adding outgoing header: Location: %s",
			authorization_request);

	/* and tell Apache to return an HTTP Redirect (302) message */
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * indicate whether the incoming HTTP POST request is an OpenID Connect Authorization Response
 */
apr_byte_t oidc_proto_is_post_authorization_response(request_rec *r,
		oidc_cfg *cfg) {

	/* prereq: this is a call to the configured redirect_uri; see if it is a POST */
	return (r->method_number == M_POST);
}

/*
 * indicate whether the incoming HTTP GET request is an OpenID Connect Authorization Response
 */
apr_byte_t oidc_proto_is_redirect_authorization_response(request_rec *r,
		oidc_cfg *cfg) {

	/* prereq: this is a call to the configured redirect_uri; see if it is a GET with state and id_token or code parameters */
	return ((r->method_number == M_GET)
			&& oidc_util_request_has_parameter(r, "state")
			&& (oidc_util_request_has_parameter(r, "id_token")
					|| oidc_util_request_has_parameter(r, "code")));
}

#define OIDC_PROTO_NONCE_LENGTH 32

/*
 * generate a random value (nonce) to correlate request/response through browser state
 */
apr_byte_t oidc_proto_generate_nonce(request_rec *r, char **nonce) {
	unsigned char *nonce_bytes = apr_pcalloc(r->pool, OIDC_PROTO_NONCE_LENGTH);
	if (apr_generate_random_bytes(nonce_bytes,
			OIDC_PROTO_NONCE_LENGTH) != APR_SUCCESS) {
		oidc_error(r, "apr_generate_random_bytes returned an error");
		return FALSE;
	}
	if (oidc_base64url_encode(r, nonce, (const char *) nonce_bytes,
			OIDC_PROTO_NONCE_LENGTH, TRUE) <= 0) {
		oidc_error(r, "oidc_base64url_encode returned an error");
		return FALSE;
	}
	return TRUE;
}

/*
 * if a nonce was passed in the authorization request (and stored in the browser state),
 * check that it matches the nonce value in the id_token payload
 */
static apr_byte_t oidc_proto_validate_nonce(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *nonce, apr_jwt_t *jwt) {

	apr_jwt_error_t err;

	/* see if we have this nonce cached already */
	const char *replay = NULL;
	cfg->cache->get(r, OIDC_CACHE_SECTION_NONCE, nonce, &replay);
	if (replay != NULL) {
		oidc_error(r,
				"the nonce value (%s) passed in the browser state was found in the cache already; possible replay attack!?",
				nonce);
		return FALSE;
	}

	/* get the "nonce" value in the id_token payload */
	char *j_nonce = NULL;
	if (apr_jwt_get_string(r->pool, jwt->payload.value.json, "nonce", TRUE,
			&j_nonce, &err) == FALSE) {
		oidc_error(r,
				"id_token JSON payload did not contain a \"nonce\" string: %s",
				apr_jwt_e2s(r->pool, err));
		return FALSE;
	}

	/* see if the nonce in the id_token matches the one that we sent in the authorization request */
	if (apr_strnatcmp(nonce, j_nonce) != 0) {
		oidc_error(r,
				"the nonce value (%s) in the id_token did not match the one stored in the browser session (%s)",
				j_nonce, nonce);
		return FALSE;
	}

	/*
	 * nonce cache duration (replay prevention window) is the 2x the configured
	 * slack on the timestamp (+-) for token issuance plus 10 seconds for safety
	 */
	apr_time_t nonce_cache_duration = apr_time_from_sec(
			provider->idtoken_iat_slack * 2 + 10);

	/* store it in the cache for the calculated duration */
	cfg->cache->set(r, OIDC_CACHE_SECTION_NONCE, nonce, nonce,
			apr_time_now() + nonce_cache_duration);

	oidc_debug(r,
			"nonce \"%s\" validated successfully and is now cached for %" APR_TIME_T_FMT " seconds",
			nonce, apr_time_sec(nonce_cache_duration));

	return TRUE;
}

/*
 * validate the "aud" and "azp" claims in the id_token payload
 */
static apr_byte_t oidc_proto_validate_aud_and_azp(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, apr_jwt_payload_t *id_token_payload) {

	char *azp = NULL;
	apr_jwt_get_string(r->pool, id_token_payload->value.json, "azp", FALSE,
			&azp,
			NULL);

	/*
	 * the "azp" claim is only needed when the id_token has a single audience value and that audience
	 * is different than the authorized party; it MAY be included even when the authorized party is
	 * the same as the sole audience.
	 */
	if ((azp != NULL) && (apr_strnatcmp(azp, provider->client_id) != 0)) {
		oidc_error(r,
				"the \"azp\" claim (%s) is present in the id_token, but is not equal to the configured client_id (%s)",
				azp, provider->client_id);
		return FALSE;
	}

	/* get the "aud" value from the JSON payload */
	json_t *aud = json_object_get(id_token_payload->value.json, "aud");
	if (aud != NULL) {

		/* check if it is a single-value */
		if (json_is_string(aud)) {

			/* a single-valued audience must be equal to our client_id */
			if (apr_strnatcmp(json_string_value(aud), provider->client_id)
					!= 0) {
				oidc_error(r,
						"the configured client_id (%s) did not match the \"aud\" claim value (%s) in the id_token",
						provider->client_id, json_string_value(aud));
				return FALSE;
			}

			/* check if this is a multi-valued audience */
		} else if (json_is_array(aud)) {

			if ((json_array_size(aud) > 1) && (azp == NULL)) {
				oidc_debug(r,
						"the \"aud\" claim value in the id_token is an array with more than 1 element, but \"azp\" claim is not present (a SHOULD in the spec...)");
			}

			if (oidc_util_json_array_has_value(r, aud,
					provider->client_id) == FALSE) {
				oidc_error(r,
						"our configured client_id (%s) could not be found in the array of values for \"aud\" claim",
						provider->client_id);
				return FALSE;
			}
		} else {
			oidc_error(r,
					"id_token JSON payload \"aud\" claim is not a string nor an array");
			return FALSE;
		}

	} else {
		oidc_error(r, "id_token JSON payload did not contain an \"aud\" claim");
		return FALSE;
	}

	return TRUE;
}

/*
 * validate "iat" claim in JWT
 */
static apr_byte_t oidc_proto_validate_iat(request_rec *r, apr_jwt_t *jwt,
		apr_byte_t is_mandatory, int slack) {

	/* get the current time */
	apr_time_t now = apr_time_sec(apr_time_now());

	/* sanity check for iat being set */
	if (jwt->payload.iat == APR_JWT_CLAIM_TIME_EMPTY) {
		if (is_mandatory) {
			oidc_error(r, "JWT did not contain an \"iat\" number value");
			return FALSE;
		}
		return TRUE;
	}

	/* check if this id_token has been issued just now +- slack (default 10 minutes) */
	if ((now - slack) > jwt->payload.iat) {
		oidc_error(r,
				"\"iat\" validation failure (%" JSON_INTEGER_FORMAT "): JWT was issued more than %d seconds ago",
				jwt->payload.iat, slack);
		return FALSE;
	}
	if ((now + slack) < jwt->payload.iat) {
		oidc_error(r,
				"\"iat\" validation failure (%" JSON_INTEGER_FORMAT "): JWT was issued more than %d seconds in the future",
				jwt->payload.iat, slack);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate "exp" claim in JWT
 */
static apr_byte_t oidc_proto_validate_exp(request_rec *r, apr_jwt_t *jwt,
		apr_byte_t is_mandatory) {

	/* get the current time */
	apr_time_t now = apr_time_sec(apr_time_now());

	/* sanity check for exp being set */
	if (jwt->payload.exp == APR_JWT_CLAIM_TIME_EMPTY) {
		if (is_mandatory) {
			oidc_error(r, "JWT did not contain an \"exp\" number value");
			return FALSE;
		}
		return TRUE;
	}

	/* see if now is beyond the JWT expiry timestamp */
	if (now > jwt->payload.exp) {
		oidc_error(r,
				"\"exp\" validation failure (%" JSON_INTEGER_FORMAT "): JWT expired %" JSON_INTEGER_FORMAT " seconds ago",
				jwt->payload.exp, now - jwt->payload.exp);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate a JSON Web token
 */
apr_byte_t oidc_proto_validate_jwt(request_rec *r, apr_jwt_t *jwt,
		const char *iss, apr_byte_t exp_is_mandatory,
		apr_byte_t iat_is_mandatory, int iat_slack) {

	if (iss != NULL) {

		/* issuer is set and must match */
		if (jwt->payload.iss == NULL) {
			oidc_error(r,
					"JWT did not contain an \"iss\" string (requested value: %s)",
					iss);
			return FALSE;
		}

		/* check if the issuer matches the requested value */
		if (oidc_util_issuer_match(iss, jwt->payload.iss) == FALSE) {
			oidc_error(r,
					"requested issuer (%s) does not match received \"iss\" value in id_token (%s)",
					iss, jwt->payload.iss);
			return FALSE;
		}
	}

	/* check exp */
	if (oidc_proto_validate_exp(r, jwt, exp_is_mandatory) == FALSE)
		return FALSE;

	/* check iat */
	if (oidc_proto_validate_iat(r, jwt, iat_is_mandatory, iat_slack) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * check whether the provided JWT is a valid id_token for the specified "provider"
 */
static apr_byte_t oidc_proto_validate_idtoken(request_rec *r,
		oidc_provider_t *provider, apr_jwt_t *jwt, const char *nonce) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	oidc_debug(r, "enter, jwt.header=\"%s\", jwt.payload=\%s\", nonce=%s",
			jwt->header.value.str, jwt->payload.value.str, nonce);

	/* if a nonce is not passed, we're doing a ("code") flow where the nonce is optional */
	if (nonce != NULL) {
		/* if present, verify the nonce */
		if (oidc_proto_validate_nonce(r, cfg, provider, nonce, jwt) == FALSE)
			return FALSE;
	}

	/* validate the ID Token JWT, requiring iss match, and valid exp + iat */
	if (oidc_proto_validate_jwt(r, jwt, provider->issuer, TRUE, TRUE,
			provider->idtoken_iat_slack) == FALSE)
		return FALSE;

	/* check if the required-by-spec "sub" claim is present */
	if (jwt->payload.sub == NULL) {
		oidc_error(r,
				"id_token JSON payload did not contain the required-by-spec \"sub\" string value");
		return FALSE;
	}

	/* verify the "aud" and "azp" values */
	if (oidc_proto_validate_aud_and_azp(r, cfg, provider,
			&jwt->payload) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * get the key from the JWKs that corresponds with the key specified in the header
 */
static apr_byte_t oidc_proto_get_key_from_jwks(request_rec *r, apr_jwt_t *jwt,
		json_t *j_jwks, apr_hash_t *result) {

	apr_byte_t rc = TRUE;
	apr_jwt_error_t err;
	char *x5t = NULL;
	apr_jwk_t *jwk = NULL;

	const char *key_type = apr_jwt_signature_to_jwk_type(r->pool, jwt);
	if (key_type == NULL) {
		oidc_error(r, "unsupported signing algorithm in JWT header: %s",
				jwt->header.alg);
		return FALSE;
	}

	apr_jwt_get_string(r->pool, jwt->header.value.json, "x5t", FALSE, &x5t,
			NULL);

	oidc_debug(r, "search for kid \"%s\" or thumbprint x5t \"%s\"",
			jwt->header.kid, x5t);

	/* get the "keys" JSON array from the JWKs object */
	json_t *keys = json_object_get(j_jwks, "keys");
	if ((keys == NULL) || !(json_is_array(keys))) {
		oidc_error(r, "\"keys\" array element is not a JSON array");
		return FALSE;
	}

	int i;
	for (i = 0; i < json_array_size(keys); i++) {

		/* get the next element in the array */
		json_t *elem = json_array_get(keys, i);

		/* check that it is a JSON object */
		if (!json_is_object(elem)) {
			oidc_warn(r,
					"\"keys\" array element is not a JSON object, skipping");
			continue;
		}

		/* get the key type and see if it is the type that we are looking for */
		json_t *kty = json_object_get(elem, "kty");
		if ((!json_is_string(kty))
				|| (strcmp(json_string_value(kty), key_type) != 0))
			continue;

		/* see if we were looking for a specific kid, if not we'll include any key that matches the type */
		if ((jwt->header.kid == NULL) && (x5t == NULL)) {
			oidc_debug(r, "no kid/x5t to match, include matching key type");

			rc = apr_jwk_parse_json(r->pool, elem, &jwk, &err);
			if (rc == FALSE)
				oidc_error(r, "JWK parsing failed: %s",
						apr_jwt_e2s(r->pool, err));
			else
				apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
			continue;
		}

		/* we are looking for a specific kid, get the kid from the current element */
		json_t *ekid = json_object_get(elem, "kid");
		if ((ekid != NULL) && json_is_string(ekid)
				&& (jwt->header.kid != NULL)) {
			/* compare the requested kid against the current element */
			if (apr_strnatcmp(jwt->header.kid, json_string_value(ekid)) == 0) {
				oidc_debug(r, "found matching kid: \"%s\"", jwt->header.kid);

				rc = apr_jwk_parse_json(r->pool, elem, &jwk, &err);
				if (rc == FALSE)
					oidc_error(r, "JWK parsing failed: %s",
							apr_jwt_e2s(r->pool, err));
				else
					apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
				break;
			}
		}

		/* we are looking for a specific x5t, get the x5t from the current element */
		json_t *ex5t = json_object_get(elem, "kid");
		if ((ex5t != NULL) && json_is_string(ex5t) && (x5t != NULL)) {
			/* compare the requested kid against the current element */
			if (apr_strnatcmp(x5t, json_string_value(ex5t)) == 0) {
				oidc_debug(r, "found matching x5t: \"%s\"", x5t);

				rc = apr_jwk_parse_json(r->pool, elem, &jwk, &err);
				if (rc == FALSE)
					oidc_error(r, "JWK parsing failed: %s",
							apr_jwt_e2s(r->pool, err));
				else
					apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
				break;
			}
		}

	}

	return rc;
}

/*
 * get the keys from the (possibly cached) set of JWKs on the jwk_uri that corresponds with the key specified in the header
 */
apr_byte_t oidc_proto_get_keys_from_jwks_uri(request_rec *r, oidc_cfg *cfg,
		apr_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri, apr_hash_t *keys,
		apr_byte_t *force_refresh) {

	json_t *j_jwks = NULL;

	/* get the set of JSON Web Keys for this provider (possibly by downloading them from the specified provider->jwk_uri) */
	oidc_metadata_jwks_get(r, cfg, jwks_uri, &j_jwks, force_refresh);
	if (j_jwks == NULL) {
		oidc_error(r, "could not %s JSON Web Keys",
				*force_refresh ? "refresh" : "get");
		return FALSE;
	}

	/*
	 * get the key corresponding to the kid from the header, referencing the key that
	 * was used to sign this message (or get all keys in case no kid was set)
	 *
	 * we don't check the error return value because we'll treat "error" in the same
	 * way as "key not found" i.e. by refreshing the keys from the JWKs URI if not
	 * already done
	 */
	oidc_proto_get_key_from_jwks(r, jwt, j_jwks, keys);

	/* no need anymore for the parsed json_t contents, release the it */
	json_decref(j_jwks);

	/* if we've got no keys and we did not do a fresh download, then the cache may be stale */
	if ((apr_hash_count(keys) < 1) && (*force_refresh == FALSE)) {

		/* we did not get a key, but we have not refreshed the JWKs from the jwks_uri yet */
		oidc_warn(r,
				"could not find a key in the cached JSON Web Keys, doing a forced refresh in case keys were rolled over");
		/* get the set of JSON Web Keys forcing a fresh download from the specified JWKs URI */
		*force_refresh = TRUE;
		return oidc_proto_get_keys_from_jwks_uri(r, cfg, jwt, jwks_uri, keys,
				force_refresh);
	}

	oidc_debug(r,
			"returning %d key(s) obtained from the (possibly cached) JWKs URI",
			apr_hash_count(keys));

	return TRUE;
}

/*
 * verify the signature on a JWT using the dynamically obtained and statically configured keys
 */
apr_byte_t oidc_proto_jwt_verify(request_rec *r, oidc_cfg *cfg, apr_jwt_t *jwt,
		const oidc_jwks_uri_t *jwks_uri, apr_hash_t *static_keys) {

	apr_jwt_error_t err;
	apr_hash_t *dynamic_keys = apr_hash_make(r->pool);

	/* see if we've got a JWKs URI set for signature validation with dynamically obtained asymmetric keys */
	if (jwks_uri->url == NULL) {
		oidc_debug(r,
				"\"jwks_uri\" is not set, signature validation will only be performed against statically configured keys");
		/* the JWKs URI was provided, but let's see if it makes sense to pull down keys, i.e. if it is an asymmetric signature */
	} else if (apr_jws_signature_is_hmac(r->pool, jwt)) {
		oidc_debug(r,
				"\"jwks_uri\" is set, but the JWT has a symmetric signature so we won't pull/use keys from there");
	} else {
		apr_byte_t force_refresh = FALSE;
		/* get the key from the JWKs that corresponds with the key specified in the header */
		if (oidc_proto_get_keys_from_jwks_uri(r, cfg, jwt, jwks_uri,
				dynamic_keys, &force_refresh) == FALSE)
			return FALSE;
	}

	/* do the actual JWS verification with the locally and remotely provided key material */
	// TODO: now static keys "win" if the same `kid` was used in both local and remote key sets
	if (apr_jws_verify(r->pool, jwt,
			oidc_util_merge_key_sets(r->pool, static_keys, dynamic_keys),
			&err) == FALSE) {
		oidc_error(r, "JWT signature verification failed: %s",
				apr_jwt_e2s(r->pool, err));
		return FALSE;
	}

	oidc_debug(r,
			"JWT signature verification with algorithm \"%s\" was successful",
			jwt->header.alg);

	return TRUE;
}

/*
 * set the unique user identifier that will be propagated in the Apache r->user and REMOTE_USER variables
 */
static apr_byte_t oidc_proto_set_remote_user(request_rec *r, oidc_cfg *c,
		oidc_provider_t *provider, apr_jwt_t *jwt, char **user) {

	char *issuer = provider->issuer;
	char *claim_name = apr_pstrdup(r->pool, c->remote_user_claim);
	int n = strlen(claim_name);
	int post_fix_with_issuer = (claim_name[n - 1] == '@');
	if (post_fix_with_issuer) {
		claim_name[n - 1] = '\0';
		issuer =
				(strstr(issuer, "https://") == NULL) ?
						apr_pstrdup(r->pool, issuer) :
						apr_pstrdup(r->pool, issuer + strlen("https://"));
	}

	/* extract the username claim (default: "sub") from the id_token payload */
	char *username = NULL;
	if (apr_jwt_get_string(r->pool, jwt->payload.value.json, claim_name, TRUE,
			&username, NULL) == FALSE) {
		oidc_error(r,
				"OIDCRemoteUserClaim is set to \"%s\", but the id_token JSON payload did not contain a \"%s\" string",
				c->remote_user_claim, claim_name);
		return FALSE;
	}

	/* set the unique username in the session (will propagate to r->user/REMOTE_USER) */
	*user = post_fix_with_issuer ?
			apr_psprintf(r->pool, "%s@%s", username, issuer) :
			apr_pstrdup(r->pool, username);

	oidc_debug(r, "set remote_user to \"%s\"", *user);

	return TRUE;
}

/*
 * check whether the provided string is a valid id_token and return its parsed contents
 */
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *id_token, const char *nonce,
		char **user, apr_jwt_t **jwt, apr_byte_t is_code_flow) {

	char buf[APR_RFC822_DATE_LEN + 1];
	apr_jwt_error_t err;

	oidc_debug(r, "enter");

	if (apr_jwt_parse(r->pool, id_token, jwt,
			oidc_util_merge_symmetric_key(r->pool, cfg->private_keys,
					provider->client_secret, "sha256"), &err) == FALSE) {
		oidc_error(r, "apr_jwt_parse failed for JWT with header \"%s\": %s",
				apr_jwt_header_to_string(r->pool, id_token, NULL),
				apr_jwt_e2s(r->pool, err));
		apr_jwt_destroy(*jwt);
		return FALSE;
	}

	oidc_debug(r,
			"successfully parsed (and possibly decrypted) JWT with header: \"%s\"",
			apr_jwt_header_to_string(r->pool, id_token, NULL));

	// make signature validation exception for 'code' flow and the algorithm NONE
	if (is_code_flow == FALSE || strcmp((*jwt)->header.alg, "none") != 0) {

		oidc_jwks_uri_t jwks_uri = { provider->jwks_uri,
				provider->jwks_refresh_interval, provider->ssl_validate_server };
		if (oidc_proto_jwt_verify(r, cfg, *jwt, &jwks_uri,
				oidc_util_merge_symmetric_key(r->pool, NULL,
						provider->client_secret, NULL)) == FALSE) {

			oidc_error(r,
					"id_token signature could not be validated, aborting");
			apr_jwt_destroy(*jwt);
			return FALSE;
		}
	}

	/* this is where the meat is */
	if (oidc_proto_validate_idtoken(r, provider, *jwt, nonce) == FALSE) {
		oidc_error(r, "id_token payload could not be validated, aborting");
		apr_jwt_destroy(*jwt);
		return FALSE;
	}

	if (oidc_proto_set_remote_user(r, cfg, provider, *jwt, user) == FALSE) {
		oidc_error(r, "remote user could not be set, aborting");
		apr_jwt_destroy(*jwt);
		return FALSE;
	}

	/* log our results */

	apr_rfc822_date(buf, apr_time_from_sec((*jwt)->payload.exp));
	oidc_debug(r,
			"valid id_token for user \"%s\" expires: [%s], in %" JSON_INTEGER_FORMAT " secs from now)",
			*user, buf, (*jwt)->payload.exp - apr_time_sec(apr_time_now()));

	/* since we've made it so far, we may as well say it is a valid id_token */
	return TRUE;
}

/*
 * check that the access_token type is supported
 */
static apr_byte_t oidc_proto_validate_token_type(request_rec *r,
		oidc_provider_t *provider, const char *token_type) {
	/*  we only support bearer/Bearer  */
	if ((token_type != NULL) && (apr_strnatcasecmp(token_type, "Bearer") != 0)
			&& (provider->userinfo_endpoint_url != NULL)) {
		oidc_error(r,
				"token_type is \"%s\" and UserInfo endpoint (%s) for issuer \"%s\" is set: can only deal with Bearer authentication against a UserInfo endpoint!",
				token_type, provider->userinfo_endpoint_url, provider->issuer);
		return FALSE;
	}
	return TRUE;
}

/*
 * send a code/refresh request to the token endpoint and return the parsed contents
 */
static apr_byte_t oidc_proto_token_endpoint_request(request_rec *r,
		oidc_cfg *cfg, oidc_provider_t *provider, apr_table_t *params,
		char **id_token, char **access_token, char **token_type,
		int *expires_in, char **refresh_token) {

	/* get a handle to the directory config */
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);

	const char *response = NULL;

	/* see if we need to do basic auth or auth-through-post-params (both applied through the HTTP POST method though) */
	const char *basic_auth = NULL;
	if ((provider->token_endpoint_auth == NULL)
			|| (apr_strnatcmp(provider->token_endpoint_auth,
					"client_secret_basic") == 0)) {
		basic_auth = apr_psprintf(r->pool, "%s:%s", provider->client_id,
				provider->client_secret);
	} else {
		apr_table_addn(params, "client_id", provider->client_id);
		apr_table_addn(params, "client_secret", provider->client_secret);
	}

	/* add any configured extra static parameters to the token endpoint */
	oidc_util_table_add_query_encoded_params(r->pool, params,
			provider->token_endpoint_params);

	/* send the refresh request to the token endpoint */
	if (oidc_util_http_post_form(r, provider->token_endpoint_url, params,
			basic_auth, NULL, provider->ssl_validate_server, &response,
			cfg->http_timeout_long, cfg->outgoing_proxy,
			dir_cfg->pass_cookies) == FALSE) {
		oidc_warn(r, "error when calling the token endpoint (%s)",
				provider->token_endpoint_url);
		return FALSE;
	}

	/* check for errors, the response itself will have been logged already */
	json_t *result = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	/* get the id_token from the parsed response */
	oidc_json_object_get_string(r->pool, result, "id_token", id_token, NULL);

	/* get the access_token from the parsed response */
	oidc_json_object_get_string(r->pool, result, "access_token", access_token,
			NULL);

	/* get the token type from the parsed response */
	oidc_json_object_get_string(r->pool, result, "token_type", token_type,
			NULL);

	/* check the new token type */
	if (token_type != NULL) {
		if (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE) {
			oidc_warn(r, "access token type did not validate, dropping it");
			*access_token = NULL;
		}
	}

	/* get the expires_in value */
	oidc_json_object_get_int(r->pool, result, "expires_in", expires_in, -1);

	/* get the refresh_token from the parsed response */
	oidc_json_object_get_string(r->pool, result, "refresh_token", refresh_token,
			NULL);

	json_decref(result);

	return TRUE;
}

/*
 * resolves the code received from the OP in to an id_token, access_token and refresh_token
 */
apr_byte_t oidc_proto_resolve_code(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *code, char **id_token,
		char **access_token, char **token_type, int *expires_in,
		char **refresh_token) {

	oidc_debug(r, "enter");

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_addn(params, "grant_type", "authorization_code");
	apr_table_addn(params, "code", code);
	apr_table_addn(params, "redirect_uri", cfg->redirect_uri);

	return oidc_proto_token_endpoint_request(r, cfg, provider, params, id_token,
			access_token, token_type, expires_in, refresh_token);
}

/*
 * refreshes the access_token/id_token /refresh_token received from the OP using the refresh_token
 */
apr_byte_t oidc_proto_refresh_request(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *rtoken, char **id_token,
		char **access_token, char **token_type, int *expires_in,
		char **refresh_token) {

	oidc_debug(r, "enter");

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_addn(params, "grant_type", "refresh_token");
	apr_table_addn(params, "refresh_token", rtoken);
	apr_table_addn(params, "scope", provider->scope);

	return oidc_proto_token_endpoint_request(r, cfg, provider, params, id_token,
			access_token, token_type, expires_in, refresh_token);
}

/*
 * get claims from the OP UserInfo endpoint using the provided access_token
 */
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *access_token,
		const char **response, json_t **claims) {

	/* get a handle to the directory config */
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);

	oidc_debug(r, "enter, endpoint=%s, access_token=%s",
			provider->userinfo_endpoint_url, access_token);

	/* get the JSON response */
	if (oidc_util_http_get(r, provider->userinfo_endpoint_url,
			NULL, NULL, access_token, provider->ssl_validate_server, response,
			cfg->http_timeout_long, cfg->outgoing_proxy,
			dir_cfg->pass_cookies) == FALSE)
		return FALSE;

	/* decode and check for an "error" response */
	return oidc_util_decode_json_and_check_error(r, *response, claims);
}

/*
 * based on an account name, perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and store its metadata
 */
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg,
		const char *acct, char **issuer) {

	/* get a handle to the directory config */
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);

	// TODO: maybe show intermediate/progress screen "discovering..."

	oidc_debug(r, "enter, acct=%s", acct);

	const char *resource = apr_psprintf(r->pool, "acct:%s", acct);
	const char *domain = strrchr(acct, '@');
	if (domain == NULL) {
		oidc_error(r, "invalid account name");
		return FALSE;
	}
	domain++;
	const char *url = apr_psprintf(r->pool, "https://%s/.well-known/webfinger",
			domain);

	apr_table_t *params = apr_table_make(r->pool, 1);
	apr_table_addn(params, "resource", resource);
	apr_table_addn(params, "rel", "http://openid.net/specs/connect/1.0/issuer");

	const char *response = NULL;
	if (oidc_util_http_get(r, url, params, NULL, NULL,
			cfg->provider.ssl_validate_server, &response,
			cfg->http_timeout_short, cfg->outgoing_proxy,
			dir_cfg->pass_cookies) == FALSE) {
		/* errors will have been logged by now */
		return FALSE;
	}

	/* decode and see if it is not an error response somehow */
	json_t *j_response = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &j_response) == FALSE)
		return FALSE;

	/* get the links parameter */
	json_t *j_links = json_object_get(j_response, "links");
	if ((j_links == NULL) || (!json_is_array(j_links))) {
		oidc_error(r, "response JSON object did not contain a \"links\" array");
		json_decref(j_response);
		return FALSE;
	}

	/* get the one-and-only object in the "links" array */
	json_t *j_object = json_array_get(j_links, 0);
	if ((j_object == NULL) || (!json_is_object(j_object))) {
		oidc_error(r,
				"response JSON object did not contain a JSON object as the first element in the \"links\" array");
		json_decref(j_response);
		return FALSE;
	}

	/* get the href from that object, which is the issuer value */
	json_t *j_href = json_object_get(j_object, "href");
	if ((j_href == NULL) || (!json_is_string(j_href))) {
		oidc_error(r,
				"response JSON object did not contain a \"href\" element in the first \"links\" array object");
		json_decref(j_response);
		return FALSE;
	}

	*issuer = apr_pstrdup(r->pool, json_string_value(j_href));

	oidc_debug(r,
			"returning issuer \"%s\" for account \"%s\" after doing successful webfinger-based discovery",
			*issuer, acct);

	json_decref(j_response);

	return TRUE;
}

int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c) {

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

	const char *html_body =
			"    <p>Submitting...</p>\n"
			"    <form method=\"post\" action=\"\">\n"
			"      <p>\n"
			"        <input type=\"hidden\" name=\"response_mode\" value=\"fragment\">\n"
			"      </p>\n"
			"    </form>\n";

	return oidc_util_html_send(r, "Submitting...", java_script, "postOnLoad",
			html_body, DONE);
}

/*
 * check a provided hash value (at_hash|c_hash) against a corresponding hash calculated for a specified value and algorithm
 */
static apr_byte_t oidc_proto_validate_hash(request_rec *r, const char *alg,
		const char *hash, const char *value, const char *type) {

	char *calc = NULL;
	unsigned int hash_len = 0;
	apr_jwt_error_t err;

	/* hash the provided access_token */
	if (apr_jws_hash_string(r->pool, alg, value, &calc, &hash_len,
			&err) == FALSE) {
		oidc_error(r, "apr_jws_hash_string failed: %s",
				apr_jwt_e2s(r->pool, err));
		return FALSE;
	}

	/* calculate the base64url-encoded value of the hash */
	char *encoded = NULL;
	oidc_base64url_encode(r, &encoded, calc, apr_jws_hash_length(alg) / 2, 1);

	/* compare the calculated hash against the provided hash */
	if ((apr_strnatcmp(encoded, hash) != 0)) {
		oidc_error(r,
				"provided \"%s\" hash value (%s) does not match the calculated value (%s)",
				type, hash, encoded);
		return FALSE;
	}

	oidc_debug(r,
			"successfully validated the provided \"%s\" hash value (%s) against the calculated value (%s)",
			type, hash, encoded);

	return TRUE;
}

/*
 * check a hash value in the id_token against the corresponding hash calculated over a provided value
 */
static apr_byte_t oidc_proto_validate_hash_value(request_rec *r,
		oidc_provider_t *provider, apr_jwt_t *jwt, const char *response_type,
		const char *value, const char *key,
		apr_array_header_t *required_for_flows) {

	/*
	 * get the hash value from the id_token
	 */
	char *hash = NULL;
	apr_jwt_get_string(r->pool, jwt->payload.value.json, key, FALSE, &hash,
			NULL);

	/*
	 * check if the hash was present
	 */
	if (hash == NULL) {

		/* no hash..., now see if the flow required it */
		int i;
		for (i = 0; i < required_for_flows->nelts; i++) {
			if (oidc_util_spaced_string_equals(r->pool, response_type,
					((const char**) required_for_flows->elts)[i])) {
				oidc_warn(r, "flow is \"%s\", but no %s found in id_token",
						response_type, key);
				return FALSE;
			}
		}

		/* no hash but it was not required anyway */
		return TRUE;
	}

	/*
	 * we have a hash, validate it and return the result
	 */
	return oidc_proto_validate_hash(r, jwt->header.alg, hash, value, key);
}

/*
 * check the c_hash value in the id_token against the code
 */
apr_byte_t oidc_proto_validate_code(request_rec *r, oidc_provider_t *provider,
		apr_jwt_t *jwt, const char *response_type, const char *code) {
	apr_array_header_t *required_for_flows = apr_array_make(r->pool, 2,
			sizeof(const char*));
	*(const char**) apr_array_push(required_for_flows) = "code id_token";
	*(const char**) apr_array_push(required_for_flows) = "code id_token token";
	return oidc_proto_validate_hash_value(r, provider, jwt, response_type, code,
			"c_hash", required_for_flows);
}

/*
 * check the at_hash value in the id_token against the access_token
 */
apr_byte_t oidc_proto_validate_access_token(request_rec *r,
		oidc_provider_t *provider, apr_jwt_t *jwt, const char *response_type,
		const char *access_token, const char *token_type) {
	apr_array_header_t *required_for_flows = apr_array_make(r->pool, 2,
			sizeof(const char*));
	*(const char**) apr_array_push(required_for_flows) = "id_token token";
	*(const char**) apr_array_push(required_for_flows) = "code id_token token";
	return oidc_proto_validate_hash_value(r, provider, jwt, response_type,
			access_token, "at_hash", required_for_flows);
}

/*
 * return the supported flows
 */
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 6, sizeof(const char*));
	*(const char**) apr_array_push(result) = "code";
	*(const char**) apr_array_push(result) = "id_token";
	*(const char**) apr_array_push(result) = "id_token token";
	*(const char**) apr_array_push(result) = "code id_token";
	*(const char**) apr_array_push(result) = "code token";
	*(const char**) apr_array_push(result) = "code id_token token";
	return result;
}

/*
 * check if a particular OpenID Connect flow is supported
 */
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow) {
	apr_array_header_t *flows = oidc_proto_supported_flows(pool);
	int i;
	for (i = 0; i < flows->nelts; i++) {
		if (oidc_util_spaced_string_equals(pool, flow,
				((const char**) flows->elts)[i]))
			return TRUE;
	}
	return FALSE;
}

/*
 * check the required parameters for the various flows on receipt of the authorization response
 */
apr_byte_t oidc_proto_validate_authorization_response(request_rec *r,
		const char *response_type, const char *requested_response_mode,
		char **code, char **id_token, char **access_token, char **token_type,
		const char *used_response_mode) {

	oidc_debug(r,
			"enter, response_type=%s, requested_response_mode=%s, code=%s, id_token=%s, access_token=%s, token_type=%s, used_response_mode=%s",
			response_type, requested_response_mode, *code, *id_token,
			*access_token, *token_type, used_response_mode);

	/* check the requested response mode against the one used by the OP */
	if ((requested_response_mode != NULL)
			&& (strcmp(requested_response_mode, used_response_mode)) != 0) {
		/*
		 * only warn because I'm not sure that most OPs will respect a requested
		 * response_mode and rather use the default for the flow
		 */
		oidc_warn(r,
				"requested response_mode is \"%s\" the provider used \"%s\" for the authorization response...",
				requested_response_mode, used_response_mode);
	}

	/*
	 * check code parameter
	 */
	if (oidc_util_spaced_string_contains(r->pool, response_type, "code")) {

		if (*code == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"code\" parameter found in the authorization response",
					response_type);
			return FALSE;
		}

	} else {

		if (*code != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is a \"code\" parameter in the authorization response that will be dropped",
					response_type);
			*code = NULL;
		}
	}

	/*
	 * check id_token parameter
	 */
	if (oidc_util_spaced_string_contains(r->pool, response_type, "id_token")) {

		if (*id_token == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"id_token\" parameter found in the authorization response",
					response_type);
			return FALSE;
		}

	} else {

		if (*id_token != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is an \"id_token\" parameter in the authorization response that will be dropped",
					response_type);
			*id_token = NULL;
		}

	}

	/*
	 * check access_token parameter
	 */
	if (oidc_util_spaced_string_contains(r->pool, response_type, "token")) {

		if (*access_token == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"access_token\" parameter found in the authorization response",
					response_type);
			return FALSE;
		}

		if (*token_type == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"token_type\" parameter found in the authorization response",
					response_type);
			return FALSE;
		}

	} else {

		if (*access_token != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is an \"access_token\" parameter in the authorization response that will be dropped",
					response_type);
			*access_token = NULL;
		}

		if (*token_type != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is a \"token_type\" parameter in the authorization response that will be dropped",
					response_type);
			*token_type = NULL;
		}

	}

	return TRUE;
}

/*
 * check the required parameters for the various flows after resolving the authorization code
 */
apr_byte_t oidc_proto_validate_code_response(request_rec *r,
		const char *response_type, char **id_token, char **access_token,
		char **token_type) {

	oidc_debug(r, "enter");

	/*
	 * check id_token parameter
	 */
	if (!oidc_util_spaced_string_contains(r->pool, response_type, "id_token")) {

		if (*id_token == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"id_token\" parameter found in the code response",
					response_type);
			return FALSE;
		}

	} else {

		if (*id_token != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is an \"id_token\" parameter in the code response that will be dropped",
					response_type);
			*id_token = NULL;
		}

	}

	/*
	 * check access_token parameter
	 */
	if (!oidc_util_spaced_string_contains(r->pool, response_type, "token")) {

		if (*access_token == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"access_token\" parameter found in the code response",
					response_type);
			return FALSE;
		}

		if (*token_type == NULL) {
			oidc_error(r,
					"requested flow is \"%s\" but no \"token_type\" parameter found in the code response",
					response_type);
			return FALSE;
		}

	} else {

		if (*access_token != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is an \"access_token\" parameter in the code response that will be dropped",
					response_type);
			*access_token = NULL;
		}

		if (*token_type != NULL) {
			oidc_warn(r,
					"requested flow is \"%s\" but there is a \"token_type\" parameter in the code response that will be dropped",
					response_type);
			*token_type = NULL;
		}

	}

	return TRUE;
}
