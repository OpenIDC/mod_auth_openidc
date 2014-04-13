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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include "mod_auth_openidc.h"
#include "jose/apr_jose.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/*
 * send an OpenID Connect authorization request to the specified provider
 */
int oidc_proto_authorization_request(request_rec *r,
		struct oidc_provider_t *provider, const char *redirect_uri,
		const char *state, const char *original_url, const char *nonce) {

	/* log some stuff */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_authorization_request: entering (issuer=%s, redirect_uri=%s, original_url=%s, state=%s, nonce=%s)",
			provider->issuer, redirect_uri, original_url, state, nonce);

	/* assemble the full URL as the authorization request to the OP where we want to redirect to */
	char *destination =
			apr_psprintf(r->pool,
					"%s%sresponse_type=%s&scope=%s&client_id=%s&state=%s&redirect_uri=%s",
					provider->authorization_endpoint_url,
					(strchr(provider->authorization_endpoint_url, '?') != NULL ?
							"&" : "?"),
					oidc_util_escape_string(r, provider->response_type),
					oidc_util_escape_string(r, provider->scope),
					oidc_util_escape_string(r, provider->client_id),
					oidc_util_escape_string(r, state),
					oidc_util_escape_string(r, redirect_uri));

	/*
	 * see if the chosen flow requires a nonce parameter
	 *
	 * TODO: I'd like to include the nonce in the code flow as well but Google does not allow me to do that:
	 * Error: invalid_request: Parameter not allowed for this message type: nonce
	 */
	if ((strstr(provider->response_type, "id_token") != NULL)
			|| (strcmp(provider->response_type, "token") == 0)) {
		destination = apr_psprintf(r->pool, "%s&nonce=%s", destination,
				oidc_util_escape_string(r, nonce));
		//destination = apr_psprintf(r->pool, "%s&response_mode=fragment", destination);
	}

	/* add the redirect location header */
	apr_table_add(r->headers_out, "Location", destination);

	/* some more logging */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_authorization_request: adding outgoing header: Location: %s",
			destination);

	/* and tell Apache to return an HTTP Redirect (302) message */
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * indicate whether the incoming HTTP request is an OpenID Connect Authorization Response from a Basic Client flow, syntax-wise
 */
apr_byte_t oidc_proto_is_basic_authorization_response(request_rec *r,
		oidc_cfg *cfg) {

	/* see if this is a call to the configured redirect_uri and the "code" and "state" parameters are present */
	return ((oidc_util_request_matches_url(r, cfg->redirect_uri) == TRUE)
			&& oidc_util_request_has_parameter(r, "code")
			&& oidc_util_request_has_parameter(r, "state"));
}

/*
 * indicate whether the incoming HTTP request is an OpenID Connect Authorization Response from an Implicit Client flow, syntax-wise
 */
apr_byte_t oidc_proto_is_implicit_post(request_rec *r, oidc_cfg *cfg) {

	/* see if this is a call to the configured redirect_uri and it is a POST */
	return ((oidc_util_request_matches_url(r, cfg->redirect_uri) == TRUE)
			&& (r->method_number == M_POST));
}

/*
 * indicate whether the incoming HTTP request is an OpenID Connect Authorization Response from an Implicit Client flow using the query parameter response type, syntax-wise
 */
apr_byte_t oidc_proto_is_implicit_redirect(request_rec *r, oidc_cfg *cfg) {

	/* see if this is a call to the configured redirect_uri and it is a POST */
	return ((oidc_util_request_matches_url(r, cfg->redirect_uri) == TRUE)
			&& (r->method_number == M_GET)
			&& oidc_util_request_has_parameter(r, "state")
			&& oidc_util_request_has_parameter(r, "id_token"));
}

/*
 * if a nonce was passed in the authorization request (and stored in the browser state),
 * check that it matches the nonce value in the id_token payload
 */
static apr_byte_t oidc_proto_validate_nonce(request_rec *r, oidc_cfg *cfg,
		const char *nonce, apr_jwt_t *jwt) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_validate_nonce: looking for nonce: %s", nonce);

	/* see if we have this nonce cached already */
	const char *replay = NULL;
	cfg->cache->get(r, nonce, &replay);
	if (replay != NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_nonce: the nonce value (%s) passed in the browser state was found in the cache already; possible replay attack!?",
				nonce);
		return FALSE;
	}

	/* get the "nonce" value in the id_token payload */
	char *j_nonce = NULL;
	apr_jwt_get_string(r->pool, &jwt->payload.value, "nonce", &j_nonce);

	if (j_nonce == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_nonce: id_token JSON payload did not contain a \"nonce\" string");
		return FALSE;
	}

	/* see if the nonce in the id_token matches the one that we sent in the authorization request */
	if (apr_strnatcmp(nonce, j_nonce) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_nonce: the nonce value (%s) in the id_token did not match the one stored in the browser session (%s)",
				j_nonce, nonce);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate the "aud" and "azp" claims in the id_token payload
 */
static apr_byte_t oidc_proto_validate_aud_and_azp(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, apr_json_value_t *j_payload) {

	/* get the "azp" value from the JSON payload, which may be NULL */
	apr_json_value_t *azp = apr_hash_get(j_payload->value.object, "azp",
	APR_HASH_KEY_STRING);
	if ((azp != NULL) && (azp->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_aud_and_azp: id_token JSON payload contained an \"azp\" value, but it was not a string");
		return FALSE;
	}

	/*
	 * the "azp" claim is only needed when the id_token has a single audience value and that audience
	 * is different than the authorized party; it MAY be included even when the authorized party is
	 * the same as the sole audience.
	 */
	if ((azp != NULL)
			&& (apr_strnatcmp(azp->value.string.p, provider->client_id) != 0)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_aud_and_azp: the \"azp\" claim (%s) is present in the id_token, but is not equal to the configured client_id (%s)",
				azp->value.string.p, provider->client_id);
		return FALSE;
	}

	/* get the "aud" value from the JSON payload */
	apr_json_value_t *aud = apr_hash_get(j_payload->value.object, "aud",
	APR_HASH_KEY_STRING);
	if (aud != NULL) {

		/* check if it is a single-value */
		if (aud->type == APR_JSON_STRING) {

			/* a single-valued audience must be equal to our client_id */
			if (apr_strnatcmp(aud->value.string.p, provider->client_id) != 0) {

				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"oidc_proto_validate_aud_and_azp: the configured client_id (%s) did not match the \"aud\" claim value (%s) in the id_token",
						provider->client_id, aud->value.string.p);
				return FALSE;
			}

			/* check if this is a multi-valued audience */
		} else if (aud->type == APR_JSON_ARRAY) {

			if ((aud->value.array->nelts > 1) && (azp == NULL)) {
				ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
						"oidc_proto_validate_aud_and_azp: the \"aud\" claim value in the id_token is an array with more than 1 element, but \"azp\" claim is not present (a SHOULD in the spec...)");
			}

			/* loop over the audience values */
			int i;
			for (i = 0; i < aud->value.array->nelts; i++) {

				apr_json_value_t *elem = APR_ARRAY_IDX(aud->value.array, i,
						apr_json_value_t *);

				/* check if it is a string, warn otherwise */
				if (elem->type != APR_JSON_STRING) {
					ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
							"oidc_proto_validate_aud_and_azp: the \"aud\" claim is an array but it contains an entry with an unhandled JSON object type [%d]",
							elem->type);
					continue;
				}

				/* we're looking for a value in the list that matches our client id */
				if (apr_strnatcmp(elem->value.string.p, provider->client_id)
						== 0) {
					break;
				}
			}

			/* check if we've found a match or not */
			if (i == aud->value.array->nelts) {

				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"oidc_proto_validate_aud_and_azp: our configured client_id (%s) could not be found in the array of values for \"aud\" claim",
						provider->client_id);
				return FALSE;
			}

		} else {

			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_validate_aud_and_azp: id_token JSON payload \"aud\" claim is not a string nor an array");
			return FALSE;
		}

	} else {

		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_aud_and_azp: id_token JSON payload did not contain an \"aud\" claim");
		return FALSE;
	}

	return TRUE;
}

/*
 * check whether the provided JSON payload (in the j_payload parameter) is a valid id_token for the specified "provider"
 */
static apr_byte_t oidc_proto_validate_idtoken(request_rec *r,
		oidc_provider_t *provider, apr_jwt_t *jwt, const char *nonce) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_validate_idtoken: entering (nonce=%s)", nonce);

	/* if a nonce is not passed, we're doing a ("code") flow where the nonce is optional */
	if (nonce != NULL) {
		/* if present, verify the nonce */
		if (oidc_proto_validate_nonce(r, cfg, nonce, jwt) == FALSE)
			return FALSE;
	}

	/* issuer is mandatory in id_token */
	if (jwt->payload.iss == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_idtoken: response JSON object did not contain an \"iss\" string");
		return FALSE;
	}

	/* check if the issuer matches the requested value */
	if (oidc_util_issuer_match(provider->issuer, jwt->payload.iss) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_idtoken: configured issuer (%s) does not match received \"iss\" value in id_token (%s)",
				provider->issuer, jwt->payload.iss);
		return FALSE;
	}

	/* check the "exp" timestamp */

	/* check if this id_token has already expired */
	if (apr_time_now() > jwt->payload.exp) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_idtoken: \"exp\" validation failure (%" APR_TIME_T_FMT "): id_token expired",
				jwt->payload.exp);
		return FALSE;
	}

	if (jwt->payload.iat == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_idtoken: id_token JSON payload did not contain an \"iat\" number value");
		return FALSE;
	}

	/* check if this id_token has been issued just now +- slack (default 10 minutes) */
	if ((apr_time_now() - apr_time_from_sec(provider->idtoken_iat_slack))
			> jwt->payload.iat) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_idtoken: \"iat\" validation failure (%" APR_TIME_T_FMT "): id_token was issued more than %d seconds ago",
				jwt->payload.iat, provider->idtoken_iat_slack);
		return FALSE;
	}
	if ((apr_time_now() + apr_time_from_sec(provider->idtoken_iat_slack))
			< jwt->payload.iat) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_idtoken: \"iat\" validation failure (%" APR_TIME_T_FMT "): id_token was issued more than %d seconds in the future",
				jwt->payload.iat, provider->idtoken_iat_slack);
		return FALSE;
	}

	if (nonce != NULL) {
		/* cache the nonce for the window time of the token for replay prevention plus 10 seconds for safety */
		cfg->cache->set(r, nonce, nonce,
				apr_time_from_sec(provider->idtoken_iat_slack * 2 + 10));
	}

	if (jwt->payload.sub == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_validate_idtoken: id_token JSON payload did not contain the required-by-spec \"sub\" string value");
		return FALSE;
	}

	/* verify the "aud" and "azp" values */
	if (oidc_proto_validate_aud_and_azp(r, cfg, provider,
			jwt->payload.value.json) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * get the key from the JWKs that corresponds with the key specified in the header
 */
static apr_jwk_t *oidc_proto_get_key_from_jwks(request_rec *r,
		apr_jwt_header_t *jwt_hdr, apr_json_value_t *j_jwks) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_get_key_from_jwks: search for kid \"%s\"",
			jwt_hdr->kid);

	apr_json_value_t *keys = apr_hash_get(j_jwks->value.object, "keys",
			APR_HASH_KEY_STRING);

	apr_jwk_t *jwk = NULL;

	int i;
	for (i = 0; i < keys->value.array->nelts; i++) {

		apr_json_value_t *elem = APR_ARRAY_IDX(keys->value.array, i,
				apr_json_value_t *);
		if (elem->type != APR_JSON_OBJECT) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_proto_get_key_from_jwks: \"keys\" array element is not a JSON object, skipping");
			continue;
		}
		apr_json_value_t *kty = apr_hash_get(elem->value.object, "kty",
				APR_HASH_KEY_STRING);
		if (strcmp(kty->value.string.p, "RSA") != 0) {
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_proto_get_key_from_jwks: \"keys\" array element is not an RSA key type (%s), skipping",
					kty->value.string.p);
			continue;
		}
		if (jwt_hdr->kid == NULL) {
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_proto_get_key_from_jwks: no kid to match, return first key found");

			apr_jwk_parse_json(r->pool, elem, NULL, &jwk);
			break;
		}
		apr_json_value_t *ekid = apr_hash_get(elem->value.object, "kid",
				APR_HASH_KEY_STRING);
		if (ekid == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_proto_get_key_from_jwks: \"keys\" array element does not have a \"kid\" entry, skipping");
			continue;
		}
		if (apr_strnatcmp(jwt_hdr->kid, ekid->value.string.p) == 0) {
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_proto_get_key_from_jwks: found matching kid: \"%s\"",
					jwt_hdr->kid);

			apr_jwk_parse_json(r->pool, elem, NULL, &jwk);
			break;
		}
	}

	return jwk;
}

/*
 * get the key from the (possibly cached) set of JWKs on the jwk_uri that corresponds with the key specified in the header
 */
static apr_jwk_t *oidc_proto_get_key_from_jwk_uri(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, apr_jwt_header_t *jwt_hdr,
		apr_byte_t *refresh) {
	apr_json_value_t *j_jwks = NULL;
	apr_jwk_t *jwk = NULL;

	/* get the set of JSON Web Keys for this provider (possibly by downloading them from the specified provider->jwk_uri) */
	oidc_metadata_jwks_get(r, cfg, provider, &j_jwks, refresh);
	if (j_jwks == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_get_key_from_jwk_uri: could not resolve JSON Web Keys");
		return NULL;
	}

	/* get the key corresponding to the kid from the header, referencing the key that was used to sign this message */
	jwk = oidc_proto_get_key_from_jwks(r, jwt_hdr, j_jwks);

	/* see what we've got back */
	if ((jwk == NULL) && (refresh == FALSE)) {

		/* we did not get a key, but we have not refreshed the JWKs from the jwks_uri yet */

		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_proto_get_key_from_jwk_uri: could not find a key in the cached JSON Web Keys, doing a forced refresh");

		/* get the set of JSON Web Keys for this provider forcing a fresh download from the specified provider->jwk_uri) */
		*refresh = TRUE;
		oidc_metadata_jwks_get(r, cfg, provider, &j_jwks, refresh);
		if (j_jwks == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_get_key_from_jwk_uri: could not refresh JSON Web Keys");
			return NULL;
		}

		jwk = oidc_proto_get_key_from_jwks(r, jwt_hdr, j_jwks);

	}

	return jwk;
}

/*
 * verify the signature on an id_token
 */
static apr_byte_t oidc_proto_idtoken_verify_signature(request_rec *r,
		oidc_cfg *cfg, oidc_provider_t *provider, apr_jwt_t *jwt,
		apr_byte_t *refresh) {

	apr_byte_t result = FALSE;

	if (apr_jws_signature_is_hmac(r->pool, jwt)) {

		result = apr_jws_verify_hmac(r->pool, jwt, provider->client_secret);

	} else if (apr_jws_signature_is_rsa(r->pool, jwt)) {

		/* get the key from the JWKs that corresponds with the key specified in the header */
		apr_jwk_t *jwk = oidc_proto_get_key_from_jwk_uri(r, cfg, provider,
				&jwt->header, refresh);

		if (jwk != NULL) {

			result = apr_jws_verify_rsa(r->pool, jwt, jwk);

		} else {

			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_idtoken_verify_signature: could not find a key in the JSON Web Keys");

			if (*refresh == FALSE) {

				/* do it again, forcing a JWKS refresh */
				*refresh = TRUE;
				result = oidc_proto_idtoken_verify_signature(r, cfg, provider, jwt, refresh);
			}
		}
	}

	if (result == TRUE) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_proto_idtoken_verify_signature: signature with algorithm \"%s\" verified OK!",
				jwt->header.alg);
	}

	return result;
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
	apr_jwt_get_string(r->pool, &jwt->payload.value, claim_name, &username);

	if (username == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_set_remote_user: OIDCRemoteUserClaim is set to \"%s\", but the id_token JSON payload did not contain a \"%s\" string",
				c->remote_user_claim, claim_name);
		return FALSE;
	}

	/* set the unique username in the session (will propagate to r->user/REMOTE_USER) */
	*user = post_fix_with_issuer ?
			apr_psprintf(r->pool, "%s@%s", username, issuer) :
			apr_pstrdup(r->pool, username);

	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"oidc_proto_set_remote_user: set remote_user to %s", *user);

	return TRUE;
}

/*
 * check whether the provided string is a valid id_token and return its parsed contents
 */
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *id_token, const char *nonce,
		char **user, apr_jwt_t **jwt) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_parse_idtoken: entering");

	if (apr_jwt_parse(r->pool, id_token, jwt) == FALSE)
		return FALSE;

	// verify signature unless we did 'code' flow and the algorithm is NONE
	// TODO: should improve "detection": in principle nonce can be used in "code" flow too
//	apr_json_value_t *algorithm = apr_hash_get(j_header->value.object, "alg", APR_HASH_KEY_STRING);
//	if ((strcmp(algorithm->value.string.p, "NONE") != 0) || (nonce != NULL)) {
//		/* verify the signature on the id_token */
//		apr_byte_t refresh = FALSE;
//		if (oidc_proto_idtoken_verify_signature(r, cfg, provider, j_header, signature, apr_pstrcat(r->pool, header, ".", payload, NULL), &refresh) == FALSE) return FALSE;
//	}

	apr_byte_t refresh = FALSE;
	if (oidc_proto_idtoken_verify_signature(r, cfg, provider, *jwt,
			&refresh) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_idtoken: id_token signature could not be validated, aborting");
		return FALSE;
	}

	/* this is where the meat is */
	if (oidc_proto_validate_idtoken(r, provider, *jwt, nonce) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_idtoken: id_token payload could not be validated, aborting");
		return FALSE;
	}

	if (oidc_proto_set_remote_user(r, cfg, provider, *jwt, user) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_idtoken: remote user could not be set, aborting");
		return FALSE;
	}

	/* log our results */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_parse_idtoken: valid id_token for user \"%s\" (expires in %" APR_TIME_T_FMT " seconds)",
			*user, (*jwt)->payload.exp - apr_time_sec(apr_time_now()));

	/* since we've made it so far, we may as well say it is a valid id_token */
	return TRUE;
}

/*
 * resolves the code received from the OP in to an access_token and id_token and returns the parsed contents
 */
apr_byte_t oidc_proto_resolve_code(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, char *code, const char *nonce, char **user,
		apr_jwt_t **jwt, char **s_access_token) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_resolve_code: entering");
	const char *response = NULL;

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_addn(params, "grant_type", "authorization_code");
	apr_table_addn(params, "code", code);
	apr_table_addn(params, "redirect_uri", cfg->redirect_uri);

	/* see if we need to do basic auth or auth-through-post-params (both applied through the HTTP POST method though) */
	const char *basic_auth = NULL;
	if ((apr_strnatcmp(provider->token_endpoint_auth, "client_secret_basic"))
			== 0) {
		basic_auth = apr_psprintf(r->pool, "%s:%s", provider->client_id,
				provider->client_secret);
	} else {
		apr_table_addn(params, "client_id", provider->client_id);
		apr_table_addn(params, "client_secret", provider->client_secret);
	}
	/*
	 if (strcmp(provider->issuer, "https://sts.windows.net/b4ea3de6-839e-4ad1-ae78-c78e5c0cdc06/") == 0) {
	 apr_table_addn(params, "resource", "https://graph.windows.net");
	 }
	 */
	/* resolve the code against the token endpoint */
	if (oidc_util_http_call(r, provider->token_endpoint_url,
	OIDC_HTTP_POST_FORM, params, basic_auth, NULL,
			provider->ssl_validate_server, &response,
			cfg->http_timeout_long) == FALSE) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_proto_resolve_code: could not successfully resolve the \"code\" (%s) against the token endpoint (%s)",
				code, provider->token_endpoint_url);
		return FALSE;
	}

	/* check for errors, the response itself will have been logged already */
	apr_json_value_t *result = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	/* get the access_token from the parsed response */
	apr_json_value_t *access_token = apr_hash_get(result->value.object,
			"access_token", APR_HASH_KEY_STRING);
	if ((access_token == NULL) || (access_token->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_resolve_code: response JSON object did not contain an access_token string");
		return FALSE;
	}

	/* log and set the obtained acces_token */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_resolve_code: returned access_token: %s",
			access_token->value.string.p);
	*s_access_token = apr_pstrdup(r->pool, access_token->value.string.p);

	/* the provider must the token type */
	apr_json_value_t *token_type = apr_hash_get(result->value.object,
			"token_type", APR_HASH_KEY_STRING);
	if ((token_type == NULL) || (token_type->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_resolve_code: response JSON object did not contain a token_type string");
		return FALSE;
	}

	/* we got the type, we only support bearer/Bearer, check that */
	if ((apr_strnatcasecmp(token_type->value.string.p, "Bearer") != 0)
			&& (provider->userinfo_endpoint_url != NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_resolve_code: token_type is \"%s\" and UserInfo endpoint is set: can only deal with Bearer authentication against the UserInfo endpoint!",
				token_type->value.string.p);
		return FALSE;
	}

	/* get the id_token from the response */
	apr_json_value_t *id_token = apr_hash_get(result->value.object, "id_token",
	APR_HASH_KEY_STRING);
	if ((id_token == NULL) || (id_token->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_resolve_code: response JSON object did not contain an id_token string");
		return FALSE;
	}

	/* log and set the obtained id_token */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_resolve_code: returned id_token: %s",
			id_token->value.string.p);

	/* parse and validate the obtained id_token and return success/failure of that */
	return oidc_proto_parse_idtoken(r, cfg, provider, id_token->value.string.p,
			nonce, user, jwt);
}

/*
 * get claims from the OP UserInfo endpoint using the provided access_token
 */
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *access_token,
		const char **response, apr_json_value_t **claims) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_resolve_userinfo: entering, endpoint=%s, access_token=%s",
			provider->userinfo_endpoint_url, access_token);

	/* only do this if an actual endpoint was set */
	if (provider->userinfo_endpoint_url == NULL)
		return FALSE;

	/* get the JSON response */
	if (oidc_util_http_call(r, provider->userinfo_endpoint_url, OIDC_HTTP_GET,
	NULL, NULL, access_token, provider->ssl_validate_server, response,
			cfg->http_timeout_long) == FALSE)
		return FALSE;

	/* decode and check for an "error" response */
	return oidc_util_decode_json_and_check_error(r, *response, claims);
}

/*
 * based on an account name, perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and store its metadata
 */
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg,
		const char *acct, char **issuer) {

	// TODO: maybe show intermediate/progress screen "discovering..."

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_account_based_discovery: entering, acct=%s", acct);

	const char *resource = apr_psprintf(r->pool, "acct:%s", acct);
	const char *domain = strrchr(acct, '@');
	if (domain == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_account_based_discovery: invalid account name");
		return FALSE;
	}
	domain++;
	const char *url = apr_psprintf(r->pool, "https://%s/.well-known/webfinger",
			domain);

	apr_table_t *params = apr_table_make(r->pool, 1);
	apr_table_addn(params, "resource", resource);
	apr_table_addn(params, "rel", "http://openid.net/specs/connect/1.0/issuer");

	const char *response = NULL;
	if (oidc_util_http_call(r, url, OIDC_HTTP_GET, params, NULL, NULL,
			cfg->provider.ssl_validate_server, &response,
			cfg->http_timeout_short) == FALSE) {
		/* errors will have been logged by now */
		return FALSE;
	}

	/* decode and see if it is not an error response somehow */
	apr_json_value_t *j_response = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &j_response) == FALSE)
		return FALSE;

	/* get the links parameter */
	apr_json_value_t *j_links = apr_hash_get(j_response->value.object, "links",
	APR_HASH_KEY_STRING);
	if ((j_links == NULL) || (j_links->type != APR_JSON_ARRAY)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_account_based_discovery: response JSON object did not contain a \"links\" array");
		return FALSE;
	}

	/* get the one-and-only object in the "links" array */
	apr_json_value_t *j_object =
			((apr_json_value_t**) j_links->value.array->elts)[0];
	if ((j_object == NULL) || (j_object->type != APR_JSON_OBJECT)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_account_based_discovery: response JSON object did not contain a JSON object as the first element in the \"links\" array");
		return FALSE;
	}

	/* get the href from that object, which is the issuer value */
	apr_json_value_t *j_href = apr_hash_get(j_object->value.object, "href",
	APR_HASH_KEY_STRING);
	if ((j_href == NULL) || (j_href->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_account_based_discovery: response JSON object did not contain a \"href\" element in the first \"links\" array object");
		return FALSE;
	}

	*issuer = (char *) j_href->value.string.p;

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_account_based_discovery: returning issuer \"%s\" for account \"%s\" after doing succesful webfinger-based discovery",
			*issuer, acct);

	return TRUE;
}

int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_javascript_implicit: entering");

//	char *java_script = NULL;
//	if (oidc_util_file_read(r, "/Users/hzandbelt/eclipse-workspace/mod_auth_openidc/src/implicit_post.html", &java_script) == FALSE) return HTTP_INTERNAL_SERVER_ERROR;

	const char *java_script =
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
					"<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">\n"
					"  <head>\n"
					"    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\n"
					"    <script type=\"text/javascript\">\n"
					"      function postOnLoad() {\n"
					"        var params = {}\n"
					"        encoded = location.hash.substring(1).split(\"&\");\n"
					"        for (i = 0; i < encoded.length; i++) {\n"
					"          encoded[i].replace(/\\+/g, \" \");\n"
					"          var n = encoded[i].indexOf(\"=\");\n"
					"          var input = document.createElement(\"input\");\n"
					"          input.type = \"hidden\";\n"
					"          input.name = decodeURIComponent(encoded[i].substring(0, n));\n"
					"          input.value = decodeURIComponent(encoded[i].substring(n+1));\n"
					"          document.forms[0].appendChild(input);\n"
					"        }\n"
					"        document.forms[0].action = window.location.href.substr(0, window.location.href.indexOf('#'));\n"
					"        document.forms[0].submit();\n"
					"      }\n"
					"    </script>\n"
					"    <title>Submitting...</title>\n"
					"  </head>\n"
					"  <body onload=\"postOnLoad()\">\n"
					"    <p>Submitting...</p>\n"
					"    <form method=\"post\"/>\n"
					"  </body>\n"
					"</html>\n";

	//return oidc_util_http_sendstring(r, apr_psprintf(r->pool, java_script, c->redirect_uri), OK);
	//return oidc_util_http_sendstring(r, apr_psprintf(r->pool, java_script, c->redirect_uri), HTTP_MOVED_TEMPORARILY);
	return oidc_util_http_sendstring(r, java_script, HTTP_UNAUTHORIZED);
}

