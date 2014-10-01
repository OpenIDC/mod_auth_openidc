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

#include <apr_lib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include "mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/* the grant type string that the Authorization server expects when validating access tokens */
#define OIDC_OAUTH_VALIDATION_GRANT_TYPE "urn:pingidentity.com:oauth2:grant_type:validate_bearer"

/*
 * validate an access token against the validation endpoint of the Authorization server and gets a response back
 */
static int oidc_oauth_validate_access_token(request_rec *r, oidc_cfg *c,
		const char *token, const char **response) {

	/* assemble parameters to call the token endpoint for validation */
	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_addn(params, "grant_type", OIDC_OAUTH_VALIDATION_GRANT_TYPE);
	apr_table_addn(params, "token", token);

	/* see if we want to do basic auth or post-param-based auth */
	const char *basic_auth = NULL;
	if ((c->oauth.validate_endpoint_auth != NULL)
			&& (apr_strnatcmp(c->oauth.validate_endpoint_auth,
					"client_secret_post") == 0)) {
		apr_table_addn(params, "client_id", c->oauth.client_id);
		apr_table_addn(params, "client_secret", c->oauth.client_secret);
	} else {
		basic_auth = apr_psprintf(r->pool, "%s:%s", c->oauth.client_id,
				c->oauth.client_secret);
	}

	/* call the endpoint with the constructed parameter set and return the resulting response */
	return oidc_util_http_post_form(r, c->oauth.validate_endpoint_url, params,
			basic_auth, NULL, c->oauth.ssl_validate_server, response,
			c->http_timeout_long, c->outgoing_proxy);
}

/*
 * get the authorization header that should contain a bearer token
 */
static apr_byte_t oidc_oauth_get_bearer_token(request_rec *r,
		const char **access_token) {

	/* get the authorization header */
	const char *auth_line;
	auth_line = apr_table_get(r->headers_in, "Authorization");
	if (!auth_line) {
		oidc_debug(r, "no authorization header found");
		return FALSE;
	}

	/* look for the Bearer keyword */
	if (apr_strnatcasecmp(ap_getword(r->pool, &auth_line, ' '), "Bearer")) {
		oidc_error(r, "client used unsupported authentication scheme: %s",
				r->uri);
		return FALSE;
	}

	/* skip any spaces after the Bearer keyword */
	while (apr_isspace(*auth_line)) {
		auth_line++;
	}

	/* copy the result in to the access_token */
	*access_token = apr_pstrdup(r->pool, auth_line);

	/* log some stuff */
	oidc_debug(r, "bearer token: %s", *access_token);

	return TRUE;
}

/*
 * resolve and validate an access_token against the configured Authorization Server
 */
static apr_byte_t oidc_oauth_resolve_access_token(request_rec *r, oidc_cfg *c,
		const char *access_token, json_t **token, char **response) {

	json_t *result = NULL;
	const char *json = NULL;

	/* see if we've got the claims for this access_token cached already */
	c->cache->get(r, OIDC_CACHE_SECTION_ACCESS_TOKEN, access_token, &json);

	if (json == NULL) {

		/* not cached, go out and validate the access_token against the Authorization server and get the JSON claims back */
		if (oidc_oauth_validate_access_token(r, c, access_token, &json) == FALSE) {
			oidc_error(r,
					"could not get a validation response from the Authorization server");
			return FALSE;
		}

		/* decode and see if it is not an error response somehow */
		if (oidc_util_decode_json_and_check_error(r, json, &result) == FALSE)
			return FALSE;

		/* get and check the expiry timestamp */
		json_t *expires_in = json_object_get(result, "expires_in");
		if ((expires_in == NULL) || (!json_is_number(expires_in))) {
			oidc_error(r,
					"response JSON object did not contain an \"expires_in\" number");
			json_decref(result);
			return FALSE;
		}
		if (json_integer_value(expires_in) <= 0) {
			oidc_warn(r,
					"\"expires_in\" number <= 0 (%" JSON_INTEGER_FORMAT "); token already expired...",
					json_integer_value(expires_in));
			json_decref(result);
			return FALSE;
		}

		/* set it in the cache so subsequent request don't need to validate the access_token and get the claims anymore */
		c->cache->set(r, OIDC_CACHE_SECTION_ACCESS_TOKEN, access_token, json,
				apr_time_now() + apr_time_from_sec(json_integer_value(expires_in)));

	} else {

		/* we got the claims for this access_token in our cache, decode it in to a JSON structure */
		json_error_t json_error;
		result = json_loads(json, 0, &json_error);
		if (result == NULL) {
			oidc_error(r, "cached JSON was corrupted: %s", json_error.text);
			return FALSE;
		}
	}

	/* return the access_token JSON object */
	json_t *tkn = json_object_get(result, "access_token");
	if ((tkn == NULL) || (!json_is_object(tkn))) {
		oidc_error(r,
				"response JSON object did not contain an access_token object");
		json_decref(result);
		return FALSE;
	}

	/* copy over client_id from resolved token in to access_token to apply authorization on that */
	json_object_set(tkn, "client_id", json_object_get(result, "client_id"));
	//json_object_set(tkn, "scope", json_object_get(result, "scope"));

	/* copy over space separated scope value but do it in an array for authorization purposes */
	char *val;
	const char *data = apr_pstrdup(r->pool,
			json_string_value(json_object_get(result, "scope")));
	json_t *a_scopes = json_array();
	while (*data && (val = ap_getword_white(r->pool, &data))) {
		json_array_append_new(a_scopes, json_string(val));
	}
	json_object_set_new(tkn, "scope", a_scopes);

	/* return only the pimped access_token results */
	*token = json_deep_copy(tkn);
	char *s_token = json_dumps(*token, 0);
	*response = apr_pstrdup(r->pool, s_token);
	free(s_token);

	json_decref(result);
	return TRUE;
}

/*
 * set the unique user identifier that will be propagated in the Apache r->user and REMOTE_USER variables
 */
static apr_byte_t oidc_oauth_set_remote_user(request_rec *r, oidc_cfg *c,
		json_t *token) {

	/* get the configured claim name to populate REMOTE_USER with (defaults to "Username") */
	char *claim_name = apr_pstrdup(r->pool, c->oauth.remote_user_claim);

	/* get the claim value from the resolved token JSON response to use as the REMOTE_USER key */
	json_t *username = json_object_get(token, claim_name);
	if ((username == NULL) || (!json_is_string(username))) {
		oidc_warn(r, "response JSON object did not contain a \"%s\" string",
				claim_name);
		return FALSE;
	}

	r->user = apr_pstrdup(r->pool, json_string_value(username));

	oidc_debug(r, "set REMOTE_USER to claim %s=%s", claim_name,
			json_string_value(username));

	return TRUE;
}

/*
 * main routine: handle OAuth 2.0 authentication/authorization
 */
int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c) {

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

			return OK;
		}
	}

	/* we don't have a session yet */

	/* get the bearer access token from the Authorization header */
	const char *access_token = NULL;
	if (oidc_oauth_get_bearer_token(r, &access_token) == FALSE)
		return HTTP_UNAUTHORIZED;

	/* validate the obtained access token against the OAuth AS validation endpoint */
	json_t *token = NULL;
	char *s_token = NULL;
	if (oidc_oauth_resolve_access_token(r, c, access_token, &token,
			&s_token) == FALSE)
		return HTTP_UNAUTHORIZED;

	/* check that we've got something back */
	if (token == NULL) {
		oidc_error(r, "could not resolve claims (token == NULL)");
		return HTTP_UNAUTHORIZED;
	}

	/* store the parsed token (cq. the claims from the response) in the request state so it can be accessed by the authz routines */
	oidc_request_state_set(r, OIDC_CLAIMS_SESSION_KEY, (const char *) s_token);

	/* set the REMOTE_USER variable */
	if (oidc_oauth_set_remote_user(r, c, token) == FALSE) {
		oidc_error(r,
				"remote user could not be set, aborting with HTTP_UNAUTHORIZED");
		return HTTP_UNAUTHORIZED;
	}

	/* get a handle to the director config */
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);

	/* set the user authentication HTTP header if set and required */
	if ((r->user != NULL) && (dir_cfg->authn_header != NULL)) {
		oidc_debug(r, "setting authn header (%s) to: %s", dir_cfg->authn_header,
				r->user);
		apr_table_set(r->headers_in, dir_cfg->authn_header, r->user);
	}

	/* set the resolved claims in the HTTP headers for the target application */
	oidc_util_set_app_headers(r, token, c->claim_prefix, c->claim_delimiter);

	/* set the access_token in the app headers */
	if (access_token != NULL) {
		oidc_util_set_app_header(r, "access_token", access_token, "OIDC_");
	}

	/* free JSON resources */
	json_decref(token);

	return OK;
}
