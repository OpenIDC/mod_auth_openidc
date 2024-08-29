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

#include "metrics.h"
#include "proto/proto.h"
#include "util.h"

/*
 * indicate whether the incoming HTTP POST request is an OpenID Connect Authorization Response
 */
apr_byte_t oidc_proto_response_is_post(request_rec *r, oidc_cfg_t *cfg) {

	/* prereq: this is a call to the configured redirect_uri; see if it is a POST */
	return (r->method_number == M_POST);
}

/*
 * indicate whether the incoming HTTP GET request is an OpenID Connect Authorization Response
 */
apr_byte_t oidc_proto_response_is_redirect(request_rec *r, oidc_cfg_t *cfg) {

	/* prereq: this is a call to the configured redirect_uri; see if it is a GET with id_token or code
	 * parameters */
	return ((r->method_number == M_GET) && (oidc_util_request_has_parameter(r, OIDC_PROTO_ID_TOKEN) ||
						oidc_util_request_has_parameter(r, OIDC_PROTO_CODE)));
}

/*
 * check the required parameters for the various flows after resolving the authorization code
 */
static apr_byte_t oidc_proto_validate_code_response(request_rec *r, const char *response_type, char *id_token,
						    char *access_token, char *token_type) {

	oidc_debug(r, "enter");

	/*
	 * check id_token parameter
	 */
	if (!oidc_util_spaced_string_contains(r->pool, response_type, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN)) {
		if (id_token == NULL) {
			oidc_error(r, "requested flow is \"%s\" but no \"%s\" parameter found in the code response",
				   response_type, OIDC_PROTO_ID_TOKEN);
			return FALSE;
		}
	} else {
		if (id_token != NULL) {
			oidc_warn(r,
				  "requested flow is \"%s\" but there is an \"%s\" parameter in the code response that "
				  "will be dropped",
				  response_type, OIDC_PROTO_ID_TOKEN);
		}
	}

	/*
	 * check access_token parameter
	 */
	if (!oidc_util_spaced_string_contains(r->pool, response_type, OIDC_PROTO_RESPONSE_TYPE_TOKEN)) {
		if (access_token == NULL) {
			oidc_error(r, "requested flow is \"%s\" but no \"%s\" parameter found in the code response",
				   response_type, OIDC_PROTO_ACCESS_TOKEN);
			return FALSE;
		}
		if (token_type == NULL) {
			oidc_error(r, "requested flow is \"%s\" but no \"%s\" parameter found in the code response",
				   response_type, OIDC_PROTO_TOKEN_TYPE);
			return FALSE;
		}
	} else {
		if (access_token != NULL) {
			oidc_warn(r,
				  "requested flow is \"%s\" but there is an \"%s\" parameter in the code response that "
				  "will be dropped",
				  response_type, OIDC_PROTO_ACCESS_TOKEN);
		}

		if (token_type != NULL) {
			oidc_warn(r,
				  "requested flow is \"%s\" but there is a \"%s\" parameter in the code response that "
				  "will be dropped",
				  response_type, OIDC_PROTO_TOKEN_TYPE);
		}
	}

	return TRUE;
}

/*
 * validate the response parameters provided by the OP against the requested response type
 */
static apr_byte_t oidc_proto_validate_response_type(request_rec *r, const char *requested_response_type,
						    const char *code, const char *id_token, const char *access_token) {

	if (oidc_util_spaced_string_contains(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_CODE)) {
		if (code == NULL) {
			oidc_error(
			    r,
			    "the requested response type was (%s) but the response does not contain a \"%s\" parameter",
			    requested_response_type, OIDC_PROTO_CODE);
			return FALSE;
		}
	} else if (code != NULL) {
		oidc_error(r, "the requested response type was (%s) but the response contains a \"%s\" parameter",
			   requested_response_type, OIDC_PROTO_CODE);
		return FALSE;
	}

	if (oidc_util_spaced_string_contains(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN)) {
		if (id_token == NULL) {
			oidc_error(r,
				   "the requested response type was (%s) but the response does not contain an \"%s\" "
				   "parameter",
				   requested_response_type, OIDC_PROTO_ID_TOKEN);
			return FALSE;
		}
	} else if (id_token != NULL) {
		oidc_error(r, "the requested response type was (%s) but the response contains an \"%s\" parameter",
			   requested_response_type, OIDC_PROTO_ID_TOKEN);
		return FALSE;
	}

	if (oidc_util_spaced_string_contains(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_TOKEN)) {
		if (access_token == NULL) {
			oidc_error(r,
				   "the requested response type was (%s) but the response does not contain an \"%s\" "
				   "parameter",
				   requested_response_type, OIDC_PROTO_ACCESS_TOKEN);
			return FALSE;
		}
	} else if (access_token != NULL) {
		oidc_error(r, "the requested response type was (%s) but the response contains an \"%s\" parameter",
			   requested_response_type, OIDC_PROTO_ACCESS_TOKEN);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate the response mode used by the OP against the requested response mode
 */
static apr_byte_t oidc_proto_validate_response_mode(request_rec *r, oidc_proto_state_t *proto_state,
						    const char *response_mode, const char *default_response_mode) {

	const char *requested_response_mode = oidc_proto_state_get_response_mode(proto_state);
	if (requested_response_mode == NULL)
		requested_response_mode = default_response_mode;

	if (_oidc_strcmp(requested_response_mode, response_mode) != 0) {
		oidc_error(r, "requested response mode (%s) does not match the response mode used by the OP (%s)",
			   requested_response_mode, response_mode);
		return FALSE;
	}

	return TRUE;
}

/*
 * validate the client_id/iss provided by the OP against the client_id/iss registered with the provider that the request
 * was sent to
 */
static apr_byte_t oidc_proto_validate_issuer_client_id(request_rec *r, const char *configured_issuer,
						       const char *response_issuer, int require_issuer,
						       const char *configured_client_id,
						       const char *response_client_id) {

	if (response_issuer != NULL) {
		if (_oidc_strcmp(configured_issuer, response_issuer) != 0) {
			oidc_error(
			    r,
			    "configured issuer (%s) does not match the issuer provided in the response by the OP (%s)",
			    configured_issuer, response_issuer);
			return FALSE;
		}
	} else if (require_issuer) {
		oidc_error(r, "no required \"iss\" parameter provided in the response by the OP");
		return FALSE;
	}

	if (response_client_id != NULL) {
		if (_oidc_strcmp(configured_client_id, response_client_id) != 0) {
			oidc_error(r,
				   "configured client_id (%s) does not match the client_id provided in the response by "
				   "the OP (%s)",
				   configured_client_id, response_client_id);
			return FALSE;
		}
	}

	oidc_debug(r, "iss and/or client_id matched OK: %s, %s, %s, %s", response_issuer, configured_issuer,
		   response_client_id, configured_client_id);

	return TRUE;
}

/*
 * helper function to validate both the response type and the response mode in a single function call
 */
static apr_byte_t oidc_proto_validate_response_type_mode_issuer(request_rec *r, const char *requested_response_type,
								apr_table_t *params, oidc_proto_state_t *proto_state,
								const char *response_mode,
								const char *default_response_mode, const char *issuer,
								int require_issuer, const char *c_client_id) {

	const char *code = apr_table_get(params, OIDC_PROTO_CODE);
	const char *id_token = apr_table_get(params, OIDC_PROTO_ID_TOKEN);
	const char *access_token = apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN);
	const char *iss = apr_table_get(params, OIDC_PROTO_ISS);
	const char *client_id = apr_table_get(params, OIDC_PROTO_CLIENT_ID);

	if (oidc_proto_validate_issuer_client_id(r, issuer, iss, require_issuer, c_client_id, client_id) == FALSE)
		return FALSE;

	if (oidc_proto_validate_response_type(r, requested_response_type, code, id_token, access_token) == FALSE)
		return FALSE;

	if (oidc_proto_validate_response_mode(r, proto_state, response_mode, default_response_mode) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * parse and id_token and check the c_hash if the code is provided
 */
static apr_byte_t oidc_proto_parse_idtoken_and_validate_code(request_rec *r, oidc_cfg_t *c,
							     oidc_proto_state_t *proto_state, oidc_provider_t *provider,
							     const char *response_type, apr_table_t *params,
							     oidc_jwt_t **jwt, apr_byte_t must_validate_code) {

	const char *code = apr_table_get(params, OIDC_PROTO_CODE);
	const char *id_token = apr_table_get(params, OIDC_PROTO_ID_TOKEN);

	apr_byte_t is_code_flow =
	    (oidc_util_spaced_string_contains(r->pool, response_type, OIDC_PROTO_RESPONSE_TYPE_CODE) == TRUE) &&
	    (oidc_util_spaced_string_contains(r->pool, response_type, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN) == FALSE);

	const char *nonce = oidc_proto_state_get_nonce(proto_state);
	if (oidc_proto_idtoken_parse(r, c, provider, id_token, nonce, jwt, is_code_flow) == FALSE)
		return FALSE;

	if ((must_validate_code == TRUE) &&
	    (oidc_proto_idtoken_validate_code(r, provider, *jwt, response_type, code) == FALSE)) {
		oidc_jwt_destroy(*jwt);
		*jwt = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * resolves the code received from the OP in to an id_token, access_token and refresh_token
 */
static apr_byte_t oidc_proto_resolve_code(request_rec *r, oidc_cfg_t *cfg, oidc_provider_t *provider, const char *code,
					  const char *code_verifier, char **id_token, char **access_token,
					  char **token_type, int *expires_in, char **refresh_token, const char *state) {

	oidc_debug(r, "enter");

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE);
	apr_table_setn(params, OIDC_PROTO_CODE, code);
	apr_table_set(params, OIDC_PROTO_REDIRECT_URI, oidc_util_redirect_uri(r, cfg));

	if (code_verifier)
		apr_table_setn(params, OIDC_PROTO_CODE_VERIFIER, code_verifier);

	/* add state to mitigate IDP mixup attacks, only useful in a multi-provider setup */
	if ((oidc_cfg_metadata_dir_get(cfg) != NULL) && (state))
		apr_table_setn(params, OIDC_PROTO_STATE, state);

	return oidc_proto_token_endpoint_request(r, cfg, provider, params, id_token, access_token, token_type,
						 expires_in, refresh_token);
}

/*
 * resolve the code against the token endpoint and validate the response that is returned by the OP
 */
static apr_byte_t oidc_proto_resolve_code_and_validate_response(request_rec *r, oidc_cfg_t *c,
								oidc_provider_t *provider, const char *response_type,
								apr_table_t *params, oidc_proto_state_t *proto_state) {

	char *id_token = NULL;
	char *access_token = NULL;
	char *token_type = NULL;
	int expires_in = -1;
	char *refresh_token = NULL;
	char *code_verifier = NULL;

	if (oidc_cfg_provider_pkce_get(provider) != &oidc_pkce_none)
		oidc_cfg_provider_pkce_get(provider)->verifier(r, oidc_proto_state_get_pkce_state(proto_state),
							       &code_verifier);

	const char *state = oidc_proto_state_get_state(proto_state);

	if (oidc_proto_resolve_code(r, c, provider, apr_table_get(params, OIDC_PROTO_CODE), code_verifier, &id_token,
				    &access_token, &token_type, &expires_in, &refresh_token, state) == FALSE) {
		oidc_error(r, "failed to resolve the code");
		OIDC_METRICS_COUNTER_INC(r, c, OM_PROVIDER_TOKEN_ERROR);
		return FALSE;
	}

	if (oidc_proto_validate_code_response(r, response_type, id_token, access_token, token_type) == FALSE) {
		oidc_error(r, "code response validation failed");
		return FALSE;
	}

	/* don't override parameters that may already have been (rightfully) set in the authorization response */
	if ((apr_table_get(params, OIDC_PROTO_ID_TOKEN) == NULL) && (id_token != NULL)) {
		apr_table_set(params, OIDC_PROTO_ID_TOKEN, id_token);
	}

	/* override access token if returned from the token endpoint in the backchannel */
	if (access_token != NULL) {
		apr_table_set(params, OIDC_PROTO_ACCESS_TOKEN, access_token);
		if (token_type != NULL)
			apr_table_set(params, OIDC_PROTO_TOKEN_TYPE, token_type);
		if (expires_in != -1)
			apr_table_setn(params, OIDC_PROTO_EXPIRES_IN, apr_psprintf(r->pool, "%d", expires_in));
	}

	/* refresh token should not have been set before */
	if (refresh_token != NULL) {
		apr_table_set(params, OIDC_PROTO_REFRESH_TOKEN, refresh_token);
	}

	return TRUE;
}

/*
 * handle the "code id_token" response type
 */
apr_byte_t oidc_proto_response_code_idtoken(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
					    oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
					    oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN;

	if (oidc_proto_validate_response_type_mode_issuer(
		r, response_type, params, proto_state, response_mode, OIDC_PROTO_RESPONSE_MODE_FRAGMENT,
		oidc_cfg_provider_issuer_get(provider), oidc_cfg_provider_response_require_iss_get(provider),
		oidc_cfg_provider_client_id_get(provider)) == FALSE)
		return FALSE;

	if (oidc_proto_parse_idtoken_and_validate_code(r, c, proto_state, provider, response_type, params, jwt, TRUE) ==
	    FALSE)
		return FALSE;

	/* clear parameters that should only be set from the token endpoint */
	apr_table_unset(params, OIDC_PROTO_ACCESS_TOKEN);
	apr_table_unset(params, OIDC_PROTO_TOKEN_TYPE);
	apr_table_unset(params, OIDC_PROTO_EXPIRES_IN);
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	if (oidc_proto_resolve_code_and_validate_response(r, c, provider, response_type, params, proto_state) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * handle the "code token" response type
 */
apr_byte_t oidc_proto_response_code_token(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
					  oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
					  oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN;

	if (oidc_proto_validate_response_type_mode_issuer(
		r, response_type, params, proto_state, response_mode, OIDC_PROTO_RESPONSE_MODE_FRAGMENT,
		oidc_cfg_provider_issuer_get(provider), oidc_cfg_provider_response_require_iss_get(provider),
		oidc_cfg_provider_client_id_get(provider)) == FALSE)
		return FALSE;

	/* clear parameters that should only be set from the token endpoint */
	apr_table_unset(params, OIDC_PROTO_ID_TOKEN);
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	if (oidc_proto_resolve_code_and_validate_response(r, c, provider, response_type, params, proto_state) == FALSE)
		return FALSE;

	if (oidc_proto_parse_idtoken_and_validate_code(r, c, proto_state, provider, response_type, params, jwt,
						       FALSE) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * handle the "code" response type
 */
apr_byte_t oidc_proto_response_code(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
				    oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
				    oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_CODE;

	if (oidc_proto_validate_response_type_mode_issuer(
		r, response_type, params, proto_state, response_mode, OIDC_PROTO_RESPONSE_MODE_QUERY,
		oidc_cfg_provider_issuer_get(provider), oidc_cfg_provider_response_require_iss_get(provider),
		oidc_cfg_provider_client_id_get(provider)) == FALSE)
		return FALSE;

	/* clear parameters that should only be set from the token endpoint */
	apr_table_unset(params, OIDC_PROTO_ACCESS_TOKEN);
	apr_table_unset(params, OIDC_PROTO_TOKEN_TYPE);
	apr_table_unset(params, OIDC_PROTO_EXPIRES_IN);
	apr_table_unset(params, OIDC_PROTO_ID_TOKEN);
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	if (oidc_proto_resolve_code_and_validate_response(r, c, provider, response_type, params, proto_state) == FALSE)
		return FALSE;

	/*
	 * in this flow it is actually optional to check the code token against the c_hash
	 */
	if (oidc_proto_parse_idtoken_and_validate_code(r, c, proto_state, provider, response_type, params, jwt, TRUE) ==
	    FALSE)
		return FALSE;

	/*
	 * in this flow it is actually optional to check the access token against the at_hash
	 */
	if ((apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN) != NULL) &&
	    (oidc_proto_idtoken_validate_access_token(r, provider, *jwt, response_type,
						      apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN)) == FALSE)) {
		oidc_jwt_destroy(*jwt);
		*jwt = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * helper function for implicit flows: shared code for "id_token token" and "id_token"
 */
static apr_byte_t oidc_proto_handle_implicit_flow(request_rec *r, oidc_cfg_t *c, const char *response_type,
						  oidc_proto_state_t *proto_state, oidc_provider_t *provider,
						  apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt) {

	if (oidc_proto_validate_response_type_mode_issuer(
		r, response_type, params, proto_state, response_mode, OIDC_PROTO_RESPONSE_MODE_FRAGMENT,
		oidc_cfg_provider_issuer_get(provider), oidc_cfg_provider_response_require_iss_get(provider),
		oidc_cfg_provider_client_id_get(provider)) == FALSE)
		return FALSE;

	if (oidc_proto_parse_idtoken_and_validate_code(r, c, proto_state, provider, response_type, params, jwt, TRUE) ==
	    FALSE)
		return FALSE;

	return TRUE;
}

/*
 * handle the "code id_token token" response type
 */
apr_byte_t oidc_proto_response_code_idtoken_token(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
						  oidc_provider_t *provider, apr_table_t *params,
						  const char *response_mode, oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;

	if (oidc_proto_handle_implicit_flow(r, c, response_type, proto_state, provider, params, response_mode, jwt) ==
	    FALSE)
		return FALSE;

	if (oidc_proto_idtoken_validate_access_token(r, provider, *jwt, response_type,
						     apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN)) == FALSE)
		return FALSE;

	/* clear parameters that should only be set from the token endpoint */
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	if (oidc_proto_resolve_code_and_validate_response(r, c, provider, response_type, params, proto_state) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * handle the "id_token token" response type
 */
apr_byte_t oidc_proto_response_idtoken_token(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
					     oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
					     oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN;

	if (oidc_proto_handle_implicit_flow(r, c, response_type, proto_state, provider, params, response_mode, jwt) ==
	    FALSE)
		return FALSE;

	if (oidc_proto_idtoken_validate_access_token(r, provider, *jwt, response_type,
						     apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN)) == FALSE)
		return FALSE;

	/* clear parameters that should not be part of this flow */
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	return TRUE;
}

/*
 * handle the "id_token" response type
 */
apr_byte_t oidc_proto_response_idtoken(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state,
				       oidc_provider_t *provider, apr_table_t *params, const char *response_mode,
				       oidc_jwt_t **jwt) {

	oidc_debug(r, "enter");

	static const char *response_type = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN;

	if (oidc_proto_handle_implicit_flow(r, c, response_type, proto_state, provider, params, response_mode, jwt) ==
	    FALSE)
		return FALSE;

	/* clear parameters that should not be part of this flow */
	apr_table_unset(params, OIDC_PROTO_TOKEN_TYPE);
	apr_table_unset(params, OIDC_PROTO_EXPIRES_IN);
	apr_table_unset(params, OIDC_PROTO_REFRESH_TOKEN);

	return TRUE;
}
