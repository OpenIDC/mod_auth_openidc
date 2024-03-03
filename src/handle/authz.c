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

#include "handle/handle.h"
#include "metrics.h"
#include "pcre_subst.h"

static apr_byte_t oidc_authz_match_value(request_rec *r, const char *spec_c, const json_t *val, const char *key) {

	const json_t *elem = NULL;
	int i = 0;

	oidc_debug(r, "matching: spec_c=%s, key=%s", spec_c, key);

	/* see if it is a string and it (case-insensitively) matches the Require'd value */
	if (json_is_string(val)) {

		if (_oidc_strcmp(json_string_value(val), spec_c) == 0)
			return TRUE;

		/* see if it is a integer and it equals the Require'd value */
	} else if (json_is_integer(val)) {

		if (json_integer_value(val) == _oidc_str_to_int(spec_c, -1))
			return TRUE;

		/* see if it is a boolean and it (case-insensitively) matches the Require'd value */
	} else if (json_is_boolean(val)) {

		if (_oidc_strcmp((json_is_true(val) ? "true" : "false"), spec_c) == 0)
			return TRUE;

		/* if it is an array, we'll walk it */
	} else if (json_is_array(val)) {

		/* compare the claim values */
		for (i = 0; i < json_array_size(val); i++) {

			elem = json_array_get(val, i);

			if (json_is_string(elem)) {
				/*
				 * approximately compare the claim value (ignoring
				 * whitespace). At this point, spec_c points to the
				 * NULL-terminated value pattern.
				 */
				if (_oidc_strcmp(json_string_value(elem), spec_c) == 0)
					return TRUE;

			} else if (json_is_boolean(elem)) {

				if (_oidc_strcmp((json_is_true(elem) ? "true" : "false"), spec_c) == 0)
					return TRUE;

			} else if (json_is_integer(elem)) {

				if (json_integer_value(elem) == _oidc_str_to_int(spec_c, -1))
					return TRUE;

			} else {

				oidc_warn(r, "unhandled in-array JSON object type [%d] for key \"%s\"", elem->type,
					  (const char *)key);
			}
		}

	} else {
		oidc_warn(r, "unhandled JSON object type [%d] for key \"%s\"", val->type, (const char *)key);
	}

	return FALSE;
}

static apr_byte_t oidc_authz_match_expression(request_rec *r, const char *spec_c, const json_t *val) {
	apr_byte_t rc = FALSE;
	struct oidc_pcre *preg = NULL;
	char *error_str = NULL;
	int i = 0;

	/* setup the regex; spec_c points to the NULL-terminated value pattern */
	preg = oidc_pcre_compile(r->pool, spec_c, &error_str);

	if (preg == NULL) {
		oidc_error(r, "pattern [%s] is not a valid regular expression: %s", spec_c, error_str);
		goto end;
	}

	/* see if the claim is a literal string */
	if (json_is_string(val)) {

		error_str = NULL;
		/* PCRE-compare the string value against the expression */
		if (oidc_pcre_exec(r->pool, preg, json_string_value(val), (int)_oidc_strlen(json_string_value(val)),
				   &error_str) > 0) {
			oidc_debug(r, "value \"%s\" matched regex \"%s\"", json_string_value(val), spec_c);
			rc = TRUE;
			goto end;
		} else if (error_str) {
			oidc_debug(r, "pcre error (string): %s", error_str);
		}

		/* see if the claim value is an array */
	} else if (json_is_array(val)) {

		/* compare the claim values in the array against the expression */
		for (i = 0; i < json_array_size(val); i++) {

			json_t *elem = json_array_get(val, i);
			if (json_is_string(elem)) {

				error_str = NULL;
				/* PCRE-compare the string value against the expression */
				if (oidc_pcre_exec(r->pool, preg, json_string_value(elem),
						   (int)_oidc_strlen(json_string_value(elem)), &error_str) > 0) {
					oidc_debug(r, "array value \"%s\" matched regex \"%s\"",
						   json_string_value(elem), spec_c);
					rc = TRUE;
					goto end;
				} else if (error_str) {
					oidc_pcre_free_match(preg);
					oidc_debug(r, "pcre error (array): %s", error_str);
				}
			}
		}
	}

end:

	if (preg)
		oidc_pcre_free(preg);

	return rc;
}

/*
 * see if a the Require value matches with a set of provided claims
 */
apr_byte_t oidc_authz_match_claim(request_rec *r, const char *const attr_spec, json_t *claims) {

	const char *key;
	json_t *val;

	/* if we don't have any claims, they can never match any Require claim primitive */
	if (claims == NULL)
		return FALSE;

	/* loop over all of the user claims */
	void *iter = json_object_iter(claims);
	while (iter) {

		key = json_object_iter_key(iter);
		val = json_object_iter_value(iter);

		oidc_debug(r, "evaluating key \"%s\"", (const char *)key);

		const char *attr_c = key;
		const char *spec_c = attr_spec;

		/* walk both strings until we get to the end of either or we find a differing character */
		while ((*attr_c) && (*spec_c) && (*attr_c) == (*spec_c)) {
			attr_c++;
			spec_c++;
		}

		/* The match is a success if we walked the whole claim name and the attr_spec is at a colon. */
		if (!(*attr_c) && (*spec_c) == OIDC_CHAR_COLON) {

			/* skip the colon */
			spec_c++;

			if (oidc_authz_match_value(r, spec_c, val, key) == TRUE)
				return TRUE;

			/* a tilde denotes a string PCRE match */
		} else if (!(*attr_c) && (*spec_c) == OIDC_CHAR_TILDE) {

			/* skip the tilde */
			spec_c++;

			if (oidc_authz_match_expression(r, spec_c, val) == TRUE)
				return TRUE;

			/* dot means child nodes must be evaluated */
		} else if (!(*attr_c) && (*spec_c) == OIDC_CHAR_DOT) {

			/* skip the dot */
			spec_c++;

			if (json_is_object(val)) {
				oidc_debug(r, "attribute chunk matched, evaluating children of key: \"%s\".", key);
				return oidc_authz_match_claim(r, spec_c, json_object_get(claims, key));
			} else if (json_is_array(val)) {
				oidc_debug(r, "attribute chunk matched, evaluating array values of key: \"%s\".", key);
				return oidc_authz_match_value(r, spec_c, json_object_get(claims, key), key);
			} else {
				oidc_warn(r,
					  "\"%s\" matched, and child nodes or array values should be evaluated, but "
					  "value is not an object or array.",
					  key);
				return FALSE;
			}
		}

		iter = json_object_iter_next(claims, iter);
	}

	return FALSE;
}

#ifdef USE_LIBJQ

/*
 * see if a the Require value matches a configured expression
 */
static apr_byte_t oidc_authz_match_claims_expr(request_rec *r, const char *const attr_spec, json_t *claims) {
	apr_byte_t rv = FALSE;
	const char *str = NULL;

	oidc_debug(r, "enter: '%s'", attr_spec);

	str = oidc_util_jq_filter(r, oidc_util_encode_json_object(r, claims, JSON_PRESERVE_ORDER | JSON_COMPACT),
				  attr_spec);
	rv = (_oidc_strcmp(str, "true") == 0);

	return rv;
}

#endif

#define OIDC_AUTHZ_ERROR "OIDC_AUTHZ_ERROR"

static void oidc_authz_error_add(request_rec *r, const char *msg) {
	const char *envvar = NULL;
	if (r->subprocess_env != NULL) {
		envvar = apr_table_get(r->subprocess_env, OIDC_AUTHZ_ERROR);
		oidc_debug(r, "adding %s to environment variable %s=%s", msg, OIDC_AUTHZ_ERROR, envvar);
		apr_table_set(r->subprocess_env, OIDC_AUTHZ_ERROR,
			      apr_psprintf(r->pool, "%s%s%s", envvar ? envvar : "", envvar ? "," : "", msg ? msg : ""));
	}
}

/*
 * get the claims and id_token from request state
 */
static void oidc_authz_get_claims_and_idtoken(request_rec *r, json_t **claims, json_t **id_token) {

	const char *s_claims = oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_CLAIMS);
	if (s_claims != NULL)
		oidc_util_decode_json_object(r, s_claims, claims);

	const char *s_id_token = oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_IDTOKEN);
	if (s_id_token != NULL)
		oidc_util_decode_json_object(r, s_id_token, id_token);
}

#if HAVE_APACHE_24

/*
 * Apache >=2.4 authorization routine: match the claims from the authenticated user against the Require primitive
 */
authz_status oidc_authz_24_worker(request_rec *r, json_t *claims, const char *require_args,
				  const void *parsed_require_args, oidc_authz_match_claim_fn_type match_claim_fn) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	int count_oauth_claims = 0;
	const char *t, *w, *err = NULL;
	const ap_expr_info_t *expr = parsed_require_args;

	/* needed for anonymous authentication */
	if (r->user == NULL)
		return AUTHZ_DENIED_NO_USER;

	/* if no claims, impossible to satisfy */
	if (!claims)
		return AUTHZ_DENIED;

	if (expr) {
		t = ap_expr_str_exec(r, expr, &err);
		if (err) {
			oidc_error(r, "could not evaluate expression '%s': %s", require_args, err);
			return AUTHZ_DENIED;
		}
	} else {
		t = require_args;
	}

	/* loop over the Required specifications */
	while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {

		count_oauth_claims++;

		oidc_debug(r, "evaluating claim/expr specification: %s", w);

		/* see if we can match any of out input claims against this Require'd value */
		if (match_claim_fn(r, w, claims) == TRUE) {

			OIDC_METRICS_COUNTER_INC_SPEC(r, cfg, OM_AUTHZ_MATCH_REQUIRE_CLAIM, require_args);

			oidc_debug(r, "require claim/expr '%s' matched", w);
			return AUTHZ_GRANTED;
		}
	}

	/* if there wasn't anything after the Require claims directive... */
	if (count_oauth_claims == 0) {
		oidc_warn(r, "'require claim/expr' missing specification(s) in configuration, denying");
	}

	OIDC_METRICS_COUNTER_INC_SPEC(r, cfg, OM_AUTHZ_ERROR_REQUIRE_CLAIM, require_args);

	oidc_debug(r, "could not match require claim expression '%s'", require_args);
	oidc_authz_error_add(r, require_args);

	return AUTHZ_DENIED;
}

#define OIDC_OAUTH_BEARER_SCOPE_ERROR "OIDC_OAUTH_BEARER_SCOPE_ERROR"
#define OIDC_OAUTH_BEARER_SCOPE_ERROR_VALUE                                                                            \
	"Bearer error=\"insufficient_scope\", error_description=\"Different scope(s) or other claims required\""

/*
 * find out which action we need to take when encountering an unauthorized request
 */
static authz_status oidc_authz_24_unauthorized_user(request_rec *r) {

	char *html_head = NULL;

	oidc_debug(r, "enter");

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	if (_oidc_strnatcasecmp((const char *)ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ERROR_OAUTH20);
		oidc_debug(r, "setting environment variable %s to \"%s\" for usage in mod_headers",
			   OIDC_OAUTH_BEARER_SCOPE_ERROR, OIDC_OAUTH_BEARER_SCOPE_ERROR_VALUE);
		apr_table_set(r->subprocess_env, OIDC_OAUTH_BEARER_SCOPE_ERROR, OIDC_OAUTH_BEARER_SCOPE_ERROR_VALUE);
		return AUTHZ_DENIED;
	}

	/* see if we've configured OIDCUnAutzAction for this path */
	switch (oidc_dir_cfg_unautz_action(r)) {
	case OIDC_UNAUTZ_RETURN403:
	case OIDC_UNAUTZ_RETURN401:
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_401);
		oidc_util_html_send_error(r, c->error_template, "Authorization Error", oidc_dir_cfg_unauthz_arg(r),
					  HTTP_UNAUTHORIZED);
		if (c->error_template)
			r->header_only = 1;
		return AUTHZ_DENIED;
	case OIDC_UNAUTZ_RETURN302:
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_302);
		html_head = apr_psprintf(r->pool, "<meta http-equiv=\"refresh\" content=\"0; url=%s\">",
					 oidc_dir_cfg_unauthz_arg(r));
		oidc_util_html_send(r, "Authorization Error Redirect", html_head, NULL, NULL, HTTP_UNAUTHORIZED);
		r->header_only = 1;
		return AUTHZ_DENIED;
	case OIDC_UNAUTZ_AUTHENTICATE:
		/*
		 * exception handling: if this looks like an HTTP request that cannot
		 * complete an authentication round trip to the provider, we
		 * won't redirect the user and thus avoid creating a state cookie
		 */
		if (oidc_is_auth_capable_request(r) == FALSE) {
			OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_401);
			return AUTHZ_DENIED;
		}

		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_AUTH);

		break;
	}

	oidc_request_authenticate_user(r, c, NULL, oidc_get_current_url(r, c->x_forwarded_headers), NULL, NULL, NULL,
				       oidc_dir_cfg_path_auth_request_params(r), oidc_dir_cfg_path_scope(r));

	const char *location = oidc_http_hdr_out_location_get(r);

	if ((oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL) && (location == NULL))
		return AUTHZ_GRANTED;

	if (location != NULL) {
		oidc_debug(r, "send HTML refresh with authorization redirect: %s", location);
		html_head = apr_psprintf(r->pool, "<meta http-equiv=\"refresh\" content=\"0; url=%s\">", location);
		oidc_util_html_send(r, "Stepup Authentication", html_head, NULL, NULL, HTTP_UNAUTHORIZED);
		r->header_only = 1;
	}

	return AUTHZ_DENIED;
}

/*
 * generic Apache >=2.4 authorization hook for this module
 * handles both OpenID Connect or OAuth 2.0 in the same way, based on the claims stored in the session
 */
authz_status oidc_authz_24_checker(request_rec *r, const char *require_args, const void *parsed_require_args,
				   oidc_authz_match_claim_fn_type match_claim_fn) {

	oidc_debug(r, "enter: (r->user=%s) require_args=\"%s\"", r->user, require_args);

	/* check for anonymous access and PASS mode */
	if ((r->user != NULL) && (_oidc_strlen(r->user) == 0)) {
		if (oidc_dir_cfg_unauth_action(r) == OIDC_UNAUTH_PASS)
			return AUTHZ_GRANTED;
		if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL)
			return AUTHZ_GRANTED;
		if (r->method_number == M_OPTIONS)
			return AUTHZ_GRANTED;
	}

	/* get the set of claims from the request state (they've been set in the authentication part earlier */
	json_t *claims = NULL, *id_token = NULL;
	oidc_authz_get_claims_and_idtoken(r, &claims, &id_token);

	/* merge id_token claims (e.g. "iss") in to claims json object */
	if (claims)
		oidc_util_json_merge(r, id_token, claims);

	/* dispatch to the >=2.4 specific authz routine */
	authz_status rc =
	    oidc_authz_24_worker(r, claims ? claims : id_token, require_args, parsed_require_args, match_claim_fn);

	/* cleanup */
	if (claims)
		json_decref(claims);
	if (id_token)
		json_decref(id_token);

	if ((rc == AUTHZ_DENIED) && ap_auth_type(r))
		rc = oidc_authz_24_unauthorized_user(r);

	return rc;
}

authz_status oidc_authz_24_checker_claim(request_rec *r, const char *require_args, const void *parsed_require_args) {
	return oidc_authz_24_checker(r, require_args, parsed_require_args, oidc_authz_match_claim);
}

#ifdef USE_LIBJQ
authz_status oidc_authz_24_checker_claims_expr(request_rec *r, const char *require_args,
					       const void *parsed_require_args) {
	return oidc_authz_24_checker(r, require_args, parsed_require_args, oidc_authz_match_claims_expr);
}
#endif

#else

/*
 * Apache <2.4 authorization routine: match the claims from the authenticated user against the Require primitive
 */
static int oidc_authz_22_worker(request_rec *r, json_t *claims, const require_line *const reqs, int nelts) {
	const int m = r->method_number;
	const char *token;
	const char *requirement;
	int i;
	int have_oauthattr = 0;
	int count_oauth_claims = 0;
	oidc_authz_match_claim_fn_type match_claim_fn = NULL;

	/* go through applicable Require directives */
	for (i = 0; i < nelts; ++i) {

		/* ignore this Require if it's in a <Limit> section that exclude this method */
		if (!(reqs[i].method_mask & (AP_METHOD_BIT << m))) {
			continue;
		}

		/* ignore if it's not a "Require claim ..." */
		requirement = reqs[i].requirement;

		token = ap_getword_white(r->pool, &requirement);

		/* see if we've got anything meant for us */
		if (_oidc_strnatcasecmp(token, OIDC_REQUIRE_CLAIM_NAME) == 0) {
			match_claim_fn = oidc_authz_match_claim;
#ifdef USE_LIBJQ
		} else if (_oidc_strnatcasecmp(token, OIDC_REQUIRE_CLAIMS_EXPR_NAME) == 0) {
			match_claim_fn = oidc_authz_match_claims_expr;
#endif
		} else {
			continue;
		}

		/* ok, we have a "Require claim/claims_expr" to satisfy */
		have_oauthattr = 1;

		/*
		 * If we have an applicable claim, but no claims were sent in the request, then we can
		 * just stop looking here, because it's not satisfiable. The code after this loop will
		 * give the appropriate response.
		 */
		if (!claims) {
			break;
		}

		/*
		 * iterate over the claim specification strings in this require directive searching
		 * for a specification that matches one of the claims/expressions.
		 */
		while (*requirement) {
			token = ap_getword_conf(r->pool, &requirement);
			count_oauth_claims++;

			oidc_debug(r, "evaluating claim/expr specification: %s", token);

			if (match_claim_fn(r, token, claims) == TRUE) {

				/* if *any* claim matches, then authorization has succeeded and all of the others are
				 * ignored */
				oidc_debug(r, "require claim/expr '%s' matched", token);
				return OK;
			}
		}

		oidc_authz_error_add(r, requirement);
	}

	/* if there weren't any "Require claim" directives, we're irrelevant */
	if (!have_oauthattr) {
		oidc_debug(r, "no claim/expr statements found, not performing authz");
		return DECLINED;
	}
	/* if there was a "Require claim", but no actual claims, that's cause to warn the admin of an iffy configuration
	 */
	if (count_oauth_claims == 0) {
		oidc_warn(r, "'require claim/expr' missing specification(s) in configuration, declining");
		return DECLINED;
	}

	/* log the event, also in Apache speak */
	oidc_debug(r, "authorization denied for require claims (0/%d): '%s'", nelts,
		   nelts > 0 ? reqs[0].requirement : "(none)");

	ap_note_auth_failure(r);

	return HTTP_UNAUTHORIZED;
}

/*
 * find out which action we need to take when encountering an unauthorized request
 */
static int oidc_authz_22_unauthorized_user(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	if (_oidc_strnatcasecmp((const char *)ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ERROR_OAUTH20);
		oidc_oauth_return_www_authenticate(r, "insufficient_scope",
						   "Different scope(s) or other claims required");
		return HTTP_UNAUTHORIZED;
	}

	/* see if we've configured OIDCUnAutzAction for this path */
	switch (oidc_dir_cfg_unautz_action(r)) {
	case OIDC_UNAUTZ_RETURN403:
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_403);
		if (oidc_dir_cfg_unauthz_arg(r))
			oidc_util_html_send(r, "Authorization Error", NULL, NULL, oidc_dir_cfg_unauthz_arg(r),
					    HTTP_FORBIDDEN);
		return HTTP_FORBIDDEN;
	case OIDC_UNAUTZ_RETURN401:
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_401);
		if (oidc_dir_cfg_unauthz_arg(r))
			oidc_util_html_send(r, "Authorization Error", NULL, NULL, oidc_dir_cfg_unauthz_arg(r),
					    HTTP_UNAUTHORIZED);
		return HTTP_UNAUTHORIZED;
	case OIDC_UNAUTZ_RETURN302:
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_302);
		oidc_http_hdr_out_location_set(r, oidc_dir_cfg_unauthz_arg(r));
		return HTTP_MOVED_TEMPORARILY;
	case OIDC_UNAUTZ_AUTHENTICATE:
		/*
		 * exception handling: if this looks like a XMLHttpRequest call we
		 * won't redirect the user and thus avoid creating a state cookie
		 * for a non-browser (= Javascript) call that will never return from the OP
		 */
		if (oidc_is_auth_capable_request(r) == FALSE) {
			OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_401);
			return HTTP_UNAUTHORIZED;
		}

		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_AUTH);
	}

	return oidc_request_authenticate_user(r, c, NULL, oidc_get_current_url(r, c->x_forwarded_headers), NULL, NULL,
					      NULL, oidc_dir_cfg_path_auth_request_params(r),
					      oidc_dir_cfg_path_scope(r));
}

/*
 * generic Apache <2.4 authorization hook for this module
 * handles both OpenID Connect and OAuth 2.0 in the same way, based on the claims stored in the request context
 */
int oidc_authz_22_checker(request_rec *r) {

	/* check for anonymous access and PASS mode */
	if ((r->user != NULL) && (_oidc_strlen(r->user) == 0)) {
		r->user = NULL;
		if (oidc_dir_cfg_unauth_action(r) == OIDC_UNAUTH_PASS)
			return OK;
		if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL)
			return OK;
		if (r->method_number == M_OPTIONS)
			return OK;
	}

	/* get the set of claims from the request state (they've been set in the authentication part earlier */
	json_t *claims = NULL, *id_token = NULL;
	oidc_authz_get_claims_and_idtoken(r, &claims, &id_token);

	/* get the Require statements */
	const apr_array_header_t *const reqs_arr = ap_requires(r);

	/* see if we have any */
	const require_line *const reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;
	if (!reqs_arr) {
		oidc_debug(r, "no require statements found, so declining to perform authorization.");
		return DECLINED;
	}

	/* merge id_token claims (e.g. "iss") in to claims json object */
	if (claims)
		oidc_util_json_merge(r, id_token, claims);

	/* dispatch to the <2.4 specific authz routine */
	int rc = oidc_authz_22_worker(r, claims ? claims : id_token, reqs, reqs_arr->nelts);

	/* cleanup */
	if (claims)
		json_decref(claims);
	if (id_token)
		json_decref(id_token);

	if ((rc == HTTP_UNAUTHORIZED) && ap_auth_type(r))
		rc = oidc_authz_22_unauthorized_user(r);

	return rc;
}

#endif
