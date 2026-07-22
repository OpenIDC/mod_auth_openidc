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
 * Copyright (C) 2017-2026 ZmartZone Holding BV
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

#include "cfg/dir.h"
#include "handle/handle.h"
#include "http_protocol.h"
#include "metrics.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/cache_local.h"
#include "util/pcre_subst.h"
#include "util/util.h"

/*
 * process-lifetime cache of compiled Require-claim regular expressions: the patterns come from
 * config-time constant (or expression-expanded) Require lines, so their number is small and
 * stable; compiling once per process instead of once per evaluation removes the dominant cost
 * of every regex authorization match. Consumers borrow the compiled program by reference (via
 * oidc_pcre_alias), so a live entry is never evicted: the cache simply stops caching once full.
 */
static oidc_cache_local_t *_oidc_authz_pcre_cache = NULL;

/* bounds the cache in case expression-expanded Require lines generate ever-changing patterns */
#define OIDC_AUTHZ_PCRE_CACHE_MAX_ENTRIES 64

/* oidc_cache_local free/compute adapters over the typed oidc_pcre API */
static void oidc_authz_pcre_free_value(void *value) {
	oidc_pcre_free((struct oidc_pcre *)value);
}

static void *oidc_authz_pcre_compile(apr_pool_t *pool, const char *key, void *baton) {
	char *s_err = NULL;
	return oidc_pcre_compile(pool, key, &s_err);
}

void oidc_authz_pcre_cache_init(apr_pool_t *pool) {
	oidc_cache_local_create(&_oidc_authz_pcre_cache, pool, "authz-pcre", OIDC_AUTHZ_PCRE_CACHE_MAX_ENTRIES, FALSE,
				oidc_authz_pcre_free_value);
}

/*
 * obtain a request-local alias to the cached compiled program for the specified pattern,
 * compiling and caching it on first use; returns NULL when the cache is not initialized, the
 * cache is full or the pattern does not compile - the caller then compiles per-request as before
 */
static struct oidc_pcre *oidc_authz_pcre_cache_get(request_rec *r, const char *spec) {
	struct oidc_pcre *cached =
	    oidc_cache_local_get_or_compute(_oidc_authz_pcre_cache, spec, oidc_authz_pcre_compile, NULL);
	return (cached != NULL) ? oidc_pcre_alias(r->pool, cached) : NULL;
}

static apr_byte_t oidc_authz_match_json_string(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	return (_oidc_strcmp(oidc_json_string_value(val), spec) == 0);
}

static apr_byte_t oidc_authz_match_json_integer(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	oidc_json_int_t i = 0;
	if ((spec == NULL) || (val == NULL))
		return FALSE;
	if (sscanf(spec, "%" OIDC_JSON_INT_FORMAT, &i) != 1) {
		oidc_warn(r, "integer parsing error for spec input: %s", spec);
		return FALSE;
	}
	return (oidc_json_integer_value(val) == i);
}

static apr_byte_t oidc_authz_match_json_real(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	double d = 0;
	if ((spec == NULL) || (val == NULL))
		return FALSE;
	if (sscanf(spec, "%lf", &d) != 1) {
		oidc_warn(r, "double parsing error for spec input: %s", spec);
		return FALSE;
	}
	return (oidc_json_real_value(val) == d);
}

static apr_byte_t oidc_authz_match_json_true(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	if ((spec == NULL) || (val == NULL))
		return FALSE;
	return (_oidc_strcmp(spec, "true") == 0);
}

static apr_byte_t oidc_authz_match_json_false(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	if ((spec == NULL) || (val == NULL))
		return FALSE;
	return (_oidc_strcmp(spec, "false") == 0);
}

static apr_byte_t oidc_authz_match_json_null(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	if ((spec == NULL) || (val == NULL))
		return FALSE;
	return (_oidc_strcmp(spec, "null") == 0);
}

typedef apr_byte_t(oidc_match_json_function_t)(request_rec *r, const char *spec, oidc_json_t *val, const char *key);

typedef struct oidc_authz_json_handler_t {
	int type;
	oidc_match_json_function_t *handler;
} oidc_authz_json_handler_t;

static apr_byte_t oidc_authz_match_json_array(request_rec *r, const char *spec, oidc_json_t *val, const char *key);

// clang-format off
static oidc_authz_json_handler_t _oidc_authz_json_handlers[] = {
	{ OIDC_JSON_TYPE_ARRAY, oidc_authz_match_json_array },
	{ OIDC_JSON_TYPE_STRING, oidc_authz_match_json_string },
	{ OIDC_JSON_TYPE_INTEGER, oidc_authz_match_json_integer },
	{ OIDC_JSON_TYPE_REAL, oidc_authz_match_json_real },
	{ OIDC_JSON_TYPE_TRUE, oidc_authz_match_json_true },
	{ OIDC_JSON_TYPE_FALSE, oidc_authz_match_json_false },
	{ OIDC_JSON_TYPE_NULL, oidc_authz_match_json_null },
	{ 0, NULL}
};
// clang-format on

static apr_byte_t oidc_authz_match_json_array_elem(request_rec *r, const char *spec, oidc_json_t *e, const char *key) {
	// avoid recursing into a nested array; matching needs to be done with the "." syntax
	if (oidc_json_typeof(e) != OIDC_JSON_TYPE_ARRAY)
		// loop over the JSON object type handlers
		for (const oidc_authz_json_handler_t *h = _oidc_authz_json_handlers; h->handler; h++)
			if (h->type == oidc_json_typeof(e))
				// found the handler for this type: its result decides the match
				return h->handler(r, spec, e, key);

	oidc_warn(r, "unhandled in-array JSON object type [%d] for key \"%s\"", oidc_json_typeof(e), key);
	return FALSE;
}

static apr_byte_t oidc_authz_match_json_array(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	oidc_json_t *e = NULL;

	if ((spec == NULL) || (val == NULL) || (key == NULL))
		return FALSE;

	// loop over the elements in the array, trying to find a match
	for (int i = 0; i < oidc_json_array_size(val); i++) {
		e = oidc_json_array_get(val, i);
		if (oidc_authz_match_json_array_elem(r, spec, e, key) == TRUE)
			return TRUE;
	}
	return FALSE;
}

static apr_byte_t oidc_authz_match_value(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	if ((spec == NULL) || (val == NULL) || (key == NULL))
		return FALSE;

	oidc_debug(r, "matching: spec=%s, key=%s", spec, key);

	for (const oidc_authz_json_handler_t *h = _oidc_authz_json_handlers; h->handler; h++) {
		if (h->type == oidc_json_typeof(val))
			return h->handler(r, spec, val, key);
	}

	oidc_warn(r, "unhandled JSON object type [%d] for key \"%s\"", oidc_json_typeof(val), (const char *)key);

	return FALSE;
}

typedef apr_byte_t(oidc_match_pcre_function_t)(request_rec *r, const char *, const oidc_json_t *, const char *,
					       struct oidc_pcre *);

typedef struct oidc_authz_pcre_handler_t {
	int type;
	oidc_match_pcre_function_t *handler;
} oidc_authz_pcre_handler_t;

static apr_byte_t oidc_authz_match_pcre_string(request_rec *r, const char *spec, const oidc_json_t *val,
					       const char *key, struct oidc_pcre *preg) {
	char *s_err = NULL;
	const char *s = oidc_json_string_value(val);

	if ((spec == NULL) || (val == NULL) || (key == NULL) || (preg == NULL))
		return FALSE;

	if (oidc_pcre_exec(r->pool, preg, s, (int)_oidc_strlen(s), &s_err) <= 0) {
		if (s_err)
			oidc_debug(r, "oidc_pcre_exec error: %s", s_err);
		return FALSE;
	}

	oidc_debug(r, "value \"%s\" matched regex \"%s\" for key \"%s\"", s, spec, key);

	return TRUE;
}

static apr_byte_t oidc_authz_match_pcre_array(request_rec *r, const char *spec, const oidc_json_t *val, const char *key,
					      struct oidc_pcre *);

// clang-format off
static oidc_authz_pcre_handler_t _oidc_authz_pcre_handlers[] = {
	{ OIDC_JSON_TYPE_ARRAY, oidc_authz_match_pcre_array },
	{ OIDC_JSON_TYPE_STRING, oidc_authz_match_pcre_string },
	{ 0, NULL }
};
// clang-format on

static apr_byte_t oidc_authz_match_pcre_array(request_rec *r, const char *spec, const oidc_json_t *val, const char *key,
					      struct oidc_pcre *preg) {

	const oidc_json_t *e = NULL;

	if ((spec == NULL) || (val == NULL) || (key == NULL) || (preg == NULL))
		return FALSE;

	// loop over the elements in the array, trying to find a match
	for (int i = 0; i < oidc_json_array_size(val); i++) {
		e = oidc_json_array_get(val, i);

		if (oidc_json_typeof(e) == OIDC_JSON_TYPE_STRING) {

			if (oidc_authz_match_pcre_string(r, spec, e, key, preg) == TRUE)
				return TRUE;

			// need to free any failed match to avoid a memory leak in subsequent calls to oidc_pcre_exec
			oidc_pcre_free_match(preg);

			continue;
		}

		oidc_warn(r, "unhandled non-string in-array JSON object type [%d] for key \"%s\"", oidc_json_typeof(e),
			  key);
	}

	return FALSE;
}

static apr_byte_t oidc_authz_match_pcre(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	apr_byte_t rc = FALSE;
	struct oidc_pcre *preg = NULL;
	char *s_err = NULL;
	const oidc_authz_pcre_handler_t *h = NULL;

	if ((spec == NULL) || (val == NULL) || (key == NULL))
		return FALSE;

	preg = oidc_authz_pcre_cache_get(r, spec);
	if (preg == NULL)
		preg = oidc_pcre_compile(r->pool, spec, &s_err);
	if (preg == NULL) {
		oidc_error(r, "pattern [%s] is not a valid regular expression: %s", spec, s_err ? s_err : "<n/a>");
		return FALSE;
	}

	// loop over the JSON object PCRE handlers
	for (h = _oidc_authz_pcre_handlers; h->handler; h++) {
		if (h->type != oidc_json_typeof(val))
			continue;
		// we found a handler, and possibly a match
		rc = h->handler(r, spec, val, key, preg);
		break;
	}

	// see if we have found an object handler
	if (h->handler == NULL)
		oidc_warn(r, "unhandled JSON object type [%d] for key \"%s\"", oidc_json_typeof(val), key);

	oidc_pcre_free(preg);

	return rc;
}

static apr_byte_t oidc_authz_separator_dot(request_rec *r, const char *spec, oidc_json_t *val, const char *key) {
	if ((spec == NULL) || (val == NULL) || (key == NULL))
		return FALSE;
	if (oidc_json_is_object(val)) {
		oidc_debug(r, "attribute chunk matched, evaluating children of key: \"%s\".", key);
		return oidc_authz_match_claim(r, spec, val);
	}
	oidc_warn(r,
		  "JSON key \"%s\" matched a \".\" and child nodes should be evaluated, but the corresponding JSON "
		  "value is not an object",
		  key);
	return FALSE;
}

// clang-format off
static oidc_authz_json_handler_t _oidc_authz_separator_handlers[] = {
		// there's some overloading going on here, applying a char as an int index
	{ OIDC_CHAR_COLON, oidc_authz_match_value },
	{ OIDC_CHAR_TILDE, oidc_authz_match_pcre },
	{ OIDC_CHAR_DOT, oidc_authz_separator_dot },
	{ 0, NULL }
};
// clang-format on

static apr_byte_t oidc_auth_handle_separator(request_rec *r, const char *key, oidc_json_t *val, const char *spec) {
	if ((spec == NULL) || (val == NULL) || (key == NULL))
		return FALSE;
	for (const oidc_authz_json_handler_t *h = _oidc_authz_separator_handlers; h->handler; h++) {
		// there's some overloading going on here, applying a char as an int index;
		// NB: spec advances past each matched separator, so after a non-matching handler the
		// remaining handlers are compared against the following character (preserved behavior)
		if (h->type != (*spec))
			continue;
		// skip the separator
		spec++;
		if (h->handler(r, spec, val, key) == TRUE)
			return TRUE;
	}
	return FALSE;
}

/*
 * see if a the Require value matches with a set of provided claims
 */
apr_byte_t oidc_authz_match_claim(request_rec *r, const char *const attr_spec, oidc_json_t *claims) {

	const char *key = NULL;
	const char *attr_c = NULL;
	const char *spec_c = NULL;
	oidc_json_t *val = NULL;

	// if we don't have any claims, they can never match any Require claim primitive
	if (claims == NULL)
		return FALSE;

	// loop over all of the user claims to find one that matches the attr_spec
	void *iter = oidc_json_object_iter(claims);
	while (iter) {

		key = oidc_json_object_iter_key(iter);
		val = oidc_json_object_iter_value(iter);

		oidc_debug(r, "evaluating key \"%s\"", (const char *)key);

		// initialize pointers for traversing the attribute name and the Require spec
		attr_c = key;
		spec_c = attr_spec;

		// walk both strings until we get to the end of either or we find a differing character
		while ((*attr_c) && (*spec_c) && (*attr_c) == (*spec_c)) {
			attr_c++;
			spec_c++;
		}

		if ((!(*attr_c)) && (oidc_auth_handle_separator(r, key, val, spec_c) == TRUE))
			return TRUE;

		iter = oidc_json_object_iter_next(claims, iter);
	}

	return FALSE;
}

#ifdef USE_LIBJQ

/*
 * see if a the Require value matches a configured expression
 */
static apr_byte_t oidc_authz_match_claims_expr(request_rec *r, const char *const attr_spec, oidc_json_t *claims) {
	apr_byte_t rv = FALSE;
	const char *str = NULL;

	oidc_debug(r, "enter: '%s'", attr_spec);

	str = oidc_util_jq_filter(r, claims, attr_spec);
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
static void oidc_authz_get_claims_idtoken_scope(request_rec *r, oidc_json_t **claims, oidc_json_t **id_token,
						const char **scope) {
	*claims = oidc_request_state_json_get(r, OIDC_REQUEST_STATE_KEY_CLAIMS);
	*id_token = oidc_request_state_json_get(r, OIDC_REQUEST_STATE_KEY_IDTOKEN);
	*scope = oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_SCOPE);
}

/*
 * merge the claims from the userinfo endpoint, the claims from the id_token, and the scope returned
 * from the userinfo endpoint into a single set of claims that can be used to authorize on
 */
static oidc_json_t *oidc_authz_merge_claims(request_rec *r) {
	oidc_json_t *result = oidc_json_object();
	oidc_json_t *claims = NULL;
	oidc_json_t *id_token = NULL;
	const char *scope = NULL;

	/* get the set of claims from the request state as they have been set in the authentication part earlier */
	oidc_authz_get_claims_idtoken_scope(r, &claims, &id_token, &scope);

	/* if scope was returned from the token endpoint, include it in the set of authorization claims */
	if (scope)
		oidc_json_object_set_new(result, OIDC_CLAIM_SCOPE, oidc_json_string(scope));

	/* merge userinfo claims into the authorization claims (take precedence over scope) */
	if (claims)
		oidc_json_merge(r, claims, result);

	/* merge id_token claims (e.g. "iss") into the authorization claims (take precedence over userinfo claims and
	 * scope) */
	if (id_token)
		oidc_json_merge(r, id_token, result);

	return result;
}

/*
 * check if this request should be passed to the content handler without applying authorization
 */
static apr_byte_t oidc_authz_skip_to_content_handler(request_rec *r) {
	if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL)
		return TRUE;
	if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_AUTHN_POST) != NULL)
		return TRUE;
	if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_AUTHN_PRESERVE) != NULL)
		return TRUE;
	if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_HTTP) != NULL)
		return TRUE;
	if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_HTML) != NULL)
		return TRUE;
	return FALSE;
}

/*
 * Apache >=2.4 authorization routine: match the claims from the authenticated user against the Require primitive
 */
authz_status oidc_authz_24_worker(request_rec *r, oidc_json_t *claims, const char *require_args,
				  const void *parsed_require_args, oidc_authz_match_claim_fn_type match_claim_fn) {

	const oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	int count_oauth_claims = 0;
	const char *t;
	const char *w;
	const char *err = NULL;
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

			OIDC_METRICS_COUNTER_INC_VALUE(r, cfg, OM_AUTHZ_MATCH_REQUIRE_CLAIM, require_args);

			oidc_debug(r, "require claim/expr '%s' matched", w);
			return AUTHZ_GRANTED;
		}
	}

	/* if there wasn't anything after the Require claims directive... */
	if (count_oauth_claims == 0) {
		oidc_warn(r, "'require claim/expr' missing specification(s) in configuration, denying");
	}

	OIDC_METRICS_COUNTER_INC_VALUE(r, cfg, OM_AUTHZ_ERROR_REQUIRE_CLAIM, require_args);

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

	const char *html_head = NULL;

	oidc_debug(r, "enter");

	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	if (_oidc_strnatcasecmp(ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ERROR_OAUTH20);
		oidc_debug(r, "setting environment variable %s to \"%s\" for usage in mod_headers",
			   OIDC_OAUTH_BEARER_SCOPE_ERROR, OIDC_OAUTH_BEARER_SCOPE_ERROR_VALUE);
		apr_table_set(r->subprocess_env, OIDC_OAUTH_BEARER_SCOPE_ERROR, OIDC_OAUTH_BEARER_SCOPE_ERROR_VALUE);
		return AUTHZ_DENIED;
	}

	/* see if we've configured OIDCUnAutzAction for this path */
	switch (oidc_cfg_dir_unautz_action_get(r)) {
	case OIDC_UNAUTZ_RETURN403:
	case OIDC_UNAUTZ_RETURN401:
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_401);
		oidc_util_html_send_error(r, "Authorization Error", oidc_cfg_dir_unauthz_arg_get(r), HTTP_UNAUTHORIZED);
		return AUTHZ_DENIED;
	case OIDC_UNAUTZ_RETURN302:
		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_302);
		html_head = apr_psprintf(r->pool, "<meta http-equiv=\"refresh\" content=\"0; url=%s\">",
					 oidc_util_html_escape(r->pool, oidc_cfg_dir_unauthz_arg_get(r)));
		oidc_util_html_send(r, "Authorization Error Redirect", html_head, NULL, NULL, HTTP_UNAUTHORIZED);
		r->header_only = 1;
		return AUTHZ_DENIED;
	case OIDC_UNAUTZ_AUTHENTICATE:
		/*
		 * exception handling: if this looks like an HTTP request that cannot
		 * complete an authentication round trip to the provider, we
		 * won't redirect the user and thus avoid creating a state cookie
		 *
		 * NB: when the expression argument to OIDCUnAuthAction is configured,
		 * it is re-used here to detect XHR requests.
		 */
		if (oidc_cfg_dir_unauth_expr_is_set(r) == TRUE) {
			if (oidc_cfg_dir_unauth_action_get(r) != OIDC_UNAUTH_AUTHENTICATE) {
				OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_401);
				return AUTHZ_DENIED;
			}
		} else if (oidc_is_auth_capable_request(r) == FALSE) {
			OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_401);
			return AUTHZ_DENIED;
		}

		OIDC_METRICS_COUNTER_INC(r, c, OM_AUTHZ_ACTION_AUTH);

		break;
	}

	oidc_request_authenticate_user(r, c, NULL, oidc_util_url_cur(r, oidc_cfg_x_forwarded_headers_get(c)), NULL,
				       NULL, NULL, oidc_cfg_dir_path_auth_request_params_get(r),
				       oidc_cfg_dir_path_scope_get(r));

	const char *location = oidc_http_hdr_out_location_get(r);

	if ((oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL) && (location == NULL))
		return AUTHZ_GRANTED;

	if (location != NULL) {
		oidc_debug(r, "send HTML refresh with authorization redirect: %s", location);
		oidc_http_hdr_out_location_set(r, NULL);
		html_head = apr_psprintf(r->pool, "<meta http-equiv=\"refresh\" content=\"0; url=%s\">",
					 oidc_util_html_escape(r->pool, location));
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
		if (oidc_cfg_dir_unauth_action_get(r) == OIDC_UNAUTH_PASS)
			return AUTHZ_GRANTED;
		if (oidc_authz_skip_to_content_handler(r) == TRUE)
			return AUTHZ_GRANTED;
		if (r->method_number == M_OPTIONS)
			return AUTHZ_GRANTED;
	}

	/* build the merged set of claims (as set in the authentication part earlier) fresh for each
	 * evaluation: it is NOT safe to memoize it across a request, because Apache evaluates the
	 * authorization provider in phases/subrequests where the underlying claim state in the
	 * request context is not necessarily the same, so a cached merge can go stale */
	oidc_json_t *claims = oidc_authz_merge_claims(r);

	/* dispatch to the >=2.4 specific authz routine */
	authz_status rc = oidc_authz_24_worker(r, claims, require_args, parsed_require_args, match_claim_fn);

	/* cleanup */
	if (claims)
		oidc_json_decref(claims);

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
