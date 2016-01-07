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
 * Copyright (C) 2013-2016 Ping Identity Corporation
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
 * mostly copied from mod_auth_cas
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>

#include "mod_auth_openidc.h"

#include <pcre.h>

static apr_byte_t oidc_authz_match_value(request_rec *r, const char *spec_c,
		json_t *val, const char *key) {

	int i = 0;

	/* see if it is a string and it (case-insensitively) matches the Require'd value */
	if (json_is_string(val)) {

		if (apr_strnatcmp(json_string_value(val), spec_c) == 0)
			return TRUE;

		/* see if it is a integer and it equals the Require'd value */
	} else if (json_is_integer(val)) {

		if (json_integer_value(val) == atoi(spec_c))
			return TRUE;

		/* see if it is a boolean and it (case-insensitively) matches the Require'd value */
	} else if (json_is_boolean(val)) {

		if (apr_strnatcmp(json_is_true(val) ? "true" : "false", spec_c) == 0)
			return TRUE;

		/* if it is an array, we'll walk it */
	} else if (json_is_array(val)) {

		/* compare the claim values */
		for (i = 0; i < json_array_size(val); i++) {

			json_t *elem = json_array_get(val, i);

			if (json_is_string(elem)) {
				/*
				 * approximately compare the claim value (ignoring
				 * whitespace). At this point, spec_c points to the
				 * NULL-terminated value pattern.
				 */
				if (apr_strnatcmp(json_string_value(elem), spec_c) == 0)
					return TRUE;

			} else if (json_is_boolean(elem)) {

				if (apr_strnatcmp(
				json_is_true(elem) ? "true" : "false", spec_c) == 0)
					return TRUE;

			} else if (json_is_integer(elem)) {

				if (json_integer_value(elem) == atoi(spec_c))
					return TRUE;

			} else {

				oidc_warn(r,
						"unhandled in-array JSON object type [%d] for key \"%s\"",
						elem->type, (const char * ) key);
			}

		}

	} else {
		oidc_warn(r, "unhandled JSON object type [%d] for key \"%s\"",
				val->type, (const char * ) key);
	}

	return FALSE;
}

static apr_byte_t oidc_authz_match_expression(request_rec *r,
		const char *spec_c, json_t *val) {
	const char *errorptr;
	int erroffset;
	pcre *preg;
	int i = 0;

	/* setup the regex; spec_c points to the NULL-terminated value pattern */
	preg = pcre_compile(spec_c, 0, &errorptr, &erroffset, NULL);

	if (preg == NULL) {
		oidc_error(r, "pattern [%s] is not a valid regular expression", spec_c);
		pcre_free(preg);
		return FALSE;
	}

	/* see if the claim is a literal string */
	if (json_is_string(val)) {

		/* PCRE-compare the string value against the expression */
		if (pcre_exec(preg, NULL, json_string_value(val),
				(int) strlen(json_string_value(val)), 0, 0, NULL, 0) == 0) {
			pcre_free(preg);
			return TRUE;
		}

		/* see if the claim value is an array */
	} else if (json_is_array(val)) {

		/* compare the claim values in the array against the expression */
		for (i = 0; i < json_array_size(val); i++) {

			json_t *elem = json_array_get(val, i);
			if (json_is_string(elem)) {

				/* PCRE-compare the string value against the expression */
				if (pcre_exec(preg, NULL, json_string_value(elem),
						(int) strlen(json_string_value(elem)), 0, 0,
						NULL, 0) == 0) {
					pcre_free(preg);
					return TRUE;
				}
			}
		}
	}

	pcre_free(preg);

	return FALSE;
}

/*
 * see if a the Require value matches with a set of provided claims
 */
static apr_byte_t oidc_authz_match_claim(request_rec *r,
		const char * const attr_spec, const json_t * const claims) {

	const char *key;
	json_t *val;

	/* if we don't have any claims, they can never match any Require claim primitive */
	if (claims == NULL)
		return FALSE;

	/* loop over all of the user claims */
	void *iter = json_object_iter((json_t*) claims);
	while (iter) {

		key = json_object_iter_key(iter);
		val = json_object_iter_value(iter);

		oidc_debug(r, "evaluating key \"%s\"", (const char * ) key);

		const char *attr_c = (const char *) key;
		const char *spec_c = attr_spec;

		/* walk both strings until we get to the end of either or we find a differing character */
		while ((*attr_c) && (*spec_c) && (*attr_c) == (*spec_c)) {
			attr_c++;
			spec_c++;
		}

		/* The match is a success if we walked the whole claim name and the attr_spec is at a colon. */
		if (!(*attr_c) && (*spec_c) == ':') {

			/* skip the colon */
			spec_c++;

			if (oidc_authz_match_value(r, spec_c, val, key) == TRUE)
				return TRUE;

			/* a tilde denotes a string PCRE match */
		} else if (!(*attr_c) && (*spec_c) == '~') {

			/* skip the tilde */
			spec_c++;

			if (oidc_authz_match_expression(r, spec_c, val) == TRUE)
				return TRUE;
		}

		iter = json_object_iter_next((json_t *) claims, iter);
	}

	return FALSE;
}

/*
 * Apache <2.4 authorization routine: match the claims from the authenticated user against the Require primitive
 */
int oidc_authz_worker(request_rec *r, const json_t * const claims,
		const require_line * const reqs, int nelts) {
	const int m = r->method_number;
	const char *token;
	const char *requirement;
	int i;
	int have_oauthattr = 0;
	int count_oauth_claims = 0;

	/* go through applicable Require directives */
	for (i = 0; i < nelts; ++i) {

		/* ignore this Require if it's in a <Limit> section that exclude this method */
		if (!(reqs[i].method_mask & (AP_METHOD_BIT << m))) {
			continue;
		}

		/* ignore if it's not a "Require claim ..." */
		requirement = reqs[i].requirement;

		token = ap_getword_white(r->pool, &requirement);

		if (apr_strnatcasecmp(token, OIDC_REQUIRE_NAME) != 0) {
			continue;
		}

		/* ok, we have a "Require claim" to satisfy */
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
		 * for a specification that matches one of the claims.
		 */
		while (*requirement) {
			token = ap_getword_conf(r->pool, &requirement);
			count_oauth_claims++;

			oidc_debug(r, "evaluating claim specification: %s", token);

			if (oidc_authz_match_claim(r, token, claims) == TRUE) {

				/* if *any* claim matches, then authorization has succeeded and all of the others are ignored */
				oidc_debug(r, "require claim '%s' matched", token);
				return OK;
			}
		}
	}

	/* if there weren't any "Require claim" directives, we're irrelevant */
	if (!have_oauthattr) {
		oidc_debug(r, "no claim statements found, not performing authz");
		return DECLINED;
	}
	/* if there was a "Require claim", but no actual claims, that's cause to warn the admin of an iffy configuration */
	if (count_oauth_claims == 0) {
		oidc_warn(r,
				"'require claim' missing specification(s) in configuration, declining");
		return DECLINED;
	}

	/* log the event, also in Apache speak */
	oidc_debug(r, "authorization denied for client session");
	ap_note_auth_failure(r);

	return HTTP_UNAUTHORIZED;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
/*
 * Apache >=2.4 authorization routine: match the claims from the authenticated user against the Require primitive
 */
authz_status oidc_authz_worker24(request_rec *r, const json_t * const claims, const char *require_args) {

	int count_oauth_claims = 0;
	const char *t, *w;

	/* needed for anonymous authentication */
	if (r->user == NULL) return AUTHZ_DENIED_NO_USER;

	/* if no claims, impossible to satisfy */
	if (!claims) return AUTHZ_DENIED;

	/* loop over the Required specifications */
	t = require_args;
	while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {

		count_oauth_claims++;

		oidc_debug(r, "evaluating claim specification: %s", w);

		/* see if we can match any of out input claims against this Require'd value */
		if (oidc_authz_match_claim(r, w, claims) == TRUE) {

			oidc_debug(r, "require claim '%s' matched", w);
			return AUTHZ_GRANTED;
		}
	}

	/* if there wasn't anything after the Require claims directive... */
	if (count_oauth_claims == 0) {
		oidc_warn(r,
				"'require claim' missing specification(s) in configuration, denying");
	}

	return AUTHZ_DENIED;
}
#endif
