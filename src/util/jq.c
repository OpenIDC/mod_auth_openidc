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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
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

#include "util/util.h"

#ifdef USE_LIBJQ

#include <jq.h>
/*
 * execute a JQ expression
 */
static const char *oidc_util_jq_exec(request_rec *r, jq_state *jq, struct jv_parser *parser) {
	const char *rv = NULL;
	jv value, elem, str, msg;

	while (jv_is_valid((value = jv_parser_next(parser)))) {
		jq_start(jq, value, 0);
		while (jv_is_valid(elem = jq_next(jq))) {
			str = jv_dump_string(elem, 0);
			rv = apr_pstrdup(r->pool, jv_string_value(str));
			oidc_debug(r, "jv_dump_string: %s", rv);
			jv_free(str);
		}
		jv_free(elem);
	}

	if (jv_invalid_has_msg(jv_copy(value))) {
		msg = jv_invalid_get_msg(value);
		oidc_error(r, "invalid: %s", jv_string_value(msg));
		jv_free(msg);
	} else {
		jv_free(value);
	}

	return rv;
}

#define OIDC_JQ_FILTER_EXPIRE_DEFAULT 600
#define OIDC_JQ_FILTER_CACHE_TTL_ENVVAR "OIDC_JQ_FILTER_CACHE_TTL"

/*
 * return the JQ expression result cache expiry
 */
static int oidc_jq_filter_cache_ttl(request_rec *r) {
	const char *s_ttl = apr_table_get(r->subprocess_env, OIDC_JQ_FILTER_CACHE_TTL_ENVVAR);
	return _oidc_str_to_int(s_ttl, OIDC_JQ_FILTER_EXPIRE_DEFAULT);
}

#endif

/*
 * apply a JQ expression/filter to the provided JSON input
 */
const char *oidc_util_jq_filter(request_rec *r, json_t *json, const char *filter) {
	const char *result = NULL;
#ifdef USE_LIBJQ
	const char *input = oidc_util_json_encode(r->pool, json, JSON_PRESERVE_ORDER | JSON_COMPACT);
	jq_state *jq = NULL;
	struct jv_parser *parser = NULL;
	int ttl = 0;
	char *key = NULL;
	char *value = NULL;

	if (filter == NULL) {
		oidc_debug(r, "filter is NULL, abort");
		result = input;
		goto end;
	}

	if (input == NULL) {
		oidc_debug(r, "input is NULL, set to empty object");
		input = "{}";
	}

	oidc_debug(r, "processing input: %s", input);
	oidc_debug(r, "processing filter: %s", filter);

	ttl = oidc_jq_filter_cache_ttl(r);
	if (ttl > 0) {
		if (oidc_util_hash_string_and_base64url_encode(
			r, OIDC_JOSE_ALG_SHA256, apr_pstrcat(r->pool, input, filter, NULL), &key) == FALSE) {
			oidc_error(r, "oidc_util_hash_string_and_base64url_encode returned an error");
			goto end;
		}
		oidc_cache_get_jq_filter(r, key, &value);
		if (value != NULL) {
			oidc_debug(r, "return cached result: %s", value);
			result = value;
			goto end;
		}
	}

	jq = jq_init();
	if (jq == NULL) {
		oidc_error(r, "jq_init returned NULL");
		result = input;
		goto end;
	}

	if (jq_compile(jq, filter) == 0) {
		oidc_error(r, "jq_compile returned an error");
		result = input;
		goto end;
	}

	parser = jv_parser_new(0);
	if (parser == NULL) {
		oidc_error(r, "jv_parser_new returned NULL");
		result = input;
		goto end;
	}

	jv_parser_set_buf(parser, input, _oidc_strlen(input), 0);

	result = oidc_util_jq_exec(r, jq, parser);

	if ((result != NULL) && (ttl != 0)) {
		oidc_debug(r, "caching result: %s", result);
		oidc_cache_set_jq_filter(r, key, result, apr_time_now() + apr_time_from_sec(ttl));
	}

end:

	if (parser)
		jv_parser_free(parser);
	if (jq)
		jq_teardown(&jq);
#else
	result = oidc_util_json_encode(r->pool, json, JSON_PRESERVE_ORDER | JSON_COMPACT);
#endif

	return result;
}
