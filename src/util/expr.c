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

#include "util/pcre_subst.h"
#include "util/util.h"

/*
 * regexp substitute
 *   Example:
 *     regex: "^.*([0-9]+).*$"
 *     replace: "$1"
 *     text_original: "match 292 numbers"
 *     text_replaced: "292"
 */
apr_byte_t oidc_util_regexp_substitute(apr_pool_t *pool, const char *input, const char *regexp, const char *replace,
				       char **output, char **error_str) {

	char *substituted = NULL;
	apr_byte_t rc = FALSE;

	struct oidc_pcre *preg = oidc_pcre_compile(pool, regexp, error_str);
	if (preg == NULL) {
		*error_str =
		    apr_psprintf(pool, "pattern [%s] is not a valid regular expression: %s", regexp, *error_str);
		goto out;
	}

	if (_oidc_strlen(input) >= OIDC_PCRE_MAXCAPTURE - 1) {
		*error_str =
		    apr_psprintf(pool, "string length (%d) is larger than the maximum allowed for pcre_subst (%d)",
				 (int)_oidc_strlen(input), OIDC_PCRE_MAXCAPTURE - 1);
		goto out;
	}

	substituted = oidc_pcre_subst(pool, preg, input, (int)_oidc_strlen(input), replace);
	if (substituted == NULL) {
		*error_str = apr_psprintf(
		    pool, "unknown error could not match string [%s] using pattern [%s] and replace matches in [%s]",
		    input, regexp, replace);
		goto out;
	}

	*output = apr_pstrdup(pool, substituted);
	rc = TRUE;

out:

	if (preg)
		oidc_pcre_free(preg);

	return rc;
}

/*
 * regexp match
 */
apr_byte_t oidc_util_regexp_first_match(apr_pool_t *pool, const char *input, const char *regexp, char **output,
					char **error_str) {
	apr_byte_t rv = FALSE;
	int rc = 0;

	struct oidc_pcre *preg = oidc_pcre_compile(pool, regexp, error_str);
	if (preg == NULL) {
		*error_str =
		    apr_psprintf(pool, "pattern [%s] is not a valid regular expression: %s", regexp, *error_str);
		goto out;
	}

	if ((rc = oidc_pcre_exec(pool, preg, input, (int)_oidc_strlen(input), error_str)) < 0)
		goto out;

	if (output && (oidc_pcre_get_substring(pool, preg, input, rc, output, error_str) <= 0)) {
		*error_str = apr_psprintf(pool, "pcre_get_substring failed: %s", *error_str);
		goto out;
	}

	rv = TRUE;

out:

	if (preg)
		oidc_pcre_free(preg);

	return rv;
}

/*
 * parse an Apache expression
 */
char *oidc_util_apr_expr_parse(cmd_parms *cmd, const char *str, oidc_apr_expr_t **expr, apr_byte_t result_is_str) {
	char *rv = NULL;
	if ((str == NULL) || (expr == NULL))
		return NULL;
	*expr = apr_pcalloc(cmd->pool, sizeof(oidc_apr_expr_t));
	(*expr)->str = apr_pstrdup(cmd->pool, str);
	const char *expr_err = NULL;
	unsigned int flags = AP_EXPR_FLAG_DONT_VARY & AP_EXPR_FLAG_RESTRICTED;
	if (result_is_str)
		flags += AP_EXPR_FLAG_STRING_RESULT;
	(*expr)->expr = ap_expr_parse_cmd(cmd, str, flags, &expr_err, NULL);
	if (expr_err != NULL) {
		rv = apr_pstrcat(cmd->temp_pool, "cannot parse expression: ", expr_err, NULL);
		*expr = NULL;
	}
	return rv;
}

/*
 * execute an Apache expression
 */
const char *oidc_util_apr_expr_exec(request_rec *r, const oidc_apr_expr_t *expr, apr_byte_t result_is_str) {
	const char *expr_result = NULL;
	if (expr == NULL)
		return NULL;
	const char *expr_err = NULL;
	if (result_is_str) {
		expr_result = ap_expr_str_exec(r, expr->expr, &expr_err);
	} else {
		expr_result = ap_expr_exec(r, expr->expr, &expr_err) ? "" : NULL;
	}
	if (expr_err) {
		oidc_error(r, "executing expression \"%s\" failed: %s", expr->str, expr_err);
		expr_result = NULL;
	}
	return expr_result;
}
