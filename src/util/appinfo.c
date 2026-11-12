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

#include "util/util.h"
#include "util/util_cfg.h"

/*
 * convert a claim value from UTF-8 to the Latin1 character set
 */
static char *_oidc_util_appinfo_utf8_to_latin1(request_rec *r, const char *src) {
	char *dst = NULL;
	unsigned int cp = 0;
	unsigned char ch;
	int i = 0;
	if (src == NULL)
		return NULL;
	dst = apr_pcalloc(r->pool, _oidc_strlen(src) + 1);
	while (*src != '\0') {
		ch = (unsigned char)(*src);
		if (ch <= 0x7f)
			cp = ch;
		else if (ch <= 0xbf)
			cp = (cp << 6) | (ch & 0x3f);
		else if (ch <= 0xdf)
			cp = ch & 0x1f;
		else if (ch <= 0xef)
			cp = ch & 0x0f;
		else
			cp = ch & 0x07;
		++src;
		if (((*src & 0xc0) != 0x80) && (cp <= 0x10ffff)) {
			if (cp <= 255) {
				dst[i] = (unsigned char)cp;
			} else {
				// no encoding possible
				dst[i] = '?';
			}
			i++;
		}
	}
	dst[i] = '\0';
	return dst;
}

/*
 * render the application header/envvar name and (possibly encoded) value for a single claim
 */
static void oidc_util_appinfo_render(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix,
				     oidc_appinfo_encoding_t encoding, const char **r_name, const char **r_value) {

	/* construct the header name, cq. put the prefix in front of a normalized key name */
	*r_name = apr_psprintf(r->pool, "%s%s", claim_prefix, oidc_http_hdr_normalize_name(r, s_key));
	char *d_value = NULL;

	if (s_value != NULL) {
		if (encoding == OIDC_APPINFO_ENCODING_BASE64URL) {
			oidc_util_base64url_encode(r, &d_value, s_value, (int)_oidc_strlen(s_value),
						   OIDC_BASE64URL_PADDING_STRIP);
		} else if (encoding == OIDC_APPINFO_ENCODING_LATIN1) {
			d_value = _oidc_util_appinfo_utf8_to_latin1(r, s_value);
		}
	}

	*r_value = (d_value != NULL) ? d_value : s_value;
}

/*
 * how the claims of one oidc_util_appinfo_set_all() call (or one oidc_util_appinfo_set() call) are
 * passed to the application: the rendered pairs are collected in the scratch tables and merged into
 * the request's header and environment tables in one apr_table_overlap() each; an apr_table_set()
 * per claim scans the whole table for the name, which made the work quadratic in the number of claims
 * of a provider- or client-supplied token, whereas the overlap sorts once and keeps the last value of a
 * name that occurs more than once, which is what the per-claim set did; without scratch tables (a
 * single oidc_util_appinfo_set()) the pair is set on the request directly
 */
typedef struct oidc_appinfo_ctx_t {
	const char *claim_prefix;
	const char *claim_delimiter;
	oidc_appinfo_pass_in_t pass_in;
	oidc_appinfo_encoding_t encoding;
	apr_table_t *headers;
	apr_table_t *env;
} oidc_appinfo_ctx_t;

/*
 * pass one rendered name/value pair to the application as HTTP header and/or environment variable
 */
static void oidc_util_appinfo_pair_apply(request_rec *r, const char *s_name, const char *s_value,
					 const oidc_appinfo_ctx_t *ctx) {
	const apr_byte_t batched = (((ctx->headers != NULL) || (ctx->env != NULL)) && (s_value != NULL)) ? TRUE : FALSE;

	if (ctx->pass_in & OIDC_APPINFO_PASS_HEADERS) {
		if (batched == TRUE)
			oidc_http_hdr_table_add(r, ctx->headers, s_name, s_value);
		else
			oidc_http_hdr_in_set(r, s_name, s_value);
	}

	if (ctx->pass_in & OIDC_APPINFO_PASS_ENVVARS) {

		/* do some logging about this event */
		oidc_debug(r, "setting environment variable \"%s: %s\"", s_name,
			   oidc_http_hdr_value_for_log(r, s_name, s_value));

		if (batched == TRUE)
			apr_table_addn(ctx->env, s_name, s_value);
		else
			apr_table_set(r->subprocess_env, s_name, s_value);
	}
}

static void oidc_util_appinfo_set_impl(request_rec *r, const char *s_key, const char *s_value,
				       const oidc_appinfo_ctx_t *ctx) {
	const char *s_name = NULL;
	const char *s_rendered = NULL;
	oidc_util_appinfo_render(r, s_key, s_value, ctx->claim_prefix, ctx->encoding, &s_name, &s_rendered);
	oidc_util_appinfo_pair_apply(r, s_name, s_rendered, ctx);
}

/*
 * set a HTTP header and/or environment variable to pass information to the application
 */
void oidc_util_appinfo_set(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix,
			   oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding) {
	const oidc_appinfo_ctx_t ctx = {claim_prefix, NULL, pass_in, encoding, NULL, NULL};
	oidc_util_appinfo_set_impl(r, s_key, s_value, &ctx);
}

#define OIDC_JSON_MAX_INT_STR_LEN 64

/* Reversibly escape backslashes and delimiters within an array element. */
static const char *oidc_util_appinfo_escape(request_rec *r, const char *claim_delimiter, const char *s_value) {
	size_t dlen = _oidc_strlen(claim_delimiter);

	if ((s_value == NULL) || (dlen == 0))
		return s_value;

	size_t slen = _oidc_strlen(s_value);
	/* worst case every input character is doubled (a value consisting solely of backslashes) */
	char *dst = apr_pcalloc(r->pool, 2 * slen + 1);
	char *d = dst;
	for (size_t i = 0; i < slen;) {
		if (s_value[i] == '\\') {
			*d++ = '\\';
			*d++ = s_value[i++];
		} else if ((i + dlen <= slen) && (_oidc_strncmp(s_value + i, claim_delimiter, dlen) == 0)) {
			/* the (i + dlen <= slen) bound makes the delimiter-length copy provably in-range */
			*d++ = '\\';
			for (size_t k = 0; k < dlen; k++)
				*d++ = s_value[i++];
		} else {
			*d++ = s_value[i++];
		}
	}
	*d = '\0';

	return dst;
}

/*
 * Join string and boolean array elements, escaping embedded delimiters and skipping other types.
 * The elements are rendered first and copied into a single allocation afterwards: growing the
 * result with an apr_psprintf() per element copied everything accumulated so far each time and
 * left every intermediate copy in the request pool, which made the memory quadratic in the number
 * of elements of a provider- or client-supplied claims array (OSS-Fuzz 554464974).
 */
static const char *oidc_util_appinfo_array_concat(request_rec *r, const oidc_json_t *j_array,
						  const char *claim_delimiter, const char *s_key) {
	const size_t n_elems = oidc_json_array_size(j_array);
	const size_t dlen = _oidc_strlen(claim_delimiter);
	const char **elems = NULL;
	size_t n = 0;
	size_t total = 0;

	oidc_debug(r, "parsing attribute array for key \"%s\" (#nr-of-elems: %lu)", s_key, (unsigned long)n_elems);

	if (n_elems == 0)
		return "";

	elems = apr_palloc(r->pool, n_elems * sizeof(const char *));
	for (size_t i = 0; i < n_elems; i++) {
		const oidc_json_t *elem = oidc_json_array_get(j_array, i);
		const char *s_elem = NULL;

		if (oidc_json_is_string(elem))
			s_elem = oidc_json_string_value(elem);
		else if (oidc_json_is_boolean(elem))
			s_elem = oidc_json_is_true(elem) ? "1" : "0";
		else {
			oidc_debug(r,
				   "unhandled in-array JSON object type [%d] for key \"%s\" when parsing claims "
				   "array elements",
				   oidc_json_typeof(elem), s_key);
			continue;
		}

		s_elem = oidc_util_appinfo_escape(r, claim_delimiter, s_elem);

		/* empty elements in front of the first non-empty one leave no trace, as before */
		if ((n == 0) && (*s_elem == '\0'))
			continue;

		elems[n] = s_elem;
		n++;
		total += _oidc_strlen(s_elem);
	}

	if (n == 0)
		return "";

	total += (n - 1) * dlen;
	char *s_concat = apr_palloc(r->pool, total + 1);
	char *p = s_concat;
	for (size_t i = 0; i < n; i++) {
		const size_t len = _oidc_strlen(elems[i]);
		if (i > 0) {
			_oidc_memcpy(p, claim_delimiter, dlen);
			p += dlen;
		}
		_oidc_memcpy(p, elems[i], len);
		p += len;
	}
	*p = '\0';

	return s_concat;
}

/*
 * render a single JSON claim value to its application-header textual form
 */
static void oidc_util_appinfo_set_one(request_rec *r, const char *s_key, const oidc_json_t *j_value,
				      const oidc_appinfo_ctx_t *ctx) {

	char s_int[OIDC_JSON_MAX_INT_STR_LEN];

	if (oidc_json_is_string(j_value)) {
		oidc_util_appinfo_set_impl(r, s_key, oidc_json_string_value(j_value), ctx);
	} else if (oidc_json_is_boolean(j_value)) {
		oidc_util_appinfo_set_impl(r, s_key, oidc_json_is_true(j_value) ? "1" : "0", ctx);
	} else if (oidc_json_is_integer(j_value)) {
		if (snprintf(s_int, OIDC_JSON_MAX_INT_STR_LEN, "%ld", (long)oidc_json_integer_value(j_value)) > 0)
			oidc_util_appinfo_set_impl(r, s_key, s_int, ctx);
	} else if (oidc_json_is_real(j_value)) {
		oidc_util_appinfo_set_impl(r, s_key, apr_psprintf(r->pool, "%.8g", oidc_json_real_value(j_value)), ctx);
	} else if (oidc_json_is_object(j_value)) {
		oidc_util_appinfo_set_impl(
		    r, s_key, oidc_json_encode(r->pool, j_value, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT), ctx);
	} else if (oidc_json_is_array(j_value)) {
		oidc_util_appinfo_set_impl(
		    r, s_key, oidc_util_appinfo_array_concat(r, j_value, ctx->claim_delimiter, s_key), ctx);
	} else {
		oidc_debug(r, "unhandled JSON object type [%d] for key \"%s\" when parsing claims",
			   oidc_json_typeof(j_value), s_key);
	}
}

/*
 * set the user/claims information from the session in HTTP headers passed on to the application
 */
void oidc_util_appinfo_set_all(request_rec *r, oidc_json_t *j_attrs, const char *claim_prefix,
			       const char *claim_delimiter, oidc_appinfo_pass_in_t pass_in,
			       oidc_appinfo_encoding_t encoding) {

	/* if not attributes are set, nothing needs to be done */
	if (j_attrs == NULL) {
		oidc_debug(r, "no attributes to set");
		return;
	}

	oidc_appinfo_ctx_t ctx = {claim_prefix, claim_delimiter, pass_in, encoding, NULL, NULL};
	if (pass_in & OIDC_APPINFO_PASS_HEADERS)
		ctx.headers = apr_table_make(r->pool, 16);
	if (pass_in & OIDC_APPINFO_PASS_ENVVARS)
		ctx.env = apr_table_make(r->pool, 16);

	/* loop over the claims in the JSON structure */
	void *iter = oidc_json_object_iter(j_attrs);
	while (iter) {
		oidc_util_appinfo_set_one(r, oidc_json_object_iter_key(iter), oidc_json_object_iter_value(iter), &ctx);
		iter = oidc_json_object_iter_next(j_attrs, iter);
	}

	if (ctx.headers != NULL)
		apr_table_overlap(r->headers_in, ctx.headers, APR_OVERLAP_TABLES_SET);
	if (ctx.env != NULL)
		apr_table_overlap(r->subprocess_env, ctx.env, APR_OVERLAP_TABLES_SET);
}
