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
 * set a HTTP header and/or environment variable to pass information to the application
 */
void oidc_util_appinfo_set(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix,
			   oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding) {

	/* construct the header name, cq. put the prefix in front of a normalized key name */
	const char *s_name = apr_psprintf(r->pool, "%s%s", claim_prefix, oidc_http_hdr_normalize_name(r, s_key));
	char *d_value = NULL;

	if (s_value != NULL) {
		if (encoding == OIDC_APPINFO_ENCODING_BASE64URL) {
			oidc_util_base64url_encode(r, &d_value, s_value, (int)_oidc_strlen(s_value), TRUE);
		} else if (encoding == OIDC_APPINFO_ENCODING_LATIN1) {
			d_value = _oidc_util_appinfo_utf8_to_latin1(r, s_value);
		}
	}

	if (pass_in & OIDC_APPINFO_PASS_HEADERS) {
		oidc_http_hdr_in_set(r, s_name, (d_value != NULL) ? d_value : s_value);
	}

	if (pass_in & OIDC_APPINFO_PASS_ENVVARS) {

		/* do some logging about this event */
		oidc_debug(r, "setting environment variable \"%s: %s\"", s_name, (d_value != NULL) ? d_value : s_value);

		apr_table_set(r->subprocess_env, s_name, (d_value != NULL) ? d_value : s_value);
	}
}

#define OIDC_JSON_MAX_INT_STR_LEN 64

/*
 * concatenate the (string/boolean) elements of a JSON array into a single delimiter-separated string;
 * non-string/non-boolean elements are skipped with a debug message
 */
// TODO: escape the delimiter in the values (maybe reuse/extract url-formatted code from oidc_session_identity_encode)
static const char *oidc_util_appinfo_array_concat(request_rec *r, const oidc_json_t *j_array,
						  const char *claim_delimiter, const char *s_key) {

	oidc_debug(r, "parsing attribute array for key \"%s\" (#nr-of-elems: %lu)", s_key,
		   (unsigned long)oidc_json_array_size(j_array));

	char *s_concat = apr_pstrdup(r->pool, "");
	for (size_t i = 0; i < oidc_json_array_size(j_array); i++) {
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

		if (_oidc_strcmp(s_concat, "") != 0)
			s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat, claim_delimiter, s_elem);
		else
			s_concat = apr_pstrdup(r->pool, s_elem);
	}

	return s_concat;
}

/*
 * render a single JSON claim value to its application-header textual form and pass it to oidc_util_appinfo_set
 */
static void oidc_util_appinfo_set_one(request_rec *r, const char *s_key, const oidc_json_t *j_value,
				      const char *claim_prefix, const char *claim_delimiter,
				      oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding) {

	char s_int[OIDC_JSON_MAX_INT_STR_LEN];

	if (oidc_json_is_string(j_value)) {
		oidc_util_appinfo_set(r, s_key, oidc_json_string_value(j_value), claim_prefix, pass_in, encoding);
	} else if (oidc_json_is_boolean(j_value)) {
		oidc_util_appinfo_set(r, s_key, oidc_json_is_true(j_value) ? "1" : "0", claim_prefix, pass_in,
				      encoding);
	} else if (oidc_json_is_integer(j_value)) {
		if (snprintf(s_int, OIDC_JSON_MAX_INT_STR_LEN, "%ld", (long)oidc_json_integer_value(j_value)) > 0)
			oidc_util_appinfo_set(r, s_key, s_int, claim_prefix, pass_in, encoding);
	} else if (oidc_json_is_real(j_value)) {
		oidc_util_appinfo_set(r, s_key, apr_psprintf(r->pool, "%.8g", oidc_json_real_value(j_value)),
				      claim_prefix, pass_in, encoding);
	} else if (oidc_json_is_object(j_value)) {
		oidc_util_appinfo_set(r, s_key,
				      oidc_json_encode(r->pool, j_value, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT),
				      claim_prefix, pass_in, encoding);
	} else if (oidc_json_is_array(j_value)) {
		oidc_util_appinfo_set(r, s_key, oidc_util_appinfo_array_concat(r, j_value, claim_delimiter, s_key),
				      claim_prefix, pass_in, encoding);
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

	/* loop over the claims in the JSON structure */
	void *iter = oidc_json_object_iter(j_attrs);
	while (iter) {
		oidc_util_appinfo_set_one(r, oidc_json_object_iter_key(iter), oidc_json_object_iter_value(iter),
					  claim_prefix, claim_delimiter, pass_in, encoding);
		iter = oidc_json_object_iter_next(j_attrs, iter);
	}
}
