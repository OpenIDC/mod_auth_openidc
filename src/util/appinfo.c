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
			oidc_util_base64url_encode(r, &d_value, s_value, _oidc_strlen(s_value), TRUE);
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
 * set the user/claims information from the session in HTTP headers passed on to the application
 */
void oidc_util_appinfo_set_all(request_rec *r, json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter,
			       oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding) {

	char s_int[OIDC_JSON_MAX_INT_STR_LEN];
	json_t *j_value = NULL;
	const char *s_key = NULL;

	/* if not attributes are set, nothing needs to be done */
	if (j_attrs == NULL) {
		oidc_debug(r, "no attributes to set");
		return;
	}

	/* loop over the claims in the JSON structure */
	void *iter = json_object_iter((json_t *)j_attrs);
	while (iter) {

		/* get the next key/value entry */
		s_key = json_object_iter_key(iter);
		j_value = json_object_iter_value(iter);

		/* check if it is a single value string */
		if (json_is_string(j_value)) {

			/* set the single string in the application header whose name is based on the key and the prefix
			 */
			oidc_util_appinfo_set(r, s_key, json_string_value(j_value), claim_prefix, pass_in, encoding);

		} else if (json_is_boolean(j_value)) {

			/* set boolean value in the application header whose name is based on the key and the prefix */
			oidc_util_appinfo_set(r, s_key, (json_is_true(j_value) ? "1" : "0"), claim_prefix, pass_in,
					      encoding);

		} else if (json_is_integer(j_value)) {

			if (snprintf(s_int, OIDC_JSON_MAX_INT_STR_LEN, "%ld", (long)json_integer_value(j_value)) > 0) {
				/* set long value in the application header whose name is based on the key and the
				 * prefix */
				oidc_util_appinfo_set(r, s_key, s_int, claim_prefix, pass_in, encoding);
			}

		} else if (json_is_real(j_value)) {

			/* set float value in the application header whose name is based on the key and the prefix */
			oidc_util_appinfo_set(r, s_key, apr_psprintf(r->pool, "%.8g", json_real_value(j_value)),
					      claim_prefix, pass_in, encoding);

		} else if (json_is_object(j_value)) {

			/* set json value in the application header whose name is based on the key and the prefix */
			oidc_util_appinfo_set(
			    r, s_key, oidc_util_json_encode(r->pool, j_value, JSON_PRESERVE_ORDER | JSON_COMPACT),
			    claim_prefix, pass_in, encoding);

			/* check if it is a multi-value string */
		} else if (json_is_array(j_value)) {

			/* some logging about what we're going to do */
			oidc_debug(r, "parsing attribute array for key \"%s\" (#nr-of-elems: %lu)", s_key,
				   (unsigned long)json_array_size(j_value));

			/* string to hold the concatenated array string values */
			char *s_concat = apr_pstrdup(r->pool, "");
			size_t i = 0;

			/* loop over the array */
			for (i = 0; i < json_array_size(j_value); i++) {

				/* get the current element */
				json_t *elem = json_array_get(j_value, i);

				/* check if it is a string */
				if (json_is_string(elem)) {

					/* concatenate the string to the s_concat value using the configured separator
					 * char */
					// TODO: escape the delimiter in the values (maybe reuse/extract url-formatted
					// code from oidc_session_identity_encode)
					if (_oidc_strcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat, claim_delimiter,
									json_string_value(elem));
					} else {
						s_concat = apr_psprintf(r->pool, "%s", json_string_value(elem));
					}

				} else if (json_is_boolean(elem)) {

					if (_oidc_strcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat, claim_delimiter,
									json_is_true(elem) ? "1" : "0");
					} else {
						s_concat = apr_psprintf(r->pool, "%s", json_is_true(elem) ? "1" : "0");
					}

				} else {

					/* don't know how to handle a non-string array element */
					oidc_debug(r,
						   "unhandled in-array JSON object type [%d] for key \"%s\" when "
						   "parsing claims array elements",
						   elem->type, s_key);
				}
			}

			/* set the concatenated string */
			oidc_util_appinfo_set(r, s_key, s_concat, claim_prefix, pass_in, encoding);

		} else {

			/* no string and no array, so unclear how to handle this */
			oidc_debug(r, "unhandled JSON object type [%d] for key \"%s\" when parsing claims",
				   j_value->type, s_key);
		}

		iter = json_object_iter_next(j_attrs, iter);
	}
}
