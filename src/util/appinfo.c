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

#include "util/cache_local.h"

/*
 * process-lifetime cache of flattened claim name/value pairs, keyed by the identity of the
 * claims JSON object (plus the flattening parameters): with the parsed-session cache the claim
 * sets of an unchanged session are the same shared JSON objects on every request, so the
 * per-claim name construction, value rendering and encoding runs once instead of per request.
 * Each entry holds its own reference to the claims object, pinning the pointer so the key can
 * never be reused for a different object while the entry lives; requires atomic JSON reference
 * counting (the init function leaves the cache disabled otherwise). Each entry owns a private
 * subpool so evicted/replaced entries return the memory of their copied pairs.
 */
typedef struct oidc_appinfo_cache_entry_t {
	apr_pool_t *pool;
	oidc_json_t *claims;
	apr_table_t *pairs;
} oidc_appinfo_cache_entry_t;

static oidc_cache_local_t *_oidc_appinfo_cache = NULL;

/* bounds the cache; on overflow the least-recently-used entry is evicted, retaining the hot set */
#define OIDC_APPINFO_CACHE_MAX_ENTRIES 1000

/* replays a single flattened pair into the request (defined below; used by the cache use callback) */
static void oidc_util_appinfo_pair_apply(request_rec *r, const char *s_name, const char *s_value,
					 oidc_appinfo_pass_in_t pass_in);

/* release an entry: drop the pinning claims reference and return the subpool holding entry+pairs */
static void oidc_util_appinfo_cache_free(void *value) {
	oidc_appinfo_cache_entry_t *entry = value;
	oidc_json_decref(entry->claims);
	apr_pool_destroy(entry->pool);
}

/* freshness: the flattened pairs are valid while the key still maps to the same claims object;
 * the pinned reference guarantees the pointer cannot have been reused for a different object */
static int oidc_util_appinfo_cache_valid(void *value, const void *ctx) {
	return ((const oidc_appinfo_cache_entry_t *)value)->claims == (const oidc_json_t *)ctx;
}

struct oidc_util_appinfo_cache_use_ctx {
	request_rec *r;
	oidc_appinfo_pass_in_t pass_in;
};

/* under the read lock: replay the cached pairs into the request's tables (copying the strings, so
 * nothing references entry-owned memory once the lock is released) */
static void oidc_util_appinfo_cache_use(void *value, void *baton) {
	const oidc_appinfo_cache_entry_t *entry = value;
	const struct oidc_util_appinfo_cache_use_ctx *ctx = baton;
	const apr_array_header_t *arr = apr_table_elts(entry->pairs);
	const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
	for (int i = 0; i < arr->nelts; i++)
		oidc_util_appinfo_pair_apply(ctx->r, elts[i].key, elts[i].val, ctx->pass_in);
}

struct oidc_util_appinfo_cache_build_ctx {
	oidc_json_t *claims;
	const apr_table_t *pairs;
};

/* under the write lock: build an entry in its own subpool, taking a pinning reference on the claims
 * object and copying the flattened pairs; returns NULL (not cached) when the subpool cannot be made */
static void *oidc_util_appinfo_cache_build(apr_pool_t *pool, const char *key, void *baton) {
	const struct oidc_util_appinfo_cache_build_ctx *ctx = baton;
	apr_pool_t *entry_pool = NULL;
	oidc_appinfo_cache_entry_t *entry = NULL;
	const apr_array_header_t *arr = apr_table_elts(ctx->pairs);
	const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
	if (apr_pool_create(&entry_pool, pool) != APR_SUCCESS)
		return NULL;
	entry = apr_pcalloc(entry_pool, sizeof(oidc_appinfo_cache_entry_t));
	entry->pool = entry_pool;
	entry->claims = oidc_json_incref(ctx->claims);
	entry->pairs = apr_table_make(entry_pool, arr->nelts + 1);
	for (int i = 0; i < arr->nelts; i++)
		apr_table_set(entry->pairs, elts[i].key, elts[i].val);
	return entry;
}

void oidc_util_appinfo_cache_init(apr_pool_t *pool, server_rec *s) {
	/* pinning/sharing JSON objects across threads is only safe with atomic reference counting */
	if (oidc_json_refcount_threadsafe() == FALSE)
		return;
	oidc_cache_local_create(&_oidc_appinfo_cache, pool, "appinfo", OIDC_APPINFO_CACHE_MAX_ENTRIES, TRUE,
				oidc_util_appinfo_cache_free, oidc_util_cache_local_warn, s);
}

static const char *oidc_util_appinfo_cache_key(apr_pool_t *pool, const oidc_json_t *j_attrs, const char *claim_prefix,
					       const char *claim_delimiter, oidc_appinfo_encoding_t encoding) {
	return apr_psprintf(pool, "%pp#%s#%s#%d", (const void *)j_attrs, claim_prefix, claim_delimiter, (int)encoding);
}

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
 * pass one rendered name/value pair to the application as HTTP header and/or environment variable
 */
static void oidc_util_appinfo_pair_apply(request_rec *r, const char *s_name, const char *s_value,
					 oidc_appinfo_pass_in_t pass_in) {

	if (pass_in & OIDC_APPINFO_PASS_HEADERS) {
		oidc_http_hdr_in_set(r, s_name, s_value);
	}

	if (pass_in & OIDC_APPINFO_PASS_ENVVARS) {

		/* do some logging about this event */
		oidc_debug(r, "setting environment variable \"%s: %s\"", s_name, s_value);

		apr_table_set(r->subprocess_env, s_name, s_value);
	}
}

/*
 * set a HTTP header and/or environment variable to pass information to the application
 */
void oidc_util_appinfo_set(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix,
			   oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding) {
	const char *s_name = NULL;
	const char *s_rendered = NULL;
	oidc_util_appinfo_render(r, s_key, s_value, claim_prefix, encoding, &s_name, &s_rendered);
	oidc_util_appinfo_pair_apply(r, s_name, s_rendered, pass_in);
}

#define OIDC_JSON_MAX_INT_STR_LEN 64

/*
 * escape the escape character and the delimiter within a single array element value, so that a delimiter
 * occurring inside a value cannot be mistaken for an element separator by the application; the escaping is
 * reversible: "\\" decodes back to a literal "\" and "\<delimiter>" to a literal "<delimiter>"
 */
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
 * concatenate the (string/boolean) elements of a JSON array into a single delimiter-separated string;
 * non-string/non-boolean elements are skipped with a debug message; a delimiter (or the backslash escape
 * character) occurring inside an element value is escaped by oidc_util_appinfo_escape so it cannot be
 * mistaken for an element separator
 */
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

		s_elem = oidc_util_appinfo_escape(r, claim_delimiter, s_elem);

		if (_oidc_strcmp(s_concat, "") != 0)
			s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat, claim_delimiter, s_elem);
		else
			s_concat = apr_pstrdup(r->pool, s_elem);
	}

	return s_concat;
}

/*
 * render one claim and either pass it to the application directly or collect it into a pairs table
 */
static void oidc_util_appinfo_set_or_collect(request_rec *r, const char *s_key, const char *s_value,
					     const char *claim_prefix, oidc_appinfo_pass_in_t pass_in,
					     oidc_appinfo_encoding_t encoding, apr_table_t *pairs) {
	const char *s_name = NULL;
	const char *s_rendered = NULL;
	oidc_util_appinfo_render(r, s_key, s_value, claim_prefix, encoding, &s_name, &s_rendered);
	if (pairs != NULL) {
		if (s_rendered != NULL)
			apr_table_set(pairs, s_name, s_rendered);
	} else {
		oidc_util_appinfo_pair_apply(r, s_name, s_rendered, pass_in);
	}
}

/*
 * render a single JSON claim value to its application-header textual form
 */
static void oidc_util_appinfo_set_one(request_rec *r, const char *s_key, const oidc_json_t *j_value,
				      const char *claim_prefix, const char *claim_delimiter,
				      oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding,
				      apr_table_t *pairs) {

	char s_int[OIDC_JSON_MAX_INT_STR_LEN];

	if (oidc_json_is_string(j_value)) {
		oidc_util_appinfo_set_or_collect(r, s_key, oidc_json_string_value(j_value), claim_prefix, pass_in,
						 encoding, pairs);
	} else if (oidc_json_is_boolean(j_value)) {
		oidc_util_appinfo_set_or_collect(r, s_key, oidc_json_is_true(j_value) ? "1" : "0", claim_prefix,
						 pass_in, encoding, pairs);
	} else if (oidc_json_is_integer(j_value)) {
		if (snprintf(s_int, OIDC_JSON_MAX_INT_STR_LEN, "%ld", (long)oidc_json_integer_value(j_value)) > 0)
			oidc_util_appinfo_set_or_collect(r, s_key, s_int, claim_prefix, pass_in, encoding, pairs);
	} else if (oidc_json_is_real(j_value)) {
		oidc_util_appinfo_set_or_collect(r, s_key, apr_psprintf(r->pool, "%.8g", oidc_json_real_value(j_value)),
						 claim_prefix, pass_in, encoding, pairs);
	} else if (oidc_json_is_object(j_value)) {
		oidc_util_appinfo_set_or_collect(
		    r, s_key, oidc_json_encode(r->pool, j_value, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT),
		    claim_prefix, pass_in, encoding, pairs);
	} else if (oidc_json_is_array(j_value)) {
		oidc_util_appinfo_set_or_collect(r, s_key,
						 oidc_util_appinfo_array_concat(r, j_value, claim_delimiter, s_key),
						 claim_prefix, pass_in, encoding, pairs);
	} else {
		oidc_debug(r, "unhandled JSON object type [%d] for key \"%s\" when parsing claims",
			   oidc_json_typeof(j_value), s_key);
	}
}

/*
 * apply the flattened pairs cached for the specified claims object; TRUE when served from the cache
 */
static apr_byte_t oidc_util_appinfo_cache_apply(request_rec *r, const oidc_json_t *j_attrs, const char *key,
						oidc_appinfo_pass_in_t pass_in) {
	struct oidc_util_appinfo_cache_use_ctx ctx = {.r = r, .pass_in = pass_in};
	return oidc_cache_local_get_use(_oidc_appinfo_cache, key, oidc_util_appinfo_cache_valid, j_attrs,
					oidc_util_appinfo_cache_use, &ctx);
}

/*
 * store the flattened pairs for the specified claims object, taking a reference that pins it
 */
static void oidc_util_appinfo_cache_store(oidc_json_t *j_attrs, const char *key, const apr_table_t *pairs) {
	struct oidc_util_appinfo_cache_build_ctx ctx = {.claims = j_attrs, .pairs = pairs};
	oidc_cache_local_set_build(_oidc_appinfo_cache, key, oidc_util_appinfo_cache_build, &ctx);
}

/*
 * set the user/claims information from the session in HTTP headers passed on to the application;
 * cacheable indicates that j_attrs is a shared (read-only, process-lifetime) object from the
 * parsed-session cache so its flattened form may be cached and replayed keyed by its identity
 */
void oidc_util_appinfo_set_all(request_rec *r, oidc_json_t *j_attrs, const char *claim_prefix,
			       const char *claim_delimiter, oidc_appinfo_pass_in_t pass_in,
			       oidc_appinfo_encoding_t encoding, apr_byte_t cacheable) {

	apr_table_t *pairs = NULL;
	const char *key = NULL;

	/* if not attributes are set, nothing needs to be done */
	if (j_attrs == NULL) {
		oidc_debug(r, "no attributes to set");
		return;
	}

	if ((cacheable == TRUE) && (_oidc_appinfo_cache != NULL)) {
		key = oidc_util_appinfo_cache_key(r->pool, j_attrs, claim_prefix, claim_delimiter, encoding);
		if (oidc_util_appinfo_cache_apply(r, j_attrs, key, pass_in) == TRUE)
			return;
		pairs = apr_table_make(r->pool, 16);
	}

	/* loop over the claims in the JSON structure */
	void *iter = oidc_json_object_iter(j_attrs);
	while (iter) {
		oidc_util_appinfo_set_one(r, oidc_json_object_iter_key(iter), oidc_json_object_iter_value(iter),
					  claim_prefix, claim_delimiter, pass_in, encoding, pairs);
		iter = oidc_json_object_iter_next(j_attrs, iter);
	}

	if (pairs != NULL) {
		/* apply the collected pairs and keep them for subsequent requests of this claims object */
		const apr_array_header_t *arr = apr_table_elts(pairs);
		const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
		for (int i = 0; i < arr->nelts; i++)
			oidc_util_appinfo_pair_apply(r, elts[i].key, elts[i].val, pass_in);
		oidc_util_appinfo_cache_store(j_attrs, key, pairs);
	}
}
