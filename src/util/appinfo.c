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

#include <apr_thread_rwlock.h>

/*
 * process-lifetime cache of flattened claim name/value pairs, keyed by the identity of the
 * claims JSON object (plus the flattening parameters): with the parsed-session cache the claim
 * sets of an unchanged session are the same shared JSON objects on every request, so the
 * per-claim name construction, value rendering and encoding runs once instead of per request.
 * Each entry holds its own reference to the claims object, pinning the pointer so the key can
 * never be reused for a different object while the entry lives; requires atomic JSON reference
 * counting (the init function leaves the cache disabled otherwise).
 */
typedef struct oidc_appinfo_cache_entry_t {
	apr_pool_t *pool;
	char *key;
	oidc_json_t *claims;
	apr_table_t *pairs;
} oidc_appinfo_cache_entry_t;

static apr_hash_t *_oidc_appinfo_cache = NULL;
static apr_pool_t *_oidc_appinfo_cache_pool = NULL;
#if APR_HAS_THREADS
static apr_thread_rwlock_t *_oidc_appinfo_cache_rwlock = NULL;
#endif

/* bounds the cache; entries for changed sessions go stale until the reset-on-overflow */
#define OIDC_APPINFO_CACHE_MAX_ENTRIES 256

static void oidc_util_appinfo_cache_rdlock(void) {
#if APR_HAS_THREADS
	apr_thread_rwlock_rdlock(_oidc_appinfo_cache_rwlock);
#endif
}

static void oidc_util_appinfo_cache_wrlock(void) {
#if APR_HAS_THREADS
	apr_thread_rwlock_wrlock(_oidc_appinfo_cache_rwlock);
#endif
}

static void oidc_util_appinfo_cache_unlock(void) {
#if APR_HAS_THREADS
	apr_thread_rwlock_unlock(_oidc_appinfo_cache_rwlock);
#endif
}

/* release all cached entries; must be called with the write lock held (or at pool pre-cleanup) */
static void oidc_util_appinfo_cache_clear_unlocked(void) {
	void *val = NULL;
	if (_oidc_appinfo_cache == NULL)
		return;
	for (apr_hash_index_t *hi = apr_hash_first(NULL, _oidc_appinfo_cache); hi; hi = apr_hash_next(hi)) {
		oidc_appinfo_cache_entry_t *entry = NULL;
		apr_hash_this(hi, NULL, NULL, &val);
		entry = (oidc_appinfo_cache_entry_t *)val;
		oidc_json_decref(entry->claims);
		apr_pool_destroy(entry->pool);
	}
	apr_hash_clear(_oidc_appinfo_cache);
}

static apr_status_t oidc_util_appinfo_cache_cleanup(void *data) {
	oidc_util_appinfo_cache_clear_unlocked();
	_oidc_appinfo_cache = NULL;
	_oidc_appinfo_cache_pool = NULL;
#if APR_HAS_THREADS
	_oidc_appinfo_cache_rwlock = NULL;
#endif
	return APR_SUCCESS;
}

void oidc_util_appinfo_cache_init(apr_pool_t *pool) {
	if (_oidc_appinfo_cache != NULL)
		return;
	/* pinning/sharing JSON objects across threads is only safe with atomic reference counting */
	if (oidc_json_refcount_threadsafe() == FALSE)
		return;
#if APR_HAS_THREADS
	if (apr_thread_rwlock_create(&_oidc_appinfo_cache_rwlock, pool) != APR_SUCCESS)
		return;
#endif
	_oidc_appinfo_cache = apr_hash_make(pool);
	_oidc_appinfo_cache_pool = pool;
	/* must be a PRE-cleanup: it destroys the per-entry subpools itself, which a regular
	 * cleanup would touch after apr_pool_clear had already destroyed them */
	apr_pool_pre_cleanup_register(pool, NULL, oidc_util_appinfo_cache_cleanup);
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
	const oidc_appinfo_cache_entry_t *entry = NULL;
	apr_byte_t rv = FALSE;

	oidc_util_appinfo_cache_rdlock();
	entry = apr_hash_get(_oidc_appinfo_cache, key, APR_HASH_KEY_STRING);
	if ((entry != NULL) && (entry->claims == j_attrs)) {
		/* applying copies the strings into the request's tables, so nothing references
		 * entry-owned memory after the lock is released */
		const apr_array_header_t *arr = apr_table_elts(entry->pairs);
		const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
		for (int i = 0; i < arr->nelts; i++)
			oidc_util_appinfo_pair_apply(r, elts[i].key, elts[i].val, pass_in);
		rv = TRUE;
	}
	oidc_util_appinfo_cache_unlock();

	return rv;
}

/*
 * store the flattened pairs for the specified claims object, taking a reference that pins it
 */
static void oidc_util_appinfo_cache_store(oidc_json_t *j_attrs, const char *key, const apr_table_t *pairs) {
	oidc_appinfo_cache_entry_t *entry = NULL;
	apr_pool_t *entry_pool = NULL;

	oidc_util_appinfo_cache_wrlock();
	if (apr_hash_count(_oidc_appinfo_cache) >= OIDC_APPINFO_CACHE_MAX_ENTRIES)
		oidc_util_appinfo_cache_clear_unlocked();
	entry = apr_hash_get(_oidc_appinfo_cache, key, APR_HASH_KEY_STRING);
	if (entry != NULL) {
		/* remove the entry this store replaces before destroying the pool holding its key */
		apr_hash_set(_oidc_appinfo_cache, entry->key, APR_HASH_KEY_STRING, NULL);
		oidc_json_decref(entry->claims);
		apr_pool_destroy(entry->pool);
	}
	/* pool operations happen under the write lock only (pools/allocators are not thread-safe) */
	if (apr_pool_create(&entry_pool, _oidc_appinfo_cache_pool) == APR_SUCCESS) {
		const apr_array_header_t *arr = apr_table_elts(pairs);
		const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
		entry = apr_pcalloc(entry_pool, sizeof(oidc_appinfo_cache_entry_t));
		entry->pool = entry_pool;
		entry->key = apr_pstrdup(entry_pool, key);
		entry->claims = oidc_json_incref(j_attrs);
		entry->pairs = apr_table_make(entry_pool, arr->nelts + 1);
		for (int i = 0; i < arr->nelts; i++)
			apr_table_set(entry->pairs, elts[i].key, elts[i].val);
		apr_hash_set(_oidc_appinfo_cache, entry->key, APR_HASH_KEY_STRING, entry);
	}
	oidc_util_appinfo_cache_unlock();
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
