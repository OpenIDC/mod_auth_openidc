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

/*
 * This is the single translation unit that talks to the JSON backend library (libjansson).
 * The opaque oidc_json_t type, the oidc_json_* functions and the OIDC_JSON_* constants declared
 * in json.h shield the rest of the module from the backend; oidc_json_t is identical to the
 * backend value type (struct json_t), so the thin wrappers below pass pointers through without
 * casting. Backend-specific concepts (encode/decode flags, value types) are translated here.
 */

#include <limits.h>

#include <jansson.h>

#include "const.h"

#include "json.h"
#include "proto/proto.h"
#include "util/util.h"

/*
 * translate the backend-independent OIDC_JSON_* flags into libjansson encode/decode flags
 */
static size_t oidc_json_flags2backend(int flags) {
	size_t f = 0;
	int indent = 0;
	if (flags & OIDC_JSON_COMPACT)
		f |= JSON_COMPACT;
	if (flags & OIDC_JSON_PRESERVE_ORDER)
		f |= JSON_PRESERVE_ORDER;
	if (flags & OIDC_JSON_ENCODE_ANY)
		f |= JSON_ENCODE_ANY;
	if (flags & OIDC_JSON_DECODE_ANY)
		f |= JSON_DECODE_ANY;
	indent = (flags >> 8) & 0x1F;
	if (indent > 0)
		f |= JSON_INDENT(indent);
	return f;
}

/*
 * construction
 */
oidc_json_t *oidc_json_object(void) {
	return json_object();
}

oidc_json_t *oidc_json_array(void) {
	return json_array();
}

oidc_json_t *oidc_json_string(const char *value) {
	return json_string(value);
}

oidc_json_t *oidc_json_integer(oidc_json_int_t value) {
	return json_integer((json_int_t)value);
}

oidc_json_t *oidc_json_boolean(int value) {
	return json_boolean(value);
}

/*
 * reference counting and copying
 */
void oidc_json_decref(oidc_json_t *json) {
	json_decref(json);
}

oidc_json_t *oidc_json_copy(const oidc_json_t *json) {
	return json_copy((oidc_json_t *)json);
}

oidc_json_t *oidc_json_deep_copy(const oidc_json_t *json) {
	return json_deep_copy(json);
}

/*
 * type inspection
 */
oidc_json_type_t oidc_json_typeof(const oidc_json_t *json) {
	switch (json_typeof(json)) {
	case JSON_OBJECT:
		return OIDC_JSON_TYPE_OBJECT;
	case JSON_ARRAY:
		return OIDC_JSON_TYPE_ARRAY;
	case JSON_STRING:
		return OIDC_JSON_TYPE_STRING;
	case JSON_INTEGER:
		return OIDC_JSON_TYPE_INTEGER;
	case JSON_REAL:
		return OIDC_JSON_TYPE_REAL;
	case JSON_TRUE:
		return OIDC_JSON_TYPE_TRUE;
	case JSON_FALSE:
		return OIDC_JSON_TYPE_FALSE;
	case JSON_NULL:
	default:
		return OIDC_JSON_TYPE_NULL;
	}
}

int oidc_json_is_object(const oidc_json_t *json) {
	return json_is_object(json);
}

int oidc_json_is_array(const oidc_json_t *json) {
	return json_is_array(json);
}

int oidc_json_is_string(const oidc_json_t *json) {
	return json_is_string(json);
}

int oidc_json_is_integer(const oidc_json_t *json) {
	return json_is_integer(json);
}

int oidc_json_is_real(const oidc_json_t *json) {
	return json_is_real(json);
}

int oidc_json_is_number(const oidc_json_t *json) {
	return json_is_number(json);
}

int oidc_json_is_boolean(const oidc_json_t *json) {
	return json_is_boolean(json);
}

int oidc_json_is_true(const oidc_json_t *json) {
	return json_is_true(json);
}

int oidc_json_is_null(const oidc_json_t *json) {
	return json_is_null(json);
}

/*
 * scalar value access
 */
const char *oidc_json_string_value(const oidc_json_t *json) {
	return json_string_value(json);
}

oidc_json_int_t oidc_json_integer_value(const oidc_json_t *json) {
	return (oidc_json_int_t)json_integer_value(json);
}

double oidc_json_real_value(const oidc_json_t *json) {
	return json_real_value(json);
}

double oidc_json_number_value(const oidc_json_t *json) {
	return json_number_value(json);
}

void oidc_json_integer_set(oidc_json_t *json, oidc_json_int_t value) {
	json_integer_set(json, (json_int_t)value);
}

/*
 * object access/mutation
 */
oidc_json_t *oidc_json_object_get(const oidc_json_t *json, const char *key) {
	return json_object_get(json, key);
}

int oidc_json_object_set(oidc_json_t *json, const char *key, oidc_json_t *value) {
	return json_object_set(json, key, value);
}

int oidc_json_object_set_new(oidc_json_t *json, const char *key, oidc_json_t *value) {
	return json_object_set_new(json, key, value);
}

int oidc_json_object_del(oidc_json_t *json, const char *key) {
	return json_object_del(json, key);
}

/*
 * object iteration
 */
void *oidc_json_object_iter(oidc_json_t *json) {
	return json_object_iter(json);
}

void *oidc_json_object_iter_next(oidc_json_t *json, void *iter) {
	return json_object_iter_next(json, iter);
}

const char *oidc_json_object_iter_key(void *iter) {
	return json_object_iter_key(iter);
}

oidc_json_t *oidc_json_object_iter_value(void *iter) {
	return json_object_iter_value(iter);
}

/*
 * array access/mutation
 */
size_t oidc_json_array_size(const oidc_json_t *json) {
	return json_array_size(json);
}

oidc_json_t *oidc_json_array_get(const oidc_json_t *json, size_t index) {
	return json_array_get(json, index);
}

int oidc_json_array_append_new(oidc_json_t *json, oidc_json_t *value) {
	return json_array_append_new(json, value);
}

/*
 * encode a JSON object into a pool-allocated string
 */
char *oidc_json_encode(apr_pool_t *pool, const oidc_json_t *json, int flags) {
	if (json == NULL)
		return NULL;
	char *s = json_dumps(json, oidc_json_flags2backend(flags));
	char *s_value = apr_pstrdup(pool, s);
	free(s);
	return s_value;
}

#define OIDC_JSON_MAX_ERROR_STR 4096

/*
 * parse a string into a JSON value; pool-based and silent, optionally returning an error message
 */
apr_byte_t oidc_json_parse(apr_pool_t *pool, const char *str, int flags, oidc_json_t **json, char **s_err) {
	json_error_t json_error;

	*json = NULL;
	if (s_err != NULL)
		*s_err = NULL;

	if (str == NULL) {
		if (s_err != NULL)
			*s_err = apr_pstrdup(pool, "input string is NULL");
		return FALSE;
	}

	*json = json_loads(str, oidc_json_flags2backend(flags), &json_error);
	if (*json == NULL) {
		if (s_err != NULL) {
#if JANSSON_VERSION_HEX >= 0x020B00
			if (json_error_code(&json_error) == json_error_null_character)
				*s_err = apr_pstrdup(pool, json_error.text);
			else
#endif
				*s_err = apr_psprintf(pool, "%s (%s)", json_error.text,
						      apr_pstrndup(pool, str, OIDC_JSON_MAX_ERROR_STR));
		}
		return FALSE;
	}

	return TRUE;
}

/*
 * parse a JSON object
 */
apr_byte_t oidc_json_decode_object_err(request_rec *r, const char *str, oidc_json_t **json, apr_byte_t log_err) {
	char *s_err = NULL;

	if (str == NULL)
		return FALSE;

	/* decode the JSON contents of the buffer */
	if (oidc_json_parse(r->pool, str, 0, json, &s_err) == FALSE) {
		/* something went wrong */
		if (log_err)
			oidc_error(r, "JSON parsing returned an error: %s", s_err);
		return FALSE;
	}

	if (!oidc_json_is_object(*json)) {
		/* oops, no JSON object */
		if (log_err) {
			oidc_error(r, "parsed JSON did not contain a JSON object");
			oidc_json_decref(*json);
			*json = NULL;
			return FALSE;
		}

		return TRUE;
	}

	return TRUE;
}

apr_byte_t oidc_json_decode_object(request_rec *r, const char *str, oidc_json_t **json) {
	return oidc_json_decode_object_err(r, str, json, TRUE);
}

/*
 * printout a JSON string value
 */
static apr_byte_t oidc_json_string_print(request_rec *r, const oidc_json_t *result, const char *key, const char *log) {
	const oidc_json_t *value = oidc_json_object_get(result, key);
	if (value != NULL && !oidc_json_is_null(value)) {
		oidc_error(r, "%s: response contained an \"%s\" entry with value: \"%s\"", log, key,
			   oidc_json_encode(r->pool, value,
					    OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT | OIDC_JSON_ENCODE_ANY));
		return TRUE;
	}
	return FALSE;
}

/*
 * check a JSON object for "error" results and printout
 */
apr_byte_t oidc_json_check_error(request_rec *r, const oidc_json_t *json) {
	if (oidc_json_string_print(r, json, OIDC_PROTO_ERROR, "oidc_util_check_json_error") == TRUE) {
		oidc_json_string_print(r, json, OIDC_PROTO_ERROR_DESCRIPTION, "oidc_util_check_json_error");
		return TRUE;
	}
	return FALSE;
}

/*
 * decode a JSON string, check for "error" results and printout
 */
apr_byte_t oidc_json_decode_and_check_error(request_rec *r, const char *str, oidc_json_t **json) {

	if (oidc_json_decode_object(r, str, json) == FALSE)
		return FALSE;

	// see if it is an error response
	if (oidc_json_check_error(r, *json) == TRUE) {
		oidc_json_decref(*json);
		*json = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * see if a certain string value is part of a JSON array with string elements
 */
apr_byte_t oidc_json_array_has_value(request_rec *r, const oidc_json_t *haystack, const char *needle) {

	if ((haystack == NULL) || (!oidc_json_is_array(haystack)))
		return FALSE;

	int i;
	for (i = 0; i < oidc_json_array_size(haystack); i++) {
		const oidc_json_t *elem = oidc_json_array_get(haystack, i);
		if (!oidc_json_is_string(elem)) {
			oidc_error(r, "unhandled in-array JSON non-string object type [%d]", oidc_json_typeof(elem));
			continue;
		}
		if (_oidc_strcmp(oidc_json_string_value(elem), needle) == 0) {
			break;
		}
	}

	return (i == oidc_json_array_size(haystack)) ? FALSE : TRUE;
}

/*
 * get (optional) string from a JSON object
 */
apr_byte_t oidc_json_object_get_string(apr_pool_t *pool, const oidc_json_t *json, const char *name, char **value,
				       const char *default_value) {
	*value = default_value ? apr_pstrdup(pool, default_value) : NULL;
	if (json != NULL) {
		const oidc_json_t *v = oidc_json_object_get(json, name);
		if ((v != NULL) && (oidc_json_is_string(v))) {
			*value = apr_pstrdup(pool, oidc_json_string_value(v));
		}
	}
	return TRUE;
}

/*
 * get (optional) string array from a JSON object
 */
apr_byte_t oidc_json_object_get_string_array(apr_pool_t *pool, const oidc_json_t *json, const char *name,
					     apr_array_header_t **value, const apr_array_header_t *default_value) {
	const oidc_json_t *v = NULL;
	const oidc_json_t *arr = NULL;
	*value = (default_value != NULL) ? apr_array_copy(pool, default_value) : NULL;
	if (json != NULL) {
		arr = oidc_json_object_get(json, name);
		if ((arr != NULL) && (oidc_json_is_array(arr))) {
			*value = apr_array_make(pool, (int)oidc_json_array_size(arr), sizeof(const char *));
			for (size_t i = 0; i < oidc_json_array_size(arr); i++) {
				v = oidc_json_array_get(arr, i);
				/* skip non-string elements rather than pushing a NULL (oidc_json_string_value
				 * returns NULL for them), matching the single-string getter above */
				if (oidc_json_is_string(v))
					APR_ARRAY_PUSH(*value, const char *) =
					    apr_pstrdup(pool, oidc_json_string_value(v));
			}
		}
	}
	return TRUE;
}

/*
 * get (optional) int from a JSON object
 */
apr_byte_t oidc_json_object_get_int(const oidc_json_t *json, const char *name, int *value, const int default_value) {
	const oidc_json_t *v = NULL;
	*value = default_value;
	if (json != NULL) {
		v = oidc_json_object_get(json, name);
		if ((v != NULL) && (oidc_json_is_integer(v))) {
			/* oidc_json_int_t is at least int64; clamp into int range to avoid silent truncation */
			oidc_json_int_t n = oidc_json_integer_value(v);
			if (n > INT_MAX)
				*value = INT_MAX;
			else if (n < INT_MIN)
				*value = INT_MIN;
			else
				*value = (int)n;
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * get (optional) boolean from a JSON object
 */
apr_byte_t oidc_json_object_get_bool(const oidc_json_t *json, const char *name, int *value, const int default_value) {
	const oidc_json_t *v = NULL;
	*value = default_value;
	if (json != NULL) {
		v = oidc_json_object_get(json, name);
		if ((v != NULL) && (oidc_json_is_boolean(v))) {
			*value = oidc_json_is_true(v);
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * merge two JSON objects
 */
apr_byte_t oidc_json_merge(request_rec *r, oidc_json_t *src, oidc_json_t *dst) {

	const char *key;
	oidc_json_t *value = NULL;
	void *iter = NULL;

	if ((src == NULL) || (dst == NULL))
		return FALSE;

	oidc_debug(r, "src=%s, dst=%s", oidc_json_encode(r->pool, src, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT),
		   oidc_json_encode(r->pool, dst, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT));

	iter = oidc_json_object_iter(src);
	while (iter) {
		key = oidc_json_object_iter_key(iter);
		value = oidc_json_object_iter_value(iter);
		oidc_json_object_set(dst, key, value);
		iter = oidc_json_object_iter_next(src, iter);
	}

	oidc_debug(r, "result dst=%s", oidc_json_encode(r->pool, dst, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT));

	return TRUE;
}
