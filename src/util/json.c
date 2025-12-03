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

#include "proto/proto.h"
#include "util/util.h"

/*
 * printout a JSON string value
 */
static apr_byte_t oidc_util_json_string_print(request_rec *r, json_t *result, const char *key, const char *log) {
	json_t *value = json_object_get(result, key);
	if (value != NULL && !json_is_null(value)) {
		oidc_error(r, "%s: response contained an \"%s\" entry with value: \"%s\"", log, key,
			   oidc_util_json_encode(r->pool, value, JSON_PRESERVE_ORDER | JSON_COMPACT | JSON_ENCODE_ANY));
		return TRUE;
	}
	return FALSE;
}

/*
 * check a JSON object for "error" results and printout
 */
apr_byte_t oidc_util_json_check_error(request_rec *r, json_t *json) {
	if (oidc_util_json_string_print(r, json, OIDC_PROTO_ERROR, "oidc_util_check_json_error") == TRUE) {
		oidc_util_json_string_print(r, json, OIDC_PROTO_ERROR_DESCRIPTION, "oidc_util_check_json_error");
		return TRUE;
	}
	return FALSE;
}

#define OIDC_JSON_MAX_ERROR_STR 4096

/*
 * parse a JSON object
 */
apr_byte_t oidc_util_json_decode_object_err(request_rec *r, const char *str, json_t **json, apr_byte_t log_err) {
	if (str == NULL)
		return FALSE;

	json_error_t json_error;
	*json = json_loads(str, 0, &json_error);

	/* decode the JSON contents of the buffer */
	if (*json == NULL) {
		if (log_err) {
			/* something went wrong */
#if JANSSON_VERSION_HEX >= 0x020B00
			if (json_error_code(&json_error) == json_error_null_character) {
				oidc_error(r, "JSON parsing returned an error: %s", json_error.text);
			} else {
#endif
				oidc_error(r, "JSON parsing returned an error: %s (%s)", json_error.text,
					   apr_pstrndup(r->pool, str, OIDC_JSON_MAX_ERROR_STR));
#if JANSSON_VERSION_HEX >= 0x020B00
			}
#endif
		}
		return FALSE;
	}

	if (!json_is_object(*json)) {
		/* oops, no JSON */
		if (log_err) {
			oidc_error(r, "parsed JSON did not contain a JSON object");
			json_decref(*json);
			*json = NULL;
			return FALSE;
		}

		return TRUE;
	}

	return TRUE;
}

apr_byte_t oidc_util_json_decode_object(request_rec *r, const char *str, json_t **json) {
	return oidc_util_json_decode_object_err(r, str, json, TRUE);
}

/*
 * encode a JSON object
 */
char *oidc_util_json_encode(apr_pool_t *pool, json_t *json, size_t flags) {
	if (json == NULL)
		return NULL;
	char *s = json_dumps(json, flags);
	char *s_value = apr_pstrdup(pool, s);
	free(s);
	return s_value;
}

/*
 * decode a JSON string, check for "error" results and printout
 */
apr_byte_t oidc_util_json_decode_and_check_error(request_rec *r, const char *str, json_t **json) {

	if (oidc_util_json_decode_object(r, str, json) == FALSE)
		return FALSE;

	// see if it is an error response
	if (oidc_util_json_check_error(r, *json) == TRUE) {
		json_decref(*json);
		*json = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * see if a certain string value is part of a JSON array with string elements
 */
apr_byte_t oidc_util_json_array_has_value(request_rec *r, json_t *haystack, const char *needle) {

	if ((haystack == NULL) || (!json_is_array(haystack)))
		return FALSE;

	int i;
	for (i = 0; i < json_array_size(haystack); i++) {
		json_t *elem = json_array_get(haystack, i);
		if (!json_is_string(elem)) {
			oidc_error(r, "unhandled in-array JSON non-string object type [%d]", elem->type);
			continue;
		}
		if (_oidc_strcmp(json_string_value(elem), needle) == 0) {
			break;
		}
	}

	/*	oidc_debug(r,
	 *			"returning (%d=%d)", i,
	 *			haystack->value.array->nelts);
	 */

	return (i == json_array_size(haystack)) ? FALSE : TRUE;
}

/*
 * get (optional) string from a JSON object
 */
apr_byte_t oidc_util_json_object_get_string(apr_pool_t *pool, json_t *json, const char *name, char **value,
					    const char *default_value) {
	*value = default_value ? apr_pstrdup(pool, default_value) : NULL;
	if (json != NULL) {
		json_t *v = json_object_get(json, name);
		if ((v != NULL) && (json_is_string(v))) {
			*value = apr_pstrdup(pool, json_string_value(v));
		}
	}
	return TRUE;
}

/*
 * get (optional) string array from a JSON object
 */
apr_byte_t oidc_util_json_object_get_string_array(apr_pool_t *pool, json_t *json, const char *name,
						  apr_array_header_t **value, const apr_array_header_t *default_value) {
	json_t *v = NULL, *arr = NULL;
	size_t i = 0;
	*value = (default_value != NULL) ? apr_array_copy(pool, default_value) : NULL;
	if (json != NULL) {
		arr = json_object_get(json, name);
		if ((arr != NULL) && (json_is_array(arr))) {
			*value = apr_array_make(pool, json_array_size(arr), sizeof(const char *));
			for (i = 0; i < json_array_size(arr); i++) {
				v = json_array_get(arr, i);
				APR_ARRAY_PUSH(*value, const char *) = apr_pstrdup(pool, json_string_value(v));
			}
		}
	}
	return TRUE;
}

/*
 * get (optional) int from a JSON object
 */
apr_byte_t oidc_util_json_object_get_int(const json_t *json, const char *name, int *value, const int default_value) {
	const json_t *v = NULL;
	*value = default_value;
	if (json != NULL) {
		v = json_object_get(json, name);
		if ((v != NULL) && (json_is_integer(v))) {
			*value = json_integer_value(v);
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * get (optional) boolean from a JSON object
 */
apr_byte_t oidc_util_json_object_get_bool(const json_t *json, const char *name, int *value, const int default_value) {
	const json_t *v = NULL;
	*value = default_value;
	if (json != NULL) {
		v = json_object_get(json, name);
		if ((v != NULL) && (json_is_boolean(v))) {
			*value = json_is_true(v);
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * merge two JSON objects
 */
apr_byte_t oidc_util_json_merge(request_rec *r, json_t *src, json_t *dst) {

	const char *key;
	json_t *value = NULL;
	void *iter = NULL;

	if ((src == NULL) || (dst == NULL))
		return FALSE;

	oidc_debug(r, "src=%s, dst=%s", oidc_util_json_encode(r->pool, src, JSON_PRESERVE_ORDER | JSON_COMPACT),
		   oidc_util_json_encode(r->pool, dst, JSON_PRESERVE_ORDER | JSON_COMPACT));

	iter = json_object_iter(src);
	while (iter) {
		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		json_object_set(dst, key, value);
		iter = json_object_iter_next(src, iter);
	}

	oidc_debug(r, "result dst=%s", oidc_util_json_encode(r->pool, dst, JSON_PRESERVE_ORDER | JSON_COMPACT));

	return TRUE;
}
