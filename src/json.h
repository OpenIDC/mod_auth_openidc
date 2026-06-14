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

#ifndef _MOD_AUTH_OPENIDC_JSON_H_
#define _MOD_AUTH_OPENIDC_JSON_H_

#include <httpd.h>

#include <apr_pools.h>
#include <apr_tables.h>

#include <limits.h>
#include <stddef.h>

/*
 * JSON backend abstraction layer.
 *
 * Nothing outside json.c references the JSON backend library (currently libjansson) directly:
 * the rest of the module only ever sees the opaque oidc_json_t type, the oidc_json_* functions
 * and the OIDC_JSON_* constants declared in this header. The one place that binds the abstraction
 * to a concrete backend is the typedef below (whose struct tag is the backend's value-struct tag)
 * plus the translations in json.c, so swapping the backend is a matter of changing this header and
 * reimplementing json.c. The single exception is jose.c, the cjose seam: cjose's public API is
 * itself defined in terms of the backend's value type, so jose.c includes the backend header
 * directly and relies on oidc_json_t being identical to the backend value type.
 */
typedef struct json_t oidc_json_t;

/* widest integer a JSON number can hold (matches the backend's integer type) */
typedef long long oidc_json_int_t;
#define OIDC_JSON_INT_FORMAT "lld"
#define OIDC_JSON_INT_MAX LLONG_MAX

/* JSON value types, kept independent of the backend library */
typedef enum {
	OIDC_JSON_TYPE_OBJECT,
	OIDC_JSON_TYPE_ARRAY,
	OIDC_JSON_TYPE_STRING,
	OIDC_JSON_TYPE_INTEGER,
	OIDC_JSON_TYPE_REAL,
	OIDC_JSON_TYPE_TRUE,
	OIDC_JSON_TYPE_FALSE,
	OIDC_JSON_TYPE_NULL
} oidc_json_type_t;

/* encode/decode flags, kept independent of the backend library */
#define OIDC_JSON_COMPACT 0x01
#define OIDC_JSON_PRESERVE_ORDER 0x02
#define OIDC_JSON_ENCODE_ANY 0x04
#define OIDC_JSON_DECODE_ANY 0x08
#define OIDC_JSON_INDENT(n) (((n) & 0x1F) << 8)

/*
 * construction
 */
oidc_json_t *oidc_json_object(void);
oidc_json_t *oidc_json_array(void);
oidc_json_t *oidc_json_string(const char *value);
oidc_json_t *oidc_json_integer(oidc_json_int_t value);
oidc_json_t *oidc_json_boolean(int value);

/*
 * reference counting and copying
 */
void oidc_json_decref(oidc_json_t *json);
oidc_json_t *oidc_json_copy(const oidc_json_t *json);
oidc_json_t *oidc_json_deep_copy(const oidc_json_t *json);

/*
 * type inspection
 */
oidc_json_type_t oidc_json_typeof(const oidc_json_t *json);
int oidc_json_is_object(const oidc_json_t *json);
int oidc_json_is_array(const oidc_json_t *json);
int oidc_json_is_string(const oidc_json_t *json);
int oidc_json_is_integer(const oidc_json_t *json);
int oidc_json_is_real(const oidc_json_t *json);
int oidc_json_is_number(const oidc_json_t *json);
int oidc_json_is_boolean(const oidc_json_t *json);
int oidc_json_is_true(const oidc_json_t *json);
int oidc_json_is_null(const oidc_json_t *json);

/*
 * scalar value access
 */
const char *oidc_json_string_value(const oidc_json_t *json);
oidc_json_int_t oidc_json_integer_value(const oidc_json_t *json);
double oidc_json_real_value(const oidc_json_t *json);
double oidc_json_number_value(const oidc_json_t *json);
void oidc_json_integer_set(oidc_json_t *json, oidc_json_int_t value);

/*
 * object access/mutation
 */
oidc_json_t *oidc_json_object_get(const oidc_json_t *json, const char *key);
int oidc_json_object_set(oidc_json_t *json, const char *key, oidc_json_t *value);
int oidc_json_object_set_new(oidc_json_t *json, const char *key, oidc_json_t *value);
int oidc_json_object_del(oidc_json_t *json, const char *key);

/*
 * object iteration
 */
void *oidc_json_object_iter(oidc_json_t *json);
void *oidc_json_object_iter_next(oidc_json_t *json, void *iter);
const char *oidc_json_object_iter_key(void *iter);
oidc_json_t *oidc_json_object_iter_value(void *iter);

/*
 * array access/mutation
 */
size_t oidc_json_array_size(const oidc_json_t *json);
oidc_json_t *oidc_json_array_get(const oidc_json_t *json, size_t index);
int oidc_json_array_append_new(oidc_json_t *json, oidc_json_t *value);

/*
 * serialization: returns a pool-allocated string, NULL on error
 */
char *oidc_json_encode(apr_pool_t *pool, const oidc_json_t *json, int flags);

/*
 * parsing primitive: pool-based, does not log; on error returns FALSE and (when s_err != NULL) a
 * pool-allocated error message
 */
apr_byte_t oidc_json_parse(apr_pool_t *pool, const char *str, int flags, oidc_json_t **json, char **s_err);

/*
 * request-level parsing/inspection helpers (log via oidc_error)
 */
apr_byte_t oidc_json_decode_object_err(request_rec *r, const char *str, oidc_json_t **json, apr_byte_t log_err);
apr_byte_t oidc_json_decode_object(request_rec *r, const char *str, oidc_json_t **json);
apr_byte_t oidc_json_decode_and_check_error(request_rec *r, const char *str, oidc_json_t **json);
apr_byte_t oidc_json_check_error(request_rec *r, const oidc_json_t *json);

/*
 * typed object getters with defaults
 */
apr_byte_t oidc_json_object_get_string(apr_pool_t *pool, const oidc_json_t *json, const char *name, char **value,
				       const char *default_value);
apr_byte_t oidc_json_object_get_string_array(apr_pool_t *pool, const oidc_json_t *json, const char *name,
					     apr_array_header_t **value, const apr_array_header_t *default_value);
apr_byte_t oidc_json_object_get_int(const oidc_json_t *json, const char *name, int *value, const int default_value);
apr_byte_t oidc_json_object_get_bool(const oidc_json_t *json, const char *name, int *value, const int default_value);

/*
 * misc helpers
 */
apr_byte_t oidc_json_merge(request_rec *r, oidc_json_t *src, oidc_json_t *dst);
apr_byte_t oidc_json_array_has_value(request_rec *r, const oidc_json_t *haystack, const char *needle);

#endif /* _MOD_AUTH_OPENIDC_JSON_H_ */
