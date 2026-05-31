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
 * Copyright (C) 2023-2026 ZmartZone Holding BV
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

// clang-format off

#include "util/util.h"
#include "metrics.h"
#include <limits.h>
#include <apr_atomic.h>
#include <apr_shm.h>
#include <apr_lib.h>

// NB: formatting matters for docs script from here until clang-format on

// KEEP THIS: start-of-classes

#define OM_CLASS_AUTH_TYPE     "authtype"       // Request counter, overall and per AuthType: openid-connect, oauth20 and auth-openidc.
#define OM_CLASS_AUTHN         "authn"          // Authentication request creation and response processing.
#define OM_CLASS_AUTHZ         "authz"          // Authorization errors per OIDCUnAuthzAction (per Require statement, not overall).
#define OM_CLASS_REQUIRE_CLAIM "require.claim"  // Match/failure count of Require claim directives (per Require statement, not overall).
#define OM_CLASS_CLAIM         "claim"          // Claims per value
#define OM_CLASS_PROVIDER      "provider"       // Requests to the provider [token, userinfo, metadata] endpoints.
#define OM_CLASS_SESSION       "session"        // Existing session processing.
#define OM_CLASS_CACHE         "cache"          // Cache read/write timings and errors.
#define OM_CLASS_REDIRECT_URI  "redirect_uri"   // Requests to the Redirect URI, per type.
#define OM_CLASS_CONTENT       "content"        // Requests to the content handler, per type of request: info, metrics, jwks, etc.

// KEEP THIS: end-of-classes

// NB: order must match the oidc_metrics_timing_type_t enum type in metrics.h

const oidc_metrics_timing_info_t _oidc_metrics_timings_info[] = {

  // KEEP THIS: start-of-timers

  { OM_CLASS_AUTH_TYPE, "handler", "the overall authz+authz processing time" },

  { OM_CLASS_AUTHN,    "request",  "authentication requests" },
  { OM_CLASS_AUTHN,    "response", "authentication responses" },

  { OM_CLASS_SESSION,  "valid",    "successfully validated existing sessions" },

  { OM_CLASS_PROVIDER, "metadata", "provider discovery document requests" },
  { OM_CLASS_PROVIDER, "token",    "provider token requests" },
  { OM_CLASS_PROVIDER, "refresh",  "provider refresh token requests" },
  { OM_CLASS_PROVIDER, "userinfo", "provider userinfo requests" },

  { OM_CLASS_CACHE,    "read",     "cache read requests" },
  { OM_CLASS_CACHE,    "write",    "cache write requests" },

  // KEEP THIS: end-of-timers

};

// NB: order must match the oidc_metrics_counter_type_t enum type in metrics.h

const oidc_metrics_counter_info_t _oidc_metrics_counters_info[] = {

   // KEEP THIS: start-of-counters

  { OM_CLASS_AUTH_TYPE, "mod_auth_openidc", "requests handled by mod_auth_openidc" },
  { OM_CLASS_AUTH_TYPE, "openid-connect",   "requests handled by AuthType openid-connect" },
  { OM_CLASS_AUTH_TYPE, "oauth20",          "requests handled by AuthType oauth20" },
  { OM_CLASS_AUTH_TYPE, "auth-openidc",     "requests handled by AuthType auth-openidc" },
  { OM_CLASS_AUTH_TYPE, "declined",         "requests not handled by mod_auth_openidc"},

  { OM_CLASS_AUTHN, "request.error.url", "errors matching the incoming request URL against the configuration" },

  { OM_CLASS_AUTHN, "response.error.state-mismatch", "state mismatch errors in authentication responses" },
  { OM_CLASS_AUTHN, "response.error.state-expired",  "state expired errors in authentication responses" },
  { OM_CLASS_AUTHN, "response.error.provider",       "errors returned by the provider in authentication responses" },
  { OM_CLASS_AUTHN, "response.error.protocol",       "protocol errors handling authentication responses" },
  { OM_CLASS_AUTHN, "response.error.remote-user",    "errors identifying the remote user based on provided claims" },

  { OM_CLASS_AUTHZ, "action.auth",          "step-up authentication requests" },
  { OM_CLASS_AUTHZ, "action.401",           "401 authorization errors" },
  { OM_CLASS_AUTHZ, "action.403",           "403 authorization errors" },
  { OM_CLASS_AUTHZ, "action.302",           "302 authorization errors" },
  { OM_CLASS_AUTHZ, "error.oauth20",        "AuthType oauth20 (401) authorization errors" },

  { OM_CLASS_REQUIRE_CLAIM, "match", "(per-) Require claim authorization matches" },
  { OM_CLASS_REQUIRE_CLAIM, "error", "(per-) Require claim authorization errors" },

  { OM_CLASS_CLAIM, "id_token",  "claim values in the ID Token" },
  { OM_CLASS_CLAIM, "userinfo", "claim values returned from the Userinfo Endpoint" },

  { OM_CLASS_PROVIDER, "metadata.error",     "errors retrieving a provider discovery document" },
  { OM_CLASS_PROVIDER, "token.error",        "errors making a token request to a provider" },
  { OM_CLASS_PROVIDER, "refresh.error",      "errors refreshing the access token at the token endpoint" },
  { OM_CLASS_PROVIDER, "userinfo.error",     "errors calling a provider userinfo endpoint" },
  { OM_CLASS_PROVIDER, "http.connect.error", "(libcurl) provider/network connectivity errors" },
  { OM_CLASS_PROVIDER, "http.response.code", "HTTP response code calling a provider endpoint" },

  { OM_CLASS_SESSION, "error.cookie-domain",        "cookie domain validation errors for existing sessions" },
  { OM_CLASS_SESSION, "error.expired",              "sessions that exceeded the maximum duration" },
  { OM_CLASS_SESSION, "error.refresh-access-token", "errors refreshing the access token before expiry in existing sessions" },
  { OM_CLASS_SESSION, "error.refresh-user-info",    "errors refreshing claims from the userinfo endpoint in existing sessions" },
  { OM_CLASS_SESSION, "error.general",              "existing sessions that failed validation" },

  { OM_CLASS_CACHE, "cache.error", "cache read/write errors" },

  { OM_CLASS_REDIRECT_URI, "authn.response.redirect", "authentication responses received in a redirect", },
  { OM_CLASS_REDIRECT_URI, "authn.response.post",     "authentication responses received in a HTTP POST", },
  { OM_CLASS_REDIRECT_URI, "authn.response.implicit", "(presumed) implicit authentication responses to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "discovery.response",      "discovery responses to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.logout",          "logout requests to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.jwks",            "JWKs retrieval requests to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.session",         "session management requests to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.refresh",         "refresh access token requests to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.request_uri",     "Request URI calls to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.remove_at_cache", "access token cache removal requests to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.session",         "revoke session requests to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.info",            "info hook requests to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "request.dpop",            "DPoP requests to the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "error.provider",          "provider authentication response errors received at the redirect URI", },
  { OM_CLASS_REDIRECT_URI, "error.invalid",           "invalid requests to the redirect URI", },

  { OM_CLASS_CONTENT, "request.declined",      "requests declined by the content handler" },
  { OM_CLASS_CONTENT, "request.info",          "info hook requests to the content handler" },
  { OM_CLASS_CONTENT, "request.dpop",          "DPoP requests to the content handler" },
  { OM_CLASS_CONTENT, "request.jwks",          "JWKs requests to the content handler" },
  { OM_CLASS_CONTENT, "request.discovery",     "discovery requests to the content handler" },
  { OM_CLASS_CONTENT, "request.post-preserve", "HTTP POST preservation requests to the content handler" },
  { OM_CLASS_CONTENT, "request.authn-post",    "HTTP POST authentication requests to the content handler" },
  { OM_CLASS_CONTENT, "request.unknown",       "unknown requests to the content handler" },

  // KEEP THIS: end-of-counters

};

// clang-format on

typedef struct oidc_metrics_t {
	apr_hash_t *counters;
	apr_hash_t *timings;
} oidc_metrics_t;

// pointer to the shared memory segment that holds the JSON metrics data
static apr_shm_t *_oidc_metrics_cache = NULL;
// flag to record if we are a parent process or a child process
static apr_byte_t _oidc_metrics_is_parent = FALSE;
/* flag to signal the metrics write thread to exit; accessed from the flush thread and from the
 * cleanup/child-init paths, so use apr_atomic_* to enforce visibility across threads (without this,
 * LTO is free to hoist the load out of the polling loop and shutdown stalls) */
static volatile apr_uint32_t _oidc_metrics_thread_exit = 0;
// mutex to protect the shared memory storage
static oidc_cache_mutex_t *_oidc_metrics_global_mutex = NULL;
// pointer to the thread that periodically writes the locally gathered metrics to shared memory
static apr_thread_t *_oidc_metrics_thread = NULL;
// pid that owns _oidc_metrics_thread; used to tell a post-fork stale handle from a same-process double-init
static pid_t _oidc_metrics_thread_pid = 0;
// local in-memory cached metrics
static oidc_metrics_t _oidc_metrics = {NULL, NULL};
// mutex to protect the local metrics hash table
static oidc_cache_mutex_t *_oidc_metrics_process_mutex = NULL;

// default shared memory write interval in seconds
#define OIDC_METRICS_CACHE_STORAGE_INTERVAL_DEFAULT 5000

// maximum length of the string representation of the global JSON metrics data in shared memory
//   1024 sample size (compact, long keys, large json_int values, no description), timing + counter
//   256 number of individual metrics collected
//     4 number of vhosts supported
#define OIDC_METRICS_CACHE_JSON_MAX_DEFAULT 1024 * 256 * 4

typedef struct oidc_metrics_bucket_t {
	const char *name;
	const char *label;
	apr_time_t threshold;
} oidc_metrics_bucket_t;

// clang-format off

static oidc_metrics_bucket_t _oidc_metric_buckets[] = {
	{ "le01", "le=\"0.1\"", 100 },
	{ "le05", "le=\"0.5\"", 500 },
	{ "le1", "le=\"1\"", apr_time_from_msec(1) },
	{ "le5", "le=\"5\"", apr_time_from_msec(5) },
	{ "le10", "le=\"10\"", apr_time_from_msec(10) },
	{ "le50", "le=\"50\"", apr_time_from_msec(50) },
	{ "le100", "le=\"100\"",  apr_time_from_msec(100) },
	{ "le500", "le=\"500\"",  apr_time_from_msec(500) },
	{ "le1000", "le=\"1000\"", apr_time_from_msec(1000) },
    { "le5000", "le=\"5000\"", apr_time_from_msec(5000) },
    { "inf", "le=\"+Inf\"", 0 }
};

// clang-format on

#define OIDC_METRICS_BUCKET_NUM sizeof(_oidc_metric_buckets) / sizeof(oidc_metrics_bucket_t)

// NB: matters for Prometheus formatting
#define OIDC_METRICS_SUM "sum"
#define OIDC_METRICS_COUNT "count"

#define OIDC_METRICS_SPECS "specs"

#define OIDC_METRICS_JSON_CLASS_NAME "class"
#define OIDC_METRICS_JSON_METRIC_NAME "name"
#define OIDC_METRICS_JSON_DESC "desc"

#define OIDC_METRICS_TIMINGS "timings"
#define OIDC_METRICS_COUNTERS "counters"

/*
 * convert a Jansson number to a string: JSON_INTEGER_FORMAT does not work with apr_psprintf !?
 */
static inline char *_json_int2str(apr_pool_t *pool, json_int_t n) {
	char s[255];
	snprintf(s, 255, "%" JSON_INTEGER_FORMAT, n);
	return apr_pstrdup(pool, s);
}

#if JSON_INTEGER_IS_LONG_LONG
#define OIDC_METRICS_INT_MAX LLONG_MAX
#else
#define OIDC_METRICS_INT_MAX LONG_MAX
#endif

/*
 * check Jansson specific integer/long number overrun
 */
static inline int _is_overflow(server_rec *s, json_int_t cur, json_int_t add) {
	if (add > (OIDC_METRICS_INT_MAX - cur)) {
		oidc_swarn(s,
			   "reset metrics since the size (%s) of the integer value would be larger than the "
			   "JSON/libjansson maximum "
			   "(%s)",
			   _json_int2str(s->process->pool, add), _json_int2str(s->process->pool, OIDC_METRICS_INT_MAX));
		return 1;
	}
	return 0;
}

// single counter container
typedef struct oidc_metrics_counter_t {
	json_int_t count;
} oidc_metrics_counter_t;

// single timing stats container
typedef struct oidc_metrics_timing_t {
	json_int_t buckets[OIDC_METRICS_BUCKET_NUM];
	apr_time_t sum;
	json_int_t count;
} oidc_metrics_timing_t;

// context holder for parsing valid classnames
typedef struct oidc_metrics_add_classname_ctx_t {
	apr_pool_t *pool;
	char **valid_names;
} oidc_metrics_add_classname_ctx_t;

/*
 * loop function for parsing valid classnames
 */
static int oidc_metrics_add_classnames(void *rec, const char *key, const char *value) {
	oidc_metrics_add_classname_ctx_t *ctx = (oidc_metrics_add_classname_ctx_t *)rec;
	*ctx->valid_names = apr_psprintf(ctx->pool, "%s%s%s", *ctx->valid_names ? *ctx->valid_names : "",
					 *ctx->valid_names ? " | " : "", value);
	return 1;
}

/*
 * check if the provided value is a valid classname
 */
apr_byte_t oidc_metrics_is_valid_classname(apr_pool_t *pool, const char *name, char **valid_names) {
	int i = 0;
	int n = 0;
	apr_table_t *names = apr_table_make(pool, 1);
	oidc_metrics_add_classname_ctx_t ctx = {pool, valid_names};

	n = sizeof(_oidc_metrics_timings_info) / sizeof(oidc_metrics_timing_info_t);
	for (i = 0; i < n; i++) {
		apr_table_set(names, _oidc_metrics_timings_info[i].class_name,
			      _oidc_metrics_timings_info[i].class_name);
	}
	n = sizeof(_oidc_metrics_counters_info) / sizeof(oidc_metrics_counter_info_t);
	for (i = 0; i < n; i++) {
		// TODO: instead of using hardcoded single "claim" name/value option, make this a static list
		if (_oidc_strcmp(_oidc_metrics_counters_info[i].class_name, "claim") != 0)
			apr_table_set(names, _oidc_metrics_counters_info[i].class_name,
				      _oidc_metrics_counters_info[i].class_name);
	}

	*valid_names = NULL;
	apr_table_do(oidc_metrics_add_classnames, &ctx, names, NULL);
	*valid_names = apr_psprintf(pool, "%s%s%s", *valid_names ? *valid_names : "", *valid_names ? " | " : "",
				    "claim.id_token.* | claim.userinfo.*");

	return apr_table_get(names, name) ? TRUE
					  : ((_oidc_strstr(name, "claim.id_token.") != NULL) ||
					     (_oidc_strstr(name, "claim.userinfo.") != NULL));
}

/*
 * retrieve environment variable integer with default setting
 */
static inline int _oidc_metrics_get_env_int(const char *name, int dval) {
	return _oidc_str_to_int(getenv(name), dval);
}

#define OIDC_METRICS_CACHE_JSON_MAX_ENV_VAR "OIDC_METRICS_CACHE_JSON_MAX"

static apr_size_t _g_oidc_metrics_shm_size = 0;

/*
 * get the size of the to-be-allocated shared memory segment
 */
static inline apr_size_t _oidc_metrics_shm_size(server_rec *s) {
	if (_g_oidc_metrics_shm_size == 0) {
		int n =
		    _oidc_metrics_get_env_int(OIDC_METRICS_CACHE_JSON_MAX_ENV_VAR, OIDC_METRICS_CACHE_JSON_MAX_DEFAULT);
		if ((n < 1) || (n > 1024 * 256 * 4 * 100)) {
			oidc_serror(s, "environment value %s out of bounds, fallback to default",
				    OIDC_METRICS_CACHE_JSON_MAX_ENV_VAR);
			_g_oidc_metrics_shm_size = OIDC_METRICS_CACHE_JSON_MAX_DEFAULT;
		} else {
			_g_oidc_metrics_shm_size = n;
		}
	}
	return _g_oidc_metrics_shm_size;
}

/*
 * retrieve the (JSON) serialized (global) metrics data from shared memory
 */
static inline char *_oidc_metrics_storage_get(server_rec *s) {
	const char *p = (char *)apr_shm_baseaddr_get(_oidc_metrics_cache);
	return p && (*p != 0) ? apr_pstrndup(s->process->pool, p, _oidc_metrics_shm_size(s)) : NULL;
}

/*
 * store the serialized (global) metrics data in shared memory
 */
static inline void _oidc_metrics_storage_set(server_rec *s, const char *value) {
	char *p = apr_shm_baseaddr_get(_oidc_metrics_cache);
	if (value) {
		int n = (int)_oidc_strlen(value) + 1;
		if (n > _oidc_metrics_shm_size(s))
			oidc_serror(s,
				    "json value too large: set or increase system environment variable %s to a value "
				    "larger than %" APR_SIZE_T_FMT,
				    OIDC_METRICS_CACHE_JSON_MAX_ENV_VAR, _oidc_metrics_shm_size(s));
		else
			_oidc_memcpy(p, value, n);
	} else {
		*p = 0;
	}
}

/*
 * parse a string into a JSON object
 */
static json_t *oidc_metrics_json_load(const char *s_json, json_error_t *json_error) {
	if (s_json == NULL)
		s_json = "{}";
	return json_loads(s_json, 0, json_error);
}

/*
 * parse a string into a JSON object in a server_rec context
 */
static json_t *oidc_metrics_json_parse_s(server_rec *s, const char *s_json) {
	json_error_t json_error;
	json_t *json = oidc_metrics_json_load(s_json, &json_error);
	if (json == NULL)
		oidc_serror(s, "JSON parsing failed: %s", json_error.text);
	return json;
}

/*
 * recursively reset all integer leaf values within a JSON object tree to 0
 */
static void oidc_metrics_reset_integer_tree(json_t *json) {
	void *iter = json_object_iter(json);
	while (iter) {
		json_t *value = json_object_iter_value(iter);
		if (json_is_integer(value))
			json_integer_set(value, 0);
		else if (json_is_object(value))
			oidc_metrics_reset_integer_tree(value);
		iter = json_object_iter_next(json, iter);
	}
}

/*
 * reset a single timings entry (buckets, sum, count) to 0
 */
static void oidc_metrics_reset_timer(json_t *j_entry) {
	for (int i = 0; i < OIDC_METRICS_BUCKET_NUM; i++)
		json_object_set_new(j_entry, _oidc_metric_buckets[i].name, json_integer(0));
	json_object_set_new(j_entry, OIDC_METRICS_SUM, json_integer(0));
	json_object_set_new(j_entry, OIDC_METRICS_COUNT, json_integer(0));
}

/*
 * reset all counter and timer entries for a single server in the JSON data
 */
static void oidc_metrics_reset_server(const json_t *j_server) {
	json_t *j_entries = NULL;
	void *iter = NULL;

	j_entries = json_object_get(j_server, OIDC_METRICS_COUNTERS);
	if (j_entries)
		oidc_metrics_reset_integer_tree(j_entries);

	j_entries = json_object_get(j_server, OIDC_METRICS_TIMINGS);
	iter = json_object_iter(j_entries);
	while (iter) {
		oidc_metrics_reset_timer(json_object_iter_value(iter));
		iter = json_object_iter_next(j_entries, iter);
	}
}

/*
 * reset the serialized (global) metrics data in shared memory
 */
static inline void oidc_metrics_storage_reset(server_rec *s) {
	const char *s_json = NULL;
	json_t *json = NULL;
	void *iter = NULL;

	/* get the global stringified JSON metrics */
	s_json = _oidc_metrics_storage_get(s);

	/* parse the metrics string to JSON */
	json = oidc_metrics_json_parse_s(s, s_json);
	if (json == NULL)
		json = json_object();

	iter = json_object_iter(json);
	while (iter) {
		oidc_metrics_reset_server(json_object_iter_value(iter));
		iter = json_object_iter_next(json, iter);
	}

	/* serialize the metrics data, preserve order is required for Prometheus */
	s_json = oidc_util_json_encode(s->process->pool, json, JSON_COMPACT | JSON_PRESERVE_ORDER);

	/* free the JSON data */
	json_decref(json);

	/* store the serialized metrics data in shared memory */
	_oidc_metrics_storage_set(s, s_json);
}

/*
 * create a new timings entry in the collected JSON data
 */
static json_t *oidc_metrics_timings_new(server_rec *s, const oidc_metrics_timing_t *timing) {
	json_t *entry = json_object();
	for (int i = 0; i < OIDC_METRICS_BUCKET_NUM; i++)
		json_object_set_new(entry, _oidc_metric_buckets[i].name, json_integer(timing->buckets[i]));
	json_object_set_new(entry, OIDC_METRICS_SUM, json_integer(apr_time_as_msec(timing->sum)));
	json_object_set_new(entry, OIDC_METRICS_COUNT, json_integer(timing->count));
	return entry;
}

/*
 * update an entry in the collected JSON data
 */
static void oidc_metrics_timings_update(server_rec *s, const json_t *entry, const oidc_metrics_timing_t *timing) {
	json_t *j_member = NULL;
	json_int_t n = 0;
	json_int_t v = 0;

	for (int i = 0; i < OIDC_METRICS_BUCKET_NUM; i++) {
		j_member = json_object_get(entry, _oidc_metric_buckets[i].name);
		json_integer_set(j_member, json_integer_value(j_member) + timing->buckets[i]);
	}

	j_member = json_object_get(entry, OIDC_METRICS_SUM);
	n = json_integer_value(j_member);

	v = apr_time_as_msec(timing->sum);
	if (_is_overflow(s, n, v))
		n = 0;

	json_integer_set(j_member, n + v);

	j_member = json_object_get(entry, OIDC_METRICS_COUNT);
	n = json_integer_value(j_member);
	json_integer_set(j_member, n + timing->count);
}

#define OIDC_METRICS_VALUE_DEFAULT "_"

/*
 * value helper to make sure it is not empty
 */
static inline const char *_metrics_value2key(const char *value) {
	return (value && _oidc_strcmp(value, "") != 0) ? value : OIDC_METRICS_VALUE_DEFAULT;
}

/*
 * create a new counter entry in the collected JSON data
 */
static json_t *oidc_metrics_counter_new(server_rec *s, apr_hash_t *htable) {
	oidc_metrics_counter_t *counter = NULL;
	char *value = NULL;
	json_t *j_values = NULL;
	for (apr_hash_index_t *hi = apr_hash_first(s->process->pool, htable); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, (const void **)&value, NULL, (void **)&counter);
		if (_oidc_strcmp(value, OIDC_METRICS_VALUE_DEFAULT) == 0) {
			j_values = json_integer(counter->count);
		} else {
			if (j_values == NULL)
				j_values = json_object();
			json_object_set_new(j_values, value, json_integer(counter->count));
		}
	}
	return j_values;
}

/*
 * update a counter entry in the collected JSON data
 */
static void oidc_metrics_counter_update(server_rec *s, json_t *j_counter, apr_hash_t *htable) {
	json_int_t v = 0;
	oidc_metrics_counter_t *counter = NULL;
	char *value = NULL;
	json_t *j_value = NULL;
	for (apr_hash_index_t *hi = apr_hash_first(s->process->pool, htable); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, (const void **)&value, NULL, (void **)&counter);
		if (_oidc_strcmp(value, OIDC_METRICS_VALUE_DEFAULT) == 0) {
			j_value = j_counter;
		} else {
			j_value = json_object_get(j_counter, value);
			if (j_value == NULL) {
				json_object_set_new(j_counter, value, json_integer(counter->count));
				continue;
			}
		}
		v = json_integer_value(j_value);
		if (_is_overflow(s, v, counter->count))
			v = 0;
		json_integer_set(j_value, v + counter->count);
	}
}

/*
 * get or create the vhost entry in the global metrics
 */
static json_t *oidc_metrics_server_get(json_t *json, const char *name) {
	json_t *j_server = json_object_get(json, name);
	if (j_server == NULL) {
		j_server = json_object();
		json_object_set_new(j_server, OIDC_METRICS_COUNTERS, json_object());
		json_object_set_new(j_server, OIDC_METRICS_TIMINGS, json_object());
		json_object_set_new(json, name, j_server);
	}
	return j_server;
}

/*
 * convert an enum type value to its corresponding string
 */
static inline char *_oidc_metrics_type_name2key(apr_pool_t *pool, unsigned int type, const char *name) {
	return (name == NULL) ? apr_psprintf(pool, "%u", type) : apr_psprintf(pool, "%u.%s", type, name);
}

/*
 * convert a string key type to an enum type
 */
static inline unsigned int _oidc_metrics_key2type(const char *key) {
	unsigned int type = 0;
	sscanf(key, "%u", &type);
	return type;
}

/*
 * update an existing counter under parent[key] or create a new one from counter_hash
 */
static void oidc_metrics_counter_set_or_update(server_rec *s, json_t *parent, const char *key,
					       apr_hash_t *counter_hash) {
	json_t *j_counter = json_object_get(parent, key);
	if (j_counter != NULL)
		oidc_metrics_counter_update(s, j_counter, counter_hash);
	else
		json_object_set_new(parent, key, oidc_metrics_counter_new(s, counter_hash));
}

/*
 * merge a single local counter entry into the global counters object;
 * keys of the form "class.name" are nested as j_counters[class][name]
 */
static void oidc_metrics_store_counter_entry(server_rec *s, json_t *j_counters, const char *key,
					     apr_hash_t *counter_hash) {
	const char *class_name = apr_pstrdup(s->process->pool, key);
	char *name = _oidc_strstr(class_name, ".");
	json_t *j_names = NULL;

	if (name == NULL) {
		oidc_metrics_counter_set_or_update(s, j_counters, class_name, counter_hash);
		return;
	}

	*name++ = '\0';
	j_names = json_object_get(j_counters, class_name);
	if (j_names == NULL) {
		j_names = json_object();
		json_object_set_new(j_names, name, oidc_metrics_counter_new(s, counter_hash));
		json_object_set_new(j_counters, class_name, j_names);
		return;
	}

	oidc_metrics_counter_set_or_update(s, j_names, name, counter_hash);
}

/*
 * merge all locally collected counters into the global JSON
 */
static void oidc_metrics_store_counters(server_rec *s, json_t *json) {
	const char *name = NULL;
	const char *key = NULL;
	apr_hash_t *server_hash = NULL;
	apr_hash_t *counter_hash = NULL;
	json_t *j_counters = NULL;

	for (apr_hash_index_t *hi1 = apr_hash_first(s->process->pool, _oidc_metrics.counters); hi1;
	     hi1 = apr_hash_next(hi1)) {
		apr_hash_this(hi1, (const void **)&name, NULL, (void **)&server_hash);
		j_counters = json_object_get(oidc_metrics_server_get(json, name), OIDC_METRICS_COUNTERS);
		for (apr_hash_index_t *hi2 = apr_hash_first(s->process->pool, server_hash); hi2;
		     hi2 = apr_hash_next(hi2)) {
			apr_hash_this(hi2, (const void **)&key, NULL, (void **)&counter_hash);
			oidc_metrics_store_counter_entry(s, j_counters, key, counter_hash);
		}
	}
}

/*
 * merge all locally collected timings into the global JSON
 */
static void oidc_metrics_store_timings(server_rec *s, json_t *json) {
	const char *name = NULL;
	const char *key = NULL;
	apr_hash_t *server_hash = NULL;
	oidc_metrics_timing_t *timing = NULL;
	json_t *j_timings = NULL;
	const json_t *j_timer = NULL;

	for (apr_hash_index_t *hi1 = apr_hash_first(s->process->pool, _oidc_metrics.timings); hi1;
	     hi1 = apr_hash_next(hi1)) {
		apr_hash_this(hi1, (const void **)&name, NULL, (void **)&server_hash);
		j_timings = json_object_get(oidc_metrics_server_get(json, name), OIDC_METRICS_TIMINGS);
		for (apr_hash_index_t *hi2 = apr_hash_first(s->process->pool, server_hash); hi2;
		     hi2 = apr_hash_next(hi2)) {
			apr_hash_this(hi2, (const void **)&key, NULL, (void **)&timing);
			j_timer = json_object_get(j_timings, key);
			if (j_timer != NULL)
				oidc_metrics_timings_update(s, j_timer, timing);
			else
				json_object_set_new(j_timings, key, oidc_metrics_timings_new(s, timing));
		}
	}
}

/*
 * flush the locally gathered metrics data into the global data kept in shared memory
 */
static void oidc_metrics_store(server_rec *s) {
	const char *s_json = NULL;
	json_t *json = NULL;

	if ((apr_hash_count(_oidc_metrics.counters) == 0) && (apr_hash_count(_oidc_metrics.timings) == 0))
		return;

	/* lock the shared memory for other processes */
	oidc_cache_mutex_lock(s->process->pool, s, _oidc_metrics_global_mutex);

	/* get the global stringified JSON metrics */
	s_json = _oidc_metrics_storage_get(s);

	/* parse the metrics string to JSON */
	json = oidc_metrics_json_parse_s(s, s_json);
	if (json == NULL)
		json = json_object();

	oidc_metrics_store_counters(s, json);
	oidc_metrics_store_timings(s, json);

	/* serialize the metrics data, preserve order is required for Prometheus */
	s_json = oidc_util_json_encode(s->process->pool, json, JSON_COMPACT | JSON_PRESERVE_ORDER);

	/* free the JSON data */
	json_decref(json);

	/* store the serialized metrics data in shared memory */
	_oidc_metrics_storage_set(s, s_json);

	/* unlock the shared memory for other processes */
	oidc_cache_mutex_unlock(s->process->pool, s, _oidc_metrics_global_mutex);
}

#define OIDC_METRICS_CACHE_STORAGE_INTERVAL_ENV_VAR "OIDC_METRICS_CACHE_STORAGE_INTERVAL"

/*
 * obtain the metrics flush interval from the environment variables
 */
static inline apr_interval_time_t _oidc_metrics_interval(void) {
	return apr_time_from_msec(_oidc_metrics_get_env_int(OIDC_METRICS_CACHE_STORAGE_INTERVAL_ENV_VAR,
							    OIDC_METRICS_CACHE_STORAGE_INTERVAL_DEFAULT));
}

#define OIDC_METRICS_POLL_INTERVAL 250

/*
 * thread that periodically writes the local data into the shared memory
 */
static void *APR_THREAD_FUNC oidc_metrics_thread_run(apr_thread_t *thread, void *data) {
	server_rec *s = (server_rec *)data;

	/* sleep for a short random time <0.1s so child processes write-lock on a different frequency */
	apr_sleep(apr_time_from_msec(oidc_util_rand_int(100)));

	/* split the flush interval into POLL_INTERVAL-sized ticks so shutdown is observed quickly; if the
	 * configured interval is shorter than POLL_INTERVAL, use it as the tick directly so we still flush
	 * on schedule rather than busy-looping with n=0 */
	apr_interval_time_t interval = _oidc_metrics_interval();
	/* a misconfigured env var parses to 0 (or negative) — fall back to the default to avoid 0/0 below */
	if (interval <= 0)
		interval = apr_time_from_msec(OIDC_METRICS_CACHE_STORAGE_INTERVAL_DEFAULT);
	apr_interval_time_t tick = apr_time_from_msec(OIDC_METRICS_POLL_INTERVAL);
	if (tick > interval)
		tick = interval;
	int n = (int)(interval / tick);

	/* see if we are asked to exit */
	while (apr_atomic_read32(&_oidc_metrics_thread_exit) == 0) {

		/* break up the sleep interval in short intervals so we can exit timely fashion without confusing Apache
		 * at shutdown */
		for (int i = 0; i < n; i++) {
			apr_sleep(tick);
			if (apr_atomic_read32(&_oidc_metrics_thread_exit) != 0)
				break;
		}

		// NB: no exit here because we need to write our local metrics into the cache before exiting

		/* lock the mutex that protects the locally cached metrics */
		oidc_cache_mutex_lock(s->process->pool, s, _oidc_metrics_process_mutex);

		/* flush the locally cached metrics into the global shared memory */
		oidc_metrics_store(s);

		/* reset the local hashtables */
		oidc_util_apr_hash_clear(_oidc_metrics.counters);
		oidc_util_apr_hash_clear(_oidc_metrics.timings);

		/* unlock the mutex that protects the locally cached metrics */
		oidc_cache_mutex_unlock(s->process->pool, s, _oidc_metrics_process_mutex);
	}

	/* NB: don't call apr_thread_exit here because it seems that Apache is cleaning up its own threads */

	return NULL;
}

/*
 * server config handlers
 */

/*
 * NB: global, yet called for each vhost that has metrics enabled!
 */
apr_byte_t oidc_metrics_post_config(apr_pool_t *pool, server_rec *s) {

	/* make sure it gets executed exactly once! */
	if (_oidc_metrics_cache != NULL)
		return TRUE;

	/* create the shared memory segment that holds the stringified JSON formatted metrics data */
	if (apr_shm_create(&_oidc_metrics_cache, _oidc_metrics_shm_size(s), NULL, s->process->pool) != APR_SUCCESS)
		return FALSE;
	if (_oidc_metrics_cache == NULL)
		return FALSE;

	/* initialize the shared memory segment to 0 */
	char *p = apr_shm_baseaddr_get(_oidc_metrics_cache);
	_oidc_memset(p, 0, _oidc_metrics_shm_size(s));

	/* flag this as the parent, for shared memory cleanup purposes and "multiple child-init calls" detection */
	_oidc_metrics_is_parent = TRUE;

	/* create the thread that will periodically flush the local metrics data to shared memory */
	if (apr_thread_create(&_oidc_metrics_thread, NULL, oidc_metrics_thread_run, s, s->process->pool) != APR_SUCCESS)
		return FALSE;
	_oidc_metrics_thread_pid = getpid();

	/* create the hashtable that holds local metrics data */
	_oidc_metrics.counters = apr_hash_make(s->process->pool);
	_oidc_metrics.timings = apr_hash_make(s->process->pool);

	/* create and initialize the mutex that guards _oidc_metrics_hash */
	_oidc_metrics_global_mutex = oidc_cache_mutex_create(s->process->pool, TRUE);
	if (_oidc_metrics_global_mutex == NULL)
		return FALSE;
	if (oidc_cache_mutex_post_config(s->process->pool, s, _oidc_metrics_global_mutex, "metrics-global") == FALSE)
		return FALSE;

	/* create and initialize the mutex that guards the shared memory */
	_oidc_metrics_process_mutex = oidc_cache_mutex_create(s->process->pool, FALSE);
	if (_oidc_metrics_process_mutex == NULL)
		return FALSE;
	if (oidc_cache_mutex_post_config(s->process->pool, s, _oidc_metrics_process_mutex, "metrics-process") == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * NB: global, yet called for each vhost that has metrics enabled!
 */
apr_status_t oidc_metrics_child_init(apr_pool_t *p, server_rec *s) {
	apr_status_t rv = APR_SUCCESS;

	/* make sure this executes only once per child */
	if (_oidc_metrics_is_parent == FALSE)
		return APR_SUCCESS;

	if (oidc_cache_mutex_child_init(p, s, _oidc_metrics_global_mutex) != APR_SUCCESS)
		return APR_EGENERAL;

	if (oidc_cache_mutex_child_init(p, s, _oidc_metrics_process_mutex) != APR_SUCCESS)
		return APR_EGENERAL;

	/* if a flush thread already exists in this process (e.g. unit tests calling post_config and
	 * child_init without forking) shut it down before overwriting the handle; after a real fork the
	 * pid differs and the parent's thread didn't carry over, so the stale handle is just discarded */
	if (_oidc_metrics_thread != NULL && _oidc_metrics_thread_pid == getpid()) {
		apr_atomic_set32(&_oidc_metrics_thread_exit, 1);
		apr_thread_join(&rv, _oidc_metrics_thread);
		apr_atomic_set32(&_oidc_metrics_thread_exit, 0);
	}
	_oidc_metrics_thread = NULL;

	/* the metrics flush thread is not inherited from the parent, so re-create it in the child */
	if (apr_thread_create(&_oidc_metrics_thread, NULL, oidc_metrics_thread_run, s, s->process->pool) != APR_SUCCESS)
		return APR_EGENERAL;
	_oidc_metrics_thread_pid = getpid();

	/* flag this is a child */
	_oidc_metrics_is_parent = FALSE;

	return APR_SUCCESS;
}

/*
 * NB: global, yet called for each vhost that has metrics enabled!
 */
apr_status_t oidc_metrics_cleanup(server_rec *s) {
	apr_status_t rv = APR_SUCCESS;

	/* make sure it gets executed exactly once! */
	if ((_oidc_metrics_cache == NULL) || (apr_atomic_read32(&_oidc_metrics_thread_exit) != 0) ||
	    (_oidc_metrics_thread == NULL))
		return APR_SUCCESS;

	/* signal the collector thread to exit */
	apr_atomic_set32(&_oidc_metrics_thread_exit, 1);
	apr_thread_join(&rv, _oidc_metrics_thread);
	if (rv != APR_SUCCESS)
		oidc_serror(s, "apr_thread_join failed");
	apr_atomic_set32(&_oidc_metrics_thread_exit, 0);
	_oidc_metrics_thread = NULL;
	_oidc_metrics_thread_pid = 0;

	/* delete the shared memory segment if we are in the parent process */
	if (_oidc_metrics_is_parent == TRUE)
		apr_shm_destroy(_oidc_metrics_cache);
	_oidc_metrics_cache = NULL;

	/* delete the process mutex that guards the local metrics data */
	if (oidc_cache_mutex_destroy(s, _oidc_metrics_process_mutex) == FALSE)
		return APR_EGENERAL;
	_oidc_metrics_process_mutex = NULL;

	/* delete the process mutex that guards the global shared memory segment */
	if (oidc_cache_mutex_destroy(s, _oidc_metrics_global_mutex) == FALSE)
		return APR_EGENERAL;
	_oidc_metrics_global_mutex = NULL;

	return APR_SUCCESS;
}

/*
 * sampling
 */

/*
 * obtain the local metrics hashtable for the current vhost
 */
static inline apr_hash_t *_oidc_metrics_server_hash(request_rec *r, apr_hash_t *table) {
	apr_hash_t *server_hash = NULL;
	const char *name = "_default_";

	/* obtain the server name */
	if (r->server->server_hostname)
		name = r->server->server_hostname;

	/* get the entry to the vhost record, or newly create it */
	server_hash = apr_hash_get(table, name, APR_HASH_KEY_STRING);
	if (server_hash == NULL) {
		// NB: process pool!
		server_hash = apr_hash_make(r->server->process->pool);
		apr_hash_set(table, name, APR_HASH_KEY_STRING, server_hash);
	}

	return server_hash;
}

/*
 * retrieve or create a local timing for the specified type
 */
static inline oidc_metrics_timing_t *_oidc_metrics_timing_get(request_rec *r, unsigned int type) {
	oidc_metrics_timing_t *result = NULL;
	const char *key = _oidc_metrics_type_name2key(r->server->process->pool, type, NULL);
	apr_hash_t *server_hash = _oidc_metrics_server_hash(r, _oidc_metrics.timings);
	/* get the entry to the specified metric */
	result = apr_hash_get(server_hash, key, APR_HASH_KEY_STRING);
	if (result == NULL) {
		/* allocate the timing structure in the process pool */
		result = apr_pcalloc(r->server->process->pool, sizeof(oidc_metrics_timing_t));
		apr_hash_set(server_hash, key, APR_HASH_KEY_STRING, result);
	}
	return result;
}

/*
 * retrieve or create a counter from a hashtable of values
 */
static inline oidc_metrics_counter_t *_oidc_metrics_counter_value_get(request_rec *r, apr_hash_t *table,
								      const char *value) {
	/* get the entry to the specified metric */
	oidc_metrics_counter_t *result = apr_hash_get(table, value, APR_HASH_KEY_STRING);
	if (result == NULL) {
		result = apr_pcalloc(r->server->process->pool, sizeof(oidc_metrics_counter_t));
		apr_hash_set(table, apr_pstrdup(r->server->process->pool, value), APR_HASH_KEY_STRING, result);
	}
	return result;
}

/*
 * retrieve or create a local counter for the specified type and name
 */
static inline apr_hash_t *_oidc_metrics_counter_get(request_rec *r, unsigned int type, const char *name) {
	apr_hash_t *result = NULL;
	const char *key = _oidc_metrics_type_name2key(r->server->process->pool, type, name);
	apr_hash_t *server_hash = _oidc_metrics_server_hash(r, _oidc_metrics.counters);

	/* get the entry to the specified metric */
	result = apr_hash_get(server_hash, key, APR_HASH_KEY_STRING);
	if (result == NULL) {
		/* allocate the values hashtable in the process pool */
		result = apr_hash_make(r->server->process->pool);
		apr_hash_set(server_hash, key, APR_HASH_KEY_STRING, result);
	}

	return result;
}

/*
 * add/increase a counter metric in the locally cached data
 */
void oidc_metrics_counter_inc(request_rec *r, oidc_metrics_counter_type_t type, const char *name, const char *value) {
	oidc_metrics_counter_t *counter = NULL;

	/* lock the local metrics cache hashtable */
	oidc_cache_mutex_lock(r->pool, r->server, _oidc_metrics_process_mutex);

	/* obtain or create the entry for the specified key */
	counter =
	    _oidc_metrics_counter_value_get(r, _oidc_metrics_counter_get(r, type, name), _metrics_value2key(value));

	/* performance */
	if (counter->count <= 0) {
		// new counter was created just now or reset earlier
		counter->count = 1;
	} else {
		// increase after checking possible overflow
		if (_is_overflow(r->server, counter->count, 1))
			counter->count = 0;
		counter->count++;
	}

	/* unlock the local metrics cache hashtable */
	oidc_cache_mutex_unlock(r->pool, r->server, _oidc_metrics_process_mutex);
}

/*
 * zero out a timings entry (count, sum and all buckets)
 */
static inline void _oidc_metrics_timing_clear(oidc_metrics_timing_t *timing) {
	timing->count = 0;
	timing->sum = 0;
	for (int i = 0; i < OIDC_METRICS_BUCKET_NUM; i++)
		timing->buckets[i] = 0;
}

/*
 * increment every bucket whose threshold covers elapsed (buckets are ordered;
 * threshold == 0 marks the open-ended last bucket)
 */
static inline void _oidc_metrics_timing_buckets_inc(oidc_metrics_timing_t *timing, apr_time_t elapsed) {
	for (int i = 0; i < OIDC_METRICS_BUCKET_NUM; i++) {
		if ((elapsed < _oidc_metric_buckets[i].threshold) || (_oidc_metric_buckets[i].threshold == 0)) {
			for (int j = i; j < OIDC_METRICS_BUCKET_NUM; j++)
				timing->buckets[j]++;
			break;
		}
	}
}

/*
 * add a metrics timing sample to the locally cached data
 */
void oidc_metrics_timing_add(request_rec *r, oidc_metrics_timing_type_t type, apr_time_t elapsed) {
	oidc_metrics_timing_t *timing = NULL;

	/* TODO: how can this happen? */
	if (elapsed < 0) {
		oidc_warn(r, "discarding metrics timing [%s.%s]: elapsed (%" APR_TIME_T_FMT ") < 0",
			  _oidc_metrics_timings_info[type].class_name, _oidc_metrics_timings_info[type].metric_name,
			  elapsed);
		return;
	}

	/* lock the local metrics cache hashtable */
	oidc_cache_mutex_lock(r->pool, r->server, _oidc_metrics_process_mutex);

	/* obtain or create the entry for the specified key */
	timing = _oidc_metrics_timing_get(r, type);

	/* reset on overflow; a freshly-created entry already has count/sum/buckets at zero */
	if ((timing->count > 0) && _is_overflow(r->server, timing->sum, elapsed))
		_oidc_metrics_timing_clear(timing);

	_oidc_metrics_timing_buckets_inc(timing, elapsed);
	timing->sum += elapsed;
	timing->count++;

	/* unlock the local metrics cache hashtable */
	oidc_cache_mutex_unlock(r->pool, r->server, _oidc_metrics_process_mutex);
}

/*
 * representation handlers
 */

/*
 * convert in integer counter enum type to its corresponding string name
 */
static inline char *_oidc_metrics_counter_type2s(apr_pool_t *pool, unsigned int type) {
	return apr_psprintf(pool, "%s.%s", _oidc_metrics_counters_info[type].class_name,
			    _oidc_metrics_counters_info[type].metric_name);
}

/*
 * convert in integer timings enum type to its corresponding string name
 */
static inline char *_oidc_metrics_timing_type2s(apr_pool_t *pool, unsigned int type) {
	return apr_psprintf(pool, "%s.%s", _oidc_metrics_timings_info[type].class_name,
			    _oidc_metrics_timings_info[type].metric_name);
}

/*
 * parse a string into a JSON object in the request_rec context
 */
static json_t *oidc_metrics_json_parse_r(request_rec *r, const char *s_json) {
	json_error_t json_error;
	json_t *json = oidc_metrics_json_load(s_json, &json_error);
	if (json == NULL)
		oidc_error(r, "JSON parsing failed: %s", json_error.text);
	return json;
}

/*
 * JSON with extended descriptions/names
 */
static int oidc_metrics_handle_json(request_rec *r, const char *s_json) {

	json_t *json = NULL;
	const json_t *j_server = NULL;
	json_t *j_timings = NULL;
	json_t *j_counters = NULL;
	const json_t *j_timing = NULL;
	json_t *j_counter = NULL;
	json_t *o_json = NULL;
	json_t *o_server = NULL;
	json_t *o_counters = NULL;
	json_t *o_counter = NULL;
	json_t *o_timings = NULL;
	json_t *o_timing = NULL;
	const char *s_server = NULL;
	unsigned int type = 0;
	void *i1 = NULL;
	void *i2 = NULL;

	/* parse the metrics string to JSON */
	json = oidc_metrics_json_parse_r(r, s_json);
	if (json == NULL)
		goto end;

	o_json = json_object();

	i1 = json_object_iter(json);
	while (i1) {
		s_server = json_object_iter_key(i1);
		j_server = json_object_iter_value(i1);

		o_server = json_object();
		json_object_set_new(o_json, s_server, o_server);

		j_counters = json_object_get(j_server, OIDC_METRICS_COUNTERS);
		o_counters = json_object();
		json_object_set_new(o_server, OIDC_METRICS_COUNTERS, o_counters);

		i2 = json_object_iter(j_counters);
		while (i2) {
			type = _oidc_metrics_key2type(json_object_iter_key(i2));
			j_counter = json_object_iter_value(i2);
			o_counter = json_object();
			if (json_is_integer(j_counter))
				json_object_set(o_counter, "count", j_counter);
			else
				json_object_set_new(o_counter, "values", json_deep_copy(j_counter));
			json_object_set_new(o_counter, OIDC_METRICS_JSON_CLASS_NAME,
					    json_string(_oidc_metrics_counters_info[type].class_name));
			json_object_set_new(o_counter, OIDC_METRICS_JSON_METRIC_NAME,
					    json_string(_oidc_metrics_counters_info[type].metric_name));
			json_object_set_new(o_counter, OIDC_METRICS_JSON_DESC,
					    json_string(_oidc_metrics_counters_info[type].desc));
			json_object_set_new(o_counters, _oidc_metrics_counter_type2s(r->pool, type), o_counter);
			i2 = json_object_iter_next(j_counters, i2);
		}

		j_timings = json_object_get(j_server, OIDC_METRICS_TIMINGS);
		o_timings = json_object();
		json_object_set_new(o_server, OIDC_METRICS_TIMINGS, o_timings);

		i2 = json_object_iter(j_timings);
		while (i2) {
			type = _oidc_metrics_key2type(json_object_iter_key(i2));
			j_timing = json_object_iter_value(i2);

			o_timing = json_deep_copy(j_timing);
			json_object_set_new(o_timing, OIDC_METRICS_JSON_CLASS_NAME,
					    json_string(_oidc_metrics_timings_info[type].class_name));
			json_object_set_new(o_timing, OIDC_METRICS_JSON_METRIC_NAME,
					    json_string(_oidc_metrics_timings_info[type].metric_name));
			json_object_set_new(o_timing, OIDC_METRICS_JSON_DESC,
					    json_string(_oidc_metrics_timings_info[type].desc));

			json_object_set_new(o_timings, _oidc_metrics_timing_type2s(r->pool, type), o_timing);

			i2 = json_object_iter_next(j_timings, i2);
		}
		i1 = json_object_iter_next(json, i1);
	}

	s_json = oidc_util_json_encode(r->pool, o_json, JSON_COMPACT | JSON_PRESERVE_ORDER);

	json_decref(o_json);
	json_decref(json);

end:

	/* return the data to the caller */
	return oidc_util_http_send(r, s_json, _oidc_strlen(s_json), OIDC_HTTP_CONTENT_TYPE_JSON, OK);
}

/*
 * dump the internal shared memory segment
 */
static int oidc_metrics_handle_internal(request_rec *r, const char *s_json) {
	if (s_json == NULL)
		return HTTP_NOT_FOUND;
	return oidc_util_http_send(r, s_json, _oidc_strlen(s_json), OIDC_HTTP_CONTENT_TYPE_JSON, OK);
}

#define OIDC_METRICS_SERVER_PARAM "server_name"
#define OIDC_METRICS_COUNTER_PARAM "counter"
#define OIDC_METRICS_NAME_PARAM "name"
#define OIDC_METRICS_VALUE_PARAM "value"

/*
 * find the counter entry in j_counters whose type matches "class.metric" (s_metric_param)
 */
static json_t *oidc_metrics_status_find_counter(request_rec *r, json_t *j_counters, const char *s_metric_param) {
	void *iter = json_object_iter(j_counters);
	while (iter) {
		unsigned int type = _oidc_metrics_key2type(json_object_iter_key(iter));
		if (_oidc_strcmp(_oidc_metrics_counter_type2s(r->pool, type), s_metric_param) == 0)
			return json_object_iter_value(iter);
		iter = json_object_iter_next(j_counters, iter);
	}
	return NULL;
}

/*
 * extract the requested integer value out of a counter entry:
 *   - integer entry: the counter itself
 *   - object entry with value-only selector: j_counter[value]
 *   - object entry with name+value selectors: j_counter[name][value]
 */
static json_t *oidc_metrics_status_select_value(json_t *j_counter, const char *s_name_param,
						const char *s_value_param) {
	const json_t *j_values = NULL;
	if (json_is_integer(j_counter))
		return j_counter;
	if (s_value_param == NULL)
		return NULL;
	if (s_name_param == NULL)
		return json_object_get(j_counter, s_value_param);
	j_values = json_object_get(j_counter, s_name_param);
	if (j_values == NULL)
		return NULL;
	return json_object_get(j_values, s_value_param);
}

/*
 * return status updates
 */
static int oidc_metrics_handle_status(request_rec *r, const char *s_json) {
	const char *msg = "OK\n";
	char *s_metric_param = NULL;
	char *s_server_param = NULL;
	char *s_name_param = NULL;
	char *s_value_param = NULL;
	json_t *json = NULL;
	const json_t *j_server = NULL;
	json_t *j_counters = NULL;
	json_t *j_counter = NULL;
	const json_t *j_value = NULL;

	oidc_util_url_parameter_get(r, OIDC_METRICS_SERVER_PARAM, &s_server_param);
	oidc_util_url_parameter_get(r, OIDC_METRICS_COUNTER_PARAM, &s_metric_param);
	oidc_util_url_parameter_get(r, OIDC_METRICS_NAME_PARAM, &s_name_param);
	oidc_util_url_parameter_get(r, OIDC_METRICS_VALUE_PARAM, &s_value_param);

	if (s_server_param == NULL)
		s_server_param = "localhost";

	if (s_metric_param == NULL)
		goto end;

	json = oidc_metrics_json_parse_r(r, s_json);
	if (json == NULL)
		goto end;

	j_server = json_object_get(json, s_server_param);
	if (j_server == NULL)
		goto end;

	j_counters = json_object_get(j_server, OIDC_METRICS_COUNTERS);
	if (j_counters == NULL)
		goto end;

	j_counter = oidc_metrics_status_find_counter(r, j_counters, s_metric_param);
	if (j_counter == NULL)
		goto end;

	j_value = oidc_metrics_status_select_value(j_counter, s_name_param, s_value_param);
	if (j_value)
		msg = apr_psprintf(r->pool, "OK: %s\n", _json_int2str(r->pool, json_integer_value(j_value)));

end:

	if (json)
		json_decref(json);

	return oidc_util_http_send(r, msg, _oidc_strlen(msg), "text/plain", OK);
}

/*
 * return the Prometheus label name for a bucket
 */
static const char *oidc_metrics_prometheus_bucket_label(const char *json_name) {
	const char *name = NULL;
	for (int i = 0; i < OIDC_METRICS_BUCKET_NUM; i++) {
		if (_oidc_strcmp(_oidc_metric_buckets[i].name, json_name) == 0) {
			name = _oidc_metric_buckets[i].label;
			break;
		}
	}
	return name;
}

#define OIDC_METRICS_PROMETHEUS_PREFIX "oidc"

/*
 * normalize a metric name to something that Prometheus accepts
 */
static const char *oidc_metric_prometheus_normalize_name(apr_pool_t *pool, const char *name) {
	char *label = apr_psprintf(pool, "%s", name);
	for (int i = 0; i < _oidc_strlen(label); i++)
		if (apr_isalnum(label[i]) == 0)
			label[i] = '_';
	return apr_psprintf(pool, "%s_%s", OIDC_METRICS_PROMETHEUS_PREFIX, label);
}

#define OIDC_METRICS_PROMETHEUS_CONTENT_TYPE "text/plain; version=0.0.4"

#define OIDC_METRICS_PROMETHEUS_SERVER "server_name"
#define OIDC_METRICS_PROMETHEUS_BUCKET "bucket"
#define OIDC_METRICS_PROMETHEUS_VALUE "value"
#define OIDC_METRICS_PROMETHEUS_NAME "name"

// loop context for Prometheus output
typedef struct oidc_metric_prometheus_callback_ctx_t {
	char *s_result;
	apr_pool_t *pool;
} oidc_metric_prometheus_callback_ctx_t;

/*
 * append per-(name, value) label-pair lines for a single key under a server's counter
 */
static char *oidc_metrics_prometheus_counter_named(apr_pool_t *pool, char *s_text, const char *s_start,
						   const char *s_key, json_t *j_value) {
	void *iter = json_object_iter(j_value);
	while (iter) {
		const char *s_value = json_object_iter_key(iter);
		s_text = apr_psprintf(pool, "%s%s,%s=\"%s\",%s=\"%s\"} %s\n", s_text, s_start,
				      OIDC_METRICS_PROMETHEUS_NAME, s_key, OIDC_METRICS_PROMETHEUS_VALUE, s_value,
				      _json_int2str(pool, json_integer_value(json_object_iter_value(iter))));
		iter = json_object_iter_next(j_value, iter);
	}
	return s_text;
}

/*
 * append per-key lines for one server's counter dict; integer entries are value-labeled, sub-dict
 * entries are delegated to oidc_metrics_prometheus_counter_named for name+value labeling
 */
static char *oidc_metrics_prometheus_counter_keyed(apr_pool_t *pool, char *s_text, const char *s_start,
						   json_t *j_counter) {
	void *iter = json_object_iter(j_counter);
	while (iter) {
		const char *s_key = json_object_iter_key(iter);
		json_t *j_value = json_object_iter_value(iter);
		if (json_is_integer(j_value))
			s_text =
			    apr_psprintf(pool, "%s%s,%s=\"%s\"} %s\n", s_text, s_start, OIDC_METRICS_PROMETHEUS_VALUE,
					 s_key, _json_int2str(pool, json_integer_value(j_value)));
		else
			s_text = oidc_metrics_prometheus_counter_named(pool, s_text, s_start, s_key, j_value);
		iter = json_object_iter_next(j_counter, iter);
	}
	return s_text;
}

/*
 * loop function for converting counter metrics to Prometheus output
 */
static int oidc_metrics_prometheus_counters(oidc_metric_prometheus_callback_ctx_t *ctx, const char *key,
					    json_t *value) {
	json_t *o_counter = value;
	unsigned int type = _oidc_metrics_key2type(key);
	const char *s_label =
	    oidc_metric_prometheus_normalize_name(ctx->pool, _oidc_metrics_counter_type2s(ctx->pool, type));
	char *s_text =
	    apr_psprintf(ctx->pool, "# HELP %s The number of %s.\n", s_label, _oidc_metrics_counters_info[type].desc);
	s_text = apr_psprintf(ctx->pool, "%s# TYPE %s counter\n", s_text, s_label);

	void *iter = json_object_iter(o_counter);
	while (iter) {
		const char *s_server = json_object_iter_key(iter);
		json_t *j_counter = json_object_iter_value(iter);
		const char *s_start =
		    apr_psprintf(ctx->pool, "%s{%s=\"%s\"", s_label, OIDC_METRICS_PROMETHEUS_SERVER, s_server);
		if (json_is_integer(j_counter))
			s_text = apr_psprintf(ctx->pool, "%s%s} %s\n", s_text, s_start,
					      _json_int2str(ctx->pool, json_integer_value(j_counter)));
		else
			s_text = oidc_metrics_prometheus_counter_keyed(ctx->pool, s_text, s_start, j_counter);
		iter = json_object_iter_next(o_counter, iter);
	}
	ctx->s_result = apr_pstrcat(ctx->pool, ctx->s_result, s_text, "\n", NULL);
	json_decref(o_counter);
	return 1;
}

/*
 * loop function for converting timing metrics to Prometheus output
 */

static int oidc_metrics_prometheus_timings(oidc_metric_prometheus_callback_ctx_t *ctx, const char *key, json_t *value) {
	const char *s_server = NULL;
	const char *s_key = NULL;
	const char *s_bucket = NULL;
	json_t *j_timing = NULL;
	const json_t *j_member = NULL;
	json_t *o_timer = value;
	unsigned int type = _oidc_metrics_key2type(key);
	const char *s_label =
	    oidc_metric_prometheus_normalize_name(ctx->pool, _oidc_metrics_timing_type2s(ctx->pool, type));
	char *s_text =
	    apr_psprintf(ctx->pool, "# HELP %s A histogram of %s.\n", s_label, _oidc_metrics_timings_info[type].desc);
	s_text = apr_psprintf(ctx->pool, "%s# TYPE %s histogram\n", s_text, s_label);

	void *iter1 = json_object_iter(o_timer);
	while (iter1) {
		s_server = json_object_iter_key(iter1);
		j_timing = json_object_iter_value(iter1);
		void *iter3 = json_object_iter(j_timing);
		while (iter3) {
			s_key = json_object_iter_key(iter3);
			j_member = json_object_iter_value(iter3);
			s_bucket = oidc_metrics_prometheus_bucket_label(s_key);
			if (s_bucket)
				s_text = apr_psprintf(ctx->pool, "%s%s_%s{%s,", s_text, s_label,
						      OIDC_METRICS_PROMETHEUS_BUCKET, s_bucket);
			else
				s_text = apr_psprintf(ctx->pool, "%s%s_%s{", s_text, s_label, s_key);

			s_text = apr_psprintf(ctx->pool, "%s%s=\"%s\"} %s\n", s_text, OIDC_METRICS_PROMETHEUS_SERVER,
					      s_server, _json_int2str(ctx->pool, json_integer_value(j_member)));
			iter3 = json_object_iter_next(j_timing, iter3);
		}
		iter1 = json_object_iter_next(o_timer, iter1);
	}
	ctx->s_result = apr_pstrcat(ctx->pool, ctx->s_result, s_text, "\n", NULL);
	json_decref(o_timer);
	return 1;
}

/*
 * take a list of metrics from a server indexed list and add it to a type indexed list
 */
static void oidc_metrics_prometheus_convert(apr_hash_t *hash, const char *server, json_t *list) {
	const char *type = NULL;
	json_t *src = NULL;
	json_t *dst = NULL;
	void *iter = json_object_iter(list);
	while (iter) {
		type = json_object_iter_key(iter);
		src = json_object_iter_value(iter);
		dst = (json_t *)apr_hash_get(hash, type, APR_HASH_KEY_STRING);
		if (dst) {
			json_object_set(dst, server, src);
		} else {
			dst = json_object();
			json_object_set(dst, server, src);
			apr_hash_set(hash, type, APR_HASH_KEY_STRING, dst);
		}
		iter = json_object_iter_next(list, iter);
	}
}

/*
 * generate output in Prometheus formatting
 */
static int oidc_metrics_handle_prometheus(request_rec *r, const char *s_json) {
	json_t *json = NULL;
	const json_t *j_server = NULL;
	const char *s_server = NULL;
	apr_hash_t *t_counters = apr_hash_make(r->pool);
	apr_hash_t *t_timings = apr_hash_make(r->pool);
	apr_hash_index_t *hi = NULL;
	const char *name = NULL;
	void *value = NULL;

	oidc_metric_prometheus_callback_ctx_t ctx = {"", r->pool};
	void *iter = NULL;

	/* parse the metrics string to JSON */
	json = oidc_metrics_json_parse_r(r, s_json);
	if (json == NULL)
		return OK;

	iter = json_object_iter(json);
	while (iter) {
		s_server = json_object_iter_key(iter);
		j_server = json_object_iter_value(iter);
		oidc_metrics_prometheus_convert(t_counters, s_server, json_object_get(j_server, OIDC_METRICS_COUNTERS));
		oidc_metrics_prometheus_convert(t_timings, s_server, json_object_get(j_server, OIDC_METRICS_TIMINGS));
		iter = json_object_iter_next(json, iter);
	}

	for (hi = apr_hash_first(r->pool, t_counters); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, (const void **)&name, NULL, &value);
		oidc_metrics_prometheus_counters(&ctx, name, value);
	}

	for (hi = apr_hash_first(r->pool, t_timings); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, (const void **)&name, NULL, &value);
		oidc_metrics_prometheus_timings(&ctx, name, value);
	}

	json_decref(json);

	return oidc_util_http_send(r, ctx.s_result, _oidc_strlen(ctx.s_result), OIDC_METRICS_PROMETHEUS_CONTENT_TYPE,
				   OK);
}

/*
 * definitions for handler callbacks
 */

typedef int (*oidc_metrics_handler_function_t)(request_rec *, const char *);

// holder for output function callback context
typedef struct oidc_metrics_handler_t {
	const char *format;
	oidc_metrics_handler_function_t callback;
	int reset;
} oidc_metrics_content_handler_t;

// output handlers
const oidc_metrics_content_handler_t _oidc_metrics_handlers[] = {
    // first is default
    {"prometheus", oidc_metrics_handle_prometheus, 0},
    {"json", oidc_metrics_handle_json, 1},
    {"internal", oidc_metrics_handle_internal, 0},
    {"status", oidc_metrics_handle_status, 0},
};

#define OIDC_CONTENT_HANDLER_MAX sizeof(_oidc_metrics_handlers) / sizeof(oidc_metrics_content_handler_t)

#define OIDC_METRICS_RESET_PARAM "reset"

/*
 * see if we are going to reset the cache after this
 */
static int oidc_metric_reset(request_rec *r, int dvalue) {
	char *s_reset = NULL;
	int value = 0;

	oidc_util_url_parameter_get(r, OIDC_METRICS_RESET_PARAM, &s_reset);

	if (s_reset == NULL)
		return dvalue;

	if (_oidc_strnatcasecmp(s_reset, "true") == 0)
		value = 1;
	else if (_oidc_strnatcasecmp(s_reset, "false") == 0)
		value = 0;

	return value;
}

#define OIDC_METRICS_FORMAT_PARAM "format"

/*
 * find the format handler
 */
const oidc_metrics_content_handler_t *oidc_metrics_find_handler(request_rec *r) {
	const oidc_metrics_content_handler_t *handler = NULL;
	char *s_format = NULL;

	/* get the specified format */
	oidc_util_url_parameter_get(r, OIDC_METRICS_FORMAT_PARAM, &s_format);

	if (s_format == NULL)
		return &_oidc_metrics_handlers[0];

	for (int i = 0; i < OIDC_CONTENT_HANDLER_MAX; i++) {
		if (_oidc_strcmp(s_format, _oidc_metrics_handlers[i].format) == 0) {
			handler = &_oidc_metrics_handlers[i];
			break;
		}
	}

	if (handler == NULL)
		oidc_warn(r, "could not find a metrics handler for format: %s", s_format);

	return handler;
}

/*
 * return the metrics to the caller and flush the storage
 */
int oidc_metrics_handle_request(request_rec *r) {
	const char *s_json = NULL;
	const oidc_metrics_content_handler_t *handler = NULL;

	/* get the content handler for the format */
	handler = oidc_metrics_find_handler(r);
	if (handler == NULL)
		return HTTP_NOT_FOUND;

	/* lock the global shared memory */
	oidc_cache_mutex_lock(r->pool, r->server, _oidc_metrics_global_mutex);

	/* retrieve the JSON formatted metrics as a string */
	s_json = _oidc_metrics_storage_get(r->server);

	/* now that the metrics have been consumed, clear the shared memory segment */
	if (oidc_metric_reset(r, handler->reset))
		oidc_metrics_storage_reset(r->server);

	/* unlock the global shared memory */
	oidc_cache_mutex_unlock(r->pool, r->server, _oidc_metrics_global_mutex);

	/* handle the specified format */
	return handler->callback(r, s_json);
}
