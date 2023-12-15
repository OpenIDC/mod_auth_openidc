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
 * Copyright (C) 2023 ZmartZone Holding BV
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

#include "mod_auth_openidc.h"
#include "metrics.h"
#include <limits.h>

#define OM_CLASS_AUTH_TYPE    "authtype"
#define OM_CLASS_AUTHN        "authn"
#define OM_CLASS_AUTHZ        "authz"
#define OM_CLASS_REQUESTS     "requests"
#define OM_CLASS_SESSION      "session"
#define OM_CLASS_CACHE        "cache"
#define OM_CLASS_CONTENT      "content"
#define OM_CLASS_REDIRECT_URI "redirect_uri"

const oidc_metrics_timing_info_t _oidc_metrics_timings_info[] = {

    { OM_AUTHN_REQUEST, OM_CLASS_AUTHN, "request",
        "authentication requests" },
    { OM_AUTHN_RESPONSE, OM_CLASS_AUTHN, "response",
	    "authentication responses" },
    { OM_SESSION_VALID, OM_CLASS_SESSION, "valid",
        "successfully validated existing sessions" },

    { OM_PROVIDER_METADATA, OM_CLASS_REQUESTS, "metadata",
        "provider discovery document requests" },
    { OM_PROVIDER_TOKEN, OM_CLASS_REQUESTS, "token",
        "provider token requests" },
    { OM_PROVIDER_REFRESH, OM_CLASS_REQUESTS, "refresh",
        "provider refresh token requests" },
    { OM_PROVIDER_USERINFO, OM_CLASS_REQUESTS, "userinfo",
        "provider userinfo requests" },

    { OM_CACHE_READ, OM_CLASS_CACHE, "read",
        "cache read requests" },
    { OM_CACHE_WRITE, OM_CLASS_CACHE, "write",
        "cache write requests" },

};

const oidc_metrics_counter_info_t _oidc_metrics_counters_info[] = {

    { OM_AUTHTYPE_OPENID_CONNECT, OM_CLASS_AUTH_TYPE, "handler", "openid-connect",
        "incoming requests" },
    { OM_AUTHTYPE_OAUTH20,        OM_CLASS_AUTH_TYPE, "handler", "oauth20",
        "incoming requests" },
    { OM_AUTHTYPE_AUTH_OPENIDC,   OM_CLASS_AUTH_TYPE, "handler", "auth-openidc",
        "incoming requests" },
    { OM_AUTHTYPE_DECLINED,       OM_CLASS_AUTH_TYPE, "handler", "declined",
        "incoming requests" },

	{ OM_AUTHN_REQUEST_ERROR_URL, OM_CLASS_AUTHN, "request.error", "url",
		"errors matching the incoming request URL against the configuration" },

    { OM_AUTHN_RESPONSE_ERROR_STATE_MISMATCH, OM_CLASS_AUTHN, "response.error", "state-mismatch",
        "state mismatch errors in authentication responses" },
    { OM_AUTHN_RESPONSE_ERROR_STATE_EXPIRED,  OM_CLASS_AUTHN, "response.error", "state-expired",
        "state expired errors in authentication responses" },
    { OM_AUTHN_RESPONSE_ERROR_PROVIDER,       OM_CLASS_AUTHN, "response.error", "provider",
        "errors returned by the provider in authentication responses" },
    { OM_AUTHN_RESPONSE_ERROR_PROTOCOL,       OM_CLASS_AUTHN, "response.error", "protocol",
        "errors handling authentication responses" },
    { OM_AUTHN_RESPONSE_ERROR_REMOTE_USER,    OM_CLASS_AUTHN, "response.error", "remote-user",
        "errors identifying the remote user based on provided claims" },

    { OM_AUTHZ_ERROR_GENERAL, OM_CLASS_AUTHZ, "error", "general",
        "authorization errors" },
    { OM_AUTHZ_ACTION_AUTH, OM_CLASS_AUTHZ, "action", "auth",
        "step-up authentication requests" },
	{ OM_AUTHZ_ACTION_401, OM_CLASS_AUTHZ, "action", "401",
        "401 authorization errors" },
	{ OM_AUTHZ_ACTION_403, OM_CLASS_AUTHZ, "action", "403",
        "403 authorization errors" },
    { OM_AUTHZ_ACTION_302, OM_CLASS_AUTHZ, "action", "302",
        "302 authorization errors" },
    { OM_AUTHZ_ERROR_OAUTH20, OM_CLASS_AUTHZ, "error", "oauth20",
        "AuthType oauth20 authorization errors 401" },

    { OM_PROVIDER_METADATA_ERROR, OM_CLASS_REQUESTS, "provider.metadata", "error"
        "errors retrieving provider discovery document" },
    { OM_PROVIDER_TOKEN_ERROR, OM_CLASS_REQUESTS, "provider.token", "error",
        "errors making a token request to the provider" },
    { OM_PROVIDER_REFRESH_ERROR, OM_CLASS_REQUESTS, "provider.refresh", "error",
        "errors refreshing the access token" },
    { OM_PROVIDER_USERINFO_ERROR, OM_CLASS_REQUESTS, "provider.userinfo", "error",
        "errors calling the provider userinfo endpoint" },

    { OM_SESSION_ERROR_COOKIE_DOMAIN,        OM_CLASS_SESSION, "error", "cookie-domain",
         "cookie domain validation errors for existing sessions" },
    { OM_SESSION_ERROR_EXPIRED,              OM_CLASS_SESSION, "error", "expired",
        "sessions that exceeded the maximum duration" },
    { OM_SESSION_ERROR_REFRESH_ACCESS_TOKEN, OM_CLASS_SESSION, "error", "refresh-access-token",
        "errors refreshing the access token before expiry in existing sessions" },
    { OM_SESSION_ERROR_REFRESH_USERINFO,     OM_CLASS_SESSION, "error", "refresh-user-info",
        "errors refreshing claims from the userinfo endpoint in existing sessions" },
    { OM_SESSION_ERROR_GENERAL,             OM_CLASS_SESSION, "error", "general",
        "existing sessions that failed validation" },

    { OM_CACHE_ERROR, OM_CLASS_CACHE, "cache", "error",
        "cache read/write errors" },

    { OM_REDIRECT_URI_AUTHN_RESPONSE_REDIRECT, OM_CLASS_REDIRECT_URI, "authn.response", "redirect",
        "authentication responses received in a redirect", },
    { OM_REDIRECT_URI_AUTHN_RESPONSE_POST,     OM_CLASS_REDIRECT_URI, "authn.response", "post",
        "authentication responses received in a HTTP POST", },
    { OM_REDIRECT_URI_AUTHN_RESPONSE_IMPLICIT, OM_CLASS_REDIRECT_URI, "authn.response", "implicit",
        "(presumed) implicit authentication responses to the redirect URI", },
    { OM_REDIRECT_URI_DISCOVERY_RESPONSE,      OM_CLASS_REDIRECT_URI, "discovery", "response",
        "discovery responses to the redirect URI", },
    { OM_REDIRECT_URI_REQUEST_LOGOUT,          OM_CLASS_REDIRECT_URI, "request", "logout",
        "logout requests to the redirect URI", },
    { OM_REDIRECT_URI_REQUEST_JWKS,            OM_CLASS_REDIRECT_URI, "request", "jwks",
        "JWKs retrieval requests to the redirect URI", },
    { OM_REDIRECT_URI_REQUEST_SESSION,         OM_CLASS_REDIRECT_URI, "request", "session",
        "session management requests to the redirect URI", },
    { OM_REDIRECT_URI_REQUEST_REFRESH,         OM_CLASS_REDIRECT_URI, "request", "refresh",
        "refresh access token requests to the redirect URI", },
    { OM_REDIRECT_URI_REQUEST_REQUEST_URI,     OM_CLASS_REDIRECT_URI, "request", "request_uri",
        "Request URI calls to the redirect URI", },
    { OM_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE, OM_CLASS_REDIRECT_URI, "request", "remove_at_cache",
        "access token cache removal requests to the redirect URI", },
    { OM_REDIRECT_URI_REQUEST_REVOKE_SESSION,  OM_CLASS_REDIRECT_URI, "request", "session",
        "revoke session requests to the redirect URI", },
    { OM_REDIRECT_URI_REQUEST_INFO,            OM_CLASS_REDIRECT_URI, "request", "info",
        "info hook requests to the redirect URI", },
    { OM_REDIRECT_URI_ERROR_PROVIDER,          OM_CLASS_REDIRECT_URI, "error", "provider",
        "provider authentication response errors received at the redirect URI", },
    { OM_REDIRECT_URI_ERROR_INVALID,           OM_CLASS_REDIRECT_URI, "error", "invalid",
        "invalid requests to the redirect URI", },

    { OM_CONTENT_REQUEST_DECLINED,      OM_CLASS_CONTENT, "request", "declined",
        "requests declined by the content handler" },
    { OM_CONTENT_REQUEST_INFO,          OM_CLASS_CONTENT, "request", "info",
        "info hook requests to the content handler" },
    { OM_CONTENT_REQUEST_JWKS,          OM_CLASS_CONTENT, "request", "jwks",
        "JWKs requests to the content handler" },
    { OM_CONTENT_REQUEST_DISCOVERY,     OM_CLASS_CONTENT, "request", "discovery",
        "discovery requests to the content handler" },
    { OM_CONTENT_REQUEST_POST_PRESERVE, OM_CLASS_CONTENT, "request", "post-preserve",
        "HTTP POST preservation requests to the content handler" },
    { OM_CONTENT_REQUEST_UNKNOWN,       OM_CLASS_CONTENT, "request", "unknown",
        "unknown requests to the content handler" },

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
// flag to signal the metrics write thread to exit
static apr_byte_t _oidc_metrics_thread_exit = FALSE;
// mutex to protect the shared memory storage
static oidc_cache_mutex_t *_oidc_metrics_global_mutex = NULL;
// pointer to the thread that periodically writes the locally gathered metrics to shared memory
static apr_thread_t *_oidc_metrics_thread = NULL;
// local in-memory cached metrics
static oidc_metrics_t _oidc_metrics = {NULL, NULL};
// mutex to protect the local metrics hash table
static oidc_cache_mutex_t *_oidc_metrics_process_mutex = NULL;

// shared memory write interval in seconds
#define OIDC_CACHE_METRICS_STORAGE_INTERVAL 5

// maximum length of the string representation of the global JSON metrics data in shared memory
//   1024 sample size (compact, long keys, large json_int values, no description), timing + counter
//   256 number of individual metrics collected
//     4 number of vhosts supported
#define OIDC_CACHE_METRICS_JSON_MAX 1024 * 256 * 4

typedef struct oidc_metrics_bucket_t {
	const char *name;
	const char *label;
	apr_time_t threshold;
} oidc_metrics_bucket_t;

// clang-format off

static oidc_metrics_bucket_t _oidc_metric_buckets[] = {
	//{ "le005", "bucket{le=\"0.05\"}", 50 },
	{ "le01", "bucket{le=\"0.1\"}", 100 },
	{ "le05", "bucket{le=\"0.5\"}", 500 },
	{ "le1", "bucket{le=\"1\"}", apr_time_from_msec(1) },
	{ "le5", "bucket{le=\"5\"}", apr_time_from_msec(5) },
	{ "le10", "bucket{le=\"10\"}", apr_time_from_msec(10) },
	{ "le50", "bucket{le=\"50\"}", apr_time_from_msec(50) },
	{ "le100", "bucket{le=\"100\"}",  apr_time_from_msec(100) },
	{ "le500", "bucket{le=\"500\"}",  apr_time_from_msec(500) },
	{ "le1000", "bucket{le=\"1000\"}", apr_time_from_msec(1000) },
    { "le5000", "bucket{le=\"5000\"}", apr_time_from_msec(5000) },
    { "inf", "bucket{le=\"+Inf\"}", 0 }
};

#define OIDC_METRICS_BUCKET_NUM sizeof(_oidc_metric_buckets) / sizeof(oidc_metrics_bucket_t)

// clang-format on

// NB: shared between JSON and Prometheus formatting
#define OIDC_METRICS_SUM "sum"
#define OIDC_METRICS_COUNT "count"

#define OIDC_METRICS_TYPE "type"

#define OIDC_METRICS_NAME "name"
#define OIDC_METRICS_LABEL_NAME "lname"
#define OIDC_METRICS_LABEL_VALUE "lvalue"
#define OIDC_METRICS_DESC "desc"

#define OIDC_METRICS_TIMINGS "timings"
#define OIDC_METRICS_COUNTERS "counters"

// single counter container
typedef struct oidc_metrics_counter_t {
	oidc_metrics_counter_type_t type;
	json_int_t count;
} oidc_metrics_counter_t;

// single timing stats container
typedef struct oidc_metrics_timing_t {
	oidc_metrics_timing_type_t type;
	json_int_t *buckets;
	apr_time_t sum;
	json_int_t count;
} oidc_metrics_timing_t;

/*
 * retrieve the (JSON) serialized (global) metrics data from shared memory
 */
static void oidc_metrics_storage_get(server_rec *s, char **value) {
	char *p = apr_shm_baseaddr_get(_oidc_metrics_cache);
	if (*p)
		*value = apr_pstrdup(s->process->pool, p);
}

/*
 * store the serialized (global) metrics data in shared memory
 */
static void oidc_metrics_storage_set(server_rec *s, const char *value) {
	char *p = apr_shm_baseaddr_get(_oidc_metrics_cache);
	if (value) {
		int n = strlen(value) + 1;
		if (n > OIDC_CACHE_METRICS_JSON_MAX)
			oidc_serror(s, "json value too large");
		else
			_oidc_memcpy(p, value, n);
	} else {
		*p = 0;
	}
}

/*
 * create a new timings entry in the collected JSON data
 */
static json_t *oidc_metrics_timings_new(server_rec *s, const oidc_metrics_timing_t *timing) {
	int i = 0;
	json_t *entry = json_object();
	json_object_set_new(entry, OIDC_METRICS_TYPE, json_integer(timing->type));
	for (i = 0; i < OIDC_METRICS_BUCKET_NUM; i++)
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
	int i = 0;

	for (i = 0; i < OIDC_METRICS_BUCKET_NUM; i++) {
		j_member = json_object_get(entry, _oidc_metric_buckets[i].name);
		json_integer_set(j_member, json_integer_value(j_member) + timing->buckets[i]);
	}

	j_member = json_object_get(entry, OIDC_METRICS_SUM);
	n = json_integer_value(j_member);
	// check Jansson specific integer/long overrun
	if ((LONG_MAX - apr_time_as_msec(timing->sum)) < n) {
		oidc_serror(s,
			    "cannot update metrics since the size (%ld"
			    ") of the integer value would be larger than the JSON/libjansson maximum "
			    "(%ld)",
			    (long int)n, LONG_MAX);
		return;
	}
	json_integer_set(j_member, n + apr_time_as_msec(timing->sum));

	j_member = json_object_get(entry, OIDC_METRICS_COUNT);
	n = json_integer_value(j_member);
	json_integer_set(j_member, n + timing->count);
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
 * flush the locally gathered metrics data into the global data kept in shared memory
 */
static void oidc_metrics_store(server_rec *s) {
	char *s_json = NULL;
	json_t *json = NULL, *j_server = NULL, *j_value = NULL, *j_counters = NULL, *j_timings = NULL, *j_member = NULL;
	apr_hash_index_t *hi1 = NULL, *hi2 = NULL;
	const char *name = NULL, *key = NULL;
	apr_hash_t *server_hash = NULL;
	oidc_metrics_timing_t *timing = NULL;
	oidc_metrics_counter_t *counter = NULL;
	json_error_t json_error;

	/* lock the shared memory for other processes */
	oidc_cache_mutex_lock(s->process->pool, s, _oidc_metrics_global_mutex);

	/* get the global stringified JSON metrics */
	oidc_metrics_storage_get(s, &s_json);

	/* parse the metrics string to JSON */
	if (s_json != NULL)
		json = json_loads(s_json, 0, &json_error);
	if (json == NULL)
		json = json_object();

	for (hi1 = apr_hash_first(s->process->pool, _oidc_metrics.counters); hi1; hi1 = apr_hash_next(hi1)) {
		apr_hash_this(hi1, (const void **)&name, NULL, (void **)&server_hash);

		j_server = oidc_metrics_server_get(json, name);
		j_counters = json_object_get(j_server, OIDC_METRICS_COUNTERS);

		/* loop over the individual metrics */
		for (hi2 = apr_hash_first(s->process->pool, server_hash); hi2; hi2 = apr_hash_next(hi2)) {
			apr_hash_this(hi2, (const void **)&key, NULL, (void **)&counter);

			/* get or create the corresponding metric entry in the global metrics */
			j_value = json_object_get(j_counters, key);
			if (j_value != NULL) {
				j_member = json_object_get(j_value, OIDC_METRICS_COUNT);
				json_integer_set(j_member, json_integer_value(j_member) + counter->count);
			} else {
				j_member = json_object();
				json_object_set_new(j_member, OIDC_METRICS_COUNT, json_integer(counter->count));
				json_object_set_new(j_member, OIDC_METRICS_TYPE, json_integer(counter->type));
				json_object_set_new(j_counters, key, j_member);
			}
		}
	}

	/* loop over the locally cached metrics from this process */
	for (hi1 = apr_hash_first(s->process->pool, _oidc_metrics.timings); hi1; hi1 = apr_hash_next(hi1)) {
		apr_hash_this(hi1, (const void **)&name, NULL, (void **)&server_hash);

		j_server = oidc_metrics_server_get(json, name);
		j_timings = json_object_get(j_server, OIDC_METRICS_TIMINGS);

		/* loop over the individual metrics */
		for (hi2 = apr_hash_first(s->process->pool, server_hash); hi2; hi2 = apr_hash_next(hi2)) {
			apr_hash_this(hi2, (const void **)&key, NULL, (void **)&timing);

			/* get or create the corresponding metric entry in the global metrics */
			j_value = json_object_get(j_timings, key);
			if (j_value != NULL)
				oidc_metrics_timings_update(s, j_value, timing);
			else
				json_object_set_new(j_timings, key, oidc_metrics_timings_new(s, timing));
		}
	}

	/* serialize the metrics data, preserve order is required for Prometheus */
	char *str = json_dumps(json, JSON_COMPACT | JSON_PRESERVE_ORDER);
	s_json = apr_pstrdup(s->process->pool, str);
	free(str);

	/* free the JSON data */
	json_decref(json);

	/* store the serialized metrics data in shared memory */
	oidc_metrics_storage_set(s, s_json);

	/* unlock the shared memory for other processes */
	oidc_cache_mutex_unlock(s->process->pool, s, _oidc_metrics_global_mutex);
}

/*
 * thread that periodically writes the local data into the shared memory
 */
static void *oidc_metrics_thread_run(apr_thread_t *thread, void *data) {
	server_rec *s = (server_rec *)data;

	/* see if we are asked to exit */
	while (_oidc_metrics_thread_exit == FALSE) {

		apr_sleep(apr_time_from_sec(OIDC_CACHE_METRICS_STORAGE_INTERVAL));
		// NB: no exit here because we need to write our local metrics into the cache before exiting

		/* lock the mutex that protects the locally cached metrics */
		oidc_cache_mutex_lock(s->process->pool, s, _oidc_metrics_process_mutex);

		/* flush the locally cached metrics into the global shared memory */
		oidc_metrics_store(s);

		/* reset the local hashtables */
		apr_hash_clear(_oidc_metrics.counters);
		apr_hash_clear(_oidc_metrics.timings);

		/* unlock the mutex that protects the locally cached metrics */
		oidc_cache_mutex_unlock(s->process->pool, s, _oidc_metrics_process_mutex);
	}

	apr_thread_exit(thread, APR_SUCCESS);

	return NULL;
}

/*
 * NB: global, yet called for each vhost that has metrics enabled!
 */
apr_byte_t oidc_metrics_cache_post_config(server_rec *s) {

	/* make sure it gets executed exactly once! */
	if (_oidc_metrics_cache != NULL)
		return TRUE;

	/* create the shared memory segment that holds the stringified JSON formatted metrics data */
	if (apr_shm_create(&_oidc_metrics_cache, OIDC_CACHE_METRICS_JSON_MAX, NULL, s->process->pconf) != APR_SUCCESS)
		return FALSE;
	if (_oidc_metrics_cache == NULL)
		return FALSE;

	/* initialize the shared memory segment to 0 */
	char *p = apr_shm_baseaddr_get(_oidc_metrics_cache);
	*p = 0;

	/* flag this as the parent, for shared memory cleanup purposes and "multiple child-init calls" detection */
	_oidc_metrics_is_parent = TRUE;

	/* create the thread that will periodically flush the local metrics data to shared memory */
	if (apr_thread_create(&_oidc_metrics_thread, NULL, oidc_metrics_thread_run, s, s->process->pool) != APR_SUCCESS)
		return FALSE;

	/* create the hashtable that holds local metrics data */
	_oidc_metrics.counters = apr_hash_make(s->process->pool);
	_oidc_metrics.timings = apr_hash_make(s->process->pool);

	/* create and initialize the mutex that guards _oidc_metrics_hash */
	_oidc_metrics_global_mutex = oidc_cache_mutex_create(s->process->pool, TRUE);
	if (_oidc_metrics_global_mutex == NULL)
		return FALSE;
	if (oidc_cache_mutex_post_config(s, _oidc_metrics_global_mutex, "metrics-global") == FALSE)
		return FALSE;

	/* create and initialize the mutex that guards the shared memory */
	_oidc_metrics_process_mutex = oidc_cache_mutex_create(s->process->pool, FALSE);
	if (_oidc_metrics_process_mutex == NULL)
		return FALSE;
	if (oidc_cache_mutex_post_config(s, _oidc_metrics_process_mutex, "metrics-process") == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * NB: global, yet called for each vhost that has metrics enabled!
 */
apr_status_t oidc_metrics_cache_child_init(apr_pool_t *p, server_rec *s) {

	/* make sure this executes only once per child */
	if (_oidc_metrics_is_parent == FALSE)
		return APR_SUCCESS;

	if (oidc_cache_mutex_child_init(p, s, _oidc_metrics_global_mutex) != APR_SUCCESS)
		return APR_EGENERAL;

	if (oidc_cache_mutex_child_init(p, s, _oidc_metrics_process_mutex) != APR_SUCCESS)
		return APR_EGENERAL;

	/* the metrics flush thread is not inherited from the parent, so re-create it in the child */
	if (apr_thread_create(&_oidc_metrics_thread, NULL, oidc_metrics_thread_run, s, s->process->pool) != APR_SUCCESS)
		return APR_EGENERAL;

	/* flag this is a child */
	_oidc_metrics_is_parent = FALSE;

	return APR_SUCCESS;
}

/*
 * NB: global, yet called for each vhost that has metrics enabled!
 */
apr_status_t oidc_metrics_cache_cleanup(server_rec *s) {

	/* make sure it gets executed exactly once! */
	if (_oidc_metrics_cache == NULL)
		return APR_SUCCESS;

	/* signal the collector thread to exit and wait (at max 5 seconds) for it to flush its data and exit */
	_oidc_metrics_thread_exit = TRUE;
	apr_status_t rv = APR_SUCCESS;
	apr_thread_join(&rv, _oidc_metrics_thread);
	if (rv != APR_SUCCESS)
		return rv;

	/* delete the shared memory segment if we are in the parent process */
	if (_oidc_metrics_is_parent == TRUE)
		apr_shm_destroy(_oidc_metrics_cache);
	_oidc_metrics_cache = NULL;

	/* delete the process mutex that guards the local metrics data */
	if (oidc_cache_mutex_destroy(s, _oidc_metrics_process_mutex) == FALSE)
		return APR_EGENERAL;

	/* delete the process mutex that guards the global shared memory segment */
	if (oidc_cache_mutex_destroy(s, _oidc_metrics_global_mutex) == FALSE)
		return APR_EGENERAL;

	return rv;
}

/*
 * obtain the local metrics hashtable for the current vhost
 */
static apr_hash_t *oidc_metrics_server_hash(request_rec *r, apr_hash_t *table) {
	apr_hash_t *server_hash = NULL;
	char *name = "_default_";

	/* obtain the vhost name */
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
 * retrieve or create a local hashtable for the specified key
 * NB: assumes local hashtable has been locked
 */
static void *oidc_metrics_get(request_rec *r, const char *key, apr_hash_t *table, size_t size) {
	void *result = NULL;
	apr_hash_t *server_hash = oidc_metrics_server_hash(r, table);

	/* get the entry to the specified metric */
	result = apr_hash_get(server_hash, key, APR_HASH_KEY_STRING);
	if (result == NULL) {
		/* newly create it with the passed value */
		result = apr_pcalloc(r->server->process->pool, size);
		// NB: allocate the key in the process pool
		apr_hash_set(server_hash, apr_pstrdup(r->server->process->pool, key), APR_HASH_KEY_STRING, result);
	}

	return result;
}

/*
 * add/increase a counter metric in the locally cached data
 */
void oidc_metrics_counter_inc(request_rec *r, oidc_metrics_counter_type_t type) {
	oidc_metrics_counter_t *counter = NULL;
	char *key = NULL;

	/* lock the local metrics cache hashtable */
	oidc_cache_mutex_lock(r->pool, r->server, _oidc_metrics_process_mutex);

	/* obtain or create the entry for the specified key */
	key = apr_psprintf(r->server->process->pool, "%s", _oidc_metrics_counters_info[type].name);
	if ((_oidc_metrics_counters_info[type].label_name) &&
	    (_oidc_strcmp(_oidc_metrics_counters_info[type].label_name, "") != 0)) {
		key =
		    apr_psprintf(r->server->process->pool, "%s.%s", key, _oidc_metrics_counters_info[type].label_name);
		if ((_oidc_metrics_counters_info[type].label_value) &&
		    (_oidc_strcmp(_oidc_metrics_counters_info[type].label_value, "") != 0)) {
			key = apr_psprintf(r->server->process->pool, "%s.%s", key,
					   _oidc_metrics_counters_info[type].label_value);
		}
	}

	counter =
	    (oidc_metrics_counter_t *)oidc_metrics_get(r, key, _oidc_metrics.counters, sizeof(oidc_metrics_counter_t));
	counter->type = type;
	counter->count++;

	/* unlock the local metrics cache hashtable */
	oidc_cache_mutex_unlock(r->pool, r->server, _oidc_metrics_process_mutex);
}

/*
 * add a metrics timing sample to the locally cached data
 */
void oidc_metrics_timing_add(request_rec *r, oidc_metrics_timing_type_t type, apr_time_t elapsed) {
	oidc_metrics_timing_t *timing = NULL;
	int i = 0;

	const char *key = apr_psprintf(r->pool, "%s.%s", _oidc_metrics_timings_info[type].name,
				       _oidc_metrics_timings_info[type].subkey);

	/* TODO: how can this happen? */
	if (elapsed < 0) {
		oidc_warn(r, "discarding metrics timing %s: elapsed (%" APR_TIME_T_FMT ") < 0", key, elapsed);
		return;
	}

	/* lock the local metrics cache hashtable */
	oidc_cache_mutex_lock(r->pool, r->server, _oidc_metrics_process_mutex);

	/* obtain or create the entry for the specified key */
	timing = oidc_metrics_get(r, key, _oidc_metrics.timings, sizeof(oidc_metrics_timing_t));
	if (timing->buckets == NULL)
		timing->buckets = apr_pcalloc(r->server->process->pool, sizeof(json_int_t) * OIDC_METRICS_BUCKET_NUM);
	timing->type = type;
	for (i = 0; i < OIDC_METRICS_BUCKET_NUM; i++)
		if ((elapsed < _oidc_metric_buckets[i].threshold) || (_oidc_metric_buckets[i].threshold == 0))
			timing->buckets[i]++;
	timing->sum += elapsed;
	timing->count++;

	/* unlock the local metrics cache hashtable */
	oidc_cache_mutex_unlock(r->pool, r->server, _oidc_metrics_process_mutex);
}

static int oidc_metrics_handle_json(request_rec *r, char *s_json) {

	json_t *json = NULL, *j_server = NULL, *j_timings, *j_counters, *j_timing = NULL, *j_counter = NULL;
	const char *s_server = NULL, *s_key = NULL;
	json_int_t type = 0;
	json_error_t json_error;

	/* parse the metrics string to JSON */
	if (s_json != NULL)
		json = json_loads(s_json, 0, &json_error);
	if (json == NULL)
		return HTTP_NOT_FOUND;

	void *iter1 = json_object_iter(json);
	while (iter1) {
		s_server = json_object_iter_key(iter1);
		j_server = json_object_iter_value(iter1);

		j_counters = json_object_get(j_server, OIDC_METRICS_COUNTERS);

		void *iter2 = json_object_iter(j_counters);
		while (iter2) {
			s_key = json_object_iter_key(iter2);
			j_counter = json_object_iter_value(iter2);

			type = json_integer_value(json_object_get(j_counter, OIDC_METRICS_TYPE));
			json_object_del(j_counter, OIDC_METRICS_TYPE);

			json_object_set_new(j_counter, OIDC_METRICS_NAME,
					    json_string(_oidc_metrics_counters_info[type].name));
			json_object_set_new(j_counter, OIDC_METRICS_LABEL_NAME,
					    json_string(_oidc_metrics_counters_info[type].label_name));
			json_object_set_new(j_counter, OIDC_METRICS_LABEL_VALUE,
					    json_string(_oidc_metrics_counters_info[type].label_value));
			json_object_set_new(j_counter, OIDC_METRICS_DESC,
					    json_string(_oidc_metrics_counters_info[type].desc));

			iter2 = json_object_iter_next(j_counters, iter2);
		}

		j_timings = json_object_get(j_server, OIDC_METRICS_TIMINGS);

		iter2 = json_object_iter(j_timings);
		while (iter2) {
			s_key = json_object_iter_key(iter2);
			j_timing = json_object_iter_value(iter2);

			type = json_integer_value(json_object_get(j_timing, OIDC_METRICS_TYPE));
			json_object_del(j_timing, OIDC_METRICS_TYPE);

			json_object_set_new(j_timing, OIDC_METRICS_DESC,
					    json_string(_oidc_metrics_timings_info[type].desc));

			iter2 = json_object_iter_next(j_timings, iter2);
		}
		iter1 = json_object_iter_next(json, iter1);
	}

	if (json) {
		char *str = json_dumps(json, JSON_COMPACT | JSON_PRESERVE_ORDER);
		s_json = apr_pstrdup(r->pool, str);
		free(str);
		json_decref(json);
	} else {
		s_json = "{}";
	}

	/* return the data to the caller */
	return oidc_util_http_send(r, s_json, _oidc_strlen(s_json), OIDC_CONTENT_TYPE_JSON, OK);
}

static const char *oidc_metrics_name_to_label(request_rec *r, const char *json_name) {
	const char *name = json_name;
	int i = 0;
	for (i = 0; i < OIDC_METRICS_BUCKET_NUM; i++) {
		if (_oidc_strcmp(_oidc_metric_buckets[i].name, json_name) == 0) {
			name = _oidc_metric_buckets[i].label;
			break;
		}
	}
	return name;
}

static const char *oidc_prometheus_normalize(request_rec *r, const char *v1, const char *v2) {
	char *label = apr_psprintf(r->pool, "%s%s%s", v1 ? v1 : "", v2 ? "_" : "", v2 ? v2 : "");
	int i = 0;
	for (i = 0; i < strlen(label); i++)
		if ((label[i] == '-') || (label[i] == '.'))
			label[i] = '_';
	return label;
}

static int oidc_metrics_handle_prometheus(request_rec *r, const char *s_json) {
	json_t *json = NULL, *j_server = NULL, *j_timings, *j_counters, *j_timing = NULL, *j_member = NULL,
	       *j_counter = NULL;
	const char *s_server = NULL, *s_key = NULL, *s_label = NULL, *s_bucket = NULL;
	char *s_text = "";
	json_error_t json_error;
	json_int_t type = 0;

	/* parse the metrics string to JSON */
	if (s_json != NULL)
		json = json_loads(s_json, 0, &json_error);
	if (json == NULL)
		return OK;

	void *iter1 = json_object_iter(json);
	while (iter1) {
		s_server = json_object_iter_key(iter1);
		j_server = json_object_iter_value(iter1);

		j_counters = json_object_get(j_server, OIDC_METRICS_COUNTERS);

		void *iter2 = json_object_iter(j_counters);
		while (iter2) {
			s_key = json_object_iter_key(iter2);
			j_counter = json_object_iter_value(iter2);

			type = json_integer_value(json_object_get(j_counter, OIDC_METRICS_TYPE));
			s_label = oidc_prometheus_normalize(r, s_server, s_key);
			s_text = apr_psprintf(r->pool, "%s# HELP %s The number of %s.\n", s_text, s_label,
					      _oidc_metrics_counters_info[type].desc);
			s_text = apr_psprintf(r->pool, "%s# TYPE %s counter\n", s_text, s_label);
			s_text = apr_psprintf(
			    r->pool, "%s%s", s_text,
			    oidc_prometheus_normalize(r, s_server, _oidc_metrics_counters_info[type].name));
			if (_oidc_metrics_counters_info[type].label_name) {
				s_text = apr_psprintf(
				    r->pool, "%s{%s=\"%s\"}", s_text,
				    oidc_prometheus_normalize(r, _oidc_metrics_counters_info[type].label_name, NULL),
				    _oidc_metrics_counters_info[type].label_value);
			}
			j_member = json_object_get(j_counter, OIDC_METRICS_COUNT);
			s_text = apr_psprintf(r->pool, "%s %ld\n", s_text, (long int)json_integer_value(j_member));
			s_text = apr_psprintf(r->pool, "%s\n", s_text);

			iter2 = json_object_iter_next(j_counters, iter2);
		}

		j_timings = json_object_get(j_server, OIDC_METRICS_TIMINGS);

		iter2 = json_object_iter(j_timings);
		while (iter2) {
			s_key = json_object_iter_key(iter2);
			j_timing = json_object_iter_value(iter2);

			type = json_integer_value(json_object_get(j_timing, OIDC_METRICS_TYPE));
			json_object_del(j_timing, OIDC_METRICS_TYPE);

			s_label = oidc_prometheus_normalize(r, s_server, s_key);
			s_text = apr_psprintf(r->pool, "%s# HELP %s A histogram of %s.\n", s_text, s_label,
					      _oidc_metrics_timings_info[type].desc);
			s_text = apr_psprintf(r->pool, "%s# TYPE %s histogram\n", s_text, s_label);

			void *iter3 = json_object_iter(j_timing);
			while (iter3) {
				s_bucket = json_object_iter_key(iter3);
				j_member = json_object_iter_value(iter3);
				s_text = apr_psprintf(r->pool, "%s%s_%s %ld\n", s_text, s_label,
						      oidc_metrics_name_to_label(r, s_bucket),
						      (long int)json_integer_value(j_member));
				iter3 = json_object_iter_next(j_timing, iter3);
			}
			s_text = apr_psprintf(r->pool, "%s\n", s_text);

			iter2 = json_object_iter_next(j_timings, iter2);
		}
		iter1 = json_object_iter_next(json, iter1);

		s_text = apr_psprintf(r->pool, "%s\n\n", s_text);
	}

	json_decref(json);

	return oidc_util_http_send(r, s_text, _oidc_strlen(s_text), "text/plain; version=0.0.4", OK);
}

#define OIDC_METRICS_FORMAT_PARAM "format"
#define OIDC_METRICS_FORMAT_JSON "json"
#define OIDC_METRICS_FORMAT_PROMETHEUS "prometheus"

/*
 * return the metrics to the caller and flush the storage
 */
int oidc_metrics_handle_request(request_rec *r) {
	char *s_format = NULL;
	char *s_json = NULL;
	char *s_content_type = NULL;

	/* lock the global shared memory */
	oidc_cache_mutex_lock(r->pool, r->server, _oidc_metrics_global_mutex);

	/* retrieve the JSON formatted metrics as a string */
	oidc_metrics_storage_get(r->server, &s_json);

	/* now that the metrics have been consumed, clear the shared memory segment */
	oidc_metrics_storage_set(r->server, NULL);

	/* unlock the global shared memory */
	oidc_cache_mutex_unlock(r->pool, r->server, _oidc_metrics_global_mutex);

	/* handle specified format */
	oidc_util_get_request_parameter(r, OIDC_METRICS_FORMAT_PARAM, &s_format);
	if (_oidc_strcmp(s_format, OIDC_METRICS_FORMAT_JSON) == 0)
		return oidc_metrics_handle_json(r, s_json);

	return oidc_metrics_handle_prometheus(r, s_json);
}
