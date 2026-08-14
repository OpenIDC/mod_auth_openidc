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
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * JWKS retrieval, caching, and validation for OIDC metadata.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "cfg/dir.h"
#include "metadata/internal.h"

#include "cache/cache.h"
#include "http.h"
#include "metrics.h"
#include "proto/proto.h"
#include "util/util.h"

#include <apr_hash.h>
#include <apr_strings.h>

/*
 * get cache key for the JWKs file for a specified URI
 */
static const char *oidc_metadata_jwks_cache_key(const oidc_jwks_uri_t *jwks_uri) {
	return jwks_uri->signed_uri ? jwks_uri->signed_uri : jwks_uri->uri;
}

/* rate-limit forced (i.e. cache-bypassing) refreshes of a jwks_uri to one per this many seconds */
#define OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_DEFAULT 60

/* environment variable overriding that window, in seconds; 0 turns the rate limit off entirely */
#define OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_ENVVAR "OIDC_JWKS_FORCED_REFRESH_INTERVAL"

/* upper bound on the window: past an hour a genuine key rollover would go unnoticed for too long */
#define OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_MAX 3600

/* postfix distinguishing the forced-refresh marker from the JWKs document under the same key */
#define OIDC_METADATA_JWKS_FORCED_REFRESH_POSTFIX "#forced"

/*
 * Forced-refresh rate-limit window. OIDC_JWKS_FORCED_REFRESH_INTERVAL accepts 0-3600 seconds;
 * invalid values retain the safe default.
 */
static int oidc_metadata_jwks_forced_refresh_interval(request_rec *r) {
	int interval = 0;
	const char *s_interval =
	    (r->subprocess_env != NULL)
		? apr_table_get(r->subprocess_env, OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_ENVVAR)
		: NULL;

	if (s_interval == NULL)
		return OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_DEFAULT;

	if ((_oidc_str_to_int_checked(s_interval, &interval) == FALSE) || (interval < 0) ||
	    (interval > OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_MAX)) {
		oidc_warn(
		    r, "ignoring %s value \"%s\": must be an integer number of seconds between 0 and %d; using %d",
		    OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_ENVVAR, s_interval,
		    OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_MAX, OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_DEFAULT);
		return OIDC_METADATA_JWKS_FORCED_REFRESH_INTERVAL_DEFAULT;
	}

	return interval;
}

/* the shared-cache key recording that a forced refresh of this jwks_uri was recently attempted */
static const char *oidc_metadata_jwks_forced_refresh_key(request_rec *r, const oidc_jwks_uri_t *jwks_uri) {
	return apr_pstrcat(r->pool, oidc_metadata_jwks_cache_key(jwks_uri), OIDC_METADATA_JWKS_FORCED_REFRESH_POSTFIX,
			   NULL);
}

/*
 * Check whether this URI was forcibly refreshed within the rate-limit window. Unauthenticated
 * unknown-key requests must not each trigger an outbound fetch. This check has no side effects;
 * oidc_metadata_jwks_get() records the attempt.
 */
apr_byte_t oidc_metadata_jwks_forced_refresh_throttled(request_rec *r, const oidc_jwks_uri_t *jwks_uri) {
	char *value = NULL;
	/* a zero-length window disables the guard: never report a forced refresh as throttled, whatever
	 * marker an earlier request may have left in the cache */
	if (oidc_metadata_jwks_forced_refresh_interval(r) == 0)
		return FALSE;
	if (oidc_cache_get_jwks(r, oidc_metadata_jwks_forced_refresh_key(r, jwks_uri), &value) == FALSE) {
		/* Fail the throttle closed on cache errors to prevent unknown-key fetches during an outage. */
		oidc_warn(r, "cache lookup for the JWKs forced-refresh throttle failed; treating the forced refresh "
			     "as throttled");
		return TRUE;
	}
	return (value != NULL);
}

/* record a forced-refresh attempt so the next one within the window is rate-limited; stamped before
 * the fetch rather than after it, so a jwks_uri that is down or slow is not retried per request */
static apr_byte_t oidc_metadata_jwks_forced_refresh_stamp(request_rec *r, const oidc_jwks_uri_t *jwks_uri) {
	const int interval = oidc_metadata_jwks_forced_refresh_interval(r);
	/* with the guard disabled there is nothing to record: writing a marker that expires immediately
	 * would still put an entry in the shared cache on every forced refresh */
	if (interval == 0)
		return TRUE;
	return oidc_cache_set_jwks(r, oidc_metadata_jwks_forced_refresh_key(r, jwks_uri), "1",
				   apr_time_now() + apr_time_from_sec(interval));
}

/*
 * checks if a parsed JWKs file is a valid one, cq. contains "keys"
 */
static apr_byte_t oidc_metadata_jwks_is_valid(request_rec *r, const char *url, const oidc_json_t *j_jwks) {

	const oidc_json_t *keys = oidc_json_object_get(j_jwks, OIDC_METADATA_KEYS);
	if ((keys == NULL) || (!oidc_json_is_array(keys))) {
		oidc_error(
		    r, "JWKs JSON metadata obtained from URL \"%s\" did not contain a \"" OIDC_METADATA_KEYS "\" array",
		    url);
		return FALSE;
	}
	return TRUE;
}

/*
 * helper function to get the JWKs for the specified issuer
 */
static apr_byte_t oidc_metadata_jwks_retrieve_and_cache(request_rec *r, oidc_cfg_t *cfg,
							const oidc_jwks_uri_t *jwks_uri, int ssl_validate_server,
							oidc_json_t **j_jwks) {

	char *response = NULL;
	const char *url = (jwks_uri->signed_uri != NULL) ? jwks_uri->signed_uri : jwks_uri->uri;

	OIDC_METRICS_TIMING_START(r, cfg);

	/* get the JWKs from the specified URL with the specified parameters */
	if (oidc_http_get(r, url, NULL, NULL, NULL, NULL, ssl_validate_server, &response, NULL, NULL,
			  oidc_cfg_http_timeout_long_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
			  oidc_cfg_dir_pass_cookies_get(r), NULL, NULL, NULL) == FALSE) {
		OIDC_METRICS_COUNTER_INC(r, cfg, OM_PROVIDER_JWKS_ERROR);
		return FALSE;
	}

	OIDC_METRICS_TIMING_ADD(r, cfg, OM_PROVIDER_JWKS);

	if ((jwks_uri->signed_uri != NULL) && (jwks_uri->jwk_list != NULL)) {

		oidc_jwt_t *jwt = NULL;
		oidc_jose_error_t err;
		apr_hash_t *keys = apr_hash_make(r->pool);

		oidc_debug(r, "signed_jwks verifier keys count=%d", jwks_uri->jwk_list->nelts);
		for (int i = 0; i < jwks_uri->jwk_list->nelts; i++) {
			oidc_jwk_t *jwk = APR_ARRAY_IDX(jwks_uri->jwk_list, i, oidc_jwk_t *);
			if (jwk->kid != NULL) {
				oidc_debug(r, "signed_jwks verifier kid=%s", jwk->kid);
				apr_hash_set(keys, jwk->kid, APR_HASH_KEY_STRING, jwk);
			} else {
				const char *kid = apr_psprintf(r->pool, "%d", apr_hash_count(keys));
				oidc_debug(r, "signed_jwks verifier kid=%s", kid);
				apr_hash_set(keys, kid, APR_HASH_KEY_STRING, jwk);
			}
		}

		if (oidc_jwt_parse(r->pool, response, &jwt, keys, FALSE, &err) == FALSE) {
			oidc_error(r, "parsing JWT failed: %s", oidc_jose_e2s(r->pool, err));
			return FALSE;
		}

		oidc_debug(r, "successfully parsed JWT returned from \"signed_jwks_uri\" endpoint");

		if (oidc_jwt_verify(r->pool, jwt, keys, &err) == FALSE) {
			oidc_error(r, "verifying JWT failed: %s", oidc_jose_e2s(r->pool, err));
			oidc_jwt_destroy(jwt);
			return FALSE;
		}

		if (oidc_proto_jwt_validate(r, jwt, NULL, FALSE, FALSE, -1) == FALSE) {
			oidc_jwt_destroy(jwt);
			return FALSE;
		}

		oidc_debug(r, "successfully verified and validated JWKs JWT");

		response = jwt->payload.value.str;
		oidc_jwt_destroy(jwt);
	}

	/* decode and see if it is not an error response somehow */
	if (oidc_json_decode_and_check_error(r, response, j_jwks) == FALSE) {
		oidc_error(r, "JSON parsing of JWKs published at the jwks_uri failed");
		return FALSE;
	}

	/* check to see if it is a set of valid JWKs */
	if (oidc_metadata_jwks_is_valid(r, url, *j_jwks) == FALSE) {
		/* the decoded object is ours now; release it before bailing */
		oidc_json_decref(*j_jwks);
		*j_jwks = NULL;
		return FALSE;
	}

	/* store the JWKs in the cache */
	oidc_cache_set_jwks(r, oidc_metadata_jwks_cache_key(jwks_uri), response,
			    apr_time_now() + apr_time_from_sec(oidc_cfg_jwks_uri_refresh_interval_get(jwks_uri)));

	return TRUE;
}

/*
 * return JWKs for the specified issuer
 */
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg_t *cfg, const oidc_jwks_uri_t *jwks_uri,
				  int ssl_validate_server, oidc_json_t **j_jwks, apr_byte_t *refresh) {
	char *value = NULL;
	const char *url = jwks_uri->signed_uri ? jwks_uri->signed_uri : jwks_uri->uri;
	/* a forced refresh that was throttled, could not be stamped, or already fetched-and-failed: the
	 * fallback path below must not turn round and fetch again, which would defeat the rate limit */
	apr_byte_t forced_refresh_attempted = FALSE;

	oidc_debug(r, "enter, %sjwks_uri=%s, refresh=%d", jwks_uri->signed_uri ? "signed_" : "", url, *refresh);

	/* see if we need to do a forced refresh */
	if (*refresh == TRUE) {
		if (oidc_metadata_jwks_forced_refresh_throttled(r, jwks_uri) == TRUE) {
			forced_refresh_attempted = TRUE;
			oidc_debug(r,
				   "not refreshing the JWKs from URI \"%s\": a forced refresh was already "
				   "attempted less than %d seconds ago",
				   url, oidc_metadata_jwks_forced_refresh_interval(r));
			// fall back to any cached JWKs
		} else if (oidc_metadata_jwks_forced_refresh_stamp(r, jwks_uri) == FALSE) {
			forced_refresh_attempted = TRUE;
			oidc_warn(r, "not refreshing the JWKs from URI \"%s\": could not record the rate-limit marker",
				  url);
			// fall back to any cached JWKs
		} else {
			forced_refresh_attempted = TRUE;
			oidc_debug(r, "doing a forced refresh of the JWKs from URI \"%s\"", url);
			if (oidc_metadata_jwks_retrieve_and_cache(r, cfg, jwks_uri, ssl_validate_server, j_jwks) ==
			    TRUE)
				return TRUE;
			// else: fall back to any cached JWKs
		}
	}

	/* see if the JWKs is cached and decodes cleanly (a cached error response is treated as a miss) */
	if ((oidc_cache_get_jwks(r, oidc_metadata_jwks_cache_key(jwks_uri), &value) == TRUE) && (value != NULL) &&
	    (oidc_json_decode_and_check_error(r, value, j_jwks) == FALSE)) {
		oidc_warn(r, "JSON parsing of cached JWKs data failed");
		value = NULL;
	}

	if (value == NULL) {
		/* a forced refresh that was throttled or already failed must not fall through into another
		 * unguarded fetch. An ordinary initial cache miss (no forced refresh was requested) is not
		 * throttled and still fetches normally. */
		if (forced_refresh_attempted == TRUE)
			return FALSE;
		/* it is non-existing, invalid or expired: do a forced refresh */
		*refresh = TRUE;
		return oidc_metadata_jwks_retrieve_and_cache(r, cfg, jwks_uri, ssl_validate_server, j_jwks);
	}

	return TRUE;
}
