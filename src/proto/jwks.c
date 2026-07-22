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

#include "metadata.h"
#include "proto/proto.h"
#include "util/util.h"

#include "util/cache_local.h"

/*
 * process-lifetime cache of JWKs selection results: maps (jwks-uri, kid, x5t, kty) to the list
 * of parsed keys that selection produced, so repeated validations against the same signing key
 * skip the per-request JSON decode of the JWKs document and the (expensive, bignum-parsing)
 * cjose key imports; entries expire in lockstep with the JWKs refresh interval and the whole
 * cache is purged on a forced refresh (suspected key rollover), preserving today's rotation
 * behavior; the cached cjose keys are refcounted so request-held copies survive a purge
 */
typedef struct oidc_proto_jwks_cache_entry_t {
	apr_time_t expires;
	apr_array_header_t *jwks;
} oidc_proto_jwks_cache_entry_t;

static oidc_cache_local_t *_oidc_proto_jwks_cache = NULL;
/* keys retired by a purge/replace: in-flight requests may still be using them, and the backend
 * refcount is not atomic, so they are only released at pool cleanup (bounded by key rollovers) */
static apr_array_header_t *_oidc_proto_jwks_cache_retired = NULL;

/* bounds the cache; reached only with many providers/kids, then the cache is simply reset */
#define OIDC_PROTO_JWKS_CACHE_MAX_ENTRIES 64

/* eviction: do not free the keys (in-flight requests plus the non-atomic backend refcount forbid
 * it) - retire them for release at pool cleanup; the entry itself lives in the cache pool */
static void oidc_proto_jwks_cache_free(void *value) {
	oidc_proto_jwks_cache_entry_t *entry = value;
	for (int i = 0; i < entry->jwks->nelts; i++)
		APR_ARRAY_PUSH(_oidc_proto_jwks_cache_retired, oidc_jwk_t *) =
		    APR_ARRAY_IDX(entry->jwks, i, oidc_jwk_t *);
}

/* freshness: a cached selection result is valid until its refresh-interval expiry */
static int oidc_proto_jwks_cache_valid(void *value, const void *ctx) {
	return ((const oidc_proto_jwks_cache_entry_t *)value)->expires > apr_time_now();
}

struct oidc_proto_jwks_cache_use_ctx {
	request_rec *r;
	const char *x5t;
	apr_hash_t *result;
};

/* under the read lock: hand out the cache-owned (shared, refcount-stable) keys into the result hash,
 * re-keyed the way selection does - by kid, x5t or a unique counter; the read path performs no
 * refcount mutation and the per-request key-list destruction leaves the shared keys alone */
static void oidc_proto_jwks_cache_use(void *value, void *baton) {
	const oidc_proto_jwks_cache_entry_t *entry = value;
	const struct oidc_proto_jwks_cache_use_ctx *ctx = baton;
	for (int i = 0; i < entry->jwks->nelts; i++) {
		const oidc_jwk_t *jwk = APR_ARRAY_IDX(entry->jwks, i, oidc_jwk_t *);
		const char *hkey = jwk->kid;
		if (hkey == NULL)
			hkey = (ctx->x5t != NULL) ? ctx->x5t
						  : apr_psprintf(ctx->r->pool, "%d", apr_hash_count(ctx->result));
		apr_hash_set(ctx->result, hkey, APR_HASH_KEY_STRING, jwk);
	}
}

struct oidc_proto_jwks_cache_build_ctx {
	apr_hash_t *result;
	int refresh_interval;
};

/* under the write lock: build an entry holding shared copies of the selected keys (the copy retains
 * the backend key of the still request-private source and is marked shared so no request context
 * ever mutates its refcount) stamped with the refresh-interval expiry */
static void *oidc_proto_jwks_cache_build(apr_pool_t *pool, const char *key, void *baton) {
	const struct oidc_proto_jwks_cache_build_ctx *ctx = baton;
	void *val = NULL;
	oidc_proto_jwks_cache_entry_t *entry = apr_palloc(pool, sizeof(oidc_proto_jwks_cache_entry_t));
	entry->expires = apr_time_now() + apr_time_from_sec(ctx->refresh_interval);
	entry->jwks = apr_array_make(pool, apr_hash_count(ctx->result), sizeof(oidc_jwk_t *));
	for (apr_hash_index_t *hi = apr_hash_first(NULL, ctx->result); hi; hi = apr_hash_next(hi)) {
		oidc_jwk_t *jwk = NULL;
		apr_hash_this(hi, NULL, NULL, &val);
		jwk = oidc_jwk_copy(pool, (oidc_jwk_t *)val);
		jwk->shared = TRUE;
		APR_ARRAY_PUSH(entry->jwks, oidc_jwk_t *) = jwk;
	}
	return entry;
}

/* release the retired backend key objects once no request context is running (at pool cleanup) */
static apr_status_t oidc_proto_jwks_cache_retired_cleanup(void *data) {
	if (_oidc_proto_jwks_cache_retired != NULL) {
		for (int i = 0; i < _oidc_proto_jwks_cache_retired->nelts; i++) {
			oidc_jwk_t *jwk = APR_ARRAY_IDX(_oidc_proto_jwks_cache_retired, i, oidc_jwk_t *);
			jwk->shared = FALSE;
			oidc_jwk_destroy(jwk);
		}
		_oidc_proto_jwks_cache_retired = NULL;
	}
	return APR_SUCCESS;
}

void oidc_proto_jwks_cache_init(apr_pool_t *pool, server_rec *s) {
	/* also guards the (non-idempotent) retired-list creation below against a repeated init */
	if (_oidc_proto_jwks_cache != NULL)
		return;
	_oidc_proto_jwks_cache_retired = apr_array_make(pool, 8, sizeof(oidc_jwk_t *));
	/* a regular (post-child) cleanup: it runs after the cache's own PRE-cleanup has retired every
	 * still-cached key, so by the time it fires the retired list holds them all for release */
	apr_pool_cleanup_register(pool, NULL, oidc_proto_jwks_cache_retired_cleanup, apr_pool_cleanup_null);
	oidc_cache_local_create(&_oidc_proto_jwks_cache, pool, "proto-jwks", OIDC_PROTO_JWKS_CACHE_MAX_ENTRIES, TRUE,
				oidc_proto_jwks_cache_free, oidc_util_cache_local_warn, s);
}

static void oidc_proto_jwks_cache_purge(void) {
	oidc_cache_local_clear(_oidc_proto_jwks_cache);
}

/* copy the cached selection result for the specified key into the result hash */
static apr_byte_t oidc_proto_jwks_cache_get(request_rec *r, const char *sel_key, const char *x5t, apr_hash_t *result) {
	struct oidc_proto_jwks_cache_use_ctx ctx = {.r = r, .x5t = x5t, .result = result};
	return oidc_cache_local_get_use(_oidc_proto_jwks_cache, sel_key, oidc_proto_jwks_cache_valid, NULL,
					oidc_proto_jwks_cache_use, &ctx);
}

/* store a non-empty selection result under the specified key, bounded by the refresh interval */
static void oidc_proto_jwks_cache_set(const char *sel_key, apr_hash_t *result, int refresh_interval) {
	struct oidc_proto_jwks_cache_build_ctx ctx = {.result = result, .refresh_interval = refresh_interval};
	if (apr_hash_count(result) < 1)
		return;
	oidc_cache_local_set_build(_oidc_proto_jwks_cache, sel_key, oidc_proto_jwks_cache_build, &ctx);
}

/*
 * when no kid/x5t was specified, include the JWK in the result if it is usable for signing;
 * takes ownership of jwk (either inserts it into result or destroys it)
 */
static void oidc_proto_jwks_key_include_any(request_rec *r, oidc_jwk_t *jwk, const oidc_json_t *elem,
					    apr_hash_t *result) {
	const char *use = oidc_json_string_value(oidc_json_object_get(elem, OIDC_JOSE_JWK_USE_STR));
	if ((use != NULL) && (_oidc_strcmp(use, OIDC_JOSE_JWK_SIG_STR) != 0)) {
		oidc_debug(r, "skipping key because of non-matching \"%s\": \"%s\"", OIDC_JOSE_JWK_USE_STR, use);
		oidc_jwk_destroy(jwk);
		return;
	}

	char *jwk_json = NULL;
	oidc_jose_error_t err;
	oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
	oidc_debug(r, "no kid/x5t to match, include matching key type: %s", jwk_json);
	if (jwk->kid != NULL)
		apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
	else
		// can do this because we never remove anything from the list
		apr_hash_set(result, apr_psprintf(r->pool, "%d", apr_hash_count(result)), APR_HASH_KEY_STRING, jwk);
}

/*
 * try a single JWKS entry against the JWT header;
 * returns TRUE when a specific kid/x5t match was found so the caller can stop iterating
 */
static apr_byte_t oidc_proto_jwks_key_apply(request_rec *r, oidc_jwt_t *jwt, const oidc_json_t *elem, const char *x5t,
					    apr_hash_t *result) {
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	char *jwk_json = NULL;
	char *s_x5t = NULL;

	if (oidc_jwk_parse_json(r->pool, elem, &jwk, &err) == FALSE) {
		oidc_warn(r, "oidc_jwk_parse_json failed: %s", oidc_jose_e2s(r->pool, err));
		return FALSE;
	}

	/* skip keys whose type does not match the JWT algorithm */
	if (oidc_jwt_alg2kty(jwt) != jwk->kty) {
		oidc_debug(r,
			   "skipping non matching kty=%d for kid=%s because it doesn't match requested kty=%d, kid=%s",
			   jwk->kty, jwk->kid, oidc_jwt_alg2kty(jwt), jwt->header.kid);
		oidc_jwk_destroy(jwk);
		return FALSE;
	}

	/* no specific kid/x5t requested: include any sig-usable key with a matching type */
	if ((jwt->header.kid == NULL) && (x5t == NULL)) {
		oidc_proto_jwks_key_include_any(r, jwk, elem, result);
		return FALSE;
	}

	/* compare the requested kid against the current element */
	if ((jwt->header.kid != NULL) && (jwk->kid != NULL) && (_oidc_strcmp(jwt->header.kid, jwk->kid) == 0)) {
		oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
		oidc_debug(r, "found matching kid: \"%s\" for jwk: %s", jwt->header.kid, jwk_json);
		apr_hash_set(result, jwt->header.kid, APR_HASH_KEY_STRING, jwk);
		return TRUE;
	}

	/* compare the requested thumbprint against the current element */
	oidc_json_object_get_string(r->pool, elem, OIDC_JOSE_JWK_X5T_STR, &s_x5t, NULL);
	if ((s_x5t != NULL) && (x5t != NULL) && (_oidc_strcmp(x5t, s_x5t) == 0)) {
		oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
		oidc_debug(r, "found matching %s: \"%s\" for jwk: %s", OIDC_JOSE_JWK_X5T_STR, x5t, jwk_json);
		apr_hash_set(result, x5t, APR_HASH_KEY_STRING, jwk);
		return TRUE;
	}

	/* the right key type but no matching kid/x5t */
	oidc_jwk_destroy(jwk);
	return FALSE;
}

/*
 * get the key from the JWKs that corresponds with the key specified in the header
 */
static apr_byte_t oidc_proto_jwks_key_get(request_rec *r, oidc_jwt_t *jwt, const oidc_json_t *j_jwks,
					  apr_hash_t *result) {

	/* get the (optional) thumbprint for comparison */
	const char *x5t = oidc_jwt_hdr_get(jwt, OIDC_JOSE_JWK_X5T_STR);
	oidc_debug(r, "search for kid \"%s\" or thumbprint x5t \"%s\"", jwt->header.kid, x5t);

	/* get the "keys" JSON array from the JWKs object */
	const oidc_json_t *keys = oidc_json_object_get(j_jwks, OIDC_JOSE_JWKS_KEYS_STR);
	if ((keys == NULL) || !(oidc_json_is_array(keys))) {
		oidc_error(r, "\"%s\" array element is not a JSON array", OIDC_JOSE_JWKS_KEYS_STR);
		return FALSE;
	}

	for (size_t i = 0; i < oidc_json_array_size(keys); i++) {
		if (oidc_proto_jwks_key_apply(r, jwt, oidc_json_array_get(keys, i), x5t, result) == TRUE)
			break;
	}

	return TRUE;
}

/*
 * get the keys from the (possibly cached) set of JWKs on the jwk_uri that corresponds with the key specified in the
 * header
 */
apr_byte_t oidc_proto_jwks_uri_keys(request_rec *r, oidc_cfg_t *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri,
				    int ssl_validate_server, apr_hash_t *keys, apr_byte_t *force_refresh) {

	oidc_json_t *j_jwks = NULL;
	const char *x5t = oidc_jwt_hdr_get(jwt, OIDC_JOSE_JWK_X5T_STR);
	const char *cache_uri = jwks_uri->signed_uri ? jwks_uri->signed_uri : jwks_uri->uri;
	const char *s_kid = jwt->header.kid ? jwt->header.kid : "";
	const char *s_x5t = x5t ? x5t : "";
	const char *sel_key = (cache_uri != NULL)
				  ? apr_psprintf(r->pool, "%s#%s#%s#%d", cache_uri, s_kid, s_x5t, oidc_jwt_alg2kty(jwt))
				  : NULL;

	if (*force_refresh == TRUE) {
		/* suspected key rollover: all cached selection results may derive from stale JWKs */
		oidc_proto_jwks_cache_purge();
	} else if ((sel_key != NULL) && (oidc_proto_jwks_cache_get(r, sel_key, x5t, keys) == TRUE)) {
		oidc_debug(r, "returning %d cached parsed key(s) for %s", apr_hash_count(keys), sel_key);
		return TRUE;
	}

	/* get the set of JSON Web Keys for this provider (possibly by downloading them from the specified
	 * provider->jwk_uri) */
	oidc_metadata_jwks_get(r, cfg, jwks_uri, ssl_validate_server, &j_jwks, force_refresh);
	if (j_jwks == NULL) {
		oidc_error(r, "could not %s JSON Web Keys", *force_refresh ? "refresh" : "get");
		return FALSE;
	}

	/*
	 * get the key corresponding to the kid from the header, referencing the key that
	 * was used to sign this message (or get all keys in case no kid was set)
	 *
	 * we don't check the error return value because we'll treat "error" in the same
	 * way as "key not found" i.e. by refreshing the keys from the JWKs URI if not
	 * already done
	 */
	oidc_proto_jwks_key_get(r, jwt, j_jwks, keys);

	/* no need anymore for the parsed oidc_json_t contents, release the it */
	oidc_json_decref(j_jwks);

	/* if we've got no keys and we did not do a fresh download, then the cache may be stale */
	if ((apr_hash_count(keys) < 1) && (*force_refresh == FALSE)) {

		/* we did not get a key, but we have not refreshed the JWKs from the jwks_uri yet */
		oidc_warn(r, "could not find a key in the cached JSON Web Keys, doing a forced refresh in case keys "
			     "were rolled over");
		/* get the set of JSON Web Keys forcing a fresh download from the specified JWKs URI */
		*force_refresh = TRUE;
		return oidc_proto_jwks_uri_keys(r, cfg, jwt, jwks_uri, ssl_validate_server, keys, force_refresh);
	}

	/* keep the parsed selection result for subsequent validations against the same signing key */
	if (sel_key != NULL)
		oidc_proto_jwks_cache_set(sel_key, keys, oidc_cfg_jwks_uri_refresh_interval_get(jwks_uri));

	oidc_debug(r, "returning %d key(s) obtained from the (possibly cached) JWKs URI", apr_hash_count(keys));

	return TRUE;
}
