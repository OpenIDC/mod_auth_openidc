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

#include "metadata.h"
#include "proto/proto.h"
#include "util/util.h"

/*
 * get the key from the JWKs that corresponds with the key specified in the header
 */
static apr_byte_t oidc_proto_jwks_key_get(request_rec *r, oidc_jwt_t *jwt, json_t *j_jwks, apr_hash_t *result) {

	apr_byte_t rc = TRUE;
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	char *jwk_json = NULL;

	/* get the (optional) thumbprint for comparison */
	const char *x5t = oidc_jwt_hdr_get(jwt, OIDC_JOSE_JWK_X5T_STR);
	oidc_debug(r, "search for kid \"%s\" or thumbprint x5t \"%s\"", jwt->header.kid, x5t);

	/* get the "keys" JSON array from the JWKs object */
	json_t *keys = json_object_get(j_jwks, OIDC_JOSE_JWKS_KEYS_STR);
	if ((keys == NULL) || !(json_is_array(keys))) {
		oidc_error(r, "\"%s\" array element is not a JSON array", OIDC_JOSE_JWKS_KEYS_STR);
		return FALSE;
	}

	int i;
	for (i = 0; i < json_array_size(keys); i++) {

		/* get the next element in the array */
		json_t *elem = json_array_get(keys, i);

		if (oidc_jwk_parse_json(r->pool, elem, &jwk, &err) == FALSE) {
			oidc_warn(r, "oidc_jwk_parse_json failed: %s", oidc_jose_e2s(r->pool, err));
			continue;
		}

		/* get the key type and see if it is the type that we are looking for */
		if (oidc_jwt_alg2kty(jwt) != jwk->kty) {
			oidc_debug(
			    r,
			    "skipping non matching kty=%d for kid=%s because it doesn't match requested kty=%d, kid=%s",
			    jwk->kty, jwk->kid, oidc_jwt_alg2kty(jwt), jwt->header.kid);
			oidc_jwk_destroy(jwk);
			continue;
		}

		/* see if we were looking for a specific kid, if not we'll include any key that matches the type */
		if ((jwt->header.kid == NULL) && (x5t == NULL)) {
			const char *use = json_string_value(json_object_get(elem, OIDC_JOSE_JWK_USE_STR));
			if ((use != NULL) && (_oidc_strcmp(use, OIDC_JOSE_JWK_SIG_STR) != 0)) {
				oidc_debug(r, "skipping key because of non-matching \"%s\": \"%s\"",
					   OIDC_JOSE_JWK_USE_STR, use);
				oidc_jwk_destroy(jwk);
			} else {
				oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
				oidc_debug(r, "no kid/x5t to match, include matching key type: %s", jwk_json);
				if (jwk->kid != NULL)
					apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
				else
					// can do this because we never remove anything from the list
					apr_hash_set(result, apr_psprintf(r->pool, "%d", apr_hash_count(result)),
						     APR_HASH_KEY_STRING, jwk);
			}
			continue;
		}

		/* we are looking for a specific kid, get the kid from the current element */
		/* compare the requested kid against the current element */
		if ((jwt->header.kid != NULL) && (jwk->kid != NULL) && (_oidc_strcmp(jwt->header.kid, jwk->kid) == 0)) {
			oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
			oidc_debug(r, "found matching kid: \"%s\" for jwk: %s", jwt->header.kid, jwk_json);
			apr_hash_set(result, jwt->header.kid, APR_HASH_KEY_STRING, jwk);
			break;
		}

		/* we are looking for a specific x5t, get the x5t from the current element */
		char *s_x5t = NULL;
		oidc_util_json_object_get_string(r->pool, elem, OIDC_JOSE_JWK_X5T_STR, &s_x5t, NULL);
		/* compare the requested thumbprint against the current element */
		if ((s_x5t != NULL) && (x5t != NULL) && (_oidc_strcmp(x5t, s_x5t) == 0)) {
			oidc_jwk_to_json(r->pool, jwk, &jwk_json, &err);
			oidc_debug(r, "found matching %s: \"%s\" for jwk: %s", OIDC_JOSE_JWK_X5T_STR, x5t, jwk_json);
			apr_hash_set(result, x5t, APR_HASH_KEY_STRING, jwk);
			break;
		}

		/* the right key type but no matching kid/x5t */
		oidc_jwk_destroy(jwk);
	}

	return rc;
}

/*
 * get the keys from the (possibly cached) set of JWKs on the jwk_uri that corresponds with the key specified in the
 * header
 */
apr_byte_t oidc_proto_jwks_uri_keys(request_rec *r, oidc_cfg_t *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri,
				    int ssl_validate_server, apr_hash_t *keys, apr_byte_t *force_refresh) {

	json_t *j_jwks = NULL;

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

	/* no need anymore for the parsed json_t contents, release the it */
	json_decref(j_jwks);

	/* if we've got no keys and we did not do a fresh download, then the cache may be stale */
	if ((apr_hash_count(keys) < 1) && (*force_refresh == FALSE)) {

		/* we did not get a key, but we have not refreshed the JWKs from the jwks_uri yet */
		oidc_warn(r, "could not find a key in the cached JSON Web Keys, doing a forced refresh in case keys "
			     "were rolled over");
		/* get the set of JSON Web Keys forcing a fresh download from the specified JWKs URI */
		*force_refresh = TRUE;
		return oidc_proto_jwks_uri_keys(r, cfg, jwt, jwks_uri, ssl_validate_server, keys, force_refresh);
	}

	oidc_debug(r, "returning %d key(s) obtained from the (possibly cached) JWKs URI", apr_hash_count(keys));

	return TRUE;
}
