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

#include "util/util.h"

/*
 * create a symmetric key from a client_secret
 */
apr_byte_t oidc_util_key_symmetric_create(request_rec *r, const char *client_secret, unsigned int r_key_len,
					  const char *hash_algo, apr_byte_t set_kid, oidc_jwk_t **jwk) {
	oidc_jose_error_t err = {{'\0'}, 0, {'\0'}, {'\0'}};
	unsigned char *key = NULL;
	unsigned int key_len;

	if ((client_secret != NULL) && (_oidc_strlen(client_secret) > 0)) {

		if (hash_algo == NULL) {
			key = (unsigned char *)client_secret;
			key_len = _oidc_strlen(client_secret);
		} else {
			/* hash the client_secret first, this is OpenID Connect specific */
			oidc_jose_hash_bytes(r->pool, hash_algo, (const unsigned char *)client_secret,
					     _oidc_strlen(client_secret), &key, &key_len, &err);
		}

		if ((key != NULL) && (key_len > 0)) {
			if ((r_key_len != 0) && (key_len >= r_key_len))
				key_len = r_key_len;
			oidc_debug(r, "key_len=%d", key_len);
			*jwk = oidc_jwk_create_symmetric_key(r->pool, NULL, key, key_len, set_kid, &err);
		}

		if (*jwk == NULL) {
			oidc_error(r, "could not create JWK from the provided secret: %s", oidc_jose_e2s(r->pool, err));
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * merge provided keys and client secret in to a single hashtable
 */
apr_hash_t *oidc_util_key_symmetric_merge(apr_pool_t *pool, const apr_array_header_t *keys, oidc_jwk_t *jwk) {
	apr_hash_t *result = apr_hash_make(pool);
	const oidc_jwk_t *elem = NULL;
	int i = 0;
	if (keys != NULL) {
		for (i = 0; i < keys->nelts; i++) {
			elem = APR_ARRAY_IDX(keys, i, oidc_jwk_t *);
			apr_hash_set(result, elem->kid, APR_HASH_KEY_STRING, elem);
		}
	}
	if (jwk != NULL) {
		apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
	}
	return result;
}

/*
 * merge the provided array of keys (k2) into a hash table of keys (k1)
 */
apr_hash_t *oidc_util_key_sets_merge(apr_pool_t *pool, apr_hash_t *k1, const apr_array_header_t *k2) {
	apr_hash_t *rv = k1 ? apr_hash_copy(pool, k1) : apr_hash_make(pool);
	const oidc_jwk_t *jwk = NULL;
	int i = 0;
	if (k2 != NULL) {
		for (i = 0; i < k2->nelts; i++) {
			jwk = APR_ARRAY_IDX(k2, i, oidc_jwk_t *);
			apr_hash_set(rv, jwk->kid, APR_HASH_KEY_STRING, jwk);
		}
	}
	return rv;
}

/*
 * merge two hash tables with key sets
 */
apr_hash_t *oidc_util_key_sets_hash_merge(apr_pool_t *pool, apr_hash_t *k1, apr_hash_t *k2) {
	if (k1 == NULL) {
		if (k2 == NULL)
			return apr_hash_make(pool);
		return k2;
	}
	if (k2 == NULL)
		return k1;
	return apr_hash_overlay(pool, k1, k2);
}

/*
 * return the first JWK that matches a provided key type and use from an array of JWKs
 */
oidc_jwk_t *oidc_util_key_list_first(const apr_array_header_t *key_list, int kty, const char *use) {
	oidc_jwk_t *rv = NULL;
	int i = 0;
	oidc_jwk_t *jwk = NULL;
	for (i = 0; (key_list) && (i < key_list->nelts); i++) {
		jwk = APR_ARRAY_IDX(key_list, i, oidc_jwk_t *);
		if ((kty != -1) && (jwk->kty != kty))
			continue;
		if (((use == NULL) || (jwk->use == NULL) || (_oidc_strncmp(jwk->use, use, _oidc_strlen(use)) == 0))) {
			rv = jwk;
			break;
		}
	}
	return rv;
}

