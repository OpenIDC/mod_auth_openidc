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
 * Copyright (C) 2017-2020 ZmartZone IAM
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * mem_cache-like interface and semantics (string keys/values) using a storage backend
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#ifndef _MOD_AUTH_OPENIDC_CACHE_H_
#define _MOD_AUTH_OPENIDC_CACHE_H_

#include "apr_global_mutex.h"
#include "apr_shm.h"

typedef void * (*oidc_cache_cfg_create)(apr_pool_t *pool);
typedef int (*oidc_cache_post_config_function)(server_rec *s);
typedef int (*oidc_cache_child_init_function)(apr_pool_t *p, server_rec *s);
typedef apr_byte_t (*oidc_cache_get_function)(request_rec *r,
		const char *section, const char *key, const char **value);
typedef apr_byte_t (*oidc_cache_set_function)(request_rec *r,
		const char *section, const char *key, const char *value,
		apr_time_t expiry);
typedef int (*oidc_cache_destroy_function)(server_rec *s);

typedef struct oidc_cache_t {
	const char *name;
	int encrypt_by_default;
	oidc_cache_post_config_function post_config;
	oidc_cache_child_init_function child_init;
	oidc_cache_get_function get;
	oidc_cache_set_function set;
	oidc_cache_destroy_function destroy;
} oidc_cache_t;

typedef struct oidc_cache_mutex_t {
	apr_global_mutex_t *mutex;
	char *mutex_filename;
	apr_shm_t *shm;
	int *sema;
	apr_byte_t is_parent;
} oidc_cache_mutex_t;

oidc_cache_mutex_t *oidc_cache_mutex_create(apr_pool_t *pool);
apr_byte_t oidc_cache_mutex_post_config(server_rec *s, oidc_cache_mutex_t *m,
		const char *type);
apr_status_t oidc_cache_mutex_child_init(apr_pool_t *p, server_rec *s,
		oidc_cache_mutex_t *m);
apr_byte_t oidc_cache_mutex_lock(server_rec *s, oidc_cache_mutex_t *m);
apr_byte_t oidc_cache_mutex_unlock(server_rec *s, oidc_cache_mutex_t *m);
apr_byte_t oidc_cache_mutex_destroy(server_rec *s, oidc_cache_mutex_t *m);

apr_byte_t oidc_cache_get(request_rec *r, const char *section, const char *key,
		char **value);
apr_byte_t oidc_cache_set(request_rec *r, const char *section, const char *key,
		const char *value, apr_time_t expiry);

#define OIDC_CACHE_SECTION_SESSION           "s"
#define OIDC_CACHE_SECTION_NONCE             "n"
#define OIDC_CACHE_SECTION_JWKS              "j"
#define OIDC_CACHE_SECTION_ACCESS_TOKEN      "a"
#define OIDC_CACHE_SECTION_PROVIDER          "p"
#define OIDC_CACHE_SECTION_OAUTH_PROVIDER    "o"
#define OIDC_CACHE_SECTION_JTI               "t"
#define OIDC_CACHE_SECTION_REQUEST_URI       "r"
#define OIDC_CACHE_SECTION_SID               "d"

// TODO: now every section occupies the same space; we may want to differentiate
//       according to section-based size, at least for the shm backend

#define oidc_cache_get_session(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, key, value)
#define oidc_cache_get_nonce(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_NONCE, key, value)
#define oidc_cache_get_jwks(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_JWKS, key, value)
#define oidc_cache_get_access_token(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_ACCESS_TOKEN, key, value)
#define oidc_cache_get_provider(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_PROVIDER, key, value)
#define oidc_cache_get_oauth_provider(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_OAUTH_PROVIDER, key, value)
#define oidc_cache_get_jti(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_JTI, key, value)
#define oidc_cache_get_request_uri(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_REQUEST_URI, key, value)
#define oidc_cache_get_sid(r, key, value) oidc_cache_get(r, OIDC_CACHE_SECTION_SID, key, value)

#define oidc_cache_set_session(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, key, value, expiry)
#define oidc_cache_set_nonce(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_NONCE, key, value, expiry)
#define oidc_cache_set_jwks(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_JWKS, key, value, expiry)
#define oidc_cache_set_access_token(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_ACCESS_TOKEN, key, value, expiry)
#define oidc_cache_set_provider(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_PROVIDER, key, value, expiry)
#define oidc_cache_set_oauth_provider(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_OAUTH_PROVIDER, key, value, expiry)
#define oidc_cache_set_jti(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_JTI, key, value, expiry)
#define oidc_cache_set_request_uri(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_REQUEST_URI, key, value, expiry)
#define oidc_cache_set_sid(r, key, value, expiry) oidc_cache_set(r, OIDC_CACHE_SECTION_SID, key, value, expiry)

extern oidc_cache_t oidc_cache_file;
extern oidc_cache_t oidc_cache_shm;

#ifdef USE_MEMCACHE
extern oidc_cache_t oidc_cache_memcache;
#endif

#ifdef USE_LIBHIREDIS
extern oidc_cache_t oidc_cache_redis;
#endif

#endif /* _MOD_AUTH_OPENIDC_CACHE_H_ */
