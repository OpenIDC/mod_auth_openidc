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
 * Copyright (C) 2013-2016 Ping Identity Corporation
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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#ifndef _MOD_AUTH_OPENIDC_CACHE_H_
#define _MOD_AUTH_OPENIDC_CACHE_H_

#include "apr_global_mutex.h"

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
	apr_byte_t secure;
	oidc_cache_cfg_create create_config;
	oidc_cache_post_config_function post_config;
	oidc_cache_child_init_function child_init;
	oidc_cache_get_function get;
	oidc_cache_set_function set;
	oidc_cache_destroy_function destroy;
} oidc_cache_t;

typedef struct oidc_cache_mutex_t {
	apr_global_mutex_t *mutex;
	char *mutex_filename;
} oidc_cache_mutex_t;

oidc_cache_mutex_t *oidc_cache_mutex_create(apr_pool_t *pool);
apr_byte_t oidc_cache_mutex_post_config(server_rec *s, oidc_cache_mutex_t *m,
		const char *type);
apr_status_t oidc_cache_mutex_child_init(apr_pool_t *p, server_rec *s,
		oidc_cache_mutex_t *m);
apr_byte_t oidc_cache_mutex_lock(request_rec *r, oidc_cache_mutex_t *m);
apr_byte_t oidc_cache_mutex_unlock(request_rec *r, oidc_cache_mutex_t *m);
apr_byte_t oidc_cache_mutex_destroy(server_rec *s, oidc_cache_mutex_t *m);

extern oidc_cache_t oidc_cache_file;
extern oidc_cache_t oidc_cache_memcache;
extern oidc_cache_t oidc_cache_shm;

#ifdef USE_LIBHIREDIS
extern oidc_cache_t oidc_cache_redis;
#endif

#endif /* _MOD_AUTH_OPENIDC_CACHE_H_ */
