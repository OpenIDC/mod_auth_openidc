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
 * caching using a memcache backend
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#ifndef _MOD_AUTH_OPENIDC_MEMCACHE_H_
#define _MOD_AUTH_OPENIDC_MEMCACHE_H_

#include "cfg/cache.h"
#include <apr_memcache.h>

struct oidc_cache_cfg_memcache_t;

/*
 * per-server "create + add" operation; the real implementation creates an apr_memcache server
 * (which connects when the connection-pool minimum is > 0) and adds it to the context, whereas
 * the unit-test mock records the pool sizes it is handed without touching the network.
 */
typedef int (*oidc_cache_memcache_add_server_function_t)(server_rec *s, apr_pool_t *p,
							 struct oidc_cache_cfg_memcache_t *context, char *split,
							 apr_uint32_t min, apr_uint32_t smax, apr_uint32_t hmax,
							 apr_interval_time_t ttl);

/*
 * data-path operations wrapping the apr_memcache calls; the real implementations talk to the
 * configured server(s) whereas the unit-test mocks fabricate results without a live memcached.
 */
typedef apr_status_t (*oidc_cache_memcache_getp_function_t)(struct oidc_cache_cfg_memcache_t *context, apr_pool_t *p,
							    const char *key, char **baton, apr_size_t *len);
typedef apr_status_t (*oidc_cache_memcache_set_function_t)(struct oidc_cache_cfg_memcache_t *context, const char *key,
							   char *baton, apr_size_t len, apr_uint32_t timeout);
typedef apr_status_t (*oidc_cache_memcache_delete_function_t)(struct oidc_cache_cfg_memcache_t *context,
							      const char *key);
typedef apr_byte_t (*oidc_cache_memcache_status_function_t)(const struct oidc_cache_cfg_memcache_t *context);

typedef struct oidc_cache_cfg_memcache_t {
	/* cache_type = memcache: memcache ptr */
	apr_memcache_t *cache_memcache;
	/* computed connection-pool clamp values, exposed so unit tests can assert them */
	apr_uint32_t min;
	apr_uint32_t smax;
	apr_uint32_t hmax;
	apr_interval_time_t ttl;
	/* injectable per-server create+add operation (mocked in unit tests) */
	oidc_cache_memcache_add_server_function_t add_server;
	/* injectable data-path operations (mocked in unit tests) */
	oidc_cache_memcache_getp_function_t getp;
	oidc_cache_memcache_set_function_t set;
	oidc_cache_memcache_delete_function_t del;
	oidc_cache_memcache_status_function_t status;
} oidc_cache_cfg_memcache_t;

int oidc_cache_memcache_post_config(apr_pool_t *pool, server_rec *s, oidc_cfg_t *cfg);
int oidc_cache_memcache_add_servers(apr_pool_t *pool, server_rec *s, oidc_cfg_t *cfg,
				    oidc_cache_cfg_memcache_t *context);
apr_byte_t oidc_cache_memcache_get(request_rec *r, const char *section, const char *key, char **value);
apr_byte_t oidc_cache_memcache_set(request_rec *r, const char *section, const char *key, const char *value,
				   apr_time_t expiry);

#endif // _MOD_AUTH_OPENIDC_MEMCACHE_H_
