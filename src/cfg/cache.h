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

#ifndef _MOD_AUTH_OPENIDC_CFG_CACHE_H_
#define _MOD_AUTH_OPENIDC_CFG_CACHE_H_

#include "cfg/cfg.h"

void oidc_cfg_cache_create_server_config(oidc_cfg_t *c);
void oidc_cfg_cache_merge_server_config(oidc_cfg_t *c, oidc_cfg_t *base, oidc_cfg_t *add);

// NB: need the primitive strings and the custom set routines
//     here because the commands are included in config.

#define OIDCCacheType "OIDCCacheType"
#define OIDCCacheEncrypt "OIDCCacheEncrypt"

OIDC_CFG_MEMBER_FUNCS_DECL(cache_type, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_encrypt, int)

/*
 * shm
 */
#define OIDCCacheShmMax "OIDCCacheShmMax"
#define OIDCCacheShmEntrySizeMax "OIDCCacheShmEntrySizeMax"

OIDC_CFG_MEMBER_FUNCS_DECL(cache_shm_size_max, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_shm_entry_size_max, int)

/*
 * file
 */

#define OIDCCacheDir "OIDCCacheDir"
#define OIDCCacheFileCleanInterval "OIDCCacheFileCleanInterval"

OIDC_CFG_MEMBER_FUNCS_DECL(cache_file_clean_interval, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_file_dir, const char *)

/*
 * memcache
 */

#ifdef USE_MEMCACHE

#define OIDCMemCacheServers "OIDCMemCacheServers"
#define OIDCMemCacheConnectionsMin "OIDCMemCacheConnectionsMin"
#define OIDCMemCacheConnectionsSMax "OIDCMemCacheConnectionsSMax"
#define OIDCMemCacheConnectionsHMax "OIDCMemCacheConnectionsHMax"
#define OIDCMemCacheConnectionsTTL "OIDCMemCacheConnectionsTTL"

OIDC_CFG_MEMBER_FUNCS_DECL(cache_memcache_servers, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_memcache_min, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_memcache_smax, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_memcache_hmax, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_memcache_ttl, apr_interval_time_t)

#endif // USE_MEMCACHE

/*
 * redis
 */

#ifdef USE_LIBHIREDIS

#define OIDCRedisCacheServer "OIDCRedisCacheServer"
#define OIDCRedisCacheUsername "OIDCRedisCacheUsername"
#define OIDCRedisCachePassword "OIDCRedisCachePassword"
#define OIDCRedisCacheDatabase "OIDCRedisCacheDatabase"
#define OIDCRedisCacheConnectTimeout "OIDCRedisCacheConnectTimeout"
#define OIDCRedisCacheTimeout "OIDCRedisCacheTimeout"

OIDC_CFG_MEMBER_FUNCS_DECL(cache_redis_server, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_redis_username, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_redis_password, const char *)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_redis_database, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_redis_timeout, int)
OIDC_CFG_MEMBER_FUNCS_DECL(cache_redis_connect_timeout, int, const char *)
OIDC_CFG_MEMBER_FUNC_GET_DECL(cache_redis_keepalive, int)

#endif // USE_LIBHIREDIS

#endif // _MOD_AUTH_OPENIDC_CFG_CACHE_H_
