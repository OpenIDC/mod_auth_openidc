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
 * Copyright (C) 2017-2023 ZmartZone Holding BV
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
 * caching using a Redis backend
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "hiredis/hiredis.h"

#include "mod_auth_openidc.h"

struct oidc_cache_cfg_redis_t;

typedef apr_status_t (*oidc_cache_redis_connect_function_t)(request_rec*, struct oidc_cache_cfg_redis_t*);
typedef redisReply* (*oidc_cache_redis_command_function_t)(request_rec*, struct oidc_cache_cfg_redis_t*,
		char**, const char *format, va_list ap);
typedef apr_status_t (*oidc_cache_redis_disconnect_function_t)(struct oidc_cache_cfg_redis_t*);

typedef struct oidc_cache_cfg_redis_t {
	oidc_cache_mutex_t *mutex;
	char *username;
	char *passwd;
	int database;
	struct timeval connect_timeout;
	struct timeval timeout;
	char *host_str;
	apr_port_t port;
	redisContext *rctx;
	oidc_cache_redis_connect_function_t connect;
	oidc_cache_redis_command_function_t command;
	oidc_cache_redis_disconnect_function_t disconnect;
} oidc_cache_cfg_redis_t;

int oidc_cache_redis_post_config(server_rec *s, oidc_cfg *cfg, const char *name);
int oidc_cache_redis_child_init(apr_pool_t *p, server_rec *s);
redisReply* oidc_cache_redis_command(request_rec *r,
		oidc_cache_cfg_redis_t *context, char **errstr, const char *format,
		va_list ap);
apr_byte_t oidc_cache_redis_get(request_rec *r, const char *section,
		const char *key, char **value);
apr_byte_t oidc_cache_redis_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry);
apr_status_t oidc_cache_redis_disconnect(oidc_cache_cfg_redis_t *context);
