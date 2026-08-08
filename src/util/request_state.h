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

#ifndef _MOD_AUTH_OPENIDC_UTIL_REQUEST_STATE_H_
#define _MOD_AUTH_OPENIDC_UTIL_REQUEST_STATE_H_

/*
 * per-request state store; see util/request_state.c. Kept separate from util/util.h so that a
 * consumer of it does not also pull in that header's configuration dependencies.
 */

/* NB: const.h pulls in config.h and undefines the PACKAGE_* macros it brings, so it has to come
 * before httpd.h - which defines its own - or every consumer that includes this header first gets
 * a redefinition warning */
#include "const.h"
#include "json.h"

#include <httpd.h>

/* keys for storing info in the request state */
#define OIDC_REQUEST_STATE_KEY_AUTHN_POST "a"
#define OIDC_REQUEST_STATE_KEY_CLAIMS "c"
#define OIDC_REQUEST_STATE_KEY_DISCOVERY "d"
#define OIDC_REQUEST_STATE_KEY_HTTP "hp"
#define OIDC_REQUEST_STATE_KEY_HTML "hl"
#define OIDC_REQUEST_STATE_KEY_IDTOKEN "i"
#define OIDC_REQUEST_STATE_KEY_SCOPE "sc"
#define OIDC_REQUEST_STATE_KEY_AUTHN_PRESERVE "p"
#define OIDC_REQUEST_STATE_KEY_SAVE "s"
#define OIDC_REQUEST_STATE_TRACE_ID "t"

/* the pool userdata key under which the preserved POST parameters are stored */
#define OIDC_USERDATA_POST_PARAMS_KEY "oidc_userdata_post_params"

void oidc_request_state_set(request_rec *r, const char *key, const char *value);
const char *oidc_request_state_get(request_rec *r, const char *key);
oidc_json_t *oidc_request_state_json_get(request_rec *r, const char *key);
void oidc_request_state_json_set(request_rec *r, const char *key, const oidc_json_t *value);
void oidc_request_state_json_set_new(request_rec *r, const char *key, oidc_json_t *value);

#endif // _MOD_AUTH_OPENIDC_UTIL_REQUEST_STATE_H_
