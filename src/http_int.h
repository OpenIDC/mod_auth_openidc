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

/*
 * Internal-only declarations for src/http.c. Exposes the curl-adjacent
 * helpers and context types so the unit-test binary can exercise them
 * without standing up a real HTTP transfer. Not part of the public
 * module API and not installed; do not include from outside src/ or test/.
 */

#ifndef _MOD_AUTH_OPENIDC_HTTP_INT_H_
#define _MOD_AUTH_OPENIDC_HTTP_INT_H_

#include "cfg/cfg.h"
#include "http.h"

#include <curl/curl.h>

/* maximum acceptable size of HTTP responses: 10 Mb */
#define OIDC_CURL_RESPONSE_DATA_SIZE_MAX (1024 * 1024 * 10)

/* env-var names used to override defaults at runtime; exposed for tests */
#define OIDC_CURLOPT_SSL_OPTIONS_ENV_VAR_NAME "CURLOPT_SSL_OPTIONS"
#define OIDC_USER_AGENT_ENV_VAR "OIDC_USER_AGENT"
#define OIDC_CURL_INTERFACE_ENV_VAR "OIDC_CURL_INTERFACE"

/* buffer that accumulates response bytes written by libcurl */
typedef struct oidc_curl_resp_data_ctx_t {
	request_rec *r;
	char *memory;
	size_t size;
} oidc_curl_resp_data_ctx_t;

/* hash of header names whose values curl should collect from the response */
typedef struct oidc_curl_resp_hdr_ctx_t {
	request_rec *r;
	apr_hash_t *hdrs;
} oidc_curl_resp_hdr_ctx_t;

/* libcurl CURLOPT_WRITEFUNCTION callback: append response body bytes to ctx */
size_t oidc_http_response_data(void *contents, size_t size, size_t nmemb, void *userp);

/* libcurl CURLOPT_HEADERFUNCTION callback: capture requested headers into ctx->hdrs */
size_t oidc_http_response_header(const char *buffer, size_t size, size_t nitems, void *userdata);

/* build the curl_slist of outgoing request headers (Authorization, Content-Type, traceparent, DPoP) */
struct curl_slist *oidc_http_request_build_header_list(request_rec *r, const oidc_cfg_t *c, const char *content_type,
						       const char *access_token, const char *dpop);

/* construct (and cache via subprocess_env override) the outgoing User-Agent string */
const char *oidc_http_user_agent(request_rec *r);

/* return the configured local interface (CURLOPT_INTERFACE) or NULL if unset */
const char *oidc_http_interface(const request_rec *r);

#endif /* _MOD_AUTH_OPENIDC_HTTP_INT_H_ */
