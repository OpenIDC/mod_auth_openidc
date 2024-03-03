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
 * Copyright (C) 2017-2024 ZmartZone Holding BV
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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#ifndef MOD_AUTH_OPENIDC_HTTP_H_
#define MOD_AUTH_OPENIDC_HTTP_H_

#include <apr.h>
#include <apr_time.h>
// clang-format off
#include <httpd.h>
#include <http_log.h>
#include <http_request.h>
// clang-format on
#include <jansson.h>

#define OIDC_HTTP_CONTENT_TYPE_JSON "application/json"
#define OIDC_HTTP_CONTENT_TYPE_JWT "application/jwt"
#define OIDC_HTTP_CONTENT_TYPE_FORM_ENCODED "application/x-www-form-urlencoded"
#define OIDC_HTTP_CONTENT_TYPE_IMAGE_PNG "image/png"
#define OIDC_HTTP_CONTENT_TYPE_TEXT_HTML "text/html"
#define OIDC_HTTP_CONTENT_TYPE_APP_XHTML_XML "application/xhtml+xml"
#define OIDC_HTTP_CONTENT_TYPE_ANY "*/*"

/* HTTP header constants */
#define OIDC_HTTP_HDR_COOKIE "Cookie"
#define OIDC_HTTP_HDR_SET_COOKIE "Set-Cookie"
#define OIDC_HTTP_HDR_USER_AGENT "User-Agent"
#define OIDC_HTTP_HDR_X_FORWARDED_FOR "X-Forwarded-For"
#define OIDC_HTTP_HDR_CONTENT_TYPE "Content-Type"
#define OIDC_HTTP_HDR_CONTENT_LENGTH "Content-Length"
#define OIDC_HTTP_HDR_X_REQUESTED_WITH "X-Requested-With"
#define OIDC_HTTP_HDR_SEC_FETCH_MODE "Sec-Fetch-Mode"
#define OIDC_HTTP_HDR_SEC_FETCH_DEST "Sec-Fetch-Dest"
#define OIDC_HTTP_HDR_ACCEPT "Accept"
#define OIDC_HTTP_HDR_AUTHORIZATION "Authorization"
#define OIDC_HTTP_HDR_X_FORWARDED_PROTO "X-Forwarded-Proto"
#define OIDC_HTTP_HDR_X_FORWARDED_PORT "X-Forwarded-Port"
#define OIDC_HTTP_HDR_X_FORWARDED_HOST "X-Forwarded-Host"
#define OIDC_HTTP_HDR_FORWARDED "Forwarded"
#define OIDC_HTTP_HDR_HOST "Host"
#define OIDC_HTTP_HDR_LOCATION "Location"
#define OIDC_HTTP_HDR_CACHE_CONTROL "Cache-Control"
#define OIDC_HTTP_HDR_PRAGMA "Pragma"
#define OIDC_HTTP_HDR_P3P "P3P"
#define OIDC_HTTP_HDR_EXPIRES "Expires"
#define OIDC_HTTP_HDR_X_FRAME_OPTIONS "X-Frame-Options"
#define OIDC_HTTP_HDR_WWW_AUTHENTICATE "WWW-Authenticate"
#define OIDC_HTTP_HDR_TRACE_PARENT "traceparent"

#define OIDC_HTTP_HDR_VAL_XML_HTTP_REQUEST "XMLHttpRequest"
#define OIDC_HTTP_HDR_VAL_NAVIGATE "navigate"
#define OIDC_HTTP_HDR_VAL_DOCUMENT "document"

typedef struct oidc_http_timeout_t {
	int request_timeout; // in seconds
	int connect_timeout; // in seconds
	int retries;
	int retry_interval; // in milliseconds
} oidc_http_timeout_t;

#define OIDC_HTTP_PROXY_AUTH_BASIC "basic"
#define OIDC_HTTP_PROXY_AUTH_DIGEST "digest"
#define OIDC_HTTP_PROXY_AUTH_NTLM "ntlm"
#define OIDC_HTTP_PROXY_AUTH_ANY "any"
#define OIDC_HTTP_PROXY_AUTH_NEGOTIATE "negotiate"

typedef struct oidc_http_outgoing_proxy_t {
	const char *host_port;
	const char *username_password;
	unsigned long auth_type;
} oidc_http_outgoing_proxy_t;

char *oidc_http_escape_string(const request_rec *r, const char *str);
char *oidc_http_unescape_string(const request_rec *r, const char *str);

void oidc_http_hdr_err_out_add(const request_rec *r, const char *name, const char *value);
void oidc_http_hdr_in_set(const request_rec *r, const char *name, const char *value);
const char *oidc_http_hdr_in_cookie_get(const request_rec *r);
void oidc_http_hdr_in_cookie_set(const request_rec *r, const char *value);
const char *oidc_http_hdr_in_user_agent_get(const request_rec *r);
const char *oidc_http_hdr_in_x_forwarded_for_get(const request_rec *r);
const char *oidc_http_hdr_in_content_type_get(const request_rec *r);
const char *oidc_http_hdr_in_content_length_get(const request_rec *r);
const char *oidc_http_hdr_in_x_requested_with_get(const request_rec *r);
const char *oidc_http_hdr_in_sec_fetch_mode_get(const request_rec *r);
const char *oidc_http_hdr_in_sec_fetch_dest_get(const request_rec *r);
const char *oidc_http_hdr_in_accept_get(const request_rec *r);
apr_byte_t oidc_http_hdr_in_accept_contains(const request_rec *r, const char *needle);
const char *oidc_http_hdr_in_authorization_get(const request_rec *r);
const char *oidc_http_hdr_in_x_forwarded_proto_get(const request_rec *r);
const char *oidc_http_hdr_in_x_forwarded_port_get(const request_rec *r);
const char *oidc_http_hdr_in_x_forwarded_host_get(const request_rec *r);
const char *oidc_http_hdr_in_forwarded_get(const request_rec *r);
const char *oidc_http_hdr_in_host_get(const request_rec *r);
const char *oidc_http_hdr_in_traceparent_get(const request_rec *r);
void oidc_http_hdr_out_location_set(const request_rec *r, const char *value);
const char *oidc_http_hdr_out_location_get(const request_rec *r);
const char *oidc_http_hdr_forwarded_get(const request_rec *r, const char *elem);

char *oidc_http_hdr_normalize_name(const request_rec *r, const char *str);
apr_byte_t oidc_http_get(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth,
			 const char *bearer_token, int ssl_validate_server, char **response, long *response_code,
			 oidc_http_timeout_t *http_timeout, const oidc_http_outgoing_proxy_t *outgoing_proxy,
			 apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key,
			 const char *ssl_key_pwd);
apr_byte_t oidc_http_post_form(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth,
			       const char *bearer_token, int ssl_validate_server, char **response, long *response_code,
			       oidc_http_timeout_t *http_timeout, const oidc_http_outgoing_proxy_t *outgoing_proxy,
			       apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key,
			       const char *ssl_key_pwd);
apr_byte_t oidc_http_post_json(request_rec *r, const char *url, json_t *data, const char *basic_auth,
			       const char *bearer_token, int ssl_validate_server, char **response, long *response_code,
			       oidc_http_timeout_t *http_timeout, const oidc_http_outgoing_proxy_t *outgoing_proxy,
			       apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key,
			       const char *ssl_key_pwd);
apr_byte_t oidc_http_request_has_parameter(request_rec *r, const char *param);
apr_byte_t oidc_http_request_parameter_get(request_rec *r, char *name, char **value);
int oidc_http_send(request_rec *r, const char *data, size_t data_len, const char *content_type, int success_rvalue);
apr_byte_t oidc_http_read_form_encoded_params(request_rec *r, apr_table_t *table, char *data);
apr_byte_t oidc_http_read_post_params(request_rec *r, apr_table_t *table, apr_byte_t propagate,
				      const char *strip_param_name);
char *oidc_http_query_encoded_url(request_rec *r, const char *url, const apr_table_t *params);
char *oidc_http_form_encoded_data(request_rec *r, const apr_table_t *params);

char *oidc_http_get_cookie(request_rec *r, const char *cookieName);
void oidc_http_set_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires,
			  const char *ext);
char *oidc_http_get_chunked_cookie(request_rec *r, const char *cookieName, int chunkSize);
void oidc_http_set_chunked_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires,
				  int chunkSize, const char *ext);

char **oidc_http_proxy_auth_options(void);
unsigned long oidc_http_proxy_s2auth(const char *arg);

void oidc_http_init(void);
void oidc_http_cleanup(void);

#endif /* MOD_AUTH_OPENIDC_HTTP_H_ */
