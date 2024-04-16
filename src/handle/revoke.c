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

#include "handle/handle.h"

int oidc_revoke_session(request_rec *r, oidc_cfg *c) {
	apr_byte_t rc = FALSE;
	char *session_id = NULL;

	oidc_http_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_REVOKE_SESSION, &session_id);
	if (session_id == NULL)
		return HTTP_BAD_REQUEST;

	if (c->session_type == OIDC_SESSION_TYPE_SERVER_CACHE)
		rc = oidc_cache_set_session(r, session_id, NULL, 0);
	else
		oidc_warn(r, "cannot revoke session because server side caching is not in use");

	r->user = "";

	return (rc == TRUE) ? OK : HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * handle a request to invalidate a cached access token introspection result
 */
int oidc_revoke_at_cache_remove(request_rec *r, oidc_cfg *c) {
	char *access_token = NULL;
	oidc_http_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE, &access_token);

	char *cache_entry = NULL;
	oidc_cache_get_access_token(r, access_token, &cache_entry);
	if (cache_entry == NULL) {
		oidc_error(r, "no cached access token found for value: %s", access_token);
		return HTTP_NOT_FOUND;
	}

	oidc_cache_set_access_token(r, access_token, NULL, 0);

	return OK;
}
