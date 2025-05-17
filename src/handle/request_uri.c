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

#include "handle/handle.h"
#include "metadata.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

/*
 * handle request object by reference request
 */
int oidc_request_uri(request_rec *r, oidc_cfg_t *c) {

	char *request_ref = NULL;
	oidc_util_url_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_REQUEST_URI, &request_ref);
	if (request_ref == NULL) {
		oidc_error(r, "no \"%s\" parameter found", OIDC_REDIRECT_URI_REQUEST_REQUEST_URI);
		return HTTP_BAD_REQUEST;
	}

	char *jwt = NULL;
	oidc_cache_get_request_uri(r, request_ref, &jwt);
	if (jwt == NULL) {
		oidc_error(r, "no cached JWT found for %s reference: %s", OIDC_REDIRECT_URI_REQUEST_REQUEST_URI,
			   request_ref);
		return HTTP_NOT_FOUND;
	}

	oidc_cache_set_request_uri(r, request_ref, NULL, 0);

	return oidc_util_http_content_prep(r, jwt, _oidc_strlen(jwt), OIDC_HTTP_CONTENT_TYPE_JWT);
}
