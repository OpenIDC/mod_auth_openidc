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
#include "mod_auth_openidc.h"
#include "proto.h"
#include "util.h"

#define OIDC_DPOP_PARAM_URL "url"
#define OIDC_DPOP_PARAM_METHOD "method"

int oidc_dpop_request(request_rec *r, oidc_cfg_t *c, oidc_session_t *session) {
	int rc = HTTP_BAD_REQUEST;
	char *s_url = NULL;
	char *s_access_token = NULL;
	const char *session_access_token = NULL;
	char *s_method = NULL;
	char *s_dpop = NULL;
	char *s_response = NULL;
	json_t *json = NULL;

	/* try to make sure that the proof-of-possession semantics are preserved */
	if ((_oidc_strnatcasecmp(r->useragent_ip, r->connection->local_ip) != 0) &&
	    (apr_table_get(r->subprocess_env, "OIDC_DPOP_API_INSECURE") == 0)) {
		oidc_warn(
		    r,
		    "reject DPoP creation request from remote host: you should create a separate virtual (sub)host "
		    "that requires client certificate authentication to allow and proxy this request "
		    "(r->useragent_ip=%s, "
		    "r->connection->local_ip=%s)",
		    r->useragent_ip, r->connection->local_ip);
		rc = HTTP_UNAUTHORIZED;
		goto end;
	}

	/* retrieve the access token parameter */
	oidc_util_request_parameter_get(r, OIDC_REDIRECT_URI_REQUEST_DPOP, &s_access_token);
	if (s_access_token == NULL) {
		oidc_error(r, "\"access_token\" value to the \"%s\" parameter is missing",
			   OIDC_REDIRECT_URI_REQUEST_DPOP);
		goto end;
	}

	/* retrieve the URL parameter */
	oidc_util_request_parameter_get(r, OIDC_DPOP_PARAM_URL, &s_url);
	if (s_url == NULL) {
		oidc_error(r, "\"url\" parameter is missing");
		goto end;
	}

	/* parse the optional HTTP method parameter */
	oidc_util_request_parameter_get(r, OIDC_DPOP_PARAM_METHOD, &s_method);
	if (_oidc_strnatcasecmp(s_method, "post") == 0)
		s_method = "POST";
	else if ((_oidc_strnatcasecmp(s_method, "get") == 0) || (s_method == NULL))
		s_method = "GET";

	/* check that we actually have a user session and this is someone calling with a proper session cookie */
	if (session->remote_user == NULL) {
		oidc_warn(r, "no user session found");
		rc = HTTP_UNAUTHORIZED;
		goto end;
	}

	session_access_token = oidc_session_get_access_token(r, session);
	if (session_access_token == NULL) {
		oidc_error(r, "no \"access_token\" was found in the session");
		goto end;
	}

	if (_oidc_strcmp(s_access_token, session_access_token) != 0) {
		oidc_error(r, "the provided \"access_token\" parameter is not matching the current access token stored "
			      "in the user session");
		goto end;
	}

	/* create the DPoP header value */
	s_dpop = oidc_proto_dpop(r, c, s_url, s_method, s_access_token);
	if (s_dpop == NULL) {
		oidc_error(r, "creating the DPoP proof value failed");
		rc = HTTP_INTERNAL_SERVER_ERROR;
		goto end;
	}

	/* assemble and serialize the JSON response object */
	json = json_object();
	json_object_set_new(json, OIDC_HTTP_HDR_DPOP, json_string(s_dpop));
	s_response = oidc_util_encode_json_object(r, json, JSON_COMPACT | JSON_PRESERVE_ORDER);

	/* return the serialized JSON response */
	rc = oidc_util_http_send(r, s_response, _oidc_strlen(s_response), OIDC_HTTP_CONTENT_TYPE_JSON, OK);

end:

	if (json)
		json_decref(json);

	return rc;
}
