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
#include "metrics.h"

/*
 * handle content generating requests
 */
int oidc_content_handler(request_rec *r) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	int rc = DECLINED;
	/* track if the session needs to be updated/saved into the cache */
	apr_byte_t needs_save = FALSE;
	oidc_session_t *session = NULL;

	if ((r->parsed_uri.path != NULL) && (c->metrics_path != NULL))
		if (_oidc_strcmp(r->parsed_uri.path, c->metrics_path) == 0)
			return oidc_metrics_handle_request(r);

	if (oidc_enabled(r) == FALSE) {
		OIDC_METRICS_COUNTER_INC(r, c, OM_CONTENT_REQUEST_DECLINED);
		return DECLINED;
	}

	if (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, c)) == TRUE) {

		/* requests to the redirect URI are handled and finished here */
		rc = OK;

		if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_INFO)) {

			OIDC_METRICS_COUNTER_INC(r, c, OM_CONTENT_REQUEST_INFO);

			/* see if a session was retained in the request state */
			apr_pool_userdata_get((void **)&session, OIDC_USERDATA_SESSION, r->pool);

			/* if no retained session was found, load it from the cache or create a new one*/
			if (session == NULL)
				oidc_session_load(r, &session);

			/*
			 * see if the request state indicates that the (retained)
			 * session was modified and needs to be updated in the cache
			 */
			needs_save = (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_SAVE) != NULL);

			/* handle request for session info */
			rc = oidc_info_request(r, c, session, needs_save);

			/* free resources allocated for the session */
			oidc_session_free(r, session);

		} else if (oidc_http_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_JWKS)) {

			OIDC_METRICS_COUNTER_INC(r, c, OM_CONTENT_REQUEST_JWKS);

			/* handle JWKs request */
			rc = oidc_jwks_request(r, c);

		} else {

			OIDC_METRICS_COUNTER_INC(r, c, OM_CONTENT_REQUEST_UNKNOWN);
		}

	} else if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_CONTENT_REQUEST_DISCOVERY);

		/* discovery may result in a 200 HTML page or a redirect to an external URL */
		rc = oidc_discovery_request(r, c);

	} else if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_AUTHN) != NULL) {

		OIDC_METRICS_COUNTER_INC(r, c, OM_CONTENT_REQUEST_POST_PRESERVE);

		/* sending POST preserve */
		rc = OK;

	} /* else: an authenticated request for which content is produced downstream */

	return rc;
}
