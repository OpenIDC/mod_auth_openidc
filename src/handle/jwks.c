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

/*
 * handle request for JWKs
 */
int oidc_jwks_request(request_rec *r, oidc_cfg *c) {
	/* pickup requested JWKs type */
	//	char *jwks_type = NULL;
	//	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_JWKS, &jwks_type);
	char *jwks = apr_pstrdup(r->pool, "{ \"keys\" : [");
	int i = 0;
	apr_byte_t first = TRUE;
	const oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	char *s_json = NULL;

	/* loop over the RSA/EC public keys */
	for (i = 0; c->public_keys && i < c->public_keys->nelts; i++) {
		jwk = APR_ARRAY_IDX(c->public_keys, i, oidc_jwk_t *);

		if (oidc_jwk_to_json(r->pool, jwk, &s_json, &err) == TRUE) {
			jwks = apr_psprintf(r->pool, "%s%s %s ", jwks, first ? "" : ",", s_json);
			first = FALSE;
		} else {
			oidc_error(r, "could not convert RSA/EC JWK to JSON using oidc_jwk_to_json: %s",
				   oidc_jose_e2s(r->pool, err));
		}
	}

	// TODO: send stuff if first == FALSE?
	jwks = apr_psprintf(r->pool, "%s ] }", jwks);

	return oidc_http_send(r, jwks, _oidc_strlen(jwks), OIDC_HTTP_CONTENT_TYPE_JSON, OK);
}
