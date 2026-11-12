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

#include "handle/handle.h"

/*
 * handle request for JWKs
 */
int oidc_jwks_request(request_rec *r, const oidc_cfg_t *c) {
	const apr_array_header_t *keys = oidc_cfg_public_keys_get(c);
	apr_array_header_t *elems = apr_array_make(r->pool, keys ? keys->nelts : 0, sizeof(const char *));
	const oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	char *s_json = NULL;

	/* loop over the RSA/EC public keys, collecting their JSON representations to be joined once */
	for (int i = 0; keys && i < keys->nelts; i++) {
		jwk = APR_ARRAY_IDX(keys, i, oidc_jwk_t *);

		/* public key material only: OIDCPublicKeyFiles reads public keys and certificates, but what is
		 * published must not depend on that */
		if (oidc_jwk_to_jwks_json(r->pool, jwk, &s_json, &err) == TRUE) {
			APR_ARRAY_PUSH(elems, const char *) = apr_psprintf(r->pool, " %s ", s_json);
		} else {
			oidc_error(r, "could not convert RSA/EC JWK to JSON using oidc_jwk_to_jwks_json: %s",
				   oidc_jose_e2s(r->pool, err));
		}
	}

	const char *jwks =
	    apr_psprintf(r->pool, "{ \"keys\" : [%s ] }", apr_array_pstrcat(r->pool, elems, OIDC_CHAR_COMMA));

	return oidc_util_http_send(r, jwks, _oidc_strlen(jwks), OIDC_HTTP_CONTENT_TYPE_JSON, OK);
}
