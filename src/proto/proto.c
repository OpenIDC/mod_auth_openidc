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

#include "proto/proto.h"
#include "cfg/dir.h"
#include "cfg/parse.h"
#include "handle/handle.h"
#include "metadata.h"
#include "metrics.h"
#include "mod_auth_openidc.h"
#include "util/util.h"

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

/* nonce bytes length */
#define OIDC_PROTO_NONCE_LENGTH 32

/*
 * generate a random value (nonce) to correlate request/response through browser state
 */
apr_byte_t oidc_proto_nonce_gen(request_rec *r, char **nonce) {
	return oidc_util_rand_str(r, nonce, OIDC_PROTO_NONCE_LENGTH);
}

/* jti bytes length */
#define OIDC_PROTO_JWT_JTI_LEN 16

/*
 * generate a random unique "jti" JWT identifier
 */
char *oidc_proto_jti_gen(request_rec *r) {
	char *jti = NULL;
	if (oidc_util_rand_str(r, &jti, OIDC_PROTO_JWT_JTI_LEN) == FALSE) {
		oidc_error(r, "oidc_util_rand_str returned FALSE");
	}
	return jti;
}

/*
 * return the supported flows
 */
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 6, sizeof(const char *));
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN;
	APR_ARRAY_PUSH(result, const char *) = OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN;
	return result;
}

/*
 * check if a particular OpenID Connect flow is supported
 */
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow) {
	apr_array_header_t *flows = oidc_proto_supported_flows(pool);
	int i;
	for (i = 0; i < flows->nelts; i++) {
		if (oidc_util_spaced_string_equals(pool, flow, APR_ARRAY_IDX(flows, i, const char *)))
			return TRUE;
	}
	return FALSE;
}

/*
 * set the WWW-Authenticate response header according to https://tools.ietf.org/html/rfc6750#section-3
 */
int oidc_proto_return_www_authenticate(request_rec *r, const char *error, const char *error_description) {
	apr_byte_t accept_token_in = oidc_cfg_dir_oauth_accept_token_in_get(r);
	char *hdr;
	if (accept_token_in == OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC) {
		hdr = apr_psprintf(r->pool, "%s", OIDC_PROTO_BASIC);
	} else {
		hdr = apr_psprintf(r->pool, "%s", OIDC_PROTO_BEARER);
	}

	if (ap_auth_name(r) != NULL)
		hdr = apr_psprintf(r->pool, "%s %s=\"%s\"", hdr, OIDC_PROTO_REALM, ap_auth_name(r));
	if (error != NULL)
		hdr =
		    apr_psprintf(r->pool, "%s%s %s=\"%s\"", hdr, (ap_auth_name(r) ? "," : ""), OIDC_PROTO_ERROR, error);
	if (error_description != NULL)
		hdr = apr_psprintf(r->pool, "%s, %s=\"%s\"", hdr, OIDC_PROTO_ERROR_DESCRIPTION, error_description);
	oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_WWW_AUTHENTICATE, hdr);
	return HTTP_UNAUTHORIZED;
}
