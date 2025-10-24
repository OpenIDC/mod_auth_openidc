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
#include "util/util.h"

/*
 * PCKE "plain" proto state
 */
static apr_byte_t oidc_proto_pkce_state_plain(request_rec *r, char **state) {
	return oidc_util_rand_str(r, state, OIDC_PROTO_CODE_VERIFIER_LENGTH, FALSE);
}

/*
 * PCKE "plain" code_challenge
 */
static apr_byte_t oidc_proto_pkce_challenge_plain(request_rec *r, const char *state, char **code_challenge) {
	*code_challenge = apr_pstrdup(r->pool, state);
	return TRUE;
}

/*
 * PCKE "plain" code_verifier
 */
static apr_byte_t oidc_proto_pkce_verifier_plain(request_rec *r, const char *state, char **code_verifier) {
	*code_verifier = apr_pstrdup(r->pool, state);
	return TRUE;
}

/*
 * PCKE "s256" proto state
 */
static apr_byte_t oidc_proto_pkce_state_s256(request_rec *r, char **state) {
	return oidc_util_rand_str(r, state, OIDC_PROTO_CODE_VERIFIER_LENGTH, FALSE);
}

/*
 * PCKE "s256" code_challenge
 */
static apr_byte_t oidc_proto_pkce_challenge_s256(request_rec *r, const char *state, char **code_challenge) {
	if (oidc_util_hash_string_and_base64url_encode(r, OIDC_JOSE_ALG_SHA256, state, code_challenge) == FALSE) {
		oidc_error(r, "oidc_util_hash_string_and_base64url_encode returned an error for the code verifier");
		return FALSE;
	}
	return TRUE;
}

/*
 * PCKE "s256" code_verifier
 */
static apr_byte_t oidc_proto_pkce_verifier_s256(request_rec *r, const char *state, char **code_verifier) {
	*code_verifier = apr_pstrdup(r->pool, state);
	return TRUE;
}

/*
 * PKCE plain
 */
oidc_proto_pkce_t oidc_pkce_plain = {OIDC_PKCE_METHOD_PLAIN, oidc_proto_pkce_state_plain,
				     oidc_proto_pkce_verifier_plain, oidc_proto_pkce_challenge_plain};

/*
 * PKCE s256
 */
oidc_proto_pkce_t oidc_pkce_s256 = {OIDC_PKCE_METHOD_S256, oidc_proto_pkce_state_s256, oidc_proto_pkce_verifier_s256,
				    oidc_proto_pkce_challenge_s256};

/*
 * PKCE none
 */
oidc_proto_pkce_t oidc_pkce_none = {OIDC_PKCE_METHOD_NONE, NULL, NULL, NULL};
