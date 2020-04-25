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
 * Copyright (C) 2017-2020 ZmartZone IAM
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * Validation and parsing of configuration values.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#ifndef MOD_AUTH_OPENIDC_PARSE_H_
#define MOD_AUTH_OPENIDC_PARSE_H_

#include "apr_pools.h"

#define OIDC_CONFIG_STRING_UNSET  "_UNSET_"
#define OIDC_CONFIG_STRING_EMPTY  ""
#define OIDC_CONFIG_POS_INT_UNSET -1

#define OIDC_CLAIM_FORMAT_RELATIVE    "relative"
#define OIDC_CLAIM_FORMAT_ABSOLUTE    "absolute"
#define OIDC_CLAIM_REQUIRED_MANDATORY "mandatory"
#define OIDC_CLAIM_REQUIRED_OPTIONAL  "optional"

#define OIDC_PKCE_METHOD_PLAIN        "plain"
#define OIDC_PKCE_METHOD_S256         "S256"
#define OIDC_PKCE_METHOD_REFERRED_TB  "referred_tb"

#define OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC "client_secret_basic"

const char *oidc_valid_url(apr_pool_t *pool, const char *arg, const char *scheme);
const char *oidc_valid_http_url(apr_pool_t *pool, const char *arg);
const char *oidc_valid_dir(apr_pool_t *pool, const char *arg);
const char *oidc_valid_cookie_domain(apr_pool_t *pool, const char *arg);
const char *oidc_valid_endpoint_auth_method(apr_pool_t *pool,const char *arg);
const char *oidc_valid_endpoint_auth_method_no_private_key(apr_pool_t *pool, const char *arg);
const char *oidc_valid_response_type(apr_pool_t *pool, const char *arg);
const char *oidc_valid_pkce_method(apr_pool_t *pool, const char *arg);
const char *oidc_valid_response_mode(apr_pool_t *pool, const char *arg);
const char *oidc_valid_signed_response_alg(apr_pool_t *pool, const char *arg);
const char *oidc_valid_encrypted_response_alg(apr_pool_t *pool, const char *arg);
const char *oidc_valid_encrypted_response_enc(apr_pool_t *pool, const char *arg);
const char *oidc_valid_claim_format(apr_pool_t *pool, const char *arg);
const char *oidc_valid_introspection_method(apr_pool_t *pool, const char *arg);
const char *oidc_valid_session_max_duration(apr_pool_t *pool,  int v);
const char *oidc_valid_jwks_refresh_interval(apr_pool_t *pool, int v);
const char *oidc_valid_idtoken_iat_slack(apr_pool_t *pool, int v);
const char *oidc_valid_userinfo_refresh_interval(apr_pool_t *pool, int v);
const char *oidc_valid_userinfo_token_method(apr_pool_t *pool, const char *arg);
const char *oidc_valid_token_binding_policy(apr_pool_t *pool, const char *arg);
const char *oidc_valid_auth_request_method(apr_pool_t *pool, const char *arg);
const char *oidc_valid_max_number_of_state_cookies(apr_pool_t *pool, int v);

const char *oidc_parse_int(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_boolean(apr_pool_t *pool, const char *arg, int *bool_value);

const char *oidc_parse_cache_type(apr_pool_t *pool, const char *arg, oidc_cache_t **type);
const char *oidc_parse_session_type(apr_pool_t *pool, const char *arg, int *type, int *persistent);
const char *oidc_parse_cache_shm_entry_size_max(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_session_inactivity_timeout(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_session_max_duration(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_enc_kid_key_tuple(apr_pool_t *pool, const char *tuple, char **kid, char **key, int *key_len, apr_byte_t triplet);
const char *oidc_parse_pass_idtoken_as(apr_pool_t *pool, const char *v1, const char *v2, const char *v3, int *int_value);
const char *oidc_parse_pass_userinfo_as(apr_pool_t *pool, const char *v1, const char *v2, const char *v3, int *int_value);
const char *oidc_parse_logout_on_error_refresh_as(apr_pool_t *pool, const char *v1, int *int_value);
const char *oidc_parse_accept_oauth_token_in(apr_pool_t *pool, const char *arg, int *b_value, apr_hash_t *list_options);
const char *oidc_accept_oauth_token_in2str(apr_pool_t *pool, apr_byte_t v);
const char *oidc_parse_claim_required(apr_pool_t *pool, const char *arg, int *is_required);
const char *oidc_parse_set_claims_as(apr_pool_t *pool, const char *arg, int *in_headers, int *in_env_vars);
const char *oidc_parse_unauth_action(apr_pool_t *pool, const char *arg, int *action);
const char *oidc_parse_unautz_action(apr_pool_t *pool, const char *arg, int *action);
const char *oidc_parse_jwks_refresh_interval(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_idtoken_iat_slack(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_userinfo_refresh_interval(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_userinfo_token_method(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_info_hook_data(apr_pool_t *pool, const char *arg, apr_hash_t **hook_data);
const char *oidc_parse_token_binding_policy(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_token_binding_policy2str(apr_pool_t *pool, int v);
const char *oidc_parse_auth_request_method(apr_pool_t *pool, const char *arg, int *method);
const char *oidc_parse_max_number_of_state_cookies(apr_pool_t *pool, const char *arg1, const char *arg2, int *int_value, int *bool_value);
const char *oidc_parse_refresh_access_token_before_expiry(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_parse_set_state_input_headers_as(apr_pool_t *pool, const char *arg, apr_byte_t *state_input_headers);

typedef const char *(*oidc_valid_int_function_t)(apr_pool_t *, int);
typedef const char *(*oidc_valid_function_t)(apr_pool_t *, const char *);
const char *oidc_valid_string_in_array(apr_pool_t *pool, json_t *json, const char *key, oidc_valid_function_t valid_function, char **value, apr_byte_t optional, const char *preference);

#endif /* MOD_AUTH_OPENIDC_PARSE_H_ */
