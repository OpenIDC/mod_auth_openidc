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

#include "mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

// authz.c
typedef apr_byte_t (*oidc_authz_match_claim_fn_type)(request_rec *, const char *const, json_t *);
apr_byte_t oidc_authz_match_claim(request_rec *r, const char *const attr_spec, json_t *claims);
#if HAVE_APACHE_24
#ifdef USE_LIBJQ
authz_status oidc_authz_24_checker_claims_expr(request_rec *r, const char *require_args,
					       const void *parsed_require_args);
#endif
authz_status oidc_authz_24_checker_claim(request_rec *r, const char *require_args, const void *parsed_require_args);
authz_status oidc_authz_24_worker(request_rec *r, json_t *claims, const char *require_args,
				  const void *parsed_require_args, oidc_authz_match_claim_fn_type match_claim_fn);
#else
int oidc_authz_22_checker(request_rec *r);
#endif

// content.c
int oidc_content_handler(request_rec *r);

// discovery.c
int oidc_discovery_request(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_is_discovery_response(request_rec *r, oidc_cfg *cfg);
int oidc_discovery_response(request_rec *r, oidc_cfg *c);

// info.c
int oidc_info_request(request_rec *r, oidc_cfg *c, oidc_session_t *session, apr_byte_t needs_save);

// jwks_c.
int oidc_jwks_request(request_rec *r, oidc_cfg *c);

// logout.c
int oidc_logout(request_rec *r, oidc_cfg *c, oidc_session_t *session);
int oidc_logout_request(request_rec *r, oidc_cfg *c, oidc_session_t *session, const char *url,
			apr_byte_t revoke_tokens);

// refresh.c
apr_byte_t oidc_refresh_token_grant(request_rec *r, oidc_cfg *c, oidc_session_t *session, oidc_provider_t *provider,
				    char **new_access_token, char **new_id_token);
int oidc_refresh_token_request(request_rec *r, oidc_cfg *c, oidc_session_t *session);
apr_byte_t oidc_refresh_access_token_before_expiry(request_rec *r, oidc_cfg *cfg, oidc_session_t *session,
						   int ttl_minimum, apr_byte_t *needs_save);

// request_uri.c
void oidc_request_uri_add_request_param(request_rec *r, struct oidc_provider_t *provider, const char *redirect_uri,
					apr_table_t *params);
int oidc_request_uri(request_rec *r, oidc_cfg *c);

// request.c
int oidc_request_authenticate_user(request_rec *r, oidc_cfg *c, oidc_provider_t *provider, const char *original_url,
				   const char *login_hint, const char *id_token_hint, const char *prompt,
				   const char *auth_request_params, const char *path_scope);

// response.c
apr_byte_t oidc_response_post_preserve_javascript(request_rec *r, const char *location, char **javascript,
						  char **javascript_method);
char *oidc_response_make_sid_iss_unique(request_rec *r, const char *sid, const char *issuer);
int oidc_response_authorization_redirect(request_rec *r, oidc_cfg *c, oidc_session_t *session);
int oidc_response_authorization_post(request_rec *r, oidc_cfg *c, oidc_session_t *session);

// revoke.c
int oidc_revoke_session(request_rec *r, oidc_cfg *c);
int oidc_revoke_at_cache_remove(request_rec *r, oidc_cfg *c);

// session_management.c
int oidc_session_management(request_rec *r, oidc_cfg *c, oidc_session_t *session);

// userinfo.c
void oidc_userinfo_store_claims(request_rec *r, oidc_cfg *c, oidc_session_t *session, oidc_provider_t *provider,
				const char *claims, const char *userinfo_jwt);
const char *oidc_userinfo_retrieve_claims(request_rec *r, oidc_cfg *c, oidc_provider_t *provider,
					  const char *access_token, oidc_session_t *session, char *id_token_sub,
					  char **userinfo_jwt);
apr_byte_t oidc_userinfo_refresh_claims(request_rec *r, oidc_cfg *cfg, oidc_session_t *session, apr_byte_t *needs_save);
