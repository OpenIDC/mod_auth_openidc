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
 * Copyright (C) 2013-2017 Ping Identity Corporation
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

#ifndef _MOD_AUTH_OPENIDC_H_
#define _MOD_AUTH_OPENIDC_H_

#include "cfg/cfg.h"
#include "cfg/provider.h"
#include "session.h"

#define OIDC_AUTH_TYPE_OPENID_CONNECT "openid-connect"
#define OIDC_AUTH_TYPE_OPENID_OAUTH20 "oauth20"
#define OIDC_AUTH_TYPE_OPENID_BOTH "auth-openidc"

/* keys for storing info in the request state */
#define OIDC_REQUEST_STATE_KEY_IDTOKEN "i"
#define OIDC_REQUEST_STATE_KEY_CLAIMS "c"
#define OIDC_REQUEST_STATE_KEY_DISCOVERY "d"
#define OIDC_REQUEST_STATE_KEY_AUTHN "a"
#define OIDC_REQUEST_STATE_KEY_SAVE "s"
#define OIDC_REQUEST_STATE_TRACE_ID "t"

/* parameter name of the original method in the discovery response */
#define OIDC_DISC_RM_PARAM "method"

/* default prefix for information passed in HTTP headers */
#define OIDC_DEFAULT_HEADER_PREFIX "OIDC_"

/* the (global) key for the mod_auth_openidc related state that is stored in the request userdata context */
#define OIDC_USERDATA_KEY "mod_auth_openidc_state"
#define OIDC_USERDATA_SESSION "mod_auth_openidc_session"
#define OIDC_USERDATA_POST_PARAMS_KEY "oidc_userdata_post_params"

#define OIDC_POST_PRESERVE_ESCAPE_NONE 0
#define OIDC_POST_PRESERVE_ESCAPE_HTML 1
#define OIDC_POST_PRESERVE_ESCAPE_JAVASCRIPT 2

/* defines for how long provider metadata will be cached */
#define OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT 86400

/* define the parameter value for the "logout" request that indicates a GET-style logout call from the OP */
#define OIDC_GET_STYLE_LOGOUT_PARAM_VALUE "get"
#define OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE "img"
#define OIDC_BACKCHANNEL_STYLE_LOGOUT_PARAM_VALUE "backchannel"

/* http methods */
#define OIDC_METHOD_GET "get"
#define OIDC_METHOD_FORM_POST "form_post"

#define OIDC_REDIRECT_URI_REQUEST_INFO "info"
#define OIDC_REDIRECT_URI_REQUEST_DPOP "dpop"
#define OIDC_REDIRECT_URI_REQUEST_LOGOUT "logout"
#define OIDC_REDIRECT_URI_REQUEST_JWKS "jwks"
#define OIDC_REDIRECT_URI_REQUEST_SESSION "session"
#define OIDC_REDIRECT_URI_REQUEST_REFRESH "refresh"
#define OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE "remove_at_cache"
#define OIDC_REDIRECT_URI_REQUEST_REVOKE_SESSION "revoke_session"
#define OIDC_REDIRECT_URI_REQUEST_REQUEST_URI "request_uri"
#define OIDC_REDIRECT_URI_REQUEST_SID "sid"
#define OIDC_REDIRECT_URI_REQUEST_ISS "iss"

#define OIDC_CLAIM_ISS "iss"
#define OIDC_CLAIM_AUD "aud"
#define OIDC_CLAIM_AZP "azp"
#define OIDC_CLAIM_SUB "sub"
#define OIDC_CLAIM_JTI "jti"
#define OIDC_CLAIM_EXP "exp"
#define OIDC_CLAIM_IAT "iat"
#define OIDC_CLAIM_NBF "nbf"
#define OIDC_CLAIM_NONCE "nonce"
#define OIDC_CLAIM_AT_HASH "at_hash"
#define OIDC_CLAIM_C_HASH "c_hash"
#define OIDC_CLAIM_RFP "rfp"
#define OIDC_CLAIM_TARGET_LINK_URI "target_link_uri"
#define OIDC_CLAIM_SID "sid"
#define OIDC_CLAIM_EVENTS "events"
#define OIDC_CLAIM_TYP "typ"
#define OIDC_CLAIM_JWK "jwk"
#define OIDC_CLAIM_HTM "htm"
#define OIDC_CLAIM_HTU "htu"
#define OIDC_CLAIM_ATH "ath"

#define OIDC_APP_INFO_REFRESH_TOKEN "refresh_token"
#define OIDC_APP_INFO_ACCESS_TOKEN "access_token"
#define OIDC_APP_INFO_ACCESS_TOKEN_EXP "access_token_expires"
#define OIDC_APP_INFO_ID_TOKEN "id_token"
#define OIDC_APP_INFO_ID_TOKEN_PAYLOAD "id_token_payload"
#define OIDC_APP_INFO_USERINFO_JSON "userinfo_json"
#define OIDC_APP_INFO_USERINFO_JWT "userinfo_jwt"
#define OIDC_APP_INFO_SIGNED_JWT "signed_jwt"

#define OIDC_COOKIE_EXT_SAME_SITE_LAX "SameSite=Lax"
#define OIDC_COOKIE_EXT_SAME_SITE_STRICT "SameSite=Strict"
#define OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r) oidc_util_request_is_secure(r, c) ? "SameSite=None" : NULL

int oidc_check_user_id(request_rec *r);
int oidc_fixups(request_rec *r);
apr_byte_t oidc_enabled(request_rec *r);
void oidc_request_state_set(request_rec *r, const char *key, const char *value);
const char *oidc_request_state_get(request_rec *r, const char *key);
void oidc_scrub_headers(request_rec *r);
void oidc_strip_cookies(request_rec *r);
apr_byte_t oidc_get_remote_user(request_rec *r, const char *claim_name, const char *replace, const char *reg_exp,
				json_t *json, char **request_user);
apr_byte_t oidc_get_provider_from_session(request_rec *r, oidc_cfg_t *c, oidc_session_t *session,
					  oidc_provider_t **provider);
apr_byte_t oidc_session_pass_tokens(request_rec *r, oidc_cfg_t *cfg, oidc_session_t *session, apr_byte_t *needs_save);
void oidc_log_session_expires(request_rec *r, const char *msg, apr_time_t session_expires);
apr_byte_t oidc_provider_static_config(request_rec *r, oidc_cfg_t *c, oidc_provider_t **provider);
const char *oidc_original_request_method(request_rec *r, oidc_cfg_t *cfg, apr_byte_t handle_discovery_response);
oidc_provider_t *oidc_get_provider_for_issuer(request_rec *r, oidc_cfg_t *c, const char *issuer,
					      apr_byte_t allow_discovery);
char *oidc_get_state_cookie_name(request_rec *r, const char *state);
int oidc_clean_expired_state_cookies(request_rec *r, oidc_cfg_t *c, const char *currentCookieName, int delete_oldest);
char *oidc_get_browser_state_hash(request_rec *r, oidc_cfg_t *c, const char *nonce);
apr_byte_t oidc_is_auth_capable_request(request_rec *r);
apr_byte_t oidc_validate_redirect_url(request_rec *r, oidc_cfg_t *c, const char *redirect_to_url,
				      apr_byte_t restrict_to_host, char **err_str, char **err_desc);

#endif /* _MOD_AUTH_OPENIDC_H_ */
