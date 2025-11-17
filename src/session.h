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

#ifndef _MOD_AUTH_OPENIDC_SESSION_H_
#define _MOD_AUTH_OPENIDC_SESSION_H_

#include "cfg/cfg.h"
#include <apr_time.h>

typedef struct {
	char *uuid;	   /* unique id */
	char *remote_user; /* user who owns this particular session */
	json_t *state;	   /* the state for this session, encoded in a JSON object */
	apr_time_t expiry; /* if > 0, the time of expiry of this session */
	char *sid;
} oidc_session_t;

/* value that indicates to use server-side cache based session tracking */
#define OIDC_SESSION_TYPE_SERVER_CACHE 0
/* value that indicates to use client cookie based session tracking */
#define OIDC_SESSION_TYPE_CLIENT_COOKIE 1

apr_byte_t oidc_session_load(request_rec *r, oidc_session_t **z);
apr_byte_t oidc_session_save(request_rec *r, oidc_session_t *z, apr_byte_t first_time);
apr_byte_t oidc_session_kill(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_free(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_extract(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_load_cache_by_uuid(request_rec *r, oidc_cfg_t *c, const char *uuid, oidc_session_t *z);
void oidc_session_id_new(request_rec *r, oidc_session_t *z);

void oidc_session_set_userinfo_jwt(request_rec *r, oidc_session_t *z, const char *userinfo_jwt);
const char *oidc_session_get_userinfo_jwt(request_rec *r, oidc_session_t *z);
void oidc_session_set_userinfo_claims(request_rec *r, oidc_session_t *z, json_t *userinfo_claims);
json_t *oidc_session_get_userinfo_claims(request_rec *r, oidc_session_t *z);
void oidc_session_set_idtoken_claims(request_rec *r, oidc_session_t *z, json_t *idtoken_claims);
json_t *oidc_session_get_idtoken_claims(request_rec *r, oidc_session_t *z);
void oidc_session_set_idtoken(request_rec *r, oidc_session_t *z, const char *s_id_token);
const char *oidc_session_get_idtoken(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token(request_rec *r, oidc_session_t *z, const char *access_token);
const char *oidc_session_get_access_token(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token_type(request_rec *r, oidc_session_t *z, const char *token_type);
const char *oidc_session_get_access_token_type(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token_expires(request_rec *r, oidc_session_t *z, const int expires_in);
apr_time_t oidc_session_get_access_token_expires(request_rec *r, oidc_session_t *z);
const char *oidc_session_get_access_token_expires2str(request_rec *r, oidc_session_t *z);
void oidc_session_set_refresh_token(request_rec *r, oidc_session_t *z, const char *refresh_token);
const char *oidc_session_get_refresh_token(request_rec *r, oidc_session_t *z);
void oidc_session_set_session_expires(request_rec *r, oidc_session_t *z, const apr_time_t expires);
apr_time_t oidc_session_get_session_expires(request_rec *r, oidc_session_t *z);
void oidc_session_set_cookie_domain(request_rec *r, oidc_session_t *z, const char *cookie_domain);
const char *oidc_session_get_cookie_domain(request_rec *r, oidc_session_t *z);
void oidc_session_reset_userinfo_last_refresh(request_rec *r, oidc_session_t *z);
void oidc_session_set_userinfo_refresh_interval(request_rec *r, oidc_session_t *z, const int interval);
int oidc_session_get_userinfo_refresh_interval(request_rec *r, oidc_session_t *z);
apr_time_t oidc_session_get_userinfo_last_refresh(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token_last_refresh(request_rec *r, oidc_session_t *z, apr_time_t ts);
apr_time_t oidc_session_get_access_token_last_refresh(request_rec *r, oidc_session_t *z);
void oidc_session_set_request_state(request_rec *r, oidc_session_t *z, const char *request_state);
const char *oidc_session_get_request_state(request_rec *r, oidc_session_t *z);
void oidc_session_set_original_url(request_rec *r, oidc_session_t *z, const char *original_url);
const char *oidc_session_get_original_url(request_rec *r, oidc_session_t *z);
void oidc_session_set_session_state(request_rec *r, oidc_session_t *z, const char *session_state);
const char *oidc_session_get_session_state(request_rec *r, oidc_session_t *z);
void oidc_session_set_issuer(request_rec *r, oidc_session_t *z, const char *issuer);
const char *oidc_session_get_issuer(request_rec *r, oidc_session_t *z);
void oidc_session_set_client_id(request_rec *r, oidc_session_t *z, const char *client_id);
void oidc_session_set_session_new(request_rec *r, oidc_session_t *z, const int is_new);
int oidc_session_get_session_new(request_rec *r, oidc_session_t *z);
const char *oidc_session_get_scope(request_rec *r, oidc_session_t *z);
void oidc_session_set_scope(request_rec *r, oidc_session_t *z, const char *scope);

#endif /* _MOD_AUTH_OPENIDC_SESSION_H_ */
