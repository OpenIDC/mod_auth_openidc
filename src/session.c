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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#include <apr_base64.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>

#include "mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/* the name of the remote-user attribute in the session  */
#define OIDC_SESSION_REMOTE_USER_KEY "r"
/* the name of the session expiry attribute in the session */
#define OIDC_SESSION_EXPIRY_KEY      "e"

static apr_byte_t oidc_session_encode(request_rec *r, oidc_cfg *c,
		oidc_session_t *z, char **s_value, apr_byte_t secure) {
	if (secure == FALSE) {
		char *s = json_dumps(z->state, JSON_COMPACT);
		*s_value = apr_pstrdup(r->pool, s);
		free(s);
		return TRUE;
	}

	if (oidc_util_jwt_create(r, c->crypto_passphrase, z->state,
			s_value) == FALSE)
		return FALSE;

	return TRUE;
}

static apr_byte_t oidc_session_decode(request_rec *r, oidc_cfg *c,
		oidc_session_t *z, const char *s_json, apr_byte_t secure) {
	if (secure == FALSE) {
		oidc_util_decode_json_object(r, s_json, &z->state);
		if (z->state == NULL) {
			oidc_error(r, "cached JSON parsing (json_loads) failed: (%s)",
					s_json);
			return FALSE;
		}
		return TRUE;
	}

	if (oidc_util_jwt_verify(r, c->crypto_passphrase, s_json,
			&z->state) == FALSE) {
		oidc_error(r,
				"could not verify secure JWT: cache value possibly corrupted");
		return FALSE;
	}
	return TRUE;
}

/*
 * load the session from the cache using the cookie as the index
 */
static apr_byte_t oidc_session_load_cache(request_rec *r, oidc_session_t *z) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	/* get the cookie that should be our uuid/key */
	char *uuid = oidc_util_get_cookie(r, oidc_cfg_dir_cookie(r));

	/* get the string-encoded session from the cache based on the key */
	if (uuid != NULL) {
		const char *s_json = NULL;
		c->cache->get(r, OIDC_CACHE_SECTION_SESSION, uuid, &s_json);
		if ((s_json != NULL)
				&& (oidc_session_decode(r, c, z, s_json, c->cache->secure)
						== FALSE))
			return FALSE;
		strncpy(z->uuid, uuid, strlen(uuid));
	}

	return TRUE;
}

/*
 * save the session to the cache using a cookie for the index
 */
static apr_byte_t oidc_session_save_cache(request_rec *r, oidc_session_t *z) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	apr_byte_t rc = TRUE;

	if (z->state != NULL) {

		if (apr_strnatcmp(z->uuid, "") == 0) {
			/* get a new uuid for this session */
			apr_uuid_t uuid;
			apr_uuid_get(&uuid);
			apr_uuid_format((char *) &z->uuid, &uuid);
		}

		/* store the string-encoded session in the cache */
		char *s_value = NULL;
		if (oidc_session_encode(r, c, z, &s_value, c->cache->secure) == FALSE)
			return FALSE;
		rc = c->cache->set(r, OIDC_CACHE_SECTION_SESSION, z->uuid, s_value,
				z->expiry);

		if (rc == TRUE)
			/* set the uuid in the cookie */
			oidc_util_set_cookie(r, oidc_cfg_dir_cookie(r), z->uuid,
					c->persistent_session_cookie ? z->expiry : -1);

	} else {
		/* clear the cookie */
		oidc_util_set_cookie(r, oidc_cfg_dir_cookie(r), "", 0);
	}

	return rc;
}

/*
 * load the session from a self-contained client-side cookie
 */
static apr_byte_t oidc_session_load_cookie(request_rec *r, oidc_cfg *c,
		oidc_session_t *z) {
	char *cookieValue = oidc_util_get_chunked_cookie(r, oidc_cfg_dir_cookie(r),
			c->session_cookie_chunk_size);
	if ((cookieValue != NULL)
			&& (oidc_session_decode(r, c, z, cookieValue, TRUE) == FALSE))
		return FALSE;
	return TRUE;
}

/*
 * store the session in a self-contained client-side-only cookie storage
 */
static apr_byte_t oidc_session_save_cookie(request_rec *r, oidc_session_t *z) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	char *cookieValue = "";
	if ((z->state != NULL)
			&& (oidc_session_encode(r, c, z, &cookieValue, TRUE) == FALSE))
		return FALSE;

	oidc_util_set_chunked_cookie(r, oidc_cfg_dir_cookie(r), cookieValue,
			c->persistent_session_cookie ? z->expiry : -1,
					c->session_cookie_chunk_size);

	return TRUE;
}

/*
 * load a session from the cache/cookie
 */
apr_byte_t oidc_session_load(request_rec *r, oidc_session_t **zz) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	/* allocate space for the session object and fill it */
	oidc_session_t *z = (*zz = apr_pcalloc(r->pool, sizeof(oidc_session_t)));

	strncpy(z->uuid, "", strlen(""));
	z->remote_user = NULL;
	z->state = NULL;

	if (c->session_type == OIDC_SESSION_TYPE_SERVER_CACHE) {
		/* load the session from the cache */
		oidc_session_load_cache(r, z);
	} else if (c->session_type == OIDC_SESSION_TYPE_CLIENT_COOKIE) {
		/* load the session from a self-contained cookie */
		oidc_session_load_cookie(r, c, z);
	} else {
		oidc_error(r, "unknown session type: %d", c->session_type);
	}

	if (z->state != NULL) {

		json_t *j_expires = json_object_get(z->state, OIDC_SESSION_EXPIRY_KEY);
		if (j_expires)
			z->expiry = apr_time_from_sec(json_integer_value(j_expires));

		/* check whether it has expired */
		if (apr_time_now() > z->expiry) {

			oidc_warn(r, "session restored from cache has expired");
			oidc_session_free(r, z);
			z->state = json_object();

		} else {

			oidc_session_get(r, z, OIDC_SESSION_REMOTE_USER_KEY,
					&z->remote_user);
		}
	} else {

		z->state = json_object();
	}

	return TRUE;
}

/*
 * save a session to cache/cookie
 */
apr_byte_t oidc_session_save(request_rec *r, oidc_session_t *z) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	apr_byte_t rc = TRUE;

	if (z->state != NULL) {
		oidc_session_set(r, z, OIDC_SESSION_REMOTE_USER_KEY, z->remote_user);
		json_object_set_new(z->state, OIDC_SESSION_EXPIRY_KEY,
				json_integer(apr_time_sec(z->expiry)));
	}

	if (c->session_type == OIDC_SESSION_TYPE_SERVER_CACHE) {
		/* store the session in the cache */
		rc = oidc_session_save_cache(r, z);
	} else if (c->session_type == OIDC_SESSION_TYPE_CLIENT_COOKIE) {
		/* store the session in a self-contained cookie */
		rc = oidc_session_save_cookie(r, z);
	} else {
		oidc_error(r, "unknown session type: %d", c->session_type);
		rc = FALSE;
	}

	return rc;
}

/*
 * free resources allocated for a session
 */
apr_byte_t oidc_session_free(request_rec *r, oidc_session_t *z) {
	if (z->state) {
		json_decref(z->state);
		z->state = NULL;
	}
	z->expiry = 0;
	return TRUE;
}

/*
 * terminate a session
 */
apr_byte_t oidc_session_kill(request_rec *r, oidc_session_t *z) {
	oidc_session_free(r, z);
	return oidc_session_save(r, z);
}

/*
 * get a value from the session based on the name from a name/value pair
 */
apr_byte_t oidc_session_get(request_rec *r, oidc_session_t *z, const char *key,
		const char **value) {

	/* just return the value for the key */
	oidc_json_object_get_string(r->pool, z->state, key, (char **) value, NULL);

	return TRUE;
}

/*
 * set a name/value key pair in the session
 */
apr_byte_t oidc_session_set(request_rec *r, oidc_session_t *z, const char *key,
		const char *value) {

	/* only set it if non-NULL, otherwise delete the entry */
	if (value) {
		json_object_set_new(z->state, key, json_string(value));
	} else {
		json_object_del(z->state, key);
	}
	return TRUE;
}

/*
 * session object keys
 */
/* key for storing the claims in the session context */
#define OIDC_SESSION_KEY_USERINFO_CLAIMS "uic"
/* key for storing the id_token in the session context */
#define OIDC_SESSION_KEY_IDTOKEN_CLAIMS "idc"
/* key for storing the raw id_token in the session context */
#define OIDC_SESSION_KEY_IDTOKEN "idt"
/* key for storing the access_token in the session context */
#define OIDC_SESSION_KEY_ACCESSTOKEN "at"
/* key for storing the access_token expiry in the session context */
#define OIDC_SESSION_KEY_ACCESSTOKEN_EXPIRES "ate"
/* key for storing the refresh_token in the session context */
#define OIDC_SESSION_KEY_REFRESH_TOKEN "rt"
/* key for storing maximum session duration in the session context */
#define OIDC_SESSION_KEY_SESSION_EXPIRES "se"
/* key for storing the cookie domain in the session context */
#define OIDC_SESSION_KEY_COOKIE_DOMAIN "cd"
/* key for storing last user info refresh timestamp in the session context */
#define OIDC_SESSION_KEY_USERINFO_LAST_REFRESH "uilr"
/* key for storing last access token refresh timestamp in the session context */
#define OIDC_SESSION_KEY_ACCESS_TOKEN_LAST_REFRESH "atlr"
/* key for storing request state */
#define OIDC_SESSION_KEY_REQUEST_STATE "rs"
/* key for storing the original URL */
#define OIDC_SESSION_KEY_ORIGINAL_URL "ou"
/* key for storing the session_state in the session context */
#define OIDC_SESSION_KEY_SESSION_STATE "ss"
/* key for storing the issuer in the session context */
#define OIDC_SESSION_KEY_ISSUER "iss"
/* key for storing the client_id in the session context */
#define OIDC_SESSION_KEY_CLIENT_ID "cid"
/* key for storing the check_session_iframe in the session context */
#define OIDC_SESSION_KEY_CHECK_SESSION_IFRAME "csi"
/* key for storing the end_session_endpoint in the session context */
#define OIDC_SESSION_KEY_LOGOUT_ENDPOINT "ese"

/*
 * helper functions
 */
typedef const char *(*oidc_session_get_str_function)(request_rec *r,
		oidc_session_t *z);

static void oidc_session_set_timestamp(request_rec *r, oidc_session_t *z,
		const char *key, const apr_time_t timestamp) {
	if (timestamp != -1)
		oidc_session_set(r, z, key,
				apr_psprintf(r->pool, "%" APR_TIME_T_FMT, timestamp));
}

static json_t *oidc_session_get_str2json(request_rec *r, oidc_session_t *z,
		oidc_session_get_str_function session_get_str_fn) {
	json_t *json = NULL;
	const char *str = session_get_str_fn(r, z);
	if (str != NULL)
		oidc_util_decode_json_object(r, str, &json);
	return json;
}

static const char *oidc_session_get_key2string(request_rec *r,
		oidc_session_t *z, const char *key) {
	const char *s_value = NULL;
	oidc_session_get(r, z, key, &s_value);
	return s_value;
}

static apr_time_t oidc_session_get_key2timestamp(request_rec *r,
		oidc_session_t *z, const char *key) {
	apr_time_t t_expires = 0;
	const char *s_expires = oidc_session_get_key2string(r, z, key);
	if (s_expires != NULL)
		sscanf(s_expires, "%" APR_TIME_T_FMT, &t_expires);
	return t_expires;
}

/*
 * userinfo claims
 */
void oidc_session_set_userinfo_claims(request_rec *r, oidc_session_t *z,
		const char *claims) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_USERINFO_CLAIMS, claims);
}

const char * oidc_session_get_userinfo_claims(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_USERINFO_CLAIMS);
}

json_t *oidc_session_get_userinfo_claims_json(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_str2json(r, z, oidc_session_get_userinfo_claims);
}

/*
 * id_token claims
 */
void oidc_session_set_idtoken_claims(request_rec *r, oidc_session_t *z,
		const char *idtoken_claims) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_IDTOKEN_CLAIMS, idtoken_claims);
}

const char * oidc_session_get_idtoken_claims(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_IDTOKEN_CLAIMS);
}

json_t *oidc_session_get_idtoken_claims_json(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_str2json(r, z, oidc_session_get_idtoken_claims);
}

/*
 * compact serialized id_token
 */
void oidc_session_set_idtoken(request_rec *r, oidc_session_t *z,
		const char *s_id_token) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_IDTOKEN, s_id_token);
}

const char * oidc_session_get_idtoken(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_IDTOKEN);
}

/*
 * access token
 */
void oidc_session_set_access_token(request_rec *r, oidc_session_t *z,
		const char *access_token) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_ACCESSTOKEN, access_token);
}

const char * oidc_session_get_access_token(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_ACCESSTOKEN);
}

/*
 * access token expires
 */
void oidc_session_set_access_token_expires(request_rec *r, oidc_session_t *z,
		const int expires_in) {
	if (expires_in != -1) {
		oidc_session_set(r, z, OIDC_SESSION_KEY_ACCESSTOKEN_EXPIRES,
				apr_psprintf(r->pool, "%" APR_TIME_T_FMT,
						apr_time_sec(apr_time_now()) + expires_in));
	}
}

const char * oidc_session_get_access_token_expires(request_rec *r,
		oidc_session_t *z) {
	return oidc_session_get_key2string(r, z,
			OIDC_SESSION_KEY_ACCESSTOKEN_EXPIRES);
}

/*
 * refresh token
 */
void oidc_session_set_refresh_token(request_rec *r, oidc_session_t *z,
		const char *refresh_token) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_REFRESH_TOKEN, refresh_token);
}

const char * oidc_session_get_refresh_token(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_REFRESH_TOKEN);
}

/*
 * session expires
 */
void oidc_session_set_session_expires(request_rec *r, oidc_session_t *z,
		const apr_time_t expires) {
	oidc_session_set_timestamp(r, z, OIDC_SESSION_KEY_SESSION_EXPIRES, expires);
}

apr_time_t oidc_session_get_session_expires(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2timestamp(r, z,
			OIDC_SESSION_KEY_SESSION_EXPIRES);
}

/*
 * cookie domain
 */
void oidc_session_set_cookie_domain(request_rec *r, oidc_session_t *z,
		const char *cookie_domain) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_COOKIE_DOMAIN, cookie_domain);
}

const char * oidc_session_get_cookie_domain(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_COOKIE_DOMAIN);
}

/*
 * userinfo last refresh
 */
void oidc_session_reset_userinfo_last_refresh(request_rec *r, oidc_session_t *z) {
	oidc_session_set_timestamp(r, z, OIDC_SESSION_KEY_USERINFO_LAST_REFRESH,
			apr_time_now());
}

apr_time_t oidc_session_get_userinfo_last_refresh(request_rec *r,
		oidc_session_t *z) {
	return oidc_session_get_key2timestamp(r, z,
			OIDC_SESSION_KEY_USERINFO_LAST_REFRESH);
}

/*
 * access_token last refresh
 */
void oidc_session_reset_access_token_last_refresh(request_rec *r, oidc_session_t *z) {
	oidc_session_set_timestamp(r, z, OIDC_SESSION_KEY_ACCESS_TOKEN_LAST_REFRESH,
			apr_time_now());
}

apr_time_t oidc_session_get_access_token_last_refresh(request_rec *r,
		oidc_session_t *z) {
	return oidc_session_get_key2timestamp(r, z,
			OIDC_SESSION_KEY_ACCESS_TOKEN_LAST_REFRESH);
}

/*
 * request state
 */
void oidc_session_set_request_state(request_rec *r, oidc_session_t *z,
		const char *request_state) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_REQUEST_STATE, request_state);
}

const char * oidc_session_get_request_state(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_REQUEST_STATE);
}

/*
 * original url
 */
void oidc_session_set_original_url(request_rec *r, oidc_session_t *z,
		const char *original_url) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_ORIGINAL_URL, original_url);
}

const char * oidc_session_get_original_url(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_ORIGINAL_URL);
}

/*
 * session state
 */
void oidc_session_set_session_state(request_rec *r, oidc_session_t *z,
		const char *session_state) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_SESSION_STATE, session_state);
}

const char * oidc_session_get_session_state(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_SESSION_STATE);
}

/*
 * issuer
 */
void oidc_session_set_issuer(request_rec *r, oidc_session_t *z,
		const char *issuer) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_ISSUER, issuer);
}

const char * oidc_session_get_issuer(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_ISSUER);
}

/*
 * client_id
 */
void oidc_session_set_client_id(request_rec *r, oidc_session_t *z,
		const char *client_id) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_CLIENT_ID, client_id);
}

const char * oidc_session_get_client_id(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_CLIENT_ID);
}

/*
 * check session iframe URL
 */
void oidc_session_set_check_session_iframe(request_rec *r, oidc_session_t *z,
		const char *check_session_iframe) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_CHECK_SESSION_IFRAME,
			check_session_iframe);
}

const char * oidc_session_get_check_session_iframe(request_rec *r,
		oidc_session_t *z) {
	return oidc_session_get_key2string(r, z,
			OIDC_SESSION_KEY_CHECK_SESSION_IFRAME);
}

/*
 * logout endpoint URL
 */
void oidc_session_set_logout_endpoint(request_rec *r, oidc_session_t *z,
		const char *logout_endpoint) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_LOGOUT_ENDPOINT, logout_endpoint);
}

const char * oidc_session_get_logout_endpoint(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_LOGOUT_ENDPOINT);
}
