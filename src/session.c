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
 * Copyright (C) 2013-2016 Ping Identity Corporation
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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <apr_base64.h>
#include <apr_uuid.h>
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
		z->state = json_loads(s_json, 0, 0);
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

	/* check for an old cache entry */
	char *oldkey = oidc_util_get_cookie(r, oidc_cfg_dir_cookie(r));

	if (oldkey != NULL) {
		/* remove the old session from the cache */
		rc = c->cache->set(r, OIDC_CACHE_SECTION_SESSION, oldkey, NULL, 0);
	}

	if (z->state != NULL) {
		/* get a new uuid for this session */
		apr_uuid_t uuid;
		apr_uuid_get(&uuid);
		char key[APR_UUID_FORMATTED_LENGTH + 1];
		apr_uuid_format((char *) &key, &uuid);

		/* store the string-encoded session in the cache */
		char *s_value = NULL;
		if (oidc_session_encode(r, c, z, &s_value, c->cache->secure) == FALSE)
			return FALSE;
		rc = c->cache->set(r, OIDC_CACHE_SECTION_SESSION, key, s_value,
				z->expiry);

		if (rc == TRUE)
			/* set the uuid in the cookie */
			oidc_util_set_cookie(r, oidc_cfg_dir_cookie(r), key,
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
