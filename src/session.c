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

#include "cfg/dir.h"
#include "metrics.h"
#include "mod_auth_openidc.h"
#include "util/util.h"

/* the name of the remote-user attribute in the session  */
#define OIDC_SESSION_REMOTE_USER_KEY "r"
/* the name of the session expiry attribute in the session */
#define OIDC_SESSION_EXPIRY_KEY "e"
/* the name of the session identifier in the session */
#define OIDC_SESSION_SESSION_ID "i"
/* the name of the sub attribute in the session */
#define OIDC_SESSION_SUB_KEY "sub"
/* the name of the sid attribute in the session */
#define OIDC_SESSION_SID_KEY "sid"

/*
 * encode/serialize the session object/data into a string, possibly a serialized encrypted JWT when encryption is
 * requested
 */
static apr_byte_t oidc_session_encode(request_rec *r, oidc_cfg_t *c, oidc_session_t *z, char **s_value,
				      apr_byte_t encrypt) {

	if (encrypt == FALSE) {
		*s_value = oidc_util_json_encode(r->pool, z->state, JSON_COMPACT);
		return (*s_value != NULL);
	} else if (oidc_cfg_crypto_passphrase_secret1_get(c) == NULL) {
		oidc_error(r, "cannot encrypt session state because " OIDCCryptoPassphrase " is not set");
		return FALSE;
	}

	if (oidc_util_jwt_create(r, oidc_cfg_crypto_passphrase_get(c),
				 oidc_util_json_encode(r->pool, z->state, JSON_COMPACT), s_value) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * parse a session object from the provided string, which may be an encrypted JWT is encryption is on
 */
static apr_byte_t oidc_session_decode(request_rec *r, oidc_cfg_t *c, oidc_session_t *z, const char *s_json,
				      apr_byte_t encrypt) {
	char *s_payload = NULL;

	if (encrypt == FALSE) {
		return oidc_util_json_decode_object(r, s_json, &z->state);
	} else if (oidc_cfg_crypto_passphrase_secret1_get(c) == NULL) {
		oidc_error(r, "cannot decrypt session state because " OIDCCryptoPassphrase " is not set");
		return FALSE;
	}

	if (oidc_util_jwt_verify(r, oidc_cfg_crypto_passphrase_get(c), s_json, &s_payload) == FALSE) {
		oidc_error(r, "could not verify secure JWT: cache value possibly corrupted");
		return FALSE;
	}

	return oidc_util_json_decode_object(r, s_payload, &z->state);
}

/*
 * generate a unique identifier for a session
 */
void oidc_session_id_new(request_rec *r, oidc_session_t *z) {
	oidc_util_random_hexstr_gen(r, &z->uuid, 20);
}

/*
 * clear contents of a session
 */
static void oidc_session_clear(request_rec *r, oidc_session_t *z) {
	z->remote_user = NULL;
	// NB: don't clear sid or uuid
	z->expiry = 0;
	if (z->state) {
		json_decref(z->state);
		z->state = NULL;
	}
}

/*
 * load the session from the session cache, indexed by its uuid session id
 */
apr_byte_t oidc_session_load_cache_by_uuid(request_rec *r, oidc_cfg_t *c, const char *uuid, oidc_session_t *z) {
	char *stored_uuid = NULL;
	char *s_json = NULL;
	apr_byte_t rc = FALSE;

	rc = oidc_cache_get_session(r, uuid, &s_json);

	if ((rc == TRUE) && (s_json != NULL)) {
		rc = oidc_session_decode(r, c, z, s_json, FALSE);
		if (rc == TRUE) {
			z->uuid = apr_pstrdup(r->pool, uuid);

			/* compare the session id in the cache value so it allows  us to detect cache corruption */
			oidc_session_get(r, z, OIDC_SESSION_SESSION_ID, &stored_uuid);
			if ((stored_uuid == NULL) || (_oidc_strcmp(stored_uuid, uuid) != 0)) {
				oidc_error(r,
					   "cache corruption detected: stored session id (%s) is not equal to "
					   "requested session id (%s)",
					   stored_uuid, uuid);

				/* delete the cache entry */
				oidc_cache_set_session(r, z->uuid, NULL, 0);
				/* clear the session */
				oidc_session_clear(r, z);

				rc = FALSE;
			}
		}
	}

	return rc;
}

/*
 * load the session from the cache using the cookie as the index
 */
static apr_byte_t oidc_session_load_cache(request_rec *r, oidc_session_t *z) {
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	apr_byte_t rc = FALSE;

	/* get the cookie that should be our uuid/key */
	char *uuid = oidc_http_get_cookie(r, oidc_cfg_dir_cookie_get(r));

	/* get the string-encoded session from the cache based on the key; decryption is based on the cache backend
	 * config */
	if (uuid != NULL) {

		rc = oidc_session_load_cache_by_uuid(r, c, uuid, z);

		/* cache backend experienced an error while attempting lookup */
		if (rc == FALSE) {
			oidc_error(r, "cache backend failure for key %s", uuid);
			return FALSE;
		}

		/* cache backend does not contain an entry for the given key */
		if (z->state == NULL) {
			/* delete the session cookie */
			oidc_http_set_cookie(r, oidc_cfg_dir_cookie_get(r), "", 0,
					     OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r));
		}
	}

	return rc;
}

static const char *oidc_session_samesite_cookie(request_rec *r, struct oidc_cfg_t *c, int first_time) {
	const char *rv = NULL;
	switch (oidc_cfg_cookie_same_site_get(c)) {
	case OIDC_SAMESITE_COOKIE_STRICT:
		rv = first_time ? OIDC_HTTP_COOKIE_SAMESITE_LAX : OIDC_HTTP_COOKIE_SAMESITE_STRICT;
		break;
	case OIDC_SAMESITE_COOKIE_LAX:
		rv = OIDC_HTTP_COOKIE_SAMESITE_LAX;
		break;
	case OIDC_SAMESITE_COOKIE_NONE:
		rv = OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r);
		break;
	case OIDC_SAMESITE_COOKIE_DISABLED:
		break;
	default:
		break;
	}
	return rv;
}

/*
 * save the session to the cache using a cookie for the index
 */
static apr_byte_t oidc_session_save_cache(request_rec *r, oidc_session_t *z, apr_byte_t first_time) {
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	apr_byte_t rc = TRUE;

	if (z->state != NULL) {

		if (z->sid != NULL) {
			oidc_cache_set_sid(r, z->sid, z->uuid, z->expiry);
			oidc_session_set(r, z, OIDC_SESSION_SID_KEY, z->sid);
		}

		/* store the string-encoded session in the cache; encryption depends on cache backend settings */
		char *s_value = NULL;
		if (oidc_session_encode(r, c, z, &s_value, FALSE) == FALSE)
			return FALSE;

		rc = oidc_cache_set_session(r, z->uuid, s_value, z->expiry);
		if (rc == TRUE)
			/* set the uuid in the cookie */
			oidc_http_set_cookie(r, oidc_cfg_dir_cookie_get(r), z->uuid,
					     oidc_cfg_persistent_session_cookie_get(c) ? z->expiry : -1,
					     oidc_session_samesite_cookie(r, c, first_time));

	} else {

		if (z->sid != NULL)
			oidc_cache_set_sid(r, z->sid, NULL, 0);

		/* clear the cookie */
		oidc_http_set_cookie(r, oidc_cfg_dir_cookie_get(r), "", 0, OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r));

		/* remove the session from the cache */
		rc = oidc_cache_set_session(r, z->uuid, NULL, 0);
	}

	return rc;
}

/*
 * load the session from a self-contained client-side cookie
 */
static apr_byte_t oidc_session_load_cookie(request_rec *r, oidc_cfg_t *c, oidc_session_t *z) {
	char *cookieValue =
	    oidc_http_get_chunked_cookie(r, oidc_cfg_dir_cookie_get(r), oidc_cfg_session_cookie_chunk_size_get(c));
	if ((cookieValue != NULL) && (oidc_session_decode(r, c, z, cookieValue, TRUE) == FALSE))
		return FALSE;
	return TRUE;
}

/*
 * store the session in a self-contained client-side-only cookie storage
 */
static apr_byte_t oidc_session_save_cookie(request_rec *r, oidc_session_t *z, apr_byte_t first_time) {
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	char *cookieValue = "";
	if ((z->state != NULL) && (oidc_session_encode(r, c, z, &cookieValue, TRUE) == FALSE))
		return FALSE;

	oidc_http_set_chunked_cookie(
	    r, oidc_cfg_dir_cookie_get(r), cookieValue, oidc_cfg_persistent_session_cookie_get(c) ? z->expiry : -1,
	    oidc_cfg_session_cookie_chunk_size_get(c),
	    (z->state == NULL) ? OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r) : oidc_session_samesite_cookie(r, c, first_time));

	return TRUE;
}

/*
 * retrieve an integer from the session state
 */
static inline int oidc_session_get_int(request_rec *r, oidc_session_t *z, const char *key, int def_val) {
	int v;
	oidc_util_json_object_get_int(z->state, key, &v, def_val);
	return v;
}

/*
 * retrieve a timestamp from the session state
 */
static inline apr_time_t oidc_session_get_key2timestamp(request_rec *r, oidc_session_t *z, const char *key) {
	int value = -1;
	oidc_util_json_object_get_int(z->state, key, &value, -1);
	return (value > -1) ? apr_time_from_sec(value) : -1;
}

/*
 * parse data from the session state into the session struct members
 */
apr_byte_t oidc_session_extract(request_rec *r, oidc_session_t *z) {
	apr_byte_t rc = FALSE;

	if (z->state == NULL)
		goto out;

	/* check whether it has expired */
	z->expiry = oidc_session_get_key2timestamp(r, z, OIDC_SESSION_EXPIRY_KEY);
	if (apr_time_now() > z->expiry) {

		oidc_warn(r, "session restored from cache has expired");
		oidc_session_kill(r, z);

		goto out;
	}

	oidc_session_get(r, z, OIDC_SESSION_REMOTE_USER_KEY, &z->remote_user);
	oidc_session_get(r, z, OIDC_SESSION_SID_KEY, &z->sid);
	oidc_session_get(r, z, OIDC_SESSION_SESSION_ID, &z->uuid);

	rc = TRUE;

out:

	return rc;
}

/*
 * load a session from the cache/cookie
 */
apr_byte_t oidc_session_load(request_rec *r, oidc_session_t **zz) {
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	apr_byte_t rc = FALSE;

	/* allocate space for the session object and fill it */
	oidc_session_t *z = (*zz = apr_pcalloc(r->pool, sizeof(oidc_session_t)));
	oidc_session_clear(r, z);
	oidc_session_id_new(r, z);
	z->sid = NULL;

	if (oidc_cfg_session_type_get(c) == OIDC_SESSION_TYPE_SERVER_CACHE)
		/* load the session from the cache */
		rc = oidc_session_load_cache(r, z);

	/* if we get here we configured client-cookie or retrieving from the cache failed */
	if ((oidc_cfg_session_type_get(c) == OIDC_SESSION_TYPE_CLIENT_COOKIE) ||
	    ((rc == FALSE) && oidc_cfg_session_cache_fallback_to_cookie_get(c)))
		/* load the session from a self-contained cookie */
		rc = oidc_session_load_cookie(r, c, z);

	if (rc == TRUE)
		rc = oidc_session_extract(r, z);

	oidc_util_set_trace_parent(r, c, z->uuid);

	return rc;
}

/*
 * store an integer value into the session state
 */
static void oidc_session_set_int(request_rec *r, oidc_session_t *z, const char *key, int v) {
	if (z->state == NULL)
		z->state = json_object();
	json_object_set_new(z->state, key, json_integer(v));
}

/*
 * store a timestamp value into the session state
 */
static void oidc_session_set_timestamp(request_rec *r, oidc_session_t *z, const char *key, const apr_time_t timestamp) {
	if (timestamp > -1)
		oidc_session_set_int(r, z, key, apr_time_sec(timestamp));
}

/*
 * save a session to cache/cookie
 */
apr_byte_t oidc_session_save(request_rec *r, oidc_session_t *z, apr_byte_t first_time) {
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	apr_byte_t rc = FALSE;

	if (z->state != NULL) {
		oidc_session_set(r, z, OIDC_SESSION_REMOTE_USER_KEY, z->remote_user);
		oidc_session_set_timestamp(r, z, OIDC_SESSION_EXPIRY_KEY, z->expiry);
		oidc_session_set(r, z, OIDC_SESSION_SESSION_ID, z->uuid);
	}

	if (oidc_cfg_session_type_get(c) == OIDC_SESSION_TYPE_SERVER_CACHE)
		/* store the session in the cache */
		rc = oidc_session_save_cache(r, z, first_time);

	/* if we get here we configured client-cookie or saving in the cache failed */
	if ((oidc_cfg_session_type_get(c) == OIDC_SESSION_TYPE_CLIENT_COOKIE) ||
	    ((rc == FALSE) && oidc_cfg_session_cache_fallback_to_cookie_get(c)))
		/* store the session in a self-contained cookie */
		rc = oidc_session_save_cookie(r, z, first_time);

	return rc;
}

/*
 * free resources allocated for a session
 */
apr_byte_t oidc_session_free(request_rec *r, oidc_session_t *z) {
	oidc_session_clear(r, z);
	return TRUE;
}

/*
 * terminate a session
 */
apr_byte_t oidc_session_kill(request_rec *r, oidc_session_t *z) {
	r->user = NULL;
	if (z->state) {
		json_decref(z->state);
		z->state = NULL;
	}
	oidc_session_save(r, z, FALSE);
	return oidc_session_free(r, z);
}

/*
 * get a value from the session based on the name from a name/value pair
 */
apr_byte_t oidc_session_get(request_rec *r, oidc_session_t *z, const char *key, char **value) {

	/* just return the value for the key */
	oidc_util_json_object_get_string(r->pool, z->state, key, (char **)value, NULL);

	return TRUE;
}

/*
 * set a name/value key pair in the session
 */
apr_byte_t oidc_session_set(request_rec *r, oidc_session_t *z, const char *key, const char *value) {

	/* only set it if non-NULL, otherwise delete the entry */
	if (value) {
		if (z->state == NULL)
			z->state = json_object();
		json_object_set_new(z->state, key, json_string(value));
	} else if (z->state != NULL) {
		json_object_del(z->state, key);
	}

	return TRUE;
}

/*
 * session object keys
 */
/* key for storing the userinfo claims in the session context */
#define OIDC_SESSION_KEY_USERINFO_CLAIMS "uic"
/* key for storing the userinfo JWT in the session context */
#define OIDC_SESSION_KEY_USERINFO_JWT "uij"
/* key for storing the id_token in the session context */
#define OIDC_SESSION_KEY_IDTOKEN_CLAIMS "idc"
/* key for storing the raw id_token in the session context */
#define OIDC_SESSION_KEY_IDTOKEN "idt"
/* key for storing the access_token in the session context */
#define OIDC_SESSION_KEY_ACCESSTOKEN "at"
/* key for storing the access_token type in the session context */
#define OIDC_SESSION_KEY_ACCESSTOKEN_TYPE "att"
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
/* key for storing the provider specific user info refresh interval */
#define OIDC_SESSION_KEY_USERINFO_REFRESH_INTERVAL "uir"
/* key for storing whether this is a newly created session or not */
#define OIDC_SESSION_KEY_SESSION_IS_NEW "sn"
/* key for storing the scope in the session context */
#define OIDC_SESSION_KEY_SCOPE "scp"

/*
 * helper functions
 */
typedef const char *(*oidc_session_get_str_function)(request_rec *r, oidc_session_t *z);

static json_t *oidc_session_get_str2json(request_rec *r, oidc_session_t *z,
					 oidc_session_get_str_function session_get_str_fn) {
	json_t *json = NULL;
	const char *str = session_get_str_fn(r, z);
	if (str != NULL)
		oidc_util_json_decode_object(r, str, &json);
	return json;
}

static const char *oidc_session_get_key2string(request_rec *r, oidc_session_t *z, const char *key) {
	char *s_value = NULL;
	oidc_session_get(r, z, key, &s_value);
	return s_value;
}

#define OIDC_SESSION_WARN_CLAIM_SIZE 1024 * 8
#define OIDC_SESSION_WARN_CLAIM_SIZE_VAR "OIDC_SESSION_WARN_CLAIM_SIZE"

/*
 * apply whitelisting/blacklisting and a JQ filter  to the provided (serialized JSON) claims
 * session_key may refer to id_token claims or userinfo claims
 */
void oidc_session_set_filtered_claims(request_rec *r, oidc_session_t *z, const char *session_key, const char *claims) {
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	const char *name = NULL;
	json_t *src = NULL, *dst = NULL, *value = NULL;
	void *iter = NULL;
	apr_byte_t is_allowed = TRUE;
	int warn_claim_size = OIDC_SESSION_WARN_CLAIM_SIZE;
	const char *s = NULL;

	// avoid gcc 14 warning: '%s' directive argument is null [-Wformat-overflow=]
	if (session_key == NULL)
		session_key = "";

	if (oidc_util_json_decode_object(r, claims, &src) == FALSE) {
		oidc_session_set(r, z, session_key, NULL);
		return;
	}

	if (r->subprocess_env != NULL) {
		s = apr_table_get(r->subprocess_env, OIDC_SESSION_WARN_CLAIM_SIZE_VAR);
		if (s) {
			warn_claim_size = _oidc_str_to_int(s, OIDC_SESSION_WARN_CLAIM_SIZE);
			oidc_debug(r, "warn_claim_size set to %d in environment variable %s", warn_claim_size,
				   OIDC_SESSION_WARN_CLAIM_SIZE_VAR);
		}
	}

	dst = json_object();
	iter = json_object_iter(src);
	while (iter) {
		is_allowed = TRUE;
		name = json_object_iter_key(iter);
		value = json_object_iter_value(iter);

		if ((oidc_cfg_black_listed_claims_get(c) != NULL) &&
		    (apr_hash_get(oidc_cfg_black_listed_claims_get(c), name, APR_HASH_KEY_STRING) != NULL)) {
			oidc_debug(r, "removing blacklisted claim [%s]: '%s'", session_key, name);
			is_allowed = FALSE;
		}

		if ((is_allowed == TRUE) && (oidc_cfg_white_listed_claims_get(c) != NULL) &&
		    (apr_hash_get(oidc_cfg_white_listed_claims_get(c), name, APR_HASH_KEY_STRING) == NULL)) {
			oidc_debug(r, "removing non-whitelisted claim [%s]: '%s'", session_key, name);
			is_allowed = FALSE;
		}

		if (is_allowed == TRUE) {
			s = value ? oidc_util_json_encode(r->pool, value,
							  JSON_PRESERVE_ORDER | JSON_COMPACT | JSON_ENCODE_ANY)
				  : "";
			if (_oidc_strlen(s) > warn_claim_size)
				oidc_warn(r,
					  "(encoded) value size of [%s] claim \"%s\" is larger than %d; consider "
					  "blacklisting it in OIDCBlackListedClaims "
					  "or increase the warning limit with environment variable %s",
					  session_key, name, warn_claim_size, OIDC_SESSION_WARN_CLAIM_SIZE_VAR);
			json_object_set(dst, name, value);

			if (_oidc_strcmp(session_key, OIDC_SESSION_KEY_USERINFO_CLAIMS) == 0) {
				OIDC_METRICS_COUNTER_INC_NAME_VALUE(r, c, OM_CLAIM_USER_INFO, name,
								    json_is_string(value) ? json_string_value(value)
											  : s);
			} else {
				OIDC_METRICS_COUNTER_INC_NAME_VALUE(r, c, OM_CLAIM_ID_TOKEN, name,
								    json_is_string(value) ? json_string_value(value)
											  : s);
			}
		}

		iter = json_object_iter_next(src, iter);
	}

	const char *filtered_claims = oidc_util_json_encode(r->pool, dst, JSON_PRESERVE_ORDER | JSON_COMPACT);
	filtered_claims = oidc_util_jq_filter(r, filtered_claims,
					      oidc_util_apr_expr_exec(r, oidc_cfg_filter_claims_expr_get(c), TRUE));
	json_decref(dst);
	json_decref(src);
	oidc_session_set(r, z, session_key, filtered_claims);
}

/*
 * userinfo claims
 */
void oidc_session_set_userinfo_claims(request_rec *r, oidc_session_t *z, const char *claims) {
	oidc_session_set_filtered_claims(r, z, OIDC_SESSION_KEY_USERINFO_CLAIMS, claims);
}

const char *oidc_session_get_userinfo_claims(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_USERINFO_CLAIMS);
}

json_t *oidc_session_get_userinfo_claims_json(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_str2json(r, z, oidc_session_get_userinfo_claims);
}

void oidc_session_set_userinfo_jwt(request_rec *r, oidc_session_t *z, const char *s_userinfo_jwt) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_USERINFO_JWT, s_userinfo_jwt);
}

const char *oidc_session_get_userinfo_jwt(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_USERINFO_JWT);
}

/*
 * id_token claims
 */
void oidc_session_set_idtoken_claims(request_rec *r, oidc_session_t *z, const char *idtoken_claims) {
	if (apr_table_get(r->subprocess_env, "OIDC_DONT_STORE_ID_TOKEN_CLAIMS_IN_SESSION") == NULL)
		oidc_session_set_filtered_claims(r, z, OIDC_SESSION_KEY_IDTOKEN_CLAIMS, idtoken_claims);
}

const char *oidc_session_get_idtoken_claims(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_IDTOKEN_CLAIMS);
}

json_t *oidc_session_get_idtoken_claims_json(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_str2json(r, z, oidc_session_get_idtoken_claims);
}

/*
 * compact serialized id_token
 */
void oidc_session_set_idtoken(request_rec *r, oidc_session_t *z, const char *s_id_token) {
	oidc_debug(r, "storing id_token in the session");
	oidc_session_set(r, z, OIDC_SESSION_KEY_IDTOKEN, s_id_token);
}

const char *oidc_session_get_idtoken(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_IDTOKEN);
}

/*
 * access token
 */
void oidc_session_set_access_token(request_rec *r, oidc_session_t *z, const char *access_token) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_ACCESSTOKEN, access_token);
}

const char *oidc_session_get_access_token(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_ACCESSTOKEN);
}

/*
 * access token type
 */
void oidc_session_set_access_token_type(request_rec *r, oidc_session_t *z, const char *token_type) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_ACCESSTOKEN_TYPE, token_type);
}

const char *oidc_session_get_access_token_type(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_ACCESSTOKEN_TYPE);
}

/*
 * access token expires
 */
void oidc_session_set_access_token_expires(request_rec *r, oidc_session_t *z, const int expires_in) {
	if (expires_in > -1) {
		oidc_debug(r, "storing access token expires_in in the session: %d", expires_in);
		oidc_session_set_timestamp(r, z, OIDC_SESSION_KEY_ACCESSTOKEN_EXPIRES,
					   apr_time_now() + apr_time_from_sec(expires_in));
	}
}

apr_time_t oidc_session_get_access_token_expires(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2timestamp(r, z, OIDC_SESSION_KEY_ACCESSTOKEN_EXPIRES);
}

const char *oidc_session_get_access_token_expires2str(request_rec *r, oidc_session_t *z) {
	apr_time_t expires = oidc_session_get_access_token_expires(r, z);
	return (expires > -1) ? apr_psprintf(r->pool, "%" APR_TIME_T_FMT, apr_time_sec(expires)) : NULL;
}

/*
 * refresh token
 */
void oidc_session_set_refresh_token(request_rec *r, oidc_session_t *z, const char *refresh_token) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_REFRESH_TOKEN, refresh_token);
}

const char *oidc_session_get_refresh_token(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_REFRESH_TOKEN);
}

/*
 * session expires
 */
void oidc_session_set_session_expires(request_rec *r, oidc_session_t *z, const apr_time_t expires) {
	oidc_session_set_timestamp(r, z, OIDC_SESSION_KEY_SESSION_EXPIRES, expires);
}

apr_time_t oidc_session_get_session_expires(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2timestamp(r, z, OIDC_SESSION_KEY_SESSION_EXPIRES);
}

/*
 * cookie domain
 */
void oidc_session_set_cookie_domain(request_rec *r, oidc_session_t *z, const char *cookie_domain) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_COOKIE_DOMAIN, cookie_domain);
}

const char *oidc_session_get_cookie_domain(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_COOKIE_DOMAIN);
}

/*
 * userinfo last refresh
 */

void oidc_session_set_userinfo_refresh_interval(request_rec *r, oidc_session_t *z, const int interval) {
	oidc_session_set_int(r, z, OIDC_SESSION_KEY_USERINFO_REFRESH_INTERVAL, interval);
}

int oidc_session_get_userinfo_refresh_interval(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_int(r, z, OIDC_SESSION_KEY_USERINFO_REFRESH_INTERVAL, -1);
}

void oidc_session_reset_userinfo_last_refresh(request_rec *r, oidc_session_t *z) {
	oidc_session_set_timestamp(r, z, OIDC_SESSION_KEY_USERINFO_LAST_REFRESH, apr_time_now());
}

apr_time_t oidc_session_get_userinfo_last_refresh(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2timestamp(r, z, OIDC_SESSION_KEY_USERINFO_LAST_REFRESH);
}

/*
 * access_token last refresh
 */
void oidc_session_set_access_token_last_refresh(request_rec *r, oidc_session_t *z, apr_time_t ts) {
	oidc_session_set_timestamp(r, z, OIDC_SESSION_KEY_ACCESS_TOKEN_LAST_REFRESH, ts);
}

apr_time_t oidc_session_get_access_token_last_refresh(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2timestamp(r, z, OIDC_SESSION_KEY_ACCESS_TOKEN_LAST_REFRESH);
}

/*
 * request state
 */
void oidc_session_set_request_state(request_rec *r, oidc_session_t *z, const char *request_state) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_REQUEST_STATE, request_state);
}

const char *oidc_session_get_request_state(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_REQUEST_STATE);
}

/*
 * original url
 */
void oidc_session_set_original_url(request_rec *r, oidc_session_t *z, const char *original_url) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_ORIGINAL_URL, original_url);
}

const char *oidc_session_get_original_url(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_ORIGINAL_URL);
}

/*
 * session state
 */
void oidc_session_set_session_state(request_rec *r, oidc_session_t *z, const char *session_state) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_SESSION_STATE, session_state);
}

const char *oidc_session_get_session_state(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_SESSION_STATE);
}

/*
 * issuer
 */
void oidc_session_set_issuer(request_rec *r, oidc_session_t *z, const char *issuer) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_ISSUER, issuer);
}

const char *oidc_session_get_issuer(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_ISSUER);
}

/*
 * new session
 */
void oidc_session_set_session_new(request_rec *r, oidc_session_t *z, const int is_new) {
	if (z->state == NULL)
		z->state = json_object();
	if (is_new)
		json_object_set_new(z->state, OIDC_SESSION_KEY_SESSION_IS_NEW, json_integer(1));
	else
		json_object_del(z->state, OIDC_SESSION_KEY_SESSION_IS_NEW);
}

int oidc_session_get_session_new(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_int(r, z, OIDC_SESSION_KEY_SESSION_IS_NEW, 0);
}

/*
 * scope
 */
void oidc_session_set_scope(request_rec *r, oidc_session_t *z, const char *scope) {
	oidc_session_set(r, z, OIDC_SESSION_KEY_SCOPE, scope);
}

const char *oidc_session_get_scope(request_rec *r, oidc_session_t *z) {
	return oidc_session_get_key2string(r, z, OIDC_SESSION_KEY_SCOPE);
}
