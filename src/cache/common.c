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
 * Copyright (C) 2017-2023 ZmartZone Holding BV
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
 * core cache functions: locking, crypto and utils
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#ifndef WIN32
#include <unistd.h>
#endif

#include "mod_auth_openidc.h"

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/* create the cache lock context */
oidc_cache_mutex_t* oidc_cache_mutex_create(apr_pool_t *pool, apr_byte_t global) {
	oidc_cache_mutex_t *ctx = apr_pcalloc(pool, sizeof(oidc_cache_mutex_t));
	ctx->gmutex = NULL;
	ctx->pmutex = NULL;
	ctx->mutex_filename = NULL;
	ctx->is_parent = TRUE;
	ctx->is_global = global;
	return ctx;
}

#define OIDC_CACHE_ERROR_STR_MAX 255

/*
 * convert a apr status code to a string
 */
char* oidc_cache_status2str(apr_pool_t *p, apr_status_t statcode) {
	char buf[OIDC_CACHE_ERROR_STR_MAX];
	apr_strerror(statcode, buf, OIDC_CACHE_ERROR_STR_MAX);
	return apr_pstrdup(p, buf);
}

apr_byte_t oidc_cache_mutex_post_config(server_rec *s, oidc_cache_mutex_t *m,
		const char *type) {

	apr_status_t rv = APR_SUCCESS;
	const char *dir;

	/* construct the mutex filename */
	apr_temp_dir_get(&dir, s->process->pool);
	m->mutex_filename = apr_psprintf(s->process->pool,
			"%s/mod_auth_openidc_%s_mutex.%ld.%pp", dir, type,
			(long int) getpid(), s);

	/* set the lock type */
	apr_lockmech_e mech =
#ifdef OIDC_LOCK
			OIDC_LOCK
#elif APR_HAS_POSIXSEM_SERIALIZE
			APR_LOCK_POSIXSEM
#else
			APR_LOCK_DEFAULT
#endif
			;

	/* create the mutex lock */
	if (m->is_global)
		rv = apr_global_mutex_create(&m->gmutex,
				(const char*) m->mutex_filename, mech, s->process->pool);
	else
		rv = apr_proc_mutex_create(&m->pmutex, (const char*) m->mutex_filename,
				mech, s->process->pool);

	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"apr_global_mutex_create/apr_proc_mutex_create failed to create mutex (%d) on file %s: %s (%d)",
				mech, m->mutex_filename,
				oidc_cache_status2str(s->process->pool, rv), rv);
		return FALSE;
	}

	/* need this on Linux */
#ifdef AP_NEED_SET_MUTEX_PERMS
	if (m->is_global) {
#if MODULE_MAGIC_NUMBER_MAJOR >= 20081201
		rv = ap_unixd_set_global_mutex_perms(m->gmutex);
#else
		rv = unixd_set_global_mutex_perms(m->gmutex);
#endif
		if (rv != APR_SUCCESS) {
			oidc_serror(s,
					"unixd_set_global_mutex_perms failed; could not set permissions: %s (%d)",
					oidc_cache_status2str(s->process->pool, rv), rv);
			return FALSE;
		}
	}
#endif

	oidc_slog(s, APLOG_TRACE1, "create: %pp (m=%pp,s=%pp, p=%d)", m,
			m->gmutex ? m->gmutex : 0, s, m->is_parent);

	return TRUE;
}

/*
 * initialize the cache lock in a child process
 */
apr_status_t oidc_cache_mutex_child_init(apr_pool_t *p, server_rec *s,
		oidc_cache_mutex_t *m) {

	oidc_slog(s, APLOG_TRACE1, "init: %pp (m=%pp,s=%pp, p=%d)", m,
			m->gmutex ? m->gmutex : 0, s, m->is_parent);

	if (m->is_parent == FALSE)
		return APR_SUCCESS;

	/* initialize the lock for the child process */
	apr_status_t rv;

	if (m->is_global)
		rv = apr_global_mutex_child_init(&m->gmutex,
				(const char*) m->mutex_filename, p);
	else
		rv = apr_proc_mutex_child_init(&m->pmutex,
				(const char*) m->mutex_filename, p);

	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"apr_global_mutex_child_init/apr_proc_mutex_child_init failed to reopen mutex on file %s: %s (%d)",
				m->mutex_filename, oidc_cache_status2str(p, rv), rv);
	}

	m->is_parent = FALSE;

	return rv;
}

/*
 * mutex lock
 */
apr_byte_t oidc_cache_mutex_lock(apr_pool_t *pool, server_rec *s,
		oidc_cache_mutex_t *m) {

	apr_status_t rv;

	if (m->is_global)
		rv = apr_global_mutex_lock(m->gmutex);
	else
		rv = apr_proc_mutex_lock(m->pmutex);

	if (rv != APR_SUCCESS)
		oidc_serror(s,
				"apr_global_mutex_lock/apr_proc_mutex_lock failed: %s (%d)",
				oidc_cache_status2str(pool, rv), rv);

	return TRUE;
}

/*
 * mutex unlock
 */
apr_byte_t oidc_cache_mutex_unlock(apr_pool_t *pool, server_rec *s,
		oidc_cache_mutex_t *m) {

	apr_status_t rv;

	if (m->is_global)
		rv = apr_global_mutex_unlock(m->gmutex);
	else
		rv = apr_proc_mutex_unlock(m->pmutex);

	if (rv != APR_SUCCESS)
		oidc_serror(s,
				"apr_global_mutex_unlock/apr_proc_mutex_unlock failed: %s (%d)",
				oidc_cache_status2str(pool, rv), rv);

	return TRUE;
}

/*
 * destroy mutex
 */
apr_byte_t oidc_cache_mutex_destroy(server_rec *s, oidc_cache_mutex_t *m) {

	apr_status_t rv = APR_SUCCESS;

	oidc_slog(s, APLOG_TRACE1, "init: %pp (m=%pp,s=%pp, p=%d)", m,
			m->gmutex ? m->gmutex : 0, s, m->is_parent);

	if ((m) && (m->is_parent == TRUE)) {
		if ((m->is_global) && (m->gmutex)) {
			rv = apr_global_mutex_destroy(m->gmutex);
			m->gmutex = NULL;
		} else if (m->pmutex) {
			rv = apr_proc_mutex_destroy(m->pmutex);
			m->pmutex = NULL;
		}
		oidc_sdebug(s,
				"apr_global_mutex_destroy/apr_proc_mutex_destroy returned :%d",
				rv);
	}

	return (rv == APR_SUCCESS);
}

/*
 * AES GCM encrypt using the crypto passphrase as symmetric key
 */
static apr_byte_t oidc_cache_crypto_encrypt(request_rec *r,
		const char *plaintext, const char *key, char **result) {
	return oidc_util_jwt_create(r, key, plaintext, result);
}

/*
 * AES GCM decrypt using the crypto passphrase as symmetric key
 */
static apr_byte_t oidc_cache_crypto_decrypt(request_rec *r,
		const char *cache_value, const char *key, char **plaintext) {
	return oidc_util_jwt_verify(r, key, cache_value, plaintext);
}

/*
 * hash a cache key and a crypto passphrase so the result is suitable as an randomized cache key
 */
static char* oidc_cache_get_hashed_key(request_rec *r, const char *passphrase,
		const char *key) {
	const char *input = apr_psprintf(r->pool, "%s:%s", passphrase, key);
	char *output = NULL;
	if (oidc_util_hash_string_and_base64url_encode(r, OIDC_JOSE_ALG_SHA256,
			input, &output) == FALSE) {
		oidc_error(r,
				"oidc_util_hash_string_and_base64url_encode returned an error");
		return NULL;
	}
	return output;
}

/*
 * get a key/value string pair from the cache, possibly decrypting it
 */
apr_byte_t oidc_cache_get(request_rec *r, const char *section, const char *key,
		char **value) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	int encrypted = oidc_cfg_cache_encrypt(r);
	apr_byte_t rc = TRUE;
	char *msg = NULL;
	char *cache_value = NULL;

	oidc_debug(r, "enter: %s (section=%s, decrypt=%d, type=%s)", key, section,
			encrypted, cfg->cache->name);

	/* see if encryption is turned on */
	if (encrypted == 1)
		key = oidc_cache_get_hashed_key(r, cfg->crypto_passphrase, key);

	/* get the value from the cache */
	if (cfg->cache->get(r, section, key, &cache_value) == FALSE) {
		rc = FALSE;
		goto out;
	}

	/* see if it is any good */
	if (cache_value == NULL)
		goto out;

	/* see if encryption is turned on */
	if (encrypted == 0) {
		*value = apr_pstrdup(r->pool, cache_value);
		goto out;
	}

	if (cfg->crypto_passphrase == NULL) {
		oidc_error(r,
				"could not decrypt cache entry because " OIDCCryptoPassphrase " is not set");
		goto out;
	}

	rc = oidc_cache_crypto_decrypt(r, cache_value, cfg->crypto_passphrase,
			value);

out:
	/* log the result */
	msg = apr_psprintf(r->pool, "from %s cache backend for %skey %s",
			cfg->cache->name, encrypted ? "encrypted " : "", key);
	if (rc == TRUE)
		if (*value != NULL)
			oidc_debug(r, "cache hit: return %d bytes %s",
					*value ? (int )_oidc_strlen(*value) : 0, msg);
		else
			oidc_debug(r, "cache miss %s", msg);
	else
		oidc_warn(r, "error retrieving value %s", msg);

	return rc;
}

/*
 * store a key/value string pair in the cache, possibly in encrypted form
 */
apr_byte_t oidc_cache_set(request_rec *r, const char *section, const char *key,
		const char *value, apr_time_t expiry) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	int encrypted = oidc_cfg_cache_encrypt(r);
	char *encoded = NULL;
	apr_byte_t rc = FALSE;
	char *msg = NULL;

	oidc_debug(r,
			"enter: %s (section=%s, len=%d, encrypt=%d, ttl(s)=%" APR_TIME_T_FMT ", type=%s)",
			key, section, value ? (int )_oidc_strlen(value) : 0, encrypted,
					apr_time_sec(expiry - apr_time_now()), cfg->cache->name);

	/* see if we need to encrypt */
	if (encrypted == 1) {

		key = oidc_cache_get_hashed_key(r, cfg->crypto_passphrase, key);
		if (key == NULL)
			goto out;

		if (value != NULL) {
			if (cfg->crypto_passphrase == NULL) {
				oidc_error(r,
						"could not encrypt cache entry because " OIDCCryptoPassphrase " is not set");
				goto out;
			}
			if (oidc_cache_crypto_encrypt(r, value, cfg->crypto_passphrase,
					&encoded) == FALSE)
				goto out;
			value = encoded;
		}
	}

	/* store the resulting value in the cache */
	rc = cfg->cache->set(r, section, key, value, expiry);

out:
	/* log the result */
	msg = apr_psprintf(r->pool, "%d bytes in %s cache backend for %skey %s",
			(value ? (int) _oidc_strlen(value) : 0),
			(cfg->cache->name ? cfg->cache->name : ""),
			(encrypted ? "encrypted " : ""), (key ? key : ""));
	if (rc == TRUE)
		oidc_debug(r, "successfully stored %s", msg);
	else
		oidc_warn(r, "could NOT store %s", msg);

	return rc;
}
