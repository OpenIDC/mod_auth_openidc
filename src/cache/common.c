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
 * Copyright (C) 2017-2021 ZmartZone Holding BV
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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#ifndef WIN32
#include <unistd.h>
#endif

#include "apr_general.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#include <apr_base64.h>

#include "../mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/* create the cache lock context */
oidc_cache_mutex_t *oidc_cache_mutex_create(apr_pool_t *pool) {
	oidc_cache_mutex_t *ctx = apr_pcalloc(pool, sizeof(oidc_cache_mutex_t));
	ctx->mutex = NULL;
	ctx->mutex_filename = NULL;
	ctx->shm = NULL;
	ctx->sema = NULL;
	ctx->is_parent = TRUE;
	return ctx;
}

#define OIDC_CACHE_ERROR_STR_MAX 255

/*
 * convert a apr status code to a string
 */
char *oidc_cache_status2str(apr_status_t statcode) {
	char buf[OIDC_CACHE_ERROR_STR_MAX];
	return apr_strerror(statcode, buf, OIDC_CACHE_ERROR_STR_MAX);
}

apr_byte_t oidc_cache_mutex_post_config(server_rec *s, oidc_cache_mutex_t *m,
		const char *type) {

	apr_status_t rv = APR_SUCCESS;
	const char *dir;

	// oidc_sdebug(s, "enter: %d (m=%pp,s=%pp, p=%d)", (m && m->sema) ? *m->sema : -1, m->mutex ? m->mutex : 0, s, m->is_parent);

	/* construct the mutex filename */
	apr_temp_dir_get(&dir, s->process->pool);
	m->mutex_filename = apr_psprintf(s->process->pool,
			"%s/mod_auth_openidc_%s_mutex.%ld.%pp", dir, type,
			(long int) getpid(), s);

	/* create the mutex lock */
	rv = apr_global_mutex_create(&m->mutex, (const char *) m->mutex_filename,
			APR_LOCK_DEFAULT, s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"apr_global_mutex_create failed to create mutex on file %s: %s (%d)",
				m->mutex_filename, oidc_cache_status2str(rv), rv);
		return FALSE;
	}

	/* need this on Linux */
#ifdef AP_NEED_SET_MUTEX_PERMS
#if MODULE_MAGIC_NUMBER_MAJOR >= 20081201
	rv = ap_unixd_set_global_mutex_perms(m->mutex);
#else
	rv = unixd_set_global_mutex_perms(m->mutex);
#endif
	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"unixd_set_global_mutex_perms failed; could not set permissions: %s (%d)",
				oidc_cache_status2str(rv), rv);
		return FALSE;
	}
#endif

	apr_global_mutex_lock(m->mutex);

	rv = apr_shm_create(&m->shm, sizeof(int), NULL, s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s, "apr_shm_create failed to create shared memory segment");
		return FALSE;
	}

	m->sema = apr_shm_baseaddr_get(m->shm);
	*m->sema = 1;

	apr_global_mutex_unlock(m->mutex);

	return TRUE;
}

/*
 * initialize the cache lock in a child process
 */
apr_status_t oidc_cache_mutex_child_init(apr_pool_t *p, server_rec *s,
		oidc_cache_mutex_t *m) {

	// oidc_sdebug(s, "enter: %d (m=%pp,s=%pp, p=%d)", (m && m->sema) ? *m->sema : -1, m->mutex ? m->mutex : 0, s, m->is_parent);

	if (m->is_parent == FALSE)
		return APR_SUCCESS;

	/* initialize the lock for the child process */
	apr_status_t rv = apr_global_mutex_child_init(&m->mutex,
			(const char *) m->mutex_filename, p);

	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"apr_global_mutex_child_init failed to reopen mutex on file %s: %s (%d)",
				m->mutex_filename, oidc_cache_status2str(rv), rv);
	} else {
		apr_global_mutex_lock(m->mutex);
		m->sema = apr_shm_baseaddr_get(m->shm);
		(*m->sema)++;
		apr_global_mutex_unlock(m->mutex);
	}

	m->is_parent = FALSE;
	//oidc_sdebug(s, "semaphore: %d (m=%pp,s=%pp)", *m->sema, m, s);

	return rv;
}

/*
 * global lock
 */
apr_byte_t oidc_cache_mutex_lock(server_rec *s, oidc_cache_mutex_t *m) {

	apr_status_t rv = apr_global_mutex_lock(m->mutex);

	if (rv != APR_SUCCESS)
		oidc_serror(s, "apr_global_mutex_lock() failed: %s (%d)",
				oidc_cache_status2str(rv), rv);

	return TRUE;
}

/*
 * global unlock
 */
apr_byte_t oidc_cache_mutex_unlock(server_rec *s, oidc_cache_mutex_t *m) {

	apr_status_t rv = apr_global_mutex_unlock(m->mutex);

	if (rv != APR_SUCCESS)
		oidc_serror(s, "apr_global_mutex_unlock() failed: %s (%d)",
				oidc_cache_status2str(rv), rv);

	return TRUE;
}

/*
 * destroy mutex
 */
apr_byte_t oidc_cache_mutex_destroy(server_rec *s, oidc_cache_mutex_t *m) {

	apr_status_t rv = APR_SUCCESS;

	// oidc_sdebug(s, "enter: %d (m=%pp,s=%pp, p=%d)", (m && m->sema) ? *m->sema : -1, m->mutex ? m->mutex : 0, s, m->is_parent);

	if (m->mutex != NULL) {

		apr_global_mutex_lock(m->mutex);
		(*m->sema)--;
		//oidc_sdebug(s, "semaphore: %d (m=%pp,s=%pp)", *m->sema, m->mutex, s);

		// oidc_sdebug(s, "processing: %d (m=%pp,s=%pp, p=%d)", (m && m->sema) ? *m->sema : -1, m->mutex ? m->mutex : 0, s, m->is_parent);

		if ((m->shm != NULL) && (*m->sema == 0)) {

			rv = apr_shm_destroy(m->shm);
			oidc_sdebug(s, "apr_shm_destroy for semaphore returned: %d", rv);
			m->shm = NULL;

			apr_global_mutex_unlock(m->mutex);

			rv = apr_global_mutex_destroy(m->mutex);
			oidc_sdebug(s, "apr_global_mutex_destroy returned :%d", rv);
			m->mutex = NULL;

			rv = APR_SUCCESS;

		} else {

			apr_global_mutex_unlock(m->mutex);

		}
	}

	return rv;
}

#define OIDC_CACHE_CRYPTO_JSON_KEY "c"

/*
 * AES GCM encrypt using the crypto passphrase as symmetric key
 */
static apr_byte_t oidc_cache_crypto_encrypt(request_rec *r, const char *plaintext, const char *key,
		char **result) {
	apr_byte_t rv = FALSE;
	json_t *json = NULL;

	json = json_object();
	json_object_set_new(json, OIDC_CACHE_CRYPTO_JSON_KEY, json_string(plaintext));

	rv = oidc_util_jwt_create(r, (const char*) key, json, result);

	if (json)
		json_decref(json);

	return rv;
}

/*
 * AES GCM decrypt using the crypto passphrase as symmetric key
 */
static apr_byte_t oidc_cache_crypto_decrypt(request_rec *r, const char *cache_value,
		const char *key, char **plaintext) {

	apr_byte_t rv = FALSE;
	json_t *json = NULL;

	rv = oidc_util_jwt_verify(r, (const char*) key, cache_value, &json);
	if (rv == FALSE)
		goto end;

	rv = oidc_json_object_get_string(r->pool, json, OIDC_CACHE_CRYPTO_JSON_KEY, plaintext, NULL);

	end:

	if (json)
		json_decref(json);

	return rv;
}

/*
 * hash a cache key and a crypto passphrase so the result is suitable as an randomized cache key
 */
static char* oidc_cache_get_hashed_key(request_rec *r, const char *passphrase, const char *key) {
	char *input = apr_psprintf(r->pool, "%s:%s", passphrase, key);
	char *output = NULL;
	if (oidc_util_hash_string_and_base64url_encode(r, OIDC_JOSE_ALG_SHA256, input, &output)
			== FALSE) {
		oidc_error(r, "oidc_util_hash_string_and_base64url_encode returned an error");
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

	oidc_debug(r, "enter: %s (section=%s, decrypt=%d, type=%s)", key, section,
			encrypted, cfg->cache->name);

	/* see if encryption is turned on */
	if (encrypted == 1)
		key = oidc_cache_get_hashed_key(r, cfg->crypto_passphrase, key);

	/* get the value from the cache */
	const char *cache_value = NULL;
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

	rc = oidc_cache_crypto_decrypt(r, cache_value, cfg->crypto_passphrase, value);

out:
	/* log the result */
	msg = apr_psprintf(r->pool, "from %s cache backend for %skey %s",
			cfg->cache->name, encrypted ? "encrypted " : "", key);
	if (rc == TRUE)
		if (*value != NULL)
			oidc_debug(r, "cache hit: return %d bytes %s",
					*value ? (int )strlen(*value) : 0, msg);
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
			key, section, value ? (int )strlen(value) : 0, encrypted,
					apr_time_sec(expiry - apr_time_now()), cfg->cache->name);

	/* see if we need to encrypt */
	if (encrypted == 1) {

		key = oidc_cache_get_hashed_key(r, cfg->crypto_passphrase, key);
		if (key == NULL)
			goto out;

		if (value != NULL) {
			if (oidc_cache_crypto_encrypt(r, value, cfg->crypto_passphrase, &encoded) == FALSE)
				goto out;
			value = encoded;
		}
	}

	/* store the resulting value in the cache */
	rc = cfg->cache->set(r, section, key, value, expiry);

out:
	/* log the result */
	msg = apr_psprintf(r->pool, "%d bytes in %s cache backend for %skey %s",
			(value ? (int) strlen(value) : 0),
			(cfg->cache->name ? cfg->cache->name : ""),
			(encrypted ? "encrypted " : ""), (key ? key : ""));
	if (rc == TRUE)
		oidc_debug(r, "successfully stored %s", msg);
	else
		oidc_warn(r, "could NOT store %s", msg);

	return rc;
}
