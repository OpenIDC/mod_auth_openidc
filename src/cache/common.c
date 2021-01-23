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

#define oidc_cache_crypto_openssl_error(r, fmt, ...) \
		oidc_error(r, "%s: %s", apr_psprintf(r->pool, fmt, ##__VA_ARGS__), ERR_error_string(ERR_get_error(), NULL))

#define OIDC_CACHE_CIPHER							EVP_aes_256_gcm()
#define OIDC_CACHE_TAG_LEN							16

#if (OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER))
#define OIDC_CACHE_CRYPTO_GET_TAG					EVP_CTRL_AEAD_GET_TAG
#define OIDC_CACHE_CRYPTO_SET_TAG					EVP_CTRL_AEAD_SET_TAG
#define OIDC_CACHE_CRYPTO_SET_IVLEN					EVP_CTRL_AEAD_SET_IVLEN
#else
#define OIDC_CACHE_CRYPTO_GET_TAG					EVP_CTRL_GCM_GET_TAG
#define OIDC_CACHE_CRYPTO_SET_TAG					EVP_CTRL_GCM_SET_TAG
#define OIDC_CACHE_CRYPTO_SET_IVLEN					EVP_CTRL_GCM_SET_IVLEN
#endif

/*
 * AES GCM encrypt
 */
static int oidc_cache_crypto_encrypt_impl(request_rec *r,
		unsigned char *plaintext, int plaintext_len, const unsigned char *aad,
		int aad_len, unsigned char *key, const unsigned char *iv, int iv_len,
		unsigned char *ciphertext, const unsigned char *tag, int tag_len) {
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* create and initialize the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		oidc_cache_crypto_openssl_error(r, "EVP_CIPHER_CTX_new");
		return -1;
	}

	/* initialize the encryption cipher */
	if (!EVP_EncryptInit_ex(ctx, OIDC_CACHE_CIPHER, NULL, NULL, NULL)) {
		oidc_cache_crypto_openssl_error(r, "EVP_EncryptInit_ex");
		return -1;
	}

	/* set IV length */
	if (!EVP_CIPHER_CTX_ctrl(ctx, OIDC_CACHE_CRYPTO_SET_IVLEN, iv_len, NULL)) {
		oidc_cache_crypto_openssl_error(r, "EVP_CIPHER_CTX_ctrl");
		return -1;
	}

	/* initialize key and IV */
	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
		oidc_cache_crypto_openssl_error(r, "EVP_EncryptInit_ex");
		return -1;
	}

	/* provide AAD data */
	if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		oidc_cache_crypto_openssl_error(r, "EVP_DecryptUpdate aad: aad_len=%d",
				aad_len);
		return -1;
	}

	/* provide the message to be encrypted and obtain the encrypted output */
	if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		oidc_cache_crypto_openssl_error(r, "EVP_EncryptUpdate ciphertext");
		return -1;
	}
	ciphertext_len = len;

	/*
	 * finalize the encryption; normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		oidc_cache_crypto_openssl_error(r, "EVP_EncryptFinal_ex");
		return -1;
	}
	ciphertext_len += len;

	/* get the tag */
	if (!EVP_CIPHER_CTX_ctrl(ctx, OIDC_CACHE_CRYPTO_GET_TAG, tag_len,
			(void *) tag)) {
		oidc_cache_crypto_openssl_error(r, "EVP_CIPHER_CTX_ctrl");
		return -1;
	}

	/* clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

/*
 * AES GCM decrypt
 */
static int oidc_cache_crypto_decrypt_impl(request_rec *r,
		unsigned char *ciphertext, int ciphertext_len, const unsigned char *aad,
		int aad_len, const unsigned char *tag, int tag_len, unsigned char *key,
		const unsigned char *iv, int iv_len, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* create and initialize the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		oidc_cache_crypto_openssl_error(r, "EVP_CIPHER_CTX_new");
		return -1;
	}

	/* initialize the decryption cipher */
	if (!EVP_DecryptInit_ex(ctx, OIDC_CACHE_CIPHER, NULL, NULL, NULL)) {
		oidc_cache_crypto_openssl_error(r, "EVP_DecryptInit_ex");
		return -1;
	}

	/* set IV length */
	if (!EVP_CIPHER_CTX_ctrl(ctx, OIDC_CACHE_CRYPTO_SET_IVLEN, iv_len, NULL)) {
		oidc_cache_crypto_openssl_error(r, "EVP_CIPHER_CTX_ctrl");
		return -1;
	}

	/* initialize key and IV */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		oidc_cache_crypto_openssl_error(r, "EVP_DecryptInit_ex");
		return -1;
	}

	/* provide AAD data */
	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		oidc_cache_crypto_openssl_error(r, "EVP_DecryptUpdate aad: aad_len=%d",
				aad_len);
		return -1;
	}

	/* provide the message to be decrypted and obtain the plaintext output */
	if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		oidc_cache_crypto_openssl_error(r, "EVP_DecryptUpdate ciphertext");
		return -1;
	}
	plaintext_len = len;

	/* set expected tag value; works in OpenSSL 1.0.1d and later */
	if (!EVP_CIPHER_CTX_ctrl(ctx, OIDC_CACHE_CRYPTO_SET_TAG, tag_len,
			(void *) tag)) {
		oidc_cache_crypto_openssl_error(r, "EVP_CIPHER_CTX_ctrl");
		return -1;
	}

	/*
	 * finalize the decryption; a positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* clean up */
	EVP_CIPHER_CTX_free(ctx);

	if (ret > 0) {
		/* success */
		plaintext_len += len;
		return plaintext_len;
	} else {
		/* verify failed */
		oidc_cache_crypto_openssl_error(r, "EVP_DecryptFinal_ex");
		return -1;
	}
}

/*
 * static AAD value for encryption/decryption
 */
static const unsigned char OIDC_CACHE_CRYPTO_GCM_AAD[] = { 0x4d, 0x23, 0xc3,
		0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78,
		0xde };

/*
 * static IV value for encryption/decryption
 */
static const unsigned char OIDC_CACHE_CRYPTO_GCM_IV[] = { 0x00, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f };

/*
 * AES GCM encrypt using the static AAD and IV
 */
static int oidc_cache_crypto_encrypt(request_rec *r, const char *plaintext,
		unsigned char *key, char **result) {
	char *encoded = NULL, *p = NULL, *e_tag = NULL;
	unsigned char *ciphertext = NULL;
	int plaintext_len, ciphertext_len, encoded_len, e_tag_len;
	unsigned char tag[OIDC_CACHE_TAG_LEN];

	/* allocate space for the ciphertext */
	plaintext_len = strlen(plaintext) + 1;
	ciphertext = apr_pcalloc(r->pool,
			(plaintext_len + EVP_CIPHER_block_size(OIDC_CACHE_CIPHER)));

	ciphertext_len = oidc_cache_crypto_encrypt_impl(r,
			(unsigned char *) plaintext, plaintext_len,
			OIDC_CACHE_CRYPTO_GCM_AAD, sizeof(OIDC_CACHE_CRYPTO_GCM_AAD), key,
			OIDC_CACHE_CRYPTO_GCM_IV, sizeof(OIDC_CACHE_CRYPTO_GCM_IV),
			ciphertext, tag, sizeof(tag));

	/* base64url encode the resulting ciphertext */
	encoded_len = oidc_base64url_encode(r, &encoded, (const char *) ciphertext,
			ciphertext_len, 1);
	if (encoded_len > 0) {
		p = encoded;

		/* base64url encode the tag */
		e_tag_len = oidc_base64url_encode(r, &e_tag, (const char *) tag,
				OIDC_CACHE_TAG_LEN, 1);

		/* now allocated space for the concatenated base64url encoded ciphertext and tag */
		encoded = apr_pcalloc(r->pool, encoded_len + 1 + e_tag_len + 1);
		memcpy(encoded, p, encoded_len);
		p = encoded + encoded_len;
		*p = OIDC_CHAR_DOT;
		p++;

		/* append the tag in the buffer */
		memcpy(p, e_tag, e_tag_len);
		encoded_len += e_tag_len + 1;

		/* make sure the result is \0 terminated */
		encoded[encoded_len] = '\0';

		*result = encoded;
	}

	return encoded_len;
}

/*
 * AES GCM decrypt using the static AAD and IV
 */
static int oidc_cache_crypto_decrypt(request_rec *r, const char *cache_value,
		unsigned char *key, unsigned char **plaintext) {

	int len = -1;

	/* grab the base64url-encoded tag after the "." */
	char *encoded_tag = strstr(cache_value, ".");
	if (encoded_tag == NULL) {
		oidc_error(r,
				"corrupted cache value: no tag separator found in encrypted value");
		return FALSE;
	}

	/* make sure we don't modify the original string since it may be just a pointer into the cache (shm) */
	cache_value = apr_pstrmemdup(r->pool, cache_value,
			strlen(cache_value) - strlen(encoded_tag));
	encoded_tag++;

	/* base64url decode the ciphertext */
	char *d_bytes = NULL;
	int d_len = oidc_base64url_decode(r->pool, &d_bytes, cache_value);

	/* base64url decode the tag */
	char *t_bytes = NULL;
	int t_len = oidc_base64url_decode(r->pool, &t_bytes, encoded_tag);

	/* see if we're still good to go */
	if ((d_len > 0) && (t_len > 0)) {

		/* allocated space for the plaintext */
		*plaintext = apr_pcalloc(r->pool,
				(d_len + EVP_CIPHER_block_size(OIDC_CACHE_CIPHER) - 1));

		/* decrypt the ciphertext providing the tag value */

		len = oidc_cache_crypto_decrypt_impl(r, (unsigned char *) d_bytes,
				d_len, OIDC_CACHE_CRYPTO_GCM_AAD,
				sizeof(OIDC_CACHE_CRYPTO_GCM_AAD), (unsigned char *) t_bytes,
				t_len, key, OIDC_CACHE_CRYPTO_GCM_IV,
				sizeof(OIDC_CACHE_CRYPTO_GCM_IV), *plaintext);

		/* check the result and make sure it is \0 terminated */
		if (len > -1) {
			(*plaintext)[len] = '\0';
		} else {
			*plaintext = NULL;
		}

	}

	return len;
}

/*
 * hash the crypto passhphrase so it has enough key length for AES GCM 256
 */
static unsigned char *oidc_cache_hash_passphrase(request_rec *r,
		const char *passphrase) {

	unsigned char *key = NULL;
	unsigned int key_len = 0;
	oidc_jose_error_t err;

	if (oidc_jose_hash_bytes(r->pool, OIDC_JOSE_ALG_SHA256,
			(const unsigned char *) passphrase, strlen(passphrase), &key,
			&key_len, &err) == FALSE) {
		oidc_error(r, "oidc_jose_hash_bytes returned an error: %s", err.text);
		return NULL;
	}

	return key;
}

/*
 * hash a cache key and a crypto passphrase so the result is suitable as an randomized cache key
 */
static char *oidc_cache_get_hashed_key(request_rec *r, const char *passphrase,
		const char *key) {
	char *input = apr_psprintf(r->pool, "%s:%s", passphrase, key);
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

	rc = (oidc_cache_crypto_decrypt(r, cache_value,
			oidc_cache_hash_passphrase(r, cfg->crypto_passphrase),
			(unsigned char **) value) > 0);

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
			if (oidc_cache_crypto_encrypt(r, value,
					oidc_cache_hash_passphrase(r, cfg->crypto_passphrase),
					&encoded) <= 0)
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
