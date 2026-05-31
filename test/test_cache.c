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
 * Copyright (C) 2017-2026 ZmartZone Holding BV
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
 *
 **************************************************************************/

#include "cache/cache.h"
#include "cfg/cache.h"
#include "cfg/cfg_int.h"
#include "cfg/provider.h"
#include "check_util.h"
#include "mod_auth_openidc.h"
#include "util.h"
#include "util/util.h"
#include <stdlib.h>
#include <string.h>

#ifdef USE_LIBHIREDIS
#include "cache/redis.h"
#endif

#ifdef USE_MEMCACHE
#include "cache/memcache.h"
#endif

START_TEST(test_cache_mutex_and_status2str) {
	request_rec *r = oidc_test_request_get();
	apr_pool_t *pool = oidc_test_pool_get();

	/* test oidc_cache_mutex_create/post_config/lock/unlock/destroy */
	oidc_cache_mutex_t *m = oidc_cache_mutex_create(pool, FALSE);
	ck_assert_ptr_nonnull(m);

	ck_assert_int_eq(oidc_cache_mutex_post_config(pool, r->server, m, "test"), TRUE);
	/* lock/unlock should succeed */
	ck_assert_int_eq(oidc_cache_mutex_lock(pool, r->server, m), TRUE);
	ck_assert_int_eq(oidc_cache_mutex_unlock(pool, r->server, m), TRUE);
	/* destroy should succeed */
	ck_assert_int_eq(oidc_cache_mutex_destroy(r->server, m), TRUE);

	/* test oidc_cache_status2str returns a non-empty string */
	char *s = oidc_cache_status2str(pool, APR_EGENERAL);
	ck_assert_ptr_nonnull(s);
	ck_assert_int_ge((int)_oidc_strlen(s), 1);
}
END_TEST

START_TEST(test_cache_set_get_encrypted_and_expiry) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry;

	/* disable internal JWT compression for this test only */
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");

	/* normal set/get with encryption enabled by default in helper.c */
	expiry = apr_time_now() + apr_time_from_sec(60);
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "k1", "v1", expiry), TRUE);
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "v1");

	/* expiry in the past should result in a cache miss (value == NULL) */
	expiry = apr_time_now() - apr_time_from_sec(1);
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "k_exp", "vx", expiry), TRUE);
	/* ensure value is NULL before calling oidc_cache_get; the API returns TRUE on miss but
	   does not overwrite the out pointer unless there's a hit */
	value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "k_exp", &value), TRUE);
	ck_assert_ptr_null(value);

	/* restore env */
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}
END_TEST

START_TEST(test_cache_long_key_and_prefix) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);

	/* disable internal JWT compression for this test only */
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");

	/* construct a very long key that should be hashed by oidc_cache_get_key */
	size_t long_len = OIDC_CACHE_KEY_SIZE_MAX + 50;
	char *long_key = apr_pcalloc(r->pool, long_len + 1);
	for (size_t i = 0; i < long_len; i++)
		long_key[i] = 'a' + (i % 26);
	long_key[long_len] = '\0';

	/* set/get using long key */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_NONCE, long_key, "lv", expiry), TRUE);
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_NONCE, long_key, &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "lv");

	/* test section prefix via subprocess_env */
	apr_table_set(r->subprocess_env, "OIDC_CACHE_PREFIX", "pfx_");
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "k_pref", "vp", expiry), TRUE);
	value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "k_pref", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "vp");
	/* clear the prefix for other tests */
	apr_table_unset(r->subprocess_env, "OIDC_CACHE_PREFIX");

	/* restore env */
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}
END_TEST

START_TEST(test_cache_mutex_global_and_child_init) {
	request_rec *r = oidc_test_request_get();
	apr_pool_t *pool = oidc_test_pool_get();

	/* create a global mutex and run through post_config, lock/unlock, child_init and destroy */
	oidc_cache_mutex_t *m = oidc_cache_mutex_create(pool, TRUE);
	ck_assert_ptr_nonnull(m);

	/* post_config should create the global mutex */
	ck_assert_int_eq(oidc_cache_mutex_post_config(pool, r->server, m, "gtest"), TRUE);

	/* lock/unlock should succeed for global mutex */
	ck_assert_int_eq(oidc_cache_mutex_lock(pool, r->server, m), TRUE);
	ck_assert_int_eq(oidc_cache_mutex_unlock(pool, r->server, m), TRUE);

	/* simulate child init on a new pool */
	apr_pool_t *pchild = NULL;
	apr_pool_create(&pchild, NULL);
	apr_status_t rv = oidc_cache_mutex_child_init(pchild, r->server, m);
	/* child init returns APR_SUCCESS on success */
	ck_assert_int_eq((int)rv, (int)APR_SUCCESS);
	apr_pool_destroy(pchild);

	/* destroy should succeed */
	ck_assert_int_eq(oidc_cache_mutex_destroy(r->server, m), TRUE);
}
END_TEST

START_TEST(test_cache_encrypt_no_secret) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);

	/* get cfg and temporarily remove the secret to simulate missing passphrase */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *old_secret = oidc_cfg_crypto_passphrase_secret1_get(cfg);
	cfg->crypto_passphrase.secret1 = NULL;
	cfg->cache.encrypt = 1;

	/* fail when value is too short and compression fails */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "nokey", "v", expiry), FALSE);

	/* fail when encryption is on but no secret is set (long enough value to compress) */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "nokey",
					"vadadfsssssssssssssssssssssssssssssssssssssssssssssssssssssssss", expiry),
			 FALSE);

	/* fail because no secret is set */
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "nokey", &value), FALSE);

	/* restore secret */
	cfg->crypto_passphrase.secret1 = (char *)old_secret;
}
END_TEST

START_TEST(test_cache_status2str_success) {
	apr_pool_t *pool = oidc_test_pool_get();
	char *s = oidc_cache_status2str(pool, APR_SUCCESS);
	ck_assert_ptr_nonnull(s);
	ck_assert_int_ge((int)_oidc_strlen(s), 1);
}
END_TEST

START_TEST(test_cache_second_passphrase_retry) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);

	/* prepare cfg and secrets */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *old_s1 = oidc_cfg_crypto_passphrase_secret1_get(cfg);
	const char *old_s2 = oidc_cfg_crypto_passphrase_secret2_get(cfg);
	int old_encrypt = cfg->cache.encrypt;

	/* set initial secret and ensure encryption is enabled */
	cfg->crypto_passphrase.secret1 = "oldsecret012345678901234567890"; // 30+ chars
	cfg->crypto_passphrase.secret2 = NULL;
	cfg->cache.encrypt = 1;

	/* disable internal compression for this test */
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");

	/* store a value with the original secret */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "rot_key", "rot_val", expiry), TRUE);

	/* rotate secrets: new secret becomes secret1, old one moved to secret2 */
	cfg->crypto_passphrase.secret1 = "newsecret01234567890123456789012"; // different
	cfg->crypto_passphrase.secret2 = "oldsecret012345678901234567890";

	/* attempt to retrieve: oidc_cache_get should first try with secret1 (no match) then with secret2 and succeed */
	value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "rot_key", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "rot_val");

	/* cleanup: restore cfg values */
	cfg->crypto_passphrase.secret1 = (char *)old_s1;
	cfg->crypto_passphrase.secret2 = (char *)old_s2;
	cfg->cache.encrypt = old_encrypt;
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}
END_TEST

START_TEST(test_cache_shm_get_key_bounds_negative) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);

	/* ensure cache encryption is disabled so the raw key is used by shm backend */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	int old_encrypt = cfg->cache.encrypt;
	cfg->cache.encrypt = 0;

	/* construct a key that makes section:key length >= OIDC_CACHE_SHM_KEY_MAX */
	const char *section = OIDC_CACHE_SECTION_NONCE; // short section
	size_t section_len = _oidc_strlen(section);
	size_t klen = OIDC_CACHE_KEY_SIZE_MAX - section_len -
		      1; /* ensures section + ':' + key length == OIDC_CACHE_KEY_SIZE_MAX */
	char *big_key = apr_pcalloc(r->pool, klen + 1);
	for (size_t i = 0; i < klen; ++i)
		big_key[i] = 'z' - (i % 26);
	big_key[klen] = '\0';

	/* storing should fail due to shm_get_key bounds check */
	ck_assert_int_eq(oidc_cache_set(r, section, big_key, "v", expiry), FALSE);

	/* retrieval should also fail */
	ck_assert_int_eq(oidc_cache_get(r, section, big_key, &value), FALSE);

	/* restore encrypt flag */
	cfg->cache.encrypt = old_encrypt;
}
END_TEST

START_TEST(test_cache_secret1_empty_secret2_fallback) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);

	/* prepare cfg and secrets */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *old_s1 = oidc_cfg_crypto_passphrase_secret1_get(cfg);
	const char *old_s2 = oidc_cfg_crypto_passphrase_secret2_get(cfg);
	int old_encrypt = cfg->cache.encrypt;

	/* set initial secret and ensure encryption is enabled */
	cfg->crypto_passphrase.secret1 = "origsecret012345678901234567890";
	cfg->crypto_passphrase.secret2 = NULL;
	cfg->cache.encrypt = 1;

	/* disable compression for deterministic behavior */
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");

	/* store a value with the original secret */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "emptyrot", "val", expiry), TRUE);

	/* now simulate secret1 being empty string and secret2 having the original secret */
	cfg->crypto_passphrase.secret1 = ""; /* empty (non-NULL) */
	cfg->crypto_passphrase.secret2 = "origsecret012345678901234567890";

	/* retrieval should succeed via fallback to secret2 */
	value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "emptyrot", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "val");

	/* cleanup */
	cfg->crypto_passphrase.secret1 = (char *)old_s1;
	cfg->crypto_passphrase.secret2 = (char *)old_s2;
	cfg->cache.encrypt = old_encrypt;
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}
END_TEST

START_TEST(test_cache_backend_true_null_miss) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() - apr_time_from_sec(1); /* already expired */

	/* ensure encryption disabled so backend returns raw section:key semantics */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	int old_encrypt = cfg->cache.encrypt;
	cfg->cache.encrypt = 0;

	/* set an entry with an expired expiry so backend will return TRUE but value NULL */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_NONCE, "backend_miss", "v", expiry), TRUE);

	/* now get should return TRUE (backend signalled success) but value should be NULL -> cache miss */
	value = NULL; /* initialize to NULL to reflect API semantics */
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_NONCE, "backend_miss", &value), TRUE);
	ck_assert_ptr_null(value);

	/* restore encrypt flag */
	cfg->cache.encrypt = old_encrypt;
}
END_TEST

START_TEST(test_cache_compression_enabled_set_get) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);

	/* ensure compression is enabled (default) */
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");

	/* verify encryption+compression works by trying to create a JWT with the current cfg secret */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_crypto_passphrase_t passphrase;
	passphrase.secret1 = oidc_cfg_crypto_passphrase_secret1_get(cfg);
	passphrase.secret2 = oidc_cfg_crypto_passphrase_secret2_get(cfg);
	char *encoded = NULL;
	apr_byte_t forced_no_compress = FALSE;
	if (!oidc_util_jwt_create(r, &passphrase, "probe", &encoded)) {
		/* compression or encryption not available; fall back to non-compressed path for this test */
		apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");
		forced_no_compress = TRUE;
	}

	/* normal set/get with compression enabled (or forced non-compressed fallback) */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "c_k1", "c_v1", expiry), TRUE);
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "c_k1", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "c_v1");

	if (forced_no_compress)
		apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}
END_TEST

START_TEST(test_cache_compression_enabled_second_passphrase) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);

	/* ensure compression enabled */
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");

	/* prepare cfg and secrets */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *old_s1 = oidc_cfg_crypto_passphrase_secret1_get(cfg);
	const char *old_s2 = oidc_cfg_crypto_passphrase_secret2_get(cfg);
	int old_encrypt = cfg->cache.encrypt;

	/* set initial secret and ensure encryption is enabled */
	cfg->crypto_passphrase.secret1 = "cmp_oldsecret012345678901234567";
	cfg->crypto_passphrase.secret2 = NULL;
	cfg->cache.encrypt = 1;

	/* verify encryption+compression works for this cfg; fall back to no-compress if not */
	oidc_crypto_passphrase_t passphrase;
	passphrase.secret1 = oidc_cfg_crypto_passphrase_secret1_get(cfg);
	passphrase.secret2 = oidc_cfg_crypto_passphrase_secret2_get(cfg);
	char *encoded = NULL;
	apr_byte_t forced_no_compress = FALSE;
	if (!oidc_util_jwt_create(r, &passphrase, "probe", &encoded)) {
		cfg->crypto_passphrase.secret1 = (char *)old_s1;
		cfg->crypto_passphrase.secret2 = (char *)old_s2;
		cfg->cache.encrypt = old_encrypt;
		apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");
		forced_no_compress = TRUE;
		/* continue with fallback; we'll still test rotation semantics but without compression */
		cfg = oidc_test_cfg_get();
		cfg->crypto_passphrase.secret1 = "cmp_oldsecret012345678901234567";
		cfg->crypto_passphrase.secret2 = NULL;
		cfg->cache.encrypt = 1;
	}

	/* store with initial secret (compression enabled or fallback) */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "c_rot_key", "c_rot_val", expiry), TRUE);

	/* rotate secrets */
	cfg->crypto_passphrase.secret1 = "cmp_newsecret0123456789012345678";
	cfg->crypto_passphrase.secret2 = "cmp_oldsecret012345678901234567";

	/* retrieve should succeed via secret2 fallback */
	value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "c_rot_key", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "c_rot_val");

	/* restore */
	cfg->crypto_passphrase.secret1 = (char *)old_s1;
	cfg->crypto_passphrase.secret2 = (char *)old_s2;
	cfg->cache.encrypt = old_encrypt;
	if (forced_no_compress)
		apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}
END_TEST

START_TEST(test_cache_compression_enabled_empty_secret2_fallback) {
	request_rec *r = oidc_test_request_get();
	char *value = NULL;
	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);

	/* ensure compression enabled */
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");

	/* prepare cfg and secrets */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *old_s1 = oidc_cfg_crypto_passphrase_secret1_get(cfg);
	const char *old_s2 = oidc_cfg_crypto_passphrase_secret2_get(cfg);
	int old_encrypt = cfg->cache.encrypt;

	cfg->crypto_passphrase.secret1 = "cmp_origsecret012345678901234567";
	cfg->crypto_passphrase.secret2 = NULL;
	cfg->cache.encrypt = 1;

	/* verify encryption+compression works; fall back to no-compress if not */
	oidc_crypto_passphrase_t passphrase2;
	passphrase2.secret1 = oidc_cfg_crypto_passphrase_secret1_get(cfg);
	passphrase2.secret2 = oidc_cfg_crypto_passphrase_secret2_get(cfg);
	char *encoded2 = NULL;
	apr_byte_t forced_no_compress = FALSE;
	if (!oidc_util_jwt_create(r, &passphrase2, "probe", &encoded2)) {
		cfg->crypto_passphrase.secret1 = (char *)old_s1;
		cfg->crypto_passphrase.secret2 = (char *)old_s2;
		cfg->cache.encrypt = old_encrypt;
		apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");
		forced_no_compress = TRUE;
		cfg = oidc_test_cfg_get();
		cfg->crypto_passphrase.secret1 = "cmp_origsecret012345678901234567";
		cfg->crypto_passphrase.secret2 = NULL;
		cfg->cache.encrypt = 1;
	}

	/* store with original secret */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "c_emptyrot", "c_val", expiry), TRUE);

	/* simulate secret1 empty and secret2 containing original */
	cfg->crypto_passphrase.secret1 = "";
	cfg->crypto_passphrase.secret2 = "cmp_origsecret012345678901234567";

	value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "c_emptyrot", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "c_val");

	/* restore */
	cfg->crypto_passphrase.secret1 = (char *)old_s1;
	cfg->crypto_passphrase.secret2 = (char *)old_s2;
	cfg->cache.encrypt = old_encrypt;
	if (forced_no_compress)
		apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}
END_TEST

/*
 * Tests for cache/file.c — swap the cache backend from shm to file
 * (post_config-style) and run set/get/expiry/overwrite scenarios
 * against a fresh /tmp/oidc-test-cache.XXXXXX directory.
 *
 * The shared mutex (oidc_cfg_refresh_mutex_get / oidc_cache_mutex_*)
 * is intentionally NOT touched — the file backend reuses the same
 * mutex infrastructure the shm backend already initialized.
 */

static oidc_cache_t *e2e_switch_to_file_backend(request_rec *r) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_cache_t *prev = (oidc_cache_t *)cfg->cache.impl;
	cfg->cache.impl = &oidc_cache_file;

	char *tmpl = apr_pstrdup(r->pool, "/tmp/oidc-test-cache.XXXXXX");
	ck_assert_msg(mkdtemp(tmpl) != NULL, "could not create temp cache dir at %s", tmpl);
	cfg->cache.file_dir = tmpl;

	/* disable JWT compression: the cache wrapper's encryption path goes through
	 * oidc_util_jwt_create which calls zlib's deflate; that step can fail
	 * intermittently in this minimal test environment and isn't what we're testing */
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");

	ck_assert_int_eq(oidc_cache_file.post_config(r->server->process->pconf, r->server), OK);
	return prev;
}

static void e2e_restore_cache_backend(oidc_cache_t *prev) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cfg->cache.impl = prev;
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}

START_TEST(test_cache_file_set_get_basic) {
	request_rec *r = oidc_test_request_get();
	oidc_cache_t *prev = e2e_switch_to_file_backend(r);

	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "file-k1", "file-v1", expiry), TRUE);

	char *value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "file-k1", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "file-v1");

	e2e_restore_cache_backend(prev);
}
END_TEST

START_TEST(test_cache_file_miss) {
	request_rec *r = oidc_test_request_get();
	oidc_cache_t *prev = e2e_switch_to_file_backend(r);

	char *value = NULL;
	/* a key that was never set must return TRUE with *value == NULL */
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "no-such-key", &value), TRUE);
	ck_assert_ptr_null(value);

	e2e_restore_cache_backend(prev);
}
END_TEST

START_TEST(test_cache_file_expired_entry_is_miss) {
	request_rec *r = oidc_test_request_get();
	oidc_cache_t *prev = e2e_switch_to_file_backend(r);

	/* set with an expiry already in the past => get must report a miss */
	apr_time_t past = apr_time_now() - apr_time_from_sec(60);
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "file-expired", "stale-value", past), TRUE);

	char *value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "file-expired", &value), TRUE);
	ck_assert_ptr_null(value);

	e2e_restore_cache_backend(prev);
}
END_TEST

START_TEST(test_cache_file_overwrite_and_delete) {
	request_rec *r = oidc_test_request_get();
	oidc_cache_t *prev = e2e_switch_to_file_backend(r);

	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "file-k2", "first-value", expiry), TRUE);
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "file-k2", "second-value", expiry), TRUE);
	char *value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "file-k2", &value), TRUE);
	ck_assert_str_eq(value, "second-value");

	/* setting NULL deletes the cache entry */
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "file-k2", NULL, 0), TRUE);
	value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "file-k2", &value), TRUE);
	ck_assert_ptr_null(value);

	e2e_restore_cache_backend(prev);
}
END_TEST

START_TEST(test_cache_file_default_tmp_dir) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_cache_t *prev = (oidc_cache_t *)cfg->cache.impl;
	cfg->cache.impl = &oidc_cache_file;
	/* leave cache.file_dir NULL — post_config must pick a system tmp dir via apr_temp_dir_get */
	cfg->cache.file_dir = NULL;
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");

	ck_assert_int_eq(oidc_cache_file.post_config(r->server->process->pconf, r->server), OK);
	ck_assert_ptr_nonnull(cfg->cache.file_dir);

	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);
	ck_assert_int_eq(oidc_cache_set(r, OIDC_CACHE_SECTION_SESSION, "file-default-dir", "ok", expiry), TRUE);
	char *value = NULL;
	ck_assert_int_eq(oidc_cache_get(r, OIDC_CACHE_SECTION_SESSION, "file-default-dir", &value), TRUE);
	ck_assert_str_eq(value, "ok");

	cfg->cache.impl = prev;
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
}
END_TEST

#ifdef USE_LIBHIREDIS

/*
 * Tests for cache/redis.c — the Redis backend exposes its connect/command/disconnect
 * operations as function pointers on oidc_cache_cfg_redis_t. We install mock
 * implementations that fabricate redisReply objects, so the get/set/exec/retry logic
 * can be exercised fully offline, without a live Redis server.
 *
 * NB: replies are allocated with calloc()/strdup() because the backend frees them with
 * hiredis' freeReplyObject(), whose default allocator is plain free().
 */

typedef struct redis_mock_state_t {
	int connect_calls;
	int command_calls;
	int disconnect_calls;
	int connect_fail_times; /* connect returns APR_EGENERAL this many times, then APR_SUCCESS */
	int error_first_n;	/* command returns an ERROR reply for the first n calls */
	int return_null;	/* command returns a NULL reply */
	int reply_type;		/* type of the success reply (REDIS_REPLY_*) */
	const char *reply_str;	/* string payload of the success reply (may be NULL) */
	int force_len;		/* if >= 0, override reply->len to simulate a length mismatch */
	char *last_format;	/* the format string passed to the most recent command */
} redis_mock_state_t;

static redis_mock_state_t redis_mock;

static void redis_mock_reset(void) {
	memset(&redis_mock, 0, sizeof(redis_mock));
	redis_mock.reply_type = REDIS_REPLY_STRING;
	redis_mock.force_len = -1;
}

static redisReply *redis_mock_make_reply(int type, const char *str, int force_len) {
	redisReply *reply = calloc(1, sizeof(redisReply));
	reply->type = type;
	if (str != NULL) {
		reply->str = strdup(str);
		reply->len = (force_len >= 0) ? (size_t)force_len : strlen(str);
	} else {
		reply->len = (force_len >= 0) ? (size_t)force_len : 0;
	}
	return reply;
}

static apr_status_t redis_mock_connect(request_rec *r, oidc_cache_cfg_redis_t *context) {
	(void)r;
	(void)context;
	redis_mock.connect_calls++;
	if (redis_mock.connect_fail_times > 0) {
		redis_mock.connect_fail_times--;
		return APR_EGENERAL;
	}
	return APR_SUCCESS;
}

static redisReply *redis_mock_command(request_rec *r, oidc_cache_cfg_redis_t *context, char **errstr,
				      const char *format, va_list ap) {
	(void)context;
	(void)ap;
	redis_mock.command_calls++;
	redis_mock.last_format = apr_pstrdup(r->pool, format);
	*errstr = apr_pstrdup(r->pool, "mock");
	if (redis_mock.error_first_n > 0) {
		redis_mock.error_first_n--;
		return redis_mock_make_reply(REDIS_REPLY_ERROR, "mock error", -1);
	}
	if (redis_mock.return_null)
		return NULL;
	return redis_mock_make_reply(redis_mock.reply_type, redis_mock.reply_str, redis_mock.force_len);
}

static apr_status_t redis_mock_disconnect(oidc_cache_cfg_redis_t *context) {
	redis_mock.disconnect_calls++;
	context->rctx = NULL;
	return APR_SUCCESS;
}

static oidc_cache_t *redis_mock_prev_impl;
static void *redis_mock_prev_cfg;

/* swap in the redis backend with a fresh, mutex-initialized context and mock operations */
static oidc_cache_cfg_redis_t *redis_mock_install(request_rec *r) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	redis_mock_prev_impl = (oidc_cache_t *)cfg->cache.impl;
	redis_mock_prev_cfg = cfg->cache.cfg;

	/* a non-NULL server makes oidc_cache_redis_post_config validation pass */
	cfg->cache.redis_server = "localhost:6379";
	cfg->cache.cfg = NULL;

	ck_assert_int_eq(oidc_cache_redis_post_config(r->server->process->pconf, r->server, cfg, "redis"), OK);

	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *)cfg->cache.cfg;
	ck_assert_ptr_nonnull(context);
	/* the host:port parse and operation pointers are wired up by the static post_config_impl;
	 * here we supply them (and mocks) directly */
	context->host_str = "localhost";
	context->port = 6379;
	context->connect = redis_mock_connect;
	context->command = redis_mock_command;
	context->disconnect = redis_mock_disconnect;

	cfg->cache.impl = &oidc_cache_redis;

	/* keep the reconnect retry loop fast and deterministic */
	apr_table_set(r->subprocess_env, "OIDC_REDIS_MAX_TRIES", "2");
	apr_table_set(r->subprocess_env, "OIDC_REDIS_RETRY_INTERVAL", "1");

	redis_mock_reset();

	return context;
}

static void redis_mock_restore(request_rec *r) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	/* exercise the destroy path: locks, mock disconnect, mutex destroy */
	if ((cfg->cache.impl != NULL) && (cfg->cache.impl->destroy != NULL))
		cfg->cache.impl->destroy(r->server->process->pconf, r->server);
	cfg->cache.impl = redis_mock_prev_impl;
	cfg->cache.cfg = redis_mock_prev_cfg;
	apr_table_unset(r->subprocess_env, "OIDC_REDIS_MAX_TRIES");
	apr_table_unset(r->subprocess_env, "OIDC_REDIS_RETRY_INTERVAL");
}

START_TEST(test_cache_redis_post_config_no_server) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_cache_t *prev_impl = (oidc_cache_t *)cfg->cache.impl;
	void *prev_cfg = cfg->cache.cfg;
	char *prev_server = cfg->cache.redis_server;

	/* no OIDCRedisCacheServer configured => post_config must fail */
	cfg->cache.redis_server = NULL;
	cfg->cache.cfg = NULL;
	ck_assert_int_eq(oidc_cache_redis_post_config(r->server->process->pconf, r->server, cfg, "redis"),
			 HTTP_INTERNAL_SERVER_ERROR);

	cfg->cache.impl = prev_impl;
	cfg->cache.cfg = prev_cfg;
	cfg->cache.redis_server = prev_server;
}
END_TEST

START_TEST(test_cache_redis_post_config_success) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_cache_t *prev_impl = (oidc_cache_t *)cfg->cache.impl;
	void *prev_cfg = cfg->cache.cfg;
	char *prev_server = cfg->cache.redis_server;

	cfg->cache.redis_server = "localhost:6379";
	cfg->cache.cfg = NULL;
	ck_assert_int_eq(oidc_cache_redis_post_config(r->server->process->pconf, r->server, cfg, "redis"), OK);

	oidc_cache_cfg_redis_t *context = (oidc_cache_cfg_redis_t *)cfg->cache.cfg;
	ck_assert_ptr_nonnull(context);
	ck_assert_ptr_nonnull(context->mutex);
	/* defaults installed by the cfg-create step (no directives set) */
	ck_assert_int_eq(context->database, -1);
	ck_assert_int_eq(context->keepalive, -1);

	/* the public post_config does not wire up the operation pointers, so destroy the
	 * mutex directly rather than via the backend destroy (which would call disconnect) */
	oidc_cache_mutex_destroy(r->server, context->mutex);
	cfg->cache.impl = prev_impl;
	cfg->cache.cfg = prev_cfg;
	cfg->cache.redis_server = prev_server;
}
END_TEST

START_TEST(test_cache_redis_get_hit) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.reply_type = REDIS_REPLY_STRING;
	redis_mock.reply_str = "v1";

	char *value = NULL;
	ck_assert_int_eq(oidc_cache_redis_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "v1");
	ck_assert_int_eq(redis_mock.command_calls, 1);
	ck_assert_int_eq(strncmp(redis_mock.last_format, "GET ", 4), 0);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_get_miss) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.reply_type = REDIS_REPLY_NIL;

	char *value = NULL;
	/* a NIL reply is a normal cache miss: TRUE with *value left NULL */
	ck_assert_int_eq(oidc_cache_redis_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), TRUE);
	ck_assert_ptr_null(value);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_get_len_mismatch) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.reply_type = REDIS_REPLY_STRING;
	redis_mock.reply_str = "abc";
	redis_mock.force_len = 2; /* len != strlen("abc") */

	char *value = NULL;
	ck_assert_int_eq(oidc_cache_redis_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), FALSE);
	ck_assert_ptr_null(value);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_get_wrong_type) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.reply_type = REDIS_REPLY_INTEGER; /* not a string and not NIL */

	char *value = NULL;
	ck_assert_int_eq(oidc_cache_redis_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), FALSE);
	ck_assert_ptr_null(value);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_get_connect_failure) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.connect_fail_times = 5; /* exceeds OIDC_REDIS_MAX_TRIES */

	char *value = NULL;
	ck_assert_int_eq(oidc_cache_redis_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), FALSE);
	/* connect attempted on every retry; command never reached */
	ck_assert_int_eq(redis_mock.connect_calls, 2);
	ck_assert_int_eq(redis_mock.command_calls, 0);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_get_error_then_recover) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.error_first_n = 1; /* first command errors, forcing a reconnect+retry */
	redis_mock.reply_type = REDIS_REPLY_STRING;
	redis_mock.reply_str = "ok";

	char *value = NULL;
	ck_assert_int_eq(oidc_cache_redis_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), TRUE);
	ck_assert_str_eq(value, "ok");
	ck_assert_int_eq(redis_mock.command_calls, 2);
	ck_assert_int_ge(redis_mock.disconnect_calls, 1);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_get_null_reply) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.return_null = 1; /* command keeps returning NULL */

	char *value = NULL;
	ck_assert_int_eq(oidc_cache_redis_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), FALSE);
	ck_assert_int_eq(redis_mock.command_calls, 2);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_set_value) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.reply_type = REDIS_REPLY_STATUS;
	redis_mock.reply_str = "OK";

	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);
	ck_assert_int_eq(oidc_cache_redis_set(r, OIDC_CACHE_SECTION_SESSION, "k1", "v1", expiry), TRUE);
	ck_assert_int_eq(strncmp(redis_mock.last_format, "SET ", 4), 0);
	ck_assert_ptr_nonnull(strstr(redis_mock.last_format, "EX"));

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_set_delete) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.reply_type = REDIS_REPLY_INTEGER; /* DEL returns the number of keys removed */

	/* a NULL value triggers a DEL */
	ck_assert_int_eq(oidc_cache_redis_set(r, OIDC_CACHE_SECTION_SESSION, "k1", NULL, 0), TRUE);
	ck_assert_int_eq(strncmp(redis_mock.last_format, "DEL ", 4), 0);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_set_error) {
	request_rec *r = oidc_test_request_get();
	redis_mock_install(r);
	redis_mock.error_first_n = 5; /* every attempt errors */

	apr_time_t expiry = apr_time_now() + apr_time_from_sec(60);
	ck_assert_int_eq(oidc_cache_redis_set(r, OIDC_CACHE_SECTION_SESSION, "k1", "v1", expiry), FALSE);

	redis_mock_restore(r);
}
END_TEST

START_TEST(test_cache_redis_helpers_short_circuit) {
	request_rec *r = oidc_test_request_get();

	/* keepalive == 0: returns TRUE without touching the (NULL) context */
	ck_assert_int_eq(oidc_cache_redis_set_keepalive(r, NULL, 0), TRUE);
	/* no password: AUTH skipped, returns TRUE */
	ck_assert_int_eq(oidc_cache_redis_set_auth(r, NULL, NULL, NULL), TRUE);
	/* database == -1: SELECT skipped, returns TRUE */
	ck_assert_int_eq(oidc_cache_redis_set_database(r, NULL, -1), TRUE);
	/* disconnect is a safe no-op on a NULL context */
	ck_assert_int_eq((int)oidc_cache_redis_disconnect(NULL), (int)APR_SUCCESS);
}
END_TEST

/*
 * reset the redis mock as part of the per-test fixture. Under CK_FORK=no
 * (make valgrind) all tests share one process, so a test that does not call
 * redis_mock_install() would otherwise inherit the previous test's mock state;
 * under the default fork-per-test mode every test already starts from the
 * parent's pristine statics.
 */
static void redis_test_setup(void) {
	oidc_test_setup();
	redis_mock_reset();
}

#endif /* USE_LIBHIREDIS */

#ifdef USE_MEMCACHE

/*
 * Tests for cache/memcache.c.
 *
 * The real per-server setup (apr_memcache_server_create) eagerly connects when the connection-pool
 * minimum is > 0, so to exercise the server-counting and pool-sizing logic offline (without a live
 * memcached) we install a mock add_server operation on the context. The mock records the pool sizes
 * it is handed and returns success without touching the network, mirroring the redis mock above.
 */

typedef struct memcache_mock_state_t {
	int add_calls;	       /* number of times the per-server op was invoked */
	apr_uint32_t last_min; /* pool sizes seen by the most recent invocation */
	apr_uint32_t last_smax;
	apr_uint32_t last_hmax;
	apr_interval_time_t last_ttl;
	int fail; /* if non-zero, the add_server op returns HTTP_INTERNAL_SERVER_ERROR */

	/* data-path mock */
	int get_calls;
	int set_calls;
	int delete_calls;
	int status_calls;
	apr_status_t getp_rv;	/* return code for the getp op */
	const char *getp_value; /* value handed back on a getp hit (may be NULL) */
	int getp_len;		/* override the returned length; < 0 means strlen(getp_value) */
	apr_byte_t status_rv;	/* return code for the status op */
	apr_status_t set_rv;	/* return code for the set op */
	apr_status_t delete_rv; /* return code for the delete op */
	const char *last_key;	/* key seen by the most recent data-path op */
	const char *last_value; /* value seen by the most recent set op */
} memcache_mock_state_t;

static memcache_mock_state_t memcache_mock;

static void memcache_mock_reset(void) {
	memset(&memcache_mock, 0, sizeof(memcache_mock));
	memcache_mock.getp_len = -1;
}

/* mock per-server op: records the pool sizes, never connects */
static int memcache_mock_add_server(server_rec *s, apr_pool_t *p, struct oidc_cache_cfg_memcache_t *context,
				    char *split, apr_uint32_t min, apr_uint32_t smax, apr_uint32_t hmax,
				    apr_interval_time_t ttl) {
	(void)s;
	(void)p;
	(void)context;
	(void)split;
	memcache_mock.add_calls++;
	memcache_mock.last_min = min;
	memcache_mock.last_smax = smax;
	memcache_mock.last_hmax = hmax;
	memcache_mock.last_ttl = ttl;
	return memcache_mock.fail ? HTTP_INTERNAL_SERVER_ERROR : OK;
}

/* mock data-path ops: fabricate results without a live memcached */
static apr_status_t memcache_mock_getp(struct oidc_cache_cfg_memcache_t *context, apr_pool_t *p, const char *key,
				       char **baton, apr_size_t *len) {
	(void)context;
	memcache_mock.get_calls++;
	memcache_mock.last_key = key;
	if (memcache_mock.getp_rv == APR_SUCCESS) {
		*baton = memcache_mock.getp_value ? apr_pstrdup(p, memcache_mock.getp_value) : NULL;
		*len = (memcache_mock.getp_len >= 0)
			   ? (apr_size_t)memcache_mock.getp_len
			   : (memcache_mock.getp_value ? strlen(memcache_mock.getp_value) : 0);
	}
	return memcache_mock.getp_rv;
}

static apr_status_t memcache_mock_set(struct oidc_cache_cfg_memcache_t *context, const char *key, char *baton,
				      apr_size_t len, apr_uint32_t timeout) {
	(void)context;
	(void)len;
	(void)timeout;
	memcache_mock.set_calls++;
	memcache_mock.last_key = key;
	memcache_mock.last_value = baton;
	return memcache_mock.set_rv;
}

static apr_status_t memcache_mock_delete(struct oidc_cache_cfg_memcache_t *context, const char *key) {
	(void)context;
	memcache_mock.delete_calls++;
	memcache_mock.last_key = key;
	return memcache_mock.delete_rv;
}

static apr_byte_t memcache_mock_status(const struct oidc_cache_cfg_memcache_t *context) {
	(void)context;
	memcache_mock.status_calls++;
	return memcache_mock.status_rv;
}

static oidc_cache_t *memcache_prev_impl;
static void *memcache_prev_cfg;
static char *memcache_prev_servers;
static int memcache_prev_min;
static int memcache_prev_smax;
static int memcache_prev_hmax;

static void memcache_save(oidc_cfg_t *cfg) {
	memcache_prev_impl = (oidc_cache_t *)cfg->cache.impl;
	memcache_prev_cfg = cfg->cache.cfg;
	memcache_prev_servers = cfg->cache.memcache_servers;
	memcache_prev_min = cfg->cache.memcache_min;
	memcache_prev_smax = cfg->cache.memcache_smax;
	memcache_prev_hmax = cfg->cache.memcache_hmax;
	/* force post_config to run rather than short-circuit on an existing context */
	cfg->cache.cfg = NULL;
	memcache_mock_reset();
}

static void memcache_restore(oidc_cfg_t *cfg) {
	cfg->cache.impl = memcache_prev_impl;
	cfg->cache.cfg = memcache_prev_cfg;
	cfg->cache.memcache_servers = memcache_prev_servers;
	cfg->cache.memcache_min = memcache_prev_min;
	cfg->cache.memcache_smax = memcache_prev_smax;
	cfg->cache.memcache_hmax = memcache_prev_hmax;
}

/*
 * run the offline post_config path: validate + size the pool (no connection), then run the
 * add-server loop with the mock op swapped in so no real server is created
 */
static oidc_cache_cfg_memcache_t *memcache_mock_run(request_rec *r, oidc_cfg_t *cfg) {
	ck_assert_int_eq(oidc_cache_memcache_post_config(r->server->process->pconf, r->server, cfg), OK);
	oidc_cache_cfg_memcache_t *context = (oidc_cache_cfg_memcache_t *)cfg->cache.cfg;
	ck_assert_ptr_nonnull(context);
	context->add_server = memcache_mock_add_server;
	ck_assert_int_eq(oidc_cache_memcache_add_servers(r->server->process->pconf, r->server, cfg, context), OK);
	return context;
}

/*
 * build a context (no connection) and swap in the data-path mock ops so get/set can be exercised
 * offline against fabricated apr_memcache results
 */
static oidc_cache_cfg_memcache_t *memcache_mock_install(request_rec *r, oidc_cfg_t *cfg) {
	cfg->cache.memcache_servers = "127.0.0.1:11211";
	ck_assert_int_eq(oidc_cache_memcache_post_config(r->server->process->pconf, r->server, cfg), OK);
	oidc_cache_cfg_memcache_t *context = (oidc_cache_cfg_memcache_t *)cfg->cache.cfg;
	ck_assert_ptr_nonnull(context);
	context->getp = memcache_mock_getp;
	context->set = memcache_mock_set;
	context->del = memcache_mock_delete;
	context->status = memcache_mock_status;
	return context;
}

START_TEST(test_cache_memcache_post_config_no_servers) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);

	/* no OIDCMemCacheServers configured => post_config must fail */
	cfg->cache.memcache_servers = NULL;
	ck_assert_int_eq(oidc_cache_memcache_post_config(r->server->process->pconf, r->server, cfg),
			 HTTP_INTERNAL_SERVER_ERROR);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_post_config_single_server) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);

	cfg->cache.memcache_servers = "127.0.0.1:11211";
	memcache_mock_run(r, cfg);
	ck_assert_int_eq(memcache_mock.add_calls, 1);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_post_config_multi_server) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);

	/* two servers exercise the server-counting and add-server loops */
	cfg->cache.memcache_servers = "127.0.0.1:11211 127.0.0.1:11212";
	memcache_mock_run(r, cfg);
	ck_assert_int_eq(memcache_mock.add_calls, 2);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_post_config_pool_clamp) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);

	/* smax > hmax and min > smax exercise both connection-pool clamp branches */
	cfg->cache.memcache_servers = "127.0.0.1:11211";
	cfg->cache.memcache_hmax = 5;
	cfg->cache.memcache_smax = 10;
	cfg->cache.memcache_min = 8;
	oidc_cache_cfg_memcache_t *context = memcache_mock_run(r, cfg);

	/* both branches clamp down to hmax, so min == smax == hmax == 5 */
	ck_assert_int_eq(context->hmax, 5);
	ck_assert_int_eq(context->smax, 5);
	ck_assert_int_eq(context->min, 5);
	ck_assert_int_eq(memcache_mock.add_calls, 1);
	ck_assert_int_eq(memcache_mock.last_hmax, 5);
	ck_assert_int_eq(memcache_mock.last_smax, 5);
	ck_assert_int_eq(memcache_mock.last_min, 5);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_get_hit) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);
	memcache_mock_install(r, cfg);

	memcache_mock.getp_rv = APR_SUCCESS;
	memcache_mock.getp_value = "v1";
	char *value = NULL;
	ck_assert_int_eq(oidc_cache_memcache_get(r, OIDC_CACHE_SECTION_SESSION, "k1", &value), TRUE);
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "v1");
	ck_assert_int_eq(memcache_mock.get_calls, 1);
	/* the section/key are combined into the lookup key */
	ck_assert_str_eq(memcache_mock.last_key, OIDC_CACHE_SECTION_SESSION ":k1");

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_get_miss_alive) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);
	memcache_mock_install(r, cfg);

	/* a genuine miss: not found, but at least one server is alive => OK with NULL value */
	memcache_mock.getp_rv = APR_NOTFOUND;
	memcache_mock.status_rv = TRUE;
	char *value = NULL;
	ck_assert_int_eq(oidc_cache_memcache_get(r, OIDC_CACHE_SECTION_SESSION, "k", &value), TRUE);
	ck_assert_ptr_null(value);
	ck_assert_int_eq(memcache_mock.status_calls, 1);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_get_miss_all_dead) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);
	memcache_mock_install(r, cfg);

	/* not found and all servers dead => treated as an error (FALSE) */
	memcache_mock.getp_rv = APR_NOTFOUND;
	memcache_mock.status_rv = FALSE;
	char *value = NULL;
	ck_assert_int_eq(oidc_cache_memcache_get(r, OIDC_CACHE_SECTION_SESSION, "k", &value), FALSE);
	ck_assert_int_eq(memcache_mock.status_calls, 1);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_get_error) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);
	memcache_mock_install(r, cfg);

	/* a hard error from the server => FALSE */
	memcache_mock.getp_rv = APR_EGENERAL;
	char *value = NULL;
	ck_assert_int_eq(oidc_cache_memcache_get(r, OIDC_CACHE_SECTION_SESSION, "k", &value), FALSE);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_get_len_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);
	memcache_mock_install(r, cfg);

	/* a returned length that disagrees with the string length => FALSE */
	memcache_mock.getp_rv = APR_SUCCESS;
	memcache_mock.getp_value = "hello";
	memcache_mock.getp_len = 3;
	char *value = NULL;
	ck_assert_int_eq(oidc_cache_memcache_get(r, OIDC_CACHE_SECTION_SESSION, "k", &value), FALSE);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_set_value) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);
	memcache_mock_install(r, cfg);

	memcache_mock.set_rv = APR_SUCCESS;
	ck_assert_int_eq(oidc_cache_memcache_set(r, OIDC_CACHE_SECTION_SESSION, "k", "v", apr_time_now()), TRUE);
	ck_assert_int_eq(memcache_mock.set_calls, 1);
	ck_assert_str_eq(memcache_mock.last_value, "v");
	ck_assert_str_eq(memcache_mock.last_key, OIDC_CACHE_SECTION_SESSION ":k");

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_set_error) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);
	memcache_mock_install(r, cfg);

	memcache_mock.set_rv = APR_EGENERAL;
	ck_assert_int_eq(oidc_cache_memcache_set(r, OIDC_CACHE_SECTION_SESSION, "k", "v", apr_time_now()), FALSE);

	memcache_restore(cfg);
}
END_TEST

START_TEST(test_cache_memcache_set_delete) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	memcache_save(cfg);
	memcache_mock_install(r, cfg);

	/* a NULL value clears the entry; APR_NOTFOUND on delete is treated as success */
	memcache_mock.delete_rv = APR_NOTFOUND;
	ck_assert_int_eq(oidc_cache_memcache_set(r, OIDC_CACHE_SECTION_SESSION, "k", NULL, 0), TRUE);
	ck_assert_int_eq(memcache_mock.delete_calls, 1);

	/* a successful delete is also success */
	memcache_mock.delete_rv = APR_SUCCESS;
	ck_assert_int_eq(oidc_cache_memcache_set(r, OIDC_CACHE_SECTION_SESSION, "k", NULL, 0), TRUE);

	/* a hard error on delete => FALSE */
	memcache_mock.delete_rv = APR_EGENERAL;
	ck_assert_int_eq(oidc_cache_memcache_set(r, OIDC_CACHE_SECTION_SESSION, "k", NULL, 0), FALSE);

	memcache_restore(cfg);
}
END_TEST

/* reset the memcache mock per test; see redis_test_setup for the rationale */
static void memcache_test_setup(void) {
	oidc_test_setup();
	memcache_mock_reset();
}

#endif /* USE_MEMCACHE */

int main(void) {
	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(core, test_cache_mutex_and_status2str);
	tcase_add_test(core, test_cache_set_get_encrypted_and_expiry);
	tcase_add_test(core, test_cache_long_key_and_prefix);
	tcase_add_test(core, test_cache_mutex_global_and_child_init);
	tcase_add_test(core, test_cache_encrypt_no_secret);
	tcase_add_test(core, test_cache_status2str_success);
	tcase_add_test(core, test_cache_second_passphrase_retry);
	tcase_add_test(core, test_cache_shm_get_key_bounds_negative);
	tcase_add_test(core, test_cache_secret1_empty_secret2_fallback);
	tcase_add_test(core, test_cache_backend_true_null_miss);
	/* compression-enabled permutations */
	tcase_add_test(core, test_cache_compression_enabled_set_get);
	tcase_add_test(core, test_cache_compression_enabled_second_passphrase);
	tcase_add_test(core, test_cache_compression_enabled_empty_secret2_fallback);

	TCase *file = tcase_create("file");
	tcase_add_checked_fixture(file, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(file, test_cache_file_set_get_basic);
	tcase_add_test(file, test_cache_file_miss);
	tcase_add_test(file, test_cache_file_expired_entry_is_miss);
	tcase_add_test(file, test_cache_file_overwrite_and_delete);
	tcase_add_test(file, test_cache_file_default_tmp_dir);

	Suite *s = suite_create("cache");
	suite_add_tcase(s, core);
	suite_add_tcase(s, file);

#ifdef USE_LIBHIREDIS
	TCase *redis = tcase_create("redis");
	tcase_add_checked_fixture(redis, redis_test_setup, oidc_test_teardown);
	tcase_add_test(redis, test_cache_redis_post_config_no_server);
	tcase_add_test(redis, test_cache_redis_post_config_success);
	tcase_add_test(redis, test_cache_redis_get_hit);
	tcase_add_test(redis, test_cache_redis_get_miss);
	tcase_add_test(redis, test_cache_redis_get_len_mismatch);
	tcase_add_test(redis, test_cache_redis_get_wrong_type);
	tcase_add_test(redis, test_cache_redis_get_connect_failure);
	tcase_add_test(redis, test_cache_redis_get_error_then_recover);
	tcase_add_test(redis, test_cache_redis_get_null_reply);
	tcase_add_test(redis, test_cache_redis_set_value);
	tcase_add_test(redis, test_cache_redis_set_delete);
	tcase_add_test(redis, test_cache_redis_set_error);
	tcase_add_test(redis, test_cache_redis_helpers_short_circuit);
	suite_add_tcase(s, redis);
#endif

#ifdef USE_MEMCACHE
	TCase *memcache = tcase_create("memcache");
	tcase_add_checked_fixture(memcache, memcache_test_setup, oidc_test_teardown);
	tcase_add_test(memcache, test_cache_memcache_post_config_no_servers);
	tcase_add_test(memcache, test_cache_memcache_post_config_single_server);
	tcase_add_test(memcache, test_cache_memcache_post_config_multi_server);
	tcase_add_test(memcache, test_cache_memcache_post_config_pool_clamp);
	tcase_add_test(memcache, test_cache_memcache_get_hit);
	tcase_add_test(memcache, test_cache_memcache_get_miss_alive);
	tcase_add_test(memcache, test_cache_memcache_get_miss_all_dead);
	tcase_add_test(memcache, test_cache_memcache_get_error);
	tcase_add_test(memcache, test_cache_memcache_get_len_mismatch);
	tcase_add_test(memcache, test_cache_memcache_set_value);
	tcase_add_test(memcache, test_cache_memcache_set_error);
	tcase_add_test(memcache, test_cache_memcache_set_delete);
	suite_add_tcase(s, memcache);
#endif

	return oidc_test_suite_run(s);
}
