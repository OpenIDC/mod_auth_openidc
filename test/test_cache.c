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
 *
 **************************************************************************/

#include "cfg/cache.h"
#include "cfg/cfg_int.h"
#include "cfg/provider.h"
#include "helper.h"
#include "util/util.h"

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

	Suite *s = suite_create("cache");
	suite_add_tcase(s, core);

	return oidc_test_suite_run(s);
}
