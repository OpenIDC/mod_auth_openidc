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
#include "check_util.h"
#include "jose.h"
#include "util.h"

// provider

START_TEST(test_cmd_provider_token_endpoint_auth_set) {
	void *ptr = NULL;
	const char *arg = NULL;
	const char *rv = NULL;
	cmd_parms *cmd = oidc_test_cmd_get(OIDCProviderTokenEndpointAuth);

	arg = "private_key_jwt";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "failed: %s", rv);

	arg = "private_key_jws";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv != NULL, "should have failed");

	arg = "private_key_jwt:RS256";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "failed: %s", rv);

	arg = "private_key_jwt:RA256";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv != NULL, "should have failed");
}
END_TEST

#ifdef USE_MEMCACHE

START_TEST(test_cfg_cache_connections_ttl) {
	const char *rv = NULL;
	void *ptr = NULL;
	const char *arg = NULL;
	apr_interval_time_t ttl = 0;
	oidc_cfg_t *cfg = NULL;

	cfg = oidc_test_cfg_get();
	ck_assert_msg(cfg->cache.memcache_ttl == OIDC_CONFIG_POS_TIMEOUT_UNSET,
		      "default not set to OIDC_CONFIG_POS_TIMEOUT_UNSET: %d", (int)cfg->cache.memcache_ttl);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCMemCacheConnectionsTTL);

	ttl = oidc_cfg_cache_memcache_ttl_get(cfg);
	ck_assert_msg(ttl == apr_time_from_sec(60), "default not set to 60s: %d", (int)ttl);

	arg = "bogus";
	rv = oidc_cmd_cache_memcache_ttl_set(cmd, ptr, arg);
	ck_assert_msg(rv != NULL, "set to \"bogus\" did not fail");

	arg = "-2";
	rv = oidc_cmd_cache_memcache_ttl_set(cmd, ptr, arg);
	ck_assert_msg(rv != NULL, "set to \"-2\" did not fail");

	arg = "120";
	rv = oidc_cmd_cache_memcache_ttl_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "set to 120 failed");

	arg = "4294";
	rv = oidc_cmd_cache_memcache_ttl_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "set to 4294 failed");

	arg = "4295";
	rv = oidc_cmd_cache_memcache_ttl_set(cmd, ptr, arg);
	ck_assert_msg(rv != NULL, "set to 4295 did not fail");

#if AP_MODULE_MAGIC_AT_LEAST(20080920, 2)
	arg = "180s";
#else
	arg = "180";
#endif
	rv = oidc_cmd_cache_memcache_ttl_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "set to %s failed", arg);

	ttl = oidc_cfg_cache_memcache_ttl_get(cfg);
	ck_assert_msg(ttl == apr_time_from_sec(180), "get 180 failed: %d", (int)ttl);
}
END_TEST

#endif

START_TEST(test_cmd_cookie_same_site) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCookieSameSite);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	// default is Lax
	ck_assert_int_eq(oidc_cfg_cookie_same_site_session_get(cfg), OIDC_SAMESITE_COOKIE_LAX);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_state_get(cfg), OIDC_SAMESITE_COOKIE_LAX);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_discovery_csrf_get(cfg), OIDC_SAMESITE_COOKIE_LAX);

	ck_assert_ptr_null(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "Lax", NULL, NULL));
	ck_assert_int_eq(oidc_cfg_cookie_same_site_session_get(cfg), OIDC_SAMESITE_COOKIE_LAX);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_state_get(cfg), OIDC_SAMESITE_COOKIE_LAX);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_discovery_csrf_get(cfg), OIDC_SAMESITE_COOKIE_LAX);

	// state and csrf cookies should inherit from session cookie */
	ck_assert_ptr_null(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "Strict", NULL, NULL));
	ck_assert_int_eq(oidc_cfg_cookie_same_site_session_get(cfg), OIDC_SAMESITE_COOKIE_STRICT);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_state_get(cfg), OIDC_SAMESITE_COOKIE_STRICT);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_discovery_csrf_get(cfg), OIDC_SAMESITE_COOKIE_STRICT);

	ck_assert_ptr_null(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "None", NULL, NULL));
	ck_assert_int_eq(oidc_cfg_cookie_same_site_session_get(cfg), OIDC_SAMESITE_COOKIE_NONE);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_state_get(cfg), OIDC_SAMESITE_COOKIE_NONE);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_discovery_csrf_get(cfg), OIDC_SAMESITE_COOKIE_NONE);

	ck_assert_ptr_null(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "Disabled", NULL, NULL));
	ck_assert_int_eq(oidc_cfg_cookie_same_site_session_get(cfg), OIDC_SAMESITE_COOKIE_DISABLED);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_state_get(cfg), OIDC_SAMESITE_COOKIE_DISABLED);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_discovery_csrf_get(cfg), OIDC_SAMESITE_COOKIE_DISABLED);

	ck_assert_ptr_nonnull(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "InvalidValue", NULL, NULL));
	ck_assert_ptr_nonnull(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "Strict", "On", NULL));
	ck_assert_ptr_nonnull(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "Strict", "Lax", "Off"));

	ck_assert_ptr_null(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "Strict", "None", NULL));
	ck_assert_int_eq(oidc_cfg_cookie_same_site_session_get(cfg), OIDC_SAMESITE_COOKIE_STRICT);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_state_get(cfg), OIDC_SAMESITE_COOKIE_NONE);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_discovery_csrf_get(cfg), OIDC_SAMESITE_COOKIE_STRICT);

	ck_assert_ptr_null(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "Strict", "None", "Lax"));
	ck_assert_int_eq(oidc_cfg_cookie_same_site_session_get(cfg), OIDC_SAMESITE_COOKIE_STRICT);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_state_get(cfg), OIDC_SAMESITE_COOKIE_NONE);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_discovery_csrf_get(cfg), OIDC_SAMESITE_COOKIE_LAX);

	ck_assert_ptr_null(oidc_cmd_cookie_same_site_session_set(cmd, NULL, "Lax", "Lax", "None"));
	ck_assert_int_eq(oidc_cfg_cookie_same_site_session_get(cfg), OIDC_SAMESITE_COOKIE_LAX);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_state_get(cfg), OIDC_SAMESITE_COOKIE_LAX);
	ck_assert_int_eq(oidc_cfg_cookie_same_site_discovery_csrf_get(cfg), OIDC_SAMESITE_COOKIE_NONE);
}
END_TEST

START_TEST(test_cmd_oauth_verify_shared_keys) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthVerifySharedKeys);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	apr_hash_t *keys = NULL;
	oidc_jwk_t *jwk = NULL;
	apr_hash_index_t *hi = NULL;

	keys = oidc_cfg_oauth_verify_shared_keys_get(cfg);
	ck_assert_ptr_null(keys);

	ck_assert_ptr_null(oidc_cmd_oauth_verify_shared_keys_set(cmd, NULL, "mysecret"));
	keys = oidc_cfg_oauth_verify_shared_keys_get(cfg);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(apr_hash_count(keys), 1);
	hi = apr_hash_first(cmd->pool, keys);
	apr_hash_this(hi, NULL, NULL, (void **)&jwk);
	ck_assert_ptr_nonnull(jwk);
	ck_assert_int_eq(jwk->kty, CJOSE_JWK_KTY_OCT);
	ck_assert_ptr_null(jwk->use);

	ck_assert_ptr_null(oidc_cmd_oauth_verify_shared_keys_set(cmd, NULL, "enc:mykid#mysecret2"));
	keys = oidc_cfg_oauth_verify_shared_keys_get(cfg);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(apr_hash_count(keys), 2);
	jwk = apr_hash_get(keys, "mykid", APR_HASH_KEY_STRING);
	ck_assert_ptr_nonnull(jwk);
	ck_assert_int_eq(jwk->kty, CJOSE_JWK_KTY_OCT);
	ck_assert_str_eq(jwk->use, "enc");
	ck_assert_str_eq(jwk->kid, "mykid");

	oidc_jwk_list_destroy_hash(keys);
}
END_TEST

int main(void) {
	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(core, test_cmd_provider_token_endpoint_auth_set);
#ifdef USE_MEMCACHE
	tcase_add_test(core, test_cfg_cache_connections_ttl);
#endif
	tcase_add_test(core, test_cmd_cookie_same_site);
	tcase_add_test(core, test_cmd_oauth_verify_shared_keys);

	Suite *s = suite_create("cfg");
	suite_add_tcase(s, core);

	return oidc_test_suite_run(s);
}
