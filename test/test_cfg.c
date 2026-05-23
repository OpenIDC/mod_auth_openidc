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

#include "cfg/cache.h"
#include "cfg/cfg_int.h"
#include "cfg/dir.h"
#include "cfg/provider.h"
#include "check_util.h"
#include "jose.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
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

/*
 * Tests for the cfg/dir.c directive setters. These follow the existing
 * test_cmd_* pattern: drive each oidc_cmd_dir_*_set through its valid /
 * invalid input matrix and assert the dir_cfg getter reflects the change.
 */

START_TEST(test_cmd_dir_pass_userinfo_as) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);

	/* every documented variant must parse — the cmd handler writes into its arg buffer
	 * (to split the "type:name" form), so the arg must be pool-allocated (mutable) */
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "claims")));
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "json")));
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "jwt")));
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "signed_jwt")));
	/* "type:name" form is accepted, the colon-suffix sets a custom header name */
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "json:CUSTOM-HDR")));
	const apr_array_header_t *arr = oidc_cfg_dir_pass_userinfo_as_get(r);
	ck_assert_ptr_nonnull(arr);
	ck_assert_int_gt(arr->nelts, 0);

	/* unknown variant rejected */
	ck_assert_ptr_nonnull(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "totally_bogus")));
}
END_TEST

START_TEST(test_cmd_dir_pass_claims_as) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassClaimsAs);

	/* one-arg form sets pass_in and leaves encoding at default */
	ck_assert_ptr_null(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "headers", NULL));
	ck_assert_int_eq(oidc_cfg_dir_pass_info_in_get(r), OIDC_APPINFO_PASS_HEADERS);

	ck_assert_ptr_null(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "environment", NULL));
	ck_assert_int_eq(oidc_cfg_dir_pass_info_in_get(r), OIDC_APPINFO_PASS_ENVVARS);

	ck_assert_ptr_null(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "both", NULL));
	/* OIDC_APPINFO_PASS_BOTH is a dir.c-internal alias for HEADERS|ENVVARS */
	ck_assert_int_eq(oidc_cfg_dir_pass_info_in_get(r), OIDC_APPINFO_PASS_HEADERS | OIDC_APPINFO_PASS_ENVVARS);

	ck_assert_ptr_null(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "none", NULL));
	ck_assert_int_eq(oidc_cfg_dir_pass_info_in_get(r), OIDC_APPINFO_PASS_NONE);

	/* two-arg form sets the encoding too */
	ck_assert_ptr_null(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "headers", "base64url"));
	ck_assert_int_eq(oidc_cfg_dir_pass_info_encoding_get(r), OIDC_APPINFO_ENCODING_BASE64URL);

	ck_assert_ptr_null(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "headers", "latin1"));
	ck_assert_int_eq(oidc_cfg_dir_pass_info_encoding_get(r), OIDC_APPINFO_ENCODING_LATIN1);

	/* both args reject unknowns */
	ck_assert_ptr_nonnull(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "BOGUS", NULL));
	ck_assert_ptr_nonnull(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "headers", "BOGUS-ENC"));
}
END_TEST

START_TEST(test_cmd_dir_accept_oauth_token_in) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get("OIDCOAuthAcceptTokenAs");

	/* every documented source must parse */
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "header"));
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "post"));
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "query"));
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "basic"));
	/* cookie with the default name */
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "cookie"));
	ck_assert_str_eq(oidc_cfg_dir_accept_token_in_option_get(r, OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME),
			 "PA.global");
	/* cookie with a custom name */
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "cookie:my-at-cookie"));
	ck_assert_str_eq(oidc_cfg_dir_accept_token_in_option_get(r, OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME),
			 "my-at-cookie");

	/* unknown source rejected */
	ck_assert_ptr_nonnull(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "smoke_signal"));
}
END_TEST

/*
 * Tests for the cfg/provider.c directive setters. Provider cmd setters look
 * up cfg via the server's module config, so passing NULL for the dir-cfg
 * parameter (the usual cmd-table convention) is fine.
 */

START_TEST(test_cmd_provider_response_type) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCResponseType);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	ck_assert_ptr_null(oidc_cmd_provider_response_type_set(cmd, NULL, "code"));
	ck_assert_str_eq(oidc_cfg_provider_response_type_get(p), "code");
	ck_assert_ptr_null(oidc_cmd_provider_response_type_set(cmd, NULL, "id_token"));
	ck_assert_str_eq(oidc_cfg_provider_response_type_get(p), "id_token");
	ck_assert_ptr_null(oidc_cmd_provider_response_type_set(cmd, NULL, "code id_token"));
	/* unsupported flow */
	ck_assert_ptr_nonnull(oidc_cmd_provider_response_type_set(cmd, NULL, "totally_bogus_flow"));
}
END_TEST

START_TEST(test_cmd_provider_session_max_duration) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCSessionMaxDuration);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	/* 0 is the special "no max" sentinel */
	ck_assert_ptr_null(oidc_cmd_provider_session_max_duration_set(cmd, NULL, "0"));
	ck_assert_int_eq(oidc_cfg_provider_session_max_duration_get(p), 0);

	ck_assert_ptr_null(oidc_cmd_provider_session_max_duration_set(cmd, NULL, "3600"));
	ck_assert_int_eq(oidc_cfg_provider_session_max_duration_get(p), 3600);

	/* below the minimum (15) is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_provider_session_max_duration_set(cmd, NULL, "5"));
	/* above the maximum (1 year) is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_provider_session_max_duration_set(cmd, NULL, "999999999"));
	/* non-numeric input is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_provider_session_max_duration_set(cmd, NULL, "soon"));
}
END_TEST

START_TEST(test_cmd_provider_scope) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCScope);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	ck_assert_ptr_null(oidc_cmd_provider_scope_set(cmd, NULL, "openid"));
	ck_assert_str_eq(oidc_cfg_provider_scope_get(p), "openid");
	ck_assert_ptr_null(oidc_cmd_provider_scope_set(cmd, NULL, "openid profile email"));
	ck_assert_str_eq(oidc_cfg_provider_scope_get(p), "openid profile email");
}
END_TEST

START_TEST(test_cmd_provider_dpop_mode) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCDPoPMode);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	ck_assert_ptr_null(oidc_cmd_provider_dpop_mode_set(cmd, NULL, "off", NULL));
	ck_assert_int_eq(oidc_cfg_provider_dpop_mode_get(p), OIDC_DPOP_MODE_OFF);
	ck_assert_ptr_null(oidc_cmd_provider_dpop_mode_set(cmd, NULL, "optional", NULL));
	ck_assert_int_eq(oidc_cfg_provider_dpop_mode_get(p), OIDC_DPOP_MODE_OPTIONAL);
	ck_assert_ptr_null(oidc_cmd_provider_dpop_mode_set(cmd, NULL, "required", NULL));
	ck_assert_int_eq(oidc_cfg_provider_dpop_mode_get(p), OIDC_DPOP_MODE_REQUIRED);
	/* unknown mode */
	ck_assert_ptr_nonnull(oidc_cmd_provider_dpop_mode_set(cmd, NULL, "maybe_later", NULL));
}
END_TEST

START_TEST(test_cmd_provider_pkce) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPKCEMethod);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	ck_assert_ptr_null(oidc_cmd_provider_pkce_set(cmd, NULL, OIDC_PKCE_METHOD_PLAIN));
	ck_assert_ptr_eq(oidc_cfg_provider_pkce_get(p), &oidc_pkce_plain);

	ck_assert_ptr_null(oidc_cmd_provider_pkce_set(cmd, NULL, OIDC_PKCE_METHOD_S256));
	ck_assert_ptr_eq(oidc_cfg_provider_pkce_get(p), &oidc_pkce_s256);

	ck_assert_ptr_null(oidc_cmd_provider_pkce_set(cmd, NULL, OIDC_PKCE_METHOD_NONE));
	ck_assert_ptr_eq(oidc_cfg_provider_pkce_get(p), &oidc_pkce_none);

	ck_assert_ptr_nonnull(oidc_cmd_provider_pkce_set(cmd, NULL, "totally_bogus"));
}
END_TEST

START_TEST(test_cmd_provider_idtoken_iat_slack) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCIDTokenIatSlack);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	ck_assert_ptr_null(oidc_cmd_provider_idtoken_iat_slack_set(cmd, NULL, "60"));
	ck_assert_int_eq(oidc_cfg_provider_idtoken_iat_slack_get(p), 60);
	/* non-numeric input rejected */
	ck_assert_ptr_nonnull(oidc_cmd_provider_idtoken_iat_slack_set(cmd, NULL, "moments"));
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

	TCase *dir = tcase_create("dir");
	tcase_add_checked_fixture(dir, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(dir, test_cmd_dir_pass_userinfo_as);
	tcase_add_test(dir, test_cmd_dir_pass_claims_as);
	tcase_add_test(dir, test_cmd_dir_accept_oauth_token_in);

	TCase *provider = tcase_create("provider");
	tcase_add_checked_fixture(provider, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(provider, test_cmd_provider_response_type);
	tcase_add_test(provider, test_cmd_provider_session_max_duration);
	tcase_add_test(provider, test_cmd_provider_scope);
	tcase_add_test(provider, test_cmd_provider_dpop_mode);
	tcase_add_test(provider, test_cmd_provider_pkce);
	tcase_add_test(provider, test_cmd_provider_idtoken_iat_slack);

	Suite *s = suite_create("cfg");
	suite_add_tcase(s, core);
	suite_add_tcase(s, dir);
	suite_add_tcase(s, provider);

	return oidc_test_suite_run(s);
}
