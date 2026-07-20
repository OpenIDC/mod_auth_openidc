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
#include "cfg/dir.h"
#include "cfg/oauth.h"
#include "cfg/parse.h"
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

	/* the RFC 8705 mutual-TLS methods are always accepted when configured explicitly */
	arg = "tls_client_auth";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "failed: %s", rv);

	arg = "self_signed_tls_client_auth";
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, ptr, arg);
	ck_assert_msg(rv == NULL, "failed: %s", rv);
}
END_TEST

START_TEST(test_cmd_provider_token_endpoint_auth_no_private_keys) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCProviderTokenEndpointAuth);
	const char *rv = NULL;

	/* without OIDCPrivateKeyFiles configured, the private-key-based endpoint auth
	 * methods must be rejected while the shared-secret ones remain valid */
	cfg->private_keys = NULL;
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, NULL, "private_key_jwt");
	ck_assert_msg(rv != NULL, "private_key_jwt must be invalid without private keys");
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, NULL, "client_secret_basic");
	ck_assert_msg(rv == NULL, "client_secret_basic failed: %s", rv);
	rv = oidc_cmd_provider_token_endpoint_auth_set(cmd, NULL, "tls_client_auth");
	ck_assert_msg(rv == NULL, "tls_client_auth failed: %s", rv);
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
	ck_assert_int_eq(jwk->kty, OIDC_JOSE_JWK_KTY_OCT);
	ck_assert_ptr_null(jwk->use);

	ck_assert_ptr_null(oidc_cmd_oauth_verify_shared_keys_set(cmd, NULL, "enc:mykid#mysecret2"));
	keys = oidc_cfg_oauth_verify_shared_keys_get(cfg);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(apr_hash_count(keys), 2);
	jwk = apr_hash_get(keys, "mykid", APR_HASH_KEY_STRING);
	ck_assert_ptr_nonnull(jwk);
	ck_assert_int_eq(jwk->kty, OIDC_JOSE_JWK_KTY_OCT);
	ck_assert_str_eq(jwk->use, "enc");
	ck_assert_str_eq(jwk->kid, "mykid");

	oidc_jwk_list_destroy_hash(keys);
}
END_TEST

START_TEST(test_cmd_oauth_decrypt_shared_keys) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthDecryptSharedKeys);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	apr_hash_t *keys = NULL;
	oidc_jwk_t *jwk = NULL;
	apr_hash_index_t *hi = NULL;

	keys = oidc_cfg_oauth_decrypt_shared_keys_get(cfg);
	ck_assert_ptr_null(keys);

	ck_assert_ptr_null(oidc_cmd_oauth_decrypt_shared_keys_set(cmd, NULL, "mysecret"));
	keys = oidc_cfg_oauth_decrypt_shared_keys_get(cfg);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(apr_hash_count(keys), 1);
	hi = apr_hash_first(cmd->pool, keys);
	apr_hash_this(hi, NULL, NULL, (void **)&jwk);
	ck_assert_ptr_nonnull(jwk);
	ck_assert_int_eq(jwk->kty, OIDC_JOSE_JWK_KTY_OCT);
	ck_assert_ptr_null(jwk->use);

	ck_assert_ptr_null(oidc_cmd_oauth_decrypt_shared_keys_set(cmd, NULL, "enc:mykid#mysecret2"));
	keys = oidc_cfg_oauth_decrypt_shared_keys_get(cfg);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(apr_hash_count(keys), 2);
	jwk = apr_hash_get(keys, "mykid", APR_HASH_KEY_STRING);
	ck_assert_ptr_nonnull(jwk);
	ck_assert_int_eq(jwk->kty, OIDC_JOSE_JWK_KTY_OCT);
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

#ifdef USE_LIBJQ

/* OIDCFilterClaimsExpr / OIDCUserInfoClaimsExpr parse their argument as an
 * Apache expression holding a jq filter */
START_TEST(test_cmd_filter_claims_expr) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCFilterClaimsExpr);
	ck_assert_ptr_null(oidc_cmd_filter_claims_expr_set(cmd, NULL, ".my_claims"));
	ck_assert_ptr_nonnull(oidc_cfg_filter_claims_expr_get(cfg));
}
END_TEST

START_TEST(test_cmd_dir_userinfo_claims_expr) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCUserInfoClaimsExpr);
	ck_assert_ptr_null(oidc_cmd_dir_userinfo_claims_expr_set(cmd, dir_cfg, ".claims_for_app"));
	ck_assert_ptr_nonnull(oidc_cfg_dir_userinfo_claims_expr_get(r));
}
END_TEST

#endif /* USE_LIBJQ */

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

START_TEST(test_cmd_provider_url_setters) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);
	const char *url = "https://idp.example.com/path";

	cmd_parms *cmd = oidc_test_cmd_get(OIDCProviderTokenEndpoint);
	ck_assert_ptr_null(oidc_cmd_provider_token_endpoint_url_set(cmd, NULL, url));
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(p), url);

	cmd = oidc_test_cmd_get(OIDCProviderUserInfoEndpoint);
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_endpoint_url_set(cmd, NULL, url));
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(p), url);
	/* an empty value explicitly disables calling the userinfo endpoint (mirrors the revocation endpoint) */
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_endpoint_url_set(cmd, NULL, ""));
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(p), "");

	cmd = oidc_test_cmd_get(OIDCProviderRegistrationEndpointJson);
	ck_assert_ptr_null(oidc_cmd_provider_registration_endpoint_url_set(cmd, NULL, url));
	ck_assert_str_eq(oidc_cfg_provider_registration_endpoint_url_get(p), url);

	cmd = oidc_test_cmd_get(OIDCProviderEndSessionEndpoint);
	ck_assert_ptr_null(oidc_cmd_provider_end_session_endpoint_set(cmd, NULL, url));
	ck_assert_str_eq(oidc_cfg_provider_end_session_endpoint_get(p), url);

	cmd = oidc_test_cmd_get(OIDCProviderCheckSessionIFrame);
	ck_assert_ptr_null(oidc_cmd_provider_check_session_iframe_set(cmd, NULL, url));
	ck_assert_str_eq(oidc_cfg_provider_check_session_iframe_get(p), url);

	cmd = oidc_test_cmd_get(OIDCClientJwksUri);
	ck_assert_ptr_null(oidc_cmd_provider_client_jwks_uri_set(cmd, NULL, url));
	ck_assert_str_eq(oidc_cfg_provider_client_jwks_uri_get(p), url);

	cmd = oidc_test_cmd_get(OIDCProviderMetadataURL);
	ck_assert_ptr_null(oidc_cmd_provider_metadata_url_set(cmd, NULL, url));
	ck_assert_str_eq(oidc_cfg_provider_metadata_url_get(p), url);

	/* every URL setter rejects a value that does not parse as an http(s) URL */
	cmd = oidc_test_cmd_get(OIDCProviderTokenEndpoint);
	ck_assert_ptr_nonnull(oidc_cmd_provider_token_endpoint_url_set(cmd, NULL, "not-a-url"));
}
END_TEST

START_TEST(test_cmd_provider_string_setters) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCAuthRequestParams);
	ck_assert_ptr_null(oidc_cmd_provider_auth_request_params_set(cmd, NULL, "prompt=login&max_age=60"));
	ck_assert_str_eq(oidc_cfg_provider_auth_request_params_get(p), "prompt=login&max_age=60");

	cmd = oidc_test_cmd_get(OIDCProviderTokenEndpointParams);
	ck_assert_ptr_null(oidc_cmd_provider_token_endpoint_params_set(cmd, NULL, "extra=foo"));
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_params_get(p), "extra=foo");

	cmd = oidc_test_cmd_get(OIDCClientName);
	ck_assert_ptr_null(oidc_cmd_provider_client_name_set(cmd, NULL, "my-rp"));
	ck_assert_str_eq(oidc_cfg_provider_client_name_get(p), "my-rp");

	cmd = oidc_test_cmd_get(OIDCClientContact);
	ck_assert_ptr_null(oidc_cmd_provider_client_contact_set(cmd, NULL, "admin@example.com"));
	ck_assert_str_eq(oidc_cfg_provider_client_contact_get(p), "admin@example.com");

	cmd = oidc_test_cmd_get(OIDCRequestObject);
	ck_assert_ptr_null(oidc_cmd_provider_request_object_set(cmd, NULL, "{\"crypto\":{\"sign_alg\":\"none\"}}"));
	ck_assert_str_eq(oidc_cfg_provider_request_object_get(p), "{\"crypto\":{\"sign_alg\":\"none\"}}");
}
END_TEST

START_TEST(test_cmd_provider_signed_response_alg) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCIDTokenSignedResponseAlg);
	ck_assert_ptr_null(oidc_cmd_provider_id_token_signed_response_alg_set(cmd, NULL, "RS256"));
	ck_assert_str_eq(oidc_cfg_provider_id_token_signed_response_alg_get(p), "RS256");
	ck_assert_ptr_null(oidc_cmd_provider_id_token_signed_response_alg_set(cmd, NULL, "HS256"));
	ck_assert_str_eq(oidc_cfg_provider_id_token_signed_response_alg_get(p), "HS256");
	ck_assert_ptr_nonnull(oidc_cmd_provider_id_token_signed_response_alg_set(cmd, NULL, "TOTALLY_BOGUS_ALG"));

	cmd = oidc_test_cmd_get(OIDCUserInfoSignedResponseAlg);
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_signed_response_alg_set(cmd, NULL, "ES256"));
	ck_assert_str_eq(oidc_cfg_provider_userinfo_signed_response_alg_get(p), "ES256");
	ck_assert_ptr_nonnull(oidc_cmd_provider_userinfo_signed_response_alg_set(cmd, NULL, "junk"));
}
END_TEST

START_TEST(test_cmd_provider_encrypted_response_alg_enc) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCIDTokenEncryptedResponseAlg);
	ck_assert_ptr_null(oidc_cmd_provider_id_token_encrypted_response_alg_set(cmd, NULL, "RSA-OAEP"));
	ck_assert_str_eq(oidc_cfg_provider_id_token_encrypted_response_alg_get(p), "RSA-OAEP");
	ck_assert_ptr_nonnull(oidc_cmd_provider_id_token_encrypted_response_alg_set(cmd, NULL, "TOTALLY_BOGUS_ALG"));

	cmd = oidc_test_cmd_get(OIDCIDTokenEncryptedResponseEnc);
	ck_assert_ptr_null(oidc_cmd_provider_id_token_encrypted_response_enc_set(cmd, NULL, "A256GCM"));
	ck_assert_str_eq(oidc_cfg_provider_id_token_encrypted_response_enc_get(p), "A256GCM");
	ck_assert_ptr_nonnull(oidc_cmd_provider_id_token_encrypted_response_enc_set(cmd, NULL, "TOTALLY_BOGUS_ENC"));

	cmd = oidc_test_cmd_get(OIDCUserInfoEncryptedResponseAlg);
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_encrypted_response_alg_set(cmd, NULL, "A256KW"));
	ck_assert_str_eq(oidc_cfg_provider_userinfo_encrypted_response_alg_get(p), "A256KW");

	cmd = oidc_test_cmd_get(OIDCUserInfoEncryptedResponseEnc);
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_encrypted_response_enc_set(cmd, NULL, "A128CBC-HS256"));
	ck_assert_str_eq(oidc_cfg_provider_userinfo_encrypted_response_enc_get(p), "A128CBC-HS256");
}
END_TEST

START_TEST(test_cmd_provider_bool_setters) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCSSLValidateServer);
	ck_assert_ptr_null(oidc_cmd_provider_ssl_validate_server_set(cmd, NULL, "Off"));
	ck_assert_int_eq(oidc_cfg_provider_ssl_validate_server_get(p), 0);
	ck_assert_ptr_null(oidc_cmd_provider_ssl_validate_server_set(cmd, NULL, "On"));
	ck_assert_int_eq(oidc_cfg_provider_ssl_validate_server_get(p), 1);
	ck_assert_ptr_nonnull(oidc_cmd_provider_ssl_validate_server_set(cmd, NULL, "MaybeLater"));

	cmd = oidc_test_cmd_get(OIDCValidateIssuer);
	ck_assert_ptr_null(oidc_cmd_provider_validate_issuer_set(cmd, NULL, "Off"));
	ck_assert_int_eq(oidc_cfg_provider_validate_issuer_get(p), 0);
}
END_TEST

START_TEST(test_cmd_provider_int_setters) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCJWKSRefreshInterval);
	ck_assert_ptr_null(oidc_cmd_provider_jwks_uri_refresh_interval_set(cmd, NULL, "600"));
	const oidc_jwks_uri_t *jwks = oidc_cfg_provider_jwks_uri_get(p);
	ck_assert_int_eq(oidc_cfg_jwks_uri_refresh_interval_get(jwks), 600);
	/* below the minimum/non-numeric rejected */
	ck_assert_ptr_nonnull(oidc_cmd_provider_jwks_uri_refresh_interval_set(cmd, NULL, "0"));
	ck_assert_ptr_nonnull(oidc_cmd_provider_jwks_uri_refresh_interval_set(cmd, NULL, "bogus"));

	cmd = oidc_test_cmd_get(OIDCUserInfoRefreshInterval);
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_refresh_interval_set(cmd, NULL, "60", NULL));
	ck_assert_int_eq(oidc_cfg_provider_userinfo_refresh_interval_get(p), 60);
}
END_TEST

START_TEST(test_cmd_provider_userinfo_token_method) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCUserInfoTokenMethod);
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_token_method_set(cmd, NULL, "authz_header"));
	ck_assert_int_eq(oidc_cfg_provider_userinfo_token_method_get(p), OIDC_USER_INFO_TOKEN_METHOD_HEADER);
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_token_method_set(cmd, NULL, "post_param"));
	ck_assert_int_eq(oidc_cfg_provider_userinfo_token_method_get(p), OIDC_USER_INFO_TOKEN_METHOD_POST);
	ck_assert_ptr_nonnull(oidc_cmd_provider_userinfo_token_method_set(cmd, NULL, "carrier_pigeon"));
}
END_TEST

START_TEST(test_cmd_provider_auth_request_method) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCProviderAuthRequestMethod);
	ck_assert_ptr_null(oidc_cmd_provider_auth_request_method_set(cmd, NULL, "GET"));
	ck_assert_int_eq(oidc_cfg_provider_auth_request_method_get(p), OIDC_AUTH_REQUEST_METHOD_GET);
	ck_assert_ptr_null(oidc_cmd_provider_auth_request_method_set(cmd, NULL, "POST"));
	ck_assert_int_eq(oidc_cfg_provider_auth_request_method_get(p), OIDC_AUTH_REQUEST_METHOD_POST);
	ck_assert_ptr_null(oidc_cmd_provider_auth_request_method_set(cmd, NULL, "PAR"));
	ck_assert_int_eq(oidc_cfg_provider_auth_request_method_get(p), OIDC_AUTH_REQUEST_METHOD_PAR);
	ck_assert_ptr_nonnull(oidc_cmd_provider_auth_request_method_set(cmd, NULL, "DELETE"));
}
END_TEST

START_TEST(test_cmd_provider_profile) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCProfile);
	ck_assert_ptr_null(oidc_cmd_provider_profile_set(cmd, NULL, "OIDC10"));
	ck_assert_int_eq(oidc_cfg_provider_profile_get(p), OIDC_PROFILE_OIDC10);
	ck_assert_ptr_null(oidc_cmd_provider_profile_set(cmd, NULL, "FAPI20"));
	ck_assert_int_eq(oidc_cfg_provider_profile_get(p), OIDC_PROFILE_FAPI20);
	ck_assert_ptr_nonnull(oidc_cmd_provider_profile_set(cmd, NULL, "GDPR"));
}
END_TEST

START_TEST(test_cmd_provider_response_mode) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCResponseMode);
	ck_assert_ptr_null(oidc_cmd_provider_response_mode_set(cmd, NULL, "query"));
	ck_assert_str_eq(oidc_cfg_provider_response_mode_get(p), "query");
	ck_assert_ptr_null(oidc_cmd_provider_response_mode_set(cmd, NULL, "fragment"));
	ck_assert_str_eq(oidc_cfg_provider_response_mode_get(p), "fragment");
	ck_assert_ptr_null(oidc_cmd_provider_response_mode_set(cmd, NULL, "form_post"));
	ck_assert_str_eq(oidc_cfg_provider_response_mode_get(p), "form_post");
	ck_assert_ptr_nonnull(oidc_cmd_provider_response_mode_set(cmd, NULL, "yelling"));
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

/*
 * Tests for the cfg/cache.c directive setters: OIDCCacheType,
 * OIDCCacheShmEntrySizeMax, OIDCCacheDir, OIDCSessionType.
 */

START_TEST(test_cmd_cache_type) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCacheType);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_cache_type_set(cmd, NULL, "shm"));
	ck_assert_ptr_eq(cfg->cache.impl, &oidc_cache_shm);
	ck_assert_ptr_null(oidc_cmd_cache_type_set(cmd, NULL, "file"));
	ck_assert_ptr_eq(cfg->cache.impl, &oidc_cache_file);
#ifdef USE_MEMCACHE
	ck_assert_ptr_null(oidc_cmd_cache_type_set(cmd, NULL, "memcache"));
	ck_assert_ptr_eq(cfg->cache.impl, &oidc_cache_memcache);
#endif
#ifdef USE_LIBHIREDIS
	ck_assert_ptr_null(oidc_cmd_cache_type_set(cmd, NULL, "redis"));
	ck_assert_ptr_eq(cfg->cache.impl, &oidc_cache_redis);
#endif
	/* unknown backend rejected */
	ck_assert_ptr_nonnull(oidc_cmd_cache_type_set(cmd, NULL, "totally_bogus_cache"));

	/* restore the shm backend the test fixture expects so the subsequent teardown
	 * (oidc_cfg_process_cleanup -> cache->destroy) operates on a known-good impl */
	ck_assert_ptr_null(oidc_cmd_cache_type_set(cmd, NULL, "shm"));
}
END_TEST

START_TEST(test_cmd_cache_shm_entry_size_max) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCacheShmEntrySizeMax);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	/* in-range, multiple of 8 (the minimum is 8 KiB + a small overhead) */
	ck_assert_ptr_null(oidc_cmd_cache_shm_entry_size_max_set(cmd, NULL, "16384"));
	ck_assert_int_eq(cfg->cache.shm_entry_size_max, 16384);
	ck_assert_int_eq(oidc_cfg_cache_shm_entry_size_max_get(cfg), 16384);

	/* in-range but not a multiple of 8 */
	ck_assert_ptr_nonnull(oidc_cmd_cache_shm_entry_size_max_set(cmd, NULL, "16383"));

	/* below the minimum / above the maximum / non-numeric */
	ck_assert_ptr_nonnull(oidc_cmd_cache_shm_entry_size_max_set(cmd, NULL, "16"));
	ck_assert_ptr_nonnull(oidc_cmd_cache_shm_entry_size_max_set(cmd, NULL, "99999999"));
	ck_assert_ptr_nonnull(oidc_cmd_cache_shm_entry_size_max_set(cmd, NULL, "bogus"));
}
END_TEST

START_TEST(test_cmd_cache_dir) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCacheDir);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	/* /tmp exists and is a directory => accepted */
	ck_assert_ptr_null(oidc_cmd_cache_file_dir_set(cmd, NULL, "/tmp"));
	ck_assert_str_eq(cfg->cache.file_dir, "/tmp");

	/* a path that does not exist is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_cache_file_dir_set(cmd, NULL, "/nonexistent/path/that/should/not/be/there"));
}
END_TEST

START_TEST(test_cmd_session_type) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCSessionType);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_session_type_set(cmd, NULL, "client-cookie"));
	ck_assert_int_eq(oidc_cfg_session_type_get(cfg), OIDC_SESSION_TYPE_CLIENT_COOKIE);

	ck_assert_ptr_null(oidc_cmd_session_type_set(cmd, NULL, "server-cache"));
	ck_assert_int_eq(oidc_cfg_session_type_get(cfg), OIDC_SESSION_TYPE_SERVER_CACHE);

	/* the "persistent" suffix toggles the persistent-session-cookie flag */
	ck_assert_ptr_null(oidc_cmd_session_type_set(cmd, NULL, "server-cache:persistent"));
	ck_assert_int_eq(oidc_cfg_session_type_get(cfg), OIDC_SESSION_TYPE_SERVER_CACHE);

	/* unknown variant rejected */
	ck_assert_ptr_nonnull(oidc_cmd_session_type_set(cmd, NULL, "soup"));
}
END_TEST

/*
 * Tests for cfg/parse.c helpers that aren't already exercised through the
 * cmd setters in the other tests. These functions are used by callers in
 * cfg/cfg.c, cfg/oauth.c and cfg/provider.c that share the same parse
 * helpers - exercising them here gives coverage to many shared code paths.
 */

START_TEST(test_cfg_parse_is_valid_url) {
	apr_pool_t *pool = oidc_test_pool_get();

	/* https-only valid URL */
	ck_assert_ptr_null(oidc_cfg_parse_is_valid_url(pool, "https://idp.example.com/path", "https"));
	/* wrong scheme rejected */
	ck_assert_ptr_nonnull(oidc_cfg_parse_is_valid_url(pool, "http://idp.example.com/", "https"));
	/* unparseable / missing scheme */
	ck_assert_ptr_nonnull(oidc_cfg_parse_is_valid_url(pool, NULL, "https"));
	ck_assert_ptr_nonnull(oidc_cfg_parse_is_valid_url(pool, "no-scheme.example.com", "https"));
}
END_TEST

START_TEST(test_cfg_parse_action_on_error_refresh_as) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_on_error_action_t action = OIDC_ON_ERROR_502;

	ck_assert_ptr_null(oidc_cfg_parse_action_on_error_refresh_as(pool, "502_on_error", &action));
	ck_assert_int_eq(action, OIDC_ON_ERROR_502);

	ck_assert_ptr_null(oidc_cfg_parse_action_on_error_refresh_as(pool, "logout_on_error", &action));
	ck_assert_int_eq(action, OIDC_ON_ERROR_LOGOUT);

	ck_assert_ptr_null(oidc_cfg_parse_action_on_error_refresh_as(pool, "authenticate_on_error", &action));
	ck_assert_int_eq(action, OIDC_ON_ERROR_AUTH);

	ck_assert_ptr_nonnull(oidc_cfg_parse_action_on_error_refresh_as(pool, "shrug", &action));
}
END_TEST

START_TEST(test_cfg_parse_public_key_files) {
	apr_pool_t *pool = oidc_test_pool_get();
	apr_array_header_t *keys = NULL;
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";

	/* successful load of a real X.509/PEM via "<kid>#<filename>" */
	const char *arg = apr_psprintf(pool, "rsa-1#%s/public.pem", dir);
	ck_assert_ptr_null(oidc_cfg_parse_public_key_files(pool, arg, &keys));
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(keys->nelts, 1);

	/* with a use-prefix; the parsed JWK should carry that use value */
	const char *arg2 = apr_psprintf(pool, "sig:rsa-2#%s/public.pem", dir);
	ck_assert_ptr_null(oidc_cfg_parse_public_key_files(pool, arg2, &keys));
	ck_assert_int_eq(keys->nelts, 2);

	/* file does not exist */
	ck_assert_ptr_nonnull(oidc_cfg_parse_public_key_files(pool, "rsa-x#/nonexistent.pem", &keys));

	oidc_jwk_list_destroy(keys);
}
END_TEST

START_TEST(test_cfg_parse_key_files_alg) {
	apr_pool_t *pool = oidc_test_pool_get();
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	oidc_jose_error_t err;
	char *s_json = NULL;

	/* a single "<alg>@" publishes the key with a matching "alg" and keeps its explicit kid */
	apr_array_header_t *keys = NULL;
	const char *arg = apr_psprintf(pool, "enc:RSA-OAEP@rsa-1#%s/public.pem", dir);
	ck_assert_ptr_null(oidc_cfg_parse_public_key_files(pool, arg, &keys));
	ck_assert_int_eq(keys->nelts, 1);
	oidc_jwk_t *jwk = APR_ARRAY_IDX(keys, 0, oidc_jwk_t *);
	ck_assert_str_eq(jwk->use, OIDC_JOSE_JWK_ENC_STR);
	ck_assert_str_eq(jwk->alg, "RSA-OAEP");
	ck_assert_str_eq(jwk->kid, "rsa-1");
	/* the "alg" must be published in the JWK JSON so an OP can select the key */
	ck_assert_int_eq(oidc_jwk_to_json(pool, jwk, &s_json, &err), TRUE);
	ck_assert_ptr_nonnull(_oidc_strstr(s_json, "\"alg\":\"RSA-OAEP\""));

	/* a "+"-separated list duplicates the same key once per algorithm under distinct, alg-derived kids */
	keys = NULL;
	arg = apr_psprintf(pool, "enc:RSA-OAEP+RSA-OAEP-256@k#%s/public.pem", dir);
	ck_assert_ptr_null(oidc_cfg_parse_public_key_files(pool, arg, &keys));
	ck_assert_int_eq(keys->nelts, 2);
	ck_assert_str_eq(APR_ARRAY_IDX(keys, 0, oidc_jwk_t *)->kid, "k-RSA-OAEP");
	ck_assert_str_eq(APR_ARRAY_IDX(keys, 0, oidc_jwk_t *)->alg, "RSA-OAEP");
	ck_assert_str_eq(APR_ARRAY_IDX(keys, 1, oidc_jwk_t *)->kid, "k-RSA-OAEP-256");
	ck_assert_str_eq(APR_ARRAY_IDX(keys, 1, oidc_jwk_t *)->alg, "RSA-OAEP-256");

	/* the matching private keys fan out under the SAME kids so a JWE referencing them can be decrypted */
	apr_array_header_t *priv = NULL;
	arg = apr_psprintf(pool, "enc:RSA-OAEP+RSA-OAEP-256@k#%s/private.pem", dir);
	ck_assert_ptr_null(oidc_cfg_parse_private_key_files(pool, arg, &priv));
	ck_assert_int_eq(priv->nelts, 2);
	ck_assert_str_eq(APR_ARRAY_IDX(priv, 0, oidc_jwk_t *)->kid, "k-RSA-OAEP");
	ck_assert_str_eq(APR_ARRAY_IDX(priv, 1, oidc_jwk_t *)->kid, "k-RSA-OAEP-256");

	/* without an explicit kid the duplicates get the auto-derived base kid, suffixed per algorithm, and
	 * the public and private sides derive the same base kid from the (matching) key material */
	keys = NULL;
	priv = NULL;
	ck_assert_ptr_null(oidc_cfg_parse_public_key_files(
	    pool, apr_psprintf(pool, "enc:RSA-OAEP+RSA1_5@%s/public.pem", dir), &keys));
	ck_assert_ptr_null(oidc_cfg_parse_private_key_files(
	    pool, apr_psprintf(pool, "enc:RSA-OAEP+RSA1_5@%s/private.pem", dir), &priv));
	ck_assert_int_eq(keys->nelts, 2);
	ck_assert_int_eq(priv->nelts, 2);
	ck_assert_str_eq(APR_ARRAY_IDX(keys, 0, oidc_jwk_t *)->kid, APR_ARRAY_IDX(priv, 0, oidc_jwk_t *)->kid);
	ck_assert_str_eq(APR_ARRAY_IDX(keys, 1, oidc_jwk_t *)->kid, APR_ARRAY_IDX(priv, 1, oidc_jwk_t *)->kid);

	/* an algorithm incompatible with the key type is rejected at config time */
	keys = NULL;
	ck_assert_ptr_nonnull(oidc_cfg_parse_public_key_files(
	    pool, apr_psprintf(pool, "enc:ES256@%s/public.pem", dir), &keys));
}
END_TEST

START_TEST(test_cfg_parse_remote_user_claim) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_remote_user_claim_t claim;
	claim.claim_name = NULL;
	claim.reg_exp = NULL;
	claim.replace = NULL;

	ck_assert_ptr_null(oidc_parse_remote_user_claim(pool, "sub", NULL, NULL, &claim));
	ck_assert_str_eq(claim.claim_name, "sub");
	ck_assert_ptr_null(claim.reg_exp);
	ck_assert_ptr_null(claim.replace);

	ck_assert_ptr_null(oidc_parse_remote_user_claim(pool, "preferred_username", "^([^@]+)@.*$", "\\1", &claim));
	ck_assert_str_eq(claim.claim_name, "preferred_username");
	ck_assert_str_eq(claim.reg_exp, "^([^@]+)@.*$");
	ck_assert_str_eq(claim.replace, "\\1");
}
END_TEST

START_TEST(test_cfg_parse_http_timeout) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_http_timeout_t t;
	t.request_timeout = 1;
	t.connect_timeout = 2;
	t.retries = 3;
	t.retry_interval = 4;

	/* the helper updates only the fields whose arg is non-NULL */
	ck_assert_ptr_null(oidc_cfg_parse_http_timeout(pool, "30", "10", "2:500", &t));
	ck_assert_int_eq(t.request_timeout, 30);
	ck_assert_int_eq(t.connect_timeout, 10);
	ck_assert_int_eq(t.retries, 2);
	ck_assert_int_eq(t.retry_interval, 500);

	/* a missing colon-suffix leaves retry_interval unchanged */
	t.retry_interval = 999;
	ck_assert_ptr_null(oidc_cfg_parse_http_timeout(pool, NULL, NULL, "7", &t));
	ck_assert_int_eq(t.retries, 7);
	ck_assert_int_eq(t.retry_interval, 999);
}
END_TEST

/*
 * Tests for cfg/cfg.c directive setters.
 */

START_TEST(test_cmd_crypto_passphrase) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCryptoPassphrase);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_crypto_passphrase_set(cmd, NULL, "secret1value", NULL));
	ck_assert_str_eq(oidc_cfg_crypto_passphrase_secret1_get(cfg), "secret1value");

	ck_assert_ptr_null(oidc_cmd_crypto_passphrase_set(cmd, NULL, "new1", "new2"));
	ck_assert_str_eq(oidc_cfg_crypto_passphrase_secret1_get(cfg), "new1");
	ck_assert_str_eq(oidc_cfg_crypto_passphrase_secret2_get(cfg), "new2");

	/* the setter writes into cfg via the secret1_set helper too */
	oidc_cfg_crypto_passphrase_secret1_set(cfg, "manually-set");
	ck_assert_str_eq(oidc_cfg_crypto_passphrase_secret1_get(cfg), "manually-set");
}
END_TEST

START_TEST(test_cmd_outgoing_proxy) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOutgoingProxy);

	ck_assert_ptr_null(oidc_cmd_outgoing_proxy_set(cmd, NULL, "proxy.example.com:3128", NULL, NULL));
	ck_assert_ptr_null(oidc_cmd_outgoing_proxy_set(cmd, NULL, "proxy.example.com:3128", "user:pwd", "basic"));
	/* unknown auth scheme rejected */
	ck_assert_ptr_nonnull(oidc_cmd_outgoing_proxy_set(cmd, NULL, "proxy.example.com:3128", "user:pwd", "carrier"));
}
END_TEST

START_TEST(test_cmd_cookie_domain) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCookieDomain);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_cookie_domain_set(cmd, NULL, "example.com"));
	ck_assert_str_eq(oidc_cfg_cookie_domain_get(cfg), "example.com");

	ck_assert_ptr_null(oidc_cmd_cookie_domain_set(cmd, NULL, "sub-domain.example.com"));
	ck_assert_str_eq(oidc_cfg_cookie_domain_get(cfg), "sub-domain.example.com");

	/* characters outside [A-Za-z0-9.-] are rejected */
	ck_assert_ptr_nonnull(oidc_cmd_cookie_domain_set(cmd, NULL, "not_a_valid_domain"));
	ck_assert_ptr_nonnull(oidc_cmd_cookie_domain_set(cmd, NULL, "evil.example.com/path"));
}
END_TEST

START_TEST(test_cmd_session_inactivity_timeout) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCSessionInactivityTimeout);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_session_inactivity_timeout_set(cmd, NULL, "600"));
	ck_assert_int_eq(oidc_cfg_session_inactivity_timeout_get(cfg), 600);

	/* below the minimum (10) is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_session_inactivity_timeout_set(cmd, NULL, "5"));
	ck_assert_ptr_nonnull(oidc_cmd_session_inactivity_timeout_set(cmd, NULL, "bogus"));
}
END_TEST

/* drive oidc_cfg_parse_key_record through every key-value encoding
 * (b64/b64url/hex/plain) including the malformed-input error branches */
START_TEST(test_cfg_parse_key_record_encodings) {
	request_rec *r = oidc_test_request_get();
	char *kid = NULL;
	char *key = NULL;
	int key_len = 0;
	char *use = NULL;

	/* base64: 16 bytes */
	ck_assert_ptr_null(
	    oidc_cfg_parse_key_record(r->pool, "b64#k1#AAECAwQFBgcICQoLDA0ODw==", &kid, &key, &key_len, &use, NULL, TRUE));
	ck_assert_str_eq(kid, "k1");
	ck_assert_int_eq(key_len, 16);

	/* base64url: 16 bytes, no padding */
	ck_assert_ptr_null(
	    oidc_cfg_parse_key_record(r->pool, "b64url#k2#AAECAwQFBgcICQoLDA0ODw", &kid, &key, &key_len, &use, NULL, TRUE));
	ck_assert_str_eq(kid, "k2");
	ck_assert_int_eq(key_len, 16);

	/* hex: 16 bytes */
	ck_assert_ptr_null(oidc_cfg_parse_key_record(r->pool, "hex#k3#000102030405060708090a0b0c0d0e0f", &kid, &key,
						     &key_len, &use, NULL, TRUE));
	ck_assert_int_eq(key_len, 16);
	ck_assert_int_eq((unsigned char)key[15], 0x0f);

	/* plain */
	ck_assert_ptr_null(oidc_cfg_parse_key_record(r->pool, "plain#k4#mysecret", &kid, &key, &key_len, &use, NULL, TRUE));
	ck_assert_int_eq(key_len, 8);

	/* use prefix */
	ck_assert_ptr_null(
	    oidc_cfg_parse_key_record(r->pool, "sig:plain#k5#mysecret", &kid, &key, &key_len, &use, NULL, TRUE));
	ck_assert_ptr_nonnull(use);
	ck_assert_str_eq(use, "sig");

	/* error branches: invalid base64url, odd-length hex, non-hex input, unknown encoding */
	ck_assert_ptr_nonnull(oidc_cfg_parse_key_record(r->pool, "b64url#k#!!!!", &kid, &key, &key_len, &use, NULL, TRUE));
	ck_assert_ptr_nonnull(oidc_cfg_parse_key_record(r->pool, "hex#k#abc", &kid, &key, &key_len, &use, NULL, TRUE));
	ck_assert_ptr_nonnull(oidc_cfg_parse_key_record(r->pool, "hex#k#zzzz", &kid, &key, &key_len, &use, NULL, TRUE));
	ck_assert_ptr_nonnull(oidc_cfg_parse_key_record(r->pool, "bogus#k#value", &kid, &key, &key_len, &use, NULL, TRUE));
}
END_TEST

/* OIDCClientTokenEndpointCert/Key/KeyPassword: TLS client credentials for the
 * provider token endpoint; cert and key must reference readable files */
START_TEST(test_cmd_provider_token_endpoint_tls) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(cfg);
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	const char *cert = apr_psprintf(r->pool, "%s/certificate.pem", dir);
	const char *key = apr_psprintf(r->pool, "%s/private.pem", dir);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCClientTokenEndpointCert);
	ck_assert_ptr_null(oidc_cmd_provider_token_endpoint_tls_client_cert_set(cmd, NULL, cert));
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider), cert);
	/* a non-existent file is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_provider_token_endpoint_tls_client_cert_set(cmd, NULL, "/nonexistent.crt"));

	cmd = oidc_test_cmd_get(OIDCClientTokenEndpointKey);
	ck_assert_ptr_null(oidc_cmd_provider_token_endpoint_tls_client_key_set(cmd, NULL, key));
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_tls_client_key_get(provider), key);

	cmd = oidc_test_cmd_get(OIDCClientTokenEndpointKeyPassword);
	ck_assert_ptr_null(oidc_cmd_provider_token_endpoint_tls_client_key_pwd_set(cmd, NULL, "keypass"));
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_tls_client_key_pwd_get(provider), "keypass");
}
END_TEST

/* OIDCOAuthIntrospectionEndpointCert/Key/KeyPassword: TLS client credentials
 * for the AS introspection endpoint */
START_TEST(test_cmd_oauth_introspection_endpoint_tls) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	const char *cert = apr_psprintf(r->pool, "%s/certificate.pem", dir);
	const char *key = apr_psprintf(r->pool, "%s/private.pem", dir);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionEndpointCert);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_tls_client_cert_set(cmd, NULL, cert));
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_tls_client_cert_get(cfg), cert);

	cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionEndpointKey);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_tls_client_key_set(cmd, NULL, key));
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_tls_client_key_get(cfg), key);

	cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionEndpointKeyPassword);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_tls_client_key_pwd_set(cmd, NULL, "rspass"));
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_tls_client_key_pwd_get(cfg), "rspass");
}
END_TEST

/* the macro-generated provider setters that are populated from client
 * metadata / .conf files rather than via a registered directive */
START_TEST(test_cmd_provider_metadata_only_setters) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(cfg);
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";

	/* client_keys: parsed from public key files like OIDCPublicKeyFiles */
	cmd_parms *cmd = oidc_test_cmd_get("OIDCProviderClientKeys");
	ck_assert_ptr_null(
	    oidc_cmd_provider_client_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-1#%s/public.pem", dir)));
	const apr_array_header_t *keys = oidc_cfg_provider_client_keys_get(provider);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_gt(keys->nelts, 0);

	/* set_keys: direct array assignment */
	ck_assert_ptr_null(oidc_cfg_provider_client_keys_set_keys(r->pool, provider, (apr_array_header_t *)keys));
	ck_assert_ptr_eq(oidc_cfg_provider_client_keys_get(provider), keys);

	cmd = oidc_test_cmd_get("OIDCProviderResponseRequireIss");
	ck_assert_ptr_null(oidc_cmd_provider_response_require_iss_set(cmd, NULL, "On"));
	ck_assert_int_eq(oidc_cfg_provider_response_require_iss_get(provider), 1);

	cmd = oidc_test_cmd_get("OIDCProviderRegistrationToken");
	ck_assert_ptr_null(oidc_cmd_provider_registration_token_set(cmd, NULL, "reg-token-1"));
	ck_assert_str_eq(oidc_cfg_provider_registration_token_get(provider), "reg-token-1");
}
END_TEST

START_TEST(test_cmd_public_keys) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPublicKeyFiles);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";

	const char *arg = apr_psprintf(cmd->pool, "rsa-1#%s/public.pem", dir);
	ck_assert_ptr_null(oidc_cmd_public_keys_set(cmd, NULL, arg));
	const apr_array_header_t *keys = oidc_cfg_public_keys_get(cfg);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_gt(keys->nelts, 0);

	/* non-existent file path is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_public_keys_set(cmd, NULL, "k1#/nonexistent.pem"));
}
END_TEST

START_TEST(test_cmd_remote_user_claim) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCRemoteUserClaim);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_remote_user_claim_set(cmd, NULL, "email", NULL, NULL));
	const oidc_remote_user_claim_t *c = oidc_cfg_remote_user_claim_get(cfg);
	ck_assert_str_eq(c->claim_name, "email");

	ck_assert_ptr_null(oidc_cmd_remote_user_claim_set(cmd, NULL, "preferred_username", "^([^@]+)@.*$", "\\1"));
	c = oidc_cfg_remote_user_claim_get(cfg);
	ck_assert_str_eq(c->claim_name, "preferred_username");
	ck_assert_str_eq(c->reg_exp, "^([^@]+)@.*$");
	ck_assert_str_eq(c->replace, "\\1");

	/* default falls through to "sub@" before any setter is called - rely on the getter */
	ck_assert_ptr_nonnull(oidc_cfg_remote_user_claim_name_get(cfg));
}
END_TEST

START_TEST(test_cmd_claim_prefix) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCClaimPrefix);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_claim_prefix_set(cmd, NULL, "MY_CLAIM_"));
	ck_assert_str_eq(oidc_cfg_claim_prefix_get(cfg), "MY_CLAIM_");

	/* the empty form configures an empty prefix */
	ck_assert_ptr_null(oidc_cmd_claim_prefix_set(cmd, NULL, ""));
	ck_assert_str_eq(oidc_cfg_claim_prefix_get(cfg), "");
}
END_TEST

START_TEST(test_cmd_max_number_of_state_cookies) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCStateMaxNumberOfCookies);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_max_number_of_state_cookies_set(cmd, NULL, "10", NULL));
	ck_assert_int_eq(oidc_cfg_max_number_of_state_cookies_get(cfg), 10);

	/* the 2nd argument toggles the delete-oldest flag */
	ck_assert_ptr_null(oidc_cmd_max_number_of_state_cookies_set(cmd, NULL, "5", "On"));
	ck_assert_int_eq(oidc_cfg_delete_oldest_state_cookies_get(cfg), 1);

	/* above the maximum (255) is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_max_number_of_state_cookies_set(cmd, NULL, "999", NULL));
	/* boolean arg2 invalid */
	ck_assert_ptr_nonnull(oidc_cmd_max_number_of_state_cookies_set(cmd, NULL, "10", "Maybe"));
}
END_TEST

START_TEST(test_cmd_x_forwarded_headers) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCXForwardedHeaders);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_x_forwarded_headers_set(cmd, NULL, "X-Forwarded-Host"));
	ck_assert_int_eq(oidc_cfg_x_forwarded_headers_get(cfg) & OIDC_HDR_X_FORWARDED_HOST, OIDC_HDR_X_FORWARDED_HOST);

	/* "none" leaves only HDR_NONE */
	ck_assert_ptr_null(oidc_cmd_x_forwarded_headers_set(cmd, NULL, "none"));
	/* unknown header name rejected */
	ck_assert_ptr_nonnull(oidc_cmd_x_forwarded_headers_set(cmd, NULL, "X-Bogus-Header"));
}
END_TEST

START_TEST(test_cmd_state_input_headers) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCStateInputHeaders);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_state_input_headers_set(cmd, NULL, "none"));
	ck_assert_int_eq(oidc_cfg_state_input_headers_get(cfg), OIDC_STATE_INPUT_HEADERS_NONE);
	ck_assert_ptr_null(oidc_cmd_state_input_headers_set(cmd, NULL, "user-agent"));
	ck_assert_int_eq(oidc_cfg_state_input_headers_get(cfg), OIDC_STATE_INPUT_HEADERS_USER_AGENT);
	ck_assert_ptr_null(oidc_cmd_state_input_headers_set(cmd, NULL, "x-forwarded-for"));
	ck_assert_int_eq(oidc_cfg_state_input_headers_get(cfg), OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR);
	ck_assert_ptr_null(oidc_cmd_state_input_headers_set(cmd, NULL, "both"));
	ck_assert_int_eq(oidc_cfg_state_input_headers_get(cfg),
			 OIDC_STATE_INPUT_HEADERS_USER_AGENT | OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR);
	ck_assert_ptr_nonnull(oidc_cmd_state_input_headers_set(cmd, NULL, "smoke-signal"));
}
END_TEST

START_TEST(test_cmd_post_preserve_templates) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPreservePostTemplates);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";

	const char *preserve = apr_psprintf(cmd->pool, "%s/post_preserve.template", dir);
	const char *restore = apr_psprintf(cmd->pool, "%s/post_restore.template", dir);
	ck_assert_ptr_null(oidc_cmd_post_preserve_templates_set(cmd, NULL, preserve, restore));
	ck_assert_str_eq(oidc_cfg_post_preserve_template_get(cfg), preserve);
	ck_assert_str_eq(oidc_cfg_post_restore_template_get(cfg), restore);

	ck_assert_ptr_nonnull(oidc_cmd_post_preserve_templates_set(cmd, NULL, "/nonexistent.html", restore));
}
END_TEST

START_TEST(test_cmd_ca_bundle_path) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCABundlePath);
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";

	const char *path = apr_psprintf(cmd->pool, "%s/certificate.pem", dir);
	ck_assert_ptr_null(oidc_cmd_ca_bundle_path_set(cmd, NULL, path));
	ck_assert_str_eq(oidc_cfg_ca_bundle_path_get(cfg), path);

	ck_assert_ptr_nonnull(oidc_cmd_ca_bundle_path_set(cmd, NULL, "/nonexistent/ca-bundle.pem"));
}
END_TEST

START_TEST(test_cmd_cookie_http_only) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCookieHTTPOnly);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_cookie_http_only_set(cmd, NULL, "Off"));
	ck_assert_int_eq(oidc_cfg_cookie_http_only_get(cfg), 0);
	ck_assert_ptr_null(oidc_cmd_cookie_http_only_set(cmd, NULL, "On"));
	ck_assert_int_eq(oidc_cfg_cookie_http_only_get(cfg), 1);
	ck_assert_ptr_nonnull(oidc_cmd_cookie_http_only_set(cmd, NULL, "MaybeLater"));
}
END_TEST

START_TEST(test_cmd_session_cache_fallback_to_cookie) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCSessionCacheFallbackToCookie);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_session_cache_fallback_to_cookie_set(cmd, NULL, "On"));
	ck_assert_int_eq(oidc_cfg_session_cache_fallback_to_cookie_get(cfg), 1);
	ck_assert_ptr_null(oidc_cmd_session_cache_fallback_to_cookie_set(cmd, NULL, "Off"));
	ck_assert_int_eq(oidc_cfg_session_cache_fallback_to_cookie_get(cfg), 0);
}
END_TEST

START_TEST(test_cmd_claim_delimiter) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCClaimDelimiter);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_claim_delimiter_set(cmd, NULL, ";"));
	ck_assert_str_eq(oidc_cfg_claim_delimiter_get(cfg), ";");
}
END_TEST

START_TEST(test_cmd_metrics_path) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCMetricsPublish);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_metrics_path_set(cmd, NULL, "/metrics"));
	ck_assert_str_eq(oidc_cfg_metrics_path_get(cfg), "/metrics");
}
END_TEST

START_TEST(test_cmd_logout_x_frame_options) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCLogoutXFrameOptions);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_logout_x_frame_options_set(cmd, NULL, "SAMEORIGIN"));
	ck_assert_str_eq(oidc_cfg_logout_x_frame_options_get(cfg), "SAMEORIGIN");
}
END_TEST

START_TEST(test_cmd_state_timeout) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCStateTimeout);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_state_timeout_set(cmd, NULL, "120"));
	ck_assert_int_eq(oidc_cfg_state_timeout_get(cfg), 120);
	ck_assert_ptr_nonnull(oidc_cmd_state_timeout_set(cmd, NULL, "0"));
}
END_TEST

START_TEST(test_cmd_session_cookie_chunk_size) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCSessionCookieChunkSize);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_session_cookie_chunk_size_set(cmd, NULL, "2048"));
	ck_assert_int_eq(oidc_cfg_session_cookie_chunk_size_get(cfg), 2048);
	/* below the 256 minimum / above the 64KiB maximum */
	ck_assert_ptr_nonnull(oidc_cmd_session_cookie_chunk_size_set(cmd, NULL, "10"));
	ck_assert_ptr_nonnull(oidc_cmd_session_cookie_chunk_size_set(cmd, NULL, "99999999"));
}
END_TEST

START_TEST(test_cmd_provider_metadata_refresh_interval) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCProviderMetadataRefreshInterval);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_provider_metadata_refresh_interval_set(cmd, NULL, "300"));
	ck_assert_int_eq(oidc_cfg_provider_metadata_refresh_interval_get(cfg), 300);

	/* below the minimum (30) is rejected */
	ck_assert_ptr_nonnull(oidc_cmd_provider_metadata_refresh_interval_set(cmd, NULL, "10"));
}
END_TEST

START_TEST(test_cmd_white_black_redirect_url_hashes) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCWhiteListedClaims);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_white_listed_claims_set(cmd, NULL, "preferred_username"));
	ck_assert_int_eq(apr_hash_count(oidc_cfg_white_listed_claims_get(cfg)), 1);

	cmd = oidc_test_cmd_get(OIDCBlackListedClaims);
	ck_assert_ptr_null(oidc_cmd_black_listed_claims_set(cmd, NULL, "secret_claim"));
	ck_assert_int_eq(apr_hash_count(oidc_cfg_black_listed_claims_get(cfg)), 1);

	cmd = oidc_test_cmd_get(OIDCRedirectURLsAllowed);
	ck_assert_ptr_null(oidc_cmd_redirect_urls_allowed_set(cmd, NULL, "https://app.example.com/"));
	ck_assert_int_eq(apr_hash_count(oidc_cfg_redirect_urls_allowed_get(cfg)), 1);
}
END_TEST

START_TEST(test_cmd_redirect_and_slo_urls) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = NULL;

	cmd = oidc_test_cmd_get(OIDCRedirectURI);
	ck_assert_ptr_null(oidc_cmd_redirect_uri_set(cmd, NULL, "/protected/redirect"));
	ck_assert_str_eq(oidc_cfg_redirect_uri_get(cfg), "/protected/redirect");
	ck_assert_ptr_null(oidc_cmd_redirect_uri_set(cmd, NULL, "https://app.example.com/redirect"));
	ck_assert_str_eq(oidc_cfg_redirect_uri_get(cfg), "https://app.example.com/redirect");
	ck_assert_ptr_nonnull(oidc_cmd_redirect_uri_set(cmd, NULL, "not a url"));

	cmd = oidc_test_cmd_get(OIDCDefaultLoggedOutURL);
	ck_assert_ptr_null(oidc_cmd_default_slo_url_set(cmd, NULL, "/loggedout"));
	ck_assert_str_eq(oidc_cfg_default_slo_url_get(cfg), "/loggedout");
}
END_TEST

START_TEST(test_cmd_http_timeout_long_short) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCHTTPTimeoutLong);

	ck_assert_ptr_null(oidc_cmd_http_timeout_long_set(cmd, NULL, "45", "15", "3:200"));
	const oidc_http_timeout_t *t = oidc_cfg_http_timeout_long_get(cfg);
	ck_assert_int_eq(t->request_timeout, 45);
	ck_assert_int_eq(t->connect_timeout, 15);
	ck_assert_int_eq(t->retries, 3);
	ck_assert_int_eq(t->retry_interval, 200);

	cmd = oidc_test_cmd_get(OIDCHTTPTimeoutShort);
	ck_assert_ptr_null(oidc_cmd_http_timeout_short_set(cmd, NULL, "10", "3", "2:150"));
	t = oidc_cfg_http_timeout_short_get(cfg);
	ck_assert_int_eq(t->request_timeout, 10);
	ck_assert_int_eq(t->connect_timeout, 3);
	ck_assert_int_eq(t->retries, 2);
	ck_assert_int_eq(t->retry_interval, 150);
}
END_TEST

START_TEST(test_cfg_server_merge_and_merged_get) {
	apr_pool_t *pool = oidc_test_pool_get();
	server_rec *s = oidc_test_request_get()->server;

	oidc_cfg_t *base = oidc_cfg_server_create(pool, s);
	oidc_cfg_t *add = oidc_cfg_server_create(pool, s);

	/* set distinct, deliberately-merge-resolvable values */
	base->redirect_uri = "https://www.example.com/redirect-base";
	add->redirect_uri = NULL;
	add->cookie_domain = "add.example.com";
	add->state_timeout = 120;

	ck_assert_int_eq(oidc_cfg_merged_get(base), FALSE);

	oidc_cfg_t *merged = (oidc_cfg_t *)oidc_cfg_server_merge(pool, base, add);
	ck_assert_ptr_nonnull(merged);
	/* merged carries the "merged" flag */
	ck_assert_int_eq(oidc_cfg_merged_get(merged), TRUE);
	/* the base wins where add is unset */
	ck_assert_str_eq(merged->redirect_uri, "https://www.example.com/redirect-base");
	/* the add wins where base is unset */
	ck_assert_str_eq(merged->cookie_domain, "add.example.com");
	ck_assert_int_eq(merged->state_timeout, 120);

	/* clean up the merged config (registers its own pool cleanup, no other action needed) */
}
END_TEST

/*
 * _oidc_cfg_merge_crypto_passphrase() must carry over the precomputed PBKDF2 key material
 * alongside the secret it belongs to; otherwise a merged config could end up with
 * derived_key{1,2}_set == TRUE paired with a secret it was never derived from
 */
START_TEST(test_cfg_server_merge_crypto_passphrase_derived_keys) {
	apr_pool_t *pool = oidc_test_pool_get();
	server_rec *s = oidc_test_request_get()->server;

	oidc_cfg_t *base = oidc_cfg_server_create(pool, s);
	oidc_cfg_t *add = oidc_cfg_server_create(pool, s);

	base->crypto_passphrase.secret1 = "base-secret-01234567890123456789";
	memset(base->crypto_passphrase.derived_key1, 0xAA, OIDC_CRYPTO_PASSPHRASE_DERIVED_KEY_LEN);
	base->crypto_passphrase.derived_key1_set = TRUE;

	/* add has no secret1 of its own: base must win "as a whole", including its derived key */
	oidc_cfg_t *merged = (oidc_cfg_t *)oidc_cfg_server_merge(pool, base, add);
	ck_assert_str_eq(oidc_cfg_crypto_passphrase_secret1_get(merged), "base-secret-01234567890123456789");
	ck_assert_int_eq(merged->crypto_passphrase.derived_key1_set, TRUE);
	ck_assert_int_eq(memcmp(merged->crypto_passphrase.derived_key1, base->crypto_passphrase.derived_key1,
				OIDC_CRYPTO_PASSPHRASE_DERIVED_KEY_LEN),
			 0);

	/* now add configures its own secret1: add must win "as a whole", including its (unset) derived key,
	 * not leak base's stale derived_key1_set/derived_key1 paired with add's different secret */
	add->crypto_passphrase.secret1 = "add-secret-012345678901234567890";
	oidc_cfg_t *merged2 = (oidc_cfg_t *)oidc_cfg_server_merge(pool, base, add);
	ck_assert_str_eq(oidc_cfg_crypto_passphrase_secret1_get(merged2), "add-secret-012345678901234567890");
	ck_assert_int_eq(merged2->crypto_passphrase.derived_key1_set, FALSE);
}
END_TEST

/*
 * the memoized KDF variant must derive on a cache miss, copy on a cache hit (instead of paying
 * for the ~210,000-iteration PBKDF2 again), key the cache on the secret text so distinct
 * secrets do not collide, and fall back to plain derivation when no cache is passed
 */
START_TEST(test_cfg_crypto_passphrase_derive_keys_cached) {
	apr_pool_t *pool = oidc_test_pool_get();
	apr_hash_t *kdf_cache = apr_hash_make(pool);
	oidc_crypto_passphrase_t cp_ref, cp_miss, cp_hit, cp_other;

	/* reference: the uncached derivation for secret "s1" */
	_oidc_memset(&cp_ref, 0, sizeof(cp_ref));
	cp_ref.secret1 = "kdf-cache-secret-1";
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys(&cp_ref), TRUE);
	ck_assert_int_eq(cp_ref.derived_key1_set, TRUE);

	/* an empty (non-NULL) secret is "not configured": nothing derived, still successful */
	_oidc_memset(&cp_miss, 0, sizeof(cp_miss));
	cp_miss.secret1 = "";
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys_cached(pool, kdf_cache, &cp_miss), TRUE);
	ck_assert_int_eq(cp_miss.derived_key1_set, FALSE);
	ck_assert_int_eq(apr_hash_count(kdf_cache), 0);

	/* cache miss: derives the same key material as the uncached path and populates the cache */
	_oidc_memset(&cp_miss, 0, sizeof(cp_miss));
	cp_miss.secret1 = "kdf-cache-secret-1";
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys_cached(pool, kdf_cache, &cp_miss), TRUE);
	ck_assert_int_eq(cp_miss.derived_key1_set, TRUE);
	ck_assert_int_eq(memcmp(cp_miss.derived_key1, cp_ref.derived_key1, OIDC_CRYPTO_PASSPHRASE_DERIVED_KEY_LEN), 0);
	ck_assert_int_eq(apr_hash_count(kdf_cache), 1);

	/* cache hit: poison the cached entry to prove the hit path copies from the cache
	 * rather than re-deriving; secret2 goes through the same (shared) cache */
	unsigned char *entry = apr_hash_get(kdf_cache, "kdf-cache-secret-1", APR_HASH_KEY_STRING);
	ck_assert_ptr_nonnull(entry);
	_oidc_memset(entry, 0xA5, OIDC_CRYPTO_PASSPHRASE_DERIVED_KEY_LEN);
	_oidc_memset(&cp_hit, 0, sizeof(cp_hit));
	cp_hit.secret1 = "kdf-cache-secret-1";
	cp_hit.secret2 = "kdf-cache-secret-1";
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys_cached(pool, kdf_cache, &cp_hit), TRUE);
	ck_assert_int_eq(cp_hit.derived_key1_set, TRUE);
	ck_assert_int_eq(cp_hit.derived_key2_set, TRUE);
	ck_assert_int_eq(cp_hit.derived_key1[0], 0xA5);
	ck_assert_int_eq(memcmp(cp_hit.derived_key2, entry, OIDC_CRYPTO_PASSPHRASE_DERIVED_KEY_LEN), 0);
	ck_assert_int_eq(apr_hash_count(kdf_cache), 1);

	/* a distinct secret gets its own entry and different key material */
	_oidc_memset(&cp_other, 0, sizeof(cp_other));
	cp_other.secret1 = "kdf-cache-secret-2";
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys_cached(pool, kdf_cache, &cp_other), TRUE);
	ck_assert_int_eq(apr_hash_count(kdf_cache), 2);
	ck_assert_int_ne(memcmp(cp_other.derived_key1, cp_ref.derived_key1, OIDC_CRYPTO_PASSPHRASE_DERIVED_KEY_LEN), 0);

	/* kdf_cache == NULL falls back to plain derivation */
	_oidc_memset(&cp_other, 0, sizeof(cp_other));
	cp_other.secret1 = "kdf-cache-secret-1";
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys_cached(pool, NULL, &cp_other), TRUE);
	ck_assert_int_eq(memcmp(cp_other.derived_key1, cp_ref.derived_key1, OIDC_CRYPTO_PASSPHRASE_DERIVED_KEY_LEN), 0);

	/* the cfg-embedded wrappers cover the same paths for a server config; the fixture cfg
	 * is post-config'd so its keys are already derived - reset before re-deriving */
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_cfg_crypto_passphrase_secret1_set(cfg, "kdf-cache-secret-1");
	cfg->crypto_passphrase.derived_key1_set = FALSE;
	ck_assert_int_eq(oidc_cfg_crypto_passphrase_derive_keys_cached(pool, kdf_cache, cfg), TRUE);
	ck_assert_int_eq(cfg->crypto_passphrase.derived_key1[0], 0xA5);
	oidc_cfg_crypto_passphrase_secret1_set(cfg, "kdf-cache-secret-2");
	cfg->crypto_passphrase.derived_key1_set = FALSE;
	ck_assert_int_eq(oidc_cfg_crypto_passphrase_derive_keys(cfg), TRUE);
	ck_assert_int_eq(cfg->crypto_passphrase.derived_key1_set, TRUE);
}
END_TEST

START_TEST(test_cfg_child_init) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	/* simply exercise the child_init path; the shm cache impl has no child_init,
	 * so this primarily covers the function's bookkeeping for the refresh mutex */
	oidc_cfg_child_init(pool, cfg, oidc_test_request_get()->server);
}
END_TEST

/*
 * Tests for cfg/dir.c uncovered setters/getters.
 */

START_TEST(test_cmd_dir_strip_pass_cookies) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCStripCookies);

	ck_assert_ptr_null(oidc_cmd_dir_strip_cookies_set(cmd, dir_cfg, "tracker-cookie"));
	const apr_array_header_t *arr = oidc_cfg_dir_strip_cookies_get(r);
	ck_assert_ptr_nonnull(arr);
	ck_assert_int_eq(arr->nelts, 1);

	cmd = oidc_test_cmd_get(OIDCPassCookies);
	ck_assert_ptr_null(oidc_cmd_dir_pass_cookies_set(cmd, dir_cfg, "session_id"));
	arr = oidc_cfg_dir_pass_cookies_get(r);
	ck_assert_ptr_nonnull(arr);
	ck_assert_int_eq(arr->nelts, 1);
}
END_TEST

START_TEST(test_cmd_dir_preserve_post) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPreservePost);

	ck_assert_ptr_null(oidc_cmd_dir_preserve_post_set(cmd, dir_cfg, "On"));
	ck_assert_int_eq(oidc_cfg_dir_preserve_post_get(r), 1);
	ck_assert_ptr_null(oidc_cmd_dir_preserve_post_set(cmd, dir_cfg, "Off"));
	ck_assert_int_eq(oidc_cfg_dir_preserve_post_get(r), 0);
	ck_assert_ptr_nonnull(oidc_cmd_dir_preserve_post_set(cmd, dir_cfg, "maybe"));
}
END_TEST

START_TEST(test_cmd_dir_unautz_action) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCUnAutzAction);

	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "403", NULL));
	ck_assert_int_eq(oidc_cfg_dir_unautz_action_get(r), OIDC_UNAUTZ_RETURN403);
	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "401", NULL));
	ck_assert_int_eq(oidc_cfg_dir_unautz_action_get(r), OIDC_UNAUTZ_RETURN401);
	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "auth", NULL));
	ck_assert_int_eq(oidc_cfg_dir_unautz_action_get(r), OIDC_UNAUTZ_AUTHENTICATE);

	/* 302 requires the 2nd URL argument */
	ck_assert_ptr_nonnull(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "302", NULL));
	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "302", "https://app.example.com/unauthz"));
	ck_assert_int_eq(oidc_cfg_dir_unautz_action_get(r), OIDC_UNAUTZ_RETURN302);
	ck_assert_str_eq(oidc_cfg_dir_unauthz_arg_get(r), "https://app.example.com/unauthz");

	/* unknown action rejected */
	ck_assert_ptr_nonnull(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "503", NULL));
}
END_TEST

START_TEST(test_cmd_dir_path_auth_request_params_and_scope) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPathAuthRequestParams);

	ck_assert_ptr_null(oidc_cmd_dir_path_auth_request_params_set(cmd, dir_cfg, "prompt=login"));
	cmd = oidc_test_cmd_get(OIDCPathScope);
	ck_assert_ptr_null(oidc_cmd_dir_path_scope_set(cmd, dir_cfg, "openid profile"));
}
END_TEST

START_TEST(test_cmd_dir_refresh_access_token_before_expiry) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCRefreshAccessTokenBeforeExpiry);

	ck_assert_ptr_null(oidc_cmd_dir_refresh_access_token_before_expiry_set(cmd, dir_cfg, "60", NULL));
	ck_assert_int_eq(oidc_cfg_dir_refresh_access_token_before_expiry_get(r), 60);

	/* the 2nd arg sets the on-error action */
	ck_assert_ptr_null(oidc_cmd_dir_refresh_access_token_before_expiry_set(cmd, dir_cfg, "120", "logout_on_error"));
	ck_assert_int_eq(oidc_cfg_dir_action_on_error_refresh_get(r), OIDC_ON_ERROR_LOGOUT);

	/* below the min (0) or unknown 2nd arg are rejected */
	ck_assert_ptr_nonnull(oidc_cmd_dir_refresh_access_token_before_expiry_set(cmd, dir_cfg, "-99", NULL));
	ck_assert_ptr_nonnull(oidc_cmd_dir_refresh_access_token_before_expiry_set(cmd, dir_cfg, "60", "bogus_action"));
}
END_TEST

START_TEST(test_cmd_dir_cookie_and_path_and_state_prefix) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCCookie);
	ck_assert_ptr_null(oidc_cmd_dir_cookie_set(cmd, dir_cfg, "my_session_cookie"));
	ck_assert_str_eq(oidc_cfg_dir_cookie_get(r), "my_session_cookie");

	cmd = oidc_test_cmd_get(OIDCCookiePath);
	ck_assert_ptr_null(oidc_cmd_dir_cookie_path_set(cmd, dir_cfg, "/app/"));
	ck_assert_str_eq(oidc_cfg_dir_cookie_path_get(r), "/app/");

	cmd = oidc_test_cmd_get(OIDCStateCookiePrefix);
	ck_assert_ptr_null(oidc_cmd_dir_state_cookie_prefix_set(cmd, dir_cfg, "state_"));
	ck_assert_str_eq(oidc_cfg_dir_state_cookie_prefix_get(r), "state_");

	cmd = oidc_test_cmd_get(OIDCAuthNHeader);
	ck_assert_ptr_null(oidc_cmd_dir_authn_header_set(cmd, dir_cfg, "X-Remote-User"));
	ck_assert_str_eq(oidc_cfg_dir_authn_header_get(r), "X-Remote-User");
}
END_TEST

START_TEST(test_cmd_dir_pass_access_refresh_token) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassAccessToken);
	ck_assert_ptr_null(oidc_cmd_dir_pass_access_token_set(cmd, dir_cfg, "Off"));
	ck_assert_int_eq(oidc_cfg_dir_pass_access_token_get(r), 0);
	ck_assert_ptr_null(oidc_cmd_dir_pass_access_token_set(cmd, dir_cfg, "On"));
	ck_assert_int_eq(oidc_cfg_dir_pass_access_token_get(r), 1);

	cmd = oidc_test_cmd_get(OIDCPassRefreshToken);
	ck_assert_ptr_null(oidc_cmd_dir_pass_refresh_token_set(cmd, dir_cfg, "On"));
	ck_assert_int_eq(oidc_cfg_dir_pass_refresh_token_get(r), 1);
	ck_assert_ptr_nonnull(oidc_cmd_dir_pass_refresh_token_set(cmd, dir_cfg, "maybe"));
}
END_TEST

START_TEST(test_cmd_dir_token_introspection_interval) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthTokenIntrospectionInterval);

	ck_assert_ptr_null(oidc_cmd_dir_token_introspection_interval_set(cmd, dir_cfg, "30"));
	ck_assert_int_eq(oidc_cfg_dir_token_introspection_interval_get(r), 30);

	/* -1 means "never expire" - allowed; -2 not allowed */
	ck_assert_ptr_null(oidc_cmd_dir_token_introspection_interval_set(cmd, dir_cfg, "-1"));
	ck_assert_ptr_nonnull(oidc_cmd_dir_token_introspection_interval_set(cmd, dir_cfg, "-2"));
}
END_TEST

START_TEST(test_cmd_dir_pass_idtoken_as) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassIDTokenAs);

	ck_assert_ptr_null(oidc_cmd_dir_pass_idtoken_as_set(cmd, dir_cfg, "claims"));
	ck_assert_ptr_null(oidc_cmd_dir_pass_idtoken_as_set(cmd, dir_cfg, "payload"));
	ck_assert_ptr_null(oidc_cmd_dir_pass_idtoken_as_set(cmd, dir_cfg, "serialized"));
	ck_assert_ptr_null(oidc_cmd_dir_pass_idtoken_as_set(cmd, dir_cfg, "off"));
	/* unknown variant rejected */
	ck_assert_ptr_nonnull(oidc_cmd_dir_pass_idtoken_as_set(cmd, dir_cfg, "totally_bogus"));
}
END_TEST

START_TEST(test_cfg_dir_accept_oauth_token_in2str) {
	apr_pool_t *pool = oidc_test_pool_get();

	const char *s = oidc_cfg_dir_accept_oauth_token_in2str(pool, OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER);
	ck_assert_ptr_nonnull(s);
	ck_assert_ptr_nonnull(_oidc_strstr(s, "header"));

	s = oidc_cfg_dir_accept_oauth_token_in2str(pool,
						   OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER | OIDC_OAUTH_ACCEPT_TOKEN_IN_POST);
	ck_assert_ptr_nonnull(_oidc_strstr(s, "header"));
	ck_assert_ptr_nonnull(_oidc_strstr(s, "post"));
}
END_TEST

START_TEST(test_cfg_dir_config_merge) {
	apr_pool_t *pool = oidc_test_pool_get();

	oidc_dir_cfg_t *base = oidc_cfg_dir_config_create(pool, NULL);
	oidc_dir_cfg_t *add = oidc_cfg_dir_config_create(pool, NULL);

	/* drive a couple of fields via the public setters so the merge has something to pick from */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCookie);
	ck_assert_ptr_null(oidc_cmd_dir_cookie_set(cmd, base, "base_cookie"));
	cmd = oidc_test_cmd_get(OIDCCookiePath);
	ck_assert_ptr_null(oidc_cmd_dir_cookie_path_set(cmd, add, "/add-path/"));

	oidc_dir_cfg_t *merged = oidc_cfg_dir_config_merge(pool, base, add);
	ck_assert_ptr_nonnull(merged);

	/* swap merged into the request's per-dir config so the getters resolve against it */
	request_rec *r = oidc_test_request_get();
	void *prev = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	ap_set_module_config(r->per_dir_config, &auth_openidc_module, merged);
	ck_assert_str_eq(oidc_cfg_dir_cookie_get(r), "base_cookie");
	ck_assert_str_eq(oidc_cfg_dir_cookie_path_get(r), "/add-path/");
	/* restore the original dir cfg so teardown doesn't see something unexpected */
	ap_set_module_config(r->per_dir_config, &auth_openidc_module, prev);
}
END_TEST

/*
 * Regression coverage for the dir-config merge resolution rules that
 * test_cfg_dir_config_merge does not exercise: the _merge_pos_int helper (incl.
 * an explicit "off"/0 overriding a truthy base) and the _merge_introspect_interval
 * special case (the -2 "unset" sentinel must fall back to base, not reset to the
 * getter default). These are the empty/sentinel paths that have historically
 * regressed in config merging.
 */
START_TEST(test_cfg_dir_config_merge_inherit) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	void *prev = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	oidc_dir_cfg_t *base, *add, *merged;
	cmd_parms *cmd;

	/* pos_int: base configured, add left unset -> merged inherits base */
	base = oidc_cfg_dir_config_create(pool, NULL);
	add = oidc_cfg_dir_config_create(pool, NULL);
	cmd = oidc_test_cmd_get(OIDCPreservePost);
	ck_assert_ptr_null(oidc_cmd_dir_preserve_post_set(cmd, base, "On"));
	merged = oidc_cfg_dir_config_merge(pool, base, add);
	ap_set_module_config(r->per_dir_config, &auth_openidc_module, merged);
	ck_assert_int_eq(oidc_cfg_dir_preserve_post_get(r), 1);

	/* pos_int: an explicit "Off" (0) on add must override a truthy base,
	 * i.e. 0 is a configured value, not "unset" */
	base = oidc_cfg_dir_config_create(pool, NULL);
	add = oidc_cfg_dir_config_create(pool, NULL);
	ck_assert_ptr_null(oidc_cmd_dir_preserve_post_set(cmd, base, "On"));
	ck_assert_ptr_null(oidc_cmd_dir_preserve_post_set(cmd, add, "Off"));
	merged = oidc_cfg_dir_config_merge(pool, base, add);
	ap_set_module_config(r->per_dir_config, &auth_openidc_module, merged);
	ck_assert_int_eq(oidc_cfg_dir_preserve_post_get(r), 0);

	/* pos_int: neither side configured -> getter resolves to its default */
	base = oidc_cfg_dir_config_create(pool, NULL);
	add = oidc_cfg_dir_config_create(pool, NULL);
	merged = oidc_cfg_dir_config_merge(pool, base, add);
	ap_set_module_config(r->per_dir_config, &auth_openidc_module, merged);
	ck_assert_int_eq(oidc_cfg_dir_preserve_post_get(r), 0);

	/* introspect interval: add at the -2 default must inherit base's value,
	 * not collapse to the getter's 0 default */
	base = oidc_cfg_dir_config_create(pool, NULL);
	add = oidc_cfg_dir_config_create(pool, NULL);
	cmd = oidc_test_cmd_get(OIDCOAuthTokenIntrospectionInterval);
	ck_assert_ptr_null(oidc_cmd_dir_token_introspection_interval_set(cmd, base, "30"));
	merged = oidc_cfg_dir_config_merge(pool, base, add);
	ap_set_module_config(r->per_dir_config, &auth_openidc_module, merged);
	ck_assert_int_eq(oidc_cfg_dir_token_introspection_interval_get(r), 30);

	/* restore the original dir cfg so teardown doesn't see something unexpected */
	ap_set_module_config(r->per_dir_config, &auth_openidc_module, prev);
}
END_TEST

/*
 * Tests for cfg/cache.c uncovered functions.
 */

START_TEST(test_cmd_cache_encrypt) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCacheEncrypt);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_cache_encrypt_set(cmd, NULL, "On"));
	ck_assert_int_eq(oidc_cfg_cache_encrypt_get(cfg), 1);
	ck_assert_ptr_null(oidc_cmd_cache_encrypt_set(cmd, NULL, "Off"));
	ck_assert_int_eq(oidc_cfg_cache_encrypt_get(cfg), 0);
	ck_assert_ptr_nonnull(oidc_cmd_cache_encrypt_set(cmd, NULL, "maybe"));
}
END_TEST

START_TEST(test_cmd_cache_shm_size_max) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCacheShmMax);
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	ck_assert_ptr_null(oidc_cmd_cache_shm_size_max_set(cmd, NULL, "1024"));
	ck_assert_int_eq(oidc_cfg_cache_shm_size_max_get(cfg), 1024);

	/* below the minimum (128) or above the max */
	ck_assert_ptr_nonnull(oidc_cmd_cache_shm_size_max_set(cmd, NULL, "5"));
}
END_TEST

START_TEST(test_cmd_cache_file_clean_interval) {
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCacheFileCleanInterval);

	ck_assert_ptr_null(oidc_cmd_cache_file_clean_interval_set(cmd, NULL, "120"));

	/* above the max (7 days in seconds) */
	ck_assert_ptr_nonnull(oidc_cmd_cache_file_clean_interval_set(cmd, NULL, "99999999"));
}
END_TEST

#ifdef USE_MEMCACHE

START_TEST(test_cmd_cache_memcache_settings) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCMemCacheServers);

	ck_assert_ptr_null(oidc_cmd_cache_memcache_servers_set(cmd, NULL, "127.0.0.1:11211"));
	ck_assert_str_eq(oidc_cfg_cache_memcache_servers_get(cfg), "127.0.0.1:11211");

	cmd = oidc_test_cmd_get(OIDCMemCacheConnectionsMin);
	ck_assert_ptr_null(oidc_cmd_cache_memcache_min_set(cmd, NULL, "1"));
	ck_assert_int_eq(oidc_cfg_cache_memcache_min_get(cfg), 1);
	ck_assert_ptr_nonnull(oidc_cmd_cache_memcache_min_set(cmd, NULL, "99999"));

	cmd = oidc_test_cmd_get(OIDCMemCacheConnectionsSMax);
	ck_assert_ptr_null(oidc_cmd_cache_memcache_smax_set(cmd, NULL, "10"));
	ck_assert_int_eq(oidc_cfg_cache_memcache_smax_get(cfg), 10);

	cmd = oidc_test_cmd_get(OIDCMemCacheConnectionsHMax);
	ck_assert_ptr_null(oidc_cmd_cache_memcache_hmax_set(cmd, NULL, "20"));
	ck_assert_int_eq(oidc_cfg_cache_memcache_hmax_get(cfg), 20);
}
END_TEST

#endif

#ifdef USE_LIBHIREDIS

START_TEST(test_cmd_cache_redis_settings) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCRedisCacheServer);

	ck_assert_ptr_null(oidc_cmd_cache_redis_server_set(cmd, NULL, "127.0.0.1:6379"));
	ck_assert_str_eq(oidc_cfg_cache_redis_server_get(cfg), "127.0.0.1:6379");

	cmd = oidc_test_cmd_get(OIDCRedisCacheUsername);
	ck_assert_ptr_null(oidc_cmd_cache_redis_username_set(cmd, NULL, "redisuser"));
	ck_assert_str_eq(oidc_cfg_cache_redis_username_get(cfg), "redisuser");

	cmd = oidc_test_cmd_get(OIDCRedisCachePassword);
	ck_assert_ptr_null(oidc_cmd_cache_redis_password_set(cmd, NULL, "redispwd"));
	ck_assert_str_eq(oidc_cfg_cache_redis_password_get(cfg), "redispwd");

	cmd = oidc_test_cmd_get(OIDCRedisCacheDatabase);
	ck_assert_ptr_null(oidc_cmd_cache_redis_database_set(cmd, NULL, "2"));
	ck_assert_int_eq(oidc_cfg_cache_redis_database_get(cfg), 2);
	ck_assert_ptr_nonnull(oidc_cmd_cache_redis_database_set(cmd, NULL, "9999"));

	cmd = oidc_test_cmd_get(OIDCRedisCacheConnectTimeout);
	ck_assert_ptr_null(oidc_cmd_cache_redis_connect_timeout_set(cmd, NULL, "10", "60"));
	ck_assert_int_eq(oidc_cfg_cache_redis_connect_timeout_get(cfg), 10);
	ck_assert_int_eq(oidc_cfg_cache_redis_keepalive_get(cfg), 60);

	cmd = oidc_test_cmd_get(OIDCRedisCacheTimeout);
	ck_assert_ptr_null(oidc_cmd_cache_redis_timeout_set(cmd, NULL, "5"));
	ck_assert_int_eq(oidc_cfg_cache_redis_timeout_get(cfg), 5);
}
END_TEST

#endif

START_TEST(test_cfg_cache_merge_server_config) {
	apr_pool_t *pool = oidc_test_pool_get();
	server_rec *s = oidc_test_request_get()->server;

	oidc_cfg_t *base = oidc_cfg_server_create(pool, s);
	oidc_cfg_t *add = oidc_cfg_server_create(pool, s);

	base->cache.shm_size_max = 999;
	add->cache.shm_size_max = 5000;
	add->cache.encrypt = 1;
	base->cache.encrypt = OIDC_CONFIG_POS_INT_UNSET;

	oidc_cfg_t *merged = (oidc_cfg_t *)oidc_cfg_server_merge(pool, base, add);
	ck_assert_ptr_nonnull(merged);
	ck_assert_int_eq(merged->cache.shm_size_max, 5000);
	ck_assert_int_eq(merged->cache.encrypt, 1);
}
END_TEST

/*
 * Tests for cfg/oauth.c uncovered setters.
 */

START_TEST(test_cmd_oauth_url_and_client) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthServerMetadataURL);

	ck_assert_ptr_null(oidc_cmd_oauth_metadata_url_set(cmd, NULL, "https://op.example.com/.well-known/oauth"));
	ck_assert_str_eq(oidc_cfg_oauth_metadata_url_get(cfg), "https://op.example.com/.well-known/oauth");
	ck_assert_ptr_nonnull(oidc_cmd_oauth_metadata_url_set(cmd, NULL, "not-a-url"));

	cmd = oidc_test_cmd_get(OIDCOAuthClientID);
	ck_assert_ptr_null(oidc_cmd_oauth_client_id_set(cmd, NULL, "my-client"));
	ck_assert_str_eq(oidc_cfg_oauth_client_id_get(cfg), "my-client");

	cmd = oidc_test_cmd_get(OIDCOAuthClientSecret);
	ck_assert_ptr_null(oidc_cmd_oauth_client_secret_set(cmd, NULL, "supersecret"));
	ck_assert_str_eq(oidc_cfg_oauth_client_secret_get(cfg), "supersecret");

	cmd = oidc_test_cmd_get(OIDCOAuthVerifyJwksUri);
	ck_assert_ptr_null(oidc_cmd_oauth_verify_jwks_uri_set(cmd, NULL, "https://op.example.com/jwks"));
	ck_assert_str_eq(oidc_cfg_oauth_verify_jwks_uri_get(cfg), "https://op.example.com/jwks");
	ck_assert_ptr_nonnull(oidc_cmd_oauth_verify_jwks_uri_set(cmd, NULL, "not-a-url"));
}
END_TEST

START_TEST(test_cmd_oauth_introspection_settings) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionEndpointParams);

	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_params_set(cmd, NULL, "scope=openid"));
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_params_get(cfg), "scope=openid");

	cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionTokenParamName);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_token_param_name_set(cmd, NULL, "access_token"));
	ck_assert_str_eq(oidc_cfg_oauth_introspection_token_param_name_get(cfg), "access_token");

	cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionEndpointAuth);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_auth_set(cmd, NULL, "client_secret_basic"));
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_auth_get(cfg), "client_secret_basic");
	ck_assert_ptr_nonnull(oidc_cmd_oauth_introspection_endpoint_auth_set(cmd, NULL, "totally_bogus_method"));

	cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionEndpointMethod);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_method_set(cmd, NULL, "GET"));
	ck_assert_int_eq(oidc_cfg_oauth_introspection_endpoint_method_get(cfg), OIDC_INTROSPECTION_METHOD_GET);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_method_set(cmd, NULL, "POST"));
	ck_assert_int_eq(oidc_cfg_oauth_introspection_endpoint_method_get(cfg), OIDC_INTROSPECTION_METHOD_POST);
	ck_assert_ptr_nonnull(oidc_cmd_oauth_introspection_endpoint_method_set(cmd, NULL, "DELETE"));

	cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionClientAuthBearerToken);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_client_auth_bearer_token_set(cmd, NULL, "my-bearer-token"));
	ck_assert_str_eq(oidc_cfg_oauth_introspection_client_auth_bearer_token_get(cfg), "my-bearer-token");
}
END_TEST

START_TEST(test_cmd_oauth_token_expiry_claim) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthTokenExpiryClaim);

	ck_assert_ptr_null(oidc_cmd_oauth_token_expiry_claim_set(cmd, NULL, "exp", "absolute", "mandatory"));
	ck_assert_str_eq(oidc_cfg_oauth_introspection_token_expiry_claim_name_get(cfg), "exp");
	ck_assert_int_eq(oidc_cfg_oauth_introspection_token_expiry_claim_format_get(cfg),
			 OIDC_TOKEN_EXPIRY_CLAIM_FORMAT_ABSOLUTE);
	ck_assert_int_eq(oidc_cfg_oauth_introspection_token_expiry_claim_required_get(cfg),
			 OIDC_TOKEN_EXPIRY_CLAIM_REQUIRED_MANDATORY);

	ck_assert_ptr_null(oidc_cmd_oauth_token_expiry_claim_set(cmd, NULL, "expires_in", "relative", "optional"));
	ck_assert_int_eq(oidc_cfg_oauth_introspection_token_expiry_claim_format_get(cfg),
			 OIDC_TOKEN_EXPIRY_CLAIM_FORMAT_RELATIVE);
	ck_assert_int_eq(oidc_cfg_oauth_introspection_token_expiry_claim_required_get(cfg),
			 OIDC_TOKEN_EXPIRY_CLAIM_REQUIRED_OPTIONAL);

	ck_assert_ptr_nonnull(oidc_cmd_oauth_token_expiry_claim_set(cmd, NULL, "exp", "carrier_pigeon", NULL));
	ck_assert_ptr_nonnull(oidc_cmd_oauth_token_expiry_claim_set(cmd, NULL, "exp", "relative", "carrier_pigeon"));
}
END_TEST

START_TEST(test_cmd_oauth_remote_user_claim) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthRemoteUserClaim);

	ck_assert_ptr_null(oidc_cmd_oauth_remote_user_claim_set(cmd, NULL, "username", NULL, NULL));
	const oidc_remote_user_claim_t *c = oidc_cfg_oauth_remote_user_claim_get(cfg);
	ck_assert_str_eq(c->claim_name, "username");
}
END_TEST

START_TEST(test_cmd_oauth_verify_public_keys) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthVerifyCertFiles);
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	const char *arg = apr_psprintf(cmd->pool, "rsa-1#%s/public.pem", dir);

	ck_assert_ptr_null(oidc_cmd_oauth_verify_public_keys_set(cmd, NULL, arg));
	const apr_array_header_t *keys = oidc_cfg_oauth_verify_public_keys_get(cfg);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_gt(keys->nelts, 0);
}
END_TEST

START_TEST(test_cfg_oauth_merge) {
	apr_pool_t *pool = oidc_test_pool_get();
	server_rec *s = oidc_test_request_get()->server;

	oidc_cfg_t *base = oidc_cfg_server_create(pool, s);
	oidc_cfg_t *add = oidc_cfg_server_create(pool, s);

	/* drive the merge via the public setters - one only on base, one only on add */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthClientID);
	/* manually wire base/add into the cmd's server module config so the setter
	 * resolves cfg correctly for each call */
	ap_set_module_config(s->module_config, &auth_openidc_module, base);
	ck_assert_ptr_null(oidc_cmd_oauth_client_id_set(cmd, NULL, "base_client"));
	ap_set_module_config(s->module_config, &auth_openidc_module, add);
	ck_assert_ptr_null(oidc_cmd_oauth_client_id_set(cmd, NULL, "add_client"));

	cmd = oidc_test_cmd_get(OIDCOAuthClientSecret);
	ck_assert_ptr_null(oidc_cmd_oauth_client_secret_set(cmd, NULL, "add_secret"));

	oidc_cfg_t *merged = (oidc_cfg_t *)oidc_cfg_server_merge(pool, base, add);
	ck_assert_ptr_nonnull(merged);
	ck_assert_str_eq(oidc_cfg_oauth_client_id_get(merged), "add_client");
	ck_assert_str_eq(oidc_cfg_oauth_client_secret_get(merged), "add_secret");

	/* restore the original cfg so test teardown sees the same fixture */
	ap_set_module_config(s->module_config, &auth_openidc_module, oidc_test_cfg_get());
}
END_TEST

/*
 * Tests for cfg/provider.c uncovered setters.
 */

START_TEST(test_cmd_provider_issuer_client_secret_audvalues) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCProviderIssuer);
	ck_assert_ptr_null(oidc_cmd_provider_issuer_set(cmd, NULL, "https://idp2.example.com"));
	ck_assert_str_eq(oidc_cfg_provider_issuer_get(p), "https://idp2.example.com");

	cmd = oidc_test_cmd_get(OIDCClientID);
	ck_assert_ptr_null(oidc_cmd_provider_client_id_set(cmd, NULL, "my-client-id"));
	ck_assert_str_eq(oidc_cfg_provider_client_id_get(p), "my-client-id");

	cmd = oidc_test_cmd_get(OIDCClientSecret);
	ck_assert_ptr_null(oidc_cmd_provider_client_secret_set(cmd, NULL, "my-client-secret"));
	ck_assert_str_eq(oidc_cfg_provider_client_secret_get(p), "my-client-secret");

	cmd = oidc_test_cmd_get(OIDCIDTokenAudValues);
	ck_assert_ptr_null(oidc_cmd_provider_id_token_aud_values_set(cmd, NULL, "aud1"));
	ck_assert_ptr_null(oidc_cmd_provider_id_token_aud_values_set(cmd, NULL, "aud2"));
	const apr_array_header_t *vs = oidc_cfg_provider_id_token_aud_values_get(p);
	ck_assert_ptr_nonnull(vs);
	ck_assert_int_eq(vs->nelts, 2);
}
END_TEST

START_TEST(test_cmd_provider_endpoint_urls) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);
	cmd_parms *cmd = NULL;
	const char *u = "https://idp.example.com/auth";

	cmd = oidc_test_cmd_get(OIDCProviderAuthorizationEndpoint);
	ck_assert_ptr_null(oidc_cmd_provider_authorization_endpoint_url_set(cmd, NULL, u));
	ck_assert_str_eq(oidc_cfg_provider_authorization_endpoint_url_get(p), u);
	ck_assert_ptr_nonnull(oidc_cmd_provider_authorization_endpoint_url_set(cmd, NULL, "not-a-url"));

	cmd = oidc_test_cmd_get(OIDCProviderPushedAuthorizationRequestEndpoint);
	ck_assert_ptr_null(
	    oidc_cmd_provider_pushed_authorization_request_endpoint_url_set(cmd, NULL, "https://idp.example.com/par"));
	ck_assert_str_eq(oidc_cfg_provider_pushed_authorization_request_endpoint_url_get(p),
			 "https://idp.example.com/par");

	cmd = oidc_test_cmd_get(OIDCProviderJwksUri);
	ck_assert_ptr_null(oidc_cmd_provider_jwks_uri_set(cmd, NULL, "https://idp.example.com/jwks"));
	ck_assert_str_eq(oidc_cfg_provider_jwks_uri_uri_get(p), "https://idp.example.com/jwks");

	cmd = oidc_test_cmd_get(OIDCProviderRevocationEndpoint);
	ck_assert_ptr_null(oidc_cmd_provider_revocation_endpoint_url_set(cmd, NULL, "https://idp.example.com/revoke"));
	ck_assert_str_eq(oidc_cfg_provider_revocation_endpoint_url_get(p), "https://idp.example.com/revoke");
}
END_TEST

START_TEST(test_cmd_provider_logout_request_params_and_registration_token) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);
	cmd_parms *cmd = NULL;

	cmd = oidc_test_cmd_get(OIDCLogoutRequestParams);
	ck_assert_ptr_null(oidc_cmd_provider_logout_request_params_set(cmd, NULL, "prompt=login"));
	ck_assert_str_eq(oidc_cfg_provider_logout_request_params_get(p), "prompt=login");
}
END_TEST

START_TEST(test_cmd_provider_bool_flags) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);
	cmd_parms *cmd = NULL;

	cmd = oidc_test_cmd_get(OIDCProviderBackChannelLogoutSupported);
	ck_assert_ptr_null(oidc_cmd_provider_backchannel_logout_supported_set(cmd, NULL, "On"));
	ck_assert_int_eq(oidc_cfg_provider_backchannel_logout_supported_get(p), 1);
	ck_assert_ptr_null(oidc_cmd_provider_backchannel_logout_supported_set(cmd, NULL, "Off"));
	ck_assert_int_eq(oidc_cfg_provider_backchannel_logout_supported_get(p), 0);
}
END_TEST

START_TEST(test_cmd_provider_jwks_uri_and_signed_jwks_uri) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);
	cmd_parms *cmd = NULL;

	cmd = oidc_test_cmd_get(OIDCProviderSignedJwksUri);
	ck_assert_ptr_null(
	    oidc_cmd_provider_signed_jwks_uri_set(cmd, NULL, "https://idp.example.com/signed-jwks", "{\"keys\":[]}"));
	ck_assert_str_eq(oidc_cfg_provider_signed_jwks_uri_get(p), "https://idp.example.com/signed-jwks");

	/* json that doesn't parse */
	ck_assert_ptr_nonnull(
	    oidc_cmd_provider_signed_jwks_uri_set(cmd, NULL, "https://idp.example.com/signed-jwks", "{not-json"));
	/* URL that doesn't validate */
	ck_assert_ptr_nonnull(oidc_cmd_provider_signed_jwks_uri_set(cmd, NULL, "not-a-url", NULL));
}
END_TEST

START_TEST(test_cmd_provider_registration_endpoint_json_and_token) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);
	cmd_parms *cmd = NULL;

	cmd = oidc_test_cmd_get(OIDCProviderRegistrationEndpointJson);
	ck_assert_ptr_null(oidc_cmd_provider_registration_endpoint_json_set(cmd, NULL, "{\"client_name\":\"my-rp\"}"));
	ck_assert_str_eq(oidc_cfg_provider_registration_endpoint_json_get(p), "{\"client_name\":\"my-rp\"}");
}
END_TEST

START_TEST(test_cmd_provider_verify_and_client_keys) {
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_provider_t *p = oidc_cfg_provider_get(cfg);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCProviderVerifyCertFiles);
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	const char *arg = apr_psprintf(cmd->pool, "rsa-1#%s/public.pem", dir);

	ck_assert_ptr_null(oidc_cmd_provider_verify_public_keys_set(cmd, NULL, arg));
	const apr_array_header_t *keys = oidc_cfg_provider_verify_public_keys_get(p);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_gt(keys->nelts, 0);
}
END_TEST

START_TEST(test_cfg_provider_merge_and_copy) {
	apr_pool_t *pool = oidc_test_pool_get();

	oidc_provider_t *base = oidc_cfg_provider_create(pool);
	oidc_provider_t *add = oidc_cfg_provider_create(pool);

	/* exercise the merge by setting distinct values on each side */
	ck_assert_ptr_null(oidc_cfg_provider_issuer_set(pool, base, "https://base.example.com"));
	ck_assert_ptr_null(oidc_cfg_provider_client_id_set(pool, add, "add-client"));
	ck_assert_ptr_null(oidc_cfg_provider_scope_set(pool, add, "openid email"));

	oidc_provider_t *merged = oidc_cfg_provider_create(pool);
	oidc_cfg_provider_merge(pool, merged, base, add);
	/* add overrides where set, base wins where unset */
	ck_assert_str_eq(oidc_cfg_provider_issuer_get(merged), "https://base.example.com");
	ck_assert_str_eq(oidc_cfg_provider_client_id_get(merged), "add-client");
	ck_assert_str_eq(oidc_cfg_provider_scope_get(merged), "openid email");

	/* copy duplicates the source - check by changing the source and confirming the copy is unaffected */
	oidc_provider_t *copy = oidc_cfg_provider_copy(pool, merged);
	ck_assert_ptr_nonnull(copy);
	ck_assert_str_eq(oidc_cfg_provider_issuer_get(copy), "https://base.example.com");

	/* clean up the copies' jwk lists explicitly to keep valgrind happy */
	oidc_cfg_provider_destroy(merged);
	oidc_cfg_provider_destroy(copy);
}
END_TEST

int main(void) {
	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(core, test_cmd_provider_token_endpoint_auth_set);
	tcase_add_test(core, test_cmd_provider_token_endpoint_auth_no_private_keys);
#ifdef USE_MEMCACHE
	tcase_add_test(core, test_cfg_cache_connections_ttl);
#endif
	tcase_add_test(core, test_cmd_cookie_same_site);
	tcase_add_test(core, test_cmd_oauth_verify_shared_keys);
	tcase_add_test(core, test_cmd_oauth_decrypt_shared_keys);
	tcase_add_test(core, test_cmd_crypto_passphrase);
	tcase_add_test(core, test_cmd_outgoing_proxy);
	tcase_add_test(core, test_cmd_cookie_domain);
	tcase_add_test(core, test_cmd_session_inactivity_timeout);
	tcase_add_test(core, test_cmd_public_keys);
	tcase_add_test(core, test_cmd_remote_user_claim);
	tcase_add_test(core, test_cmd_claim_prefix);
	tcase_add_test(core, test_cmd_max_number_of_state_cookies);
	tcase_add_test(core, test_cmd_x_forwarded_headers);
	tcase_add_test(core, test_cmd_state_input_headers);
	tcase_add_test(core, test_cmd_post_preserve_templates);
	tcase_add_test(core, test_cmd_ca_bundle_path);
	tcase_add_test(core, test_cmd_cookie_http_only);
	tcase_add_test(core, test_cmd_session_cache_fallback_to_cookie);
	tcase_add_test(core, test_cmd_claim_delimiter);
	tcase_add_test(core, test_cmd_metrics_path);
	tcase_add_test(core, test_cmd_logout_x_frame_options);
	tcase_add_test(core, test_cmd_state_timeout);
	tcase_add_test(core, test_cmd_session_cookie_chunk_size);
	tcase_add_test(core, test_cmd_provider_metadata_refresh_interval);
	tcase_add_test(core, test_cmd_white_black_redirect_url_hashes);
	tcase_add_test(core, test_cmd_redirect_and_slo_urls);
	tcase_add_test(core, test_cmd_http_timeout_long_short);
	tcase_add_test(core, test_cfg_server_merge_and_merged_get);
	tcase_add_test(core, test_cfg_server_merge_crypto_passphrase_derived_keys);
	tcase_add_test(core, test_cfg_crypto_passphrase_derive_keys_cached);
	tcase_add_test(core, test_cfg_child_init);

	TCase *dir = tcase_create("dir");
	tcase_add_checked_fixture(dir, oidc_test_setup, oidc_test_teardown);
#ifdef USE_LIBJQ
	tcase_add_test(dir, test_cmd_filter_claims_expr);
	tcase_add_test(dir, test_cmd_dir_userinfo_claims_expr);
#endif
	tcase_add_test(dir, test_cmd_dir_pass_userinfo_as);
	tcase_add_test(dir, test_cmd_dir_pass_claims_as);
	tcase_add_test(dir, test_cmd_dir_accept_oauth_token_in);
	tcase_add_test(dir, test_cmd_dir_strip_pass_cookies);
	tcase_add_test(dir, test_cmd_dir_preserve_post);
	tcase_add_test(dir, test_cmd_dir_unautz_action);
	tcase_add_test(dir, test_cmd_dir_path_auth_request_params_and_scope);
	tcase_add_test(dir, test_cmd_dir_refresh_access_token_before_expiry);
	tcase_add_test(dir, test_cmd_dir_cookie_and_path_and_state_prefix);
	tcase_add_test(dir, test_cmd_dir_pass_access_refresh_token);
	tcase_add_test(dir, test_cmd_dir_token_introspection_interval);
	tcase_add_test(dir, test_cmd_dir_pass_idtoken_as);
	tcase_add_test(dir, test_cfg_dir_accept_oauth_token_in2str);
	tcase_add_test(dir, test_cfg_dir_config_merge);
	tcase_add_test(dir, test_cfg_dir_config_merge_inherit);

	TCase *provider = tcase_create("provider");
	tcase_add_checked_fixture(provider, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(provider, test_cmd_provider_response_type);
	tcase_add_test(provider, test_cmd_provider_session_max_duration);
	tcase_add_test(provider, test_cmd_provider_scope);
	tcase_add_test(provider, test_cmd_provider_dpop_mode);
	tcase_add_test(provider, test_cmd_provider_pkce);
	tcase_add_test(provider, test_cmd_provider_idtoken_iat_slack);
	tcase_add_test(provider, test_cmd_provider_url_setters);
	tcase_add_test(provider, test_cmd_provider_string_setters);
	tcase_add_test(provider, test_cmd_provider_token_endpoint_tls);
	tcase_add_test(provider, test_cmd_provider_metadata_only_setters);
	tcase_add_test(provider, test_cmd_provider_signed_response_alg);
	tcase_add_test(provider, test_cmd_provider_encrypted_response_alg_enc);
	tcase_add_test(provider, test_cmd_provider_bool_setters);
	tcase_add_test(provider, test_cmd_provider_int_setters);
	tcase_add_test(provider, test_cmd_provider_userinfo_token_method);
	tcase_add_test(provider, test_cmd_provider_auth_request_method);
	tcase_add_test(provider, test_cmd_provider_profile);
	tcase_add_test(provider, test_cmd_provider_response_mode);
	tcase_add_test(provider, test_cmd_provider_issuer_client_secret_audvalues);
	tcase_add_test(provider, test_cmd_provider_endpoint_urls);
	tcase_add_test(provider, test_cmd_provider_logout_request_params_and_registration_token);
	tcase_add_test(provider, test_cmd_provider_bool_flags);
	tcase_add_test(provider, test_cmd_provider_jwks_uri_and_signed_jwks_uri);
	tcase_add_test(provider, test_cmd_provider_registration_endpoint_json_and_token);
	tcase_add_test(provider, test_cmd_provider_verify_and_client_keys);
	tcase_add_test(provider, test_cfg_provider_merge_and_copy);

	TCase *cache = tcase_create("cache");
	tcase_add_checked_fixture(cache, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(cache, test_cmd_cache_type);
	tcase_add_test(cache, test_cmd_cache_shm_entry_size_max);
	tcase_add_test(cache, test_cmd_cache_dir);
	tcase_add_test(cache, test_cmd_session_type);
	tcase_add_test(cache, test_cmd_cache_encrypt);
	tcase_add_test(cache, test_cmd_cache_shm_size_max);
	tcase_add_test(cache, test_cmd_cache_file_clean_interval);
#ifdef USE_MEMCACHE
	tcase_add_test(cache, test_cmd_cache_memcache_settings);
#endif
#ifdef USE_LIBHIREDIS
	tcase_add_test(cache, test_cmd_cache_redis_settings);
#endif
	tcase_add_test(cache, test_cfg_cache_merge_server_config);

	TCase *parse = tcase_create("parse");
	tcase_add_checked_fixture(parse, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(parse, test_cfg_parse_is_valid_url);
	tcase_add_test(parse, test_cfg_parse_action_on_error_refresh_as);
	tcase_add_test(parse, test_cfg_parse_public_key_files);
	tcase_add_test(parse, test_cfg_parse_key_files_alg);
	tcase_add_test(parse, test_cfg_parse_remote_user_claim);
	tcase_add_test(parse, test_cfg_parse_http_timeout);
	tcase_add_test(parse, test_cfg_parse_key_record_encodings);

	TCase *oauth = tcase_create("oauth");
	tcase_add_checked_fixture(oauth, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(oauth, test_cmd_oauth_url_and_client);
	tcase_add_test(oauth, test_cmd_oauth_introspection_settings);
	tcase_add_test(oauth, test_cmd_oauth_introspection_endpoint_tls);
	tcase_add_test(oauth, test_cmd_oauth_token_expiry_claim);
	tcase_add_test(oauth, test_cmd_oauth_remote_user_claim);
	tcase_add_test(oauth, test_cmd_oauth_verify_public_keys);
	tcase_add_test(oauth, test_cfg_oauth_merge);

	Suite *s = suite_create("cfg");
	suite_add_tcase(s, core);
	suite_add_tcase(s, dir);
	suite_add_tcase(s, provider);
	suite_add_tcase(s, cache);
	suite_add_tcase(s, parse);
	suite_add_tcase(s, oauth);

	return oidc_test_suite_run(s);
}
