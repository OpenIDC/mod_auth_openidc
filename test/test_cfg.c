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
	tcase_add_test(provider, test_cmd_provider_url_setters);
	tcase_add_test(provider, test_cmd_provider_string_setters);
	tcase_add_test(provider, test_cmd_provider_signed_response_alg);
	tcase_add_test(provider, test_cmd_provider_encrypted_response_alg_enc);
	tcase_add_test(provider, test_cmd_provider_bool_setters);
	tcase_add_test(provider, test_cmd_provider_int_setters);
	tcase_add_test(provider, test_cmd_provider_userinfo_token_method);
	tcase_add_test(provider, test_cmd_provider_auth_request_method);
	tcase_add_test(provider, test_cmd_provider_profile);
	tcase_add_test(provider, test_cmd_provider_response_mode);

	TCase *cache = tcase_create("cache");
	tcase_add_checked_fixture(cache, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(cache, test_cmd_cache_type);
	tcase_add_test(cache, test_cmd_cache_shm_entry_size_max);
	tcase_add_test(cache, test_cmd_cache_dir);
	tcase_add_test(cache, test_cmd_session_type);

	Suite *s = suite_create("cfg");
	suite_add_tcase(s, core);
	suite_add_tcase(s, dir);
	suite_add_tcase(s, provider);
	suite_add_tcase(s, cache);

	return oidc_test_suite_run(s);
}
