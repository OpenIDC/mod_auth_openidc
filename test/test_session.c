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
 */

/*
 * Tests for session.c — save/load roundtrips for both the server-cache and the
 * (otherwise uncovered) self-contained client-cookie storage backends, plus the
 * access-token / userinfo last-refresh timestamps and a getter/setter roundtrip.
 */

#include "cfg/cfg_int.h"
#include "cfg/dir.h"
#include "check_util.h"
#include "session.h"
#include "util.h"
#include "util/util.h"
#include <jansson.h> /* json_pack for claim fixtures */

/* copy every Set-Cookie written during a save into the request Cookie header so
 * the next load reads it back — bridges err_headers_out -> headers_in and works
 * regardless of how many chunks the (potentially chunked) session cookie spans */
static void replay_set_cookies(request_rec *r) {
	const apr_array_header_t *arr = apr_table_elts(r->err_headers_out);
	char *cookie = NULL;
	for (int i = 0; i < arr->nelts; i++) {
		const apr_table_entry_t *e = &((const apr_table_entry_t *)arr->elts)[i];
		if ((e->key == NULL) || (_oidc_strcmp(e->key, "Set-Cookie") != 0))
			continue;
		/* keep only the "name=value" part, dropping the cookie attributes */
		char *nv = apr_pstrdup(r->pool, e->val);
		char *semi = strchr(nv, ';');
		if (semi != NULL)
			*semi = '\0';
		cookie = (cookie == NULL) ? nv : apr_psprintf(r->pool, "%s; %s", cookie, nv);
	}
	apr_table_unset(r->err_headers_out, "Set-Cookie");
	if (cookie != NULL)
		apr_table_set(r->headers_in, "Cookie", cookie);
}

START_TEST(test_session_cache_roundtrip) {
	request_rec *r = oidc_test_request_get();

	/* default OIDCSessionType is server-cache: persist under a known uuid, then
	 * inject the matching session cookie so the reload resolves it from the shm
	 * cache */
	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);
	const char *uuid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	z->uuid = apr_pstrdup(r->pool, uuid);
	z->remote_user = apr_pstrdup(r->pool, "alice@idp.example.com");
	z->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, z, "https://idp.example.com");
	oidc_session_set_access_token(r, z, "AT-cache");
	ck_assert_int_eq(oidc_session_save(r, z, OIDC_SESSION_SAVE_NEW), TRUE);

	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), uuid));

	oidc_session_t *z2 = NULL;
	ck_assert_int_eq(oidc_session_load(r, &z2), TRUE);
	ck_assert_str_eq(z2->remote_user, "alice@idp.example.com");
	ck_assert_str_eq(oidc_session_get_issuer(r, z2), "https://idp.example.com");
	ck_assert_str_eq(oidc_session_get_access_token(r, z2), "AT-cache");

	oidc_session_free(r, z);
	oidc_session_free(r, z2);
}
END_TEST

START_TEST(test_session_cookie_roundtrip) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* switch to the self-contained client-cookie backend: the session contents
	 * are encrypted into the cookie itself, exercising oidc_session_save_cookie
	 * and oidc_session_load_cookie */
	c->session_type = OIDC_SESSION_TYPE_CLIENT_COOKIE;

	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);
	z->remote_user = apr_pstrdup(r->pool, "bob@idp.example.com");
	z->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, z, "https://idp.example.com");
	oidc_session_set_access_token(r, z, "AT-cookie");
	ck_assert_int_eq(oidc_session_save(r, z, OIDC_SESSION_SAVE_NEW), TRUE);

	replay_set_cookies(r);

	oidc_session_t *z2 = NULL;
	ck_assert_int_eq(oidc_session_load(r, &z2), TRUE);
	ck_assert_str_eq(z2->remote_user, "bob@idp.example.com");
	ck_assert_str_eq(oidc_session_get_issuer(r, z2), "https://idp.example.com");
	ck_assert_str_eq(oidc_session_get_access_token(r, z2), "AT-cookie");

	oidc_session_free(r, z);
	oidc_session_free(r, z2);
}
END_TEST

/*
 * the process-local parsed-session cache is shared by every virtual host in the process, so it must
 * not let a session cross between them. In client-cookie mode the cookie is the whole session and
 * the JWE decrypt under this vhost's OIDCCryptoPassphrase is the only thing authenticating it, so a
 * cache hit that skipped the decrypt would hand vhost B the session vhost A minted.
 */
START_TEST(test_session_cookie_not_shared_across_vhosts) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	c->session_type = OIDC_SESSION_TYPE_CLIENT_COOKIE;

	/* vhost A mints a session and hands out the cookie */
	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);
	z->remote_user = apr_pstrdup(r->pool, "carol@idp.example.com");
	z->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_access_token(r, z, "AT-vhost-a");
	ck_assert_int_eq(oidc_session_save(r, z, OIDC_SESSION_SAVE_NEW), TRUE);
	replay_set_cookies(r);

	/* vhost A reads it back, which is what populates the process-local cache */
	oidc_session_t *z2 = NULL;
	ck_assert_int_eq(oidc_session_load(r, &z2), TRUE);
	ck_assert_str_eq(z2->remote_user, "carol@idp.example.com");

	/* a second vhost in the same process, with its own OIDCCryptoPassphrase */
	oidc_cfg_t *other = oidc_cfg_server_create(r->server->process->pconf, r->server);
	other->session_type = OIDC_SESSION_TYPE_CLIENT_COOKIE;
	other->cache.impl = c->cache.impl;
	other->cache.cfg = c->cache.cfg;
	other->crypto_passphrase.secret1 = "abcdefghijklmnopqrstuvwxyz012345";
	oidc_test_crypto_passphrase_rederive(other);
	ap_set_module_config(r->server->module_config, &auth_openidc_module, other);

	/* replaying vhost A's cookie at vhost B must not resolve to A's session: B cannot decrypt it,
	 * and the cache must not answer on its behalf */
	oidc_session_t *z3 = NULL;
	apr_byte_t rc = oidc_session_load(r, &z3);
	ck_assert_msg((rc == FALSE) || (z3->remote_user == NULL),
		      "a session cookie minted by another virtual host was accepted (remote_user=%s)",
		      (z3 != NULL) && (z3->remote_user != NULL) ? z3->remote_user : "(null)");

	/* and vhost A still resolves its own cookie afterwards */
	ap_set_module_config(r->server->module_config, &auth_openidc_module, c);
	oidc_session_t *z4 = NULL;
	ck_assert_int_eq(oidc_session_load(r, &z4), TRUE);
	ck_assert_str_eq(z4->remote_user, "carol@idp.example.com");

	oidc_session_free(r, z);
	oidc_session_free(r, z2);
	oidc_session_free(r, z3);
	oidc_session_free(r, z4);
}
END_TEST

START_TEST(test_session_last_refresh_timestamps) {
	request_rec *r = oidc_test_request_get();

	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);

	/* access-token last-refresh roundtrips at second granularity */
	apr_time_t ts = apr_time_now();
	oidc_session_set_access_token_last_refresh(r, z, ts);
	ck_assert_int_eq((int)apr_time_sec(oidc_session_get_access_token_last_refresh(r, z)), (int)apr_time_sec(ts));

	/* reset_userinfo_last_refresh stamps "now"; assert via ck_assert() so the 64-bit apr_time_t
	 * is compared natively. old libcheck (RHEL/Rocky 7, check < 0.10.0) truncates ck_assert_int_*
	 * operands to 32-bit int, which mangles the microsecond timestamp into a (often negative) value */
	oidc_session_reset_userinfo_last_refresh(r, z);
	ck_assert(oidc_session_get_userinfo_last_refresh(r, z) > 0);

	oidc_session_free(r, z);
}
END_TEST

START_TEST(test_session_getter_setter_roundtrip) {
	request_rec *r = oidc_test_request_get();

	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);

	oidc_session_set_issuer(r, z, "https://op.example.org");
	oidc_session_set_access_token(r, z, "AT");
	oidc_session_set_access_token_type(r, z, "Bearer");
	oidc_session_set_refresh_token(r, z, "RT");
	oidc_session_set_scope(r, z, "openid profile");
	oidc_session_set_session_state(r, z, "sstate");
	oidc_session_set_original_url(r, z, "https://www.example.com/protected/");
	oidc_session_set_path_auth_request_params(r, z, "prompt=consent");
	oidc_session_set_path_scope(r, z, "openid profile email");

	ck_assert_str_eq(oidc_session_get_issuer(r, z), "https://op.example.org");
	ck_assert_str_eq(oidc_session_get_access_token(r, z), "AT");
	ck_assert_str_eq(oidc_session_get_access_token_type(r, z), "Bearer");
	ck_assert_str_eq(oidc_session_get_refresh_token(r, z), "RT");
	ck_assert_str_eq(oidc_session_get_scope(r, z), "openid profile");
	ck_assert_str_eq(oidc_session_get_session_state(r, z), "sstate");
	ck_assert_str_eq(oidc_session_get_original_url(r, z), "https://www.example.com/protected/");
	ck_assert_str_eq(oidc_session_get_path_auth_request_params(r, z), "prompt=consent");
	ck_assert_str_eq(oidc_session_get_path_scope(r, z), "openid profile email");
	/* an unset value reads back as NULL (drives the fallback in the session-management "check" handler) */
	oidc_session_set_path_scope(r, z, NULL);
	ck_assert_ptr_null(oidc_session_get_path_scope(r, z));

	oidc_session_free(r, z);
}
END_TEST

/* client-cookie sessions cannot be encrypted or decrypted without a crypto passphrase */
START_TEST(test_session_cookie_no_crypto_passphrase) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	c->session_type = OIDC_SESSION_TYPE_CLIENT_COOKIE;
	c->crypto_passphrase.secret1 = NULL;

	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);
	z->remote_user = apr_pstrdup(r->pool, "alice");
	z->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, z, "https://idp.example.com");
	ck_assert_int_eq(oidc_session_save(r, z, OIDC_SESSION_SAVE_NEW), FALSE);
	oidc_session_free(r, z);

	/* an (opaque) session cookie cannot be decrypted either */
	apr_table_set(r->headers_in, "Cookie",
		      apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), "an-opaque-value"));
	oidc_session_t *z2 = NULL;
	ck_assert_int_eq(oidc_session_load(r, &z2), FALSE);
	oidc_session_free(r, z2);
}
END_TEST

/* the session cookie SameSite attribute follows OIDCCookieSameSite */
START_TEST(test_session_cookie_samesite_variants) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* Strict: a first-time save still uses Lax (post-redirect cookie delivery) */
	c->cookie_same_site_session = OIDC_SAMESITE_COOKIE_STRICT;
	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);
	z->uuid = apr_pstrdup(r->pool, "aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd");
	z->remote_user = apr_pstrdup(r->pool, "alice");
	z->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, z, "https://idp.example.com");
	ck_assert_int_eq(oidc_session_save(r, z, OIDC_SESSION_SAVE_NEW), TRUE);
	const apr_array_header_t *arr = apr_table_elts(r->err_headers_out);
	int found_lax = 0, found_strict = 0, found_none = 0;
	for (int i = 0; i < arr->nelts; i++) {
		const apr_table_entry_t *e = &((const apr_table_entry_t *)arr->elts)[i];
		if ((e->val != NULL) && (_oidc_strstr(e->val, z->uuid) != NULL)) {
			if (_oidc_strstr(e->val, "SameSite=Lax"))
				found_lax = 1;
			if (_oidc_strstr(e->val, "SameSite=Strict"))
				found_strict = 1;
		}
	}
	ck_assert_msg(found_lax && !found_strict, "first-time save with Strict configured uses Lax");

	/* a non-first-time save uses Strict */
	apr_table_unset(r->err_headers_out, "Set-Cookie");
	ck_assert_int_eq(oidc_session_save(r, z, OIDC_SESSION_SAVE_UPDATE), TRUE);
	arr = apr_table_elts(r->err_headers_out);
	for (int i = 0; i < arr->nelts; i++) {
		const apr_table_entry_t *e = &((const apr_table_entry_t *)arr->elts)[i];
		if ((e->val != NULL) && (_oidc_strstr(e->val, z->uuid) != NULL) &&
		    (_oidc_strstr(e->val, "SameSite=Strict")))
			found_strict = 1;
	}
	ck_assert_msg(found_strict, "non-first-time save with Strict configured uses Strict");

	/* None (on a secure request) */
	c->cookie_same_site_session = OIDC_SAMESITE_COOKIE_NONE;
	apr_table_unset(r->err_headers_out, "Set-Cookie");
	ck_assert_int_eq(oidc_session_save(r, z, OIDC_SESSION_SAVE_NEW), TRUE);
	arr = apr_table_elts(r->err_headers_out);
	for (int i = 0; i < arr->nelts; i++) {
		const apr_table_entry_t *e = &((const apr_table_entry_t *)arr->elts)[i];
		if ((e->val != NULL) && (_oidc_strstr(e->val, z->uuid) != NULL) &&
		    (_oidc_strstr(e->val, "SameSite=None")))
			found_none = 1;
	}
	ck_assert_msg(found_none, "save with None configured uses SameSite=None");

	oidc_session_free(r, z);
}
END_TEST

/* with OIDCSessionCacheFallbackToCookie a cookie that misses the cache is
 * treated as a (potential) self-contained session instead of being deleted */
START_TEST(test_session_load_cache_fallback_to_cookie) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	c->session_cache_fallback_to_cookie = 1;

	apr_table_set(r->headers_in, "Cookie",
		      apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), "not-in-the-cache"));
	oidc_session_t *z = NULL;
	/* the cache misses, the fallback tries the cookie itself, which is not a valid session either */
	ck_assert_int_eq(oidc_session_load(r, &z), FALSE);
	oidc_session_free(r, z);

	/* a genuine cookie-fallback session: save one in client-cookie mode, replay it,
	 * then load it back in server-cache mode with the fallback enabled */
	c->session_type = OIDC_SESSION_TYPE_CLIENT_COOKIE;
	oidc_session_t *z2 = NULL;
	oidc_session_load(r, &z2);
	z2->remote_user = apr_pstrdup(r->pool, "carol");
	z2->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, z2, "https://idp.example.com");
	ck_assert_int_eq(oidc_session_save(r, z2, OIDC_SESSION_SAVE_NEW), TRUE);
	replay_set_cookies(r);
	c->session_type = OIDC_SESSION_TYPE_SERVER_CACHE;
	oidc_session_t *z3 = NULL;
	ck_assert_int_eq(oidc_session_load(r, &z3), TRUE);
	ck_assert_str_eq(z3->remote_user, "carol");
	oidc_session_free(r, z2);
	oidc_session_free(r, z3);

	/* a session too large for the shm cache slot falls back to the cookie on save */
	oidc_session_t *z4 = NULL;
	oidc_session_load(r, &z4);
	z4->remote_user = apr_pstrdup(r->pool, "dave");
	z4->expiry = apr_time_now() + apr_time_from_sec(3600);
	char *big = apr_palloc(r->pool, 64 * 1024 + 1);
	_oidc_memset(big, 'x', 64 * 1024);
	big[64 * 1024] = '\0';
	oidc_session_set_issuer(r, z4, big);
	/* the shm write fails, the cookie fallback needs too many chunks: overall failure,
	 * but both fallback branches have run */
	(void)oidc_session_save(r, z4, OIDC_SESSION_SAVE_NEW);
	oidc_session_free(r, z4);
}
END_TEST

/* corrupted cache entries: a non-object id_token claims value, an expired
 * session, and a session id mismatch */
START_TEST(test_session_cache_corruption) {
	request_rec *r = oidc_test_request_get();
	const char *uuid = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
	apr_time_t future = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_t *z = NULL;

	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), uuid));

	/* 1: id_token claims is a string rather than an object */
	char *s_json = apr_psprintf(r->pool, "{\"i\":\"%s\",\"e\":%d,\"r\":\"alice\",\"idc\":\"corrupt\"}", uuid,
				    (int)apr_time_sec(future));
	ck_assert_int_eq(oidc_cache_set_session(r, uuid, s_json, future), TRUE);
	ck_assert_int_eq(oidc_session_load(r, &z), FALSE);
	oidc_session_free(r, z);

	/* 2: the session has expired */
	s_json = apr_psprintf(r->pool, "{\"i\":\"%s\",\"e\":%d,\"r\":\"alice\"}", uuid,
			      (int)apr_time_sec(apr_time_now() - apr_time_from_sec(60)));
	ck_assert_int_eq(oidc_cache_set_session(r, uuid, s_json, future), TRUE);
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), uuid));
	ck_assert_int_eq(oidc_session_load(r, &z), FALSE);
	oidc_session_free(r, z);

	/* 3: the stored session id differs from the cache key */
	s_json =
	    apr_psprintf(r->pool, "{\"i\":\"some-other-uuid\",\"e\":%d,\"r\":\"alice\"}", (int)apr_time_sec(future));
	ck_assert_int_eq(oidc_cache_set_session(r, uuid, s_json, future), TRUE);
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), uuid));
	ck_assert_int_eq(oidc_session_load(r, &z), FALSE);
	oidc_session_free(r, z);
}
END_TEST

/* mutating a session whose parsed state is shared with the process-level cache
 * copies the state first (copy-on-write) */
START_TEST(test_session_state_unshare_on_write) {
	request_rec *r = oidc_test_request_get();
	const char *uuid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);
	z->uuid = apr_pstrdup(r->pool, uuid);
	z->remote_user = apr_pstrdup(r->pool, "alice");
	z->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, z, "https://idp.example.com");
	ck_assert_int_eq(oidc_session_save(r, z, OIDC_SESSION_SAVE_NEW), TRUE);
	oidc_session_free(r, z);

	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), uuid));
	oidc_session_t *z2 = NULL;
	ck_assert_int_eq(oidc_session_load(r, &z2), TRUE);
	ck_assert_int_eq(z2->state_shared, TRUE);
	/* the first mutation must un-share the state */
	oidc_session_set_issuer(r, z2, "https://other.example.org");
	ck_assert_int_eq(z2->state_shared, FALSE);
	ck_assert_str_eq(oidc_session_get_issuer(r, z2), "https://other.example.org");
	oidc_session_free(r, z2);

	/* a second load of the unchanged document is served straight from the parsed cache */
	oidc_session_t *z3 = NULL;
	ck_assert_int_eq(oidc_session_load(r, &z3), TRUE);
	ck_assert_int_eq(z3->state_shared, TRUE);
	oidc_session_free(r, z3);

	/* saving a state-less session with sid/sub indexes clears those cache entries;
	 * load it from a cookie-less request so its state is naturally empty */
	apr_table_unset(r->headers_in, "Cookie");
	oidc_session_t *z4 = NULL;
	oidc_session_load(r, &z4);
	ck_assert_ptr_null(z4->state);
	z4->uuid = apr_pstrdup(r->pool, uuid);
	z4->sid = apr_pstrdup(r->pool, "kill-sid");
	z4->sub = apr_pstrdup(r->pool, "kill-sub");
	ck_assert_int_eq(oidc_session_save(r, z4, OIDC_SESSION_SAVE_NEW), TRUE);
	oidc_session_free(r, z4);
}
END_TEST

/* claim black/whitelisting and the claim-size warning threshold */
START_TEST(test_session_claim_filtering) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);

	/* blacklist filters out the named claim */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCBlackListedClaims);
	ck_assert_ptr_null(oidc_cmd_black_listed_claims_set(cmd, NULL, "secret"));
	oidc_json_t *claims = json_pack("{s:s,s:s}", "sub", "alice", "secret", "hide-me");
	oidc_session_set_userinfo_claims(r, z, claims);
	oidc_json_t *stored = oidc_session_get_userinfo_claims(r, z);
	ck_assert_ptr_nonnull(oidc_json_object_get(stored, "sub"));
	ck_assert_ptr_null(oidc_json_object_get(stored, "secret"));
	oidc_json_decref(claims);
	c->black_listed_claims = NULL;

	/* whitelist keeps only the named claim */
	cmd = oidc_test_cmd_get(OIDCWhiteListedClaims);
	ck_assert_ptr_null(oidc_cmd_white_listed_claims_set(cmd, NULL, "sub"));
	claims = json_pack("{s:s,s:s}", "sub", "alice", "extra", "drop-me");
	oidc_session_set_userinfo_claims(r, z, claims);
	stored = oidc_session_get_userinfo_claims(r, z);
	ck_assert_ptr_nonnull(oidc_json_object_get(stored, "sub"));
	ck_assert_ptr_null(oidc_json_object_get(stored, "extra"));
	oidc_json_decref(claims);
	c->white_listed_claims = NULL;

	/* a claim larger than the (env-var-lowered) threshold triggers the size warning */
	apr_table_set(r->subprocess_env, "OIDC_SESSION_WARN_CLAIM_SIZE", "8");
	claims = json_pack("{s:s}", "big", "a-claim-value-larger-than-eight-bytes");
	oidc_session_set_userinfo_claims(r, z, claims);
	stored = oidc_session_get_userinfo_claims(r, z);
	ck_assert_ptr_nonnull(oidc_json_object_get(stored, "big"));
	apr_table_unset(r->subprocess_env, "OIDC_SESSION_WARN_CLAIM_SIZE");
	oidc_json_decref(claims);

	oidc_session_free(r, z);
}
END_TEST

#ifdef USE_LIBJQ
/* OIDCFilterClaimsExpr JQ-filters the claims before they are stored in the session */
START_TEST(test_session_claim_jq_filter) {
	request_rec *r = oidc_test_request_get();
	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCFilterClaimsExpr);
	ck_assert_ptr_null(oidc_cmd_filter_claims_expr_set(cmd, NULL, "{sub: .sub}"));

	oidc_json_t *claims = json_pack("{s:s,s:s}", "sub", "alice", "secret", "hide-me");
	oidc_session_set_userinfo_claims(r, z, claims);
	oidc_json_t *stored = oidc_session_get_userinfo_claims(r, z);
	ck_assert_ptr_nonnull(stored);
	ck_assert_ptr_nonnull(oidc_json_object_get(stored, "sub"));
	ck_assert_ptr_null(oidc_json_object_get(stored, "secret"));
	oidc_json_decref(claims);

	/* a filter that does not yield a JSON object drops the claims with an error */
	cmd = oidc_test_cmd_get(OIDCFilterClaimsExpr);
	ck_assert_ptr_null(oidc_cmd_filter_claims_expr_set(cmd, NULL, ".sub"));
	claims = json_pack("{s:s}", "sub", "alice");
	oidc_session_set_userinfo_claims(r, z, claims);
	ck_assert_ptr_null(oidc_session_get_userinfo_claims(r, z));
	oidc_json_decref(claims);

	oidc_session_free(r, z);
}
END_TEST
#endif

/* setting the session-new marker on a freshly cleared session allocates its state */
START_TEST(test_session_set_new_on_empty_state) {
	request_rec *r = oidc_test_request_get();
	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);
	ck_assert_ptr_null(z->state);
	oidc_session_set_session_new(r, z, 1);
	ck_assert_int_eq(oidc_session_get_session_new(r, z), 1);
	oidc_session_set_session_new(r, z, 0);
	ck_assert_int_eq(oidc_session_get_session_new(r, z), 0);
	oidc_session_free(r, z);
}
END_TEST

int main(void) {
	Suite *s = suite_create("session");

	TCase *c = tcase_create("session");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_session_cache_roundtrip);
	tcase_add_test(c, test_session_cookie_roundtrip);
	tcase_add_test(c, test_session_cookie_not_shared_across_vhosts);
	tcase_add_test(c, test_session_last_refresh_timestamps);
	tcase_add_test(c, test_session_getter_setter_roundtrip);
	tcase_add_test(c, test_session_cookie_no_crypto_passphrase);
	tcase_add_test(c, test_session_cookie_samesite_variants);
	tcase_add_test(c, test_session_load_cache_fallback_to_cookie);
	tcase_add_test(c, test_session_cache_corruption);
	tcase_add_test(c, test_session_state_unshare_on_write);
	tcase_add_test(c, test_session_claim_filtering);
#ifdef USE_LIBJQ
	tcase_add_test(c, test_session_claim_jq_filter);
#endif
	tcase_add_test(c, test_session_set_new_on_empty_state);
	suite_add_tcase(s, c);

	return oidc_test_suite_run(s);
}
