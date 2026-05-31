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
	ck_assert_int_eq(oidc_session_save(r, z, TRUE), TRUE);

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
	ck_assert_int_eq(oidc_session_save(r, z, TRUE), TRUE);

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

START_TEST(test_session_last_refresh_timestamps) {
	request_rec *r = oidc_test_request_get();

	oidc_session_t *z = NULL;
	oidc_session_load(r, &z);

	/* access-token last-refresh roundtrips at second granularity */
	apr_time_t ts = apr_time_now();
	oidc_session_set_access_token_last_refresh(r, z, ts);
	ck_assert_int_eq((int)apr_time_sec(oidc_session_get_access_token_last_refresh(r, z)), (int)apr_time_sec(ts));

	/* reset_userinfo_last_refresh stamps "now" */
	oidc_session_reset_userinfo_last_refresh(r, z);
	ck_assert_int_gt(oidc_session_get_userinfo_last_refresh(r, z), 0);

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

	ck_assert_str_eq(oidc_session_get_issuer(r, z), "https://op.example.org");
	ck_assert_str_eq(oidc_session_get_access_token(r, z), "AT");
	ck_assert_str_eq(oidc_session_get_access_token_type(r, z), "Bearer");
	ck_assert_str_eq(oidc_session_get_refresh_token(r, z), "RT");
	ck_assert_str_eq(oidc_session_get_scope(r, z), "openid profile");
	ck_assert_str_eq(oidc_session_get_session_state(r, z), "sstate");
	ck_assert_str_eq(oidc_session_get_original_url(r, z), "https://www.example.com/protected/");

	oidc_session_free(r, z);
}
END_TEST

int main(void) {
	Suite *s = suite_create("session");

	TCase *c = tcase_create("session");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_session_cache_roundtrip);
	tcase_add_test(c, test_session_cookie_roundtrip);
	tcase_add_test(c, test_session_last_refresh_timestamps);
	tcase_add_test(c, test_session_getter_setter_roundtrip);
	suite_add_tcase(s, c);

	return oidc_test_suite_run(s);
}
