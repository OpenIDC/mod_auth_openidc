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
 * Tests for state.c — oidc_state_cookie_name, oidc_state_browser_fingerprint
 * (XFF / UA / NONE input-header modes), and oidc_state_cookies_clean_expired
 * across the kept / undecodable / expired / delete-oldest branches.
 */

#include "cfg/cfg_int.h"
#include "check_util.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "state.h"
#include "util.h"
#include "util/util.h"

/* build a single state cookie value with `ts_offset` seconds applied to the
 * timestamp (negative => already expired) — returns the serialized cookie
 * value so the caller can stitch together a Cookie header */
static char *state_cookie_value(request_rec *r, oidc_cfg_t *c, int ts_offset) {
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "n");
	oidc_proto_state_set_state(ps, "s");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_response_type(ps, OIDC_PROTO_RESPONSE_TYPE_CODE);
	oidc_proto_state_set_timestamp_now(ps);
	/* override the timestamp the setter just wrote */
	oidc_json_object_set_new(ps, "t", oidc_json_integer(apr_time_sec(apr_time_now()) + ts_offset));
	char *cv = oidc_proto_state_to_cookie(r, c, ps);
	oidc_proto_state_destroy(ps);
	return cv;
}

START_TEST(test_state_cookie_name) {
	request_rec *r = oidc_test_request_get();

	/* default prefix is "mod_auth_openidc_state_" so the cookie name simply
	 * concatenates the prefix and the supplied state value */
	char *name = oidc_state_cookie_name(r, "ABC");
	ck_assert_ptr_nonnull(name);
	ck_assert_str_eq(name, "mod_auth_openidc_state_ABC");
}
END_TEST

START_TEST(test_state_browser_fingerprint_user_agent) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* default OIDCStateInputHeaders is "user-agent": the User-Agent header
	 * (when present) feeds into the SHA1 input alongside the nonce */
	apr_table_set(r->headers_in, "User-Agent", "TestAgent/1.0");
	char *fp1 = oidc_state_browser_fingerprint(r, c, "nonce-1");
	ck_assert_ptr_nonnull(fp1);

	apr_table_set(r->headers_in, "User-Agent", "OtherAgent/2.0");
	char *fp2 = oidc_state_browser_fingerprint(r, c, "nonce-1");
	ck_assert_str_ne(fp1, fp2);

	/* same User-Agent + same nonce must produce the same fingerprint */
	apr_table_set(r->headers_in, "User-Agent", "TestAgent/1.0");
	char *fp3 = oidc_state_browser_fingerprint(r, c, "nonce-1");
	ck_assert_str_eq(fp1, fp3);

	apr_table_unset(r->headers_in, "User-Agent");
}
END_TEST

START_TEST(test_state_browser_fingerprint_xff) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCStateInputHeaders);
	ck_assert_ptr_null(oidc_cmd_state_input_headers_set(cmd, NULL, "x-forwarded-for"));

	/* XFF mode: a different X-Forwarded-For value must yield a different
	 * fingerprint — this exercises the XFF branch in oidc_state_browser_fingerprint */
	apr_table_set(r->headers_in, "X-Forwarded-For", "10.0.0.1");
	char *fp1 = oidc_state_browser_fingerprint(r, c, "nonce-xff");
	apr_table_set(r->headers_in, "X-Forwarded-For", "10.0.0.2");
	char *fp2 = oidc_state_browser_fingerprint(r, c, "nonce-xff");
	ck_assert_str_ne(fp1, fp2);

	apr_table_unset(r->headers_in, "X-Forwarded-For");
}
END_TEST

START_TEST(test_state_browser_fingerprint_none) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCStateInputHeaders);
	ck_assert_ptr_null(oidc_cmd_state_input_headers_set(cmd, NULL, "none"));

	/* with NONE the User-Agent must NOT influence the fingerprint; only the
	 * nonce does */
	apr_table_set(r->headers_in, "User-Agent", "TestAgent/1.0");
	char *fp_ua = oidc_state_browser_fingerprint(r, c, "same-nonce");
	apr_table_set(r->headers_in, "User-Agent", "OtherAgent/2.0");
	char *fp_other = oidc_state_browser_fingerprint(r, c, "same-nonce");
	ck_assert_str_eq(fp_ua, fp_other);

	apr_table_unset(r->headers_in, "User-Agent");
}
END_TEST

START_TEST(test_state_cookies_clean_no_cookie_header) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	apr_table_unset(r->headers_in, "Cookie");
	ck_assert_int_eq(oidc_state_cookies_clean_expired(r, c, NULL, 0), 0);
}
END_TEST

START_TEST(test_state_cookies_clean_skip_current_and_non_state) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* a non-state cookie and the current state cookie are both ignored:
	 * non-state cookies because they don't match the state prefix,
	 * the current one because it matches the currentCookieName argument */
	char *cv = state_cookie_value(r, c, 0);
	char *current_name = oidc_state_cookie_name(r, "current");
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "foo=bar; %s=%s; baz=zot", current_name, cv));

	ck_assert_int_eq(oidc_state_cookies_clean_expired(r, c, current_name, 0), 0);
}
END_TEST

START_TEST(test_state_cookies_clean_undecodable) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* a state-prefixed cookie that does not decode as a signed-JWT proto
	 * state => oidc_proto_state_from_cookie returns NULL and the cookie is
	 * scheduled for deletion via Set-Cookie */
	apr_table_set(r->headers_in, "Cookie", "mod_auth_openidc_state_garbage=not-a-jwt");

	ck_assert_int_eq(oidc_state_cookies_clean_expired(r, c, NULL, 0), 0);
	/* the function appends a deletion Set-Cookie to err_headers_out */
	const apr_array_header_t *arr = apr_table_elts(r->err_headers_out);
	int found = 0;
	for (int i = 0; i < arr->nelts; i++) {
		const apr_table_entry_t *e = &((const apr_table_entry_t *)arr->elts)[i];
		if (e->key && _oidc_strcmp(e->key, "Set-Cookie") == 0 &&
		    _oidc_strstr(e->val, "mod_auth_openidc_state_garbage=") != NULL)
			found = 1;
	}
	ck_assert_msg(found, "expected a Set-Cookie deleting the undecodable state cookie");
}
END_TEST

START_TEST(test_state_cookies_clean_no_value) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* a state-prefixed cookie token without a '=' must be rejected and must not scan past the end of
	 * the token buffer looking for a '=' (out-of-bounds read + NUL write) */
	apr_table_set(r->headers_in, "Cookie", "mod_auth_openidc_state_novalue");

	ck_assert_int_eq(oidc_state_cookies_clean_expired(r, c, NULL, 0), 0);
}
END_TEST

START_TEST(test_state_cookies_clean_valid_kept) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* a fresh, decodable, non-expired state cookie is kept and counts as one
	 * valid outstanding request */
	char *cv = state_cookie_value(r, c, 0);
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "mod_auth_openidc_state_keep=%s", cv));

	ck_assert_int_eq(oidc_state_cookies_clean_expired(r, c, NULL, 0), 1);
}
END_TEST

START_TEST(test_state_cookies_clean_expired_deleted) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* a decodable state cookie whose timestamp pre-dates the state-timeout
	 * window is treated as expired => deletion Set-Cookie + not counted */
	char *cv = state_cookie_value(r, c, -1000);
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "mod_auth_openidc_state_old=%s", cv));

	ck_assert_int_eq(oidc_state_cookies_clean_expired(r, c, NULL, 0), 0);
}
END_TEST

START_TEST(test_state_cookies_clean_delete_oldest) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* the trim loop is `while (n >= max)` so 4 valid cookies with max=3
	 * gets trimmed to 2 (delete one to get n=3, n>=max again → delete another) */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCStateMaxNumberOfCookies);
	ck_assert_ptr_null(oidc_cmd_max_number_of_state_cookies_set(cmd, NULL, "3", "true"));

	char *cv_oldest = state_cookie_value(r, c, -180);
	char *cv_mid = state_cookie_value(r, c, -120);
	char *cv_newer = state_cookie_value(r, c, -60);
	char *cv_newest = state_cookie_value(r, c, 0);

	/* deliberately list the oldest cookie (_a) in the middle so the linked-list
	 * walk in oidc_state_cookies_delete_oldest has to *update* the running
	 * `oldest` pointer mid-iteration — this covers the prev_oldest branch */
	apr_table_set(r->headers_in, "Cookie",
		      apr_psprintf(r->pool,
				   "mod_auth_openidc_state_d=%s; "
				   "mod_auth_openidc_state_a=%s; "
				   "mod_auth_openidc_state_b=%s; "
				   "mod_auth_openidc_state_c=%s",
				   cv_newest, cv_oldest, cv_mid, cv_newer));

	int remaining = oidc_state_cookies_clean_expired(r, c, NULL, 1);
	ck_assert_int_eq(remaining, 2);

	/* the oldest cookie (_a) must be among the deleted ones */
	const apr_array_header_t *arr = apr_table_elts(r->err_headers_out);
	int found = 0;
	for (int i = 0; i < arr->nelts; i++) {
		const apr_table_entry_t *e = &((const apr_table_entry_t *)arr->elts)[i];
		if (e->key && _oidc_strcmp(e->key, "Set-Cookie") == 0 &&
		    _oidc_strstr(e->val, "mod_auth_openidc_state_a=") != NULL)
			found = 1;
	}
	ck_assert_msg(found, "expected the oldest state cookie to be deleted");
}
END_TEST

int main(void) {
	Suite *s = suite_create("state");

	TCase *state = tcase_create("state");
	tcase_add_checked_fixture(state, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(state, test_state_cookie_name);
	tcase_add_test(state, test_state_browser_fingerprint_user_agent);
	tcase_add_test(state, test_state_browser_fingerprint_xff);
	tcase_add_test(state, test_state_browser_fingerprint_none);
	tcase_add_test(state, test_state_cookies_clean_no_cookie_header);
	tcase_add_test(state, test_state_cookies_clean_skip_current_and_non_state);
	tcase_add_test(state, test_state_cookies_clean_undecodable);
	tcase_add_test(state, test_state_cookies_clean_no_value);
	tcase_add_test(state, test_state_cookies_clean_valid_kept);
	tcase_add_test(state, test_state_cookies_clean_expired_deleted);
	tcase_add_test(state, test_state_cookies_clean_delete_oldest);
	suite_add_tcase(s, state);

	return oidc_test_suite_run(s);
}
