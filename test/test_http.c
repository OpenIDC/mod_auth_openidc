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
#include "cfg/provider.h"
#include "check_util.h"
#include "http.h"
#include "util.h"
#include <curl/curl.h>

START_TEST(test_http_accept) {
	request_rec *r = oidc_test_request_get();

	// ie 9/10/11
	apr_table_set(r->headers_in, "Accept", "text/html, application/xhtml+xml, */*");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "text/html") == TRUE, "Accept: text/html (ie 9/10/11)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "application/json") == FALSE,
		      "Accept: application/json (ie 9/10/11)");

	// firefox
	apr_table_set(r->headers_in, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "text/html") == TRUE, "Accept: text/html (firefox)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "application/json") == FALSE,
		      "Accept: application/json (firefox)");

	// chrome/safari
	apr_table_set(r->headers_in, "Accept",
		      "application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "text/html") == TRUE, "Accept: text/html (chrome/safari)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "application/json") == FALSE,
		      "Accept: application/json (chrome/safari)");

	// safari 5
	apr_table_set(r->headers_in, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "text/html") == TRUE, "Accept: text/html (safari 5)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "application/json") == FALSE,
		      "Accept: application/json (safari 5)");

	// ie 8
	apr_table_set(r->headers_in, "Accept",
		      "image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, "
		      "application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "text/html") == FALSE, "Accept: text/html (ie 8)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "*/*") == TRUE, "Accept: */* (ie 8)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "application/json") == FALSE,
		      "Accept: application/json (ie 8)");

	// edge
	apr_table_set(r->headers_in, "Accept", "text/html, application/xhtml+xml, image/jxr, */*");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "text/html") == TRUE, "Accept: text/html (edge)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "application/json") == FALSE,
		      "Accept: application/json (edge)");

	// opera
	apr_table_set(r->headers_in, "Accept",
		      "text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, "
		      "image/gif, image/x-xbitmap, */*;q=0.1");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "text/html") == TRUE, "Accept: text/html (opera)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "application/json") == FALSE,
		      "Accept: application/json (opera)");

	// xmlhttprequest
	apr_table_set(r->headers_in, "Accept", "application/json");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "text/html") == FALSE, "Accept: text/html (opera)");
	ck_assert_msg(oidc_http_hdr_in_accept_contains(r, "application/json") == TRUE,
		      "Accept: application/json (opera)");
}
END_TEST

START_TEST(test_url_encode_decode) {
	request_rec *r = oidc_test_request_get();
	const char *in = "a b+c%/&=~";
	char *enc = oidc_http_url_encode(r, in);
	ck_assert_ptr_nonnull(enc);
	char *dec = oidc_http_url_decode(r, enc);
	ck_assert_ptr_nonnull(dec);
	ck_assert_msg(_oidc_strcmp(dec, in) == 0, "decoded value matches original");
}
END_TEST

START_TEST(test_hdr_getters_and_forwarded) {
	request_rec *r = oidc_test_request_get();
	apr_table_set(r->headers_in, "User-Agent", "MyAgent/1.0");
	apr_table_set(r->headers_in, "Content-Type", "text/plain");
	apr_table_set(r->headers_in, "Content-Length", "123");
	apr_table_set(r->headers_in, "X-Forwarded-For", "192.0.2.1, 10.0.0.1");
	apr_table_set(r->headers_in, "X-Forwarded-Host", "host1, host2");
	apr_table_set(r->headers_in, "Forwarded", "for=192.0.2.60; proto=http; by=203.0.113.43");

	ck_assert_ptr_nonnull(oidc_http_hdr_in_user_agent_get(r));
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_user_agent_get(r), "MyAgent/1.0") == 0, "user-agent matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_content_type_get(r), "text/plain") == 0, "content-type matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_content_length_get(r), "123") == 0, "content-length matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_x_forwarded_for_get(r), "192.0.2.1") == 0,
		      "left-most X-Forwarded-For returned");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_x_forwarded_host_get(r), "host1") == 0,
		      "left-most X-Forwarded-Host returned");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_forwarded_get(r, "proto"), "http") == 0, "forwarded proto parsed");
}
END_TEST

START_TEST(test_hdr_normalize_query_form) {
	request_rec *r = oidc_test_request_get();
	const char *name = "X(Invalid):Header/Name\t";
	char *norm = oidc_http_hdr_normalize_name(r, name);
	ck_assert_ptr_nonnull(norm);
	// ensure separators replaced by '-'
	ck_assert_msg(_oidc_strstr(norm, "-") != NULL, "normalized contains '-' character");

	apr_table_t *params = apr_table_make(r->pool, 3);
	apr_table_set(params, "a", "1");
	apr_table_set(params, "b c", "d/e");
	char *qurl = oidc_http_query_encoded_url(r, "https://example.com/path", params);
	ck_assert_ptr_nonnull(qurl);
	// should contain 'a=1' and encoded b+c
	ck_assert_msg(_oidc_strstr(qurl, "a=1") != NULL, "query contains a=1");
	ck_assert_msg(_oidc_strstr(qurl, "b+c=") != NULL || _oidc_strstr(qurl, "b%20c=") != NULL,
		      "query contains encoded b c key");

	char *form = oidc_http_form_encoded_data(r, params);
	ck_assert_ptr_nonnull(form);
	ck_assert_msg(_oidc_strstr(form, "a=1") != NULL, "form contains a=1");
}
END_TEST

START_TEST(test_cookies_and_chunking) {
	request_rec *r = oidc_test_request_get();
	// existing cookie from helper: foo=bar; mod_auth_openidc_session=0123456789abcdef; baz=zot
	char *v = oidc_http_get_cookie(r, "foo");
	ck_assert_ptr_nonnull(v);
	ck_assert_msg(_oidc_strcmp(v, "bar") == 0, "foo cookie value is bar");

	// set up chunked cookies in headers_in to simulate browser
	const char *cookie_header = "big=; big_chunks=3; big_0=AAA; big_1=BBB; big_2=CCC";
	apr_table_set(r->headers_in, "Cookie", cookie_header);
	char *big = oidc_http_get_chunked_cookie(r, "big", 5);
	ck_assert_ptr_nonnull(big);
	ck_assert_msg(_oidc_strcmp(big, "AAABBBCCC") == 0, "chunked cookie reconstructed");
}
END_TEST

START_TEST(test_proxy_options_and_s2auth) {
	const char **opts = oidc_http_proxy_auth_options();
	ck_assert_ptr_nonnull(opts);
	int found_basic = 0, found_digest = 0, found_ntlm = 0, found_any = 0;
	for (int i = 0; opts[i] != NULL; i++) {
		if (_oidc_strcmp(opts[i], OIDC_HTTP_PROXY_AUTH_BASIC) == 0)
			found_basic = 1;
		if (_oidc_strcmp(opts[i], OIDC_HTTP_PROXY_AUTH_DIGEST) == 0)
			found_digest = 1;
		if (_oidc_strcmp(opts[i], OIDC_HTTP_PROXY_AUTH_NTLM) == 0)
			found_ntlm = 1;
		if (_oidc_strcmp(opts[i], OIDC_HTTP_PROXY_AUTH_ANY) == 0)
			found_any = 1;
	}
	ck_assert_msg(found_basic && found_digest && found_ntlm && found_any, "proxy options include expected values");

	unsigned long v;
	v = oidc_http_proxy_s2auth(OIDC_HTTP_PROXY_AUTH_BASIC);
	ck_assert_msg(v == CURLAUTH_BASIC, "basic maps to CURLAUTH_BASIC");
	v = oidc_http_proxy_s2auth(OIDC_HTTP_PROXY_AUTH_DIGEST);
	ck_assert_msg(v == CURLAUTH_DIGEST, "digest maps to CURLAUTH_DIGEST");
	v = oidc_http_proxy_s2auth(OIDC_HTTP_PROXY_AUTH_NTLM);
	ck_assert_msg(v == CURLAUTH_NTLM, "ntlm maps to CURLAUTH_NTLM");
	v = oidc_http_proxy_s2auth("no-such");
	ck_assert_msg(v == CURLAUTH_NONE, "unknown maps to CURLAUTH_NONE");
}
END_TEST

START_TEST(test_hdr_setters_and_cookie_set) {
	request_rec *r = oidc_test_request_get();
	oidc_http_hdr_in_set(r, "X-Test-Header", "test-val");
	ck_assert_msg(_oidc_strcmp(apr_table_get(r->headers_in, "X-Test-Header"), "test-val") == 0,
		      "header in set/get works");

	oidc_http_hdr_in_cookie_set(r, "a=b;c=d");
	ck_assert_ptr_nonnull(oidc_http_hdr_in_cookie_get(r));
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_cookie_get(r), "a=b;c=d") == 0, "cookie header set/get works");
}
END_TEST

START_TEST(test_hdr_out_location_and_traceparent) {
	request_rec *r = oidc_test_request_get();
	oidc_http_hdr_out_location_set(r, "https://example.com/redirect");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_out_location_get(r), "https://example.com/redirect") == 0,
		      "location out set/get works");

	apr_table_set(r->headers_in, "traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_traceparent_get(r),
				   "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") == 0,
		      "traceparent get works");
}
END_TEST

START_TEST(test_set_cookie_and_chunked_set) {
	request_rec *r = oidc_test_request_get();
	apr_time_t expires = apr_time_now() + apr_time_from_sec(3600);

	oidc_http_set_cookie(r, "sname", "svalue", expires, "SameSite=Lax");
	const apr_array_header_t *h = apr_table_elts(r->err_headers_out);
	apr_table_entry_t *elts = (apr_table_entry_t *)h->elts;
	int found = 0;
	for (int i = 0; i < h->nelts; i++) {
		if (_oidc_strstr(elts[i].key, "Set-Cookie") || _oidc_strstr(elts[i].val, "sname=svalue")) {
			if (_oidc_strstr(elts[i].val, "sname=svalue")) {
				found = 1;
				break;
			}
		}
	}
	ck_assert_msg(found == 1, "Set-Cookie header contains our cookie");

	/* test chunked cookie */
	char large[1024];
	for (int i = 0; i < 1000; i++)
		large[i] = 'A' + (i % 26);
	large[1000] = '\0';
	oidc_http_set_chunked_cookie(r, "chunked", large, expires, 100, "SameSite=Lax");
	/* ensure chunk counter cookie present in err_headers_out */
	h = apr_table_elts(r->err_headers_out);
	elts = (apr_table_entry_t *)h->elts;
	int found_cnt = 0;
	for (int i = 0; i < h->nelts; i++) {
		if (_oidc_strstr(elts[i].val, "chunked_chunks=")) {
			found_cnt = 1;
			break;
		}
	}
	ck_assert_msg(found_cnt == 1, "chunked counter cookie set");
}
END_TEST

START_TEST(test_other_header_getters) {
	request_rec *r = oidc_test_request_get();
	apr_table_set(r->headers_in, "X-Requested-With", "XMLHttpRequest");
	apr_table_set(r->headers_in, "Sec-Fetch-Mode", "navigate");
	apr_table_set(r->headers_in, "Sec-Fetch-Dest", "document");
	apr_table_set(r->headers_in, "Authorization", "Bearer tok123");
	apr_table_set(r->headers_in, "X-Forwarded-Proto", "https, http");
	apr_table_set(r->headers_in, "X-Forwarded-Port", "443, 80");
	apr_table_set(r->headers_in, "Host", "host.example.com");

	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_x_requested_with_get(r), "XMLHttpRequest") == 0,
		      "X-Requested-With matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_sec_fetch_mode_get(r), "navigate") == 0, "Sec-Fetch-Mode matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_sec_fetch_dest_get(r), "document") == 0, "Sec-Fetch-Dest matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_authorization_get(r), "Bearer tok123") == 0,
		      "Authorization matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_x_forwarded_proto_get(r), "https") == 0,
		      "X-Forwarded-Proto left-most matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_x_forwarded_port_get(r), "443") == 0,
		      "X-Forwarded-Port left-most matches");
	ck_assert_msg(_oidc_strcmp(oidc_http_hdr_in_host_get(r), "host.example.com") == 0, "Host header matches");
}
END_TEST

START_TEST(test_init_and_cleanup_noop) {
	oidc_http_init();
	oidc_http_cleanup();
	ck_assert_msg(1 == 1, "init/cleanup execute without crash");
}
END_TEST

int main(void) {
	TCase *accept = tcase_create("accept");
	tcase_add_checked_fixture(accept, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(accept, test_http_accept);
	tcase_add_test(accept, test_url_encode_decode);
	tcase_add_test(accept, test_hdr_getters_and_forwarded);
	tcase_add_test(accept, test_hdr_normalize_query_form);
	tcase_add_test(accept, test_cookies_and_chunking);
	tcase_add_test(accept, test_proxy_options_and_s2auth);
	tcase_add_test(accept, test_hdr_setters_and_cookie_set);
	tcase_add_test(accept, test_hdr_out_location_and_traceparent);
	tcase_add_test(accept, test_set_cookie_and_chunked_set);
	tcase_add_test(accept, test_other_header_getters);
	tcase_add_test(accept, test_init_and_cleanup_noop);

	Suite *s = suite_create("http");
	suite_add_tcase(s, accept);

	return oidc_test_suite_run(s);
}
