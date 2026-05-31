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
#include "http_int.h"
#include "http_server.h"
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

/*
 * Unit tests for the curl-adjacent static helpers exposed via http_int.h.
 * These exercise the callbacks and builders directly so we cover the curl
 * code paths without standing up a real HTTP transfer.
 */

START_TEST(test_response_data_accumulates) {
	request_rec *r = oidc_test_request_get();
	oidc_curl_resp_data_ctx_t ctx = {r, NULL, 0};

	const char *part1 = "hello ";
	const char *part2 = "world";

	size_t n1 = oidc_http_response_data((void *)part1, 1, _oidc_strlen(part1), &ctx);
	ck_assert_msg(n1 == _oidc_strlen(part1), "first chunk consumed entirely");
	ck_assert_msg(ctx.size == _oidc_strlen(part1), "size grows by first chunk");

	size_t n2 = oidc_http_response_data((void *)part2, 1, _oidc_strlen(part2), &ctx);
	ck_assert_msg(n2 == _oidc_strlen(part2), "second chunk consumed entirely");
	ck_assert_msg(ctx.size == _oidc_strlen(part1) + _oidc_strlen(part2), "size accumulates");

	ck_assert_ptr_nonnull(ctx.memory);
	ck_assert_msg(_oidc_strcmp(ctx.memory, "hello world") == 0, "memory concatenated and NUL-terminated");
}
END_TEST

START_TEST(test_response_data_rejects_oversize) {
	request_rec *r = oidc_test_request_get();
	oidc_curl_resp_data_ctx_t ctx = {r, NULL, 0};

	/* claim a chunk bigger than the cap without actually allocating it; the callback
	 * must reject based on the advertised size before reading from contents */
	char tiny = 'x';
	size_t huge = (size_t)OIDC_CURL_RESPONSE_DATA_SIZE_MAX + 1;
	size_t rv = oidc_http_response_data(&tiny, 1, huge, &ctx);
	ck_assert_msg(rv == 0, "oversize response rejected (returns 0)");
	ck_assert_msg(ctx.size == 0, "context size unchanged on rejection");
}
END_TEST

START_TEST(test_response_header_captures_requested_only) {
	request_rec *r = oidc_test_request_get();
	apr_hash_t *hdrs = apr_hash_make(r->pool);
	/* callers seed the hash with empty-string sentinels for each header they
	 * want to capture; the callback fills in the actual value on match */
	apr_hash_set(hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING, "");
	oidc_curl_resp_hdr_ctx_t ctx = {r, hdrs};

	const char *wire1 = "DPoP-Nonce: abc123\r\n";
	const char *wire2 = "Content-Type: application/json\r\n";

	size_t n1 = oidc_http_response_header((char *)wire1, 1, _oidc_strlen(wire1), &ctx);
	ck_assert_msg(n1 == _oidc_strlen(wire1), "callback consumes full header line");

	size_t n2 = oidc_http_response_header((char *)wire2, 1, _oidc_strlen(wire2), &ctx);
	ck_assert_msg(n2 == _oidc_strlen(wire2), "non-matching header still fully consumed");

	const char *got = apr_hash_get(hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING);
	ck_assert_ptr_nonnull(got);
	ck_assert_msg(_oidc_strcmp(got, "abc123") == 0, "trimmed value stored for requested header");

	/* unrequested header should not have produced an entry under any new key */
	ck_assert_ptr_null(apr_hash_get(hdrs, OIDC_HTTP_HDR_CONTENT_TYPE, APR_HASH_KEY_STRING));
}
END_TEST

START_TEST(test_response_header_no_wanted_headers) {
	request_rec *r = oidc_test_request_get();
	oidc_curl_resp_hdr_ctx_t ctx_null = {r, NULL};
	oidc_curl_resp_hdr_ctx_t ctx_empty = {r, apr_hash_make(r->pool)};

	const char *wire = "Server: nginx\r\n";
	/* both NULL and empty hash short-circuit but still report bytes consumed */
	ck_assert_msg(oidc_http_response_header((char *)wire, 1, _oidc_strlen(wire), &ctx_null) == _oidc_strlen(wire),
		      "NULL hash short-circuit consumes bytes");
	ck_assert_msg(oidc_http_response_header((char *)wire, 1, _oidc_strlen(wire), &ctx_empty) == _oidc_strlen(wire),
		      "empty hash short-circuit consumes bytes");
}
END_TEST

/* count entries in a curl_slist */
static int slist_count(struct curl_slist *l) {
	int n = 0;
	for (; l != NULL; l = l->next)
		n++;
	return n;
}

/* return 1 if any entry in the slist contains needle as a substring */
static int slist_contains(struct curl_slist *l, const char *needle) {
	for (; l != NULL; l = l->next)
		if (l->data && _oidc_strstr(l->data, needle) != NULL)
			return 1;
	return 0;
}

START_TEST(test_build_header_list_bearer_and_content_type) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	struct curl_slist *l = oidc_http_request_build_header_list(r, c, OIDC_HTTP_CONTENT_TYPE_JSON, "tok-abc", NULL);
	ck_assert_ptr_nonnull(l);
	ck_assert_msg(slist_count(l) == 2, "Authorization + Content-Type entries present");
	ck_assert_msg(slist_contains(l, "Authorization: Bearer tok-abc"), "Bearer scheme used when no DPoP");
	ck_assert_msg(slist_contains(l, "Content-Type: " OIDC_HTTP_CONTENT_TYPE_JSON), "Content-Type passed through");
	curl_slist_free_all(l);
}
END_TEST

START_TEST(test_build_header_list_dpop_switches_scheme_and_adds_header) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	struct curl_slist *l = oidc_http_request_build_header_list(r, c, NULL, "tok-xyz", "PROOF.JWT.HERE");
	ck_assert_ptr_nonnull(l);
	ck_assert_msg(slist_contains(l, "Authorization: DPoP tok-xyz"),
		      "DPoP scheme replaces Bearer when proof present");
	ck_assert_msg(slist_contains(l, "DPoP: PROOF.JWT.HERE"), "separate DPoP header is appended");
	ck_assert_msg(!slist_contains(l, "Content-Type:"), "no Content-Type when caller passed NULL");
	curl_slist_free_all(l);
}
END_TEST

START_TEST(test_build_header_list_no_inputs) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	struct curl_slist *l = oidc_http_request_build_header_list(r, c, NULL, NULL, NULL);
	/* with no incoming traceparent and no inputs, slist should be empty */
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_TRACE_PARENT);
	ck_assert_msg(l == NULL || slist_count(l) == 0, "no entries when no inputs");
	if (l)
		curl_slist_free_all(l);
}
END_TEST

START_TEST(test_user_agent_defaults_and_override) {
	request_rec *r = oidc_test_request_get();

	apr_table_unset(r->subprocess_env, OIDC_USER_AGENT_ENV_VAR);
	const char *ua = oidc_http_user_agent(r);
	ck_assert_ptr_nonnull(ua);
	ck_assert_msg(_oidc_strstr(ua, "libcurl-") != NULL, "default UA mentions libcurl version");

	apr_table_set(r->subprocess_env, OIDC_USER_AGENT_ENV_VAR, "custom-agent/9.9");
	const char *ua2 = oidc_http_user_agent(r);
	ck_assert_ptr_nonnull(ua2);
	ck_assert_msg(_oidc_strcmp(ua2, "custom-agent/9.9") == 0, "env-var override returned verbatim");

	apr_table_unset(r->subprocess_env, OIDC_USER_AGENT_ENV_VAR);
}
END_TEST

START_TEST(test_interface_env_var_passthrough) {
	request_rec *r = oidc_test_request_get();

	apr_table_unset(r->subprocess_env, OIDC_CURL_INTERFACE_ENV_VAR);
	ck_assert_ptr_null(oidc_http_interface(r));

	apr_table_set(r->subprocess_env, OIDC_CURL_INTERFACE_ENV_VAR, "eth0");
	const char *iface = oidc_http_interface(r);
	ck_assert_ptr_nonnull(iface);
	ck_assert_msg(_oidc_strcmp(iface, "eth0") == 0, "interface returned from env var");

	apr_table_unset(r->subprocess_env, OIDC_CURL_INTERFACE_ENV_VAR);
}
END_TEST

/*
 * End-to-end tests driving oidc_http_get/post_form/post_json against a
 * loopback HTTP server fixture. These cover the curl handoff that the
 * unit tests above cannot reach: request line assembly, header passing,
 * body encoding, response decoding, response_code/headers capture,
 * and retry-on-connect-refused.
 */

static oidc_http_timeout_t e2e_timeout(void) {
	oidc_http_timeout_t t = {
	    .request_timeout = 10,
	    .connect_timeout = 5,
	    .retries = 1,
	    .retry_interval = 10,
	};
	return t;
}

static oidc_http_outgoing_proxy_t e2e_no_proxy(void) {
	oidc_http_outgoing_proxy_t p = {NULL, NULL, OIDC_CONFIG_POS_INT_UNSET};
	return p;
}

START_TEST(test_e2e_get_happy_path) {
	request_rec *r = oidc_test_request_get();
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"ok\":true}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *url = oidc_test_http_server_url(srv, r->pool);
	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_get(r, url, NULL, NULL, NULL, NULL, FALSE, &response, &status, NULL, &to, &pr, NULL,
				      NULL, NULL, NULL);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(ok == TRUE, "curl GET succeeds");
	ck_assert_msg(status == 200, "status decoded from response");
	ck_assert_ptr_nonnull(response);
	ck_assert_msg(_oidc_strcmp(response, "{\"ok\":true}") == 0, "response body returned verbatim");
	ck_assert_ptr_nonnull(cap);
	ck_assert_msg(_oidc_strcmp(cap->method, "GET") == 0, "server saw GET");
	ck_assert_msg(_oidc_strcmp(cap->path, "/") == 0, "server saw root path");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_post_form) {
	request_rec *r = oidc_test_request_get();
	oidc_test_http_response_t resp = {.status_code = 200, .body = ""};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *url = oidc_test_http_server_url(srv, r->pool);
	apr_table_t *params = apr_table_make(r->pool, 3);
	apr_table_set(params, "grant_type", "authorization_code");
	apr_table_set(params, "code", "abc 123");

	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_post_form(r, url, params, NULL, NULL, NULL, FALSE, &response, &status, NULL, &to, &pr,
					    NULL, NULL, NULL, NULL);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(ok == TRUE, "POST form succeeds");
	ck_assert_ptr_nonnull(cap);
	ck_assert_msg(_oidc_strcmp(cap->method, "POST") == 0, "server saw POST");
	const char *ct = apr_table_get(cap->headers, "Content-Type");
	ck_assert_ptr_nonnull(ct);
	ck_assert_msg(_oidc_strcmp(ct, OIDC_HTTP_CONTENT_TYPE_FORM_ENCODED) == 0, "form content-type sent");
	ck_assert_ptr_nonnull(cap->body);
	ck_assert_msg(_oidc_strstr(cap->body, "grant_type=authorization_code") != NULL,
		      "grant_type param present in body");
	ck_assert_msg(_oidc_strstr(cap->body, "code=abc%20123") != NULL, "code param url-encoded");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_post_json) {
	request_rec *r = oidc_test_request_get();
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"echo\":1}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *url = oidc_test_http_server_url(srv, r->pool);
	json_t *j = json_pack("{s:s,s:i}", "key", "value", "n", 42);
	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_post_json(r, url, j, NULL, NULL, NULL, FALSE, &response, &status, NULL, &to, &pr,
					    NULL, NULL, NULL, NULL);
	json_decref(j);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(ok == TRUE, "POST json succeeds");
	const char *ct = apr_table_get(cap->headers, "Content-Type");
	ck_assert_ptr_nonnull(ct);
	ck_assert_msg(_oidc_strcmp(ct, OIDC_HTTP_CONTENT_TYPE_JSON) == 0, "json content-type sent");
	ck_assert_ptr_nonnull(cap->body);
	ck_assert_msg(_oidc_strstr(cap->body, "\"key\"") != NULL && _oidc_strstr(cap->body, "\"value\"") != NULL,
		      "json body contains key/value");
	ck_assert_msg(_oidc_strstr(cap->body, "42") != NULL, "json body contains integer field");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_bearer_authorization) {
	request_rec *r = oidc_test_request_get();
	oidc_test_http_response_t resp = {.status_code = 200, .body = ""};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *url = oidc_test_http_server_url(srv, r->pool);
	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_get(r, url, NULL, NULL, "TOK-BEARER", NULL, FALSE, &response, &status, NULL, &to, &pr,
				      NULL, NULL, NULL, NULL);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(ok == TRUE, "bearer GET succeeds");
	const char *auth = apr_table_get(cap->headers, OIDC_HTTP_HDR_AUTHORIZATION);
	ck_assert_ptr_nonnull(auth);
	ck_assert_msg(_oidc_strcmp(auth, "Bearer TOK-BEARER") == 0, "Bearer scheme sent");
	ck_assert_table_unset(cap->headers, OIDC_HTTP_HDR_DPOP);

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_dpop_authorization) {
	request_rec *r = oidc_test_request_get();
	oidc_test_http_response_t resp = {.status_code = 200, .body = ""};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *url = oidc_test_http_server_url(srv, r->pool);
	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_get(r, url, NULL, NULL, "TOK-DPOP", "PROOF.JWT.HERE", FALSE, &response, &status, NULL,
				      &to, &pr, NULL, NULL, NULL, NULL);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(ok == TRUE, "dpop GET succeeds");
	const char *auth = apr_table_get(cap->headers, OIDC_HTTP_HDR_AUTHORIZATION);
	ck_assert_ptr_nonnull(auth);
	ck_assert_msg(_oidc_strcmp(auth, "DPoP TOK-DPOP") == 0, "DPoP scheme replaces Bearer");
	const char *dpop = apr_table_get(cap->headers, OIDC_HTTP_HDR_DPOP);
	ck_assert_ptr_nonnull(dpop);
	ck_assert_msg(_oidc_strcmp(dpop, "PROOF.JWT.HERE") == 0, "DPoP header carries proof");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_response_hdrs_and_status) {
	request_rec *r = oidc_test_request_get();
	apr_table_t *extra = apr_table_make(r->pool, 2);
	apr_table_set(extra, OIDC_HTTP_HDR_DPOP_NONCE, "nonce-123");
	oidc_test_http_response_t resp = {.status_code = 401,
					  .content_type = "application/json",
					  .body = "{\"error\":\"use_dpop_nonce\"}",
					  .extra_headers = extra};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *url = oidc_test_http_server_url(srv, r->pool);
	apr_hash_t *hdrs = apr_hash_make(r->pool);
	apr_hash_set(hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING, "");
	apr_hash_set(hdrs, OIDC_HTTP_HDR_CONTENT_TYPE, APR_HASH_KEY_STRING, "");

	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_get(r, url, NULL, NULL, NULL, NULL, FALSE, &response, &status, hdrs, &to, &pr, NULL,
				      NULL, NULL, NULL);

	(void)oidc_test_http_server_wait(srv);
	/* the call itself succeeds at the transport layer even for 401 */
	ck_assert_msg(ok == TRUE, "non-2xx still returns TRUE; the status is exposed via response_code");
	ck_assert_msg(status == 401, "401 code captured");
	const char *nonce = apr_hash_get(hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING);
	ck_assert_ptr_nonnull(nonce);
	ck_assert_msg(_oidc_strcmp(nonce, "nonce-123") == 0, "DPoP-Nonce captured from response");
	const char *ct = apr_hash_get(hdrs, OIDC_HTTP_HDR_CONTENT_TYPE, APR_HASH_KEY_STRING);
	ck_assert_ptr_nonnull(ct);
	ck_assert_msg(_oidc_strstr(ct, "application/json") != NULL, "Content-Type captured");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_basic_auth) {
	request_rec *r = oidc_test_request_get();
	oidc_test_http_response_t resp = {.status_code = 200, .body = ""};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *url = oidc_test_http_server_url(srv, r->pool);
	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_get(r, url, NULL, "alice:s3cret", NULL, NULL, FALSE, &response, &status, NULL, &to,
				      &pr, NULL, NULL, NULL, NULL);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(ok == TRUE, "basic-auth GET succeeds");
	const char *auth = apr_table_get(cap->headers, OIDC_HTTP_HDR_AUTHORIZATION);
	ck_assert_ptr_nonnull(auth);
	/* base64("alice:s3cret") = YWxpY2U6czNjcmV0 */
	ck_assert_msg(_oidc_strstr(auth, "Basic ") != NULL, "Basic scheme");
	ck_assert_msg(_oidc_strstr(auth, "YWxpY2U6czNjcmV0") != NULL, "credentials base64-encoded");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_pass_cookies) {
	request_rec *r = oidc_test_request_get();
	oidc_test_http_response_t resp = {.status_code = 200, .body = ""};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	/* seed the incoming request with two cookies; only one is in pass_cookies */
	apr_table_set(r->headers_in, "Cookie", "keep=yes; drop=no");
	apr_array_header_t *pass = apr_array_make(r->pool, 1, sizeof(const char *));
	APR_ARRAY_PUSH(pass, const char *) = "keep";

	const char *url = oidc_test_http_server_url(srv, r->pool);
	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_get(r, url, NULL, NULL, NULL, NULL, FALSE, &response, &status, NULL, &to, &pr, pass,
				      NULL, NULL, NULL);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(ok == TRUE, "GET with pass_cookies succeeds");
	const char *cookie = apr_table_get(cap->headers, "Cookie");
	ck_assert_ptr_nonnull(cookie);
	ck_assert_msg(_oidc_strstr(cookie, "keep=yes") != NULL, "selected cookie forwarded");
	ck_assert_msg(_oidc_strstr(cookie, "drop=no") == NULL, "unselected cookie filtered out");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_get_with_query_params) {
	request_rec *r = oidc_test_request_get();
	oidc_test_http_response_t resp = {.status_code = 200, .body = ""};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	apr_table_t *params = apr_table_make(r->pool, 2);
	apr_table_set(params, "resource", "acct:bob@example.com");
	apr_table_set(params, "rel", "http://openid.net/specs/connect/1.0/issuer");

	const char *url = oidc_test_http_server_url(srv, r->pool);
	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();
	apr_byte_t ok = oidc_http_get(r, url, params, NULL, NULL, NULL, FALSE, &response, &status, NULL, &to, &pr, NULL,
				      NULL, NULL, NULL);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(ok == TRUE, "GET with params succeeds");
	ck_assert_ptr_nonnull(cap->path);
	ck_assert_msg(_oidc_strstr(cap->path, "resource=acct%3Abob%40example.com") != NULL,
		      "first query parameter url-encoded");
	ck_assert_msg(_oidc_strstr(cap->path, "rel=") != NULL, "second query parameter present");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_e2e_retry_on_connect_refused) {
	request_rec *r = oidc_test_request_get();

	/* free port with nothing listening -> connect() returns ECONNREFUSED */
	int port = oidc_test_http_free_port(r->pool);
	ck_assert_msg(port > 0, "free port acquired");

	const char *url = apr_psprintf(r->pool, "http://127.0.0.1:%d", port);
	char *response = NULL;
	long status = 0;
	oidc_http_timeout_t to = {.request_timeout = 2, .connect_timeout = 2, .retries = 2, .retry_interval = 5};
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();

	apr_time_t before = apr_time_now();
	apr_byte_t ok = oidc_http_get(r, url, NULL, NULL, NULL, NULL, FALSE, &response, &status, NULL, &to, &pr, NULL,
				      NULL, NULL, NULL);
	apr_time_t after = apr_time_now();

	ck_assert_msg(ok == FALSE, "connect-refused after retries returns FALSE");
	/* with retries=2, retry_interval=5ms, we expect at least two retry_interval sleeps */
	apr_time_t elapsed_ms = (after - before) / 1000;
	ck_assert_msg(elapsed_ms >= 5, "at least one retry back-off elapsed (got %ldms)", (long)elapsed_ms);
}
END_TEST

START_TEST(test_e2e_scripted_sequence) {
	request_rec *r = oidc_test_request_get();

	/* two responses served in order from a single server (a 401 then a 200,
	 * like an error-then-retry exchange) — exercises the multi-response mock
	 * server and the per-request capture */
	oidc_test_http_response_t responses[2] = {
	    {.status_code = 401, .content_type = "application/json", .body = "{\"error\":\"invalid_token\"}"},
	    {.status_code = 200, .content_type = "application/json", .body = "{\"ok\":true}"},
	};
	oidc_test_http_server_t *srv = oidc_test_http_server_start_seq(r->pool, responses, 2);
	ck_assert_ptr_nonnull(srv);
	const char *url = oidc_test_http_server_url(srv, r->pool);
	oidc_http_timeout_t to = e2e_timeout();
	oidc_http_outgoing_proxy_t pr = e2e_no_proxy();

	/* first call hits responses[0] => 401 */
	char *body1 = NULL;
	long status1 = 0;
	oidc_http_get(r, url, NULL, NULL, NULL, NULL, FALSE, &body1, &status1, NULL, &to, &pr, NULL, NULL, NULL, NULL);
	ck_assert_int_eq(status1, 401);

	/* second call hits responses[1] => 200 with its own body */
	char *body2 = NULL;
	long status2 = 0;
	apr_byte_t ok2 = oidc_http_get(r, url, NULL, NULL, NULL, NULL, FALSE, &body2, &status2, NULL, &to, &pr, NULL,
				       NULL, NULL, NULL);
	ck_assert_int_eq(ok2, TRUE);
	ck_assert_int_eq(status2, 200);
	ck_assert_str_eq(body2, "{\"ok\":true}");

	/* both requests were handled and captured in order */
	ck_assert_int_eq(oidc_test_http_server_request_count(srv), 2);
	const oidc_test_http_captured_t *c0 = oidc_test_http_server_captured(srv, 0);
	const oidc_test_http_captured_t *c1 = oidc_test_http_server_captured(srv, 1);
	ck_assert_ptr_nonnull(c0);
	ck_assert_ptr_nonnull(c1);
	ck_assert_str_eq(c0->method, "GET");
	ck_assert_str_eq(c1->method, "GET");
	/* a third index was never requested */
	ck_assert_ptr_null(oidc_test_http_server_captured(srv, 2));

	oidc_test_http_server_stop(srv);
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

	TCase *curl_helpers = tcase_create("curl_helpers");
	tcase_add_checked_fixture(curl_helpers, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(curl_helpers, test_response_data_accumulates);
	tcase_add_test(curl_helpers, test_response_data_rejects_oversize);
	tcase_add_test(curl_helpers, test_response_header_captures_requested_only);
	tcase_add_test(curl_helpers, test_response_header_no_wanted_headers);
	tcase_add_test(curl_helpers, test_build_header_list_bearer_and_content_type);
	tcase_add_test(curl_helpers, test_build_header_list_dpop_switches_scheme_and_adds_header);
	tcase_add_test(curl_helpers, test_build_header_list_no_inputs);
	tcase_add_test(curl_helpers, test_user_agent_defaults_and_override);
	tcase_add_test(curl_helpers, test_interface_env_var_passthrough);

	TCase *e2e = tcase_create("e2e_curl");
	tcase_add_checked_fixture(e2e, oidc_test_setup, oidc_test_teardown);
	/* default tcase timeout is too tight for the retry test's back-off + connect timeouts */
	tcase_set_timeout(e2e, 30);
	tcase_add_test(e2e, test_e2e_get_happy_path);
	tcase_add_test(e2e, test_e2e_post_form);
	tcase_add_test(e2e, test_e2e_post_json);
	tcase_add_test(e2e, test_e2e_bearer_authorization);
	tcase_add_test(e2e, test_e2e_dpop_authorization);
	tcase_add_test(e2e, test_e2e_response_hdrs_and_status);
	tcase_add_test(e2e, test_e2e_basic_auth);
	tcase_add_test(e2e, test_e2e_pass_cookies);
	tcase_add_test(e2e, test_e2e_get_with_query_params);
	tcase_add_test(e2e, test_e2e_retry_on_connect_refused);
	tcase_add_test(e2e, test_e2e_scripted_sequence);

	Suite *s = suite_create("http");
	suite_add_tcase(s, accept);
	suite_add_tcase(s, curl_helpers);
	suite_add_tcase(s, e2e);

	return oidc_test_suite_run(s);
}
