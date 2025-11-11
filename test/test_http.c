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

int main(void) {
	TCase *accept = tcase_create("accept");
	tcase_add_checked_fixture(accept, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(accept, test_http_accept);

	Suite *s = suite_create("http");
	suite_add_tcase(s, accept);

	return oidc_test_suite_run(s);
}
