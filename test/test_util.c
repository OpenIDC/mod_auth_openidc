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

#include "helper.h"
#include "util/util.h"

// base64

START_TEST(test_util_base64url_encode) {
	int len = -1;
	char *dst = NULL;
	const char *src = "test";
	len = oidc_util_base64url_encode(oidc_test_request_get(), &dst, src, _oidc_strlen(src), 1);
	ck_assert_msg(dst != NULL, "dst value is NULL");
	ck_assert_int_eq(len, 6);
	ck_assert_str_eq(dst, "dGVzdA");

	len = -1;
	dst = NULL;
	len = oidc_util_base64url_encode(oidc_test_request_get(), &dst, src, _oidc_strlen(src), 0);
	ck_assert_msg(dst != NULL, "dst value is NULL");
	ck_assert_int_eq(len, 9);
	ck_assert_str_eq(dst, "dGVzdA,,");
}
END_TEST

START_TEST(test_util_base64_decode) {
	char *rv = NULL;
	const char *input = "dGVzdA==";
	char *output = NULL;
	int len = -1;
	rv = oidc_util_base64_decode(oidc_test_pool_get(), input, &output, &len);
	ck_assert_msg(rv == NULL, "return value is not NULL");
	ck_assert_int_eq(len, 4);
	ck_assert_str_eq(output, "test");
}
END_TEST

START_TEST(test_util_base64url_decode) {
	int len = -1;
	char *src = "dGVzdA==";
	char *dst = NULL;
	len = oidc_util_base64url_decode(oidc_test_pool_get(), &dst, src);
	ck_assert_msg(dst != NULL, "dst value is NULL");
	ck_assert_int_eq(len, 4);
	ck_assert_str_eq(dst, "test");
}
END_TEST

START_TEST(test_util_appinfo_set) {
	apr_byte_t rc = FALSE;
	json_t *claims = NULL;
	request_rec *r = oidc_test_request_get();

	rc = oidc_util_json_decode_object(r,
					  "{"
					  "\"simple\":\"hans\","
					  "\"name\": \"GÜnther\","
					  "\"dagger\": \"D†gÿger\","
					  "\"anarr\" : [ false, \"hans\", \"piet\", true, {} ],"
					  "\"names\" : [ \"hans\", \"piet\" ],"
					  "\"abool\": true,"
					  "\"anint\": 5,"
					  "\"lint\": 111111111111111,"
					  "\"areal\": 1.5,"
					  "\"anobj\" : { \"hans\": \"piet\", \"abool\": false },"
					  "\"anull\": null"
					  "}",
					  &claims);
	ck_assert_int_eq(rc, TRUE);

	oidc_util_appinfo_set_all(r, NULL, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_simple"), "hans");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_name"), "G\u00DCnther");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_dagger"), "D\u2020gÿger");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_anarr"), "0,hans,piet,1");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_names"), "hans,piet");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_abool"), "1");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_anint"), "5");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_lint"), "111111111111111");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_areal"), "1.5");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_anobj"), "{\"hans\":\"piet\",\"abool\":false}");

	ck_assert_ptr_null(apr_table_get(r->headers_in, "OIDC_CLAIM_anull"));
	ck_assert_ptr_null(apr_table_get(r->subprocess_env, "OIDC_CLAIM_names"));

	oidc_util_appinfo_set_all(r, claims, "MYPREFIX_", "#", OIDC_APPINFO_PASS_HEADERS | OIDC_APPINFO_PASS_ENVVARS,
				  OIDC_APPINFO_ENCODING_NONE);
	ck_assert_str_eq(apr_table_get(r->headers_in, "MYPREFIX_simple"), "hans");
	ck_assert_str_eq(apr_table_get(r->headers_in, "MYPREFIX_name"), "G\u00DCnther");
	ck_assert_str_eq(apr_table_get(r->headers_in, "MYPREFIX_dagger"), "D\u2020gÿger");
	ck_assert_str_eq(apr_table_get(r->headers_in, "MYPREFIX_anarr"), "0#hans#piet#1");

	ck_assert_ptr_null(apr_table_get(r->subprocess_env, "OIDC_CLAIM_names"));
	ck_assert_str_eq(apr_table_get(r->subprocess_env, "MYPREFIX_anarr"), "0#hans#piet#1");

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS,
				  OIDC_APPINFO_ENCODING_BASE64URL);
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_simple"), "aGFucw");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_name"), "R8OcbnRoZXI");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_dagger"), "ROKAoGfDv2dlcg");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_anarr"), "MCxoYW5zLHBpZXQsMQ");

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS,
				  OIDC_APPINFO_ENCODING_LATIN1);
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_simple"), "hans");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_name"), "G\xDCnther");
	ck_assert_str_eq(apr_table_get(r->headers_in, "OIDC_CLAIM_dagger"), "D?g\xFFger");

	json_decref(claims);
}
END_TEST

int main(void) {
	TCase *core = tcase_create("base64");
	tcase_add_checked_fixture(core, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(core, test_util_base64url_encode);
	tcase_add_test(core, test_util_base64_decode);
	tcase_add_test(core, test_util_base64url_decode);

	tcase_add_test(core, test_util_appinfo_set);

	Suite *s = suite_create("util");
	suite_add_tcase(s, core);

	return oidc_test_suite_run(s);
}
