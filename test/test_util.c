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
#include "mod_auth_openidc.h"
#include "util/util.h"

// base64

START_TEST(test_util_base64url_encode) {
	int len = -1;
	char *dst = NULL;
	const char *src = NULL;

	len = oidc_util_base64url_encode(oidc_test_request_get(), &dst, NULL, 0, 1);
	ck_assert_ptr_null(dst);
	ck_assert_int_eq(len, -1);

	src = "test";
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

	rv = oidc_util_base64_decode(oidc_test_pool_get(), NULL, &output, &len);
	ck_assert_ptr_nonnull(rv);
	ck_assert_ptr_null(output);
	ck_assert_int_eq(len, -1);

	rv = oidc_util_base64_decode(oidc_test_pool_get(), "\\", &output, &len);
	ck_assert_ptr_nonnull(rv);
	ck_assert_int_eq(len, 0);

	rv = oidc_util_base64_decode(oidc_test_pool_get(), input, &output, &len);
	ck_assert_msg(rv == NULL, "return value is not NULL");
	ck_assert_int_eq(len, 4);
	ck_assert_str_eq(output, "test");
}
END_TEST

START_TEST(test_util_base64url_decode) {
	int len = -1;
	char *src = "c3ViamVjdHM_X2Q9MQ-Tl5u,";
	char *dst = NULL;
	len = oidc_util_base64url_decode(oidc_test_pool_get(), &dst, src);
	ck_assert_msg(dst != NULL, "dst value is NULL");
	ck_assert_int_eq(len, 17);
	// TODO: need binary compare
	// ck_assert_str_eq(dst, "subjects?_d=1���");
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

START_TEST(test_util_expr_substitute) {
	apr_byte_t rc = FALSE;
	apr_pool_t *pool = oidc_test_pool_get();
	const char *input = "match 292 numbers";
	const char *regexp = "^.* ([0-9]+).*$";
	const char *replace = "$1";
	char *output = NULL;
	char *error_str = NULL;

	rc = oidc_util_regexp_substitute(pool, input, "$$$$$**@@", replace, &output, &error_str);
	ck_assert_msg(rc == FALSE, "oidc_util_regexp_substitute returned TRUE");
	ck_assert_ptr_nonnull(error_str);

	error_str = NULL;
	rc = oidc_util_regexp_substitute(
	    pool,
	    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	    regexp, replace, &output, &error_str);
	ck_assert_msg(rc == FALSE, "oidc_util_regexp_substitute returned TRUE");
	ck_assert_ptr_nonnull(error_str);

	error_str = NULL;
	rc = oidc_util_regexp_substitute(pool, "", "", "", &output, &error_str);
	ck_assert_msg(rc == FALSE, "oidc_util_regexp_substitute returned TRUE");
	ck_assert_ptr_nonnull(error_str);

	error_str = NULL;
	rc = oidc_util_regexp_substitute(pool, input, regexp, replace, &output, &error_str);
	ck_assert_msg(rc == TRUE, "oidc_util_regexp_substitute returned FALSE");
	ck_assert_ptr_null(error_str);
	ck_assert_str_eq(output, "292");
}
END_TEST

START_TEST(test_util_expr_first_match) {
	apr_byte_t rc = FALSE;
	apr_pool_t *pool = oidc_test_pool_get();
	const char *input = "12345 hello";
	const char *regexp = "^([0-9]+)\\s+([a-z]+)$";
	;
	char *output = NULL;
	char *error_str = NULL;

	rc = oidc_util_regexp_first_match(pool, input, "$$$$$**@@", &output, &error_str);
	ck_assert_msg(rc == FALSE, "oidc_util_regexp_first_match returned TRUE");
	ck_assert_ptr_nonnull(error_str);

	error_str = NULL;
	rc = oidc_util_regexp_first_match(pool, "abc", regexp, &output, &error_str);
	ck_assert_msg(rc == FALSE, "oidc_util_regexp_first_match returned TRUE");
	ck_assert_ptr_nonnull(error_str);

	error_str = NULL;
	rc = oidc_util_regexp_first_match(pool, "abc abc", regexp, &output, &error_str);
	ck_assert_msg(rc == FALSE, "oidc_util_regexp_first_match returned TRUE");
	ck_assert_ptr_nonnull(error_str);

	error_str = NULL;
	rc = oidc_util_regexp_first_match(pool, input, regexp, &output, &error_str);
	ck_assert_msg(rc == TRUE, "oidc_util_regexp_first_match returned FALSE");
	ck_assert_ptr_null(error_str);
	ck_assert_str_eq(output, "12345");
}
END_TEST

START_TEST(test_util_expr_parse) {
	char *rv = NULL;
	cmd_parms *cmd = oidc_test_cmd_get("");
	oidc_apr_expr_t *expr = NULL;

	// NB: stub only

	expr = NULL;
	rv = oidc_util_apr_expr_parse(cmd, NULL, &expr, FALSE);
	ck_assert_ptr_null(rv);
	ck_assert_ptr_null(expr);

	//	expr = NULL;
	//	rv = oidc_util_apr_expr_parse(cmd, "% ||| true)", &expr, FALSE);
	//	ck_assert_ptr_nonnull(rv);
	//	ck_assert_ptr_null(expr);

	expr = NULL;
	rv = oidc_util_apr_expr_parse(cmd, "", &expr, TRUE);
	ck_assert_ptr_null(rv);
	ck_assert_ptr_nonnull(expr);
}
END_TEST

START_TEST(test_util_expr_exec) {
	const char *result = NULL;
	char *rv = NULL;
	cmd_parms *cmd = oidc_test_cmd_get("");
	request_rec *r = oidc_test_request_get();
	oidc_apr_expr_t *expr = NULL;

	// NB: stub only
	expr = NULL;
	rv = oidc_util_apr_expr_parse(cmd, "true", &expr, FALSE);
	ck_assert_ptr_null(rv);
	ck_assert_ptr_nonnull(expr);

	// NB: stub only
	result = oidc_util_apr_expr_exec(r, expr, TRUE);
	ck_assert_ptr_nonnull(result);
#if HAVE_APACHE_24
	ck_assert_str_eq(result, "stub.c");
#else
	ck_assert_str_eq(result, "true");
#endif
	// NB: stub only
	result = oidc_util_apr_expr_exec(r, expr, FALSE);
#if HAVE_APACHE_24
	ck_assert_ptr_null(result);
#else
	ck_assert_str_eq(result, "true");
#endif

	// NB: stub only
	expr = NULL;
	rv = oidc_util_apr_expr_parse(cmd, "#", &expr, FALSE);
#if HAVE_APACHE_24
	ck_assert_ptr_nonnull(rv);
	ck_assert_ptr_null(expr);
#else
	ck_assert_ptr_null(rv);
	ck_assert_ptr_nonnull(expr);
#endif
}
END_TEST

START_TEST(test_util_file) {
	request_rec *r = oidc_test_request_get();
	const char *dir = NULL;
	char *path = NULL;
	apr_byte_t rc = FALSE;
	char *text = NULL, *read = NULL;

	apr_temp_dir_get(&dir, r->pool);
	path = apr_psprintf(r->pool, "%s/test.tmp", dir);

	oidc_util_random_str_gen(r, &text, 32);
	// write directory instead of file
	rc = oidc_util_file_write(r, dir, text);
	ck_assert_msg(rc == FALSE, "oidc_util_file_write returned TRUE");

	rc = oidc_util_file_write(r, path, text);
	ck_assert_msg(rc == TRUE, "oidc_util_file_write returned FALSE");

	// read no- existing file
	rc = oidc_util_file_read(r, apr_psprintf(r->pool, "%s/bogus.tmp", dir), r->pool, &read);
	ck_assert_msg(rc == FALSE, "oidc_util_file_read returned TRUE");

	// read directory instead of file
	rc = oidc_util_file_read(r, dir, r->pool, &read);
	ck_assert_msg(rc == FALSE, "oidc_util_file_read returned TRUE");

	rc = oidc_util_file_read(r, path, r->pool, &read);
	ck_assert_msg(rc == TRUE, "oidc_util_file_read returned FALSE");
	ck_assert_ptr_nonnull(read);
	ck_assert_str_eq(read, text);
}
END_TEST

START_TEST(test_util_html_escape) {
	apr_pool_t *pool = oidc_test_pool_get();

	ck_assert_str_eq(oidc_util_html_escape(pool, NULL), "");
	ck_assert_str_eq(oidc_util_html_escape(pool, ""), "");
	ck_assert_str_eq(oidc_util_html_escape(pool, "<script>alert('This is an XSS attack');</script>"),
			 "&lt;script&gt;alert(&apos;This is an XSS attack&apos;);&lt;/script&gt;");

	// TODO: which spec/function is actually followed here?
	ck_assert_ptr_eq(oidc_util_html_javascript_escape(pool, NULL), NULL);
	ck_assert_str_eq(oidc_util_html_javascript_escape(pool, "@*_+-./"), "@*_+-.\\/");
}
END_TEST

START_TEST(test_util_html_content) {
	int rv = -1;
	request_rec *r = oidc_test_request_get();

	r->user = NULL;
	rv = oidc_util_html_content_prep(r, "test_util_html_content", "test title", "test head", "onload", "test body");
	ck_assert_msg(rv == OK, "oidc_util_html_content_prep did not return OK: %d", rv);
	ck_assert_str_eq(r->user, "");
	ck_assert_str_eq(oidc_request_state_get(r, "title"), "test title");

	r->user = NULL;
	rv = oidc_util_html_content_send(r);
	ck_assert_msg(rv == OK, "oidc_util_html_content_send did not return OK: %d", rv);
	ck_assert_str_eq(r->user, "");

	r->user = NULL;
	rv = oidc_util_html_send(r, "test title", "test head", "onload", "test body", OK);
	ck_assert_msg(rv == OK, "oidc_util_html_send did not return OK: %d", rv);
	ck_assert_str_eq(r->user, "");

	r->user = NULL;
	rv = oidc_util_html_send(r, "test title", "test head", "onload", "test body", 201);
	ck_assert_msg(rv == 201, "oidc_util_html_send did not return 201: %d", rv);
	ck_assert_ptr_null(r->user);

	rv = oidc_util_html_send_error(r, "my error", "my error description", 404);
	ck_assert_msg(rv == 404, "oidc_util_html_send_error did not return 404: %d", rv);
	ck_assert_str_eq(apr_table_get(r->subprocess_env, "OIDC_ERROR"), "my error");
	ck_assert_str_eq(apr_table_get(r->subprocess_env, "OIDC_ERROR_DESC"), "my error description");
}
END_TEST

START_TEST(test_util_html_template) {
	int rv = -1;
	char *template_contents = NULL;
	request_rec *r = oidc_test_request_get();
	char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	char *fname = apr_psprintf(r->pool, "%s/%s", dir, "post_preserve.template");

	rv = oidc_util_html_send_in_template(r, fname, &template_contents, "arg1", OIDC_POST_PRESERVE_ESCAPE_NONE,
					     "arg2", OIDC_POST_PRESERVE_ESCAPE_NONE);
	ck_assert_msg(rv == OK, "oidc_util_html_send_in_template did not return OK: %d", rv);
	ck_assert_int_eq(_oidc_strlen(template_contents), 489);
	ck_assert_int_eq(_oidc_strncmp(template_contents, "<!DOCTYPE HTML PUBLIC", 10), 0);
	ck_assert_str_eq(oidc_request_state_get(r, "data_len"), "493");
	ck_assert_ptr_nonnull(_oidc_strstr(oidc_request_state_get(r, "data"), "window.location='arg2"));
	ck_assert_str_eq(oidc_request_state_get(r, "content_type"), "text/html");
}
END_TEST

START_TEST(test_util_jq) {
	request_rec *r = oidc_test_request_get();
#ifdef USE_LIBJQ
	ck_assert_str_eq(oidc_util_jq_filter(r, NULL, "."), "{}");
	ck_assert_str_eq(oidc_util_jq_filter(r, "{ \"jan\": \"jan\", \"piet\": \"piet\" }", NULL),
			 "{ \"jan\": \"jan\", \"piet\": \"piet\" }");
	ck_assert_str_eq(oidc_util_jq_filter(r, "{ \"jan\": \"jan\", \"piet\": \"piet\" }", "bogus"),
			 "{ \"jan\": \"jan\", \"piet\": \"piet\" }");
	ck_assert_str_eq(oidc_util_jq_filter(r, "{ \"jan\": \"jan\", \"piet\": \"piet\" }", ".jan"), "\"jan\"");
	ck_assert_str_eq(oidc_util_jq_filter(r, "{ \"jan\": \"jan\", \"piet\": \"piet\" }", ".jan"), "\"jan\"");
#else
	ck_assert_str_eq(oidc_util_jq_filter(r, "{ \"jan\": \"jan\", \"piet\": \"piet\" }", ".jan"),
			 "{ \"jan\": \"jan\", \"piet\": \"piet\" }");
#endif
}
END_TEST

START_TEST(test_util_json) {
	request_rec *r = oidc_test_request_get();
	apr_byte_t rv = FALSE;
	json_t *json = NULL;
	json_t *src = NULL;
	json_t *dst = NULL;
	json_error_t json_error;
	apr_pool_t *pool = oidc_test_pool_get();
	apr_array_header_t *arr = NULL;
	int v = 0;

	ck_assert_msg(oidc_util_json_decode_and_check_error(r, NULL, &json) == FALSE,
		      "result for NULL is not FALSE: %d", rv);
	json_decref(json);
	ck_assert_msg(oidc_util_json_decode_and_check_error(r, "{}", &json) == TRUE, "result for {} is not FALSE: %d",
		      rv);
	json_decref(json);
	ck_assert_msg(oidc_util_json_decode_and_check_error(r, "[ 1, 2 ]", &json) == FALSE,
		      "result for array object is not TRUE: %d", rv);
	json_decref(json);
	ck_assert_msg(oidc_util_json_decode_and_check_error(r, "{\"error\":\"yes\"}", &json) == FALSE,
		      "result for error object is not FALSE: %d", rv);
	json_decref(json);

	json = json_loads("[ \"hi\", 2 ]", 0, &json_error);
	ck_assert_ptr_nonnull(json);
	ck_assert_msg(oidc_util_json_array_has_value(r, json, "ho") == FALSE, "result for \"ho\" is not FALSE");
	ck_assert_msg(oidc_util_json_array_has_value(r, json, "hi") == TRUE, "result for \"hi\" is not TRUE");
	json_decref(json);

	json = json_loads("{ \"myarr\": [ \"hi\", \"ho\" ] }", 0, &json_error);
	ck_assert_ptr_nonnull(json);
	ck_assert_msg(oidc_util_json_object_get_string_array(pool, json, "my", &arr, NULL) == TRUE,
		      "result is not TRUE");
	ck_assert_ptr_null(arr);
	ck_assert_msg(oidc_util_json_object_get_string_array(pool, json, "myarr", &arr, NULL) == TRUE,
		      "result is not TRUE");
	ck_assert_ptr_nonnull(arr);
	ck_assert_msg(arr->nelts == 2, "array size is not 2");
	json_decref(json);

	json = json_loads("{ \"myint\": 1, \"mybool\": true }", 0, &json_error);
	ck_assert_ptr_nonnull(json);
	ck_assert_msg(oidc_util_json_object_get_int(json, "my", &v, 0) == FALSE, "result is not FALSE");
	ck_assert_int_eq(v, 0);
	ck_assert_msg(oidc_util_json_object_get_int(json, "myint", &v, 0) == TRUE, "result is not TRUE");
	ck_assert_int_eq(v, 1);
	ck_assert_msg(oidc_util_json_object_get_bool(json, "my", &v, 0) == FALSE, "result is not FALSE");
	ck_assert_int_eq(v, 0);
	ck_assert_msg(oidc_util_json_object_get_bool(json, "mybool", &v, 0) == TRUE, "result is not TRUE");
	ck_assert_int_eq(v, 1);
	json_decref(json);

	src = json_loads("{ \"myint1\": 1, \"mybool1\": false }", 0, &json_error);
	ck_assert_ptr_nonnull(src);
	dst = json_loads("{ \"myint2\": 2, \"mybool2\": true }", 0, &json_error);
	ck_assert_ptr_nonnull(dst);
	ck_assert_msg(oidc_util_json_merge(r, src, dst) == TRUE, "result is not TRUE");
	ck_assert_ptr_nonnull(src);
	ck_assert_ptr_nonnull(dst);
	ck_assert_msg(oidc_util_json_object_get_bool(dst, "mybool2", &v, 0) == TRUE, "result is not TRUE");
	ck_assert_int_eq(v, 1);
	ck_assert_msg(oidc_util_json_object_get_bool(dst, "mybool1", &v, 1) == TRUE, "result is not TRUE");
	ck_assert_int_eq(v, 0);
	json_decref(src);
	json_decref(dst);
}
END_TEST

START_TEST(test_util_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_crypto_passphrase_t passphrase = {"secret1", NULL};
	const char *str = "{ \"key\": \"value\" }";
	char *cser = NULL;
	char *payload = NULL;

	//	const char *empty = "{}";
	//	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, empty, &cser) == TRUE, "result is not TRUE");
	//	ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE, "result is not TRUE");
	//	ck_assert_str_eq(payload, empty);

	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, str, &cser) == TRUE, "result is not TRUE");
	ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE, "result is not TRUE");
	ck_assert_str_eq(payload, str);

	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_STRIP_HDR", "true");
	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, str, &cser) == TRUE, "result is not TRUE");
	ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE, "result is not TRUE");
	ck_assert_str_eq(payload, str);

	passphrase.secret1 = NULL;
	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, str, &cser) == FALSE, "result is not FALSE");
}
END_TEST

START_TEST(test_util_key) {
	request_rec *r = oidc_test_request_get();
	apr_pool_t *pool = oidc_test_pool_get();
	apr_hash_t *hash = NULL;
	apr_hash_t *hash2 = NULL;
	apr_hash_t *hash3 = NULL;
	oidc_jwk_t *jwk = NULL;
	oidc_jwk_t *jwk2 = NULL;
	oidc_jwk_t *jwk3 = NULL;
	apr_array_header_t *arr = NULL;
	apr_array_header_t *arr2 = NULL;

	// TODO: TRUE really?
	ck_assert_msg(oidc_util_key_symmetric_create(r, NULL, 0, NULL, TRUE, &jwk) == TRUE, "result is not TRUE");
	ck_assert_ptr_null(jwk);

	ck_assert_msg(oidc_util_key_symmetric_create(r, "mysecret", 0, "SHA100", TRUE, &jwk) == FALSE,
		      "result is not FALSE");
	ck_assert_ptr_null(jwk);

	ck_assert_msg(oidc_util_key_symmetric_create(r, "mysecret", 0, "SHA256", FALSE, &jwk) == TRUE,
		      "result is not TRUE");
	ck_assert_ptr_nonnull(jwk);
	ck_assert_ptr_null(jwk->kid);
	oidc_jwk_destroy(jwk);

	ck_assert_msg(oidc_util_key_symmetric_create(r, "mylongerthansixteensecret", 16, NULL, FALSE, &jwk) == TRUE,
		      "result is not TRUE");
	ck_assert_ptr_nonnull(jwk);
	ck_assert_ptr_null(jwk->kid);
	oidc_jwk_destroy(jwk);

	ck_assert_msg(oidc_util_key_symmetric_create(r, "mysecret", 0, "SHA256", TRUE, &jwk) == TRUE,
		      "result is not TRUE");
	ck_assert_ptr_nonnull(jwk);
	ck_assert_str_eq(jwk->kid, "6x3Xmnf4H99f-Y4R2pdjCZFnF5EUHrms85pklY5NCSc");

	hash = oidc_util_key_symmetric_merge(pool, NULL, NULL);
	ck_assert_ptr_nonnull(hash);
	ck_assert_int_eq(apr_hash_count(hash), 0);

	arr = apr_array_make(pool, 2, sizeof(const oidc_jwk_t *));
	ck_assert_msg(oidc_util_key_symmetric_create(r, "mysecret2", 0, NULL, TRUE, &jwk2) == TRUE,
		      "result is not TRUE");
	ck_assert_ptr_nonnull(jwk2);
	ck_assert_str_eq(jwk2->kid, "dxRmRMF-k0GMCu8QRtFY7aO0GyONucZRyVUf1mTRUd4");
	APR_ARRAY_PUSH(arr, const oidc_jwk_t *) = jwk2;

	hash = oidc_util_key_symmetric_merge(pool, arr, NULL);
	ck_assert_ptr_nonnull(hash);
	ck_assert_int_eq(apr_hash_count(hash), 1);

	hash = oidc_util_key_symmetric_merge(pool, arr, jwk);
	ck_assert_int_eq(apr_hash_count(hash), 2);
	ck_assert_ptr_eq(apr_hash_get(hash, "6x3Xmnf4H99f-Y4R2pdjCZFnF5EUHrms85pklY5NCSc", APR_HASH_KEY_STRING), jwk);
	ck_assert_ptr_eq(apr_hash_get(hash, "dxRmRMF-k0GMCu8QRtFY7aO0GyONucZRyVUf1mTRUd4", APR_HASH_KEY_STRING), jwk2);

	arr2 = apr_array_make(pool, 2, sizeof(const oidc_jwk_t *));
	ck_assert_msg(oidc_util_key_symmetric_create(r, "mysecret3", 0, "SHA256", TRUE, &jwk3) == TRUE,
		      "result is not TRUE");
	ck_assert_ptr_nonnull(jwk3);
	ck_assert_str_eq(jwk3->kid, "z4Fru6dQBC2pdKuIXuGmjyQpPVmZ-Y4ma54MlKMRU3o");
	APR_ARRAY_PUSH(arr2, const oidc_jwk_t *) = jwk3;
	hash2 = oidc_util_key_sets_merge(pool, hash, arr2);
	ck_assert_ptr_nonnull(hash2);
	ck_assert_int_eq(apr_hash_count(hash2), 3);
	ck_assert_ptr_eq(apr_hash_get(hash2, "6x3Xmnf4H99f-Y4R2pdjCZFnF5EUHrms85pklY5NCSc", APR_HASH_KEY_STRING), jwk);
	ck_assert_ptr_eq(apr_hash_get(hash2, "dxRmRMF-k0GMCu8QRtFY7aO0GyONucZRyVUf1mTRUd4", APR_HASH_KEY_STRING), jwk2);
	ck_assert_ptr_eq(apr_hash_get(hash2, "z4Fru6dQBC2pdKuIXuGmjyQpPVmZ-Y4ma54MlKMRU3o", APR_HASH_KEY_STRING), jwk3);

	hash3 = oidc_util_key_sets_hash_merge(pool, NULL, NULL);
	ck_assert_ptr_nonnull(hash3);
	ck_assert_int_eq(apr_hash_count(hash3), 0);

	hash3 = NULL;
	hash3 = oidc_util_key_sets_hash_merge(pool, hash, NULL);
	ck_assert_ptr_nonnull(hash3);
	ck_assert_ptr_eq(hash3, hash);
	ck_assert_int_eq(apr_hash_count(hash3), 2);

	hash3 = NULL;
	hash3 = oidc_util_key_sets_hash_merge(pool, hash, hash2);
	ck_assert_ptr_nonnull(hash3);
	ck_assert_int_eq(apr_hash_count(hash3), 3);

	ck_assert_ptr_eq(oidc_util_key_list_first(arr2, -1, NULL), jwk3);
	ck_assert_ptr_eq(oidc_util_key_list_first(arr2, CJOSE_JWK_KTY_OCT, "sig"), jwk3);
	ck_assert_ptr_null(oidc_util_key_list_first(arr2, CJOSE_JWK_KTY_RSA, "enc"));

	oidc_jwk_list_destroy_hash(hash3);
}
END_TEST

int main(void) {
	TCase *c = NULL;
	Suite *s = suite_create("util");

	c = tcase_create("base64");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(c, test_util_base64url_encode);
	tcase_add_test(c, test_util_base64_decode);
	tcase_add_test(c, test_util_base64url_decode);
	suite_add_tcase(s, c);

	c = tcase_create("appinfo");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_appinfo_set);
	suite_add_tcase(s, c);

	c = tcase_create("expr");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_expr_substitute);
	tcase_add_test(c, test_util_expr_first_match);
	tcase_add_test(c, test_util_expr_parse);
	tcase_add_test(c, test_util_expr_exec);
	suite_add_tcase(s, c);

	c = tcase_create("file");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_file);
	suite_add_tcase(s, c);

	c = tcase_create("html");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_html_escape);
	tcase_add_test(c, test_util_html_content);
	tcase_add_test(c, test_util_html_template);
	suite_add_tcase(s, c);

	c = tcase_create("jq");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_jq);
	suite_add_tcase(s, c);

	c = tcase_create("json");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_json);
	suite_add_tcase(s, c);

	c = tcase_create("jwt");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_jwt);
	suite_add_tcase(s, c);

	c = tcase_create("key");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_key);
	suite_add_tcase(s, c);

	return oidc_test_suite_run(s);
}
