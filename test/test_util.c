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

#include "check_util.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"
#include "util/pcre_subst.h"
#include "util/request_state.h"
#include "util/util.h"
#include "util/util_cfg.h"
#include <fcntl.h>   /* open()/close() for the EMFILE fd-exhaustion trick below */
#include <jansson.h> /* this test builds JSON fixtures with the backend API directly (no longer pulled in via jose.h) */
#include <signal.h>  /* SIGXFSZ for the RLIMIT_FSIZE trick below */
#include <sys/resource.h> /* getrlimit()/setrlimit(RLIMIT_NOFILE/RLIMIT_FSIZE) for the same tricks */
#include <unistd.h>

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

// base64

START_TEST(test_util_base64url_encode) {
	int len = -1;
	char *dst = NULL;
	const char *src = NULL;

	len = oidc_util_base64url_encode(oidc_test_request_get(), &dst, NULL, 0, 1);
	ck_assert_ptr_null(dst);
	ck_assert_int_eq(len, -1);

	src = "test";
	len = oidc_util_base64url_encode(oidc_test_request_get(), &dst, src, (int)_oidc_strlen(src), 1);
	ck_assert_msg(dst != NULL, "dst value is NULL");
	ck_assert_int_eq(len, 6);
	ck_assert_str_eq(dst, "dGVzdA");

	len = -1;
	dst = NULL;
	len = oidc_util_base64url_encode(oidc_test_request_get(), &dst, src, (int)_oidc_strlen(src), 0);
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
	ck_assert_mem_eq(dst, "subjects?_d=1\x0f\x93\x97\x9b", 17);
}
END_TEST

START_TEST(test_util_appinfo_set) {
	apr_byte_t rc = FALSE;
	oidc_json_t *claims = NULL;
	request_rec *r = oidc_test_request_get();

	rc = oidc_json_decode_object(r,
				     "{"
				     "\"simple\":\"hans\","
				     "\"name\": \"GÜnther\","
				     "\"dagger\": \"D†gÿger\","
				     "\"anarr\" : [ false, \"hans\", \"piet\", true, {} ],"
				     "\"names\" : [ \"hans\", \"piet\" ],"
				     "\"abool\": true,"
				     "\"anint\": 5,"
				     "\"lint\": 1111111111,"
				     "\"areal\": 1.5,"
				     "\"anobj\" : { \"hans\": \"piet\", \"abool\": false },"
				     "\"anull\": null"
				     "}",
				     &claims);
	ck_assert_int_eq(rc, TRUE);

	oidc_util_appinfo_set_all(r, NULL, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_simple", "hans");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_name", "G\u00DCnther");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_dagger", "D\u2020gÿger");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_anarr", "0,hans,piet,1");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_names", "hans,piet");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_abool", "1");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_anint", "5");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_lint", "1111111111");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_areal", "1.5");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_anobj", "{\"hans\":\"piet\",\"abool\":false}");

	ck_assert_table_unset(r->headers_in, "OIDC_CLAIM_anull");
	ck_assert_table_unset(r->subprocess_env, "OIDC_CLAIM_names");

	oidc_util_appinfo_set_all(r, claims, "MYPREFIX_", "#", OIDC_APPINFO_PASS_HEADERS | OIDC_APPINFO_PASS_ENVVARS,
				  OIDC_APPINFO_ENCODING_NONE);
	ck_assert_table_str(r->headers_in, "MYPREFIX_simple", "hans");
	ck_assert_table_str(r->headers_in, "MYPREFIX_name", "G\u00DCnther");
	ck_assert_table_str(r->headers_in, "MYPREFIX_dagger", "D\u2020gÿger");
	ck_assert_table_str(r->headers_in, "MYPREFIX_anarr", "0#hans#piet#1");

	ck_assert_table_unset(r->subprocess_env, "OIDC_CLAIM_names");
	ck_assert_table_str(r->subprocess_env, "MYPREFIX_anarr", "0#hans#piet#1");

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS,
				  OIDC_APPINFO_ENCODING_BASE64URL);
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_simple", "aGFucw");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_name", "R8OcbnRoZXI");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_dagger", "ROKAoGfDv2dlcg");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_anarr", "MCxoYW5zLHBpZXQsMQ");

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS,
				  OIDC_APPINFO_ENCODING_LATIN1);
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_simple", "hans");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_name", "G\xDCnther");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_dagger", "D?g\xFFger");

	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_util_appinfo_array_delimiter_escape) {
	apr_byte_t rc = FALSE;
	oidc_json_t *claims = NULL;
	request_rec *r = oidc_test_request_get();

	rc = oidc_json_decode_object(r,
				     "{"
				     "\"roles\" : [ \"a,b\", \"c\\\\d\", \"e\" ],"
				     "\"dns\" : [ \"CN=Admins,OU=Groups\", \"plain\" ]"
				     "}",
				     &claims);
	ck_assert_int_eq(rc, TRUE);

	/* a delimiter (or the backslash escape char) inside an element value is escaped so it cannot be
	 * mistaken for an element separator: "a,b" -> "a\,b", "c\d" -> "c\\d" */
	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_roles", "a\\,b,c\\\\d,e");
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_dns", "CN=Admins\\,OU=Groups,plain");

	/* a multi-character delimiter is matched and escaped as a unit (no delimiter present => unchanged) */
	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", "::", OIDC_APPINFO_PASS_HEADERS,
				  OIDC_APPINFO_ENCODING_NONE);
	ck_assert_table_str(r->headers_in, "OIDC_CLAIM_dns", "CN=Admins,OU=Groups::plain");

	oidc_json_decref(claims);
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

	/* an input past OIDC_PCRE_SUBST_MAX_INPUT_LEN is refused before the pattern is even applied */
	error_str = NULL;
	char *toolong = apr_palloc(pool, OIDC_PCRE_SUBST_MAX_INPUT_LEN + 2);
	_oidc_memset(toolong, 'a', OIDC_PCRE_SUBST_MAX_INPUT_LEN + 1);
	toolong[OIDC_PCRE_SUBST_MAX_INPUT_LEN + 1] = '\0';
	rc = oidc_util_regexp_substitute(pool, toolong, regexp, replace, &output, &error_str);
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

	/* a result longer than the initial output buffer is no longer truncated away into a failure:
	 * the substitution is retried against a buffer sized from PCRE2_SUBSTITUTE_OVERFLOW_LENGTH */
	error_str = NULL;
	char *big = apr_palloc(pool, 3001);
	_oidc_memset(big, 'x', 3000);
	big[3000] = '\0';
	char *big_input = apr_psprintf(pool, "match %s numbers", big);
	rc = oidc_util_regexp_substitute(pool, big_input, "^match (.*) numbers$", replace, &output, &error_str);
	ck_assert_msg(rc == TRUE, "oidc_util_regexp_substitute returned FALSE");
	ck_assert_ptr_null(error_str);
	ck_assert_int_eq((int)_oidc_strlen(output), 3000);
	ck_assert_str_eq(output, big);
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
	rv = oidc_util_apr_expr_parse(cmd, NULL, &expr, OIDC_APR_EXPR_RESULT_BOOLEAN);
	ck_assert_ptr_null(rv);
	ck_assert_ptr_null(expr);

	//	expr = NULL;
	//	rv = oidc_util_apr_expr_parse(cmd, "% ||| true)", &expr, FALSE);
	//	ck_assert_ptr_nonnull(rv);
	//	ck_assert_ptr_null(expr);

	expr = NULL;
	rv = oidc_util_apr_expr_parse(cmd, "", &expr, OIDC_APR_EXPR_RESULT_STRING);
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
	rv = oidc_util_apr_expr_parse(cmd, "true", &expr, OIDC_APR_EXPR_RESULT_BOOLEAN);
	ck_assert_ptr_null(rv);
	ck_assert_ptr_nonnull(expr);

	// NB: stub only
	result = oidc_util_apr_expr_exec(r, expr, OIDC_APR_EXPR_RESULT_STRING);
	ck_assert_ptr_nonnull(result);
	ck_assert_str_eq(result, "true");
	// NB: stub only
	result = oidc_util_apr_expr_exec(r, expr, OIDC_APR_EXPR_RESULT_BOOLEAN);
	ck_assert_ptr_null(result);

	// NB: stub only
	expr = NULL;
	rv = oidc_util_apr_expr_parse(cmd, "#", &expr, OIDC_APR_EXPR_RESULT_BOOLEAN);
	ck_assert_ptr_nonnull(rv);
	ck_assert_ptr_null(expr);
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

	oidc_util_rand_str(r, &text, 32);
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

/* symlinked config files are a fact of deployment life - a Kubernetes ConfigMap volume exposes
 * every file as a symlink into its ..data directory - so a symlink whose target is a regular
 * file must read fine; one pointing at a directory, or at nothing, is still refused */
START_TEST(test_util_file_read_symlink) {
	request_rec *r = oidc_test_request_get();
	const char *dir = NULL;
	char *target = NULL, *link_path = NULL, *dir_link = NULL, *dangling = NULL, *read = NULL;

	apr_temp_dir_get(&dir, r->pool);
	target = apr_psprintf(r->pool, "%s/test-symlink-target.tmp", dir);
	ck_assert_int_eq(oidc_util_file_write(r, target, "linked-content"), TRUE);

	link_path = apr_psprintf(r->pool, "%s/test-symlink.tmp", dir);
	unlink(link_path); /* in case a previous run left it behind */
	ck_assert_int_eq(symlink(target, link_path), 0);
	ck_assert_int_eq(oidc_util_file_read(r, link_path, r->pool, &read), TRUE);
	ck_assert_ptr_nonnull(read);
	ck_assert_str_eq(read, "linked-content");

	/* a symlink to a directory is not a regular file however you look at it */
	dir_link = apr_psprintf(r->pool, "%s/test-symlink-dir.tmp", dir);
	unlink(dir_link);
	ck_assert_int_eq(symlink(dir, dir_link), 0);
	read = NULL;
	ck_assert_int_eq(oidc_util_file_read(r, dir_link, r->pool, &read), FALSE);
	ck_assert_ptr_null(read);

	/* and a dangling one reads as absent */
	dangling = apr_psprintf(r->pool, "%s/test-symlink-dangling.tmp", dir);
	unlink(dangling);
	ck_assert_int_eq(symlink(apr_psprintf(r->pool, "%s/test-symlink-nonexistent", dir), dangling), 0);
	read = NULL;
	ck_assert_int_eq(oidc_util_file_read(r, dangling, r->pool, &read), FALSE);
	ck_assert_ptr_null(read);

	unlink(link_path);
	unlink(dir_link);
	unlink(dangling);
	apr_file_remove(target, r->pool);
}
END_TEST

/* stat succeeds (it is a regular, readable file) but the subsequent open() fails. A mode-0000 file
 * would not exercise this when the suite runs as root, which permission checks do not apply to; a
 * file descriptor table exhausted down to exactly the fd the open() would need returns EMFILE
 * regardless of privilege, and stat(2) itself needs no fd so the preceding check is unaffected. */
START_TEST(test_util_file_read_open_fails_after_stat) {
	request_rec *r = oidc_test_request_get();
	const char *dir = NULL;
	char *path = NULL;
	char *read = NULL;
	apr_byte_t rc;
	struct rlimit rl_orig, rl_low;

	apr_temp_dir_get(&dir, r->pool);
	path = apr_psprintf(r->pool, "%s/test-emfile.tmp", dir);
	ck_assert_int_eq(oidc_util_file_write(r, path, "content"), TRUE);

	int probe_fd = open("/dev/null", O_RDONLY);
	ck_assert_int_ge(probe_fd, 0);
	close(probe_fd);

	ck_assert_int_eq(getrlimit(RLIMIT_NOFILE, &rl_orig), 0);
	rl_low.rlim_cur = probe_fd;
	rl_low.rlim_max = rl_orig.rlim_max;
	ck_assert_int_eq(setrlimit(RLIMIT_NOFILE, &rl_low), 0);

	rc = oidc_util_file_read(r, path, r->pool, &read);

	/* restore before asserting, so a failed assertion cannot starve the rest of the suite of fds */
	ck_assert_int_eq(setrlimit(RLIMIT_NOFILE, &rl_orig), 0);

	ck_assert_int_eq(rc, FALSE);
	ck_assert_ptr_null(read);

	apr_file_remove(path, r->pool);
}
END_TEST

/* a file larger than OIDC_UTIL_FILE_SIZE_MAX (16MB) is rejected before its contents are read; a
 * sparse file (seek past the cap, write one byte) gets it reported as that large without actually
 * writing 16MB to disk */
START_TEST(test_util_file_read_too_large) {
	request_rec *r = oidc_test_request_get();
	const char *dir = NULL;
	char *path = NULL;
	char *read = NULL;
	apr_file_t *fd = NULL;
	apr_off_t offset = (apr_off_t)(16 * 1024 * 1024) + 1;
	apr_size_t nbytes = 1;

	apr_temp_dir_get(&dir, r->pool);
	path = apr_psprintf(r->pool, "%s/test-too-large.tmp", dir);

	ck_assert_int_eq(
	    apr_file_open(&fd, path, APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE, APR_OS_DEFAULT, r->pool),
	    APR_SUCCESS);
	ck_assert_int_eq(apr_file_seek(fd, APR_SET, &offset), APR_SUCCESS);
	ck_assert_int_eq(apr_file_write(fd, "x", &nbytes), APR_SUCCESS);
	apr_file_close(fd);

	ck_assert_int_eq(oidc_util_file_read(r, path, r->pool, &read), FALSE);
	ck_assert_ptr_null(read);

	apr_file_remove(path, r->pool);
}
END_TEST

/* oidc_util_file_read_server is the server-scoped (no request_rec) twin of oidc_util_file_read,
 * used at startup where there is no request yet; nothing in this (open-source) module calls it --
 * only the commercial license check does -- so exercise all four outcomes directly */
START_TEST(test_util_file_read_server) {
	request_rec *r = oidc_test_request_get();
	const char *dir = NULL;
	char *path = NULL;
	char *read = NULL;
	apr_file_t *fd = NULL;
	apr_off_t offset = (apr_off_t)(16 * 1024 * 1024) + 1;
	apr_size_t nbytes = 1;

	apr_temp_dir_get(&dir, r->pool);

	/* OK */
	path = apr_psprintf(r->pool, "%s/test-server-ok.tmp", dir);
	ck_assert_int_eq(oidc_util_file_write(r, path, "server-scoped"), TRUE);
	ck_assert_int_eq(oidc_util_file_read_server(r->server, path, r->pool, &read), TRUE);
	ck_assert_str_eq(read, "server-scoped");
	apr_file_remove(path, r->pool);

	/* NOT_FOUND */
	read = NULL;
	ck_assert_int_eq(
	    oidc_util_file_read_server(r->server, apr_psprintf(r->pool, "%s/bogus-server.tmp", dir), r->pool, &read),
	    FALSE);
	ck_assert_ptr_null(read);

	/* NOT_REGULAR: a directory */
	read = NULL;
	ck_assert_int_eq(oidc_util_file_read_server(r->server, dir, r->pool, &read), FALSE);
	ck_assert_ptr_null(read);

	/* the default/error arm (IO_ERROR): the same oversized-file trick as above */
	path = apr_psprintf(r->pool, "%s/test-server-too-large.tmp", dir);
	ck_assert_int_eq(
	    apr_file_open(&fd, path, APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE, APR_OS_DEFAULT, r->pool),
	    APR_SUCCESS);
	ck_assert_int_eq(apr_file_seek(fd, APR_SET, &offset), APR_SUCCESS);
	ck_assert_int_eq(apr_file_write(fd, "x", &nbytes), APR_SUCCESS);
	apr_file_close(fd);
	read = NULL;
	ck_assert_int_eq(oidc_util_file_read_server(r->server, path, r->pool, &read), FALSE);
	ck_assert_ptr_null(read);
	apr_file_remove(path, r->pool);
}
END_TEST

/* the final atomic rename() can itself fail -- e.g. the destination path already exists as a
 * non-empty directory, which rename(2) refuses to replace with a regular file -- and the temp
 * file must not be left behind dangling next to it when that happens */
START_TEST(test_util_file_write_rename_fails) {
	request_rec *r = oidc_test_request_get();
	const char *dir = NULL;
	char *target_dir = NULL;
	apr_dir_t *d = NULL;
	apr_finfo_t fi;
	int count = 0;

	apr_temp_dir_get(&dir, r->pool);
	target_dir = apr_psprintf(r->pool, "%s/test-rename-target-dir", dir);
	apr_dir_remove(target_dir, r->pool); /* in case a previous run left it behind */
	ck_assert_int_eq(apr_dir_make(target_dir, APR_OS_DEFAULT, r->pool), APR_SUCCESS);

	ck_assert_int_eq(oidc_util_file_write(r, target_dir, "data"), FALSE);

	/* the directory itself must still be there, and empty: the tmp file failed to replace it and
	 * must have been cleaned up rather than left behind alongside it */
	ck_assert_int_eq(apr_stat(&fi, target_dir, APR_FINFO_TYPE, r->pool), APR_SUCCESS);
	ck_assert_int_eq(fi.filetype, APR_DIR);

	ck_assert_int_eq(apr_dir_open(&d, target_dir, r->pool), APR_SUCCESS);
	while (apr_dir_read(&fi, APR_FINFO_NAME, d) == APR_SUCCESS) {
		if ((_oidc_strcmp(fi.name, ".") == 0) || (_oidc_strcmp(fi.name, "..") == 0))
			continue;
		count++;
	}
	apr_dir_close(d);
	ck_assert_int_eq(count, 0);

	apr_dir_remove(target_dir, r->pool);
}
END_TEST

/* apr_file_write_full surfaces a hard error (rather than a silent short write) as soon as the
 * underlying write(2) cannot make progress; RLIMIT_FSIZE, with SIGXFSZ ignored so the process is
 * not killed, gets there deterministically once the cap is exceeded, without needing a full disk */
START_TEST(test_util_file_write_hard_failure) {
	request_rec *r = oidc_test_request_get();
	const char *dir = NULL;
	char *path = NULL;
	apr_byte_t rc;
	apr_finfo_t fi;
	struct rlimit rl_orig, rl_low;
	void (*prev_handler)(int);

	apr_temp_dir_get(&dir, r->pool);
	path = apr_psprintf(r->pool, "%s/test-write-hard-failure.tmp", dir);
	apr_file_remove(path, r->pool); /* in case a previous run left it behind */

	prev_handler = signal(SIGXFSZ, SIG_IGN);
	ck_assert_int_eq(getrlimit(RLIMIT_FSIZE, &rl_orig), 0);
	rl_low.rlim_cur = 4;
	rl_low.rlim_max = rl_orig.rlim_max;
	ck_assert_int_eq(setrlimit(RLIMIT_FSIZE, &rl_low), 0);

	rc = oidc_util_file_write(r, path, "this string is longer than the 4-byte cap above");

	/* restore before asserting, so a failed assertion cannot leave the rest of the suite capped */
	ck_assert_int_eq(setrlimit(RLIMIT_FSIZE, &rl_orig), 0);
	signal(SIGXFSZ, prev_handler);

	ck_assert_int_eq(rc, FALSE);
	/* the write failed before the rename, so the destination must not exist either */
	ck_assert_int_ne(apr_stat(&fi, path, APR_FINFO_TYPE, r->pool), APR_SUCCESS);
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

	/* every entry of the JavaScript escape table in one go: quote, double quote, backslash,
	 * forward slash, CR, LF, and the angle brackets that would otherwise close a <script> */
	ck_assert_str_eq(oidc_util_html_javascript_escape(pool, "'"
								"\""
								"\\"
								"/"
								"\r"
								"\n"
								"<"
								">"),
			 "\\'"
			 "\\\""
			 "\\\\"
			 "\\/"
			 "\\r"
			 "\\n"
			 "\\x3c"
			 "\\x3e");

	/* characters with no escape sequence pass through unchanged, interleaved with escaped ones */
	ck_assert_str_eq(oidc_util_html_javascript_escape(pool, "a<b>c"), "a\\x3cb\\x3ec");
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
	ck_assert_table_str(r->subprocess_env, "OIDC_ERROR", "my error");
	ck_assert_table_str(r->subprocess_env, "OIDC_ERROR_DESC", "my error description");
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

START_TEST(test_util_html_template_escape_and_format) {
	int rv = -1;
	char *contents = NULL;
	char *path = NULL;
	const char *dir = NULL;
	request_rec *r = oidc_test_request_get();

	apr_temp_dir_get(&dir, r->pool);

	/* a template that cannot be read renders nothing and leaves the cached content NULL,
	 * so a later request retries the read rather than rendering a half-read template */
	rv = oidc_util_html_send_in_template(r, apr_psprintf(r->pool, "%s/oidc-no-such-template.html", dir), &contents,
					     "arg1", OIDC_POST_PRESERVE_ESCAPE_NONE, NULL,
					     OIDC_POST_PRESERVE_ESCAPE_NONE);
	ck_assert_int_eq(rv, OK);
	ck_assert_ptr_null(contents);

	/* "%%" is a literal percent rather than a placeholder, so a single "%s" still matches the
	 * one placeholder expected for a NULL arg2; the HTML escape mode escapes the argument */
	path = apr_psprintf(r->pool, "%s/oidc-test-template-ok.html", dir);
	ck_assert_int_eq(oidc_util_file_write(r, path, "100%% <b>%s</b>"), TRUE);
	contents = NULL;
	rv = oidc_util_html_send_in_template(r, path, &contents, "<script>", OIDC_POST_PRESERVE_ESCAPE_HTML, NULL,
					     OIDC_POST_PRESERVE_ESCAPE_NONE);
	ck_assert_int_eq(rv, OK);
	ck_assert_str_eq(oidc_request_state_get(r, "data"), "100% <b>&lt;script&gt;</b>");

	/* a specifier that is neither "%s" nor "%%" is refused outright: passing e.g. "%n" on to
	 * apr_psprintf is what the format check exists to prevent */
	path = apr_psprintf(r->pool, "%s/oidc-test-template-bad-specifier.html", dir);
	ck_assert_int_eq(oidc_util_file_write(r, path, "%s and %x"), TRUE);
	contents = NULL;
	rv = oidc_util_html_send_in_template(r, path, &contents, "arg1", OIDC_POST_PRESERVE_ESCAPE_NONE, NULL,
					     OIDC_POST_PRESERVE_ESCAPE_NONE);
	ck_assert_int_eq(rv, HTTP_INTERNAL_SERVER_ERROR);

	/* the right specifiers but the wrong number of them is refused just the same */
	path = apr_psprintf(r->pool, "%s/oidc-test-template-bad-count.html", dir);
	ck_assert_int_eq(oidc_util_file_write(r, path, "%s and %s"), TRUE);
	contents = NULL;
	rv = oidc_util_html_send_in_template(r, path, &contents, "arg1", OIDC_POST_PRESERVE_ESCAPE_NONE, NULL,
					     OIDC_POST_PRESERVE_ESCAPE_NONE);
	ck_assert_int_eq(rv, HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

START_TEST(test_util_jq) {
	request_rec *r = oidc_test_request_get();
	oidc_json_t *json = NULL;
	oidc_json_decode_object(r, "{ \"jan\": \"jan\", \"piet\": \"piet\" }", &json);
#ifdef USE_LIBJQ
	ck_assert_str_eq(oidc_util_jq_filter(r, NULL, "."), "{}");
	ck_assert_str_eq(oidc_util_jq_filter(r, json, NULL), "{\"jan\":\"jan\",\"piet\":\"piet\"}");
	ck_assert_str_eq(oidc_util_jq_filter(r, json, ".bogus"), "null");
	ck_assert_str_eq(oidc_util_jq_filter(r, json, "bogus"), "{\"jan\":\"jan\",\"piet\":\"piet\"}");
	ck_assert_str_eq(oidc_util_jq_filter(r, json, ".jan"), "\"jan\"");
	/* a filter that yields more than one output runs the result loop more than once and the
	 * last output wins, rather than the first one or a concatenation of them */
	ck_assert_str_eq(oidc_util_jq_filter(r, json, ".[]"), "\"piet\"");
	/* an identical input+filter repeat is served from the jq result cache */
	ck_assert_str_eq(oidc_util_jq_filter(r, json, ".jan"), "\"jan\"");
	/* a TTL of 0 (via the env var) disables the cache in both directions */
	apr_table_set(r->subprocess_env, "OIDC_JQ_FILTER_CACHE_TTL", "0");
	ck_assert_str_eq(oidc_util_jq_filter(r, json, ".piet"), "\"piet\"");
	apr_table_unset(r->subprocess_env, "OIDC_JQ_FILTER_CACHE_TTL");
#else
	ck_assert_str_eq(oidc_util_jq_filter(r, json, ".jan"), "{\"jan\":\"jan\",\"piet\":\"piet\"}");
#endif
	oidc_json_decref(json);
}
END_TEST

START_TEST(test_util_json) {
	request_rec *r = oidc_test_request_get();
	apr_byte_t rv = FALSE;
	oidc_json_t *json = NULL;
	oidc_json_t *src = NULL;
	oidc_json_t *dst = NULL;
	json_error_t json_error;
	apr_pool_t *pool = oidc_test_pool_get();
	apr_array_header_t *arr = NULL;
	int v = 0;

	ck_assert_msg(oidc_json_decode_and_check_error(r, NULL, &json) == FALSE, "result for NULL is not FALSE: %d",
		      rv);
	oidc_json_decref(json);
	ck_assert_msg(oidc_json_decode_and_check_error(r, "{}", &json) == TRUE, "result for {} is not FALSE: %d", rv);
	oidc_json_decref(json);
	ck_assert_msg(oidc_json_decode_and_check_error(r, "[ 1, 2 ]", &json) == FALSE,
		      "result for array object is not TRUE: %d", rv);
	oidc_json_decref(json);
	ck_assert_msg(oidc_json_decode_and_check_error(r, "{\"error\":\"yes\"}", &json) == FALSE,
		      "result for error object is not FALSE: %d", rv);
	oidc_json_decref(json);

	json = json_loads("[ \"hi\", 2 ]", 0, &json_error);
	ck_assert_ptr_nonnull(json);
	ck_assert_msg(oidc_json_array_has_value(r, json, "ho") == FALSE, "result for \"ho\" is not FALSE");
	ck_assert_msg(oidc_json_array_has_value(r, json, "hi") == TRUE, "result for \"hi\" is not TRUE");
	oidc_json_decref(json);

	json = json_loads("{ \"myarr\": [ \"hi\", \"ho\" ] }", 0, &json_error);
	ck_assert_ptr_nonnull(json);
	ck_assert_msg(oidc_json_object_get_string_array(pool, json, "my", &arr, NULL) == TRUE, "result is not TRUE");
	ck_assert_ptr_null(arr);
	ck_assert_msg(oidc_json_object_get_string_array(pool, json, "myarr", &arr, NULL) == TRUE, "result is not TRUE");
	ck_assert_ptr_nonnull(arr);
	ck_assert_msg(arr->nelts == 2, "array size is not 2");
	oidc_json_decref(json);

	json = json_loads("{ \"myint\": 1, \"mybool\": true }", 0, &json_error);
	ck_assert_ptr_nonnull(json);
	ck_assert_msg(oidc_json_object_get_int(json, "my", &v, 0) == FALSE, "result is not FALSE");
	ck_assert_int_eq(v, 0);
	ck_assert_msg(oidc_json_object_get_int(json, "myint", &v, 0) == TRUE, "result is not TRUE");
	ck_assert_int_eq(v, 1);
	ck_assert_msg(oidc_json_object_get_bool(json, "my", &v, 0) == FALSE, "result is not FALSE");
	ck_assert_int_eq(v, 0);
	ck_assert_msg(oidc_json_object_get_bool(json, "mybool", &v, 0) == TRUE, "result is not TRUE");
	ck_assert_int_eq(v, 1);
	oidc_json_decref(json);

	src = json_loads("{ \"myint1\": 1, \"mybool1\": false }", 0, &json_error);
	ck_assert_ptr_nonnull(src);
	dst = json_loads("{ \"myint2\": 2, \"mybool2\": true }", 0, &json_error);
	ck_assert_ptr_nonnull(dst);
	ck_assert_msg(oidc_json_merge(r, src, dst) == TRUE, "result is not TRUE");
	ck_assert_ptr_nonnull(src);
	ck_assert_ptr_nonnull(dst);
	ck_assert_msg(oidc_json_object_get_bool(dst, "mybool2", &v, 0) == TRUE, "result is not TRUE");
	ck_assert_int_eq(v, 1);
	ck_assert_msg(oidc_json_object_get_bool(dst, "mybool1", &v, 1) == TRUE, "result is not TRUE");
	ck_assert_int_eq(v, 0);
	oidc_json_decref(src);
	oidc_json_decref(dst);
}
END_TEST

START_TEST(test_util_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_crypto_passphrase_t passphrase = {"secret1", NULL};
	const char *str = "{ \"key\": \"value\" }";
	char *cser = NULL;
	char *payload = NULL;

	ck_assert_msg(oidc_crypto_passphrase_derive_keys(&passphrase) == TRUE, "result is not TRUE");

	//	const char *empty = "{}";
	//	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, empty, &cser) == TRUE, "result is not TRUE");
	//	ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE, "result is not TRUE");
	//	ck_assert_str_eq(payload, empty);

	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, str, &cser) == TRUE, "result is not TRUE");
	ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE, "result is not TRUE");
	ck_assert_str_eq(payload, str);

	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");
	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, str, &cser) == TRUE, "result is not TRUE");
	ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE, "result is not TRUE");
	ck_assert_str_eq(payload, str);

	/*
	 * the setting says how payloads are written from now on, not how an existing one was
	 * written, so a payload must stay readable across a change to it. Reading it on the verify
	 * side meant that toggling it under running traffic made every live session unreadable.
	 */
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, str, &cser) == TRUE, "compressed create failed");
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");
	ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE,
		      "a compressed payload must still verify after compression is switched off");
	ck_assert_str_eq(payload, str);

	/* and the other way round: written uncompressed, read by a server that compresses */
	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, str, &cser) == TRUE, "uncompressed create failed");
	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
	ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE,
		      "an uncompressed payload must still verify after compression is switched on");
	ck_assert_str_eq(payload, str);

	passphrase.secret1 = NULL;
	ck_assert_msg(oidc_util_jwt_create(r, &passphrase, str, &cser) == FALSE, "result is not FALSE");
}
END_TEST

/*
 * OIDCCryptoPassphrase takes a second, previous passphrase so that it can be rotated without
 * invalidating every live session and cache entry. Which of the two keys is used is decided from
 * the "kid" in the header of the payload in hand -- absent means it was written before the
 * rotation -- and none of that was covered.
 */
START_TEST(test_util_jwt_passphrase_rotation) {
	request_rec *r = oidc_test_request_get();
	const char *str = "{ \"key\": \"value\" }";
	char *cser = NULL;
	char *payload = NULL;
	char *kid = NULL;

	/* written before the rotation: one passphrase, so no "kid" to choose by */
	oidc_crypto_passphrase_t old = {"old-secret-0123456789012345678901", NULL};
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys(&old), TRUE);
	ck_assert_int_eq(oidc_util_jwt_create(r, &old, str, &cser), TRUE);
	ck_assert_ptr_nonnull(oidc_proto_jwt_header_peek(r, cser, NULL, NULL, &kid));
	ck_assert_ptr_null(kid);

	/* after the rotation the old passphrase is the second one, and a payload without a "kid"
	 * is read with it rather than with the new one */
	oidc_crypto_passphrase_t rotated = {"new-secret-0123456789012345678901", "old-secret-0123456789012345678901"};
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys(&rotated), TRUE);
	ck_assert_int_eq(oidc_util_jwt_verify(r, &rotated, cser, &payload), TRUE);
	ck_assert_str_eq(payload, str);

	/* anything written from now on is stamped with a "kid" and read with the new passphrase */
	cser = NULL;
	ck_assert_int_eq(oidc_util_jwt_create(r, &rotated, str, &cser), TRUE);
	kid = NULL;
	ck_assert_ptr_nonnull(oidc_proto_jwt_header_peek(r, cser, NULL, NULL, &kid));
	ck_assert_str_eq(kid, "1");
	payload = NULL;
	ck_assert_int_eq(oidc_util_jwt_verify(r, &rotated, cser, &payload), TRUE);
	ck_assert_str_eq(payload, str);

	/* once the rotation is finished and the old passphrase is dropped, what it wrote is gone --
	 * reported as a failure to read rather than as an empty payload */
	payload = NULL;
	ck_assert_int_eq(oidc_util_jwt_verify(r, &old, cser, &payload), FALSE);
	ck_assert_ptr_null(payload);
}
END_TEST

/*
 * the derived key material is computed once at post-config time; a passphrase that never went
 * through that has to be refused rather than used as if it had a key
 */
START_TEST(test_util_jwt_without_derived_keys) {
	request_rec *r = oidc_test_request_get();
	const char *str = "{ \"key\": \"value\" }";
	char *cser = NULL;
	char *payload = NULL;

	/* a passphrase that was never run through oidc_crypto_passphrase_derive_keys */
	oidc_crypto_passphrase_t raw = {"secret-0123456789012345678901234", NULL};
	ck_assert_int_eq(oidc_util_jwt_create(r, &raw, str, &cser), FALSE);

	/* the same on the read side, against a payload written with proper key material */
	oidc_crypto_passphrase_t good = {"secret-0123456789012345678901234", NULL};
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys(&good), TRUE);
	ck_assert_int_eq(oidc_util_jwt_create(r, &good, str, &cser), TRUE);
	ck_assert_int_eq(oidc_util_jwt_verify(r, &raw, cser, &payload), FALSE);
	ck_assert_ptr_null(payload);

	/* and on the branch a rotation takes: no "kid" in the payload sends the read at the second
	 * passphrase, whose key material is missing here too */
	oidc_crypto_passphrase_t raw_rotated = {"new-secret-0123456789012345678901",
						"old-secret-0123456789012345678901"};
	payload = NULL;
	ck_assert_int_eq(oidc_util_jwt_verify(r, &raw_rotated, cser, &payload), FALSE);
	ck_assert_ptr_null(payload);
}
END_TEST

/*
 * the environment-variable overrides are read off r->subprocess_env, which a request need not
 * have; the default has to hold rather than the lookup crashing
 */
START_TEST(test_util_jwt_without_subprocess_env) {
	request_rec *r = oidc_test_request_get();
	const char *str = "{ \"key\": \"value\" }";
	char *cser = NULL;
	char *payload = NULL;
	apr_table_t *saved = r->subprocess_env;

	oidc_crypto_passphrase_t passphrase = {"secret-0123456789012345678901234", NULL};
	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys(&passphrase), TRUE);

	r->subprocess_env = NULL;
	apr_byte_t created = oidc_util_jwt_create(r, &passphrase, str, &cser);
	apr_byte_t verified = created ? oidc_util_jwt_verify(r, &passphrase, cser, &payload) : FALSE;
	r->subprocess_env = saved;

	ck_assert_int_eq(created, TRUE);
	ck_assert_int_eq(verified, TRUE);
	ck_assert_str_eq(payload, str);
}
END_TEST

/*
 * regression: the decompressor decides from the payload's first two bytes, and that test has
 * false positives -- 19 printable two-character prefixes satisfy it. Session and state payloads
 * are JSON and cannot, but cache values go through the same create/verify pair and are arbitrary
 * strings, so an uncompressed cached value starting with e.g. "x " was declared compressed, failed
 * to inflate, and was lost.
 */
START_TEST(test_util_jwt_payload_that_looks_compressed) {
	request_rec *r = oidc_test_request_get();
	oidc_crypto_passphrase_t passphrase = {"secret-0123456789012345678901234", NULL};
	static const char *lookalikes[] = {"x ", "H,", "80", "X(", "h$", "(4"};

	ck_assert_int_eq(oidc_crypto_passphrase_derive_keys(&passphrase), TRUE);

	/* written without compression, which is what leaves the payload bytes on the wire as they are */
	apr_table_set(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS", "true");

	for (unsigned int i = 0; i < sizeof(lookalikes) / sizeof(lookalikes[0]); i++) {
		char *cser = NULL, *payload = NULL;
		const char *str = apr_psprintf(r->pool, "%sthe rest of a perfectly ordinary value", lookalikes[i]);
		ck_assert_int_eq(oidc_util_jwt_create(r, &passphrase, str, &cser), TRUE);
		ck_assert_msg(oidc_util_jwt_verify(r, &passphrase, cser, &payload) == TRUE,
			      "a payload starting with \"%s\" must survive the round trip", lookalikes[i]);
		ck_assert_str_eq(payload, str);
	}

	apr_table_unset(r->subprocess_env, "OIDC_JWT_INTERNAL_NO_COMPRESS");
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
	ck_assert_ptr_eq(oidc_util_key_list_first(arr2, OIDC_JOSE_JWK_KTY_OCT, "sig"), jwk3);
	ck_assert_ptr_null(oidc_util_key_list_first(arr2, OIDC_JOSE_JWK_KTY_RSA, "enc"));

	oidc_jwk_list_destroy_hash(hash3);
}
END_TEST

START_TEST(test_util_key_sets_hash_merge_precedence) {
	request_rec *r = oidc_test_request_get();
	apr_pool_t *pool = oidc_test_pool_get();
	apr_hash_t *k1 = apr_hash_make(pool);
	apr_hash_t *k2 = apr_hash_make(pool);
	apr_hash_t *merged = NULL;
	oidc_jwk_t *jwk1 = NULL;
	oidc_jwk_t *jwk2 = NULL;

	ck_assert(oidc_util_key_symmetric_create(r, "secret-one", 0, "SHA256", TRUE, &jwk1) == TRUE);
	ck_assert(oidc_util_key_symmetric_create(r, "secret-two", 0, "SHA256", TRUE, &jwk2) == TRUE);
	ck_assert_ptr_nonnull(jwk1);
	ck_assert_ptr_nonnull(jwk2);

	/* register both keys under the *same* kid to force a collision between the two sets */
	apr_hash_set(k1, "shared-kid", APR_HASH_KEY_STRING, jwk1);
	apr_hash_set(k2, "shared-kid", APR_HASH_KEY_STRING, jwk2);

	/*
	 * on a "kid" collision the first argument wins; this is the precedence oidc_proto_jwt_verify relies on
	 * to let dynamically obtained JWKS keys (passed first) override statically configured keys with the
	 * same kid
	 */
	merged = oidc_util_key_sets_hash_merge(pool, k1, k2);
	ck_assert_int_eq(apr_hash_count(merged), 1);
	ck_assert_ptr_eq(apr_hash_get(merged, "shared-kid", APR_HASH_KEY_STRING), jwk1);

	merged = oidc_util_key_sets_hash_merge(pool, k2, k1);
	ck_assert_int_eq(apr_hash_count(merged), 1);
	ck_assert_ptr_eq(apr_hash_get(merged, "shared-kid", APR_HASH_KEY_STRING), jwk2);

	oidc_jwk_destroy(jwk1);
	oidc_jwk_destroy(jwk2);
}
END_TEST

START_TEST(test_util_random) {
	request_rec *r = oidc_test_request_get();
	unsigned int v;
	char *s = NULL;

	v = oidc_util_rand_int(10);
	ck_assert_msg((v < 10), "value out of range");
	v = oidc_util_rand_int(3);
	ck_assert_msg((v < 3), "value out of range");

	ck_assert_msg(oidc_util_rand_str(r, &s, 8) == TRUE, "oidc_util_rand_str returned FALSE");
	ck_assert_int_eq(_oidc_strlen(s), 11);
	ck_assert_msg(oidc_util_rand_str(r, &s, 12) == TRUE, "oidc_util_rand_str returned FALSE");
	ck_assert_int_eq(_oidc_strlen(s), 16);

	s = oidc_util_rand_hex_str(r, r->pool, 8);
	ck_assert_ptr_nonnull(s);
	ck_assert_int_eq(_oidc_strlen(s), 16);
	s = oidc_util_rand_hex_str(r, r->pool, 16);
	ck_assert_ptr_nonnull(s);
	ck_assert_int_eq(_oidc_strlen(s), 32);
}
END_TEST

START_TEST(test_util_url) {
	request_rec *r = oidc_test_request_get();

	r->uri = "/test";
	r->unparsed_uri = apr_pstrcat(r->pool, r->uri, "?", r->args, NULL);

	ck_assert_str_eq(oidc_util_url_cur_host(r, OIDC_HDR_NONE), "www.example.com");

	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_NONE), "https://www.example.com/test?foo=bar&param1=value1");
	apr_table_set(r->headers_in, "X-Forwarded-Host", "www.outer.com");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_NONE), "https://www.example.com/test?foo=bar&param1=value1");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST),
			 "https://www.outer.com/test?foo=bar&param1=value1");
	apr_table_set(r->headers_in, "X-Forwarded-Host", "www.outer.com:654");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST),
			 "https://www.outer.com:654/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Port", "321");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_NONE), "https://www.example.com/test?foo=bar&param1=value1");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST),
			 "https://www.outer.com:654/test?foo=bar&param1=value1");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT),
			 "https://www.outer.com:321/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Proto", "http");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_NONE), "https://www.example.com/test?foo=bar&param1=value1");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST),
			 "https://www.outer.com:654/test?foo=bar&param1=value1");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT),
			 "https://www.outer.com:321/test?foo=bar&param1=value1");
	ck_assert_str_eq(
	    oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT | OIDC_HDR_X_FORWARDED_PROTO),
	    "http://www.outer.com:321/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Proto", "https , http");
	ck_assert_str_eq(
	    oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT | OIDC_HDR_X_FORWARDED_PROTO),
	    "https://www.outer.com:321/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Proto", "hxxx");
	ck_assert_str_eq(
	    oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT | OIDC_HDR_X_FORWARDED_PROTO),
	    "https://www.outer.com:321/test?foo=bar&param1=value1");

	apr_table_unset(r->headers_in, "X-Forwarded-Host");
	apr_table_unset(r->headers_in, "X-Forwarded-Port");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO),
			 "https://www.example.com/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Proto", "http ");
	apr_table_set(r->headers_in, "Host", "remotehost");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO),
			 "http://remotehost/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Host", "remotehost:8380");
	r->uri = "http://remotehost:8380/private/";
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO),
			 "http://remotehost:8380/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Host", "[fd04:41b1:1170:28:16b0:446b:9fb7:7118]:8380");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO),
			 "http://[fd04:41b1:1170:28:16b0:446b:9fb7:7118]:8380/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Host", "[fd04:41b1:1170:28:16b0:446b:9fb7:7118]");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO),
			 "http://[fd04:41b1:1170:28:16b0:446b:9fb7:7118]/private/?foo=bar&param1=value1");

	apr_table_unset(r->headers_in, "X-Forwarded-Proto");
	apr_table_unset(r->headers_in, "Host");

	apr_table_set(r->headers_in, "Forwarded", "host=www.outer.com");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_FORWARDED),
			 "https://www.outer.com/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Forwarded", "proto=http");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_FORWARDED),
			 "http://www.example.com/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Forwarded", "host=www.outer.com:8443");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_FORWARDED),
			 "https://www.outer.com:8443/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Forwarded", "proto=http; host=www.outer.com:8080");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_FORWARDED),
			 "http://www.outer.com:8080/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Forwarded", "host=www.outer.com:8080; proto=http");
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_FORWARDED),
			 "http://www.outer.com:8080/private/?foo=bar&param1=value1");

	apr_table_unset(r->headers_in, "Forwarded");
	// it should not crash when Forwarded is not present
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_FORWARDED),
			 "https://www.example.com:4433/private/?foo=bar&param1=value1");
	apr_table_set(r->headers_in, "Host", "www.example.com");

	r->uri = "http://[2001:65333322223616";
	// TODO: shouldn't we either add "/" or not concatenate?
	ck_assert_str_eq(oidc_util_url_cur(r, OIDC_HDR_NONE), "https://www.example.comhttp://[2001:65333322223616");
}
END_TEST

START_TEST(test_util_url_abs) {
	request_rec *r = oidc_test_request_get();
	ck_assert_ptr_null(oidc_util_url_abs(r, oidc_test_cfg_get(), NULL));
	ck_assert_str_eq(oidc_util_url_abs(r, oidc_test_cfg_get(), "https://www.example.com"),
			 "https://www.example.com");
	ck_assert_str_eq(oidc_util_url_abs(r, oidc_test_cfg_get(), "/mytest"), "https://www.example.com/mytest");
}
END_TEST

START_TEST(test_util_url_matches) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	ck_assert_msg(oidc_util_url_cur_matches(r, NULL) == FALSE, "match");
	ck_assert_msg(oidc_util_url_cur_matches(r, "sss//www.example.com/bla") == FALSE, "match");
	ck_assert_msg(oidc_util_url_cur_matches(r, "https://www.example.com/bla") == TRUE, "no match");
	ck_assert_msg(oidc_util_url_cur_matches(r, "https://www.example.com/bla2") == FALSE, "match");
	r->parsed_uri.path = NULL;
	ck_assert_msg(oidc_util_url_cur_matches(r, "https://www.example.com/bla2") == FALSE, "match");
	ck_assert_msg(oidc_util_url_matches_redirect_uri(r, c) == FALSE, "match");
	apr_uri_parse(r->pool, "https://www.example.com/protected/", &r->parsed_uri);
	ck_assert_msg(oidc_util_url_matches_redirect_uri(r, c) == TRUE, "no match");
}
END_TEST

START_TEST(test_util_strenv_and_casestr) {
	int d = 0;

	d = oidc_util_strnenvcmp("a.b", "A_B", -1);
	ck_assert_msg(d == 0, "oidc_util_strnenvcmp did not treat a.b == A_B");

	d = oidc_util_strnenvcmp("abc", "abd", -1);
	ck_assert_msg(d < 0, "oidc_util_strnenvcmp expected abc < abd");

	const char *p = oidc_util_strcasestr("Hello World", "world");
	ck_assert_ptr_nonnull(p);
	ck_assert_ptr_null(oidc_util_strcasestr("abcdef", "xyz"));
}
END_TEST

START_TEST(test_util_spaced_string_helpers) {
	apr_pool_t *pool = oidc_test_pool_get();
	apr_hash_t *ht = NULL;

	ht = oidc_util_spaced_string_to_hashtable(pool, "one two three");
	ck_assert_ptr_nonnull(ht);
	ck_assert_int_eq(apr_hash_count(ht), 3);

	ck_assert_msg(oidc_util_spaced_string_contains(pool, "one two three", "two") == TRUE,
		      "expected contains to return TRUE");
	ck_assert_msg(oidc_util_spaced_string_contains(pool, NULL, "two") == FALSE,
		      "expected contains with NULL str to return FALSE");

	ck_assert_msg(oidc_util_spaced_string_equals(pool, "a b c", "c a b") == TRUE,
		      "expected spaced_string_equals to treat different order as equal");
	ck_assert_msg(oidc_util_spaced_string_equals(pool, "a b c", "a b") == FALSE,
		      "expected spaced_string_equals to detect different counts");
}
END_TEST

START_TEST(test_util_hex_and_hash) {
	request_rec *r = oidc_test_request_get();
	const unsigned char bytes[] = {0xAB, 0x01};
	char *hex = NULL;
	char *out = NULL;

	hex = oidc_util_hex_encode(r->pool, bytes, 2);
	ck_assert_ptr_nonnull(hex);
	ck_assert_str_eq(hex, "ab01");

	ck_assert_msg(oidc_util_hash_string_and_base64url_encode(r, "SHA256", "test", &out) == TRUE,
		      "oidc_util_hash_string_and_base64url_encode failed");
	ck_assert_ptr_nonnull(out);
}
END_TEST

START_TEST(test_util_cookie_domain_and_issuer) {
	ck_assert_msg(oidc_util_cookie_domain_valid("www.example.com", ".example.com") == TRUE,
		      "expected cookie domain .example.com to be valid for www.example.com");
	ck_assert_msg(oidc_util_cookie_domain_valid("www.example.com", "example.org") == FALSE,
		      "expected cookie domain example.org to be invalid for www.example.com");

	ck_assert_msg(oidc_util_issuer_match("https://id.example.com", "https://id.example.com/") == TRUE,
		      "expected issuer match to ignore trailing slash");
	ck_assert_msg(oidc_util_issuer_match("https://id.example.com", "https://other.example.com") == FALSE,
		      "expected different issuers not to match");
}
END_TEST

START_TEST(test_util_table_and_hash_clear_and_openssl) {
	apr_pool_t *pool = oidc_test_pool_get();
	apr_table_t *t = apr_table_make(pool, 4);
	apr_hash_t *ht = apr_hash_make(pool);

	oidc_util_table_add_query_encoded_params(pool, t, "a=1&b=two%20words&c=3");
	ck_assert_table_str(t, "a", "1");
	// because ap_unesacpe_url doe snot decode anything in the stub.c
	ck_assert_table_str(t, "b", "two%20words");
	ck_assert_table_str(t, "c", "3");

	apr_hash_set(ht, "k1", APR_HASH_KEY_STRING, "v1");
	apr_hash_set(ht, "k2", APR_HASH_KEY_STRING, "v2");
	ck_assert_int_eq(apr_hash_count(ht), 2);
	oidc_util_apr_hash_clear(ht);
	ck_assert_int_eq(apr_hash_count(ht), 0);

	char *v = oidc_util_openssl_version(pool);
	ck_assert_ptr_nonnull(v);
	ck_assert_int_gt(_oidc_strlen(v), 0);
}
END_TEST

START_TEST(test_util_mask_value) {
	request_rec *r = oidc_test_request_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCDebugMaskSecrets);

	// masking is the default
	ck_assert_int_eq(oidc_util_log_mask_secrets(r), TRUE);

	// NULL values are represented as "(null)"
	ck_assert_str_eq(oidc_util_mask_value(r, NULL), "(null)");

	// values up to the prefix length are masked entirely so nothing of a short secret leaks
	ck_assert_str_eq(oidc_util_mask_value(r, ""), "***");
	ck_assert_str_eq(oidc_util_mask_value(r, "abc"), "***");
	ck_assert_str_eq(oidc_util_mask_value(r, "abcd"), "***");

	// longer values keep a 4-char prefix plus the length, for log correlation without disclosure
	ck_assert_str_eq(oidc_util_mask_value(r, "abcde"), "abcd...(5 chars)");
	ck_assert_str_eq(oidc_util_mask_value(r, "eyJhbGciOiJSUzI1NiJ9"), "eyJh...(20 chars)");

	// OIDCDebugMaskSecrets Off hands back the value itself, which is the point of the directive
	ck_assert_ptr_null(oidc_cmd_debug_mask_secrets_set(cmd, NULL, "Off"));
	ck_assert_int_eq(oidc_util_log_mask_secrets(r), FALSE);
	ck_assert_str_eq(oidc_util_mask_value(r, "eyJhbGciOiJSUzI1NiJ9"), "eyJhbGciOiJSUzI1NiJ9");
	ck_assert_str_eq(oidc_util_mask_value(r, "abc"), "abc");
	// ... but a NULL is still reported as such rather than dereferenced
	ck_assert_str_eq(oidc_util_mask_value(r, NULL), "(null)");

	// and back on again
	ck_assert_ptr_null(oidc_cmd_debug_mask_secrets_set(cmd, NULL, "On"));
	ck_assert_int_eq(oidc_util_log_mask_secrets(r), TRUE);
	ck_assert_str_eq(oidc_util_mask_value(r, "eyJhbGciOiJSUzI1NiJ9"), "eyJh...(20 chars)");
}
END_TEST

START_TEST(test_util_apr_time_saturating) {
	const apr_time_t sec_max = APR_INT64_MAX / APR_USEC_PER_SEC;

	// ordinary NumericDate values convert as apr_time_from_sec would
	ck_assert(oidc_util_apr_time_from_sec(1) == apr_time_from_sec(1));
	ck_assert(oidc_util_apr_time_from_sec(1780000000) == apr_time_from_sec(1780000000));

	// a fractional value truncates towards zero, expiring no later than the claim allows
	ck_assert(oidc_util_apr_time_from_sec(1.9) == apr_time_from_sec(1));

	// zero, negative and non-finite values collapse to 0 rather than converting undefined
	ck_assert(oidc_util_apr_time_from_sec(0) == 0);
	ck_assert(oidc_util_apr_time_from_sec(-1) == 0);
	ck_assert(oidc_util_apr_time_from_sec(-1e300) == 0);
	ck_assert(oidc_util_apr_time_from_sec((double)0.0 / 1.0) == 0);

	// past what apr_time_t can hold the result saturates instead of wrapping negative
	ck_assert(oidc_util_apr_time_from_sec((double)sec_max) == APR_INT64_MAX);
	ck_assert(oidc_util_apr_time_from_sec(1e300) == APR_INT64_MAX);
	ck_assert(oidc_util_apr_time_from_sec(1e300) > 0);

	// the last value that still fits converts rather than saturating
	ck_assert(oidc_util_apr_time_from_sec((double)(sec_max - 1)) < APR_INT64_MAX);
	ck_assert(oidc_util_apr_time_from_sec((double)(sec_max - 1)) > 0);

	// addition saturates too, so a far-future relative expiry does not fold back into the past
	ck_assert(oidc_util_apr_time_add(1, 2) == 3);
	ck_assert(oidc_util_apr_time_add(0, 0) == 0);
	ck_assert(oidc_util_apr_time_add(APR_INT64_MAX, 1) == APR_INT64_MAX);
	ck_assert(oidc_util_apr_time_add(APR_INT64_MAX, APR_INT64_MAX) == APR_INT64_MAX);
	ck_assert(oidc_util_apr_time_add(APR_INT64_MAX - 1, 1) == APR_INT64_MAX);
	ck_assert(oidc_util_apr_time_add(oidc_util_apr_time_from_sec(1e300), apr_time_now()) == APR_INT64_MAX);

	// a negative operand (an "expires in -1" style value) yields the larger of the two
	ck_assert(oidc_util_apr_time_add(-1, 5) == 5);
	ck_assert(oidc_util_apr_time_add(5, -1) == 5);
}
END_TEST

#ifdef HAVE_LIBPCRE2

START_TEST(test_util_pcre_get_substring_error_arms) {
	apr_pool_t *pool = oidc_test_pool_get();
	char *err = NULL;
	char *sub = NULL;

	/* a pattern without a capture group matches, but group 1 can never be extracted;
	 * the reported reason is mapped from the match rc the caller passes in - drive
	 * each arm of that mapping */
	struct oidc_pcre *pcre = oidc_pcre_compile(pool, "[a-z]+", &err);
	ck_assert_ptr_nonnull(pcre);
	ck_assert_int_gt(oidc_pcre_exec(pool, pcre, "abc", 3, &err), 0);

	const struct {
		int rc;
		const char *reason;
	} arms[] = {
	    {PCRE2_ERROR_NOSUBSTRING, "no groups of that number"},
	    {PCRE2_ERROR_UNAVAILABLE, "ovector was too small"},
	    {PCRE2_ERROR_UNSET, "did not participate"},
	    {PCRE2_ERROR_NOMEMORY, "memory could not be obtained"},
	    {12345, "pcre2_substring_get_bynumber failed"},
	};
	for (unsigned int i = 0; i < sizeof(arms) / sizeof(arms[0]); i++) {
		err = NULL;
		sub = NULL;
		ck_assert_int_lt(oidc_pcre_get_substring(pool, pcre, "abc", arms[i].rc, &sub, &err), 1);
		ck_assert_ptr_null(sub);
		ck_assert_ptr_nonnull(err);
		ck_assert_msg(_oidc_strstr(err, arms[i].reason) != NULL, "expected \"%s\" in error, got: %s",
			      arms[i].reason, err);
	}

	oidc_pcre_free_match(pcre);
	oidc_pcre_free(pcre);
}
END_TEST

#endif /* HAVE_LIBPCRE2 */

/*
 * a pattern that does not compile must cost the pool nothing: APR pools cannot release individual
 * allocations, so a caller that compiles an invalid pattern repeatedly against a long-lived pool
 * would retain the wrapper and the error message from every attempt.
 */
START_TEST(test_util_pcre_compile_failure_allocates_nothing) {
	apr_pool_t *pool = oidc_test_pool_get();
	apr_pool_t *p = NULL;
	char *before = NULL;
	char *after = NULL;
	char *err = NULL;

	ck_assert_int_eq(apr_pool_create(&p, pool), APR_SUCCESS);

	/* error_str is optional: the cache's build callback has no use for the message */
	ck_assert_ptr_null(oidc_pcre_compile(p, "[unterminated", NULL));

	/* APR pools allocate by bumping a pointer, so two adjacent allocations of the same size are
	 * exactly that size apart when nothing was allocated in between */
	before = apr_palloc(p, 64);
	for (int i = 0; i < 32; i++)
		ck_assert_ptr_null(oidc_pcre_compile(p, "[unterminated", NULL));
	after = apr_palloc(p, 64);
	ck_assert_msg((after - before) == 64,
		      "32 failing compiles allocated %d bytes from the pool; they must allocate none",
		      (int)(after - before) - 64);

	/* asking for the message does allocate it, which is right for the per-request caller that
	 * logs it out of a request pool */
	ck_assert_ptr_null(oidc_pcre_compile(p, "[unterminated", &err));
	ck_assert_ptr_nonnull(err);
	ck_assert_msg(_oidc_strstr(err, "not a valid regular expression") != NULL, "got: %s", err);

	/* a pattern that does compile still yields a usable program; the compiled program itself is
	 * malloc'ed by pcre2 rather than taken from the pool, so it needs the explicit free */
	struct oidc_pcre *compiled = oidc_pcre_compile(p, "[a-z]+", NULL);
	ck_assert_ptr_nonnull(compiled);
	oidc_pcre_free(compiled);

	apr_pool_destroy(p);
}
END_TEST

START_TEST(test_util_read_form_encoded_params) {
	request_rec *r = oidc_test_request_get();
	apr_table_t *t = apr_table_make(r->pool, 4);

	char *form = "a=1&b=two%20words&c=3";
	ck_assert_msg(oidc_util_read_form_encoded_params(r, t, form) == TRUE,
		      "oidc_util_read_form_encoded_params returned FALSE");

	ck_assert_table_str(t, "a", "1");
	ck_assert_table_str(t, "b", "two words");
	ck_assert_table_str(t, "c", "3");

	/* arbitrary application fields keep the historical last-value-wins behaviour */
	const char *const no_repeat[] = {OIDC_PROTO_STATE, OIDC_PROTO_CODE, NULL};
	t = apr_table_make(r->pool, 2);
	ck_assert_int_eq(oidc_util_read_form_encoded_params_reject_dup(r, t, "color=red&color=blue", no_repeat), TRUE);
	ck_assert_table_str(t, "color", "blue");

	/* a selected protocol field must occur exactly once, even when the duplicate spelling is
	 * percent-encoded (st%61te decodes to state) */
	t = apr_table_make(r->pool, 2);
	ck_assert_int_eq(oidc_util_read_form_encoded_params_reject_dup(r, t, "state=good&st%61te=bad", no_repeat),
			 FALSE);
	t = apr_table_make(r->pool, 2);
	ck_assert_int_eq(oidc_util_read_form_encoded_params_reject_dup(r, t, "code=one&code=two", no_repeat), FALSE);
}
END_TEST

START_TEST(test_util_read_post_params_wrong_content_type) {
	request_rec *r = oidc_test_request_get();
	apr_table_t *t = apr_table_make(r->pool, 2);

	r->method_number = M_GET;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");
	ck_assert_msg(oidc_util_read_post_params(r, t, FALSE, NULL) == FALSE,
		      "oidc_util_read_post_params should return FALSE for non-POST method");

	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/json");
	ck_assert_msg(oidc_util_read_post_params(r, t, FALSE, NULL) == FALSE,
		      "oidc_util_read_post_params should return FALSE for wrong content-type");
}
END_TEST

START_TEST(test_util_read_post_params_oversized) {
	request_rec *r = oidc_test_request_get();
	apr_table_t *t = apr_table_make(r->pool, 2);

	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");

	r->remaining = (apr_size_t)(1024 * 1024 + 1);

	ck_assert_msg(oidc_util_read_post_params(r, t, FALSE, NULL) == FALSE,
		      "oidc_util_read_post_params should return FALSE for oversized POST body");
}
END_TEST

START_TEST(test_util_read_post_params) {
	request_rec *r = oidc_test_request_get();
	apr_table_t *t = apr_table_make(r->pool, 4);

	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");
	const char *form = "a=1&b=2";
	r->remaining = (apr_size_t)_oidc_strlen(form);
	r->args = apr_pstrdup(r->pool, form);

	apr_byte_t rc = oidc_util_read_post_params(r, t, FALSE, NULL);
	ck_assert_msg(rc == TRUE, "oidc_util_read_post_params returned FALSE when propagate==FALSE");

	apr_table_t *userdata_post_params = NULL;
	apr_pool_userdata_get((void **)&userdata_post_params, OIDC_USERDATA_POST_PARAMS_KEY, r->pool);
	ck_assert_ptr_null(userdata_post_params);

	rc = oidc_util_read_post_params(r, t, TRUE, NULL);
	ck_assert_msg(rc == TRUE, "oidc_util_read_post_params returned FALSE when propagate==TRUE");
}
END_TEST

START_TEST(test_util_url_parameter_helpers) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	char *value = NULL;

	r->args = NULL;
	ck_assert_msg(oidc_util_url_has_parameter(r, "foo") == FALSE,
		      "oidc_util_url_has_parameter must return FALSE when r->args is NULL");
	ck_assert_msg(oidc_util_url_parameter_get(r, "foo", &value) == FALSE,
		      "oidc_util_url_parameter_get must return FALSE when r->args is NULL");
	ck_assert_ptr_null(value);

	r->args = "foo=bar&param1=value1";
	ck_assert_msg(oidc_util_url_has_parameter(r, "foo") == TRUE, "param at start should match");
	ck_assert_msg(oidc_util_url_has_parameter(r, "param1") == TRUE, "param after & should match");
	ck_assert_msg(oidc_util_url_has_parameter(r, "bogus") == FALSE, "unknown param must not match");
	/* must not match a substring of an existing key */
	ck_assert_msg(oidc_util_url_has_parameter(r, "param") == FALSE, "prefix-of-existing-key must not match");

	value = NULL;
	ck_assert_msg(oidc_util_url_parameter_get(r, "foo", &value) == TRUE, "foo lookup must succeed");
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "bar");

	value = NULL;
	ck_assert_msg(oidc_util_url_parameter_get(r, "param1", &value) == TRUE, "param1 lookup must succeed");
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "value1");

	value = NULL;
	ck_assert_msg(oidc_util_url_parameter_get(r, "missing", &value) == FALSE, "missing lookup must fail");
	ck_assert_ptr_null(value);

	r->args = "";
	ck_assert_msg(oidc_util_url_parameter_get(r, "foo", &value) == FALSE,
		      "empty args should make url_parameter_get return FALSE");

	/* request scheme is "https" by default in oidc_test_request_init */
	ck_assert_msg(oidc_util_url_cur_is_secure(r, c) == TRUE, "default scheme should be secure (https)");

	ck_assert_str_eq(oidc_util_url_redirect_uri(r, c), "https://www.example.com/protected/");
}
END_TEST

/*
 * Tests migrated from the legacy test/test.c suite — covers the
 * non-NULL/non-oversized branches of oidc_json_decode_object that
 * test_util_json above doesn't reach.
 */
START_TEST(test_util_legacy_json_decode_object) {
	request_rec *r = oidc_test_request_get();
	oidc_json_t *json = NULL;

	/* embedded NUL via a \u0000 escape must be rejected */
	ck_assert_int_eq(oidc_json_decode_object(r, "{ \"n\": \"\\u0000<?php echo 'Hello' ?>\"}", &json), FALSE);

	/* an oversized JSON blob (>4 KiB of garbage) must be rejected by the size guard */
	apr_pool_t *pool = oidc_test_pool_get();
	apr_size_t big_len = 8192;
	char *big = apr_palloc(pool, big_len + 1);
	memset(big, 'a', big_len);
	big[big_len] = '\0';
	ck_assert_int_eq(oidc_json_decode_object(r, big, &json), FALSE);
}
END_TEST

START_TEST(test_util_json_string_and_encode) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	oidc_json_t *json = NULL;
	char *value = NULL;
	char *encoded = NULL;

	/* encode NULL must return NULL */
	ck_assert_ptr_null(oidc_json_encode(pool, NULL, 0));

	/* with no JSON, default is returned */
	oidc_json_object_get_string(pool, NULL, "any", &value, "fallback");
	ck_assert_ptr_nonnull(value);
	ck_assert_str_eq(value, "fallback");

	/* NULL default must produce NULL output */
	value = (char *)0xdeadbeef;
	oidc_json_object_get_string(pool, NULL, "any", &value, NULL);
	ck_assert_ptr_null(value);

	ck_assert_msg(oidc_json_decode_object(r, "{\"name\":\"hans\",\"age\":42}", &json) == TRUE,
		      "decode of valid object failed");
	ck_assert_ptr_nonnull(json);

	/* existing string key */
	value = NULL;
	oidc_json_object_get_string(pool, json, "name", &value, "default");
	ck_assert_str_eq(value, "hans");

	/* missing key falls back to default */
	value = NULL;
	oidc_json_object_get_string(pool, json, "missing", &value, "default");
	ck_assert_str_eq(value, "default");

	/* non-string key (integer) falls back to default */
	value = NULL;
	oidc_json_object_get_string(pool, json, "age", &value, "default");
	ck_assert_str_eq(value, "default");

	/* round-trip encode */
	encoded = oidc_json_encode(pool, json, OIDC_JSON_PRESERVE_ORDER | OIDC_JSON_COMPACT);
	ck_assert_ptr_nonnull(encoded);
	ck_assert_str_eq(encoded, "{\"name\":\"hans\",\"age\":42}");
	oidc_json_decref(json);

	/* NULL input string returns FALSE and does not crash */
	json = NULL;
	ck_assert_msg(oidc_json_decode_object_err(r, NULL, &json, FALSE) == FALSE, "decode NULL must fail");
	ck_assert_ptr_null(json);

	/* malformed JSON must fail, but with log_err==FALSE no error is logged */
	json = NULL;
	ck_assert_msg(oidc_json_decode_object_err(r, "{not json", &json, FALSE) == FALSE,
		      "decode of invalid JSON must fail");
	ck_assert_ptr_null(json);

	/* suppressing the log must not change object validation semantics: a top-level array is
	 * still not an object and must be rejected even with log_err == FALSE */
	json = NULL;
	ck_assert_msg(oidc_json_decode_object_err(r, "[1,2,3]", &json, FALSE) == FALSE,
		      "decode of a non-object JSON value must fail even when logging is disabled");
	ck_assert_ptr_null(json);
}
END_TEST

START_TEST(test_util_strenv_length_and_casestr_edge) {
	int d = 0;

	/* with len, only the first N chars are compared */
	d = oidc_util_strnenvcmp("a.bXXX", "A_b", 3);
	ck_assert_int_eq(d, 0);

	d = oidc_util_strnenvcmp("abcZZ", "abdYY", 3);
	ck_assert_int_lt(d, 0);

	/* len == 0 always equal */
	d = oidc_util_strnenvcmp("totally different", "values here", 0);
	ck_assert_int_eq(d, 0);

	/* different lengths with len < 0 => longer string is greater */
	d = oidc_util_strnenvcmp("abc", "abcd", -1);
	ck_assert_int_lt(d, 0);
	d = oidc_util_strnenvcmp("abcd", "abc", -1);
	ck_assert_int_gt(d, 0);

	/* strcasestr: NULL needle / NULL haystack must return NULL */
	ck_assert_ptr_null(oidc_util_strcasestr(NULL, "x"));
	ck_assert_ptr_null(oidc_util_strcasestr("hello", NULL));

	/* empty needle returns the haystack pointer */
	const char *hay = "Hello World";
	ck_assert_ptr_eq(oidc_util_strcasestr(hay, ""), hay);

	/* match at start (case-insensitive) */
	ck_assert_ptr_nonnull(oidc_util_strcasestr("AbCdEf", "abc"));
}
END_TEST

START_TEST(test_util_cookie_domain_dot_prefix) {
	/* the leading dot must be tolerated */
	ck_assert_msg(oidc_util_cookie_domain_valid("WWW.Example.Com", ".example.com") == TRUE,
		      "cookie domain with leading dot must be valid (case-insensitive)");
	/* host that doesn't end with the domain must be rejected */
	ck_assert_msg(oidc_util_cookie_domain_valid("evil-example.com.attacker", "example.com") == FALSE,
		      "cookie domain must match the trailing portion of the hostname");
	/* trailing-slash issuer match in both directions */
	ck_assert_msg(oidc_util_cookie_domain_valid("www.example.com", "www.example.com") == TRUE,
		      "exact host must match itself");
}
END_TEST

START_TEST(test_util_issuer_match_trailing_slash) {
	/* trailing slash in either argument must be ignored */
	ck_assert_msg(oidc_util_issuer_match("https://id.example.com/", "https://id.example.com") == TRUE,
		      "trailing slash on a must be ignored");
	ck_assert_msg(oidc_util_issuer_match("https://id.example.com", "https://id.example.com/") == TRUE,
		      "trailing slash on b must be ignored");
	/* more than a trailing slash difference must not match */
	ck_assert_msg(oidc_util_issuer_match("https://id.example.com/foo", "https://id.example.com/bar") == FALSE,
		      "different paths must not match");
}
END_TEST

START_TEST(test_util_issuer_match_empty_and_null) {
	/* two empty strings are strictly equal and must match */
	ck_assert_msg(oidc_util_issuer_match("", "") == TRUE, "two empty issuers must match");

	/*
	 * an empty issuer differing only by a trailing slash must NOT match: the
	 * trailing-slash relaxation reduces the compare length to 0, which is
	 * rejected. This also exercises the empty-string edge of the [strlen-1]
	 * trailing-slash handling.
	 */
	ck_assert_msg(oidc_util_issuer_match("", "/") == FALSE, "empty vs \"/\" must not match");
	ck_assert_msg(oidc_util_issuer_match("/", "") == FALSE, "\"/\" vs empty must not match");

	/* a NULL issuer must never match anything, not even another NULL */
	ck_assert_msg(oidc_util_issuer_match(NULL, NULL) == FALSE, "two NULL issuers must not match");
	ck_assert_msg(oidc_util_issuer_match(NULL, "") == FALSE, "NULL vs empty must not match");
	ck_assert_msg(oidc_util_issuer_match("https://id.example.com", NULL) == FALSE,
		      "a real issuer must not match NULL");
}
END_TEST

START_TEST(test_util_set_trace_parent_flags) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_cmd_trace_parent_set(oidc_test_cmd_get(OIDCTraceParent), NULL, "generate");
	oidc_cmd_metrics_hook_data_set(oidc_test_cmd_get(OIDCMetricsData), NULL, "authn");

	oidc_request_state_set(r, OIDC_REQUEST_STATE_TRACE_ID, NULL);
	oidc_util_set_trace_parent(r, c, NULL);

	const char *tp = apr_table_get(r->headers_in, OIDC_HTTP_HDR_TRACE_PARENT);
	ck_assert_ptr_nonnull(tp);
	int len = (int)_oidc_strlen(tp);
	ck_assert_msg(len >= 2, "traceparent header too short");
	ck_assert_msg(_oidc_strncmp(&tp[len - 2], "01", 2) == 0,
		      "traceparent flags byte is not 01 when metrics hook is set");
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
	tcase_add_test(c, test_util_appinfo_array_delimiter_escape);
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
	tcase_add_test(c, test_util_file_read_symlink);
	tcase_add_test(c, test_util_file_read_open_fails_after_stat);
	tcase_add_test(c, test_util_file_read_too_large);
	tcase_add_test(c, test_util_file_read_server);
	tcase_add_test(c, test_util_file_write_rename_fails);
	tcase_add_test(c, test_util_file_write_hard_failure);
	suite_add_tcase(s, c);

	c = tcase_create("html");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_html_escape);
	tcase_add_test(c, test_util_html_content);
	tcase_add_test(c, test_util_html_template);
	tcase_add_test(c, test_util_html_template_escape_and_format);
	suite_add_tcase(s, c);

	c = tcase_create("jq");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_jq);
	suite_add_tcase(s, c);

	c = tcase_create("json");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_json);
	tcase_add_test(c, test_util_legacy_json_decode_object);
	suite_add_tcase(s, c);

	c = tcase_create("jwt");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_jwt);
	tcase_add_test(c, test_util_jwt_passphrase_rotation);
	tcase_add_test(c, test_util_jwt_without_derived_keys);
	tcase_add_test(c, test_util_jwt_without_subprocess_env);
	tcase_add_test(c, test_util_jwt_payload_that_looks_compressed);
	suite_add_tcase(s, c);

	c = tcase_create("key");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_key);
	tcase_add_test(c, test_util_key_sets_hash_merge_precedence);
	suite_add_tcase(s, c);

	c = tcase_create("random");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_random);
	suite_add_tcase(s, c);

	c = tcase_create("url");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_url);
	tcase_add_test(c, test_util_url_abs);
	tcase_add_test(c, test_util_url_matches);
	suite_add_tcase(s, c);

	c = tcase_create("util");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_strenv_and_casestr);
	tcase_add_test(c, test_util_strenv_length_and_casestr_edge);
	tcase_add_test(c, test_util_read_form_encoded_params);
	tcase_add_test(c, test_util_read_post_params_wrong_content_type);
	tcase_add_test(c, test_util_read_post_params_oversized);
	tcase_add_test(c, test_util_read_post_params);
	tcase_add_test(c, test_util_spaced_string_helpers);
	tcase_add_test(c, test_util_hex_and_hash);
	tcase_add_test(c, test_util_cookie_domain_and_issuer);
	tcase_add_test(c, test_util_cookie_domain_dot_prefix);
	tcase_add_test(c, test_util_issuer_match_trailing_slash);
	tcase_add_test(c, test_util_issuer_match_empty_and_null);
	tcase_add_test(c, test_util_set_trace_parent_flags);
	tcase_add_test(c, test_util_table_and_hash_clear_and_openssl);
	tcase_add_test(c, test_util_mask_value);
	tcase_add_test(c, test_util_apr_time_saturating);
#ifdef HAVE_LIBPCRE2
	tcase_add_test(c, test_util_pcre_get_substring_error_arms);
#endif
	tcase_add_test(c, test_util_pcre_compile_failure_allocates_nothing);
	suite_add_tcase(s, c);

	c = tcase_create("url-params");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_url_parameter_helpers);
	suite_add_tcase(s, c);

	c = tcase_create("json-string");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(c, test_util_json_string_and_encode);
	suite_add_tcase(s, c);

	return oidc_test_suite_run(s);
}
