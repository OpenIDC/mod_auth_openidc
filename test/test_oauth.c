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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include "cfg/oauth.h"
#include "check_util.h"
#include "http_server.h"
#include "mod_auth_openidc.h"
#include "oauth.h"
#include "util.h"
#include "util/util.h"

/*
 * Tests for oidc_oauth_get_bearer_token — exercise the Authorization-header
 * extraction path (default OIDCOAuthAcceptTokenAs setting is "header") and the
 * "no token anywhere" failure path.
 */

START_TEST(test_oauth_bearer_from_header) {
	request_rec *r = oidc_test_request_get();
	apr_table_set(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION, "Bearer AT-XYZ");

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), TRUE);
	ck_assert_ptr_nonnull(token);
	ck_assert_str_eq(token, "AT-XYZ");
}
END_TEST

START_TEST(test_oauth_bearer_from_header_with_leading_spaces) {
	request_rec *r = oidc_test_request_get();
	/* the parser must skip any whitespace between the scheme and the token */
	apr_table_set(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION, "Bearer    AT-PAD");

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), TRUE);
	ck_assert_str_eq(token, "AT-PAD");
}
END_TEST

START_TEST(test_oauth_bearer_not_present) {
	request_rec *r = oidc_test_request_get();
	/* make sure no Authorization header is set */
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), FALSE);
	ck_assert_ptr_null(token);
}
END_TEST

START_TEST(test_oauth_bearer_wrong_scheme) {
	request_rec *r = oidc_test_request_get();
	/* default OIDCOAuthAcceptTokenAs is "header" only; Basic-scheme auth is rejected */
	apr_table_set(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION, "Basic dXNlcjpwYXNz");

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), FALSE);
	ck_assert_ptr_null(token);
}
END_TEST

/*
 * Tests for oidc_oauth_check_userid — drive the introspection path
 * against the loopback HTTP server and cover both the no-token and the
 * inactive-token failure modes.
 */

START_TEST(test_oauth_check_userid_no_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	int rc = oidc_oauth_check_userid(r, c, NULL);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
	const char *hdr = apr_table_get(r->err_headers_out, "WWW-Authenticate");
	ck_assert_ptr_nonnull(hdr);
	ck_assert_msg(_oidc_strstr(hdr, "Bearer") != NULL, "WWW-Authenticate should advertise Bearer");
}
END_TEST

START_TEST(test_oauth_check_userid_options_no_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);
	r->method_number = M_OPTIONS;

	/* OPTIONS without a token is special-cased: returns OK with an empty user */
	int rc = oidc_oauth_check_userid(r, c, NULL);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "");
}
END_TEST

/* helper: wire the introspection endpoint to point at the test server and disable TLS validation */
static void e2e_set_introspection_endpoint(oidc_cfg_t *c, const char *url) {
	cmd_parms *cmd_ep = oidc_test_cmd_get(OIDCOAuthIntrospectionEndpoint);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_url_set(cmd_ep, NULL, url));
	cmd_parms *cmd_ssl = oidc_test_cmd_get(OIDCOAuthSSLValidateServer);
	ck_assert_ptr_null(oidc_cmd_oauth_ssl_validate_server_set(cmd_ssl, NULL, "Off"));
	(void)c;
}

START_TEST(test_oauth_check_userid_introspection_active) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"active\":true,\"sub\":\"alice\",\"scope\":\"openid\","
						  "\"client_id\":\"rp-1\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	e2e_set_introspection_endpoint(c, oidc_test_http_server_url(srv, r->pool));

	int rc = oidc_oauth_check_userid(r, c, "AT-VALID");
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "alice");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_msg(_oidc_strstr(cap->body, "token=AT-VALID") != NULL, "token sent in form body");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_oauth_check_userid_introspection_inactive) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"active\":false}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	e2e_set_introspection_endpoint(c, oidc_test_http_server_url(srv, r->pool));

	int rc = oidc_oauth_check_userid(r, c, "AT-INACTIVE");
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
	const char *hdr = apr_table_get(r->err_headers_out, "WWW-Authenticate");
	ck_assert_ptr_nonnull(hdr);
	ck_assert_msg(_oidc_strstr(hdr, "invalid_token") != NULL, "must signal invalid_token");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_oauth_check_userid_introspection_error_response) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	/* the AS returns a JSON error object — the introspection must fail */
	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"error\":\"invalid_token\",\"error_description\":\"expired\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	e2e_set_introspection_endpoint(c, oidc_test_http_server_url(srv, r->pool));

	int rc = oidc_oauth_check_userid(r, c, "AT-ERR");
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

int main(void) {
	TCase *bearer = tcase_create("bearer");
	tcase_add_checked_fixture(bearer, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(bearer, test_oauth_bearer_from_header);
	tcase_add_test(bearer, test_oauth_bearer_from_header_with_leading_spaces);
	tcase_add_test(bearer, test_oauth_bearer_not_present);
	tcase_add_test(bearer, test_oauth_bearer_wrong_scheme);

	TCase *introspect = tcase_create("introspect");
	tcase_add_checked_fixture(introspect, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(introspect, 30);
	tcase_add_test(introspect, test_oauth_check_userid_no_token);
	tcase_add_test(introspect, test_oauth_check_userid_options_no_token);
	tcase_add_test(introspect, test_oauth_check_userid_introspection_active);
	tcase_add_test(introspect, test_oauth_check_userid_introspection_inactive);
	tcase_add_test(introspect, test_oauth_check_userid_introspection_error_response);

	Suite *s = suite_create("oauth");
	suite_add_tcase(s, bearer);
	suite_add_tcase(s, introspect);

	return oidc_test_suite_run(s);
}
