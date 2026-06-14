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

#include "cfg/dir.h"
#include "cfg/oauth.h"
#include "check_util.h"
#include "http_server.h"
#include "mod_auth_openidc.h"
#include "oauth.h"
#include "util.h"
#include "util/util.h"

/* oauth.c exports this as non-static but has no header declaration; the
 * metadata-retrieve tests below drive the helper directly to cover the
 * HTTP + JSON-decode branches */
extern apr_byte_t oidc_oauth_metadata_provider_retrieve(request_rec *r, oidc_cfg_t *cfg, const char *issuer,
							const char *url, oidc_json_t **j_metadata, char **response);

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

START_TEST(test_oauth_check_userid_introspection_cached) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	/* the AS response includes an "exp" claim so the result is eligible for caching */
	int exp_ts = (int)apr_time_sec(apr_time_now()) + 3600;
	const char *body =
	    apr_psprintf(r->pool, "{\"active\":true,\"sub\":\"alice\",\"exp\":%d,\"scope\":\"openid\"}", exp_ts);
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	e2e_set_introspection_endpoint(c, oidc_test_http_server_url(srv, r->pool));

	/* prime the cache via a real introspection */
	ck_assert_int_eq(oidc_oauth_check_userid(r, c, "AT-CACHE"), OK);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);

	/* clear r->user, then call again with the same token; the cache hit must satisfy us
	 * without going back to the (now-gone) introspection endpoint */
	r->user = NULL;
	ck_assert_int_eq(oidc_oauth_check_userid(r, c, "AT-CACHE"), OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "alice");
}
END_TEST

/*
 * Tests for the non-header bearer-token sources. The default
 * OIDCOAuthAcceptTokenAs is "header"; we flip it to query / cookie via
 * the cmd setter for these tests.
 */

START_TEST(test_oauth_bearer_from_query) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get("OIDCOAuthAcceptTokenAs");
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "query"));

	r->args = "access_token=AT-FROM-QUERY";

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), TRUE);
	ck_assert_str_eq(token, "AT-FROM-QUERY");
}
END_TEST

START_TEST(test_oauth_bearer_from_cookie) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get("OIDCOAuthAcceptTokenAs");
	/* the default cookie name is "PA.global" */
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "cookie"));

	apr_table_set(r->headers_in, "Cookie", "other=foo; PA.global=AT-FROM-COOKIE; bla=baz");

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), TRUE);
	ck_assert_str_eq(token, "AT-FROM-COOKIE");
}
END_TEST

/*
 * Tests for the local-JWT access-token validation path (no introspection
 * endpoint configured), which is reached via oidc_oauth_validate_token.
 */

START_TEST(test_oauth_bearer_from_basic_header) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	/* enable basic-scheme token acceptance and provide "Authorization: Basic <b64(user:AT-XYZ)>";
	 * oidc_oauth_token_from_basic must strip the "user:" prefix and return just the token */
	cmd_parms *cmd = oidc_test_cmd_get("OIDCOAuthAcceptTokenAs");
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "basic"));
	apr_table_set(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION, "Basic dXNlcjpBVC1YWVo=");

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), TRUE);
	ck_assert_ptr_nonnull(token);
	ck_assert_str_eq(token, "AT-XYZ");
}
END_TEST

START_TEST(test_oauth_bearer_from_basic_header_no_colon) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	cmd_parms *cmd = oidc_test_cmd_get("OIDCOAuthAcceptTokenAs");
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "basic"));
	/* b64("noseparator") — no colon in the decoded payload => token_from_basic returns NULL */
	apr_table_set(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION, "Basic bm9zZXBhcmF0b3I=");

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), FALSE);
	ck_assert_ptr_null(token);
}
END_TEST

START_TEST(test_oauth_check_userid_redirect_uri_jwks) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	/* point the request path at the configured OIDCRedirectURI and ask for ?jwks=:
	 * oidc_oauth_check_userid_redirect_uri must stamp r->user="" and return OK
	 * so the content handler can serve the JWKS document. */
	r->parsed_uri.path = apr_pstrdup(r->pool, "/protected/");
	r->args = "jwks=1";
	r->user = NULL;

	int rc = oidc_oauth_check_userid(r, c, NULL);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "");
}
END_TEST

START_TEST(test_oauth_check_userid_redirect_uri_remove_at_cache) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	/* same path but with ?remove_at_cache= — the dispatcher hands off to
	 * oidc_revoke_at_cache_remove which 404s on a cache miss. */
	r->parsed_uri.path = apr_pstrdup(r->pool, "/protected/");
	r->args = "remove_at_cache=AT-not-cached";

	int rc = oidc_oauth_check_userid(r, c, NULL);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);
}
END_TEST

START_TEST(test_oauth_metadata_provider_retrieve_success) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *body = "{\"issuer\":\"https://idp.example.com\","
			   "\"introspection_endpoint\":\"https://idp.example.com/introspect\"}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	cmd_parms *cmd_ssl = oidc_test_cmd_get(OIDCOAuthSSLValidateServer);
	ck_assert_ptr_null(oidc_cmd_oauth_ssl_validate_server_set(cmd_ssl, NULL, "Off"));

	oidc_json_t *metadata = NULL;
	char *response = NULL;
	ck_assert_int_eq(oidc_oauth_metadata_provider_retrieve(r, c, "https://idp.example.com",
							       oidc_test_http_server_url(srv, r->pool), &metadata,
							       &response),
			 TRUE);
	ck_assert_ptr_nonnull(metadata);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(metadata, "issuer")), "https://idp.example.com");

	oidc_json_decref(metadata);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_oauth_metadata_provider_retrieve_invalid_json) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* server replies with non-JSON content => decode-and-check-error fails => FALSE */
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "this is not json"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	cmd_parms *cmd_ssl = oidc_test_cmd_get(OIDCOAuthSSLValidateServer);
	ck_assert_ptr_null(oidc_cmd_oauth_ssl_validate_server_set(cmd_ssl, NULL, "Off"));

	oidc_json_t *metadata = NULL;
	char *response = NULL;
	ck_assert_int_eq(oidc_oauth_metadata_provider_retrieve(r, c, "https://idp.example.com",
							       oidc_test_http_server_url(srv, r->pool), &metadata,
							       &response),
			 FALSE);
	ck_assert_ptr_null(metadata);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_oauth_check_userid_jwt_no_keys_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);
	/* no introspection endpoint and no client_secret => oidc_util_key_symmetric_create
	 * cannot derive a verification key => the JWT validation path fails => 401 */
	int rc = oidc_oauth_check_userid(r, c, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.x");
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
	const char *hdr = apr_table_get(r->err_headers_out, "WWW-Authenticate");
	ck_assert_ptr_nonnull(hdr);
	ck_assert_msg(_oidc_strstr(hdr, "JWT token could not be validated") != NULL,
		      "the error description should reference JWT validation");
}
END_TEST

int main(void) {
	TCase *bearer = tcase_create("bearer");
	tcase_add_checked_fixture(bearer, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(bearer, test_oauth_bearer_from_header);
	tcase_add_test(bearer, test_oauth_bearer_from_header_with_leading_spaces);
	tcase_add_test(bearer, test_oauth_bearer_not_present);
	tcase_add_test(bearer, test_oauth_bearer_wrong_scheme);
	tcase_add_test(bearer, test_oauth_bearer_from_query);
	tcase_add_test(bearer, test_oauth_bearer_from_cookie);
	tcase_add_test(bearer, test_oauth_bearer_from_basic_header);
	tcase_add_test(bearer, test_oauth_bearer_from_basic_header_no_colon);

	TCase *introspect = tcase_create("introspect");
	tcase_add_checked_fixture(introspect, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(introspect, 30);
	tcase_add_test(introspect, test_oauth_check_userid_no_token);
	tcase_add_test(introspect, test_oauth_check_userid_options_no_token);
	tcase_add_test(introspect, test_oauth_check_userid_introspection_active);
	tcase_add_test(introspect, test_oauth_check_userid_introspection_inactive);
	tcase_add_test(introspect, test_oauth_check_userid_introspection_error_response);
	tcase_add_test(introspect, test_oauth_check_userid_introspection_cached);
	tcase_add_test(introspect, test_oauth_check_userid_redirect_uri_jwks);
	tcase_add_test(introspect, test_oauth_check_userid_redirect_uri_remove_at_cache);

	TCase *jwt = tcase_create("jwt");
	tcase_add_checked_fixture(jwt, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(jwt, test_oauth_check_userid_jwt_no_keys_configured);

	TCase *metadata = tcase_create("metadata");
	tcase_add_checked_fixture(metadata, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(metadata, 30);
	tcase_add_test(metadata, test_oauth_metadata_provider_retrieve_success);
	tcase_add_test(metadata, test_oauth_metadata_provider_retrieve_invalid_json);

	Suite *s = suite_create("oauth");
	suite_add_tcase(s, bearer);
	suite_add_tcase(s, introspect);
	suite_add_tcase(s, jwt);
	suite_add_tcase(s, metadata);

	return oidc_test_suite_run(s);
}
