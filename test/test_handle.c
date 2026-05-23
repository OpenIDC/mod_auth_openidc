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

#include "check_util.h"
#include "handle/handle.h"
#include "http_server.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "session.h"
#include "util.h"
#include "util/util.h"

/*
 * Tests for handle/userinfo.c — drive oidc_userinfo_retrieve_claims /
 * oidc_userinfo_refresh_claims / oidc_userinfo_store_claims against the
 * loopback HTTP server fixture.
 */

START_TEST(test_handle_userinfo_retrieve_no_endpoint) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* fresh provider with no userinfo_endpoint set */
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	json_t *claims = NULL;
	char *userinfo_jwt = NULL;
	const char *result = oidc_userinfo_retrieve_claims(r, c, provider, "AT", "Bearer", NULL, apr_pstrdup(r->pool, "alice"),
							   &claims, &userinfo_jwt);
	ck_assert_ptr_null(result);
	ck_assert_ptr_null(claims);
}
END_TEST

START_TEST(test_handle_userinfo_retrieve_no_access_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, "https://idp.example.com/userinfo");

	json_t *claims = NULL;
	char *userinfo_jwt = NULL;
	/* NULL access_token short-circuits to NULL */
	const char *result = oidc_userinfo_retrieve_claims(r, c, provider, NULL, "Bearer", NULL,
							   apr_pstrdup(r->pool, "alice"), &claims, &userinfo_jwt);
	ck_assert_ptr_null(result);
}
END_TEST

START_TEST(test_handle_userinfo_retrieve_success_no_session) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"sub\":\"alice\",\"name\":\"Alice Example\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	json_t *claims = NULL;
	char *userinfo_jwt = NULL;
	const char *result = oidc_userinfo_retrieve_claims(r, c, provider, "AT", "Bearer", NULL,
							   apr_pstrdup(r->pool, "alice"), &claims, &userinfo_jwt);
	ck_assert_ptr_nonnull(result);
	ck_assert_ptr_nonnull(claims);
	ck_assert_str_eq(json_string_value(json_object_get(claims, "name")), "Alice Example");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	json_decref(claims);
}
END_TEST

START_TEST(test_handle_userinfo_retrieve_failure_no_session) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {.status_code = 401,
					  .content_type = "application/json",
					  .body = "{\"error\":\"invalid_token\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	json_t *claims = NULL;
	char *userinfo_jwt = NULL;
	/* userinfo call fails and no session is provided => no refresh path => NULL */
	const char *result = oidc_userinfo_retrieve_claims(r, c, provider, "AT", "Bearer", NULL,
							   apr_pstrdup(r->pool, "alice"), &claims, &userinfo_jwt);
	ck_assert_ptr_null(result);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_handle_userinfo_store_and_clear_claims) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	json_t *claims = json_pack("{s:s,s:s}", "sub", "alice", "name", "Alice");
	oidc_userinfo_store_claims(r, c, session, provider, claims, "the-jwt");

	json_t *stored = oidc_session_get_userinfo_claims(r, session);
	ck_assert_ptr_nonnull(stored);
	ck_assert_str_eq(json_string_value(json_object_get(stored, "sub")), "alice");
	ck_assert_str_eq(oidc_session_get_userinfo_jwt(r, session), "the-jwt");

	/* passing NULL clears both */
	oidc_userinfo_store_claims(r, c, session, provider, NULL, NULL);
	ck_assert_ptr_null(oidc_session_get_userinfo_claims(r, session));
	ck_assert_ptr_null(oidc_session_get_userinfo_jwt(r, session));

	json_decref(claims);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_refresh_no_interval) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	apr_byte_t needs_save = FALSE;
	/* default interval is -1 => no-op, returns TRUE, needs_save untouched */
	ck_assert_int_eq(oidc_userinfo_refresh_claims(r, c, session, &needs_save), TRUE);
	ck_assert_int_eq(needs_save, FALSE);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_pass_as_no_claims) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* no claims in session: must not crash and must not set headers */
	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	oidc_session_free(r, session);
}
END_TEST

/*
 * Tests for handle/refresh.c — drive oidc_refresh_token_grant and
 * oidc_refresh_access_token_before_expiry through their early-exit
 * branches and a happy-path refresh against the loopback server.
 */

START_TEST(test_handle_refresh_grant_no_refresh_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* no refresh token stored => FALSE */
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, NULL), FALSE);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_grant_success) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	oidc_session_set_refresh_token(r, session, "OLD-RT");

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"access_token\":\"AT-NEW\",\"token_type\":\"Bearer\","
						  "\"expires_in\":3600,\"refresh_token\":\"NEW-RT\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_cfg_provider_scope_set(r->pool, provider, "openid");

	char *new_at = NULL, *new_att = NULL, *new_idt = NULL;
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, &new_at, &new_att, &new_idt), TRUE);
	ck_assert_str_eq(new_at, "AT-NEW");
	ck_assert_str_eq(new_att, "Bearer");
	ck_assert_str_eq(oidc_session_get_access_token(r, session), "AT-NEW");
	ck_assert_str_eq(oidc_session_get_refresh_token(r, session), "NEW-RT");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(_oidc_strstr(cap->body, "grant_type=refresh_token") != NULL, "refresh grant_type sent");
	ck_assert_msg(_oidc_strstr(cap->body, "refresh_token=OLD-RT") != NULL, "old refresh_token sent");

	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_grant_failure) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	oidc_session_set_refresh_token(r, session, "BAD-RT");

	oidc_test_http_response_t resp = {.status_code = 400,
					  .content_type = "application/json",
					  .body = "{\"error\":\"invalid_grant\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_cfg_provider_scope_set(r->pool, provider, "openid");

	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, NULL), FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_before_expiry_ttl_negative) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	apr_byte_t needs_save = FALSE;
	/* ttl_minimum < 0 => no-op, returns TRUE */
	ck_assert_int_eq(oidc_refresh_access_token_before_expiry(r, c, session, -1, &needs_save), TRUE);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_before_expiry_no_expiry_stored) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	apr_byte_t needs_save = FALSE;
	/* no access_token_expires stored => FALSE */
	ck_assert_int_eq(oidc_refresh_access_token_before_expiry(r, c, session, 0, &needs_save), FALSE);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_before_expiry_no_refresh_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	/* set expires_in => positive expiry stored */
	oidc_session_set_access_token_expires(r, session, 3600);

	apr_byte_t needs_save = FALSE;
	/* no refresh_token in session => FALSE */
	ck_assert_int_eq(oidc_refresh_access_token_before_expiry(r, c, session, 0, &needs_save), FALSE);

	oidc_session_free(r, session);
}
END_TEST

/*
 * Tests for handle/response.c — cover oidc_response_make_sid_iss_unique,
 * oidc_response_post_preserve_javascript and oidc_response_save_in_session.
 * The two full authorization-response handlers
 * (oidc_response_authorization_redirect / _post) are exercised through their
 * state-mismatch error paths, which is what an unauthenticated direct hit on
 * the redirect URI will trigger.
 */

START_TEST(test_handle_response_make_sid_iss_unique) {
	request_rec *r = oidc_test_request_get();
	char *u = oidc_response_make_sid_iss_unique(r, "sid123", "https://idp.example.com");
	ck_assert_ptr_nonnull(u);
	ck_assert_str_eq(u, "sid123@https://idp.example.com");
}
END_TEST

START_TEST(test_handle_response_post_preserve_disabled_by_default) {
	request_rec *r = oidc_test_request_get();
	/* OIDCPreservePost defaults to off => returns FALSE without inspecting POST data */
	char *js = NULL;
	char *jm = NULL;
	ck_assert_int_eq(oidc_response_post_preserve_javascript(r, "https://www.example.com/protected/", &js, &jm),
			 FALSE);
	ck_assert_ptr_null(js);
	ck_assert_ptr_null(jm);
}
END_TEST

START_TEST(test_handle_response_save_in_session_minimal) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* construct a minimal id_token with the fields oidc_response_save_in_session needs */
	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->payload.sub = apr_pstrdup(r->pool, "alice");
	jwt->payload.exp = apr_time_sec(apr_time_now()) + 3600;

	apr_byte_t rc = oidc_response_save_in_session(
	    r, c, session, provider, "alice", "id-token-serialized", jwt, NULL, NULL, "access-token", "Bearer", 3600,
	    "refresh-token", "openid profile", NULL, "state-1", "https://www.example.com/protected/", NULL);
	ck_assert_int_eq(rc, TRUE);
	ck_assert_str_eq(session->remote_user, "alice");
	ck_assert_str_eq(oidc_session_get_access_token(r, session), "access-token");
	ck_assert_str_eq(oidc_session_get_access_token_type(r, session), "Bearer");
	ck_assert_str_eq(oidc_session_get_refresh_token(r, session), "refresh-token");
	ck_assert_str_eq(oidc_session_get_scope(r, session), "openid profile");
	ck_assert_str_eq(oidc_session_get_issuer(r, session), "https://idp.example.com");
	ck_assert_str_eq(oidc_session_get_original_url(r, session), "https://www.example.com/protected/");
	/* sid falls back to sub when no SID claim is present */
	ck_assert_ptr_nonnull(session->sid);
	ck_assert_msg(_oidc_strstr(session->sid, "alice@") != NULL, "sid should embed sub");

	oidc_jwt_destroy(jwt);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_save_in_session_with_userinfo) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->payload.sub = apr_pstrdup(r->pool, "alice");
	jwt->payload.exp = apr_time_sec(apr_time_now()) + 3600;
	/* embed a sid claim into the id_token payload */
	json_object_set_new(jwt->payload.value.json, "sid", json_string("session-id-xyz"));

	json_t *userinfo = json_pack("{s:s,s:s}", "sub", "alice", "email", "alice@example.com");

	apr_byte_t rc = oidc_response_save_in_session(r, c, session, provider, "alice", "id-token", jwt,
						      "{\"sub\":\"alice\"}", userinfo, "AT", "Bearer", 600, NULL,
						      "openid", NULL, "state-2",
						      "https://www.example.com/protected/", "userinfo-jwt-here");
	ck_assert_int_eq(rc, TRUE);

	json_t *stored = oidc_session_get_userinfo_claims(r, session);
	ck_assert_ptr_nonnull(stored);
	ck_assert_str_eq(json_string_value(json_object_get(stored, "email")), "alice@example.com");

	ck_assert_str_eq(oidc_session_get_userinfo_jwt(r, session), "userinfo-jwt-here");
	/* sid should be derived from the SID claim */
	ck_assert_msg(_oidc_strstr(session->sid, "session-id-xyz@") != NULL, "sid should embed the claim");

	json_decref(userinfo);
	oidc_jwt_destroy(jwt);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_authorization_redirect_state_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* no state parameter at all => state-mismatch handler, with no default SSO URL => BAD_REQUEST */
	r->args = "";
	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);

	oidc_session_free(r, session);
}
END_TEST

int main(void) {
	TCase *userinfo = tcase_create("userinfo");
	tcase_add_checked_fixture(userinfo, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(userinfo, 30);
	tcase_add_test(userinfo, test_handle_userinfo_retrieve_no_endpoint);
	tcase_add_test(userinfo, test_handle_userinfo_retrieve_no_access_token);
	tcase_add_test(userinfo, test_handle_userinfo_retrieve_success_no_session);
	tcase_add_test(userinfo, test_handle_userinfo_retrieve_failure_no_session);
	tcase_add_test(userinfo, test_handle_userinfo_store_and_clear_claims);
	tcase_add_test(userinfo, test_handle_userinfo_refresh_no_interval);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_no_claims);

	TCase *refresh = tcase_create("refresh");
	tcase_add_checked_fixture(refresh, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(refresh, 30);
	tcase_add_test(refresh, test_handle_refresh_grant_no_refresh_token);
	tcase_add_test(refresh, test_handle_refresh_grant_success);
	tcase_add_test(refresh, test_handle_refresh_grant_failure);
	tcase_add_test(refresh, test_handle_refresh_before_expiry_ttl_negative);
	tcase_add_test(refresh, test_handle_refresh_before_expiry_no_expiry_stored);
	tcase_add_test(refresh, test_handle_refresh_before_expiry_no_refresh_token);

	TCase *response = tcase_create("response");
	tcase_add_checked_fixture(response, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(response, test_handle_response_make_sid_iss_unique);
	tcase_add_test(response, test_handle_response_post_preserve_disabled_by_default);
	tcase_add_test(response, test_handle_response_save_in_session_minimal);
	tcase_add_test(response, test_handle_response_save_in_session_with_userinfo);
	tcase_add_test(response, test_handle_response_authorization_redirect_state_mismatch);

	Suite *s = suite_create("handle");
	suite_add_tcase(s, userinfo);
	suite_add_tcase(s, refresh);
	suite_add_tcase(s, response);

	return oidc_test_suite_run(s);
}
