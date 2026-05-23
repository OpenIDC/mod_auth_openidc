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

#include "cfg/cfg_int.h"
#include "cfg/dir.h"
#include "check_util.h"
#include "handle/handle.h"
#include "http_server.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "session.h"
#include "state.h"
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

START_TEST(test_handle_response_authorization_redirect_state_mismatch_with_sso_url) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* OIDCDefaultURL acts as a fallback for state-mismatch failures => 302 redirect */
	cmd_parms *cmd = oidc_test_cmd_get("OIDCDefaultURL");
	ck_assert_ptr_null(oidc_cmd_default_sso_url_set(cmd, NULL, "https://www.example.com/fallback"));

	r->args = "";
	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "https://www.example.com/fallback") != NULL, "redirect to OIDCDefaultURL");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_authorization_post_non_post_method) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* M_GET is the test fixture default => oidc_util_read_post_params returns FALSE
	 * => oidc_response_authorization_post short-circuits to HTTP_INTERNAL_SERVER_ERROR */
	r->method_number = M_GET;
	int rc = oidc_response_authorization_post(r, c, session);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_authorization_post_only_response_mode_fragment) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* POST body with only response_mode=fragment is treated as "no real data" =>
	 * the handler returns HTTP_INTERNAL_SERVER_ERROR via the "Invalid Request" path */
	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");
	const char *form = "response_mode=fragment";
	r->args = apr_pstrdup(r->pool, form);
	r->remaining = (apr_size_t)_oidc_strlen(form);

	int rc = oidc_response_authorization_post(r, c, session);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);

	oidc_session_free(r, session);
}
END_TEST

/* build a state cookie that oidc_response_proto_state_restore will accept, returning
 * the matching state fingerprint that the test must pass via the state query param */
static char *e2e_build_state_cookie(request_rec *r, oidc_cfg_t *c, const char *response_type) {
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "rndnonce");
	oidc_proto_state_set_state(ps, "s1");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/index.html");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_response_type(ps, response_type);
	oidc_proto_state_set_timestamp_now(ps);

	char *fingerprint = oidc_state_browser_fingerprint(r, c, "rndnonce");
	char *cookie = oidc_proto_state_to_cookie(r, c, ps);
	const char *cookie_name = oidc_state_cookie_name(r, fingerprint);
	apr_table_set(r->headers_in, "Cookie",
		      apr_psprintf(r->pool, "foo=bar; %s=%s; baz=zot", cookie_name, cookie));
	oidc_proto_state_destroy(ps);
	return fingerprint;
}

START_TEST(test_handle_response_authorization_redirect_error_param) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	char *state = e2e_build_state_cookie(r, c, OIDC_PROTO_RESPONSE_TYPE_CODE);
	/* state restoration succeeds; an "error" param is present so the handler maps to authorization_error */
	r->args = apr_psprintf(r->pool, "state=%s&error=invalid_request&error_description=Bad+request",
			       oidc_http_url_encode(r, state));
	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);

	oidc_session_free(r, session);
}
END_TEST

/* build an HS256-signed id_token signed with the symmetric key derived from the provider's
 * client_secret, with the standard claims that oidc_proto_validate_idtoken requires */
static char *e2e_sign_idtoken_hs256(request_rec *r, const char *issuer, const char *client_id, const char *sub,
				    const char *nonce, const char *secret) {
	apr_pool_t *pool = r->pool;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk), TRUE);
	ck_assert_ptr_nonnull(jwk);

	oidc_jwt_t *jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(pool, "HS256");
	json_object_set_new(jwt->payload.value.json, "iss", json_string(issuer));
	json_object_set_new(jwt->payload.value.json, "aud", json_string(client_id));
	json_object_set_new(jwt->payload.value.json, "sub", json_string(sub));
	json_object_set_new(jwt->payload.value.json, "nonce", json_string(nonce));
	apr_time_t now = apr_time_sec(apr_time_now());
	json_object_set_new(jwt->payload.value.json, "iat", json_integer(now));
	json_object_set_new(jwt->payload.value.json, "exp", json_integer(now + 600));
	/* keep payload.iss / .sub / .iat / .exp in sync with the JSON for the validator */
	jwt->payload.iss = apr_pstrdup(pool, issuer);
	jwt->payload.sub = apr_pstrdup(pool, sub);
	jwt->payload.iat = now;
	jwt->payload.exp = now + 600;

	ck_assert_int_eq(oidc_jwt_sign(pool, jwt, jwk, FALSE, &err), TRUE);
	char *cser = oidc_jose_jwt_serialize(pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
	return cser;
}

START_TEST(test_handle_response_authorization_redirect_code_flow_happy_path) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	const char *secret = "code-flow-shared-secret-long-enough";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);
	/* the token endpoint is on our loopback server */
	oidc_test_http_response_t resp = {0};
	resp.status_code = 200;
	resp.content_type = "application/json";
	/* build the id_token the token endpoint will return; signed HS256 with the same secret */
	char *id_token = e2e_sign_idtoken_hs256(r, "https://idp.example.com", "client_id", "alice", "nonce-code", secret);
	resp.body = apr_psprintf(r->pool,
				 "{\"access_token\":\"AT-1\",\"token_type\":\"Bearer\",\"expires_in\":3600,"
				 "\"refresh_token\":\"RT-1\",\"id_token\":\"%s\"}",
				 id_token);
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	/* proto_state mirrors what oidc_proto_request_auth would have stored: response_type=code,
	 * response_mode=query (matching the default for the redirect handler) and a pkce_state
	 * so the s256 verifier (the default PKCE method) can derive a verifier */
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "nonce-code");
	oidc_proto_state_set_state(ps, "s-code");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/index.html");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_response_type(ps, OIDC_PROTO_RESPONSE_TYPE_CODE);
	oidc_proto_state_set_response_mode(ps, OIDC_PROTO_RESPONSE_MODE_QUERY);
	oidc_proto_state_set_pkce_state(ps, "pkce-state-1234567890abcdef1234567890abcdef1234567890ab");
	oidc_proto_state_set_timestamp_now(ps);

	char *fingerprint = oidc_state_browser_fingerprint(r, c, "nonce-code");
	char *cookie = oidc_proto_state_to_cookie(r, c, ps);
	const char *cookie_name = oidc_state_cookie_name(r, fingerprint);
	apr_table_set(r->headers_in, "Cookie",
		      apr_psprintf(r->pool, "foo=bar; %s=%s; baz=zot", cookie_name, cookie));
	oidc_proto_state_destroy(ps);

	r->args = apr_psprintf(r->pool, "state=%s&code=the-auth-code", oidc_http_url_encode(r, fingerprint));

	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_str_eq(loc, "https://www.example.com/protected/index.html");
	/* the token endpoint exchange + id_token validation should have populated the session */
	ck_assert_str_eq(session->remote_user, "alice@idp.example.com");
	ck_assert_str_eq(oidc_session_get_access_token(r, session), "AT-1");
	ck_assert_str_eq(oidc_session_get_refresh_token(r, session), "RT-1");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_msg(_oidc_strstr(cap->body, "code=the-auth-code") != NULL,
		      "token endpoint must be hit with the authorization code");

	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_authorization_redirect_idtoken_happy_path) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* configure the provider with a client_secret so the HS256 id_token verification succeeds */
	const char *secret = "shared-secret-for-hs256-verification";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	/* build a proto_state with response_type=id_token and response_mode=query so the response
	 * mode reported by the redirect handler ("query") lines up with what's in the cookie */
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "nonce-1");
	oidc_proto_state_set_state(ps, "s1");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/index.html");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_response_type(ps, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN);
	oidc_proto_state_set_response_mode(ps, OIDC_PROTO_RESPONSE_MODE_QUERY);
	oidc_proto_state_set_timestamp_now(ps);

	char *fingerprint = oidc_state_browser_fingerprint(r, c, "nonce-1");
	char *cookie = oidc_proto_state_to_cookie(r, c, ps);
	const char *cookie_name = oidc_state_cookie_name(r, fingerprint);
	apr_table_set(r->headers_in, "Cookie",
		      apr_psprintf(r->pool, "foo=bar; %s=%s; baz=zot", cookie_name, cookie));
	oidc_proto_state_destroy(ps);

	char *id_token = e2e_sign_idtoken_hs256(r, "https://idp.example.com", "client_id", "alice", "nonce-1", secret);
	r->args = apr_psprintf(r->pool, "state=%s&id_token=%s", oidc_http_url_encode(r, fingerprint),
			       oidc_http_url_encode(r, id_token));

	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_str_eq(loc, "https://www.example.com/protected/index.html");
	ck_assert_ptr_nonnull(r->user);
	/* default OIDCRemoteUserClaim is "sub@" which post-fixes the username with the issuer */
	ck_assert_str_eq(r->user, "alice@idp.example.com");
	/* the session must now reflect the new authentication */
	ck_assert_str_eq(session->remote_user, "alice@idp.example.com");
	ck_assert_str_eq(oidc_session_get_issuer(r, session), "https://idp.example.com");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_authorization_redirect_unknown_response_type) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* state validates, but the response_type stored in the cookie is unsupported
	 * => oidc_response_flows fails => authorization_error => HTTP_BAD_REQUEST */
	char *state = e2e_build_state_cookie(r, c, "totally_bogus_flow");
	r->args = apr_psprintf(r->pool, "state=%s", oidc_http_url_encode(r, state));
	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);

	oidc_session_free(r, session);
}
END_TEST

/*
 * Tests for handle/discovery.c — cover the is_discovery_response classifier
 * and the request-side branches that don't require a configured metadata
 * directory or upstream OP.
 */

START_TEST(test_handle_is_discovery_response) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* the default args have neither iss nor disc_user => FALSE */
	ck_assert_int_eq(oidc_is_discovery_response(r, c), FALSE);

	/* iss parameter present => TRUE */
	r->args = "iss=https%3A%2F%2Fidp.example.com";
	ck_assert_int_eq(oidc_is_discovery_response(r, c), TRUE);

	/* disc_user parameter present => TRUE */
	r->args = "disc_user=alice%40example.com";
	ck_assert_int_eq(oidc_is_discovery_response(r, c), TRUE);
}
END_TEST

START_TEST(test_handle_discovery_request_external_url) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* configure an external discovery handler via the dir cmd */
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCDiscoverURL);
	ck_assert_ptr_null(oidc_cmd_dir_discover_url_set(cmd, dir_cfg, "https://disco.example.com/select"));

	int rc = oidc_discovery_request(r, c);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "https://disco.example.com/select?") != NULL,
		      "should redirect to the configured discovery handler");
	/* the target_link_uri/return-to and the callback (redirect_uri) must be present */
	ck_assert_msg(_oidc_strstr(loc, "target_link_uri=") != NULL, "redirect carries target_link_uri");
	ck_assert_msg(_oidc_strstr(loc, "oidc_callback=") != NULL, "redirect carries the callback URI");
}
END_TEST

START_TEST(test_handle_discovery_response_static_provider_redirects) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* iss matches the static provider's issuer and target_link_uri is on our host;
	 * no OIDCMetadataDir is configured so this falls into oidc_discovery_response_static,
	 * which dispatches to oidc_request_authenticate_user -> 302 to the authorization_endpoint */
	r->args = "iss=https%3A%2F%2Fidp.example.com"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2Fwhatever";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "https://idp.example.com/authorize") != NULL,
		      "redirect must hit the static authorization_endpoint");
}
END_TEST

START_TEST(test_handle_discovery_response_static_provider_iss_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* a different iss than the configured static provider's => INTERNAL_SERVER_ERROR */
	r->args = "iss=https%3A%2F%2Fother.example.com"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

START_TEST(test_handle_discovery_response_target_link_uri_open_redirect) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* iss is valid but target_link_uri points to a different host => open-redirect rejected */
	r->args = "iss=https%3A%2F%2Fidp.example.com"
		  "&target_link_uri=https%3A%2F%2Fevil.example.com%2Foops";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

START_TEST(test_handle_discovery_request_with_metadata_dir) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* point OIDCMetadataDir at a fresh temp dir with one provider entry, then
	 * exercise the form-generation branch of oidc_discovery_request */
	char *tmpl = apr_pstrdup(r->pool, "/tmp/oidc-test-disco.XXXXXX");
	ck_assert_msg(mkdtemp(tmpl) != NULL, "could not create temp metadata dir at %s", tmpl);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCMetadataDir);
	ck_assert_ptr_null(oidc_cmd_metadata_dir_set(cmd, NULL, tmpl));

	/* write minimum-viable provider + client metadata under the temp dir */
	const char *provider_json = "{\"issuer\":\"https://idp.example.com\","
				    "\"authorization_endpoint\":\"https://idp.example.com/authorize\","
				    "\"token_endpoint\":\"https://idp.example.com/token\","
				    "\"jwks_uri\":\"https://idp.example.com/jwks\","
				    "\"response_types_supported\":[\"code\"],"
				    "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}";
	apr_file_t *f = NULL;
	ck_assert_int_eq(apr_file_open(&f, apr_psprintf(r->pool, "%s/idp.example.com.provider", tmpl),
				       APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE,
				       APR_FPROT_UREAD | APR_FPROT_UWRITE, r->pool),
			 APR_SUCCESS);
	apr_size_t len = (apr_size_t)_oidc_strlen(provider_json);
	apr_file_write(f, provider_json, &len);
	apr_file_close(f);

	const char *client_json = "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\"}";
	ck_assert_int_eq(apr_file_open(&f, apr_psprintf(r->pool, "%s/idp.example.com.client", tmpl),
				       APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE,
				       APR_FPROT_UREAD | APR_FPROT_UWRITE, r->pool),
			 APR_SUCCESS);
	len = (apr_size_t)_oidc_strlen(client_json);
	apr_file_write(f, client_json, &len);
	apr_file_close(f);

	int rc = oidc_discovery_request(r, c);
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_discovery_response_no_target_link_uri_no_sso_url) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* iss is set so it looks like a discovery response, but there's no target_link_uri
	 * and no OIDCDefaultURL configured => INTERNAL_SERVER_ERROR */
	r->args = "iss=https%3A%2F%2Fidp.example.com";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

/*
 * Tests for handle/info.c — drive oidc_info_request through the early
 * validation branches and a happy-path JSON response.
 */

START_TEST(test_handle_info_unknown_format) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	r->args = "info=xml";
	int rc = oidc_info_request(r, c, session, FALSE);
	ck_assert_int_eq(rc, HTTP_UNSUPPORTED_MEDIA_TYPE);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_info_no_remote_user) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	r->args = "info=json";
	/* session->remote_user is NULL by default */
	int rc = oidc_info_request(r, c, session, FALSE);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_info_no_hook_data_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	session->remote_user = apr_pstrdup(r->pool, "alice");

	r->args = "info=json";
	/* no OIDCInfoHook directive applied => NOT_FOUND */
	int rc = oidc_info_request(r, c, session, FALSE);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_info_json_happy_path) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	session->remote_user = apr_pstrdup(r->pool, "alice");
	oidc_session_set_access_token(r, session, "AT-123");
	oidc_session_set_access_token_type(r, session, "Bearer");

	/* enable two of the info hook fields via the cmd setter */
	cmd_parms *cmd_iat = oidc_test_cmd_get(OIDCInfoHook);
	ck_assert_ptr_null(oidc_cmd_info_hook_data_set(cmd_iat, NULL, OIDC_HOOK_INFO_TIMESTAMP));
	cmd_parms *cmd_user = oidc_test_cmd_get(OIDCInfoHook);
	ck_assert_ptr_null(oidc_cmd_info_hook_data_set(cmd_user, NULL, OIDC_HOOK_INFO_SESSION_REMOTE_USER));

	r->args = "info=json&extend_session=false";
	int rc = oidc_info_request(r, c, session, FALSE);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "alice");

	oidc_session_free(r, session);
}
END_TEST

/*
 * Tests for handle/dpop.c — cover the disabled path, the missing-parameter
 * paths and the case where DPoP creation fails because no private keys are
 * configured.
 */

START_TEST(test_handle_dpop_disabled_by_default) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* OIDCDPoPMode defaults to off => the DPoP API is disabled => rc stays at HTTP_BAD_REQUEST */
	int rc = oidc_dpop_request(r, c);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);
}
END_TEST

/*
 * Helper that flips the (otherwise-undirective) DPoP API switch and sets
 * OIDC_DPOP_API_INSECURE so the loopback request_rec doesn't trip the
 * "remote_ip != local_ip" guard (both are NULL in the test fixture, and
 * _oidc_strnatcasecmp(NULL, NULL) deliberately returns -1).
 */
static void e2e_dpop_enable(request_rec *r, oidc_cfg_t *c) {
	c->dpop_api_enabled = 1;
	apr_table_set(r->subprocess_env, "OIDC_DPOP_API_INSECURE", "1");
}

START_TEST(test_handle_dpop_missing_access_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	e2e_dpop_enable(r, c);
	r->args = "";

	int rc = oidc_dpop_request(r, c);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);
}
END_TEST

START_TEST(test_handle_dpop_missing_url_parameter) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	e2e_dpop_enable(r, c);
	/* access_token is supplied but the url is not */
	r->args = "dpop=AT-xyz";

	int rc = oidc_dpop_request(r, c);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);
}
END_TEST

START_TEST(test_handle_dpop_create_fails_without_private_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	e2e_dpop_enable(r, c);
	/* both required params are present, but the test fixture has an empty private_keys array
	 * so oidc_proto_dpop_create cannot sign the proof and returns FALSE */
	r->args = "dpop=AT-xyz&url=https%3A%2F%2Frs.example.com%2Fapi";

	int rc = oidc_dpop_request(r, c);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

/*
 * Additional tests for handle/userinfo.c — exercise the
 * oidc_userinfo_refresh_claims happy path (interval > 0, session ready,
 * loopback userinfo endpoint) and the oidc_userinfo_pass_as dispatcher
 * for the "json" pass-as variant.
 */

START_TEST(test_handle_userinfo_refresh_with_interval) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"sub\":\"alice\",\"email\":\"alice@example.com\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	/* arm the session so the refresh logic decides to call the userinfo endpoint */
	oidc_session_set_issuer(r, session, "https://idp.example.com");
	oidc_session_set_access_token(r, session, "AT-1");
	oidc_session_set_access_token_type(r, session, "Bearer");
	oidc_session_set_userinfo_refresh_interval(r, session, 60);
	/* last_refresh defaults to 0 => long enough ago to trigger a refresh */

	apr_byte_t needs_save = FALSE;
	ck_assert_int_eq(oidc_userinfo_refresh_claims(r, c, session, &needs_save), TRUE);
	ck_assert_int_eq(needs_save, TRUE);

	json_t *stored = oidc_session_get_userinfo_claims(r, session);
	ck_assert_ptr_nonnull(stored);
	ck_assert_str_eq(json_string_value(json_object_get(stored, "email")), "alice@example.com");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_pass_as_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* seed the session with both claims and the JWT representation of those claims */
	json_t *claims = json_pack("{s:s}", "sub", "alice");
	oidc_session_set_userinfo_claims(r, session, claims);
	oidc_session_set_userinfo_jwt(r, session, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig-bytes");

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "jwt")));

	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	const char *hdr = apr_table_get(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_USERINFO_JWT);
	ck_assert_ptr_nonnull(hdr);
	ck_assert_str_eq(hdr, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig-bytes");

	json_decref(claims);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_pass_as_signed_jwt_without_private_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	json_t *claims = json_pack("{s:s}", "sub", "alice");
	oidc_session_set_userinfo_claims(r, session, claims);

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "signed_jwt")));

	/* the test fixture has an empty private_keys array, so signed-JWT creation
	 * silently fails and no header is set (the function is a void, this is its
	 * graceful-degradation path) */
	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	ck_assert_ptr_null(apr_table_get(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_SIGNED_JWT));

	json_decref(claims);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_pass_as_json) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* seed the session with userinfo claims and configure the dir to pass them as a JSON header */
	json_t *claims = json_pack("{s:s,s:s}", "sub", "alice", "groups", "admins");
	oidc_session_set_userinfo_claims(r, session, claims);

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, "json"));

	/* must not crash and must populate the OIDC_userinfo_json header on r->headers_in */
	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	const char *hdr = apr_table_get(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_USERINFO_JSON);
	ck_assert_ptr_nonnull(hdr);
	ck_assert_msg(_oidc_strstr(hdr, "\"sub\":\"alice\"") != NULL, "JSON-encoded userinfo should be passed as a header");

	json_decref(claims);
	oidc_session_free(r, session);
}
END_TEST

/*
 * Additional tests for handle/refresh.c — exercise the
 * oidc_refresh_token_request HTTP handler through its error and
 * happy-path branches.
 */

START_TEST(test_handle_refresh_request_no_return_to) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	r->args = "";
	/* no ?refresh=... in args => HTTP_INTERNAL_SERVER_ERROR */
	ck_assert_int_eq(oidc_refresh_token_request(r, c, session), HTTP_INTERNAL_SERVER_ERROR);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_request_no_access_token_param) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* valid return_to URL but no ?access_token= => 302 redirect with error_code=no_access_token */
	r->args = "refresh=https%3A%2F%2Fwww.example.com%2Fprotected%2F";
	ck_assert_int_eq(oidc_refresh_token_request(r, c, session), HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "error_code=no_access_token") != NULL, "missing access_token error reported");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_request_session_has_no_access_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	r->args = "refresh=https%3A%2F%2Fwww.example.com%2Fprotected%2F&access_token=AT-CLIENT";
	ck_assert_int_eq(oidc_refresh_token_request(r, c, session), HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "error_code=no_access_token_exists") != NULL, "missing session AT reported");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_request_access_token_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	oidc_session_set_access_token(r, session, "AT-SERVER");

	r->args = "refresh=https%3A%2F%2Fwww.example.com%2Fprotected%2F&access_token=AT-OTHER";
	ck_assert_int_eq(oidc_refresh_token_request(r, c, session), HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "error_code=no_access_token_match") != NULL, "XSRF mismatch reported");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_request_happy_path) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"access_token\":\"AT-NEW\",\"token_type\":\"Bearer\","
						  "\"expires_in\":3600,\"refresh_token\":\"RT-NEW\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_cfg_provider_scope_set(r->pool, provider, "openid");

	/* session must carry an issuer (for provider lookup) and a matching access token */
	oidc_session_set_issuer(r, session, "https://idp.example.com");
	oidc_session_set_access_token(r, session, "AT-MATCHING");
	oidc_session_set_refresh_token(r, session, "RT-OLD");

	r->args = "refresh=https%3A%2F%2Fwww.example.com%2Fprotected%2F&access_token=AT-MATCHING";
	ck_assert_int_eq(oidc_refresh_token_request(r, c, session), HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	/* on success the Location header is the return_to URL with no error_code appended */
	ck_assert_msg(_oidc_strstr(loc, "error_code=") == NULL, "no error code on the happy path");
	ck_assert_msg(_oidc_strstr(loc, "https://www.example.com/protected/") != NULL, "redirected to return_to");
	/* and the session reflects the refreshed tokens */
	ck_assert_str_eq(oidc_session_get_access_token(r, session), "AT-NEW");
	ck_assert_str_eq(oidc_session_get_refresh_token(r, session), "RT-NEW");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

/*
 * Tests migrated from the legacy test/test.c TST_ASSERT-based suite covering
 * the Require-claim authz worker, remote-user claim mapping, the
 * is-auth-capable heuristics, open-redirect prevention and cookie-domain checks.
 */

/* helper that re-applies the same Require-claim pattern used throughout the legacy tests */
static authz_status _legacy_authz(request_rec *r, json_t *json, const char *require_args) {
	ap_expr_info_t *parsed = (ap_expr_info_t *)apr_pcalloc(r->pool, sizeof(ap_expr_info_t));
	parsed->filename = require_args;
	return oidc_authz_24_worker(r, json, require_args, parsed, oidc_authz_match_claim);
}

START_TEST(test_handle_legacy_authz_worker) {
	request_rec *r = oidc_test_request_get();
	r->user = "dummy";

	const char *claims = "{"
			     "\"sub\":\"stef\","
			     "\"areal\":1.1,"
			     "\"anull\":null,"
			     "\"anint\":99,"
			     "\"anegativeint\":-99,"
			     "\"aminusoneint\":-1,"
			     "\"nested\":{\"level1\":{\"level2\":\"hans\"},"
			     "\"nestedarray\":[\"b\",\"c\",true,\"false\",[\"d\",\"e\"]],"
			     "\"somebool\":false},"
			     "\"somearray\":[\"one\",\"two\",\"three\"],"
			     "\"somebool\":false,"
			     "\"realm_access\":{\"roles\":[\"someRole1\",\"someRole2\"]},"
			     "\"resource_access\":{\"someClient\":{\"roles\":[\"someRole3\",\"someRole4\"]}},"
			     "\"https://test.com/pay\":\"alot\","
			     "\"https://company.com/productAccess\":[\"snake2\",\"snake2ref\",\"fxt\"]"
			     "}";
	json_error_t err;
	json_t *json = json_loads(claims, 0, &err);
	ck_assert_msg(json != NULL, "JSON parsed [%s]", err.text);

	/* simple sub claim — denied / granted */
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim sub:hans"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim sub:stef"), AUTHZ_GRANTED);

	/* nested-dotted-path claims */
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim nested.level1.level2:hans"), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim nested.nestedarray:a"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim nested.nestedarray:c"), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim nested.level1:a"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim somebool:a"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim somebool.level1:a"), AUTHZ_DENIED);

	/* Keycloak-style role checks */
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim realm_access.roles:someRole1"), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim resource_access.someClient.roles:someRole4"),
			 AUTHZ_GRANTED);

	/* namespaced (URI-shaped) keys */
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim https://test.com/pay:alot"), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim https://company.com/productAccess:snake2"),
			 AUTHZ_GRANTED);

	/* PCRE expressions */
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim nested.level1.level2~.an."), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim nested.level1.level2~zan."), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim nested.nestedarray~."), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim nested.nestedarray~.b"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim email~...$"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim sub~...$"), AUTHZ_GRANTED);

	/* numeric / null comparisons */
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim areal:1.1"), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim anull:null"), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim areal:null"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim anint:99"), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim anint:100"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim anegativeint:-99"), AUTHZ_GRANTED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim anegativeint:$99"), AUTHZ_DENIED);
	ck_assert_int_eq(_legacy_authz(r, json, "Require claim aminusoneint:-1"), AUTHZ_GRANTED);

	json_decref(json);
}
END_TEST

START_TEST(test_handle_legacy_remote_user) {
	request_rec *r = oidc_test_request_get();
	char *remote_user = NULL;
	json_t *json = NULL;

	/* simple username extracted by regex first-match (no replace) */
	ck_assert_int_eq(oidc_util_json_decode_object(r, "{\"upn\":\"nneul@umsystem.edu\"}", &json), TRUE);
	oidc_get_remote_user(r, "upn", "^(.*)@umsystem\\.edu", NULL, json, &remote_user);
	ck_assert_str_eq(remote_user, "nneul");
	ck_assert_int_eq(oidc_get_remote_user(r, "upn", "^(.*)@umsystem\\.edu", "$1", json, &remote_user), TRUE);
	ck_assert_str_eq(remote_user, "nneul");
	json_decref(json);

	/* regex with replace expression that swaps captured groups */
	json = NULL;
	ck_assert_int_eq(oidc_util_json_decode_object(r, "{\"email\":\"nneul@umsystem.edu\"}", &json), TRUE);
	ck_assert_int_eq(oidc_get_remote_user(r, "email", "^(.*)@([^.]+)\\..+$", "$2\\$1", json, &remote_user), TRUE);
	ck_assert_str_eq(remote_user, "umsystem\\nneul");
	json_decref(json);

	/* UTF-8 username — must round-trip through the replace expression intact */
	json = NULL;
	ck_assert_int_eq(oidc_util_json_decode_object(r, "{ \"name\": \"Dominik František Bučík\" }", &json), TRUE);
	ck_assert_int_eq(oidc_get_remote_user(r, "name", "^(.*)$", "$1@test.com", json, &remote_user), TRUE);
	ck_assert_str_eq(remote_user, "Dominik František Bučík@test.com");
	json_decref(json);

	json = NULL;
	ck_assert_int_eq(oidc_util_json_decode_object(r, "{ \"preferred_username\": \"dbucik\" }", &json), TRUE);
	ck_assert_int_eq(oidc_get_remote_user(r, "preferred_username", "^(.*)$", "$1@test.com", json, &remote_user),
			 TRUE);
	ck_assert_str_eq(remote_user, "dbucik@test.com");
	json_decref(json);
}
END_TEST

START_TEST(test_handle_legacy_is_auth_capable_request) {
	request_rec *r = oidc_test_request_get();

	apr_table_set(r->headers_in, "Accept", "*/*");
	ck_assert_int_eq(oidc_is_auth_capable_request(r), TRUE);

	apr_table_set(r->headers_in, "X-Requested-With", "XMLHttpRequest");
	ck_assert_int_eq(oidc_is_auth_capable_request(r), FALSE);
	apr_table_unset(r->headers_in, "X-Requested-With");

	apr_table_set(r->headers_in, "Sec-Fetch-Mode", "navigate");
	ck_assert_int_eq(oidc_is_auth_capable_request(r), TRUE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Mode");

	apr_table_set(r->headers_in, "Sec-Fetch-Mode", "cors");
	ck_assert_int_eq(oidc_is_auth_capable_request(r), FALSE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Mode");

	apr_table_set(r->headers_in, "Sec-Fetch-Dest", "iframe");
	ck_assert_int_eq(oidc_is_auth_capable_request(r), FALSE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Dest");

	apr_table_set(r->headers_in, "Sec-Fetch-Dest", "image");
	ck_assert_int_eq(oidc_is_auth_capable_request(r), FALSE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Dest");

	apr_table_set(r->headers_in, "Sec-Fetch-Dest", "document");
	ck_assert_int_eq(oidc_is_auth_capable_request(r), TRUE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Dest");

	apr_table_set(r->headers_in, "Accept", "application/json");
	ck_assert_int_eq(oidc_is_auth_capable_request(r), FALSE);
	apr_table_unset(r->headers_in, "Accept");
}
END_TEST

START_TEST(test_handle_legacy_open_redirect) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	char *err_str = NULL, *err_desc = NULL;

	/* a same-host URL is allowed; a different-host URL is not */
	ck_assert_int_eq(oidc_validate_redirect_url(r, c, "https://www.example.com/somewhere", TRUE, &err_str, &err_desc),
			 TRUE);
	ck_assert_int_eq(oidc_validate_redirect_url(r, c, "https://evil.example.com/somewhere", TRUE, &err_str, &err_desc),
			 FALSE);

	/* now walk the open-redirect payload list — every entry must be REJECTED */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	const char *filename = apr_psprintf(r->pool, "%s/%s", dir, "open-redirect-payload-list.txt");
	apr_file_t *f = NULL;
	apr_status_t rv = apr_file_open(&f, filename, APR_READ, APR_OS_DEFAULT, r->pool);
	ck_assert_msg(rv == APR_SUCCESS, "could not open open-redirect-payload-list.txt at %s", filename);

	char line_buf[8096];
	while (apr_file_gets(line_buf, sizeof(line_buf), f) == APR_SUCCESS) {
		size_t line_s = _oidc_strlen(line_buf);
		if (line_s > 0 && line_buf[line_s - 1] == '\n')
			line_buf[line_s - 1] = '\0';
		err_str = NULL;
		err_desc = NULL;
		ck_assert_msg(oidc_validate_redirect_url(r, c, line_buf, TRUE, &err_str, &err_desc) == FALSE,
			      "open-redirect payload was accepted: %s", line_buf);
	}
	apr_file_close(f);
}
END_TEST

START_TEST(test_handle_legacy_check_cookie_domain) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_session_t *session = NULL;

	oidc_session_load(r, &session);
	oidc_session_set_cookie_domain(r, session, "ab001sb161djbn.xyz.com");
	apr_table_set(r->headers_in, "Host", "ab001SB161djbn.xyz.com");

	ck_assert_int_eq(oidc_check_cookie_domain(r, c, session), TRUE);
	ck_assert_int_eq(oidc_request_check_cookie_domain(r, c, "https://WWW.example.com/protected/index.html"), TRUE);

	c->cookie_domain = ".XYZ.com";
	ck_assert_int_eq(
	    oidc_request_check_cookie_domain(r, c, "https://ab001sb161djbn.xyz.com/protected/index.html"), TRUE);

	c->cookie_domain = "ab001SB161djbn.xyz.com";
	ck_assert_int_eq(
	    oidc_request_check_cookie_domain(r, c, "https://ab001sb161djbn.xyz.com/protected/index.html"), TRUE);

	c->cookie_domain = NULL;
	oidc_session_free(r, session);
}
END_TEST

/*
 * Tests for handle/revoke.c — oidc_revoke_session and oidc_revoke_at_cache_remove.
 */

START_TEST(test_handle_revoke_session_no_id) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* no ?revoke_session= => BAD_REQUEST */
	r->args = "";
	int rc = oidc_revoke_session(r, c);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);
}
END_TEST

START_TEST(test_handle_revoke_session_server_cache) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* test fixture uses server-cache session type; cache_set with NULL value returns TRUE => OK */
	r->args = "revoke_session=session-uuid-1";
	int rc = oidc_revoke_session(r, c);
	ck_assert_int_eq(rc, OK);
	ck_assert_str_eq(r->user, "");
}
END_TEST

START_TEST(test_handle_revoke_at_cache_remove_not_cached) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	r->args = "remove_at_cache=AT-not-in-cache";
	int rc = oidc_revoke_at_cache_remove(r, c);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);
}
END_TEST

START_TEST(test_handle_revoke_at_cache_remove_cached) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* prime the AT cache then remove */
	oidc_cache_set_access_token(r, "AT-cached", "{\"sub\":\"alice\"}", apr_time_now() + apr_time_from_sec(3600));
	r->args = "remove_at_cache=AT-cached";
	int rc = oidc_revoke_at_cache_remove(r, c);
	ck_assert_int_eq(rc, OK);
}
END_TEST

/*
 * Tests for handle/session_management.c — oidc_session_management entry point.
 */

START_TEST(test_handle_session_management_no_cmd) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	r->args = "";
	int rc = oidc_session_management(r, c, session);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_session_management_unknown_cmd) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	r->args = "session=something_unrecognized";
	int rc = oidc_session_management(r, c, session);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_session_management_logout) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* session=logout maps to oidc_logout_request with the OIDCDefaultSLOURL as the URL */
	r->args = "session=logout";
	int rc = oidc_session_management(r, c, session);
	/* no OIDCDefaultSLOURL configured => the logout helper renders the "Logged Out" HTML page */
	ck_assert_int_eq(rc, OK);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_session_management_iframe_op_unconfigured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* check_session_iframe not configured on the static provider => NOT_FOUND */
	r->args = "session=iframe_op";
	int rc = oidc_session_management(r, c, session);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_session_management_iframe_op_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_cfg_provider_check_session_iframe_set(r->pool, provider, "https://idp.example.com/check-session");

	r->args = "session=iframe_op";
	int rc = oidc_session_management(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	ck_assert_str_eq(apr_table_get(r->headers_out, "Location"), "https://idp.example.com/check-session");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_session_management_iframe_rp_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_cfg_provider_check_session_iframe_set(r->pool, provider, "https://idp.example.com/check-session");
	/* client_id is already "client_id" by default => iframe_rp generates the JS body */

	r->args = "session=iframe_rp";
	int rc = oidc_session_management(r, c, session);
	ck_assert_int_eq(rc, OK);

	oidc_session_free(r, session);
}
END_TEST

/*
 * Tests for mod_auth_openidc.c oidc_check_user_id — the main Apache
 * authentication hook.
 *
 * ap_auth_type() in the test stub always returns "openid-connect", so
 * oidc_enabled is TRUE and the dispatcher routes to the OIDC branch.
 */

START_TEST(test_handle_check_user_id_unauthenticated_redirects_to_op) {
	request_rec *r = oidc_test_request_get();

	/* oidc_handle_unauthenticated_user rejects non-auth-capable requests up-front
	 * with 401; setting Accept to a wildcard takes the request through the
	 * authentication dispatch => 302 to the authorization_endpoint */
	apr_table_set(r->headers_in, "Accept", "*/*");

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "https://idp.example.com/authorize") != NULL,
		      "redirect must target the configured authorization_endpoint, got: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "client_id=client_id") != NULL,
		      "authn request must carry the configured client_id");
	ck_assert_msg(_oidc_strstr(loc, "response_type=code") != NULL, "authn request defaults to code flow");
}
END_TEST

START_TEST(test_handle_check_user_id_unauthenticated_not_auth_capable) {
	request_rec *r = oidc_test_request_get();

	/* without a wildcard Accept and without OIDCUnAuthExpr the request is not
	 * considered auth-capable (likely an XHR-style call) => 401 instead of 302 */
	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

START_TEST(test_handle_check_user_id_unauth_action_pass) {
	request_rec *r = oidc_test_request_get();

	/* OIDCUnAuthAction "pass" => no session + no redirect, just set r->user="" and OK */
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get("OIDCUnAuthAction");
	ck_assert_ptr_null(oidc_cmd_dir_unauth_action_set(cmd, dir_cfg, "pass", NULL));

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "");
}
END_TEST

START_TEST(test_handle_check_user_id_unauth_action_return_401) {
	request_rec *r = oidc_test_request_get();

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get("OIDCUnAuthAction");
	ck_assert_ptr_null(oidc_cmd_dir_unauth_action_set(cmd, dir_cfg, "401", NULL));

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

START_TEST(test_handle_check_user_id_unauth_action_return_410) {
	request_rec *r = oidc_test_request_get();

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get("OIDCUnAuthAction");
	ck_assert_ptr_null(oidc_cmd_dir_unauth_action_set(cmd, dir_cfg, "410", NULL));

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, HTTP_GONE);
}
END_TEST

/*
 * Tests for handle/jwks.c and handle/content.c
 */

START_TEST(test_handle_jwks_request_empty_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* the fixture has an empty public_keys array => return "{ keys: [] }" with OK */
	int rc = oidc_jwks_request(r, c);
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_content_handler_jwks) {
	request_rec *r = oidc_test_request_get();

	/* match the configured OIDCRedirectURI path */
	r->parsed_uri.path = apr_pstrdup(r->pool, "/protected/");
	r->args = "jwks";
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_content_handler_unknown_redirect_uri_request) {
	request_rec *r = oidc_test_request_get();

	/* matches redirect URI but the request carries none of the recognized parameters */
	r->parsed_uri.path = apr_pstrdup(r->pool, "/protected/");
	r->args = "";
	int rc = oidc_content_handler(r);
	/* the unknown-redirect-URI-request branch leaves rc at OK */
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_content_handler_non_redirect_no_state) {
	request_rec *r = oidc_test_request_get();

	/* path does NOT match the configured OIDCRedirectURI and no request state hints are set
	 * => the dispatcher silently falls through with rc=DECLINED */
	r->parsed_uri.path = apr_pstrdup(r->pool, "/somewhere/else");
	r->args = "";
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, DECLINED);
}
END_TEST

/*
 * Tests for handle/logout.c — drive oidc_logout and oidc_logout_request
 * through the local-logout, front-channel and backchannel branches that
 * the existing test_logout_request doesn't reach.
 */

START_TEST(test_handle_logout_op_request_with_id_token_hint) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* configure end_session_endpoint + seed the session with an id_token + issuer so
	 * oidc_logout_build_op_request injects id_token_hint into the OP request URL */
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(provider));
	oidc_session_set_idtoken(r, session, "stored-id-token-jwt-here");
	oidc_cfg_provider_end_session_endpoint_set(r->pool, provider, "https://idp.example.com/endsession");

	r->args = "logout=https%3A%2F%2Fwww.example.com%2Floggedout";
	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	/* the resulting URL must contain the end_session_endpoint, the post_logout_redirect_uri
	 * and an id_token_hint that round-trips through oidc_http_url_encode */
	ck_assert_msg(_oidc_strstr(loc, "https://idp.example.com/endsession?") != NULL,
		      "must redirect to the end_session_endpoint");
	ck_assert_msg(_oidc_strstr(loc, "id_token_hint=stored-id-token-jwt-here") != NULL,
		      "must propagate the id_token_hint from the session");
	ck_assert_msg(_oidc_strstr(loc, "post_logout_redirect_uri=https%3A%2F%2Fwww.example.com%2Floggedout") != NULL,
		      "must url-encode and append the post_logout_redirect_uri");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_op_request_no_session_no_extra_params) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* end_session_endpoint configured, session has no idtoken (empty session) and no
	 * logout_request_params on the provider => the redirect URL has only the
	 * post_logout_redirect_uri appended */
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(provider));
	oidc_cfg_provider_end_session_endpoint_set(r->pool, provider, "https://idp.example.com/endsession?fixed=1");

	r->args = "logout=https%3A%2F%2Fwww.example.com%2Floggedout";
	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	/* end_session_endpoint already contains '?' so the next param must be appended with '&' */
	ck_assert_msg(_oidc_strstr(loc, "https://idp.example.com/endsession?fixed=1&"
					"post_logout_redirect_uri=https%3A%2F%2Fwww.example.com%2Floggedout") != NULL,
		      "Location must preserve existing query and use '&' as the separator: got %s", loc);
	/* no id_token_hint and no logout_request_params should land here */
	ck_assert_msg(_oidc_strstr(loc, "id_token_hint=") == NULL, "no id_token_hint expected");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_local_no_return_url) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* no ?logout= and no end_session_endpoint configured => local-logout HTML response */
	r->args = "";
	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, OK);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_local_with_return_url) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* return URL pointing to our hostname is accepted by the open-redirect guard */
	r->args = "logout=https%3A%2F%2Fwww.example.com%2Flogged-out";
	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	ck_assert_str_eq(apr_table_get(r->headers_out, "Location"), "https://www.example.com/logged-out");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_invalid_return_url) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a return URL on a different host is rejected as a potential open redirect */
	r->args = "logout=https%3A%2F%2Fevil.example.com%2Foops";
	int rc = oidc_logout(r, c, session);
	ck_assert_int_ne(rc, HTTP_MOVED_TEMPORARILY);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_request_no_url_no_session) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* direct entry: no session, no URL => "Logged Out" HTML page */
	int rc = oidc_logout_request(r, c, session, NULL, FALSE);
	ck_assert_int_eq(rc, OK);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_request_frontchannel_get) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* front-channel "get" style: spec-compliant iframe logout; OP supplies sid+iss */
	r->args = "logout=get&sid=session-id&iss=https%3A%2F%2Fidp.example.com";
	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, OK);
	/* the recommended caching headers must be emitted */
	const char *cc = apr_table_get(r->err_headers_out, "Cache-Control");
	ck_assert_ptr_nonnull(cc);
	ck_assert_msg(_oidc_strstr(cc, "no-cache") != NULL, "front-channel logout must set no-cache");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_request_frontchannel_img) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* "img" style returns a transparent pixel rather than an HTML body */
	r->args = "logout=img";
	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, OK);

	oidc_session_free(r, session);
}
END_TEST

/* build a backchannel-logout JWT with the spec-required events claim, HS256-signed
 * with the given symmetric secret (default: NULL events claim is omitted, default:
 * NULL nonce claim is omitted) */
static char *e2e_sign_backchannel_logout_jwt(request_rec *r, const char *iss, const char *aud, const char *sub,
					     const char *jti, apr_byte_t with_events, apr_byte_t with_nonce,
					     const char *secret) {
	apr_pool_t *pool = r->pool;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk), TRUE);
	ck_assert_ptr_nonnull(jwk);

	oidc_jwt_t *jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(pool, "HS256");
	json_object_set_new(jwt->payload.value.json, "iss", json_string(iss));
	json_object_set_new(jwt->payload.value.json, "aud", json_string(aud));
	json_object_set_new(jwt->payload.value.json, "sub", json_string(sub));
	json_object_set_new(jwt->payload.value.json, "jti", json_string(jti));
	apr_time_t now = apr_time_sec(apr_time_now());
	json_object_set_new(jwt->payload.value.json, "iat", json_integer(now));
	if (with_events) {
		json_t *events = json_object();
		json_object_set_new(events, "http://schemas.openid.net/event/backchannel-logout", json_object());
		json_object_set_new(jwt->payload.value.json, "events", events);
	}
	if (with_nonce)
		json_object_set_new(jwt->payload.value.json, "nonce", json_string("n1"));
	jwt->payload.iss = apr_pstrdup(pool, iss);
	jwt->payload.sub = apr_pstrdup(pool, sub);
	jwt->payload.iat = now;

	ck_assert_int_eq(oidc_jwt_sign(pool, jwt, jwk, FALSE, &err), TRUE);
	char *cser = oidc_jose_jwt_serialize(pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
	return cser;
}

/* prepare a POST body the way oidc_util_read_post_params expects it */
static void e2e_post_body(request_rec *r, const char *body) {
	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");
	r->args = apr_pstrdup(r->pool, body);
	r->remaining = (apr_size_t)_oidc_strlen(body);
}

START_TEST(test_handle_logout_backchannel_happy_path) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	const char *secret = "backchannel-logout-shared-secret-XYZ";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	char *logout_jwt = e2e_sign_backchannel_logout_jwt(r, "https://idp.example.com", "client_id", "alice",
							    "jti-1", TRUE, FALSE, secret);
	char *body = apr_psprintf(r->pool, "logout_token=%s", oidc_http_url_encode(r, logout_jwt));
	e2e_post_body(r, body);
	apr_table_set(r->subprocess_env, "OIDC_REDIRECT_URI_REQUEST", "backchannel");
	r->args = apr_pstrcat(r->pool, "logout=backchannel&", body, NULL);
	r->remaining = (apr_size_t)_oidc_strlen(r->args);

	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, OK);
	/* the recommended caching headers should have been emitted */
	const char *cc = apr_table_get(r->err_headers_out, "Cache-Control");
	ck_assert_ptr_nonnull(cc);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_backchannel_missing_events_claim) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	const char *secret = "backchannel-logout-shared-secret-XYZ";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	/* JWT signs and verifies, but no events claim => spec violation => BAD_REQUEST */
	char *logout_jwt = e2e_sign_backchannel_logout_jwt(r, "https://idp.example.com", "client_id", "alice",
							    "jti-2", FALSE, FALSE, secret);
	char *body = apr_psprintf(r->pool, "logout_token=%s", oidc_http_url_encode(r, logout_jwt));
	e2e_post_body(r, body);
	r->args = apr_pstrcat(r->pool, "logout=backchannel&", body, NULL);
	r->remaining = (apr_size_t)_oidc_strlen(r->args);

	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_backchannel_nonce_claim_rejected) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	const char *secret = "backchannel-logout-shared-secret-XYZ";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	/* a logout token containing a "nonce" claim is rejected per OIDC backchannel spec */
	char *logout_jwt = e2e_sign_backchannel_logout_jwt(r, "https://idp.example.com", "client_id", "alice",
							    "jti-3", TRUE, TRUE, secret);
	char *body = apr_psprintf(r->pool, "logout_token=%s", oidc_http_url_encode(r, logout_jwt));
	e2e_post_body(r, body);
	r->args = apr_pstrcat(r->pool, "logout=backchannel&", body, NULL);
	r->remaining = (apr_size_t)_oidc_strlen(r->args);

	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_backchannel_no_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* POST to the backchannel endpoint without a logout_token => BAD_REQUEST */
	r->args = "logout=backchannel";
	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");
	r->remaining = 0;
	int rc = oidc_logout(r, c, session);
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
	tcase_add_test(userinfo, test_handle_userinfo_refresh_with_interval);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_no_claims);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_jwt);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_signed_jwt_without_private_keys);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_json);

	TCase *refresh = tcase_create("refresh");
	tcase_add_checked_fixture(refresh, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(refresh, 30);
	tcase_add_test(refresh, test_handle_refresh_grant_no_refresh_token);
	tcase_add_test(refresh, test_handle_refresh_grant_success);
	tcase_add_test(refresh, test_handle_refresh_grant_failure);
	tcase_add_test(refresh, test_handle_refresh_before_expiry_ttl_negative);
	tcase_add_test(refresh, test_handle_refresh_before_expiry_no_expiry_stored);
	tcase_add_test(refresh, test_handle_refresh_before_expiry_no_refresh_token);
	tcase_add_test(refresh, test_handle_refresh_request_no_return_to);
	tcase_add_test(refresh, test_handle_refresh_request_no_access_token_param);
	tcase_add_test(refresh, test_handle_refresh_request_session_has_no_access_token);
	tcase_add_test(refresh, test_handle_refresh_request_access_token_mismatch);
	tcase_add_test(refresh, test_handle_refresh_request_happy_path);

	TCase *response = tcase_create("response");
	tcase_add_checked_fixture(response, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(response, test_handle_response_make_sid_iss_unique);
	tcase_add_test(response, test_handle_response_post_preserve_disabled_by_default);
	tcase_add_test(response, test_handle_response_save_in_session_minimal);
	tcase_add_test(response, test_handle_response_save_in_session_with_userinfo);
	tcase_add_test(response, test_handle_response_authorization_redirect_state_mismatch);
	tcase_add_test(response, test_handle_response_authorization_redirect_state_mismatch_with_sso_url);
	tcase_add_test(response, test_handle_response_authorization_post_non_post_method);
	tcase_add_test(response, test_handle_response_authorization_post_only_response_mode_fragment);
	tcase_add_test(response, test_handle_response_authorization_redirect_error_param);
	tcase_add_test(response, test_handle_response_authorization_redirect_unknown_response_type);
	tcase_add_test(response, test_handle_response_authorization_redirect_idtoken_happy_path);
	tcase_add_test(response, test_handle_response_authorization_redirect_code_flow_happy_path);

	TCase *discovery = tcase_create("discovery");
	tcase_add_checked_fixture(discovery, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(discovery, test_handle_is_discovery_response);
	tcase_add_test(discovery, test_handle_discovery_request_external_url);
	tcase_add_test(discovery, test_handle_discovery_response_no_target_link_uri_no_sso_url);
	tcase_add_test(discovery, test_handle_discovery_response_static_provider_redirects);
	tcase_add_test(discovery, test_handle_discovery_response_static_provider_iss_mismatch);
	tcase_add_test(discovery, test_handle_discovery_response_target_link_uri_open_redirect);
	tcase_add_test(discovery, test_handle_discovery_request_with_metadata_dir);

	TCase *info = tcase_create("info");
	tcase_add_checked_fixture(info, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(info, test_handle_info_unknown_format);
	tcase_add_test(info, test_handle_info_no_remote_user);
	tcase_add_test(info, test_handle_info_no_hook_data_configured);
	tcase_add_test(info, test_handle_info_json_happy_path);

	TCase *dpop = tcase_create("dpop");
	tcase_add_checked_fixture(dpop, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(dpop, test_handle_dpop_disabled_by_default);
	tcase_add_test(dpop, test_handle_dpop_missing_access_token);
	tcase_add_test(dpop, test_handle_dpop_missing_url_parameter);
	tcase_add_test(dpop, test_handle_dpop_create_fails_without_private_keys);

	TCase *legacy = tcase_create("legacy");
	tcase_add_checked_fixture(legacy, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(legacy, test_handle_legacy_authz_worker);
	tcase_add_test(legacy, test_handle_legacy_remote_user);
	tcase_add_test(legacy, test_handle_legacy_is_auth_capable_request);
	tcase_add_test(legacy, test_handle_legacy_open_redirect);
	tcase_add_test(legacy, test_handle_legacy_check_cookie_domain);

	TCase *logout = tcase_create("logout");
	tcase_add_checked_fixture(logout, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(logout, test_handle_logout_local_no_return_url);
	tcase_add_test(logout, test_handle_logout_local_with_return_url);
	tcase_add_test(logout, test_handle_logout_invalid_return_url);
	tcase_add_test(logout, test_handle_logout_request_no_url_no_session);
	tcase_add_test(logout, test_handle_logout_request_frontchannel_get);
	tcase_add_test(logout, test_handle_logout_request_frontchannel_img);
	tcase_add_test(logout, test_handle_logout_backchannel_no_token);
	tcase_add_test(logout, test_handle_logout_backchannel_happy_path);
	tcase_add_test(logout, test_handle_logout_backchannel_missing_events_claim);
	tcase_add_test(logout, test_handle_logout_backchannel_nonce_claim_rejected);
	tcase_add_test(logout, test_handle_logout_op_request_with_id_token_hint);
	tcase_add_test(logout, test_handle_logout_op_request_no_session_no_extra_params);

	TCase *content = tcase_create("content");
	tcase_add_checked_fixture(content, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(content, test_handle_jwks_request_empty_keys);
	tcase_add_test(content, test_handle_content_handler_jwks);
	tcase_add_test(content, test_handle_content_handler_unknown_redirect_uri_request);
	tcase_add_test(content, test_handle_content_handler_non_redirect_no_state);

	TCase *checkuid = tcase_create("check_user_id");
	tcase_add_checked_fixture(checkuid, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(checkuid, test_handle_check_user_id_unauthenticated_redirects_to_op);
	tcase_add_test(checkuid, test_handle_check_user_id_unauthenticated_not_auth_capable);
	tcase_add_test(checkuid, test_handle_check_user_id_unauth_action_pass);
	tcase_add_test(checkuid, test_handle_check_user_id_unauth_action_return_401);
	tcase_add_test(checkuid, test_handle_check_user_id_unauth_action_return_410);

	TCase *revoke = tcase_create("revoke");
	tcase_add_checked_fixture(revoke, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(revoke, test_handle_revoke_session_no_id);
	tcase_add_test(revoke, test_handle_revoke_session_server_cache);
	tcase_add_test(revoke, test_handle_revoke_at_cache_remove_not_cached);
	tcase_add_test(revoke, test_handle_revoke_at_cache_remove_cached);

	TCase *session_mgmt = tcase_create("session_mgmt");
	tcase_add_checked_fixture(session_mgmt, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(session_mgmt, test_handle_session_management_no_cmd);
	tcase_add_test(session_mgmt, test_handle_session_management_unknown_cmd);
	tcase_add_test(session_mgmt, test_handle_session_management_logout);
	tcase_add_test(session_mgmt, test_handle_session_management_iframe_op_unconfigured);
	tcase_add_test(session_mgmt, test_handle_session_management_iframe_op_configured);
	tcase_add_test(session_mgmt, test_handle_session_management_iframe_rp_configured);

	Suite *s = suite_create("handle");
	suite_add_tcase(s, userinfo);
	suite_add_tcase(s, refresh);
	suite_add_tcase(s, response);
	suite_add_tcase(s, discovery);
	suite_add_tcase(s, info);
	suite_add_tcase(s, dpop);
	suite_add_tcase(s, legacy);
	suite_add_tcase(s, logout);
	suite_add_tcase(s, content);
	suite_add_tcase(s, checkuid);
	suite_add_tcase(s, revoke);
	suite_add_tcase(s, session_mgmt);

	return oidc_test_suite_run(s);
}
