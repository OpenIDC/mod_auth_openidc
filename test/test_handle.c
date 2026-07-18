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
#include <jansson.h> /* this test builds JSON fixtures with the backend API directly (no longer pulled in via jose.h) */

/* the top-level dispatch entry for OIDCRedirectURI requests lives in
 * mod_auth_openidc.c and has no public header — declare it here so the
 * dispatch tests below can exercise the routing decisions directly */
extern int oidc_handle_redirect_uri_request(request_rec *r, oidc_cfg_t *c, oidc_session_t *session);

/* minimum-viable OpenID Connect provider metadata used by the static-config tests below */
#define OIDC_TEST_PROVIDER_METADATA_JSON                                                                               \
	"{"                                                                                                            \
	"\"issuer\":\"https://idp.example.com\","                                                                      \
	"\"authorization_endpoint\":\"https://idp.example.com/authorize\","                                            \
	"\"token_endpoint\":\"https://idp.example.com/token\","                                                        \
	"\"userinfo_endpoint\":\"https://idp.example.com/userinfo\","                                                  \
	"\"jwks_uri\":\"https://idp.example.com/jwks\","                                                               \
	"\"response_types_supported\":[\"code\",\"id_token\",\"id_token token\"],"                                     \
	"\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"]"                   \
	"}"

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

	oidc_json_t *claims = NULL;
	char *userinfo_jwt = NULL;
	const char *result = oidc_userinfo_retrieve_claims(r, c, provider, "AT", "Bearer", NULL,
							   apr_pstrdup(r->pool, "alice"), &claims, &userinfo_jwt);
	ck_assert_ptr_null(result);
	ck_assert_ptr_null(claims);
}
END_TEST

START_TEST(test_handle_userinfo_retrieve_no_access_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, "https://idp.example.com/userinfo");

	oidc_json_t *claims = NULL;
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

	oidc_json_t *claims = NULL;
	char *userinfo_jwt = NULL;
	const char *result = oidc_userinfo_retrieve_claims(r, c, provider, "AT", "Bearer", NULL,
							   apr_pstrdup(r->pool, "alice"), &claims, &userinfo_jwt);
	ck_assert_ptr_nonnull(result);
	ck_assert_ptr_nonnull(claims);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(claims, "name")), "Alice Example");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_handle_userinfo_retrieve_failure_no_session) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 401, .content_type = "application/json", .body = "{\"error\":\"invalid_token\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	oidc_json_t *claims = NULL;
	char *userinfo_jwt = NULL;
	/* userinfo call fails and no session is provided => no refresh path => NULL */
	const char *result = oidc_userinfo_retrieve_claims(r, c, provider, "AT", "Bearer", NULL,
							   apr_pstrdup(r->pool, "alice"), &claims, &userinfo_jwt);
	ck_assert_ptr_null(result);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_handle_userinfo_retrieve_non_401_no_refresh) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	oidc_session_set_refresh_token(r, session, "RT-NO-REFRESH");

	/* userinfo endpoint returns a non-401 error (500): the access token is not "expired/invalid",
	 * so the refresh grant must NOT be attempted */
	oidc_test_http_response_t resp = {
	    .status_code = 500, .content_type = "application/json", .body = "{\"error\":\"server_error\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	/* point the token endpoint at a dead port: had a refresh been (wrongly) attempted it would have failed
	 * there and left a FAILED marker in the refresh-token cache under the refresh token, which we assert is
	 * absent to prove the refresh grant was never entered */
	int free_port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(free_port, 0);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider,
						 apr_psprintf(r->pool, "http://127.0.0.1:%d/token", free_port));

	oidc_json_t *claims = NULL;
	char *userinfo_jwt = NULL;
	const char *result =
	    oidc_userinfo_retrieve_claims(r, c, provider, "AT", "Bearer", session, NULL, &claims, &userinfo_jwt);
	ck_assert_ptr_null(result);

	char *cached = NULL;
	oidc_cache_get_refresh_token(r, "RT-NO-REFRESH", &cached);
	ck_assert_ptr_null(cached);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_store_and_clear_claims) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_json_t *claims = json_pack("{s:s,s:s}", "sub", "alice", "name", "Alice");
	oidc_userinfo_store_claims(r, c, session, provider, claims, "the-jwt");

	oidc_json_t *stored = oidc_session_get_userinfo_claims(r, session);
	ck_assert_ptr_nonnull(stored);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(stored, "sub")), "alice");
	ck_assert_str_eq(oidc_session_get_userinfo_jwt(r, session), "the-jwt");

	/* passing NULL clears both */
	oidc_userinfo_store_claims(r, c, session, provider, NULL, NULL);
	ck_assert_ptr_null(oidc_session_get_userinfo_claims(r, session));
	ck_assert_ptr_null(oidc_session_get_userinfo_jwt(r, session));

	oidc_json_decref(claims);
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

	oidc_test_http_response_t resp = {
	    .status_code = 400, .content_type = "application/json", .body = "{\"error\":\"invalid_grant\"}"};
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
	oidc_json_object_set_new(jwt->payload.value.json, "sid", oidc_json_string("session-id-xyz"));

	oidc_json_t *userinfo = json_pack("{s:s,s:s}", "sub", "alice", "email", "alice@example.com");

	apr_byte_t rc = oidc_response_save_in_session(
	    r, c, session, provider, "alice", "id-token", jwt, "{\"sub\":\"alice\"}", userinfo, "AT", "Bearer", 600,
	    NULL, "openid", NULL, "state-2", "https://www.example.com/protected/", "userinfo-jwt-here");
	ck_assert_int_eq(rc, TRUE);

	oidc_json_t *stored = oidc_session_get_userinfo_claims(r, session);
	ck_assert_ptr_nonnull(stored);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(stored, "email")), "alice@example.com");

	ck_assert_str_eq(oidc_session_get_userinfo_jwt(r, session), "userinfo-jwt-here");
	/* sid should be derived from the SID claim */
	ck_assert_msg(_oidc_strstr(session->sid, "session-id-xyz@") != NULL, "sid should embed the claim");

	oidc_json_decref(userinfo);
	oidc_jwt_destroy(jwt);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_save_in_session_sub_index) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *iss = oidc_cfg_provider_issuer_get(provider);

	/* an id_token carrying a distinct "sid" and "sub" */
	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->payload.sub = apr_pstrdup(r->pool, "alice");
	jwt->payload.exp = apr_time_sec(apr_time_now()) + 3600;
	oidc_json_object_set_new(jwt->payload.value.json, "sid", oidc_json_string("real-sid"));

	/* back-channel logout NOT enabled (default): no secondary "sub" index is created */
	oidc_session_t *s1 = NULL;
	oidc_session_load(r, &s1);
	ck_assert_int_eq(oidc_cfg_provider_backchannel_logout_supported_get(provider), 0);
	ck_assert_int_eq(oidc_response_save_in_session(r, c, s1, provider, "alice", "idt", jwt, NULL, NULL, "AT",
						       "Bearer", 600, NULL, "openid", NULL, "st",
						       "https://www.example.com/protected/", NULL),
			 TRUE);
	ck_assert_msg(_oidc_strstr(s1->sid, "real-sid@") != NULL, "sid is derived from the sid claim");
	ck_assert_ptr_null(s1->sub);
	oidc_session_free(r, s1);

	/* back-channel logout enabled: the session is additionally indexed by "sub" */
	ck_assert_ptr_null(oidc_cfg_provider_backchannel_logout_supported_set(r->pool, provider, 1));
	oidc_session_t *s2 = NULL;
	oidc_session_load(r, &s2);
	ck_assert_int_eq(oidc_response_save_in_session(r, c, s2, provider, "alice", "idt", jwt, NULL, NULL, "AT",
						       "Bearer", 600, NULL, "openid", NULL, "st",
						       "https://www.example.com/protected/", NULL),
			 TRUE);
	ck_assert_ptr_nonnull(s2->sub);
	ck_assert_msg(_oidc_strstr(s2->sub, "alice@") != NULL, "sub index is derived from the sub claim");
	/* and the secondary index resolves to the session uuid in the cache */
	char *by_sub = NULL;
	oidc_cache_get_sid(r, oidc_response_make_sid_iss_unique(r, "alice", iss), &by_sub);
	ck_assert_str_eq(by_sub, s2->uuid);
	oidc_session_free(r, s2);

	oidc_jwt_destroy(jwt);
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
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "foo=bar; %s=%s; baz=zot", cookie_name, cookie));
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
	oidc_json_object_set_new(jwt->payload.value.json, "iss", oidc_json_string(issuer));
	oidc_json_object_set_new(jwt->payload.value.json, "aud", oidc_json_string(client_id));
	oidc_json_object_set_new(jwt->payload.value.json, "sub", oidc_json_string(sub));
	oidc_json_object_set_new(jwt->payload.value.json, "nonce", oidc_json_string(nonce));
	apr_time_t now = apr_time_sec(apr_time_now());
	oidc_json_object_set_new(jwt->payload.value.json, "iat", oidc_json_integer(now));
	oidc_json_object_set_new(jwt->payload.value.json, "exp", oidc_json_integer(now + 600));
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

/* mirror the (deliberately file-local) refresh-cache lock markers from handle/refresh.c */
#define TEST_REFRESH_LOCK_VALUE "needstobelargerthanafewcharacters"
#define TEST_REFRESH_FAILED_LOCK_VALUE "alsoneedstobelargerthanafewcharactersbutdifferent"

START_TEST(test_handle_refresh_grant_cached_results_clamps_and_id_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a cached grant result with an out-of-int-range expires_in must be clamped, and with
	 * session_max_duration == 0 a valid cached id_token updates the session expiry */
	oidc_cfg_provider_session_max_duration_set(r->pool, provider, 0);
	char *id_token = e2e_sign_idtoken_hs256(r, "https://idp.example.com", "client_id", "alice", "nonce-cr1",
						"cached-idtoken-secret-long-enough");
	char *s_json = apr_psprintf(r->pool,
				    "{\"access_token\":\"AT-CACHED\",\"token_type\":\"Bearer\","
				    "\"expires_in\":9999999999999,\"id_token\":\"%s\","
				    "\"refresh_token\":\"RT-CACHED-1b\",\"ts\":%" APR_TIME_T_FMT "}",
				    id_token, apr_time_sec(apr_time_now()));
	oidc_session_set_refresh_token(r, session, "RT-CACHED-1");
	oidc_cache_set_refresh_token(r, "RT-CACHED-1", s_json, apr_time_now() + apr_time_from_sec(30));

	char *new_at = NULL;
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, &new_at, NULL, NULL), TRUE);
	ck_assert_str_eq(new_at, "AT-CACHED");
	ck_assert_str_eq(oidc_session_get_refresh_token(r, session), "RT-CACHED-1b");
	/* the session expiry was aligned with the id_token exp (now + 600) */
	ck_assert_int_gt(oidc_session_get_session_expires(r, session), apr_time_now());

	/* a cached result with a garbage id_token and an expires_in below INT_MIN still applies
	 * the access token; the id_token parse failure is only logged */
	s_json = "{\"access_token\":\"AT-CACHED-2\",\"token_type\":\"Bearer\","
		 "\"expires_in\":-9999999999999,\"id_token\":\"not-a-jwt\"}";
	oidc_session_set_refresh_token(r, session, "RT-CACHED-2");
	oidc_cache_set_refresh_token(r, "RT-CACHED-2", s_json, apr_time_now() + apr_time_from_sec(30));
	new_at = NULL;
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, &new_at, NULL, NULL), TRUE);
	ck_assert_str_eq(new_at, "AT-CACHED-2");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_grant_cache_locks) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a prior failed refresh (failed-lock marker) aborts without contacting the OP */
	oidc_session_set_refresh_token(r, session, "RT-ABORT");
	oidc_cache_set_refresh_token(r, "RT-ABORT", TEST_REFRESH_FAILED_LOCK_VALUE,
				     apr_time_now() + apr_time_from_sec(30));
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, NULL), FALSE);

	/* an unparseable cached value falls through to a refresh attempt of our own; with an
	 * unreachable token endpoint that attempt fails */
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, "http://127.0.0.1:1/token");
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_session_set_refresh_token(r, session, "RT-BADJSON");
	oidc_cache_set_refresh_token(r, "RT-BADJSON", "{not-valid-json", apr_time_now() + apr_time_from_sec(30));
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, NULL), FALSE);

	/* an in-progress lock marker makes us back off; when it expires (without results having
	 * been populated) we attempt our own refresh, which fails against the dead endpoint */
	oidc_session_set_refresh_token(r, session, "RT-LOCKWAIT");
	oidc_cache_set_refresh_token(r, "RT-LOCKWAIT", TEST_REFRESH_LOCK_VALUE,
				     apr_time_now() + apr_time_from_msec(600));
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, NULL), FALSE);

	/* a lock marker that outlives the bounded back-off (its expiry exceeds the lock TTL the
	 * wait is bounded to) exhausts the retries: the timeout branch gives up waiting and
	 * attempts its own refresh, which fails against the dead endpoint. NB: this scenario
	 * spends the full bounded wait (~OIDC_REFRESH_LOCK_TTL seconds) sleeping */
	oidc_session_set_refresh_token(r, session, "RT-LOCKSTUCK");
	oidc_cache_set_refresh_token(r, "RT-LOCKSTUCK", TEST_REFRESH_LOCK_VALUE,
				     apr_time_now() + apr_time_from_sec(30));
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, NULL), FALSE);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_before_expiry_due_paths) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	apr_byte_t needs_save = FALSE;

	/* the session must carry an issuer for the provider lookup */
	oidc_session_set_issuer(r, session, "https://idp.example.com");

	/* expiry is far enough out: no refresh needed */
	oidc_session_set_refresh_token(r, session, "RT-NOTDUE");
	oidc_session_set_access_token_expires(r, session, 3600);
	ck_assert_int_eq(oidc_refresh_access_token_before_expiry(r, c, session, 60, &needs_save), TRUE);
	ck_assert_int_eq(needs_save, FALSE);

	/* within the TTL window and the refresh fails against a dead endpoint */
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, "http://127.0.0.1:1/token");
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_session_set_refresh_token(r, session, "RT-DUE-FAIL");
	oidc_session_set_access_token_expires(r, session, 30);
	needs_save = TRUE;
	ck_assert_int_eq(oidc_refresh_access_token_before_expiry(r, c, session, 60, &needs_save), FALSE);
	ck_assert_int_eq(needs_save, FALSE);

	/* within the TTL window and the refresh succeeds; a scope returned from the token
	 * endpoint is stored in the session */
	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"access_token\":\"AT-DUE\",\"token_type\":\"Bearer\","
						  "\"expires_in\":3600,\"refresh_token\":\"RT-DUE-OK2\","
						  "\"scope\":\"openid profile\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_scope_set(r->pool, provider, "openid");
	oidc_session_set_refresh_token(r, session, "RT-DUE-OK");
	oidc_session_set_access_token_expires(r, session, 30);
	needs_save = FALSE;
	ck_assert_int_eq(oidc_refresh_access_token_before_expiry(r, c, session, 60, &needs_save), TRUE);
	ck_assert_int_eq(needs_save, TRUE);
	ck_assert_str_eq(oidc_session_get_access_token(r, session), "AT-DUE");
	ck_assert_str_eq(oidc_session_get_scope(r, session), "openid profile");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_request_error_arms) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a return_to URL that fails redirect validation is a hard error */
	r->args = "refresh=https%3A%2F%2Fevil.example.com%2F&access_token=AT-X";
	ck_assert_int_eq(oidc_refresh_token_request(r, c, session), HTTP_INTERNAL_SERVER_ERROR);

	/* matching access_token but no issuer in the session: the provider lookup fails */
	oidc_session_set_access_token(r, session, "AT-1");
	r->args = "refresh=https%3A%2F%2Fwww.example.com%2Fprotected%2F&access_token=AT-1";
	ck_assert_int_eq(oidc_refresh_token_request(r, c, session), HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "error_code=session_corruption") != NULL, "session_corruption error reported");

	/* with an issuer but no refresh_token in the session: the grant itself fails */
	oidc_session_set_issuer(r, session, "https://idp.example.com");
	ck_assert_int_eq(oidc_refresh_token_request(r, c, session), HTTP_MOVED_TEMPORARILY);
	loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "error_code=refresh_failed") != NULL, "refresh_failed error reported");

	oidc_session_free(r, session);
}
END_TEST

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
	char *id_token =
	    e2e_sign_idtoken_hs256(r, "https://idp.example.com", "client_id", "alice", "nonce-code", secret);
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
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "foo=bar; %s=%s; baz=zot", cookie_name, cookie));
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
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "foo=bar; %s=%s; baz=zot", cookie_name, cookie));
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

/* defined further down alongside the logout tests; used here for the form-post entrypoint tests */
static void e2e_post_body(request_rec *r, const char *body);

START_TEST(test_handle_response_authorization_error_prompt_none) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* build a state whose proto_state carries prompt=none */
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "rndnonce");
	oidc_proto_state_set_state(ps, "s1");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/index.html");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_response_type(ps, OIDC_PROTO_RESPONSE_TYPE_CODE);
	oidc_proto_state_set_response_mode(ps, OIDC_PROTO_RESPONSE_MODE_QUERY);
	oidc_proto_state_set_prompt(ps, OIDC_PROTO_PROMPT_NONE);
	oidc_proto_state_set_timestamp_now(ps);
	char *fingerprint = oidc_state_browser_fingerprint(r, c, "rndnonce");
	char *cookie = oidc_proto_state_to_cookie(r, c, ps);
	const char *cookie_name = oidc_state_cookie_name(r, fingerprint);
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", cookie_name, cookie));
	oidc_proto_state_destroy(ps);

	/* an error response under prompt=none must redirect the parent window to logout rather than
	 * render an error page */
	r->args = apr_psprintf(r->pool, "state=%s&error=login_required&error_description=x",
			       oidc_http_url_encode(r, fingerprint));
	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, OK);
	const char *head = oidc_request_state_get(r, "head");
	ck_assert_ptr_nonnull(head);
	ck_assert_msg(_oidc_strstr(head, "session=logout") != NULL,
		      "prompt=none error must redirect the parent window to logout");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_browser_back) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* an established session whose stored request-state equals the state in the URL is a browser-back
	 * event: redirect to the original URL without re-processing the authorization response */
	session->remote_user = apr_pstrdup(r->pool, "alice");
	oidc_session_set_request_state(r, session, "bb-state");
	oidc_session_set_original_url(r, session, "https://www.example.com/protected/page");

	r->args = "state=bb-state&code=whatever";
	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_str_eq(loc, "https://www.example.com/protected/page");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_post_preserve_javascript) {
	request_rec *r = oidc_test_request_get();

	/* enable POST preservation for this location and present a form POST with parameters */
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPreservePost);
	ck_assert_ptr_null(oidc_cmd_dir_preserve_post_set(cmd, dir_cfg, "On"));
	e2e_post_body(r, "name=alice&grp=admins");

	char *js = NULL;
	char *jm = NULL;
	apr_byte_t rv = oidc_response_post_preserve_javascript(r, "https://www.example.com/protected/", &js, &jm);
	ck_assert_int_eq(rv, TRUE);
	ck_assert_ptr_nonnull(js);
	ck_assert_ptr_nonnull(jm);
	ck_assert_str_eq(jm, "preserveOnLoad()");
	ck_assert_msg(_oidc_strstr(js, "mod_auth_openidc_preserve_post_params") != NULL,
		      "generated javascript must reference the preserve-post session storage");
	ck_assert_msg(_oidc_strstr(js, "name") != NULL, "the POSTed parameters must be embedded in the javascript");
}
END_TEST

START_TEST(test_handle_response_save_in_session_session_mgmt) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* session management on (check_session_iframe set) + a session_state provided + an explicit cookie domain */
	oidc_cfg_provider_check_session_iframe_set(r->pool, provider, "https://idp.example.com/check_session");
	ck_assert_ptr_null(oidc_cmd_cookie_domain_set(oidc_test_cmd_get(OIDCCookieDomain), NULL, "www.example.com"));

	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->payload.sub = apr_pstrdup(r->pool, "alice");
	jwt->payload.exp = apr_time_sec(apr_time_now()) + 3600;

	apr_byte_t rc = oidc_response_save_in_session(r, c, session, provider, "alice", "id-token", jwt, NULL, NULL,
						      NULL, NULL, 0, NULL, NULL, "the-session-state", "state-3",
						      "https://www.example.com/protected/", NULL);
	ck_assert_int_eq(rc, TRUE);
	ck_assert_str_eq(oidc_session_get_session_state(r, session), "the-session-state");
	ck_assert_str_eq(oidc_session_get_cookie_domain(r, session), "www.example.com");

	oidc_jwt_destroy(jwt);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_save_in_session_no_session_state) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* check_session_iframe set but no session_state in the response => the "no session_state provided"
	 * branch; session_max_duration==0 => the hard expiry is derived from the id_token exp claim */
	oidc_cfg_provider_check_session_iframe_set(r->pool, provider, "https://idp.example.com/check_session");
	oidc_cfg_provider_session_max_duration_set(r->pool, provider, 0);

	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->payload.sub = apr_pstrdup(r->pool, "alice");
	jwt->payload.exp = apr_time_sec(apr_time_now()) + 3600;

	apr_byte_t rc =
	    oidc_response_save_in_session(r, c, session, provider, "alice", "id-token", jwt, NULL, NULL, NULL, NULL, 0,
					  NULL, NULL, NULL, "state-4", "https://www.example.com/protected/", NULL);
	ck_assert_int_eq(rc, TRUE);
	ck_assert_str_eq(session->remote_user, "alice");

	oidc_jwt_destroy(jwt);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_state_restore_no_cookie) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a (non-empty) state with no matching state cookie => proto-state restore fails in
	 * oidc_response_proto_state_restore; with a pre-existing error in the environment and no default
	 * SSO URL the mismatch handler short-circuits to 400 */
	apr_table_set(r->subprocess_env, OIDC_ERROR_ENVVAR, "earlier error");
	r->args = "state=no-such-cookie";
	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_finish_form_post_restore) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	const char *secret = "shared-secret-for-hs256-verification";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	/* same as the id_token happy path but with original_method=form_post: instead of a 302 the handler
	 * must return an HTML page that restores and re-POSTs the preserved form data */
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "nonce-fp");
	oidc_proto_state_set_state(ps, "s-fp");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/form-target");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_FORM_POST);
	oidc_proto_state_set_response_type(ps, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN);
	oidc_proto_state_set_response_mode(ps, OIDC_PROTO_RESPONSE_MODE_QUERY);
	oidc_proto_state_set_timestamp_now(ps);

	char *fingerprint = oidc_state_browser_fingerprint(r, c, "nonce-fp");
	char *cookie = oidc_proto_state_to_cookie(r, c, ps);
	const char *cookie_name = oidc_state_cookie_name(r, fingerprint);
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", cookie_name, cookie));
	oidc_proto_state_destroy(ps);

	char *id_token = e2e_sign_idtoken_hs256(r, "https://idp.example.com", "client_id", "alice", "nonce-fp", secret);
	r->args = apr_psprintf(r->pool, "state=%s&id_token=%s", oidc_http_url_encode(r, fingerprint),
			       oidc_http_url_encode(r, id_token));

	int rc = oidc_response_authorization_redirect(r, c, session);
	ck_assert_int_eq(rc, OK);
	const char *head = oidc_request_state_get(r, "head");
	ck_assert_ptr_nonnull(head);
	ck_assert_msg(_oidc_strstr(head, "mod_auth_openidc_preserve_post_params") != NULL,
		      "form_post finish must emit the POST-restore javascript");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_response_authorization_post_state_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a real form POST with parameters reaches oidc_response_process through the POST entrypoint; the
	 * state has no matching cookie so it ends in a state-mismatch 400 */
	e2e_post_body(r, "state=no-cookie&code=abc");
	int rc = oidc_response_authorization_post(r, c, session);
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

START_TEST(test_handle_discovery_response_issuer_input_trimmed) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* stray whitespace around the user-typed iss value is trimmed before the issuer
	 * match, so the padded value still selects the static provider (it would return
	 * HTTP_INTERNAL_SERVER_ERROR on an issuer mismatch without the trim) */
	r->args = "iss=%20%09https%3A%2F%2Fidp.example.com%20"
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

/* point OIDCMetadataDir at a fresh empty temp dir so oidc_discovery_response
 * takes the resolve-issuer (non-static) code path */
static void e2e_discovery_set_empty_metadata_dir(request_rec *r) {
	char *tmpl = apr_pstrdup(r->pool, "/tmp/oidc-test-disco.XXXXXX");
	ck_assert_msg(mkdtemp(tmpl) != NULL, "could not create temp metadata dir at %s", tmpl);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCMetadataDir);
	ck_assert_ptr_null(oidc_cmd_metadata_dir_set(cmd, NULL, tmpl));
}

/* a user identifier entered on the discovery page that cannot be resolved via
 * URL-based (webfinger) discovery produces a 404 error page; the https://
 * normalization prefix is applied first */
START_TEST(test_handle_discovery_response_user_discovery_fails) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	e2e_discovery_set_empty_metadata_dir(r);

	/* 127.0.0.1:1 => https://127.0.0.1:1 => connection refused */
	r->args = "disc_user=127.0.0.1%3A1"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);
}
END_TEST

/* an account-shaped issuer value (containing "@") triggers account-based
 * (webfinger) discovery; an unresolvable domain produces a 404 error page */
START_TEST(test_handle_discovery_response_account_discovery_fails) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	e2e_discovery_set_empty_metadata_dir(r);

	r->args = "iss=jane%40127.0.0.1%3A1"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);
}
END_TEST

/*
 * OIDCDiscoverIssuersAllowed must reject a disallowed host *before* the webfinger
 * discovery HTTP call is attempted, not just against the issuer it would resolve to:
 * with the allow-list configured, 127.0.0.1 (which would otherwise fail with a
 * connection-refused 404, as in the tests above) must instead be rejected outright.
 */
START_TEST(test_handle_discovery_response_url_based_issuer_not_allowed) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	e2e_discovery_set_empty_metadata_dir(r);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCDiscoverIssuersAllowed);
	ck_assert_ptr_null(oidc_cmd_discover_issuers_allowed_set(cmd, NULL, "^https://other\\.example\\.com$"));

	r->args = "disc_user=127.0.0.1%3A1"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

START_TEST(test_handle_discovery_response_account_based_issuer_not_allowed) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	e2e_discovery_set_empty_metadata_dir(r);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCDiscoverIssuersAllowed);
	ck_assert_ptr_null(oidc_cmd_discover_issuers_allowed_set(cmd, NULL, "^https://other\\.example\\.com$"));

	r->args = "iss=jane%40127.0.0.1%3A1"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F";
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

START_TEST(test_handle_info_refresh_access_token_and_full_output) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* enable all the info hook output sections that need session data */
	const char *keys[] = {
	    OIDC_HOOK_INFO_ID_TOKEN,	    OIDC_HOOK_INFO_USER_INFO,	  OIDC_HOOK_INFO_SESSION_EXP,
	    OIDC_HOOK_INFO_SESSION_TIMEOUT, OIDC_HOOK_INFO_SESSION,	  OIDC_HOOK_INFO_REFRESH_TOKEN,
	    OIDC_HOOK_INFO_ACCES_TOKEN_EXP, OIDC_HOOK_INFO_ID_TOKEN_HINT, NULL};
	for (int i = 0; keys[i] != NULL; i++)
		ck_assert_ptr_null(oidc_cmd_info_hook_data_set(oidc_test_cmd_get(OIDCInfoHook), NULL, keys[i]));

	session->remote_user = apr_pstrdup(r->pool, "alice");
	oidc_session_set_issuer(r, session, "https://idp.example.com");
	oidc_session_set_refresh_token(r, session, "RT-INFO");
	oidc_session_set_access_token(r, session, "AT-OLD");
	oidc_session_set_access_token_expires(r, session, 3600);
	oidc_session_set_idtoken(r, session, "SERIALIZED-ID-TOKEN");
	oidc_json_t *claims = oidc_json_object();
	oidc_json_object_set_new(claims, "sub", oidc_json_string("alice"));
	oidc_session_set_idtoken_claims(r, session, claims);
	oidc_session_set_userinfo_claims(r, session, claims);
	oidc_json_decref(claims);

	/* an unparseable refresh interval is ignored; the HTML format response renders */
	r->args = "info=html&access_token_refresh_interval=notanumber&extend_session=false";
	ck_assert_int_eq(oidc_info_request(r, c, session, FALSE), OK);

	/* a recent refresh within the interval: nothing to do, JSON response renders */
	oidc_session_set_access_token_last_refresh(r, session, apr_time_now());
	r->args = "info=json&access_token_refresh_interval=3600&extend_session=false";
	ck_assert_int_eq(oidc_info_request(r, c, session, FALSE), OK);

	/* refresh due but the token endpoint is unreachable */
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, "http://127.0.0.1:1/token");
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_session_set_access_token_last_refresh(r, session, apr_time_from_sec(1));
	r->args = "info=json&access_token_refresh_interval=1&extend_session=false";
	ck_assert_int_eq(oidc_info_request(r, c, session, FALSE), HTTP_INTERNAL_SERVER_ERROR);

	/* refresh due and the token endpoint delivers: the session is updated. Use a fresh
	 * refresh_token - the prior failed attempt above locked "RT-INFO" out of further
	 * refresh attempts for OIDC_REFRESH_CACHE_TTL seconds (see handle/refresh.c) */
	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"access_token\":\"AT-INFO\",\"token_type\":\"Bearer\","
						  "\"expires_in\":3600,\"refresh_token\":\"RT-INFO-2\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_scope_set(r->pool, provider, "openid");
	oidc_session_set_refresh_token(r, session, "RT-INFO-FRESH");
	oidc_session_set_access_token_last_refresh(r, session, apr_time_from_sec(1));
	ck_assert_int_eq(oidc_info_request(r, c, session, FALSE), OK);
	ck_assert_str_eq(oidc_session_get_access_token(r, session), "AT-INFO");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_info_refresh_failures_without_issuer) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	ck_assert_ptr_null(
	    oidc_cmd_info_hook_data_set(oidc_test_cmd_get(OIDCInfoHook), NULL, OIDC_HOOK_INFO_TIMESTAMP));
	session->remote_user = apr_pstrdup(r->pool, "alice");
	oidc_session_set_refresh_token(r, session, "RT-NOISS");

	/* an access-token refresh that is due cannot resolve a provider without an issuer */
	r->args = "info=json&access_token_refresh_interval=1";
	ck_assert_int_eq(oidc_info_request(r, c, session, FALSE), HTTP_INTERNAL_SERVER_ERROR);

	/* same for the userinfo claims refresh on the extend-session path */
	oidc_session_set_userinfo_refresh_interval(r, session, 1);
	r->args = "info=json";
	ck_assert_int_eq(oidc_info_request(r, c, session, FALSE), HTTP_INTERNAL_SERVER_ERROR);

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

	oidc_json_t *stored = oidc_session_get_userinfo_claims(r, session);
	ck_assert_ptr_nonnull(stored);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(stored, "email")), "alice@example.com");

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
	oidc_json_t *claims = json_pack("{s:s}", "sub", "alice");
	oidc_session_set_userinfo_claims(r, session, claims);
	oidc_session_set_userinfo_jwt(r, session, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig-bytes");

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "jwt")));

	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	const char *hdr = apr_table_get(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_USERINFO_JWT);
	ck_assert_ptr_nonnull(hdr);
	ck_assert_str_eq(hdr, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig-bytes");

	oidc_json_decref(claims);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_pass_as_signed_jwt_without_private_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_json_t *claims = json_pack("{s:s}", "sub", "alice");
	oidc_session_set_userinfo_claims(r, session, claims);

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "signed_jwt")));

	/* the test fixture has an empty private_keys array, so signed-JWT creation
	 * silently fails and no header is set (the function is a void, this is its
	 * graceful-degradation path) */
	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	ck_assert_table_unset(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_SIGNED_JWT);

	oidc_json_decref(claims);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_pass_as_signed_jwt_with_private_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* load test/private.pem so cfg->private_keys holds an RSA signing key with kid "rsa-1" */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *key_cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *key_err = oidc_cmd_private_keys_set(
	    key_cmd, NULL, apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir)));
	ck_assert_msg(key_err == NULL, "could not load private key: %s", key_err);

	oidc_json_t *claims = json_pack("{s:s}", "sub", "alice");
	oidc_session_set_userinfo_claims(r, session, claims);

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "signed_jwt")));

	/* with a private signing key configured, the claims are signed and passed as a compact JWT */
	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	const char *hdr = apr_table_get(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_SIGNED_JWT);
	ck_assert_ptr_nonnull(hdr);

	/* a compact JWS has exactly two '.' separators (header.payload.signature) */
	const char *dot1 = _oidc_strstr(hdr, ".");
	ck_assert_ptr_nonnull(dot1);
	const char *dot2 = _oidc_strstr(dot1 + 1, ".");
	ck_assert_ptr_nonnull(dot2);

	/* confirm it was signed with the configured RSA key; parse the header via
	 * oidc_proto_jwt_header_peek rather than substring-matching the serialized JSON,
	 * whose whitespace (e.g. the space after the colon) differs across cjose versions */
	char *alg = NULL, *kid = NULL;
	ck_assert_ptr_nonnull(oidc_proto_jwt_header_peek(r, hdr, &alg, NULL, &kid));
	ck_assert_str_eq(alg, "RS256");
	ck_assert_str_eq(kid, "rsa-1");

	/* decode the payload and confirm the userinfo claim plus the synthesized iss/exp claims */
	char *dec_pl = NULL;
	ck_assert_int_gt(
	    oidc_util_base64url_decode(r->pool, &dec_pl, apr_pstrmemdup(r->pool, dot1 + 1, dot2 - (dot1 + 1))), 0);
	ck_assert_ptr_nonnull(_oidc_strstr(dec_pl, "\"sub\":\"alice\""));
	ck_assert_ptr_nonnull(_oidc_strstr(dec_pl, "\"iss\":\"https://idp.example.com\""));
	ck_assert_ptr_nonnull(_oidc_strstr(dec_pl, "\"exp\""));

	oidc_json_decref(claims);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_pass_as_signed_jwt_cached) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *key_cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *key_err = oidc_cmd_private_keys_set(
	    key_cmd, NULL, apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir)));
	ck_assert_msg(key_err == NULL, "could not load private key: %s", key_err);

	oidc_json_t *claims = json_pack("{s:s}", "sub", "alice");
	oidc_session_set_userinfo_claims(r, session, claims);

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, apr_pstrdup(r->pool, "signed_jwt")));

	/* a non-negative cache TTL makes the signed JWT eligible for caching; "0" derives the
	 * cache expiry from the JWT "exp" claim */
	apr_table_set(r->subprocess_env, "OIDC_USERINFO_SIGNED_JWT_CACHE_TTL", "0");

	/* first pass: cache miss => sign + serialize + store in the cache */
	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);
	const char *first = apr_table_get(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_SIGNED_JWT);
	ck_assert_ptr_nonnull(first);
	first = apr_pstrdup(r->pool, first);

	/* second pass with identical claims: cache hit => the exact same serialized JWT is returned */
	apr_table_unset(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_SIGNED_JWT);
	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);
	const char *second = apr_table_get(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_SIGNED_JWT);
	ck_assert_ptr_nonnull(second);
	ck_assert_str_eq(first, second);

	oidc_json_decref(claims);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_userinfo_pass_as_json) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* seed the session with userinfo claims and configure the dir to pass them as a JSON header */
	oidc_json_t *claims = json_pack("{s:s,s:s}", "sub", "alice", "groups", "admins");
	oidc_session_set_userinfo_claims(r, session, claims);

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassUserInfoAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_userinfo_as_set(cmd, dir_cfg, "json"));

	/* must not crash and must populate the OIDC_userinfo_json header on r->headers_in */
	oidc_userinfo_pass_as(r, c, session, OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);

	const char *hdr = apr_table_get(r->headers_in, OIDC_DEFAULT_HEADER_PREFIX OIDC_APP_INFO_USERINFO_JSON);
	ck_assert_ptr_nonnull(hdr);
	ck_assert_msg(_oidc_strstr(hdr, "\"sub\":\"alice\"") != NULL,
		      "JSON-encoded userinfo should be passed as a header");

	oidc_json_decref(claims);
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
static authz_status _legacy_authz(request_rec *r, oidc_json_t *json, const char *require_args) {
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
	oidc_json_t *json = json_loads(claims, 0, &err);
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

	oidc_json_decref(json);
}
END_TEST

START_TEST(test_handle_legacy_remote_user) {
	request_rec *r = oidc_test_request_get();
	char *remote_user = NULL;
	oidc_json_t *json = NULL;

	/* simple username extracted by regex first-match (no replace) */
	ck_assert_int_eq(oidc_json_decode_object(r, "{\"upn\":\"nneul@umsystem.edu\"}", &json), TRUE);
	oidc_get_remote_user(r, "upn", "^(.*)@umsystem\\.edu", NULL, json, &remote_user);
	ck_assert_str_eq(remote_user, "nneul");
	ck_assert_int_eq(oidc_get_remote_user(r, "upn", "^(.*)@umsystem\\.edu", "$1", json, &remote_user), TRUE);
	ck_assert_str_eq(remote_user, "nneul");
	oidc_json_decref(json);

	/* regex with replace expression that swaps captured groups */
	json = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, "{\"email\":\"nneul@umsystem.edu\"}", &json), TRUE);
	ck_assert_int_eq(oidc_get_remote_user(r, "email", "^(.*)@([^.]+)\\..+$", "$2\\$1", json, &remote_user), TRUE);
	ck_assert_str_eq(remote_user, "umsystem\\nneul");
	oidc_json_decref(json);

	/* UTF-8 username — must round-trip through the replace expression intact */
	json = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, "{ \"name\": \"Dominik František Bučík\" }", &json), TRUE);
	ck_assert_int_eq(oidc_get_remote_user(r, "name", "^(.*)$", "$1@test.com", json, &remote_user), TRUE);
	ck_assert_str_eq(remote_user, "Dominik František Bučík@test.com");
	oidc_json_decref(json);

	json = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, "{ \"preferred_username\": \"dbucik\" }", &json), TRUE);
	ck_assert_int_eq(oidc_get_remote_user(r, "preferred_username", "^(.*)$", "$1@test.com", json, &remote_user),
			 TRUE);
	ck_assert_str_eq(remote_user, "dbucik@test.com");
	oidc_json_decref(json);
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
	ck_assert_int_eq(
	    oidc_validate_redirect_url(r, c, "https://www.example.com/somewhere", TRUE, &err_str, &err_desc), TRUE);
	ck_assert_int_eq(
	    oidc_validate_redirect_url(r, c, "https://evil.example.com/somewhere", TRUE, &err_str, &err_desc), FALSE);

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
	ck_assert_int_eq(oidc_request_check_cookie_domain(r, c, "https://ab001sb161djbn.xyz.com/protected/index.html"),
			 TRUE);

	c->cookie_domain = "ab001SB161djbn.xyz.com";
	ck_assert_int_eq(oidc_request_check_cookie_domain(r, c, "https://ab001sb161djbn.xyz.com/protected/index.html"),
			 TRUE);

	c->cookie_domain = NULL;
	oidc_session_free(r, session);
}
END_TEST

/*
 * Additional tests for mod_auth_openidc.c top-level helpers — exercise the
 * header/cookie scrubbing branches, the no-metadata static-provider path,
 * the various OIDCPassClaimsAs / OIDCPassIDTokenAs / OIDCUnAuthAction
 * dispatches, plus a handful of validate_redirect_url corner cases that
 * the open-redirect payload list does not reach.
 */

START_TEST(test_handle_mod_scrub_headers_default_prefix) {
	request_rec *r = oidc_test_request_get();

	/* default OIDCClaimPrefix is OIDC_, so the OIDC_-prefixed header set by
	 * the fixture must be removed while other headers survive */
	apr_table_set(r->headers_in, "OIDC_foo", "evil");
	apr_table_set(r->headers_in, "X-Original", "kept");

	oidc_scrub_headers(r);

	ck_assert_table_unset(r->headers_in, "OIDC_foo");
	ck_assert_table_str(r->headers_in, "X-Original", "kept");
}
END_TEST

START_TEST(test_handle_mod_scrub_headers_empty_prefix_with_whitelist) {
	request_rec *r = oidc_test_request_get();

	/* with an empty OIDCClaimPrefix the whitelist set is overlaid on top of
	 * the default OIDC_-prefix scrub: this exercises the apr_hash_overlay
	 * branch in oidc_scrub_headers */
	cmd_parms *cmd_prefix = oidc_test_cmd_get(OIDCClaimPrefix);
	ck_assert_ptr_null(oidc_cmd_claim_prefix_set(cmd_prefix, NULL, ""));
	cmd_parms *cmd_wl = oidc_test_cmd_get(OIDCWhiteListedClaims);
	ck_assert_ptr_null(oidc_cmd_white_listed_claims_set(cmd_wl, NULL, "X-Custom-Scrub"));

	apr_table_set(r->headers_in, "X-Custom-Scrub", "should-be-scrubbed");
	apr_table_set(r->headers_in, "X-Other", "should-survive");

	oidc_scrub_headers(r);

	ck_assert_table_unset(r->headers_in, "X-Custom-Scrub");
	ck_assert_table_str(r->headers_in, "X-Other", "should-survive");
}
END_TEST

START_TEST(test_handle_mod_scrub_headers_custom_prefix) {
	request_rec *r = oidc_test_request_get();

	/* a prefix that does not start with OIDC_ triggers the second scrub pass
	 * that removes the custom-prefix headers on top of the OIDC_ ones */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCClaimPrefix);
	ck_assert_ptr_null(oidc_cmd_claim_prefix_set(cmd, NULL, "MY_"));

	apr_table_set(r->headers_in, "MY_email", "scrubbed");
	apr_table_set(r->headers_in, "OIDC_foo", "scrubbed");
	apr_table_set(r->headers_in, "X-Other", "kept");

	oidc_scrub_headers(r);

	ck_assert_table_unset(r->headers_in, "MY_email");
	ck_assert_table_unset(r->headers_in, "OIDC_foo");
	ck_assert_table_str(r->headers_in, "X-Other", "kept");
}
END_TEST

START_TEST(test_handle_mod_strip_cookies_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCStripCookies);
	ck_assert_ptr_null(oidc_cmd_dir_strip_cookies_set(cmd, dir_cfg, "session-id"));
	ck_assert_ptr_null(oidc_cmd_dir_strip_cookies_set(cmd, dir_cfg, "tracker"));

	/* leading whitespace and an all-whitespace token both exercise the
	 * cookie-trim and empty-segment-skip code paths */
	apr_table_set(r->headers_in, "Cookie", "session-id=abc; keep=this; ; tracker=xyz; mod_auth_openidc_session=ok");

	oidc_strip_cookies(r);

	const char *cookies = apr_table_get(r->headers_in, "Cookie");
	ck_assert_ptr_nonnull(cookies);
	ck_assert_msg(_oidc_strstr(cookies, "session-id") == NULL, "session-id must be stripped, got: %s", cookies);
	ck_assert_msg(_oidc_strstr(cookies, "tracker=") == NULL, "tracker must be stripped, got: %s", cookies);
	ck_assert_msg(_oidc_strstr(cookies, "keep=this") != NULL, "unmatched cookies must survive, got: %s", cookies);
	ck_assert_msg(_oidc_strstr(cookies, "mod_auth_openidc_session=ok") != NULL,
		      "unrelated cookies must survive, got: %s", cookies);
}
END_TEST

START_TEST(test_handle_mod_provider_static_config_no_metadata_url) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* default fixture has no metadata_dir and no provider_metadata_url => the
	 * early-return branch hands back the configured provider as-is */
	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_provider_static_config(r, c, &provider), TRUE);
	ck_assert_ptr_nonnull(provider);
	ck_assert_ptr_eq(provider, oidc_cfg_provider_get(c));
}
END_TEST

START_TEST(test_handle_mod_provider_static_config_metadata_url_cached) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *cfg_provider = oidc_cfg_provider_get(c);

	/* configure a metadata URL (no metadata dir) and pre-seed the provider cache,
	 * so static config takes the cache-hit branch (validate-decode, no HTTP fetch) */
	const char *metadata_url = "https://idp.example.com/.well-known/openid-configuration";
	oidc_cfg_provider_metadata_url_set(r->pool, cfg_provider, metadata_url);
	oidc_cache_set_provider(r, metadata_url, OIDC_TEST_PROVIDER_METADATA_JSON,
				apr_time_now() + apr_time_from_sec(300));

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_provider_static_config(r, c, &provider), TRUE);
	ck_assert_ptr_nonnull(provider);
	/* a metadata-derived provider is a fresh copy, not the configured struct */
	ck_assert_ptr_ne(provider, cfg_provider);
}
END_TEST

START_TEST(test_handle_mod_provider_static_config_metadata_url_fetch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *cfg_provider = oidc_cfg_provider_get(c);
	oidc_cfg_provider_ssl_validate_server_set(r->pool, cfg_provider, 0);

	/* serve the metadata from the loopback server and point the provider at it;
	 * with an empty cache this drives the HTTP retrieve + validate + cache-set path */
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = OIDC_TEST_PROVIDER_METADATA_JSON};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_metadata_url_set(r->pool, cfg_provider, oidc_test_http_server_url(srv, r->pool));

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_provider_static_config(r, c, &provider), TRUE);
	ck_assert_ptr_nonnull(provider);
	ck_assert_ptr_ne(provider, cfg_provider);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "GET");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_handle_mod_provider_static_config_metadata_url_fetch_fails) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *cfg_provider = oidc_cfg_provider_get(c);
	oidc_cfg_provider_ssl_validate_server_set(r->pool, cfg_provider, 0);

	/* point the provider at a port with nothing listening: the metadata fetch
	 * fails (cache miss + connection refused) and static config returns FALSE */
	int port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(port, 0);
	oidc_cfg_provider_metadata_url_set(r->pool, cfg_provider,
					   apr_psprintf(r->pool, "http://127.0.0.1:%d/metadata", port));

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_provider_static_config(r, c, &provider), FALSE);
}
END_TEST

START_TEST(test_handle_mod_set_app_claims_pass_none) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassClaimsAs);
	ck_assert_ptr_null(oidc_cmd_dir_pass_claims_as_set(cmd, dir_cfg, "none", NULL));

	/* PASS_NONE short-circuits => returns TRUE without populating env vars */
	oidc_json_t *claims = json_pack("{s:s}", "sub", "alice");
	ck_assert_int_eq(oidc_set_app_claims(r, c, claims), TRUE);
	ck_assert_table_unset(r->subprocess_env, "OIDC_CLAIM_sub");
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_handle_mod_set_app_claims_pass_both) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* default OIDCPassClaimsAs is "both" => the claim ends up as an env var */
	oidc_json_t *claims = json_pack("{s:s}", "sub", "alice");
	ck_assert_int_eq(oidc_set_app_claims(r, c, claims), TRUE);
	ck_assert_table_str(r->subprocess_env, "OIDC_CLAIM_sub", "alice");
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_handle_mod_log_session_expires) {
	request_rec *r = oidc_test_request_get();

	/* exercises the rfc822-date + debug-log path; no observable side effect
	 * other than not crashing on a far-future expiry */
	oidc_log_session_expires(r, "test", apr_time_now() + apr_time_from_sec(900));
}
END_TEST

START_TEST(test_handle_mod_check_cookie_domain_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* session cookie issued for another host must be rejected */
	oidc_session_set_cookie_domain(r, session, "other-host.example.com");
	ck_assert_int_eq(oidc_check_cookie_domain(r, c, session), FALSE);

	/* and a NULL session cookie domain must also fail (the OR-clause guard) */
	oidc_session_set_cookie_domain(r, session, NULL);
	ck_assert_int_eq(oidc_check_cookie_domain(r, c, session), FALSE);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_mod_get_provider_from_session_no_issuer) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* an empty session has no issuer => returns FALSE */
	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_get_provider_from_session(r, c, session, &provider), FALSE);
	ck_assert_ptr_null(provider);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_mod_get_provider_from_session_with_issuer) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)));

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_get_provider_from_session(r, c, session, &provider), TRUE);
	ck_assert_ptr_nonnull(provider);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_mod_get_remote_user_missing_claim) {
	request_rec *r = oidc_test_request_get();
	oidc_json_t *json = json_pack("{s:s}", "sub", "alice");
	char *remote_user = NULL;

	/* requested claim missing => FALSE, remote_user left untouched */
	ck_assert_int_eq(oidc_get_remote_user(r, "preferred_username", NULL, NULL, json, &remote_user), FALSE);
	ck_assert_ptr_null(remote_user);

	/* claim present but not a string => FALSE as well */
	oidc_json_object_set_new(json, "preferred_username", oidc_json_integer(42));
	ck_assert_int_eq(oidc_get_remote_user(r, "preferred_username", NULL, NULL, json, &remote_user), FALSE);
	oidc_json_decref(json);
}
END_TEST

START_TEST(test_handle_mod_validate_redirect_url_backslash_relative) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	char *err_str = NULL, *err_desc = NULL;

	/* a hostname-less URL whose only path is the empty string can't be
	 * relative-validated: the "starts with /" check fails and we get
	 * "Malformed URL" */
	ck_assert_int_eq(oidc_validate_redirect_url(r, c, "evil", TRUE, &err_str, &err_desc), FALSE);
	ck_assert_ptr_nonnull(err_str);
	ck_assert_str_eq(err_str, "Malformed URL");
}
END_TEST

START_TEST(test_handle_mod_validate_redirect_url_allowed) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCRedirectURLsAllowed);
	ck_assert_ptr_null(oidc_cmd_redirect_urls_allowed_set(cmd, NULL, "^https://[a-z]+\\.example\\.com/"));

	char *err_str = NULL, *err_desc = NULL;
	/* matching the configured regex bypasses the same-host check */
	ck_assert_int_eq(
	    oidc_validate_redirect_url(r, c, "https://other.example.com/return", TRUE, &err_str, &err_desc), TRUE);

	/* a URL that does not match the regex is rejected with "URL not allowed" */
	err_str = NULL;
	err_desc = NULL;
	ck_assert_int_eq(oidc_validate_redirect_url(r, c, "https://evil.test/return", TRUE, &err_str, &err_desc),
			 FALSE);
	ck_assert_ptr_nonnull(err_str);
	ck_assert_str_eq(err_str, "URL not allowed");
}
END_TEST

START_TEST(test_handle_mod_get_remote_user_regexp) {
	request_rec *r = oidc_test_request_get();
	oidc_json_t *json = json_pack("{s:s}", "email", "Alice@Example.COM");
	char *remote_user = NULL;

	/* substitution path (reg_exp + replace): rewrite the claim value */
	ck_assert_int_eq(oidc_get_remote_user(r, "email", "^(.*)@.*$", "$1", json, &remote_user), TRUE);
	ck_assert_ptr_nonnull(remote_user);

	/* first-match path (reg_exp, replace == NULL): extract the first capture group */
	remote_user = NULL;
	ck_assert_int_eq(oidc_get_remote_user(r, "email", "([A-Za-z]+)", NULL, json, &remote_user), TRUE);
	ck_assert_ptr_nonnull(remote_user);

	/* an invalid regex on the substitution path fails and clears the out-param */
	remote_user = NULL;
	ck_assert_int_eq(oidc_get_remote_user(r, "email", "(", "$1", json, &remote_user), FALSE);
	ck_assert_ptr_null(remote_user);

	/* an invalid regex on the first-match path fails and clears the out-param */
	remote_user = NULL;
	ck_assert_int_eq(oidc_get_remote_user(r, "email", "(", NULL, json, &remote_user), FALSE);
	ck_assert_ptr_null(remote_user);

	oidc_json_decref(json);
}
END_TEST

START_TEST(test_handle_mod_validate_redirect_url_edge_cases) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	char *err_str = NULL, *err_desc = NULL;

	/* a NULL URL is rejected up front */
	ck_assert_int_eq(oidc_validate_redirect_url(r, c, NULL, TRUE, &err_str, &err_desc), FALSE);
	ck_assert_ptr_nonnull(err_str);
	ck_assert_str_eq(err_str, "Invalid URL");

	/* a URL exceeding the maximum length is rejected before parsing */
	char *too_long = apr_pcalloc(r->pool, 20001);
	for (int i = 0; i < 20000; i++)
		too_long[i] = 'a';
	too_long[0] = '/';
	err_str = NULL;
	err_desc = NULL;
	ck_assert_int_eq(oidc_validate_redirect_url(r, c, too_long, TRUE, &err_str, &err_desc), FALSE);
	ck_assert_ptr_nonnull(err_str);
	ck_assert_str_eq(err_str, "URL too long");

	/* a relative URL carrying a CR/LF header-splitting character is rejected */
	err_str = NULL;
	err_desc = NULL;
	ck_assert_int_eq(oidc_validate_redirect_url(r, c, "/path\ninjected", TRUE, &err_str, &err_desc), FALSE);
	ck_assert_ptr_nonnull(err_str);
}
END_TEST

START_TEST(test_handle_mod_check_cookie_domain_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	cmd_parms *cmd = oidc_test_cmd_get(OIDCCookieDomain);
	ck_assert_ptr_null(oidc_cmd_cookie_domain_set(cmd, NULL, "example.com"));

	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	/* a session cookie issued for the explicitly configured domain is accepted */
	oidc_session_set_cookie_domain(r, session, "example.com");
	ck_assert_int_eq(oidc_check_cookie_domain(r, c, session), TRUE);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_mod_session_pass_tokens_full) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPassRefreshToken);
	ck_assert_ptr_null(oidc_cmd_dir_pass_refresh_token_set(cmd, dir_cfg, "On"));

	/* populate every field oidc_session_pass_tokens propagates and mark the
	 * session as new so the samesite-update branch flips needs_save */
	oidc_session_set_access_token(r, session, "AT-1");
	oidc_session_set_access_token_type(r, session, "Bearer");
	oidc_session_set_access_token_expires(r, session, 3600);
	oidc_session_set_refresh_token(r, session, "RT-1");
	oidc_session_set_scope(r, session, "openid profile");
	oidc_session_set_session_new(r, session, 1);

	/* keep the inactivity timer far from expiry so it does not also trigger */
	session->expiry = apr_time_now() + apr_time_from_sec(3600 * 24);

	apr_byte_t needs_save = FALSE;
	ck_assert_int_eq(oidc_session_pass_tokens(r, c, session, TRUE, &needs_save), TRUE);
	ck_assert_int_eq(needs_save, TRUE);

	/* the new-session bit must have been cleared as a side effect */
	ck_assert_int_eq(oidc_session_get_session_new(r, session), 0);

	/* values must have been propagated to subprocess_env */
	ck_assert_table_str(r->subprocess_env, "OIDC_access_token", "AT-1");
	ck_assert_table_str(r->subprocess_env, "OIDC_access_token_type", "Bearer");
	ck_assert_table_str(r->subprocess_env, "OIDC_scope", "openid profile");
	ck_assert_table_str(r->subprocess_env, "OIDC_refresh_token", "RT-1");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_mod_original_request_method_post_form) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	/* with OIDCPreservePost off the function always returns GET regardless of
	 * the request's actual method */
	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");
	ck_assert_str_eq(oidc_original_request_method(r, c, FALSE), OIDC_METHOD_GET);

	/* with OIDCPreservePost on, POST+form-encoded => FORM_POST */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPreservePost);
	ck_assert_ptr_null(oidc_cmd_dir_preserve_post_set(cmd, dir_cfg, "On"));
	ck_assert_str_eq(oidc_original_request_method(r, c, FALSE), OIDC_METHOD_FORM_POST);

	/* same setting but the request is a GET => still GET */
	r->method_number = M_GET;
	ck_assert_str_eq(oidc_original_request_method(r, c, FALSE), OIDC_METHOD_GET);
}
END_TEST

START_TEST(test_handle_mod_check_user_id_unauth_action_407) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCUnAuthAction);
	ck_assert_ptr_null(oidc_cmd_dir_unauth_action_set(cmd, dir_cfg, "407", NULL));

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, HTTP_PROXY_AUTHENTICATION_REQUIRED);
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
	ck_assert_table_str(r->headers_out, "Location", "https://idp.example.com/check-session");

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

START_TEST(test_handle_session_management_check_uses_session_path_params) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a session created for an originally protected path that had per-path scope and auth request params */
	oidc_session_set_path_scope(r, session, "custom_path_scope");
	oidc_session_set_path_auth_request_params(r, session, "custom_param=xyz");

	/* the silent session-management "check" re-authentication runs at the redirect URI (whose own per-path
	 * config is empty here), so it must reuse the values persisted in the session rather than dropping them */
	r->args = "session=check";
	int rc = oidc_session_management(r, c, session);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "custom_path_scope") != NULL,
		      "check re-auth must carry the session-stored per-path scope, got: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "custom_param=xyz") != NULL,
		      "check re-auth must carry the session-stored per-path auth request params, got: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "prompt=none") != NULL, "check re-auth uses prompt=none");

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

START_TEST(test_handle_check_user_id_subrequest_recycles_user) {
	request_rec *r = oidc_test_request_get();

	/* a sub-request (r->main set) recycles the authenticated user from the main request;
	 * ap_is_initial_req in the stub keys off main/prev being NULL */
	r->user = apr_pstrdup(r->pool, "alice");
	request_rec subr = *r;
	subr.main = r;
	subr.prev = NULL;
	subr.user = NULL;
	ck_assert_int_eq(oidc_check_user_id(&subr), OK);
	ck_assert_ptr_nonnull(subr.user);
	ck_assert_str_eq(subr.user, "alice");

	/* an internally-redirected request (r->prev set) recycles from the previous request */
	request_rec subr2 = *r;
	subr2.main = NULL;
	subr2.prev = r;
	subr2.user = NULL;
	ck_assert_int_eq(oidc_check_user_id(&subr2), OK);
	ck_assert_ptr_nonnull(subr2.user);
	ck_assert_str_eq(subr2.user, "alice");

	/* a sub-request whose main request carries no user cannot recycle and falls through
	 * to the regular unauthenticated handling (not auth-capable => 401) */
	r->user = NULL;
	request_rec subr3 = *r;
	subr3.main = r;
	subr3.prev = NULL;
	ck_assert_int_eq(oidc_check_user_id(&subr3), HTTP_UNAUTHORIZED);
}
END_TEST

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

START_TEST(test_handle_check_user_id_existing_session) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* build and persist a session under a known uuid, then inject the matching
	 * session cookie into r->headers_in so the second oidc_session_load (inside
	 * oidc_check_user_id) finds it in the shm cache and resumes it */
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	const char *uuid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	session->uuid = apr_pstrdup(r->pool, uuid);
	session->remote_user = apr_pstrdup(r->pool, "alice@idp.example.com");
	session->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)));
	oidc_session_set_session_expires(r, session, apr_time_now() + apr_time_from_sec(3600));
	oidc_session_set_cookie_domain(r, session, "www.example.com");
	ck_assert_int_eq(oidc_session_save(r, session, TRUE), TRUE);

	/* inject the matching cookie into the next-call's input headers */
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), uuid));

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "alice@idp.example.com");

	/* free the OUR session (the second one loaded inside oidc_check_user_id is
	 * freed by oidc_check_userid_openidc_existing_session) */
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_check_user_id_existing_session_expired) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* same setup but session_expires is already in the past => the
	 * oidc_check_max_session_duration helper short-circuits to a re-authentication
	 * (302 to OP) when the request is auth-capable */
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	const char *uuid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
	session->uuid = apr_pstrdup(r->pool, uuid);
	session->remote_user = apr_pstrdup(r->pool, "alice@idp.example.com");
	session->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)));
	oidc_session_set_session_expires(r, session, apr_time_now() - apr_time_from_sec(60));
	oidc_session_set_cookie_domain(r, session, "www.example.com");
	ck_assert_int_eq(oidc_session_save(r, session, TRUE), TRUE);

	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "%s=%s", oidc_cfg_dir_cookie_get(r), uuid));
	apr_table_set(r->headers_in, "Accept", "*/*");

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "https://idp.example.com/authorize") != NULL,
		      "expired session must trigger re-authentication, got: %s", loc);

	oidc_session_free(r, session);
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

START_TEST(test_handle_check_user_id_oauth_mixed_options) {
	request_rec *r = oidc_test_request_get();

	/* AuthType auth-openidc + an OPTIONS request with no bearer token:
	 * oidc_check_mixed_userid_oauth short-circuits to OK with an empty user */
	oidc_test_set_auth_type(OIDC_AUTH_TYPE_OPENID_BOTH);
	r->method_number = M_OPTIONS;

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, OK);
	ck_assert_str_eq(r->user, "");
}
END_TEST

START_TEST(test_handle_check_user_id_oauth_mixed_browser_fallback) {
	request_rec *r = oidc_test_request_get();

	/* AuthType auth-openidc, no bearer token and not OPTIONS: the mixed handler
	 * falls back to the OIDC browser flow => 302 to the OP for an auth-capable
	 * request */
	oidc_test_set_auth_type(OIDC_AUTH_TYPE_OPENID_BOTH);
	apr_table_set(r->headers_in, "Accept", "*/*");

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
}
END_TEST

START_TEST(test_handle_check_user_id_oauth_mixed_bearer) {
	request_rec *r = oidc_test_request_get();

	/* a bearer token routes the mixed handler to the OAuth resource-server path
	 * (oidc_oauth_check_userid); with no token validation configured it is
	 * rejected => 401 */
	oidc_test_set_auth_type(OIDC_AUTH_TYPE_OPENID_BOTH);
	apr_table_set(r->headers_in, "Authorization", "Bearer some-access-token");

	int rc = oidc_check_user_id(r);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

START_TEST(test_handle_fixups_enabled) {
	request_rec *r = oidc_test_request_get();

	/* with the module enabled (AuthType openid-connect) the fixups hook runs the
	 * metrics timing and returns OK */
	ck_assert_int_eq(oidc_fixups(r), OK);
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

START_TEST(test_handle_jwks_request_with_public_key) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* publish one RSA public key (test/public.pem) at the JWKs endpoint so the serialization loop runs */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	const char *err =
	    oidc_cmd_public_keys_set(oidc_test_cmd_get(OIDCPublicKeyFiles), NULL,
				     apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-1#%s/public.pem", dir)));
	ck_assert_msg(err == NULL, "could not load public key: %s", err);
	ck_assert_int_gt(oidc_cfg_public_keys_get(c)->nelts, 0);

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
	ck_assert_table_str(r->headers_out, "Location", "https://www.example.com/logged-out");

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
	oidc_json_object_set_new(jwt->payload.value.json, "iss", oidc_json_string(iss));
	oidc_json_object_set_new(jwt->payload.value.json, "aud", oidc_json_string(aud));
	oidc_json_object_set_new(jwt->payload.value.json, "sub", oidc_json_string(sub));
	oidc_json_object_set_new(jwt->payload.value.json, "jti", oidc_json_string(jti));
	apr_time_t now = apr_time_sec(apr_time_now());
	oidc_json_object_set_new(jwt->payload.value.json, "iat", oidc_json_integer(now));
	if (with_events) {
		oidc_json_t *events = oidc_json_object();
		oidc_json_object_set_new(events, "http://schemas.openid.net/event/backchannel-logout",
					 oidc_json_object());
		oidc_json_object_set_new(jwt->payload.value.json, "events", events);
	}
	if (with_nonce)
		oidc_json_object_set_new(jwt->payload.value.json, "nonce", oidc_json_string("n1"));
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

/* wrap a compact JWT string in a symmetric JWE (A256KW/A256GCM) using a key derived from the secret the
 * same way the module derives its decryption key, so it round-trips through oidc_logout_backchannel_parse_jwt */
static char *e2e_encrypt_symmetric(request_rec *r, const char *plaintext, const char *secret) {
	apr_pool_t *pool = r->pool;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(
	    oidc_util_key_symmetric_create(r, secret, oidc_alg2keysize("A256KW"), OIDC_JOSE_ALG_SHA256, TRUE, &jwk),
	    TRUE);
	ck_assert_ptr_nonnull(jwk);

	oidc_jwt_t *jwe = oidc_jwt_new(pool, TRUE, TRUE);
	jwe->header.alg = apr_pstrdup(pool, "A256KW");
	jwe->header.enc = apr_pstrdup(pool, "A256GCM");
	char *cser = NULL;
	ck_assert_int_eq(oidc_jwt_encrypt(pool, jwe, jwk, plaintext, (int)_oidc_strlen(plaintext), &cser, &err), TRUE);
	ck_assert_ptr_nonnull(cser);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwe);
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

	char *logout_jwt = e2e_sign_backchannel_logout_jwt(r, "https://idp.example.com", "client_id", "alice", "jti-1",
							   TRUE, FALSE, secret);
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

START_TEST(test_handle_logout_backchannel_encrypted) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	const char *secret = "backchannel-logout-shared-secret-XYZ";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	/* an HS256-signed logout token, symmetrically encrypted with a key derived from the client secret:
	 * the module must decrypt it using that same client-secret-derived key (the provider is only known
	 * after decryption, so this exercises the client-secret decryption key added at parse time) */
	char *logout_jwt = e2e_sign_backchannel_logout_jwt(r, "https://idp.example.com", "client_id", "alice",
							   "jti-enc", TRUE, FALSE, secret);
	char *logout_jwe = e2e_encrypt_symmetric(r, logout_jwt, secret);
	char *body = apr_psprintf(r->pool, "logout_token=%s", oidc_http_url_encode(r, logout_jwe));
	e2e_post_body(r, body);
	apr_table_set(r->subprocess_env, "OIDC_REDIRECT_URI_REQUEST", "backchannel");
	r->args = apr_pstrcat(r->pool, "logout=backchannel&", body, NULL);
	r->remaining = (apr_size_t)_oidc_strlen(r->args);

	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, OK);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_backchannel_by_sub) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *iss = oidc_cfg_provider_issuer_get(provider);

	const char *secret = "backchannel-logout-shared-secret-XYZ";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	/* create and persist a session indexed by a real "sid" AND (back-channel logout enabled) by "sub" */
	const char *uuid = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	session->uuid = apr_pstrdup(r->pool, uuid);
	session->remote_user = apr_pstrdup(r->pool, "alice");
	session->expiry = apr_time_now() + apr_time_from_sec(3600);
	oidc_session_set_issuer(r, session, iss);
	oidc_session_set_session_expires(r, session, session->expiry);
	session->sid = oidc_response_make_sid_iss_unique(r, "real-sid", iss);
	session->sub = oidc_response_make_sid_iss_unique(r, "alice-sub", iss);
	ck_assert_int_eq(oidc_session_save(r, session, TRUE), TRUE);

	/* a back-channel logout token carrying only "sub" must locate the session via the secondary index */
	char *logout_jwt =
	    e2e_sign_backchannel_logout_jwt(r, iss, "client_id", "alice-sub", "jti-by-sub", TRUE, FALSE, secret);
	char *body = apr_psprintf(r->pool, "logout_token=%s", oidc_http_url_encode(r, logout_jwt));
	e2e_post_body(r, body);
	apr_table_set(r->subprocess_env, "OIDC_REDIRECT_URI_REQUEST", "backchannel");
	r->args = apr_pstrcat(r->pool, "logout=backchannel&", body, NULL);
	r->remaining = (apr_size_t)_oidc_strlen(r->args);

	int rc = oidc_logout(r, c, session);
	ck_assert_int_eq(rc, OK);

	/* the session and BOTH of its cache index entries are now gone */
	char *v = NULL;
	oidc_cache_get_session(r, uuid, &v);
	ck_assert_ptr_null(v);
	oidc_cache_get_sid(r, oidc_response_make_sid_iss_unique(r, "real-sid", iss), &v);
	ck_assert_ptr_null(v);
	oidc_cache_get_sid(r, oidc_response_make_sid_iss_unique(r, "alice-sub", iss), &v);
	ck_assert_ptr_null(v);

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
	char *logout_jwt = e2e_sign_backchannel_logout_jwt(r, "https://idp.example.com", "client_id", "alice", "jti-2",
							   FALSE, FALSE, secret);
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
	char *logout_jwt = e2e_sign_backchannel_logout_jwt(r, "https://idp.example.com", "client_id", "alice", "jti-3",
							   TRUE, TRUE, secret);
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

/*
 * Tests for handle/request_uri.c — the request-object-by-reference
 * endpoint that the OP fetches when the RP advertises a request_uri
 * during the authorization request.
 */

START_TEST(test_handle_request_uri_missing_param) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* call without a request_uri= parameter => BAD_REQUEST */
	r->args = "";
	int rc = oidc_request_uri(r, c);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);
}
END_TEST

START_TEST(test_handle_request_uri_not_cached) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* parameter present but the referenced ID is not in the request-uri cache => NOT_FOUND */
	r->args = "request_uri=missing-ref";
	int rc = oidc_request_uri(r, c);
	ck_assert_int_eq(rc, HTTP_NOT_FOUND);
}
END_TEST

START_TEST(test_handle_request_uri_happy_path) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* prime the request-uri cache with a JWT-shaped payload then serve it back */
	const char *ref = "abc123";
	const char *jwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJjbGllbnQifQ.";
	oidc_cache_set_request_uri(r, ref, jwt, apr_time_now() + apr_time_from_sec(60));

	r->args = apr_psprintf(r->pool, "request_uri=%s", ref);
	int rc = oidc_request_uri(r, c);
	ck_assert_int_eq(rc, OK);
	/* oidc_util_http_content_prep stamps r->user="" and stores the body + content-type
	 * in the request state for the content handler to flush */
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "");
	ck_assert_str_eq(oidc_request_state_get(r, "data"), jwt);
	ck_assert_str_eq(oidc_request_state_get(r, "content_type"), OIDC_HTTP_CONTENT_TYPE_JWT);
	/* the cache entry is consumed in a single shot — a follow-up call must 404 */
	char *check = NULL;
	oidc_cache_get_request_uri(r, ref, &check);
	ck_assert_ptr_null(check);
}
END_TEST

/*
 * Tests for the oidc_handle_redirect_uri_request dispatcher in
 * mod_auth_openidc.c — focus on the routing decisions (which branch is
 * selected for a given request shape) rather than re-testing the
 * sub-handlers, which the other suites above cover.
 */

START_TEST(test_handle_dispatch_jwks) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* ?jwks must short-circuit to OK and stamp r->user="" so the
	 * authn hook lets the content handler serve the JWKS document;
	 * oidc_util_url_has_parameter matches on "name=" so the value is irrelevant */
	r->args = "jwks=1";
	r->method_number = M_GET;
	r->user = NULL;
	int rc = oidc_handle_redirect_uri_request(r, c, session);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_dispatch_dpop) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* ?dpop must short-circuit to OK and stamp r->user="" so the
	 * authn hook lets the content handler serve the DPoP proof */
	r->args = "dpop=1";
	r->method_number = M_GET;
	r->user = NULL;
	int rc = oidc_handle_redirect_uri_request(r, c, session);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_dispatch_info_no_session_returns_unauthorized) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* ?info on an empty session (remote_user == NULL) must return 401
	 * without touching any of the info-handler internals */
	ck_assert_ptr_null(session->remote_user);
	r->args = "info=json";
	r->method_number = M_GET;
	int rc = oidc_handle_redirect_uri_request(r, c, session);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_dispatch_unknown_args_returns_500) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a GET to the redirect URI carrying args that match none of the
	 * recognised parameters falls through to the invalid-request handler
	 * which returns HTTP_INTERNAL_SERVER_ERROR via oidc_util_html_send_error */
	r->args = "unrecognized=1";
	r->method_number = M_GET;
	int rc = oidc_handle_redirect_uri_request(r, c, session);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_dispatch_empty_args_routes_to_implicit_flow) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a "bare" GET to the redirect URI (no args) is the implicit-flow
	 * fragment-mode bootstrap: the dispatcher must hand off to
	 * oidc_javascript_implicit which preps an HTML page and returns OK */
	r->args = NULL;
	r->method_number = M_GET;
	r->user = NULL;
	int rc = oidc_handle_redirect_uri_request(r, c, session);
	ck_assert_int_eq(rc, OK);
	/* oidc_util_html_content_prep stores the body under the "body" request
	 * state key and stamps r->user="" so the content handler runs */
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "");
	const char *html = oidc_request_state_get(r, "body");
	ck_assert_ptr_nonnull(html);
	ck_assert_msg(_oidc_strstr(html, "form") != NULL,
		      "implicit-flow body must contain the fragment-collecting form");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_dispatch_logout_takes_precedence_over_post_authn) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a POST with a ?logout= query parameter must be routed to oidc_logout
	 * (back-channel logout), not to the POST authorization-response handler:
	 * the dispatcher checks for the logout parameter BEFORE oidc_proto_response_is_post.
	 * Without a logout_token in the form body, oidc_logout returns BAD_REQUEST —
	 * if routing went to the POST authn branch instead we'd see a different code
	 * (typically a state-mismatch failure). */
	r->args = "logout=backchannel";
	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");
	r->remaining = 0;
	int rc = oidc_handle_redirect_uri_request(r, c, session);
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);

	oidc_session_free(r, session);
}
END_TEST

/* (re-)populate the session fields that oidc_handle_existing_session consumes; the
 * logout/authenticate error actions kill the session so each sub-scenario re-seeds it */
static void existing_session_seed(request_rec *r, oidc_session_t *session, apr_byte_t with_issuer) {
	session->remote_user = apr_pstrdup(r->pool, "alice");
	if (with_issuer)
		oidc_session_set_issuer(r, session, "https://idp.example.com");
	/* must match the current host so oidc_check_cookie_domain passes */
	oidc_session_set_cookie_domain(r, session, "www.example.com");
	/* keep the session within its maximum duration */
	oidc_session_set_session_expires(r, session, apr_time_now() + apr_time_from_sec(3600));
}

START_TEST(test_handle_dispatch_info_happy_sets_authn_header) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* a healthy session passing through the existing-session handler must set both
	 * r->user and the configured OIDCAuthNHeader request header */
	ck_assert_ptr_null(oidc_cmd_cookie_domain_set(oidc_test_cmd_get(OIDCCookieDomain), NULL, "www.example.com"));
	ck_assert_ptr_null(oidc_cmd_dir_authn_header_set(oidc_test_cmd_get(OIDCAuthNHeader), dir_cfg, "X-Remote-User"));
	existing_session_seed(r, session, TRUE);
	r->args = "info=json";
	r->method_number = M_GET;
	ck_assert_int_eq(oidc_handle_redirect_uri_request(r, c, session), OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "alice");
	ck_assert_table_str(r->headers_in, "X-Remote-User", "alice");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_existing_session_cookie_domain_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* an authenticated session whose stored cookie domain does not match the
	 * current host must be rejected */
	session->remote_user = apr_pstrdup(r->pool, "alice");
	oidc_session_set_cookie_domain(r, session, "other.example.com");
	r->args = "info=json";
	r->method_number = M_GET;
	ck_assert_int_eq(oidc_handle_redirect_uri_request(r, c, session), HTTP_UNAUTHORIZED);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_existing_session_refresh_error_actions) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCRefreshAccessTokenBeforeExpiry);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	r->args = "info=json";
	r->method_number = M_GET;

	/* pin the configured cookie domain to the value the session seed stores */
	ck_assert_ptr_null(oidc_cmd_cookie_domain_set(oidc_test_cmd_get(OIDCCookieDomain), NULL, "www.example.com"));

	/* make the access token due for refresh while no refresh token is available,
	 * so oidc_refresh_access_token_before_expiry fails */
	ck_assert_ptr_null(oidc_cmd_dir_refresh_access_token_before_expiry_set(cmd, dir_cfg, "60", NULL));

	/* default action: 502 */
	existing_session_seed(r, session, TRUE);
	oidc_session_set_access_token_expires(r, session, 30);
	ck_assert_int_eq(oidc_handle_redirect_uri_request(r, c, session), HTTP_BAD_GATEWAY);

	/* logout action: the session is killed and the logged-out page is prepped */
	ck_assert_ptr_null(oidc_cmd_dir_refresh_access_token_before_expiry_set(cmd, dir_cfg, "60", "logout_on_error"));
	existing_session_seed(r, session, TRUE);
	oidc_session_set_access_token_expires(r, session, 30);
	ck_assert_int_eq(oidc_handle_redirect_uri_request(r, c, session), OK);

	/* authenticate action: the session is killed and re-authentication starts; the fixture
	 * request is not auth-capable (no HTML-accepting user agent) so this lands on a 401 */
	ck_assert_ptr_null(
	    oidc_cmd_dir_refresh_access_token_before_expiry_set(cmd, dir_cfg, "60", "authenticate_on_error"));
	existing_session_seed(r, session, TRUE);
	oidc_session_set_access_token_expires(r, session, 30);
	ck_assert_int_eq(oidc_handle_redirect_uri_request(r, c, session), HTTP_UNAUTHORIZED);

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_existing_session_userinfo_error_actions) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCUserInfoRefreshInterval);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	r->args = "info=json";
	r->method_number = M_GET;

	/* pin the configured cookie domain to the value the session seed stores */
	ck_assert_ptr_null(oidc_cmd_cookie_domain_set(oidc_test_cmd_get(OIDCCookieDomain), NULL, "www.example.com"));

	/* default action (502), via the provider-lookup failure: the session carries a
	 * userinfo refresh interval that is due but no issuer to resolve a provider with */
	existing_session_seed(r, session, FALSE);
	oidc_session_set_userinfo_refresh_interval(r, session, 1);
	ck_assert_int_eq(oidc_handle_redirect_uri_request(r, c, session), HTTP_BAD_GATEWAY);

	/* logout action, via an unreachable userinfo endpoint */
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, "http://127.0.0.1:1/userinfo");
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_refresh_interval_set(cmd, NULL, "1", "logout_on_error"));
	existing_session_seed(r, session, TRUE);
	oidc_session_set_userinfo_refresh_interval(r, session, 1);
	ck_assert_int_eq(oidc_handle_redirect_uri_request(r, c, session), OK);

	/* authenticate action: kills the session and starts re-authentication; the fixture
	 * request is not auth-capable (no HTML-accepting user agent) so this lands on a 401 */
	ck_assert_ptr_null(oidc_cmd_provider_userinfo_refresh_interval_set(cmd, NULL, "1", "authenticate_on_error"));
	existing_session_seed(r, session, TRUE);
	oidc_session_set_userinfo_refresh_interval(r, session, 1);
	ck_assert_int_eq(oidc_handle_redirect_uri_request(r, c, session), HTTP_UNAUTHORIZED);

	oidc_session_free(r, session);
}
END_TEST

/*
 * Tests for handle/authz.c — drive oidc_authz_24_checker_claim through the
 * anonymous shortcuts, the OAuth20 vs OpenID-Connect denial branches and
 * the OIDCUnAutzAction policy paths so oidc_authz_24_unauthorized_user,
 * oidc_authz_merge_claims, oidc_authz_get_claims_idtoken_scope and
 * oidc_authz_skip_to_content_handler all get exercised.
 */

START_TEST(test_handle_authz_24_claim_granted_from_idtoken) {
	request_rec *r = oidc_test_request_get();
	r->user = apr_pstrdup(r->pool, "alice");
	/* seed an id_token in the request state so merge_claims has something to evaluate */
	oidc_json_t *id_token = json_pack("{s:s}", "sub", "alice");
	oidc_request_state_json_set(r, OIDC_REQUEST_STATE_KEY_IDTOKEN, id_token);
	oidc_json_decref(id_token);

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:alice", NULL);
	ck_assert_int_eq(rc, AUTHZ_GRANTED);
}
END_TEST

#ifdef USE_LIBJQ

/* Require claims_expr: the jq expression evaluates to true against the
 * claims merged from the request state */
START_TEST(test_handle_authz_24_claims_expr_granted) {
	request_rec *r = oidc_test_request_get();
	r->user = apr_pstrdup(r->pool, "alice");
	oidc_json_t *id_token = json_pack("{s:s,s:[s,s]}", "sub", "alice", "groups", "users", "admins");
	oidc_request_state_json_set(r, OIDC_REQUEST_STATE_KEY_IDTOKEN, id_token);
	oidc_json_decref(id_token);

	/* NB: the Require line is split on unquoted whitespace by ap_getword_conf,
	 * so a real-world jq expression argument is either quoted or space-free */
	authz_status rc = oidc_authz_24_checker_claims_expr(r, ".groups|index(\"admins\")!=null", NULL);
	ck_assert_int_eq(rc, AUTHZ_GRANTED);
}
END_TEST

/* Require claims_expr: a jq expression that does not evaluate to true denies */
START_TEST(test_handle_authz_24_claims_expr_denied) {
	request_rec *r = oidc_test_request_get();
	r->user = apr_pstrdup(r->pool, "alice");
	oidc_json_t *id_token = json_pack("{s:s}", "sub", "alice");
	oidc_request_state_json_set(r, OIDC_REQUEST_STATE_KEY_IDTOKEN, id_token);
	oidc_json_decref(id_token);

	authz_status rc = oidc_authz_24_checker_claims_expr(r, ".sub==\"bob\"", NULL);
	ck_assert_int_eq(rc, AUTHZ_DENIED);
}
END_TEST

#endif /* USE_LIBJQ */

START_TEST(test_handle_authz_24_anonymous_unauth_pass) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCUnAuthAction);
	ck_assert_ptr_null(oidc_cmd_dir_unauth_action_set(cmd, dir_cfg, "pass", NULL));

	r->user = apr_pstrdup(r->pool, "");
	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:nobody", NULL);
	ck_assert_int_eq(rc, AUTHZ_GRANTED);
}
END_TEST

START_TEST(test_handle_authz_24_anonymous_skip_via_discovery_state) {
	request_rec *r = oidc_test_request_get();
	r->user = apr_pstrdup(r->pool, "");
	/* discovery state set => skip_to_content_handler short-circuits to GRANTED */
	oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_DISCOVERY, "1");

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:nobody", NULL);
	ck_assert_int_eq(rc, AUTHZ_GRANTED);
}
END_TEST

START_TEST(test_handle_authz_24_anonymous_options_method) {
	request_rec *r = oidc_test_request_get();
	r->user = apr_pstrdup(r->pool, "");
	r->method_number = M_OPTIONS;

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:nobody", NULL);
	ck_assert_int_eq(rc, AUTHZ_GRANTED);
}
END_TEST

START_TEST(test_handle_authz_24_oauth20_denied) {
	request_rec *r = oidc_test_request_get();
	r->user = apr_pstrdup(r->pool, "alice");
	/* setting r->ap_auth_type doesn't influence ap_auth_type(r) in the fixture
	 * (that reads from core_dir_config), so we just verify the worker denies
	 * when the claim doesn't match the id_token */
	r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_OAUTH20);

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:bob", NULL);
	ck_assert_int_eq(rc, AUTHZ_DENIED);
}
END_TEST

START_TEST(test_handle_authz_24_oauth20_sets_bearer_scope_error) {
	request_rec *r = oidc_test_request_get();
	r->user = apr_pstrdup(r->pool, "alice");
	/* oidc_test_set_auth_type actually drives ap_auth_type(r), unlike r->ap_auth_type
	 * in this fixture, so this reaches the OAuth20-specific denial branch in
	 * oidc_authz_24_unauthorized_user rather than the OIDCUnAutzAction switch */
	oidc_test_set_auth_type(OIDC_AUTH_TYPE_OPENID_OAUTH20);

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:bob", NULL);
	ck_assert_int_eq(rc, AUTHZ_DENIED);
	ck_assert_table_str(r->subprocess_env, "OIDC_OAUTH_BEARER_SCOPE_ERROR",
			    "Bearer error=\"insufficient_scope\", error_description=\"Different scope(s) or other "
			    "claims required\"");

	oidc_test_set_auth_type(NULL);
}
END_TEST

START_TEST(test_handle_authz_24_unautz_authenticate_redirects) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	r->user = apr_pstrdup(r->pool, "alice");
	r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_CONNECT);

	/* OIDCUnAutzAction must be explicitly set to "auth" - the default is 403, which never
	 * reaches the OIDC_UNAUTZ_AUTHENTICATE case at all */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCUnAutzAction);
	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "auth", NULL));

	/* the fixture sets no Accept header by default (oidc_is_auth_capable_request would
	 * otherwise deny outright); an HTML-accepting browser-like request is auth-capable, and
	 * with no unauth_expression configured the AUTHENTICATE case falls straight through to
	 * oidc_request_authenticate_user - no metadata_dir means it uses the static provider and
	 * redirects there, landing in the "Stepup Authentication" HTML-refresh branch */
	apr_table_set(r->headers_in, "Accept", "text/html");
	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:bob", NULL);
	ck_assert_int_eq(rc, AUTHZ_DENIED);
	ck_assert_int_eq(r->header_only, 1);
	/* the real authorization redirect was captured into the HTML refresh meta tag, not
	 * left on the outgoing Location header (that was cleared) */
	ck_assert_ptr_null(apr_table_get(r->headers_out, "Location"));
	/* oidc_util_html_send writes straight to the response body via ap_pass_brigade; the
	 * test stub captures that under the "sent_body" request state key */
	const char *body = oidc_request_state_get(r, "sent_body");
	ck_assert_ptr_nonnull(body);
	ck_assert_msg(_oidc_strstr(body, "https://idp.example.com/authorize") != NULL,
		      "stepup body carries the authorization redirect");
}
END_TEST

START_TEST(test_handle_authz_24_unautz_authenticate_xhr_denied_401) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	r->user = apr_pstrdup(r->pool, "alice");
	r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_CONNECT);

	/* OIDCUnAutzAction must be explicitly set to "auth" to reach the AUTHENTICATE case */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCUnAutzAction);
	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "auth", NULL));

	/* no unauth_expression configured, and an XHR-shaped request is not auth-capable,
	 * so the exception check denies with a plain 401 instead of redirecting */
	apr_table_set(r->headers_in, "X-Requested-With", "XMLHttpRequest");

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:bob", NULL);
	ck_assert_int_eq(rc, AUTHZ_DENIED);
	ck_assert_ptr_null(apr_table_get(r->headers_out, "Location"));
	ck_assert_ptr_null(oidc_request_state_get(r, "sent_body"));
}
END_TEST

START_TEST(test_handle_authz_24_unautz_authenticate_expr_bypasses_xhr_check) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	r->user = apr_pstrdup(r->pool, "alice");
	r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_CONNECT);

	/* OIDCUnAutzAction must be explicitly set to "auth" to reach the AUTHENTICATE case */
	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(oidc_test_cmd_get(OIDCUnAutzAction), dir_cfg, "auth", NULL));

	/* with an OIDCUnAuthAction expression configured, the expression replaces the built-in
	 * XHR-capability heuristic entirely: even an XHR-shaped request proceeds to the
	 * authenticate fall-through when the effective action is "auth". NB: the stubbed
	 * boolean ap_expr_exec always reports an evaluation error, so unauth_action_get falls
	 * back to its default (authenticate) here - the expr-denies arm needs a real evaluator */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCUnAuthAction);
	ck_assert_ptr_null(oidc_cmd_dir_unauth_action_set(cmd, dir_cfg, "401", "req('X-Requested-With')"));
	apr_table_set(r->headers_in, "X-Requested-With", "XMLHttpRequest");

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:bob", NULL);
	ck_assert_int_eq(rc, AUTHZ_DENIED);
	/* the XHR header did NOT stop the redirect: the stepup HTML-refresh page was sent */
	const char *body = oidc_request_state_get(r, "sent_body");
	ck_assert_ptr_nonnull(body);
	ck_assert_msg(_oidc_strstr(body, "https://idp.example.com/authorize") != NULL,
		      "stepup body carries the authorization redirect despite the XHR header");
}
END_TEST

START_TEST(test_handle_authz_24_oidc_unautz_return_401) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	r->user = apr_pstrdup(r->pool, "alice");
	r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_CONNECT);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCUnAutzAction);
	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "401", "Denied"));

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:bob", NULL);
	ck_assert_int_eq(rc, AUTHZ_DENIED);
}
END_TEST

START_TEST(test_handle_authz_24_oidc_unautz_return_302) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	r->user = apr_pstrdup(r->pool, "alice");
	r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_CONNECT);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCUnAutzAction);
	ck_assert_ptr_null(oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "302", "https://www.example.com/denied"));

	authz_status rc = oidc_authz_24_checker_claim(r, "claim sub:bob", NULL);
	ck_assert_int_eq(rc, AUTHZ_DENIED);
}
END_TEST

/*
 * Tests for handle/request.c — the cookie-domain sanity checks and the
 * oidc_request_authenticate_user branches the authz/response suites miss.
 */

START_TEST(test_handle_request_check_cookie_domain) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* a same-host original URL shares cookies with the redirect URI */
	ck_assert_int_eq(oidc_request_check_cookie_domain(r, c, "https://www.example.com/protected/x"), TRUE);

	/* an http:// original URL cannot share cookies with an https:// redirect URI */
	ck_assert_int_eq(oidc_request_check_cookie_domain(r, c, "http://www.example.com/protected/x"), FALSE);

	/* a different hostname (no OIDCCookieDomain configured) cannot share cookies */
	ck_assert_int_eq(oidc_request_check_cookie_domain(r, c, "https://other.example.org/protected/x"), FALSE);

	/* with OIDCCookieDomain configured, a host outside that domain cannot share cookies */
	ck_assert_ptr_null(oidc_cmd_cookie_domain_set(oidc_test_cmd_get(OIDCCookieDomain), NULL, "www.example.com"));
	ck_assert_int_eq(oidc_request_check_cookie_domain(r, c, "https://elsewhere.example.org/x"), FALSE);
	ck_assert_int_eq(oidc_request_check_cookie_domain(r, c, "https://www.example.com/protected/x"), TRUE);
}
END_TEST

START_TEST(test_handle_request_authenticate_user_branches) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* a NULL original URL cannot be stored in the state */
	ck_assert_int_eq(oidc_request_authenticate_user(r, c, provider, NULL, NULL, NULL, NULL, NULL, NULL),
			 HTTP_INTERNAL_SERVER_ERROR);

	/* an original URL on a different host fails the cookie-domain sanity check */
	ck_assert_int_eq(
	    oidc_request_authenticate_user(r, c, provider, "https://other.example.org/x", NULL, NULL, NULL, NULL, NULL),
	    HTTP_INTERNAL_SERVER_ERROR);

	/* happy path with a configured response_mode, a check_session_iframe (so the per-path
	 * params/scope are persisted in the state) and SameSite=None state cookies */
	c->cookie_same_site_state = OIDC_SAMESITE_COOKIE_NONE;
	ck_assert_ptr_null(oidc_cfg_provider_response_mode_set(r->pool, provider, "query"));
	ck_assert_ptr_null(
	    oidc_cfg_provider_check_session_iframe_set(r->pool, provider, "https://idp.example.com/check"));
	ck_assert_int_eq(oidc_request_authenticate_user(r, c, provider, "https://www.example.com/protected/x", NULL,
							NULL, NULL, "acr_values=urn:level:1", "extra_scope"),
			 HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "https://idp.example.com/authorize") != NULL,
		      "redirects to the authorization endpoint");
	ck_assert_msg(_oidc_strstr(loc, "response_mode=query") != NULL, "carries the configured response_mode");
}
END_TEST

START_TEST(test_handle_request_authenticate_user_too_many_state_cookies) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* an existing valid state cookie + OIDCStateMaxNumberOfCookies 1 (without deleting
	 * the oldest) means no additional state cookie may be set: 503 */
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "n");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_response_type(ps, OIDC_PROTO_RESPONSE_TYPE_CODE);
	oidc_proto_state_set_timestamp_now(ps);
	char *cv = oidc_proto_state_to_cookie(r, c, ps);
	oidc_proto_state_destroy(ps);
	ck_assert_ptr_nonnull(cv);
	apr_table_set(r->headers_in, "Cookie", apr_psprintf(r->pool, "mod_auth_openidc_state_existing=%s", cv));

	ck_assert_ptr_null(oidc_cmd_max_number_of_state_cookies_set(oidc_test_cmd_get(OIDCStateMaxNumberOfCookies),
								    NULL, "1", "false"));

	ck_assert_int_eq(oidc_request_authenticate_user(r, c, provider, "https://www.example.com/protected/x", NULL,
							NULL, NULL, NULL, NULL),
			 HTTP_SERVICE_UNAVAILABLE);
}
END_TEST

START_TEST(test_handle_request_authenticate_user_discovery_and_static_metadata) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* provider == NULL with an OIDCMetadataDir configured: discovery is deferred to the
	 * content handler by stamping the discovery request state and r->user="" */
	char *tmpl = apr_pstrdup(r->pool, "/tmp/mod_auth_openidc_test_XXXXXX");
	ck_assert_ptr_nonnull(mkdtemp(tmpl));
	ck_assert_ptr_null(oidc_cmd_metadata_dir_set(oidc_test_cmd_get(OIDCMetadataDir), NULL, tmpl));
	ck_assert_int_eq(oidc_request_authenticate_user(r, c, NULL, "https://www.example.com/protected/x", NULL, NULL,
							NULL, NULL, NULL),
			 OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "");
	ck_assert_ptr_nonnull(oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY));
	rmdir(tmpl);
}
END_TEST

START_TEST(test_handle_request_authenticate_user_static_config_fails) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* provider == NULL, no metadata dir, but an OIDCProviderMetadataURL that cannot be
	 * retrieved: oidc_provider_static_config fails and the request errors out */
	ck_assert_ptr_null(oidc_cfg_provider_metadata_url_set(r->pool, provider, "http://127.0.0.1:1/metadata"));
	ck_assert_int_eq(oidc_request_authenticate_user(r, c, NULL, "https://www.example.com/protected/x", NULL, NULL,
							NULL, NULL, NULL),
			 HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

/*
 * Additional tests for handle/content.c — exercise the request-state
 * branches in oidc_content_handler that the existing tests don't reach.
 */

START_TEST(test_handle_content_handler_redirect_uri_http_state) {
	request_rec *r = oidc_test_request_get();
	r->parsed_uri.path = apr_pstrdup(r->pool, "/protected/");
	r->args = "";
	oidc_util_http_content_prep(r, "hi", 2, "text/plain");
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_content_handler_redirect_uri_html_state) {
	request_rec *r = oidc_test_request_get();
	r->parsed_uri.path = apr_pstrdup(r->pool, "/protected/");
	r->args = "";
	oidc_util_html_content_prep(r, OIDC_REQUEST_STATE_KEY_HTML, "T", NULL, NULL, "<p>x</p>");
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_content_handler_redirect_uri_info_no_session) {
	request_rec *r = oidc_test_request_get();
	r->parsed_uri.path = apr_pstrdup(r->pool, "/protected/");
	r->args = "info=json";
	/* dispatches to oidc_info_request which short-circuits to 401 (no remote_user) */
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

START_TEST(test_handle_content_handler_redirect_uri_dpop_disabled) {
	request_rec *r = oidc_test_request_get();
	r->parsed_uri.path = apr_pstrdup(r->pool, "/protected/");
	r->args = "dpop=1";
	int rc = oidc_content_handler(r);
	/* DPoP is disabled in the fixture => oidc_dpop_request returns BAD_REQUEST */
	ck_assert_int_eq(rc, HTTP_BAD_REQUEST);
}
END_TEST

START_TEST(test_handle_content_handler_discovery_state) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	r->parsed_uri.path = apr_pstrdup(r->pool, "/somewhere/else");
	r->args = "";
	/* configure an external discovery handler so oidc_discovery_request takes the
	 * 302-to-external-page path rather than dereferencing a NULL metadata dir */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCDiscoverURL);
	ck_assert_ptr_null(oidc_cmd_dir_discover_url_set(cmd, dir_cfg, "https://disco.example.com/select"));
	oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_DISCOVERY, "1");
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
}
END_TEST

START_TEST(test_handle_content_handler_authn_post_state) {
	request_rec *r = oidc_test_request_get();
	r->parsed_uri.path = apr_pstrdup(r->pool, "/somewhere/else");
	r->args = "";
	oidc_util_html_content_prep(r, OIDC_REQUEST_STATE_KEY_AUTHN_POST, "Auth", NULL, NULL, "<form>x</form>");
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_content_handler_authn_preserve_state) {
	request_rec *r = oidc_test_request_get();
	r->parsed_uri.path = apr_pstrdup(r->pool, "/somewhere/else");
	r->args = "";
	oidc_util_html_content_prep(r, OIDC_REQUEST_STATE_KEY_AUTHN_PRESERVE, "Pres", NULL, NULL, "<p>x</p>");
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_content_handler_http_state_non_redirect) {
	request_rec *r = oidc_test_request_get();
	r->parsed_uri.path = apr_pstrdup(r->pool, "/somewhere/else");
	r->args = "";
	oidc_util_http_content_prep(r, "x", 1, "text/plain");
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, OK);
}
END_TEST

START_TEST(test_handle_content_handler_html_state_non_redirect) {
	request_rec *r = oidc_test_request_get();
	r->parsed_uri.path = apr_pstrdup(r->pool, "/somewhere/else");
	r->args = "";
	oidc_util_html_content_prep(r, OIDC_REQUEST_STATE_KEY_HTML, "T", NULL, NULL, "<p>x</p>");
	int rc = oidc_content_handler(r);
	ck_assert_int_eq(rc, OK);
}
END_TEST

/*
 * Additional test for handle/info.c — configure every hook field that the
 * test fixture can populate from session state so oidc_info_build_json
 * exercises the access_token, id_token_hint, refresh_token, session-info
 * and session-expiry branches plus the oidc_info_add_access_token /
 * oidc_info_add_session helpers.
 */

START_TEST(test_handle_info_json_full_hook_data) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	session->remote_user = apr_pstrdup(r->pool, "alice");
	oidc_session_set_access_token(r, session, "AT-XYZ");
	oidc_session_set_access_token_type(r, session, "Bearer");
	oidc_session_set_access_token_expires(r, session, 3600);
	oidc_session_set_idtoken(r, session, "id-token-jwt");
	oidc_session_set_refresh_token(r, session, "RT-XYZ");

	const char *fields[] = {OIDC_HOOK_INFO_TIMESTAMP,	OIDC_HOOK_INFO_ACCES_TOKEN,
				OIDC_HOOK_INFO_ACCES_TOKEN_EXP, OIDC_HOOK_INFO_ID_TOKEN_HINT,
				OIDC_HOOK_INFO_SESSION,		OIDC_HOOK_INFO_SESSION_EXP,
				OIDC_HOOK_INFO_SESSION_TIMEOUT, OIDC_HOOK_INFO_SESSION_REMOTE_USER,
				OIDC_HOOK_INFO_REFRESH_TOKEN};
	for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		cmd_parms *cmd = oidc_test_cmd_get(OIDCInfoHook);
		ck_assert_ptr_null(oidc_cmd_info_hook_data_set(cmd, NULL, fields[i]));
	}

	r->args = "info=json&extend_session=false";
	int rc = oidc_info_request(r, c, session, FALSE);
	ck_assert_int_eq(rc, OK);

	oidc_session_free(r, session);
}
END_TEST

/*
 * Additional tests for handle/logout.c — drive oidc_logout_revoke_tokens
 * by configuring a revocation endpoint pointing to the loopback HTTP
 * server and verifying the POST body that lands on the server.
 */

START_TEST(test_handle_logout_revoke_tokens) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = "{}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_revocation_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	/* session must have a remote_user (so the revoke branch runs) and an issuer
	 * matching the static provider so oidc_get_provider_from_session resolves it */
	session->remote_user = apr_pstrdup(r->pool, "alice");
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(provider));
	oidc_session_set_refresh_token(r, session, "RT-revoke");

	int rc = oidc_logout_request(r, c, session, NULL, TRUE);
	ck_assert_int_eq(rc, OK);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_ptr_nonnull(cap);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_msg(_oidc_strstr(cap->body, "token=RT-revoke") != NULL,
		      "revocation POST must include the refresh token: got %s", cap->body);
	ck_assert_msg(_oidc_strstr(cap->body, "token_type_hint=refresh_token") != NULL,
		      "revocation POST must hint refresh_token as the token type");

	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_logout_revoke_tokens_no_endpoint) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	/* no revocation_endpoint URL => oidc_logout_revoke_tokens early-returns silently */
	session->remote_user = apr_pstrdup(r->pool, "alice");
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(provider));
	oidc_session_set_refresh_token(r, session, "RT-x");

	int rc = oidc_logout_request(r, c, session, NULL, TRUE);
	ck_assert_int_eq(rc, OK);

	oidc_session_free(r, session);
}
END_TEST

/*
 * Additional tests for handle/refresh.c — the cache-hit fast path and the
 * id_token-in-response path that oidc_refresh_token_grant_apply_id_token
 * handles.
 */

START_TEST(test_handle_refresh_grant_cache_hit) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	oidc_session_set_refresh_token(r, session, "RT-CACHED");

	/* first call hits the token endpoint and populates the refresh-token cache */
	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"access_token\":\"AT-FRESH\",\"token_type\":\"Bearer\","
						  "\"expires_in\":3600,\"refresh_token\":\"RT-CACHED\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_cfg_provider_scope_set(r->pool, provider, "openid");

	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, NULL), TRUE);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);

	/* second call must come from the cache; point the token endpoint at a port
	 * with nothing listening so any actual HTTP request would fail */
	int free_port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(free_port, 0);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider,
						 apr_psprintf(r->pool, "http://127.0.0.1:%d/token", free_port));

	char *new_at = NULL, *new_att = NULL;
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, &new_at, &new_att, NULL), TRUE);
	ck_assert_str_eq(new_at, "AT-FRESH");
	ck_assert_str_eq(new_att, "Bearer");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_handle_refresh_grant_with_id_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);
	oidc_session_set_refresh_token(r, session, "RT-IDTOKEN");

	/* the refresh-token grant consults a shared cache first; with a persistent
	 * cache backend a prior test's entry under the same key could short-circuit
	 * the token-endpoint call and skip applying the id_token. Use a dedicated key
	 * and evict any stale grant result so this test always refreshes against the
	 * OP, independent of the configured cache backend. */
	oidc_cache_set_refresh_token(r, "RT-IDTOKEN", NULL, 0);

	/* the token endpoint also returns an id_token => triggers
	 * oidc_refresh_token_grant_apply_id_token (parse, claims store, expiry update) */
	const char *secret = "refresh-flow-shared-secret-long-enough";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);
	char *id_token =
	    e2e_sign_idtoken_hs256(r, "https://idp.example.com", "client_id", "alice", "n-refresh", secret);

	oidc_test_http_response_t resp = {0};
	resp.status_code = 200;
	resp.content_type = "application/json";
	resp.body = apr_psprintf(r->pool,
				 "{\"access_token\":\"AT-NEW\",\"token_type\":\"Bearer\","
				 "\"expires_in\":3600,\"refresh_token\":\"NEW-RT\",\"id_token\":\"%s\"}",
				 id_token);
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_cfg_provider_scope_set(r->pool, provider, "openid");

	char *new_id = NULL;
	ck_assert_int_eq(oidc_refresh_token_grant(r, c, session, provider, NULL, NULL, &new_id), TRUE);
	ck_assert_ptr_nonnull(new_id);
	ck_assert_str_eq(new_id, id_token);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_session_free(r, session);
}
END_TEST

/*
 * Additional test for handle/discovery.c — the metadata-dir + test-config
 * branch of oidc_discovery_response_authenticate which is otherwise
 * unreached.
 */

START_TEST(test_handle_discovery_response_test_config_short_circuit) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	char *tmpl = apr_pstrdup(r->pool, "/tmp/oidc-test-disco.XXXXXX");
	ck_assert_msg(mkdtemp(tmpl) != NULL, "could not create temp metadata dir at %s", tmpl);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCMetadataDir);
	ck_assert_ptr_null(oidc_cmd_metadata_dir_set(cmd, NULL, tmpl));

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

	/* iss + target_link_uri on our host + test-config => the authenticate branch
	 * resolves the issuer from the metadata dir and short-circuits to OK */
	r->args = "iss=https%3A%2F%2Fidp.example.com"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F"
		  "&test-config=1";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, OK);
}
END_TEST

/*
 * OIDCDiscoverIssuersAllowed bounds which issuers a Discovery response may
 * resolve to; verify it rejects a non-matching issuer and still allows a
 * matching one, using the same metadata-dir/test-config setup as above.
 */
static void oidc_test_discovery_write_metadata_dir(request_rec *r, const char *tmpl) {
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
}

START_TEST(test_handle_discovery_response_issuer_not_allowed) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	char *tmpl = apr_pstrdup(r->pool, "/tmp/oidc-test-disco.XXXXXX");
	ck_assert_msg(mkdtemp(tmpl) != NULL, "could not create temp metadata dir at %s", tmpl);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCMetadataDir);
	ck_assert_ptr_null(oidc_cmd_metadata_dir_set(cmd, NULL, tmpl));
	oidc_test_discovery_write_metadata_dir(r, tmpl);

	cmd = oidc_test_cmd_get(OIDCDiscoverIssuersAllowed);
	ck_assert_ptr_null(oidc_cmd_discover_issuers_allowed_set(cmd, NULL, "^https://other\\.example\\.com$"));

	r->args = "iss=https%3A%2F%2Fidp.example.com"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F"
		  "&test-config=1";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

START_TEST(test_handle_discovery_response_issuer_allowed) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	char *tmpl = apr_pstrdup(r->pool, "/tmp/oidc-test-disco.XXXXXX");
	ck_assert_msg(mkdtemp(tmpl) != NULL, "could not create temp metadata dir at %s", tmpl);
	cmd_parms *cmd = oidc_test_cmd_get(OIDCMetadataDir);
	ck_assert_ptr_null(oidc_cmd_metadata_dir_set(cmd, NULL, tmpl));
	oidc_test_discovery_write_metadata_dir(r, tmpl);

	cmd = oidc_test_cmd_get(OIDCDiscoverIssuersAllowed);
	ck_assert_ptr_null(oidc_cmd_discover_issuers_allowed_set(cmd, NULL, "^https://idp\\.example\\.com$"));

	r->args = "iss=https%3A%2F%2Fidp.example.com"
		  "&target_link_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F"
		  "&test-config=1";
	int rc = oidc_discovery_response(r, c);
	ck_assert_int_eq(rc, OK);
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
	tcase_add_test(userinfo, test_handle_userinfo_retrieve_non_401_no_refresh);
	tcase_add_test(userinfo, test_handle_userinfo_store_and_clear_claims);
	tcase_add_test(userinfo, test_handle_userinfo_refresh_no_interval);
	tcase_add_test(userinfo, test_handle_userinfo_refresh_with_interval);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_no_claims);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_jwt);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_signed_jwt_without_private_keys);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_signed_jwt_with_private_keys);
	tcase_add_test(userinfo, test_handle_userinfo_pass_as_signed_jwt_cached);
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
	tcase_add_test(refresh, test_handle_refresh_grant_cache_hit);
	tcase_add_test(refresh, test_handle_refresh_grant_with_id_token);
	tcase_add_test(refresh, test_handle_refresh_grant_cached_results_clamps_and_id_token);
	tcase_add_test(refresh, test_handle_refresh_grant_cache_locks);
	tcase_add_test(refresh, test_handle_refresh_before_expiry_due_paths);
	tcase_add_test(refresh, test_handle_refresh_request_error_arms);

	TCase *response = tcase_create("response");
	tcase_add_checked_fixture(response, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(response, test_handle_response_make_sid_iss_unique);
	tcase_add_test(response, test_handle_response_post_preserve_disabled_by_default);
	tcase_add_test(response, test_handle_response_save_in_session_minimal);
	tcase_add_test(response, test_handle_response_save_in_session_with_userinfo);
	tcase_add_test(response, test_handle_response_save_in_session_sub_index);
	tcase_add_test(response, test_handle_response_authorization_redirect_state_mismatch);
	tcase_add_test(response, test_handle_response_authorization_redirect_state_mismatch_with_sso_url);
	tcase_add_test(response, test_handle_response_authorization_post_non_post_method);
	tcase_add_test(response, test_handle_response_authorization_post_only_response_mode_fragment);
	tcase_add_test(response, test_handle_response_authorization_redirect_error_param);
	tcase_add_test(response, test_handle_response_authorization_redirect_unknown_response_type);
	tcase_add_test(response, test_handle_response_authorization_redirect_idtoken_happy_path);
	tcase_add_test(response, test_handle_response_authorization_redirect_code_flow_happy_path);
	tcase_add_test(response, test_handle_response_authorization_error_prompt_none);
	tcase_add_test(response, test_handle_response_browser_back);
	tcase_add_test(response, test_handle_response_post_preserve_javascript);
	tcase_add_test(response, test_handle_response_save_in_session_session_mgmt);
	tcase_add_test(response, test_handle_response_save_in_session_no_session_state);
	tcase_add_test(response, test_handle_response_state_restore_no_cookie);
	tcase_add_test(response, test_handle_response_finish_form_post_restore);
	tcase_add_test(response, test_handle_response_authorization_post_state_mismatch);

	TCase *discovery = tcase_create("discovery");
	tcase_add_checked_fixture(discovery, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(discovery, test_handle_is_discovery_response);
	tcase_add_test(discovery, test_handle_discovery_request_external_url);
	tcase_add_test(discovery, test_handle_discovery_response_no_target_link_uri_no_sso_url);
	tcase_add_test(discovery, test_handle_discovery_response_static_provider_redirects);
	tcase_add_test(discovery, test_handle_discovery_response_issuer_input_trimmed);
	tcase_add_test(discovery, test_handle_discovery_response_static_provider_iss_mismatch);
	tcase_add_test(discovery, test_handle_discovery_response_target_link_uri_open_redirect);
	tcase_add_test(discovery, test_handle_discovery_response_user_discovery_fails);
	tcase_add_test(discovery, test_handle_discovery_response_account_discovery_fails);
	tcase_add_test(discovery, test_handle_discovery_response_url_based_issuer_not_allowed);
	tcase_add_test(discovery, test_handle_discovery_response_account_based_issuer_not_allowed);
	tcase_add_test(discovery, test_handle_discovery_request_with_metadata_dir);
	tcase_add_test(discovery, test_handle_discovery_response_test_config_short_circuit);
	tcase_add_test(discovery, test_handle_discovery_response_issuer_not_allowed);
	tcase_add_test(discovery, test_handle_discovery_response_issuer_allowed);

	TCase *info = tcase_create("info");
	tcase_add_checked_fixture(info, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(info, test_handle_info_unknown_format);
	tcase_add_test(info, test_handle_info_no_remote_user);
	tcase_add_test(info, test_handle_info_no_hook_data_configured);
	tcase_add_test(info, test_handle_info_json_happy_path);
	tcase_add_test(info, test_handle_info_json_full_hook_data);
	tcase_add_test(info, test_handle_info_refresh_access_token_and_full_output);
	tcase_add_test(info, test_handle_info_refresh_failures_without_issuer);

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

	TCase *mod_main = tcase_create("mod_main");
	tcase_add_checked_fixture(mod_main, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(mod_main, test_handle_mod_scrub_headers_default_prefix);
	tcase_add_test(mod_main, test_handle_mod_scrub_headers_empty_prefix_with_whitelist);
	tcase_add_test(mod_main, test_handle_mod_scrub_headers_custom_prefix);
	tcase_add_test(mod_main, test_handle_mod_strip_cookies_configured);
	tcase_add_test(mod_main, test_handle_mod_provider_static_config_no_metadata_url);
	tcase_add_test(mod_main, test_handle_mod_provider_static_config_metadata_url_cached);
	tcase_add_test(mod_main, test_handle_mod_provider_static_config_metadata_url_fetch);
	tcase_add_test(mod_main, test_handle_mod_provider_static_config_metadata_url_fetch_fails);
	tcase_add_test(mod_main, test_handle_mod_set_app_claims_pass_none);
	tcase_add_test(mod_main, test_handle_mod_set_app_claims_pass_both);
	tcase_add_test(mod_main, test_handle_mod_log_session_expires);
	tcase_add_test(mod_main, test_handle_mod_check_cookie_domain_mismatch);
	tcase_add_test(mod_main, test_handle_mod_get_provider_from_session_no_issuer);
	tcase_add_test(mod_main, test_handle_mod_get_provider_from_session_with_issuer);
	tcase_add_test(mod_main, test_handle_mod_get_remote_user_missing_claim);
	tcase_add_test(mod_main, test_handle_mod_validate_redirect_url_backslash_relative);
	tcase_add_test(mod_main, test_handle_mod_validate_redirect_url_allowed);
	tcase_add_test(mod_main, test_handle_mod_get_remote_user_regexp);
	tcase_add_test(mod_main, test_handle_mod_validate_redirect_url_edge_cases);
	tcase_add_test(mod_main, test_handle_mod_check_cookie_domain_configured);
	tcase_add_test(mod_main, test_handle_mod_session_pass_tokens_full);
	tcase_add_test(mod_main, test_handle_mod_original_request_method_post_form);
	tcase_add_test(mod_main, test_handle_mod_check_user_id_unauth_action_407);

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
	tcase_add_test(logout, test_handle_logout_backchannel_encrypted);
	tcase_add_test(logout, test_handle_logout_backchannel_by_sub);
	tcase_add_test(logout, test_handle_logout_backchannel_missing_events_claim);
	tcase_add_test(logout, test_handle_logout_backchannel_nonce_claim_rejected);
	tcase_add_test(logout, test_handle_logout_op_request_with_id_token_hint);
	tcase_add_test(logout, test_handle_logout_op_request_no_session_no_extra_params);
	tcase_add_test(logout, test_handle_logout_revoke_tokens);
	tcase_add_test(logout, test_handle_logout_revoke_tokens_no_endpoint);

	TCase *content = tcase_create("content");
	tcase_add_checked_fixture(content, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(content, test_handle_jwks_request_empty_keys);
	tcase_add_test(content, test_handle_jwks_request_with_public_key);
	tcase_add_test(content, test_handle_content_handler_jwks);
	tcase_add_test(content, test_handle_content_handler_unknown_redirect_uri_request);
	tcase_add_test(content, test_handle_content_handler_non_redirect_no_state);
	tcase_add_test(content, test_handle_content_handler_redirect_uri_http_state);
	tcase_add_test(content, test_handle_content_handler_redirect_uri_html_state);
	tcase_add_test(content, test_handle_content_handler_redirect_uri_info_no_session);
	tcase_add_test(content, test_handle_content_handler_redirect_uri_dpop_disabled);
	tcase_add_test(content, test_handle_content_handler_discovery_state);
	tcase_add_test(content, test_handle_content_handler_authn_post_state);
	tcase_add_test(content, test_handle_content_handler_authn_preserve_state);
	tcase_add_test(content, test_handle_content_handler_http_state_non_redirect);
	tcase_add_test(content, test_handle_content_handler_html_state_non_redirect);

	TCase *authz_24 = tcase_create("authz_24");
	tcase_add_checked_fixture(authz_24, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(authz_24, test_handle_authz_24_claim_granted_from_idtoken);
#ifdef USE_LIBJQ
	tcase_add_test(authz_24, test_handle_authz_24_claims_expr_granted);
	tcase_add_test(authz_24, test_handle_authz_24_claims_expr_denied);
#endif
	tcase_add_test(authz_24, test_handle_authz_24_anonymous_unauth_pass);
	tcase_add_test(authz_24, test_handle_authz_24_anonymous_skip_via_discovery_state);
	tcase_add_test(authz_24, test_handle_authz_24_anonymous_options_method);
	tcase_add_test(authz_24, test_handle_authz_24_oauth20_denied);
	tcase_add_test(authz_24, test_handle_authz_24_oauth20_sets_bearer_scope_error);
	tcase_add_test(authz_24, test_handle_authz_24_oidc_unautz_return_401);
	tcase_add_test(authz_24, test_handle_authz_24_oidc_unautz_return_302);
	tcase_add_test(authz_24, test_handle_authz_24_unautz_authenticate_redirects);
	tcase_add_test(authz_24, test_handle_authz_24_unautz_authenticate_xhr_denied_401);
	tcase_add_test(authz_24, test_handle_authz_24_unautz_authenticate_expr_bypasses_xhr_check);

	TCase *checkuid = tcase_create("check_user_id");
	tcase_add_checked_fixture(checkuid, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(checkuid, test_handle_check_user_id_subrequest_recycles_user);
	tcase_add_test(checkuid, test_handle_check_user_id_unauthenticated_redirects_to_op);
	tcase_add_test(checkuid, test_handle_check_user_id_unauthenticated_not_auth_capable);
	tcase_add_test(checkuid, test_handle_check_user_id_existing_session);
	tcase_add_test(checkuid, test_handle_check_user_id_existing_session_expired);
	tcase_add_test(checkuid, test_handle_check_user_id_unauth_action_pass);
	tcase_add_test(checkuid, test_handle_check_user_id_unauth_action_return_401);
	tcase_add_test(checkuid, test_handle_check_user_id_unauth_action_return_410);
	tcase_add_test(checkuid, test_handle_check_user_id_oauth_mixed_options);
	tcase_add_test(checkuid, test_handle_check_user_id_oauth_mixed_browser_fallback);
	tcase_add_test(checkuid, test_handle_check_user_id_oauth_mixed_bearer);
	tcase_add_test(checkuid, test_handle_fixups_enabled);

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
	tcase_add_test(session_mgmt, test_handle_session_management_check_uses_session_path_params);

	TCase *request_uri = tcase_create("request_uri");
	tcase_add_checked_fixture(request_uri, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(request_uri, test_handle_request_uri_missing_param);
	tcase_add_test(request_uri, test_handle_request_uri_not_cached);
	tcase_add_test(request_uri, test_handle_request_uri_happy_path);

	TCase *dispatch = tcase_create("dispatch");
	tcase_add_checked_fixture(dispatch, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(dispatch, test_handle_dispatch_jwks);
	tcase_add_test(dispatch, test_handle_dispatch_dpop);
	tcase_add_test(dispatch, test_handle_dispatch_info_no_session_returns_unauthorized);
	tcase_add_test(dispatch, test_handle_dispatch_unknown_args_returns_500);
	tcase_add_test(dispatch, test_handle_dispatch_empty_args_routes_to_implicit_flow);
	tcase_add_test(dispatch, test_handle_dispatch_logout_takes_precedence_over_post_authn);
	tcase_add_test(dispatch, test_handle_dispatch_info_happy_sets_authn_header);
	tcase_add_test(dispatch, test_handle_existing_session_cookie_domain_mismatch);
	tcase_add_test(dispatch, test_handle_existing_session_refresh_error_actions);
	tcase_add_test(dispatch, test_handle_existing_session_userinfo_error_actions);

	Suite *s = suite_create("handle");
	suite_add_tcase(s, userinfo);
	suite_add_tcase(s, refresh);
	suite_add_tcase(s, response);
	suite_add_tcase(s, discovery);
	suite_add_tcase(s, info);
	suite_add_tcase(s, dpop);
	suite_add_tcase(s, legacy);
	suite_add_tcase(s, mod_main);
	suite_add_tcase(s, logout);
	suite_add_tcase(s, content);
	suite_add_tcase(s, authz_24);

	TCase *auth_request = tcase_create("auth_request");
	tcase_add_checked_fixture(auth_request, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(auth_request, test_handle_request_check_cookie_domain);
	tcase_add_test(auth_request, test_handle_request_authenticate_user_branches);
	tcase_add_test(auth_request, test_handle_request_authenticate_user_too_many_state_cookies);
	tcase_add_test(auth_request, test_handle_request_authenticate_user_discovery_and_static_metadata);
	tcase_add_test(auth_request, test_handle_request_authenticate_user_static_config_fails);
	suite_add_tcase(s, auth_request);

	suite_add_tcase(s, checkuid);
	suite_add_tcase(s, revoke);
	suite_add_tcase(s, session_mgmt);
	suite_add_tcase(s, request_uri);
	suite_add_tcase(s, dispatch);

	return oidc_test_suite_run(s);
}
