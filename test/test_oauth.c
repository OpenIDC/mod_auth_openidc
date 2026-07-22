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

#include "cache/cache.h"
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

/* prepare a POST body the way oidc_util_read_post_params expects it */
static void e2e_post_body(request_rec *r, const char *body) {
	r->method_number = M_POST;
	apr_table_set(r->headers_in, "Content-Type", "application/x-www-form-urlencoded");
	r->args = apr_pstrdup(r->pool, body);
	r->remaining = (apr_size_t)_oidc_strlen(body);
}

START_TEST(test_oauth_bearer_from_post) {
	request_rec *r = oidc_test_request_get();
	oidc_dir_cfg_t *dir_cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);

	cmd_parms *cmd = oidc_test_cmd_get("OIDCOAuthAcceptTokenAs");
	ck_assert_ptr_null(oidc_cmd_dir_accept_oauth_token_in_set(cmd, dir_cfg, "post"));
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);
	e2e_post_body(r, "access_token=AT-FROM-POST&other=val");

	const char *token = NULL;
	ck_assert_int_eq(oidc_oauth_get_bearer_token(r, &token), TRUE);
	ck_assert_ptr_nonnull(token);
	ck_assert_str_eq(token, "AT-FROM-POST");
}
END_TEST

/* build an HS256-signed JWT access token with the raw shared secret as key */
static char *e2e_sign_jwt_access_token_hs256(request_rec *r, const char *secret, int exp_offset_secs) {
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, FALSE, &jwk), TRUE);
	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	apr_time_t now = apr_time_sec(apr_time_now());
	oidc_json_object_set_new(jwt->payload.value.json, "sub", oidc_json_string("alice"));
	oidc_json_object_set_new(jwt->payload.value.json, "iat", oidc_json_integer(now));
	oidc_json_object_set_new(jwt->payload.value.json, "exp", oidc_json_integer(now + exp_offset_secs));
	jwt->payload.sub = apr_pstrdup(r->pool, "alice");
	jwt->payload.iat = now;
	jwt->payload.exp = now + exp_offset_secs;
	ck_assert_int_eq(oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err), TRUE);
	char *cser = oidc_jose_jwt_serialize(r->pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
	return cser;
}

/* configure the shared verification secret and the client_secret the JWT
 * validation path derives its decryption key candidate from */
static const char *e2e_setup_jwt_validation(request_rec *r, oidc_cfg_t *c) {
	const char *secret = "0123456789abcdef0123456789abcdef";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthVerifySharedKeys);
	ck_assert_ptr_null(oidc_cmd_oauth_verify_shared_keys_set(cmd, NULL, secret));
	oidc_cfg_provider_client_secret_set(r->pool, oidc_cfg_provider_get(c), secret);
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);
	return secret;
}

/* local JWT access-token validation succeeds against OIDCOAuthVerifySharedKeys
 * and sets REMOTE_USER from the default "sub" claim */
START_TEST(test_oauth_check_userid_jwt_valid_hs256) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *secret = e2e_setup_jwt_validation(r, c);
	char *access_token = e2e_sign_jwt_access_token_hs256(r, secret, 300);

	int rc = oidc_oauth_check_userid(r, c, access_token);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "alice");
}
END_TEST

/* a locally validated JWT access token is cached keyed by the token: the first request
 * populates the cache and subsequent requests are served from it, skipping re-verification */
START_TEST(test_oauth_check_userid_jwt_validation_cached) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	char *s_cache_entry = NULL;

	const char *secret = e2e_setup_jwt_validation(r, c);
	char *access_token = e2e_sign_jwt_access_token_hs256(r, secret, 300);

	ck_assert_int_eq(oidc_oauth_check_userid(r, c, access_token), OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "alice");

	/* the first validation must have populated the access-token cache */
	oidc_cache_get_access_token(r, access_token, &s_cache_entry);
	ck_assert_ptr_nonnull(s_cache_entry);

	/* plant a synthetic cache entry for the same token; the next request must then be
	 * served from the cache (sub=bob) instead of re-verifying the JWT (sub=alice) */
	apr_time_t now = apr_time_sec(apr_time_now());
	const char *planted = apr_psprintf(
	    r->pool, "{\"r\":{\"sub\":\"bob\",\"exp\":%" APR_TIME_T_FMT "},\"t\":%" APR_TIME_T_FMT "}", now + 300, now);
	oidc_cache_set_access_token(r, access_token, planted, apr_time_now() + apr_time_from_sec(300));
	r->user = NULL;
	ck_assert_int_eq(oidc_oauth_check_userid(r, c, access_token), OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "bob");
}
END_TEST

/* an expired JWT access token must be rejected by the local validation path */
START_TEST(test_oauth_check_userid_jwt_expired) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *secret = e2e_setup_jwt_validation(r, c);
	char *access_token = e2e_sign_jwt_access_token_hs256(r, secret, -3600);

	int rc = oidc_oauth_check_userid(r, c, access_token);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

/* a JWT access token signed with a different key must fail signature validation */
START_TEST(test_oauth_check_userid_jwt_bad_signature) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	(void)e2e_setup_jwt_validation(r, c);
	char *access_token = e2e_sign_jwt_access_token_hs256(r, "fedcba9876543210fedcba9876543210", 300);

	int rc = oidc_oauth_check_userid(r, c, access_token);
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
}
END_TEST

/* an encrypted (JWE) JWT access token is decrypted with the dedicated
 * OIDCOAuthDecryptSharedKeys key - not the client_secret fallback: the JWE key
 * deliberately differs from the client_secret set by e2e_setup_jwt_validation,
 * so decryption can only succeed through the configured shared decryption key -
 * and the inner HS256 signature is verified against OIDCOAuthVerifySharedKeys */
START_TEST(test_oauth_check_userid_jwt_encrypted_decrypt_shared_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	char *access_token = NULL;

	const char *secret = e2e_setup_jwt_validation(r, c);
	const char *enc_secret = "fedcba9876543210fedcba9876543210";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthDecryptSharedKeys);
	ck_assert_ptr_null(oidc_cmd_oauth_decrypt_shared_keys_set(cmd, NULL, enc_secret));

	/* wrap the signed JWT in a dir/A256GCM JWE encrypted with the dedicated decryption key */
	char *signed_jwt = e2e_sign_jwt_access_token_hs256(r, secret, 300);
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, enc_secret, 0, NULL, FALSE, &jwk), TRUE);
	oidc_jwt_t *jwe = oidc_jwt_new(r->pool, TRUE, FALSE);
	jwe->header.alg = apr_pstrdup(r->pool, OIDC_JOSE_HDR_ALG_DIR);
	jwe->header.enc = apr_pstrdup(r->pool, OIDC_JOSE_HDR_ENC_A256GCM);
	ck_assert_int_eq(
	    oidc_jwt_encrypt(r->pool, jwe, jwk, signed_jwt, (int)_oidc_strlen(signed_jwt), &access_token, &err), TRUE);
	ck_assert_ptr_nonnull(access_token);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwe);

	int rc = oidc_oauth_check_userid(r, c, access_token);
	ck_assert_int_eq(rc, OK);
	ck_assert_ptr_nonnull(r->user);
	ck_assert_str_eq(r->user, "alice");

	oidc_jwk_list_destroy_hash(oidc_cfg_oauth_decrypt_shared_keys_get(c));
}
END_TEST

/* OIDCOAuthServerMetadataURL: the AS configuration is retrieved from the
 * metadata document (first call, populating the cache) and re-read from the
 * cache on the next request */
START_TEST(test_oauth_check_userid_metadata_url) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	/* introspection endpoint server: serve two identical "active" responses */
	oidc_test_http_response_t intro_resp[2] = {
	    {.status_code = 200,
	     .content_type = "application/json",
	     .body = "{\"active\":true,\"sub\":\"alice\",\"scope\":\"openid\",\"client_id\":\"rp-1\"}"},
	    {.status_code = 200,
	     .content_type = "application/json",
	     .body = "{\"active\":true,\"sub\":\"alice\",\"scope\":\"openid\",\"client_id\":\"rp-1\"}"}};
	oidc_test_http_server_t *intro_srv = oidc_test_http_server_start_seq(r->pool, intro_resp, 2);
	ck_assert_ptr_nonnull(intro_srv);

	/* metadata server: points the introspection_endpoint at the server above */
	const char *metadata_body =
	    apr_psprintf(r->pool, "{\"issuer\":\"https://idp.example.com\",\"introspection_endpoint\":\"%s\"}",
			 oidc_test_http_server_url(intro_srv, r->pool));
	oidc_test_http_response_t md_resp = {
	    .status_code = 200, .content_type = "application/json", .body = metadata_body};
	oidc_test_http_server_t *md_srv = oidc_test_http_server_start(r->pool, &md_resp);
	ck_assert_ptr_nonnull(md_srv);

	cmd_parms *cmd_md = oidc_test_cmd_get(OIDCOAuthServerMetadataURL);
	ck_assert_ptr_null(oidc_cmd_oauth_metadata_url_set(cmd_md, NULL, oidc_test_http_server_url(md_srv, r->pool)));
	cmd_parms *cmd_ssl = oidc_test_cmd_get(OIDCOAuthSSLValidateServer);
	ck_assert_ptr_null(oidc_cmd_oauth_ssl_validate_server_set(cmd_ssl, NULL, "Off"));

	/* first call: retrieves the metadata over HTTP, caches it and introspects */
	int rc = oidc_oauth_check_userid(r, c, "AT-MD-1");
	ck_assert_int_eq(rc, OK);
	ck_assert_str_eq(r->user, "alice");

	/* the metadata document must have been fetched exactly once */
	(void)oidc_test_http_server_wait(md_srv);
	oidc_test_http_server_stop(md_srv);

	/* second call: the metadata comes from the cache (the metadata server is
	 * down now), a fresh token forces a second introspection round-trip */
	r->user = NULL;
	rc = oidc_oauth_check_userid(r, c, "AT-MD-2");
	ck_assert_int_eq(rc, OK);
	ck_assert_str_eq(r->user, "alice");

	oidc_test_http_server_stop(intro_srv);
}
END_TEST

/* a positive OIDCProviderMetadataRefreshInterval must be treated as seconds when computing the
 * AS-metadata cache expiry; without apr_time_from_sec() on that branch the entry would expire in
 * microseconds and be re-fetched on almost every request */
START_TEST(test_oauth_metadata_cache_expiry_seconds) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	/* introspection endpoint: one "active" response so the initial call succeeds */
	oidc_test_http_response_t intro_resp = {
	    .status_code = 200,
	    .content_type = "application/json",
	    .body = "{\"active\":true,\"sub\":\"alice\",\"scope\":\"openid\",\"client_id\":\"rp-1\"}"};
	oidc_test_http_server_t *intro_srv = oidc_test_http_server_start(r->pool, &intro_resp);
	ck_assert_ptr_nonnull(intro_srv);

	const char *metadata_body =
	    apr_psprintf(r->pool, "{\"issuer\":\"https://idp.example.com\",\"introspection_endpoint\":\"%s\"}",
			 oidc_test_http_server_url(intro_srv, r->pool));
	oidc_test_http_response_t md_resp = {
	    .status_code = 200, .content_type = "application/json", .body = metadata_body};
	oidc_test_http_server_t *md_srv = oidc_test_http_server_start(r->pool, &md_resp);
	ck_assert_ptr_nonnull(md_srv);

	const char *md_url = oidc_test_http_server_url(md_srv, r->pool);
	cmd_parms *cmd_md = oidc_test_cmd_get(OIDCOAuthServerMetadataURL);
	ck_assert_ptr_null(oidc_cmd_oauth_metadata_url_set(cmd_md, NULL, md_url));
	cmd_parms *cmd_ssl = oidc_test_cmd_get(OIDCOAuthSSLValidateServer);
	ck_assert_ptr_null(oidc_cmd_oauth_ssl_validate_server_set(cmd_ssl, NULL, "Off"));
	/* the minimum accepted interval (30s) selects the configured-interval expiry branch and far
	 * outlives this test, so with a correct seconds->microseconds conversion the entry stays cached */
	cmd_parms *cmd_ri = oidc_test_cmd_get(OIDCProviderMetadataRefreshInterval);
	ck_assert_ptr_null(oidc_cmd_provider_metadata_refresh_interval_set(cmd_ri, NULL, "30"));

	/* retrieves the metadata over HTTP and caches it with the interval-based expiry */
	int rc = oidc_oauth_check_userid(r, c, "AT-CACHE-1");
	ck_assert_int_eq(rc, OK);

	(void)oidc_test_http_server_wait(md_srv);
	oidc_test_http_server_stop(md_srv);
	oidc_test_http_server_stop(intro_srv);

	/* a 30s TTL cannot have elapsed; a 30us one (seconds mistaken for microseconds) already has */
	char *s_json = NULL;
	oidc_cache_get_oauth_provider(r, md_url, &s_json);
	ck_assert_ptr_nonnull(s_json);
}
END_TEST

/* metadata-derived introspection endpoints must land in a per-request config view and never mutate
 * the shared, process-lifetime server config (which would be a cross-request use-after-free under
 * threaded MPMs, since the strings are request-pool-scoped) */
START_TEST(test_oauth_metadata_does_not_mutate_shared_config) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_unset(r->headers_in, OIDC_HTTP_HDR_AUTHORIZATION);

	oidc_test_http_response_t intro_resp = {
	    .status_code = 200,
	    .content_type = "application/json",
	    .body = "{\"active\":true,\"sub\":\"alice\",\"scope\":\"openid\",\"client_id\":\"rp-1\"}"};
	oidc_test_http_server_t *intro_srv = oidc_test_http_server_start(r->pool, &intro_resp);
	ck_assert_ptr_nonnull(intro_srv);

	const char *metadata_body =
	    apr_psprintf(r->pool, "{\"issuer\":\"https://idp.example.com\",\"introspection_endpoint\":\"%s\"}",
			 oidc_test_http_server_url(intro_srv, r->pool));
	oidc_test_http_response_t md_resp = {
	    .status_code = 200, .content_type = "application/json", .body = metadata_body};
	oidc_test_http_server_t *md_srv = oidc_test_http_server_start(r->pool, &md_resp);
	ck_assert_ptr_nonnull(md_srv);

	cmd_parms *cmd_md = oidc_test_cmd_get(OIDCOAuthServerMetadataURL);
	ck_assert_ptr_null(oidc_cmd_oauth_metadata_url_set(cmd_md, NULL, oidc_test_http_server_url(md_srv, r->pool)));
	cmd_parms *cmd_ssl = oidc_test_cmd_get(OIDCOAuthSSLValidateServer);
	ck_assert_ptr_null(oidc_cmd_oauth_ssl_validate_server_set(cmd_ssl, NULL, "Off"));

	/* no statically-configured introspection endpoint on the shared config to start with */
	ck_assert_ptr_null((void *)oidc_cfg_oauth_introspection_endpoint_url_get(c));

	int rc = oidc_oauth_check_userid(r, c, "AT-SHARED-1");
	ck_assert_int_eq(rc, OK);
	ck_assert_str_eq(r->user, "alice");

	/* the metadata-derived endpoint drove introspection above but must NOT have leaked into the
	 * shared server config; with the per-request view it stays unset */
	ck_assert_ptr_null((void *)oidc_cfg_oauth_introspection_endpoint_url_get(c));

	oidc_test_http_server_stop(md_srv);
	oidc_test_http_server_stop(intro_srv);
}
END_TEST

/* sub-requests and internal redirects recycle the user from the initial request */
START_TEST(test_oauth_check_userid_subrequest) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	r->user = apr_pstrdup(r->pool, "alice");

	request_rec *sub = apr_pmemdup(r->pool, r, sizeof(request_rec));
	sub->main = r;
	sub->user = NULL;
	ck_assert_int_eq(oidc_oauth_check_userid(sub, c, NULL), OK);
	ck_assert_ptr_nonnull(sub->user);
	ck_assert_str_eq(sub->user, "alice");

	request_rec *redir = apr_pmemdup(r->pool, r, sizeof(request_rec));
	redir->prev = r;
	redir->main = NULL;
	redir->user = NULL;
	ck_assert_int_eq(oidc_oauth_check_userid(redir, c, NULL), OK);
	ck_assert_ptr_nonnull(redir->user);
	ck_assert_str_eq(redir->user, "alice");
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
	tcase_add_test(bearer, test_oauth_bearer_from_post);

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
	tcase_add_test(introspect, test_oauth_check_userid_subrequest);

	TCase *jwt = tcase_create("jwt");
	tcase_add_checked_fixture(jwt, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(jwt, test_oauth_check_userid_jwt_no_keys_configured);
	tcase_add_test(jwt, test_oauth_check_userid_jwt_valid_hs256);
	tcase_add_test(jwt, test_oauth_check_userid_jwt_validation_cached);
	tcase_add_test(jwt, test_oauth_check_userid_jwt_expired);
	tcase_add_test(jwt, test_oauth_check_userid_jwt_bad_signature);
	tcase_add_test(jwt, test_oauth_check_userid_jwt_encrypted_decrypt_shared_keys);

	TCase *metadata = tcase_create("metadata");
	tcase_add_checked_fixture(metadata, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(metadata, 30);
	tcase_add_test(metadata, test_oauth_metadata_provider_retrieve_success);
	tcase_add_test(metadata, test_oauth_metadata_provider_retrieve_invalid_json);
	tcase_add_test(metadata, test_oauth_check_userid_metadata_url);
	tcase_add_test(metadata, test_oauth_metadata_cache_expiry_seconds);
	tcase_add_test(metadata, test_oauth_metadata_does_not_mutate_shared_config);

	Suite *s = suite_create("oauth");
	suite_add_tcase(s, bearer);
	suite_add_tcase(s, introspect);
	suite_add_tcase(s, jwt);
	suite_add_tcase(s, metadata);

	return oidc_test_suite_run(s);
}
