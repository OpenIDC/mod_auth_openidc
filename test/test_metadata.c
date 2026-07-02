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
#include "cfg/provider.h"
#include "check_util.h"
#include "http_server.h"
#include "metadata.h"
#include "mod_auth_openidc.h"
#include "util.h"
#include "util/util.h"

#include <apr_file_io.h>
#include <apr_strings.h>
#include <jansson.h> /* this test builds JSON fixtures with the backend API directly (no longer pulled in via jose.h) */

/*
 * Minimum-viable OpenID Connect provider metadata JSON, used by the
 * is_valid / parse / retrieve tests below.
 */
#define VALID_METADATA_JSON                                                                                            \
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
 * Tests for oidc_metadata_provider_is_valid — pure JSON validation, no HTTP.
 */

START_TEST(test_metadata_is_valid_happy) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_is_valid(r, c, j, "https://idp.example.com"), TRUE);
	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_is_valid_missing_issuer) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* the "issuer" claim is required */
	oidc_json_t *j = json_pack("{s:s}", "authorization_endpoint", "https://idp.example.com/authorize");
	ck_assert_int_eq(oidc_metadata_provider_is_valid(r, c, j, "https://idp.example.com"), FALSE);
	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_is_valid_issuer_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
	/* asking for a different issuer than the one in the document => FALSE */
	ck_assert_int_eq(oidc_metadata_provider_is_valid(r, c, j, "https://other.example.com"), FALSE);
	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_is_valid_missing_authz_endpoint) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* authorization_endpoint is required */
	oidc_json_t *j = json_pack("{s:s}", "issuer", "https://idp.example.com");
	ck_assert_int_eq(oidc_metadata_provider_is_valid(r, c, j, "https://idp.example.com"), FALSE);
	oidc_json_decref(j);
}
END_TEST

/*
 * Tests for oidc_metadata_provider_parse — parses a JSON metadata object
 * into an oidc_provider_t. Existing values are NOT overridden.
 */

START_TEST(test_metadata_parse_populates_empty_provider) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);

	ck_assert_str_eq(oidc_cfg_provider_issuer_get(provider), "https://idp.example.com");
	ck_assert_str_eq(oidc_cfg_provider_authorization_endpoint_url_get(provider),
			 "https://idp.example.com/authorize");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider), "https://idp.example.com/userinfo");
	ck_assert_str_eq(oidc_cfg_provider_jwks_uri_uri_get(provider), "https://idp.example.com/jwks");

	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_parse_preserves_existing_values) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	/* preset values: the parser must NOT override these */
	oidc_cfg_provider_issuer_set(r->pool, provider, "https://configured.example.com");
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, "https://configured.example.com/token");

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);

	ck_assert_str_eq(oidc_cfg_provider_issuer_get(provider), "https://configured.example.com");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://configured.example.com/token");
	/* unset values are taken from the metadata */
	ck_assert_str_eq(oidc_cfg_provider_authorization_endpoint_url_get(provider),
			 "https://idp.example.com/authorize");

	oidc_json_decref(j);
}
END_TEST

/*
 * Tests for oidc_metadata_provider_retrieve — drive the HTTP fetch +
 * JSON-decode + is_valid pipeline against the loopback server.
 */

START_TEST(test_metadata_retrieve_success) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	/* the call uses the provider's ssl_validate_server flag */
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = VALID_METADATA_JSON};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_json_t *j = NULL;
	char *response = NULL;
	apr_byte_t ok = oidc_metadata_provider_retrieve(r, c, "https://idp.example.com",
							oidc_test_http_server_url(srv, r->pool), &j, &response);
	ck_assert_int_eq(ok, TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_ptr_nonnull(response);
	ck_assert_msg(_oidc_strstr(response, "\"issuer\"") != NULL, "raw response should contain the issuer key");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "GET");

	oidc_json_decref(j);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_metadata_retrieve_http_failure) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	int port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(port, 0);
	const char *url = apr_psprintf(r->pool, "http://127.0.0.1:%d/.well-known", port);

	oidc_json_t *j = NULL;
	char *response = NULL;
	/* nothing listening => HTTP fetch fails => FALSE */
	ck_assert_int_eq(oidc_metadata_provider_retrieve(r, c, "https://idp.example.com", url, &j, &response), FALSE);
}
END_TEST

START_TEST(test_metadata_retrieve_invalid_metadata) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	/* JSON parses, but the issuer field is missing => is_valid rejects it */
	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"authorization_endpoint\":\"https://idp.example.com/authorize\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_json_t *j = NULL;
	char *response = NULL;
	ck_assert_int_eq(oidc_metadata_provider_retrieve(r, c, "https://idp.example.com",
							 oidc_test_http_server_url(srv, r->pool), &j, &response),
			 FALSE);
	ck_assert_ptr_null(j);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/*
 * Tests for oidc_metadata_jwks_get — drive the HTTP fetch + JWKS-validity +
 * cache pipeline.
 */

START_TEST(test_metadata_jwks_get_forced_refresh) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *jwks_body = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks_body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.uri = oidc_test_http_server_url(srv, r->pool);
	jwks_uri.refresh_interval = 60;

	oidc_json_t *j = NULL;
	apr_byte_t refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_ptr_nonnull(oidc_json_object_get(j, "keys"));

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "GET");

	oidc_json_decref(j);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_metadata_jwks_get_http_failure) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	int port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(port, 0);
	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.uri = apr_psprintf(r->pool, "http://127.0.0.1:%d/jwks", port);
	jwks_uri.refresh_interval = 60;

	oidc_json_t *j = NULL;
	apr_byte_t refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), FALSE);
	ck_assert_ptr_null(j);
}
END_TEST

/*
 * after a successful refresh the JWKs is cached; a follow-up call with refresh=FALSE
 * must serve the cached copy and skip the HTTP round-trip
 */
START_TEST(test_metadata_jwks_get_cache_hit) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *jwks_body = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks_body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.uri = oidc_test_http_server_url(srv, r->pool);
	jwks_uri.refresh_interval = 60;

	/* first call: forced refresh populates the cache */
	oidc_json_t *j1 = NULL;
	apr_byte_t refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j1, &refresh), TRUE);
	ck_assert_ptr_nonnull(j1);
	oidc_json_decref(j1);

	/* stop the server so a second HTTP request would fail; cache should still serve */
	oidc_test_http_server_stop(srv);

	oidc_json_t *j2 = NULL;
	refresh = FALSE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j2, &refresh), TRUE);
	ck_assert_ptr_nonnull(j2);
	ck_assert_ptr_nonnull(oidc_json_object_get(j2, "keys"));
	oidc_json_decref(j2);
}
END_TEST

/*
 * a JWKs document that does not contain a "keys" array must be rejected; refresh=FALSE
 * keeps the cache-miss path linear (single HTTP attempt) since our one-shot test server
 * only services one request
 */
START_TEST(test_metadata_jwks_get_missing_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"not_keys\":[]}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.uri = oidc_test_http_server_url(srv, r->pool);
	jwks_uri.refresh_interval = 60;

	oidc_json_t *j = NULL;
	apr_byte_t refresh = FALSE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), FALSE);

	oidc_test_http_server_stop(srv);
}
END_TEST

/* non-JSON response body must be rejected (same single-HTTP-attempt setup as above) */
START_TEST(test_metadata_jwks_get_invalid_json) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "this is not json"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.uri = oidc_test_http_server_url(srv, r->pool);
	jwks_uri.refresh_interval = 60;

	oidc_json_t *j = NULL;
	apr_byte_t refresh = FALSE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), FALSE);

	oidc_test_http_server_stop(srv);
}
END_TEST

/*
 * Tests for the signed_jwks_uri branch of oidc_metadata_jwks_get — the JWKs
 * document is served as the payload of a signed JWT that must verify against
 * the keys pinned in jwks_uri->jwk_list.
 */

/* build an HS256-signed JWT whose payload is a JWKs document */
static char *signed_jwks_make_jwt(request_rec *r, const char *secret) {
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, FALSE, &jwk), TRUE);

	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	oidc_json_object_set_new(
	    jwt->payload.value.json, "keys",
	    json_loads("[{\"kty\":\"oct\",\"kid\":\"k1\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]", 0, NULL));

	ck_assert_int_eq(oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err), TRUE);
	char *cser = oidc_jose_jwt_serialize(r->pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
	return cser;
}

/* build the pinned verifier key list: one key carrying a kid and one without,
 * covering both kid-registration branches of the signed_jwks loop */
static apr_array_header_t *signed_jwks_make_verifier_list(request_rec *r, const char *secret) {
	oidc_jwk_t *jwk_kid = NULL;
	oidc_jwk_t *jwk_no_kid = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk_kid), TRUE);
	ck_assert_ptr_nonnull(jwk_kid->kid);
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, FALSE, &jwk_no_kid), TRUE);
	ck_assert_ptr_null(jwk_no_kid->kid);
	apr_array_header_t *jwk_list = apr_array_make(r->pool, 2, sizeof(oidc_jwk_t *));
	APR_ARRAY_PUSH(jwk_list, oidc_jwk_t *) = jwk_kid;
	APR_ARRAY_PUSH(jwk_list, oidc_jwk_t *) = jwk_no_kid;
	return jwk_list;
}

static void signed_jwks_destroy_verifier_list(apr_array_header_t *jwk_list) {
	for (int i = 0; i < jwk_list->nelts; i++)
		oidc_jwk_destroy(APR_ARRAY_IDX(jwk_list, i, oidc_jwk_t *));
}

START_TEST(test_metadata_jwks_get_signed_happy) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *secret = "signed-jwks-shared-secret-long-enough";
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/jwt", .body = signed_jwks_make_jwt(r, secret)};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.signed_uri = oidc_test_http_server_url(srv, r->pool);
	jwks_uri.refresh_interval = 60;
	jwks_uri.jwk_list = signed_jwks_make_verifier_list(r, secret);

	oidc_json_t *j = NULL;
	apr_byte_t refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_ptr_nonnull(oidc_json_object_get(j, "keys"));
	oidc_json_decref(j);

	/* the unwrapped payload must have been cached under the signed_uri key;
	 * stop the server so a cache miss would surface as an HTTP failure */
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);

	oidc_json_t *j2 = NULL;
	refresh = FALSE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j2, &refresh), TRUE);
	ck_assert_ptr_nonnull(j2);
	ck_assert_ptr_nonnull(oidc_json_object_get(j2, "keys"));
	oidc_json_decref(j2);

	signed_jwks_destroy_verifier_list(jwks_uri.jwk_list);
}
END_TEST

/* a signed JWKs response signed with the wrong key must be rejected */
START_TEST(test_metadata_jwks_get_signed_bad_signature) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/jwt",
					  .body = signed_jwks_make_jwt(r, "attacker-controlled-other-secret")};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.signed_uri = oidc_test_http_server_url(srv, r->pool);
	jwks_uri.refresh_interval = 60;
	jwks_uri.jwk_list = signed_jwks_make_verifier_list(r, "signed-jwks-shared-secret-long-enough");

	oidc_json_t *j = NULL;
	apr_byte_t refresh = FALSE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), FALSE);
	ck_assert_ptr_null(j);

	oidc_test_http_server_stop(srv);
	signed_jwks_destroy_verifier_list(jwks_uri.jwk_list);
}
END_TEST

/* a response that is not a JWT at all must be rejected when signed_jwks_uri is used */
START_TEST(test_metadata_jwks_get_signed_not_a_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"keys\":[]}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.signed_uri = oidc_test_http_server_url(srv, r->pool);
	jwks_uri.refresh_interval = 60;
	jwks_uri.jwk_list = signed_jwks_make_verifier_list(r, "signed-jwks-shared-secret-long-enough");

	oidc_json_t *j = NULL;
	apr_byte_t refresh = FALSE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), FALSE);
	ck_assert_ptr_null(j);

	oidc_test_http_server_stop(srv);
	signed_jwks_destroy_verifier_list(jwks_uri.jwk_list);
}
END_TEST

/*
 * Tests for oidc_oauth_metadata_provider_parse — populates cfg->oauth from
 * an AS metadata document.
 */

START_TEST(test_metadata_oauth_provider_parse) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_json_t *j = json_pack("{s:s,s:s,s:s}", "issuer", "https://as.example.com", "introspection_endpoint",
				   "https://as.example.com/introspect", "jwks_uri", "https://as.example.com/jwks");
	ck_assert_int_eq(oidc_oauth_metadata_provider_parse(r, c, j), TRUE);

	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_url_get(c), "https://as.example.com/introspect");
	ck_assert_str_eq(oidc_cfg_oauth_verify_jwks_uri_get(c), "https://as.example.com/jwks");

	oidc_json_decref(j);
}
END_TEST

/*
 * Disk-backed metadata-directory tests — set OIDCMetadataDir to a
 * fresh /tmp directory, drop in a .provider + .client file pair, and
 * exercise oidc_metadata_list / oidc_metadata_get / oidc_metadata_provider_get.
 */

/* create a fresh, empty temp dir and configure OIDCMetadataDir to point at it */
static const char *e2e_make_metadata_dir(request_rec *r) {
	char *tmpl = apr_psprintf(r->pool, "/tmp/oidc-test-metadata.XXXXXX");
	ck_assert_msg(mkdtemp(tmpl) != NULL, "could not create temp metadata dir at %s", tmpl);
	cmd_parms *cmd = oidc_test_cmd_get("OIDCMetadataDir");
	ck_assert_ptr_null(oidc_cmd_metadata_dir_set(cmd, NULL, tmpl));
	return tmpl;
}

static void e2e_write_file(request_rec *r, const char *path, const char *body) {
	apr_file_t *f = NULL;
	apr_status_t rv = apr_file_open(&f, path, APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE,
					APR_FPROT_UREAD | APR_FPROT_UWRITE, r->pool);
	ck_assert_msg(rv == APR_SUCCESS, "could not create file at %s", path);
	apr_size_t len = (apr_size_t)_oidc_strlen(body);
	rv = apr_file_write(f, body, &len);
	ck_assert_int_eq(rv, APR_SUCCESS);
	apr_file_close(f);
}

START_TEST(test_metadata_disk_list_empty_dir) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	(void)e2e_make_metadata_dir(r);

	apr_array_header_t *list = NULL;
	ck_assert_int_eq(oidc_metadata_list(r, c, &list), TRUE);
	ck_assert_ptr_nonnull(list);
	ck_assert_int_eq(list->nelts, 0);
}
END_TEST

START_TEST(test_metadata_disk_get_provider_only) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	/* a .provider file alone is enough for oidc_metadata_provider_get */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), VALID_METADATA_JSON);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_metadata_provider_get(r, c, "https://idp.example.com", &j, FALSE), TRUE);
	ck_assert_ptr_nonnull(j);
	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_disk_list_skips_provider_without_client) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	/* drop only the provider file; oidc_metadata_get fails because the
	 * companion .client file is missing and dynamic registration is not allowed,
	 * so oidc_metadata_list silently skips this issuer */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), VALID_METADATA_JSON);

	apr_array_header_t *list = NULL;
	ck_assert_int_eq(oidc_metadata_list(r, c, &list), TRUE);
	ck_assert_ptr_nonnull(list);
	ck_assert_int_eq(list->nelts, 0);
}
END_TEST

START_TEST(test_metadata_disk_get_full) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), VALID_METADATA_JSON);
	/* minimal valid client metadata */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\"}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, FALSE), TRUE);
	ck_assert_ptr_nonnull(provider);
	ck_assert_str_eq(oidc_cfg_provider_issuer_get(provider), "https://idp.example.com");
	ck_assert_str_eq(oidc_cfg_provider_client_id_get(provider), "rp-test");

	/* the same directory now produces a single-issuer list */
	apr_array_header_t *list = NULL;
	ck_assert_int_eq(oidc_metadata_list(r, c, &list), TRUE);
	ck_assert_int_eq(list->nelts, 1);
	ck_assert_str_eq(APR_ARRAY_IDX(list, 0, const char *), "https://idp.example.com");
}
END_TEST

START_TEST(test_metadata_disk_get_with_empty_conf_file) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), VALID_METADATA_JSON);
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\"}");
	/* an empty JSON conf object has no fields to validate => still accepted */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.conf", dir), "{}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, FALSE), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_issuer_get(provider), "https://idp.example.com");
}
END_TEST

START_TEST(test_metadata_disk_get_with_invalid_conf_alg) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), VALID_METADATA_JSON);
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\"}");
	/* conf contains an unsupported id_token signing algorithm => conf_is_valid rejects it */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.conf", dir),
		       "{\"id_token_signed_response_alg\":\"TOTALLY_BOGUS_ALG\"}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, FALSE), FALSE);
}
END_TEST

START_TEST(test_metadata_disk_dyn_registration_success) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	/* start a loopback server that will respond to the dynamic-registration POST */
	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"client_id\":\"dyn-rp\",\"client_secret\":\"dyn-secret\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	/* provider metadata advertises a registration_endpoint pointing at the loopback server */
	const char *provider_json = apr_psprintf(r->pool,
						 "{\"issuer\":\"https://idp.example.com\","
						 "\"authorization_endpoint\":\"https://idp.example.com/authorize\","
						 "\"token_endpoint\":\"https://idp.example.com/token\","
						 "\"jwks_uri\":\"https://idp.example.com/jwks\","
						 "\"registration_endpoint\":\"%s\","
						 "\"response_types_supported\":[\"code\",\"id_token\"],"
						 "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}",
						 oidc_test_http_server_url(srv, r->pool));
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), provider_json);
	/* no .client on disk yet => fall through to dynamic registration */

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, TRUE), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_client_id_get(provider), "dyn-rp");
	ck_assert_str_eq(oidc_cfg_provider_client_secret_get(provider), "dyn-secret");

	/* the dynamic-registration POST should have been issued */
	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_msg(_oidc_strstr(cap->body, "redirect_uris") != NULL, "registration POST body carries redirect_uris");

	oidc_test_http_server_stop(srv);
}
END_TEST

/*
 * Tests for oidc_metadata_conf_parse — exercise the static conf_parse_* helpers
 * by driving them through the public wrapper.
 */

START_TEST(test_metadata_conf_parse_string_fields) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	/* the tls_client_cert/key setters access(2)-check the path, so point them at real fixtures */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	const char *cert_path = apr_psprintf(r->pool, "%s/certificate.pem", dir);
	const char *key_path = apr_psprintf(r->pool, "%s/ecpriv.key", dir);

	const char *conf_json = apr_psprintf(r->pool,
					     "{"
					     "\"profile\":\"OIDC10\","
					     "\"client_jwks_uri\":\"https://rp.example.com/jwks\","
					     "\"id_token_signed_response_alg\":\"RS256\","
					     "\"id_token_encrypted_response_alg\":\"RSA-OAEP\","
					     "\"id_token_encrypted_response_enc\":\"A256GCM\","
					     "\"userinfo_signed_response_alg\":\"RS256\","
					     "\"userinfo_encrypted_response_alg\":\"RSA-OAEP\","
					     "\"userinfo_encrypted_response_enc\":\"A128CBC-HS256\","
					     "\"scope\":\"openid profile email\","
					     "\"auth_request_params\":\"prompt=consent\","
					     "\"logout_request_params\":\"foo=bar\","
					     "\"token_endpoint_params\":\"baz=qux\","
					     "\"response_mode\":\"form_post\","
					     "\"pkce_method\":\"S256\","
					     "\"response_type\":\"code\","
					     "\"client_name\":\"Test RP\","
					     "\"client_contact\":\"ops@example.com\","
					     "\"registration_token\":\"reg.tok.en\","
					     "\"registration_endpoint_json\":\"{\\\"custom\\\":\\\"x\\\"}\","
					     "\"token_endpoint_auth\":\"client_secret_post\","
					     "\"token_endpoint_tls_client_cert\":\"%s\","
					     "\"token_endpoint_tls_client_key\":\"%s\","
					     "\"token_endpoint_tls_client_key_pwd\":\"sekret\""
					     "}",
					     cert_path, key_path);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, conf_json, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j, provider), TRUE);

	/* keys */
	ck_assert_str_eq(oidc_cfg_provider_client_jwks_uri_get(provider), "https://rp.example.com/jwks");
	/* id_token */
	ck_assert_str_eq(oidc_cfg_provider_id_token_signed_response_alg_get(provider), "RS256");
	ck_assert_str_eq(oidc_cfg_provider_id_token_encrypted_response_alg_get(provider), "RSA-OAEP");
	ck_assert_str_eq(oidc_cfg_provider_id_token_encrypted_response_enc_get(provider), "A256GCM");
	/* userinfo */
	ck_assert_str_eq(oidc_cfg_provider_userinfo_signed_response_alg_get(provider), "RS256");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_encrypted_response_alg_get(provider), "RSA-OAEP");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_encrypted_response_enc_get(provider), "A128CBC-HS256");
	/* request params */
	ck_assert_str_eq(oidc_cfg_provider_scope_get(provider), "openid profile email");
	ck_assert_str_eq(oidc_cfg_provider_auth_request_params_get(provider), "prompt=consent");
	ck_assert_str_eq(oidc_cfg_provider_logout_request_params_get(provider), "foo=bar");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_params_get(provider), "baz=qux");
	/* response */
	ck_assert_str_eq(oidc_cfg_provider_response_mode_get(provider), "form_post");
	ck_assert_str_eq(oidc_cfg_provider_response_type_get(provider), "code");
	/* client */
	ck_assert_str_eq(oidc_cfg_provider_client_name_get(provider), "Test RP");
	ck_assert_str_eq(oidc_cfg_provider_client_contact_get(provider), "ops@example.com");
	ck_assert_str_eq(oidc_cfg_provider_registration_token_get(provider), "reg.tok.en");
	ck_assert_str_eq(oidc_cfg_provider_registration_endpoint_json_get(provider), "{\"custom\":\"x\"}");
	/* tls client */
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider), cert_path);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_tls_client_key_get(provider), key_path);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_tls_client_key_pwd_get(provider), "sekret");

	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_conf_parse_int_fields) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	/* mix of JSON booleans and integers — both must be honoured */
	const char *conf_json = "{"
				"\"ssl_validate_server\":false,"
				"\"validate_issuer\":false,"
				"\"jwks_refresh_interval\":7200,"
				"\"idtoken_iat_slack\":42,"
				"\"session_max_duration\":3600,"
				"\"userinfo_refresh_interval\":300,"
				"\"response_require_iss\":true"
				"}";

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, conf_json, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j, provider), TRUE);

	ck_assert_int_eq(oidc_cfg_provider_ssl_validate_server_get(provider), FALSE);
	ck_assert_int_eq(oidc_cfg_provider_validate_issuer_get(provider), FALSE);
	ck_assert_int_eq(oidc_cfg_provider_jwks_uri_refresh_interval_get(provider), 7200);
	ck_assert_int_eq(oidc_cfg_provider_idtoken_iat_slack_get(provider), 42);
	ck_assert_int_eq(oidc_cfg_provider_session_max_duration_get(provider), 3600);
	ck_assert_int_eq(oidc_cfg_provider_userinfo_refresh_interval_get(provider), 300);
	ck_assert_int_eq(oidc_cfg_provider_response_require_iss_get(provider), TRUE);

	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_conf_parse_id_token_aud_values) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_json_t *j = json_pack("{s:[s,s]}", "id_token_aud_values", "aud-one", "aud-two");
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j, provider), TRUE);

	const apr_array_header_t *auds = oidc_cfg_provider_id_token_aud_values_get(provider);
	ck_assert_ptr_nonnull(auds);
	ck_assert_int_eq(auds->nelts, 2);
	ck_assert_str_eq(APR_ARRAY_IDX(auds, 0, const char *), "aud-one");
	ck_assert_str_eq(APR_ARRAY_IDX(auds, 1, const char *), "aud-two");

	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_conf_parse_dpop_and_auth_request_method) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_json_t *j = json_pack("{s:s,s:s}", "dpop_mode", "required", "auth_request_method", "POST");
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j, provider), TRUE);

	ck_assert_int_eq(oidc_cfg_provider_dpop_mode_get(provider), OIDC_DPOP_MODE_REQUIRED);
	ck_assert_int_eq(oidc_cfg_provider_auth_request_method_get(provider), OIDC_AUTH_REQUEST_METHOD_POST);

	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_conf_parse_userinfo_token_method) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_json_t *j = json_pack("{s:s}", "userinfo_token_method", "post_param");
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j, provider), TRUE);

	ck_assert_int_eq(oidc_cfg_provider_userinfo_token_method_get(provider), OIDC_USER_INFO_TOKEN_METHOD_POST);

	oidc_json_decref(j);
}
END_TEST

/*
 * Tests for the oidc_metadata_client_register POST payload — drive the static
 * helper through the full disk-backed dynamic-registration flow and inspect
 * the captured POST body.
 */

START_TEST(test_metadata_disk_dyn_registration_payload_fields) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"client_id\":\"dyn-rp\",\"client_secret\":\"dyn-secret\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *provider_json = apr_psprintf(r->pool,
						 "{\"issuer\":\"https://idp.example.com\","
						 "\"authorization_endpoint\":\"https://idp.example.com/authorize\","
						 "\"token_endpoint\":\"https://idp.example.com/token\","
						 "\"jwks_uri\":\"https://idp.example.com/jwks\","
						 "\"registration_endpoint\":\"%s\","
						 "\"response_types_supported\":[\"code\",\"id_token\"],"
						 "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}",
						 oidc_test_http_server_url(srv, r->pool));
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), provider_json);
	/* the .conf supplies the provider-level fields that client_register reads */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.conf", dir),
		       "{\"client_name\":\"Test RP\","
		       "\"client_contact\":\"ops@example.com\","
		       "\"token_endpoint_auth\":\"client_secret_post\","
		       "\"id_token_signed_response_alg\":\"RS256\","
		       "\"request_object\":\"{\\\"crypto\\\":{\\\"sign_alg\\\":\\\"RS256\\\"}}\"}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, TRUE), TRUE);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");

	/* registration POST body must carry every field the server-side spec needs */
	ck_assert_msg(_oidc_strstr(cap->body, "\"client_name\"") != NULL, "missing client_name in: %s", cap->body);
	ck_assert_msg(_oidc_strstr(cap->body, "\"Test RP\"") != NULL, "missing client_name value in: %s", cap->body);
	ck_assert_msg(_oidc_strstr(cap->body, "\"redirect_uris\"") != NULL, "missing redirect_uris");
	ck_assert_msg(_oidc_strstr(cap->body, "https://www.example.com/protected/") != NULL,
		      "missing redirect_uri value");
	ck_assert_msg(_oidc_strstr(cap->body, "\"response_types\"") != NULL, "missing response_types");
	ck_assert_msg(_oidc_strstr(cap->body, "\"grant_types\"") != NULL, "missing grant_types");
	ck_assert_msg(_oidc_strstr(cap->body, "\"authorization_code\"") != NULL, "missing authorization_code grant");
	ck_assert_msg(_oidc_strstr(cap->body, "\"refresh_token\"") != NULL, "missing refresh_token grant");
	ck_assert_msg(_oidc_strstr(cap->body, "\"contacts\"") != NULL, "missing contacts");
	ck_assert_msg(_oidc_strstr(cap->body, "\"ops@example.com\"") != NULL, "missing contact value");
	ck_assert_msg(_oidc_strstr(cap->body, "\"token_endpoint_auth_method\"") != NULL,
		      "missing token_endpoint_auth_method");
	ck_assert_msg(_oidc_strstr(cap->body, "\"client_secret_post\"") != NULL,
		      "missing token_endpoint_auth_method value");
	ck_assert_msg(_oidc_strstr(cap->body, "\"id_token_signed_response_alg\"") != NULL,
		      "missing id_token_signed_response_alg");
	ck_assert_msg(_oidc_strstr(cap->body, "\"initiate_login_uri\"") != NULL, "missing initiate_login_uri");
	ck_assert_msg(_oidc_strstr(cap->body, "\"frontchannel_logout_uri\"") != NULL,
		      "missing frontchannel_logout_uri");
	ck_assert_msg(_oidc_strstr(cap->body, "\"backchannel_logout_uri\"") != NULL, "missing backchannel_logout_uri");
	ck_assert_msg(_oidc_strstr(cap->body, "\"request_object_signing_alg\"") != NULL,
		      "missing request_object_signing_alg");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_metadata_disk_dyn_registration_custom_json_merge) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"client_id\":\"dyn-rp\",\"client_secret\":\"dyn-secret\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	const char *provider_json = apr_psprintf(r->pool,
						 "{\"issuer\":\"https://idp.example.com\","
						 "\"authorization_endpoint\":\"https://idp.example.com/authorize\","
						 "\"token_endpoint\":\"https://idp.example.com/token\","
						 "\"jwks_uri\":\"https://idp.example.com/jwks\","
						 "\"registration_endpoint\":\"%s\","
						 "\"response_types_supported\":[\"code\",\"id_token\"],"
						 "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}",
						 oidc_test_http_server_url(srv, r->pool));
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), provider_json);
	/* the registration_endpoint_json contents are merged into the POST body */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.conf", dir),
		       "{\"registration_endpoint_json\":"
		       "\"{\\\"software_id\\\":\\\"my-software\\\",\\\"software_version\\\":\\\"1.2.3\\\"}\"}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, TRUE), TRUE);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(_oidc_strstr(cap->body, "\"software_id\"") != NULL, "missing software_id in: %s", cap->body);
	ck_assert_msg(_oidc_strstr(cap->body, "\"my-software\"") != NULL, "missing software_id value");
	ck_assert_msg(_oidc_strstr(cap->body, "\"software_version\"") != NULL, "missing software_version");
	ck_assert_msg(_oidc_strstr(cap->body, "\"1.2.3\"") != NULL, "missing software_version value");
	/* and the built-in fields must still be present alongside the merged ones */
	ck_assert_msg(_oidc_strstr(cap->body, "\"redirect_uris\"") != NULL, "missing redirect_uris after merge");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_metadata_disk_provider_get_missing_no_discovery) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	(void)e2e_make_metadata_dir(r);

	/* no provider file on disk and allow_discovery=FALSE => oidc_metadata_provider_get fails */
	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_metadata_provider_get(r, c, "https://missing.example.com", &j, FALSE), FALSE);
}
END_TEST

int main(void) {
	TCase *validate = tcase_create("validate");
	tcase_add_checked_fixture(validate, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(validate, test_metadata_is_valid_happy);
	tcase_add_test(validate, test_metadata_is_valid_missing_issuer);
	tcase_add_test(validate, test_metadata_is_valid_issuer_mismatch);
	tcase_add_test(validate, test_metadata_is_valid_missing_authz_endpoint);

	TCase *parse = tcase_create("parse");
	tcase_add_checked_fixture(parse, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(parse, test_metadata_parse_populates_empty_provider);
	tcase_add_test(parse, test_metadata_parse_preserves_existing_values);
	tcase_add_test(parse, test_metadata_oauth_provider_parse);

	TCase *retrieve = tcase_create("retrieve");
	tcase_add_checked_fixture(retrieve, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(retrieve, 30);
	tcase_add_test(retrieve, test_metadata_retrieve_success);
	tcase_add_test(retrieve, test_metadata_retrieve_http_failure);
	tcase_add_test(retrieve, test_metadata_retrieve_invalid_metadata);
	tcase_add_test(retrieve, test_metadata_jwks_get_forced_refresh);
	tcase_add_test(retrieve, test_metadata_jwks_get_http_failure);
	tcase_add_test(retrieve, test_metadata_jwks_get_cache_hit);
	tcase_add_test(retrieve, test_metadata_jwks_get_missing_keys);
	tcase_add_test(retrieve, test_metadata_jwks_get_invalid_json);
	tcase_add_test(retrieve, test_metadata_jwks_get_signed_happy);
	tcase_add_test(retrieve, test_metadata_jwks_get_signed_bad_signature);
	tcase_add_test(retrieve, test_metadata_jwks_get_signed_not_a_jwt);

	TCase *conf = tcase_create("conf");
	tcase_add_checked_fixture(conf, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(conf, test_metadata_conf_parse_string_fields);
	tcase_add_test(conf, test_metadata_conf_parse_int_fields);
	tcase_add_test(conf, test_metadata_conf_parse_id_token_aud_values);
	tcase_add_test(conf, test_metadata_conf_parse_dpop_and_auth_request_method);
	tcase_add_test(conf, test_metadata_conf_parse_userinfo_token_method);

	TCase *disk = tcase_create("disk");
	tcase_add_checked_fixture(disk, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(disk, test_metadata_disk_list_empty_dir);
	tcase_add_test(disk, test_metadata_disk_get_provider_only);
	tcase_add_test(disk, test_metadata_disk_list_skips_provider_without_client);
	tcase_add_test(disk, test_metadata_disk_get_full);
	tcase_add_test(disk, test_metadata_disk_get_with_empty_conf_file);
	tcase_add_test(disk, test_metadata_disk_get_with_invalid_conf_alg);
	tcase_add_test(disk, test_metadata_disk_dyn_registration_success);
	tcase_add_test(disk, test_metadata_disk_dyn_registration_payload_fields);
	tcase_add_test(disk, test_metadata_disk_dyn_registration_custom_json_merge);
	tcase_add_test(disk, test_metadata_disk_provider_get_missing_no_discovery);

	Suite *s = suite_create("metadata");
	suite_add_tcase(s, validate);
	suite_add_tcase(s, parse);
	suite_add_tcase(s, retrieve);
	suite_add_tcase(s, conf);
	suite_add_tcase(s, disk);

	return oidc_test_suite_run(s);
}
