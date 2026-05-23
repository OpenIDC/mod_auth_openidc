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
	json_t *j = NULL;
	ck_assert_int_eq(oidc_util_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_is_valid(r, c, j, "https://idp.example.com"), TRUE);
	json_decref(j);
}
END_TEST

START_TEST(test_metadata_is_valid_missing_issuer) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* the "issuer" claim is required */
	json_t *j = json_pack("{s:s}", "authorization_endpoint", "https://idp.example.com/authorize");
	ck_assert_int_eq(oidc_metadata_provider_is_valid(r, c, j, "https://idp.example.com"), FALSE);
	json_decref(j);
}
END_TEST

START_TEST(test_metadata_is_valid_issuer_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *j = NULL;
	ck_assert_int_eq(oidc_util_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
	/* asking for a different issuer than the one in the document => FALSE */
	ck_assert_int_eq(oidc_metadata_provider_is_valid(r, c, j, "https://other.example.com"), FALSE);
	json_decref(j);
}
END_TEST

START_TEST(test_metadata_is_valid_missing_authz_endpoint) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* authorization_endpoint is required */
	json_t *j = json_pack("{s:s}", "issuer", "https://idp.example.com");
	ck_assert_int_eq(oidc_metadata_provider_is_valid(r, c, j, "https://idp.example.com"), FALSE);
	json_decref(j);
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

	json_t *j = NULL;
	ck_assert_int_eq(oidc_util_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);

	ck_assert_str_eq(oidc_cfg_provider_issuer_get(provider), "https://idp.example.com");
	ck_assert_str_eq(oidc_cfg_provider_authorization_endpoint_url_get(provider),
			 "https://idp.example.com/authorize");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider), "https://idp.example.com/userinfo");
	ck_assert_str_eq(oidc_cfg_provider_jwks_uri_uri_get(provider), "https://idp.example.com/jwks");

	json_decref(j);
}
END_TEST

START_TEST(test_metadata_parse_preserves_existing_values) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	/* preset values: the parser must NOT override these */
	oidc_cfg_provider_issuer_set(r->pool, provider, "https://configured.example.com");
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, "https://configured.example.com/token");

	json_t *j = NULL;
	ck_assert_int_eq(oidc_util_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);

	ck_assert_str_eq(oidc_cfg_provider_issuer_get(provider), "https://configured.example.com");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://configured.example.com/token");
	/* unset values are taken from the metadata */
	ck_assert_str_eq(oidc_cfg_provider_authorization_endpoint_url_get(provider),
			 "https://idp.example.com/authorize");

	json_decref(j);
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

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = VALID_METADATA_JSON};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	json_t *j = NULL;
	char *response = NULL;
	apr_byte_t ok = oidc_metadata_provider_retrieve(r, c, "https://idp.example.com",
							oidc_test_http_server_url(srv, r->pool), &j, &response);
	ck_assert_int_eq(ok, TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_ptr_nonnull(response);
	ck_assert_msg(_oidc_strstr(response, "\"issuer\"") != NULL, "raw response should contain the issuer key");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "GET");

	json_decref(j);
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

	json_t *j = NULL;
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

	json_t *j = NULL;
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
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = jwks_body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.uri = oidc_test_http_server_url(srv, r->pool);
	jwks_uri.refresh_interval = 60;

	json_t *j = NULL;
	apr_byte_t refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_ptr_nonnull(json_object_get(j, "keys"));

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "GET");

	json_decref(j);
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

	json_t *j = NULL;
	apr_byte_t refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), FALSE);
	ck_assert_ptr_null(j);
}
END_TEST

/*
 * Tests for oidc_oauth_metadata_provider_parse — populates cfg->oauth from
 * an AS metadata document.
 */

START_TEST(test_metadata_oauth_provider_parse) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	json_t *j = json_pack("{s:s,s:s,s:s}", "issuer", "https://as.example.com", "introspection_endpoint",
			      "https://as.example.com/introspect", "jwks_uri", "https://as.example.com/jwks");
	ck_assert_int_eq(oidc_oauth_metadata_provider_parse(r, c, j), TRUE);

	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_url_get(c), "https://as.example.com/introspect");
	ck_assert_str_eq(oidc_cfg_oauth_verify_jwks_uri_get(c), "https://as.example.com/jwks");

	json_decref(j);
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

	Suite *s = suite_create("metadata");
	suite_add_tcase(s, validate);
	suite_add_tcase(s, parse);
	suite_add_tcase(s, retrieve);

	return oidc_test_suite_run(s);
}
