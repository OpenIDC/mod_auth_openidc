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
#include "metadata/internal.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
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
 * A provider advertising only capabilities this module does not implement has to be refused at
 * validation time, not discovered halfway through an authentication request. One valid document
 * mutated one array at a time, so each refusal is checked in isolation.
 */
START_TEST(test_metadata_is_valid_rejects_unsupported_capabilities) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	static const struct {
		const char *key;
		const char *unsupported;
	} cases[] = {
	    {"response_types_supported", "unsupported_flow"},
	    {"response_modes_supported", "carrier_pigeon"},
	    {"token_endpoint_auth_methods_supported", "secret_handshake"},
	};

	for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		oidc_json_t *j = NULL;
		ck_assert_int_eq(oidc_json_decode_object(r, VALID_METADATA_JSON, &j), TRUE);
		ck_assert_int_eq(json_object_set_new(j, cases[i].key, json_pack("[s]", cases[i].unsupported)), 0);
		ck_assert_msg(oidc_metadata_provider_is_valid(r, c, j, "https://idp.example.com") == FALSE,
			      "a provider advertising only \"%s\" for \"%s\" must be refused", cases[i].unsupported,
			      cases[i].key);
		oidc_json_decref(j);
	}
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
 * the parse also has to settle on a token endpoint authentication method, and a provider offering
 * only one this deployment cannot use has to fail the parse rather than fall through to a default
 * that the OP will then reject
 */
START_TEST(test_metadata_parse_no_usable_token_endpoint_auth) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	/* mutual-TLS client authentication only, with no client certificate configured */
	const char *metadata = "{\"issuer\":\"https://idp.example.com\","
			       "\"authorization_endpoint\":\"https://idp.example.com/authorize\","
			       "\"token_endpoint\":\"https://idp.example.com/token\","
			       "\"token_endpoint_auth_methods_supported\":[\"tls_client_auth\"]}";
	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, metadata, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), FALSE);
	oidc_json_decref(j);
}
END_TEST

/*
 * RFC 8705: an mTLS method is only auto-selected from token_endpoint_auth_methods_supported
 * when a TLS client certificate is configured; in that case the mtls_endpoint_aliases
 * override the conventional endpoint URLs.
 */
START_TEST(test_metadata_parse_mtls_endpoint_aliases) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";

	const char *metadata =
	    "{"
	    "\"issuer\":\"https://idp.example.com\","
	    "\"authorization_endpoint\":\"https://idp.example.com/authorize\","
	    "\"token_endpoint\":\"https://idp.example.com/token\","
	    "\"userinfo_endpoint\":\"https://idp.example.com/userinfo\","
	    "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"tls_client_auth\"],"
	    "\"mtls_endpoint_aliases\":{"
	    "\"token_endpoint\":\"https://mtls.idp.example.com/token\","
	    "\"userinfo_endpoint\":\"https://mtls.idp.example.com/userinfo\""
	    "}"
	    "}";

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, metadata, &j), TRUE);

	/* without a TLS client certificate configured: no mTLS auto-selection, aliases not applied */
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider), "client_secret_basic");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider), "https://idp.example.com/userinfo");

	/* with a (globally configured) TLS client certificate and no client secret: tls_client_auth is
	 * preferred over the client_secret_basic default and the mtls_endpoint_aliases are applied */
	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_tls_client_cert_set(
	    r->pool, oidc_cfg_provider_get(c), apr_psprintf(r->pool, "%s/certificate.pem", dir)));
	provider = oidc_cfg_provider_create(r->pool);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider), "tls_client_auth");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://mtls.idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/userinfo");

	/* with both a TLS client certificate *and* a client secret configured: the certificate is only
	 * for RFC 8705 section 3 token binding, so client_secret_basic remains preferred (backwards
	 * compatible) and the conventional endpoint URLs are kept */
	oidc_cfg_provider_client_secret_set(r->pool, oidc_cfg_provider_get(c), "secret");
	provider = oidc_cfg_provider_create(r->pool);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider), "client_secret_basic");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider), "https://idp.example.com/userinfo");

	oidc_json_decref(j);
}
END_TEST

/*
 * RFC 8705 section 5 aliases only the endpoints that "mtls_endpoint_aliases" lists, so an endpoint
 * it does not mention falls back to the conventional one - but an entry that is there and unusable
 * must not, since the conventional endpoint does not certificate-bind the access token.
 */
START_TEST(test_metadata_parse_mtls_endpoint_aliases_invalid) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	oidc_json_t *j = NULL;

	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_tls_client_cert_set(
	    r->pool, oidc_cfg_provider_get(c), apr_psprintf(r->pool, "%s/certificate.pem", dir)));

	/* an alias entry that is not a valid URL fails the parse rather than silently downgrading */
	const char *bad = "{"
			  "\"issuer\":\"https://idp.example.com\","
			  "\"authorization_endpoint\":\"https://idp.example.com/authorize\","
			  "\"token_endpoint\":\"https://idp.example.com/token\","
			  "\"token_endpoint_auth_methods_supported\":[\"tls_client_auth\"],"
			  "\"mtls_endpoint_aliases\":{\"token_endpoint\":\"not a url\"}"
			  "}";
	ck_assert_int_eq(oidc_json_decode_object(r, bad, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), FALSE);
	oidc_json_decref(j);

	/* an endpoint the aliases simply do not list still falls back to the conventional one */
	const char *partial = "{"
			      "\"issuer\":\"https://idp.example.com\","
			      "\"authorization_endpoint\":\"https://idp.example.com/authorize\","
			      "\"token_endpoint\":\"https://idp.example.com/token\","
			      "\"userinfo_endpoint\":\"https://idp.example.com/userinfo\","
			      "\"token_endpoint_auth_methods_supported\":[\"tls_client_auth\"],"
			      "\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://mtls.idp.example.com/token\"}"
			      "}";
	j = NULL;
	provider = oidc_cfg_provider_create(r->pool);
	ck_assert_int_eq(oidc_json_decode_object(r, partial, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://mtls.idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider), "https://idp.example.com/userinfo");
	oidc_json_decref(j);
}
END_TEST

/*
 * RFC 8705 section 3: a TLS client certificate that is not used for client authentication asks for
 * certificate-bound access tokens, which selects the mtls_endpoint_aliases too. Whether that is
 * inferred from the certificate depends on OIDCCertBoundAccessTokens and, under its "auto" default,
 * on the OP advertising "tls_client_certificate_bound_access_tokens".
 */

#define OIDC_TEST_METADATA_CERT_BOUND(advertised)                                                                      \
	"{"                                                                                                            \
	"\"issuer\":\"https://idp.example.com\","                                                                      \
	"\"authorization_endpoint\":\"https://idp.example.com/authorize\","                                            \
	"\"token_endpoint\":\"https://idp.example.com/token\","                                                        \
	"\"userinfo_endpoint\":\"https://idp.example.com/userinfo\","                                                  \
	"\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"tls_client_auth\"],"                     \
	"\"tls_client_certificate_bound_access_tokens\":" advertised ","                                               \
	"\"mtls_endpoint_aliases\":{"                                                                                  \
	"\"token_endpoint\":\"https://mtls.idp.example.com/token\","                                                   \
	"\"userinfo_endpoint\":\"https://mtls.idp.example.com/userinfo\""                                              \
	"}"                                                                                                            \
	"}"

/* a client secret plus a certificate: client_secret_basic authentication with the certificate for binding only */
static oidc_provider_t *oidc_test_metadata_cert_bound_parse(request_rec *r, oidc_cfg_t *c, const char *metadata) {
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);
	oidc_json_t *j = NULL;

	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_tls_client_cert_set(
	    r->pool, oidc_cfg_provider_get(c), apr_psprintf(r->pool, "%s/certificate.pem", dir)));
	oidc_cfg_provider_client_secret_set(r->pool, oidc_cfg_provider_get(c), "secret");

	ck_assert_int_eq(oidc_json_decode_object(r, metadata, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);
	oidc_json_decref(j);

	/* the certificate must not have changed the authentication method */
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider), "client_secret_basic");

	return provider;
}

START_TEST(test_metadata_parse_cert_bound_tokens_advertised) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* "auto" (the default) + the OP advertising support: the mtls_endpoint_aliases are applied */
	oidc_provider_t *provider = oidc_test_metadata_cert_bound_parse(r, c, OIDC_TEST_METADATA_CERT_BOUND("true"));

	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://mtls.idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/userinfo");
	/* the decision is recorded so that client registration asks for binding as well */
	ck_assert_int_eq(oidc_cfg_provider_cert_bound_tokens_get(provider), OIDC_CERT_BOUND_TOKENS_ON);
}
END_TEST

START_TEST(test_metadata_parse_cert_bound_tokens_not_advertised) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* "auto" + an OP that does not advertise support: the conventional endpoints are kept */
	oidc_provider_t *provider = oidc_test_metadata_cert_bound_parse(r, c, OIDC_TEST_METADATA_CERT_BOUND("false"));

	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider), "https://idp.example.com/userinfo");
	ck_assert_int_eq(oidc_cfg_provider_cert_bound_tokens_get(provider), OIDC_CERT_BOUND_TOKENS_OFF);
}
END_TEST

START_TEST(test_metadata_parse_cert_bound_tokens_off) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* "off": never inferred from the certificate, not even for an OP that advertises support */
	ck_assert_ptr_null(oidc_cfg_provider_cert_bound_tokens_set(r->pool, oidc_cfg_provider_get(c), "off"));
	oidc_provider_t *provider = oidc_test_metadata_cert_bound_parse(r, c, OIDC_TEST_METADATA_CERT_BOUND("true"));

	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider), "https://idp.example.com/userinfo");
}
END_TEST

START_TEST(test_metadata_parse_cert_bound_tokens_on) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* "on": the certificate itself is the signal, regardless of what the OP advertises */
	ck_assert_ptr_null(oidc_cfg_provider_cert_bound_tokens_set(r->pool, oidc_cfg_provider_get(c), "on"));
	oidc_provider_t *provider = oidc_test_metadata_cert_bound_parse(r, c, OIDC_TEST_METADATA_CERT_BOUND("false"));

	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://mtls.idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/userinfo");
}
END_TEST

START_TEST(test_metadata_parse_mtls_explicit_endpoint_wins) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);
	oidc_json_t *j = NULL;

	/* mutual-TLS client authentication, i.e. the aliases apply */
	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_tls_client_cert_set(
	    r->pool, oidc_cfg_provider_get(c), apr_psprintf(r->pool, "%s/certificate.pem", dir)));
	/* ... but this endpoint was configured explicitly, which takes precedence over the alias */
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, "https://configured.example.com/token");

	ck_assert_int_eq(oidc_json_decode_object(r, OIDC_TEST_METADATA_CERT_BOUND("true"), &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);
	oidc_json_decref(j);

	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider), "tls_client_auth");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://configured.example.com/token");
	/* the endpoints that were not configured explicitly do take the alias */
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/userinfo");
}
END_TEST

#define OIDC_TEST_METADATA_PKEY_MTLS                                                                                   \
	"{"                                                                                                            \
	"\"issuer\":\"https://idp.example.com\","                                                                      \
	"\"authorization_endpoint\":\"https://idp.example.com/authorize\","                                            \
	"\"token_endpoint\":\"https://idp.example.com/token\","                                                        \
	"\"registration_endpoint\":\"https://idp.example.com/register\","                                              \
	"\"userinfo_endpoint\":\"https://idp.example.com/userinfo\","                                                  \
	"\"mtls_endpoint_aliases\":{"                                                                                  \
	"\"token_endpoint\":\"https://mtls.idp.example.com/token\","                                                   \
	"\"registration_endpoint\":\"https://mtls.idp.example.com/register\","                                         \
	"\"userinfo_endpoint\":\"https://mtls.idp.example.com/userinfo\","                                             \
	"\"pushed_authorization_request_endpoint\":\"https://mtls.idp.example.com/par\""                               \
	"},"                                                                                                           \
	"\"jwks_uri\":\"https://idp.example.com/jwks\","                                                               \
	"\"response_types_supported\":[\"code\"],"                                                                     \
	"\"authorization_response_iss_parameter_supported\":true,"                                                     \
	"\"code_challenge_methods_supported\":[\"S256\"],"                                                             \
	"\"id_token_signing_alg_values_supported\":[\"PS256\"],"                                                       \
	"\"tls_client_certificate_bound_access_tokens\":true,"                                                         \
	"\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\"],"                                             \
	"\"pushed_authorization_request_endpoint\":\"https://idp.example.com/par\","                                   \
	"\"require_pushed_authorization_requests\":true,"                                                              \
	"\"token_endpoint_auth_signing_alg_values_supported\":[\"PS256\",\"ES256\"]"                                   \
	"}"

/*
 * an OP that separates client authentication from certificate binding: private_key_jwt is the only
 * supported authentication method, while the certificate is there for RFC 8705 section 3 binding.
 * Every advertised alias is applied - including the registration endpoint - and the authorization
 * endpoint (which carries no client credentials at all) is not.
 */
START_TEST(test_metadata_parse_mtls_aliases_private_key_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);
	oidc_json_t *j = NULL;

	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_tls_client_cert_set(
	    r->pool, oidc_cfg_provider_get(c), apr_psprintf(r->pool, "%s/certificate.pem", dir)));

	ck_assert_int_eq(oidc_json_decode_object(r, OIDC_TEST_METADATA_PKEY_MTLS, &j), TRUE);
	ck_assert_int_eq(oidc_metadata_provider_parse(r, c, j, provider), TRUE);
	oidc_json_decref(j);

	/* the certificate must not turn this in to mutual-TLS client authentication */
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider), "private_key_jwt");
	ck_assert_int_eq(oidc_cfg_provider_cert_bound_tokens_get(provider), OIDC_CERT_BOUND_TOKENS_ON);

	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://mtls.idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/userinfo");
	ck_assert_str_eq(oidc_cfg_provider_pushed_authorization_request_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/par");
	ck_assert_str_eq(oidc_cfg_provider_registration_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/register");
	ck_assert_str_eq(oidc_cfg_provider_authorization_endpoint_url_get(provider),
			 "https://idp.example.com/authorize");
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

/* the "kid" of the first key in a JWKs document, for telling two responses apart */
static const char *oidc_test_jwks_first_kid(const oidc_json_t *j) {
	const oidc_json_t *keys = oidc_json_object_get(j, "keys");
	if ((keys == NULL) || (oidc_json_array_size(keys) < 1))
		return NULL;
	return oidc_json_string_value(oidc_json_object_get(oidc_json_array_get(keys, 0), "kid"));
}

/*
 * a forced refresh bypasses the cached JWKs and fetches the jwks_uri directly; it is triggered by an
 * unrecognized "kid" or a failed signature, i.e. straight off an unauthenticated request. It must
 * therefore be rate-limited per jwks_uri: a second forced refresh inside the window has to be served
 * from the cache rather than turning into another outbound fetch.
 */
START_TEST(test_metadata_jwks_get_forced_refresh_throttled) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* two distinguishable documents, so a second fetch would be visible in the result */
	oidc_test_http_response_t resp[2] = {
	    {.status_code = 200,
	     .content_type = "application/json",
	     .body = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}"},
	    {.status_code = 200,
	     .content_type = "application/json",
	     .body = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k2\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}"}};
	oidc_test_http_server_t *srv = oidc_test_http_server_start_seq(r->pool, resp, 2);
	ck_assert_ptr_nonnull(srv);

	const char *base = oidc_test_http_server_url(srv, r->pool);
	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.uri = apr_psprintf(r->pool, "%s/a", base);
	jwks_uri.refresh_interval = 60;

	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), FALSE);

	/* first forced refresh: fetches, and records the attempt */
	oidc_json_t *j = NULL;
	apr_byte_t refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_str_eq(oidc_test_jwks_first_kid(j), "k1");
	oidc_json_decref(j);

	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), TRUE);

	/* second forced refresh inside the window: still the cached document, so no fetch happened -
	 * a fetch would have returned the second (k2) response */
	j = NULL;
	refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_str_eq(oidc_test_jwks_first_kid(j), "k1");
	oidc_json_decref(j);

	/* the rate limit is per jwks_uri: a different one still refreshes. This also consumes the
	 * second response, letting the server thread finish so the request count can be read. */
	oidc_jwks_uri_t other = {0};
	other.uri = apr_psprintf(r->pool, "%s/b", base);
	other.refresh_interval = 60;
	j = NULL;
	refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &other, 0, &j, &refresh), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_str_eq(oidc_test_jwks_first_kid(j), "k2");
	oidc_json_decref(j);

	/* exactly one fetch per distinct jwks_uri; the throttled one never hit the network */
	ck_assert_int_eq(oidc_test_http_server_request_count(srv), 2);
	ck_assert_str_eq(oidc_test_http_server_captured(srv, 0)->path, "/a");
	ck_assert_str_eq(oidc_test_http_server_captured(srv, 1)->path, "/b");

	oidc_test_http_server_stop(srv);
}
END_TEST

/*
 * the rate-limit window is configurable with the OIDC_JWKS_FORCED_REFRESH_INTERVAL environment
 * variable: 0 disables the guard entirely, and anything outside 0-3600 (or not an integer at all)
 * falls back to the 60s default rather than silently removing the guard
 */
START_TEST(test_metadata_jwks_get_forced_refresh_interval_envvar) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_test_http_response_t resp[2] = {
	    {.status_code = 200,
	     .content_type = "application/json",
	     .body = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}"},
	    {.status_code = 200,
	     .content_type = "application/json",
	     .body = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k2\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}"}};
	oidc_test_http_server_t *srv = oidc_test_http_server_start_seq(r->pool, resp, 2);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t jwks_uri = {0};
	jwks_uri.uri = apr_psprintf(r->pool, "%s/a", oidc_test_http_server_url(srv, r->pool));
	jwks_uri.refresh_interval = 60;

	/* the guard is on by default: the first forced refresh fetches and stamps */
	oidc_json_t *j = NULL;
	apr_byte_t refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), TRUE);
	ck_assert_str_eq(oidc_test_jwks_first_kid(j), "k1");
	oidc_json_decref(j);
	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), TRUE);

	/* out of range: falls back to the default, so the stamp still throttles */
	apr_table_set(r->subprocess_env, "OIDC_JWKS_FORCED_REFRESH_INTERVAL", "3601");
	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), TRUE);

	/* negative and non-integer values likewise fall back to the default */
	apr_table_set(r->subprocess_env, "OIDC_JWKS_FORCED_REFRESH_INTERVAL", "-1");
	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), TRUE);
	apr_table_set(r->subprocess_env, "OIDC_JWKS_FORCED_REFRESH_INTERVAL", "60x");
	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), TRUE);

	/* the upper bound itself is accepted */
	apr_table_set(r->subprocess_env, "OIDC_JWKS_FORCED_REFRESH_INTERVAL", "3600");
	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), TRUE);

	/* 0 disables the guard: no longer throttled despite the marker left in the cache, and a second
	 * forced refresh really does fetch again - it returns the second (k2) response */
	apr_table_set(r->subprocess_env, "OIDC_JWKS_FORCED_REFRESH_INTERVAL", "0");
	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), FALSE);

	j = NULL;
	refresh = TRUE;
	ck_assert_int_eq(oidc_metadata_jwks_get(r, c, &jwks_uri, 0, &j, &refresh), TRUE);
	ck_assert_str_eq(oidc_test_jwks_first_kid(j), "k2");
	oidc_json_decref(j);

	/* with the guard off no marker is written either, so it stays unthrottled */
	ck_assert_int_eq(oidc_metadata_jwks_forced_refresh_throttled(r, &jwks_uri), FALSE);

	ck_assert_int_eq(oidc_test_http_server_request_count(srv), 2);
	apr_table_unset(r->subprocess_env, "OIDC_JWKS_FORCED_REFRESH_INTERVAL");
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

/* when the .conf supplies no "signed_jwks_uri_key", the setter must fall back to the globally
 * configured (OIDCProviderSignedJwksUri) verification keys passed as the default, not leave them
 * unset — otherwise a provider that advertises a signed_jwks_uri would skip signature verification */
START_TEST(test_metadata_signed_jwks_uri_keys_global_fallback) {
	request_rec *r = oidc_test_request_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	apr_array_header_t *def = signed_jwks_make_verifier_list(r, "signed-jwks-shared-secret-long-enough");
	ck_assert_ptr_eq((void *)oidc_cfg_provider_signed_jwks_uri_keys_set(r->pool, provider, NULL, def), NULL);
	/* the fallback inherits a private (retaining) copy of the global keys, not the same array */
	apr_array_header_t *got = oidc_cfg_provider_signed_jwks_uri_keys_get(provider);
	ck_assert_ptr_nonnull(got);
	ck_assert_ptr_ne(got, def);
	ck_assert_int_eq(got->nelts, def->nelts);

	signed_jwks_destroy_verifier_list(got);
	signed_jwks_destroy_verifier_list(def);
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

START_TEST(test_metadata_oauth_provider_parse_mtls) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";

	oidc_json_t *j =
	    json_pack("{s:s,s:s,s:[s,s],s:{s:s}}", "issuer", "https://as.example.com", "introspection_endpoint",
		      "https://as.example.com/introspect", "introspection_endpoint_auth_methods_supported",
		      "client_secret_basic", "tls_client_auth", "mtls_endpoint_aliases", "introspection_endpoint",
		      "https://mtls.as.example.com/introspect");

	/* without an introspection TLS client certificate: the client_secret_basic preference wins
	 * and the conventional introspection endpoint is used */
	ck_assert_int_eq(oidc_oauth_metadata_provider_parse(r, c, j), TRUE);
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_auth_get(c), "client_secret_basic");
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_url_get(c), "https://as.example.com/introspect");

	/* with a certificate and no client secret: tls_client_auth is selected and the mTLS alias endpoint
	 * applied */
	cmd_parms *cmd = oidc_test_cmd_get(OIDCOAuthIntrospectionEndpointCert);
	ck_assert_ptr_null(oidc_cmd_oauth_introspection_endpoint_tls_client_cert_set(
	    cmd, NULL, apr_psprintf(r->pool, "%s/certificate.pem", dir)));
	ck_assert_int_eq(oidc_oauth_metadata_provider_parse(r, c, j), TRUE);
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_auth_get(c), "tls_client_auth");
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_url_get(c), "https://mtls.as.example.com/introspect");

	/* with both a certificate *and* a client secret: the certificate is only for RFC 8705 section 3
	 * token binding, so client_secret_basic remains preferred (backwards compatible) and the
	 * conventional introspection endpoint is kept */
	cmd = oidc_test_cmd_get(OIDCOAuthClientSecret);
	ck_assert_ptr_null(oidc_cmd_oauth_client_secret_set(cmd, NULL, "secret"));
	ck_assert_int_eq(oidc_oauth_metadata_provider_parse(r, c, j), TRUE);
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_auth_get(c), "client_secret_basic");
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_url_get(c), "https://as.example.com/introspect");

	/* ... unless the AS advertises certificate-bound access tokens: the certificate is then taken to
	 * be there for section 3 binding and the mTLS alias endpoint is used with client_secret_basic
	 * authentication too (OIDCCertBoundAccessTokens defaults to "auto") */
	oidc_json_object_set_new(j, "tls_client_certificate_bound_access_tokens", oidc_json_boolean(1));
	ck_assert_int_eq(oidc_oauth_metadata_provider_parse(r, c, j), TRUE);
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_auth_get(c), "client_secret_basic");
	ck_assert_str_eq(oidc_cfg_oauth_introspection_endpoint_url_get(c), "https://mtls.as.example.com/introspect");

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

/* with OIDCDefaultLoggedOutURL set, the dynamic-registration request carries
 * a post_logout_redirect_uris array with the absolute logged-out URL */
START_TEST(test_metadata_disk_dyn_registration_post_logout_redirect_uris) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	cmd_parms *cmd = oidc_test_cmd_get(OIDCDefaultLoggedOutURL);
	ck_assert_ptr_null(oidc_cmd_default_slo_url_set(cmd, NULL, "/logged-out.html"));

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
						 "\"response_types_supported\":[\"code\"],"
						 "\"token_endpoint_auth_methods_supported\":[\"client_secret_"
						 "basic\"]}",
						 oidc_test_http_server_url(srv, r->pool));
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), provider_json);

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, TRUE), TRUE);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_msg(_oidc_strstr(cap->body, "\"post_logout_redirect_uris\"") != NULL,
		      "missing post_logout_redirect_uris in: %s", cap->body);
	ck_assert_msg(_oidc_strstr(cap->body, "https://www.example.com/logged-out.html") != NULL,
		      "missing absolute logged-out URL in: %s", cap->body);

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_metadata_client_parse_response_type_not_advertised) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_json_t *j = NULL;
	/* the global default response_type ("code") is not in the client's list */
	ck_assert_int_eq(oidc_json_decode_object(r,
						 "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\","
						 "\"response_types\":[\"id_token\",\"id_token token\"]}",
						 &j),
			 TRUE);
	ck_assert_int_eq(oidc_metadata_client_parse(r, c, j, provider), TRUE);
	/* not explicitly configured: fall back to the first advertised entry */
	ck_assert_str_eq(oidc_cfg_provider_response_type_get(provider), "id_token");
	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_client_parse_response_type_explicitly_set) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	ck_assert_ptr_eq((void *)oidc_cfg_provider_response_type_set(r->pool, provider, "code"), NULL);

	oidc_json_t *j = NULL;
	/* an explicitly configured response_type survives even when the client metadata does not advertise it */
	ck_assert_int_eq(oidc_json_decode_object(r,
						 "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\","
						 "\"response_types\":[\"id_token\",\"id_token token\"]}",
						 &j),
			 TRUE);
	ck_assert_int_eq(oidc_metadata_client_parse(r, c, j, provider), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_response_type_get(provider), "code");
	oidc_json_decref(j);
}
END_TEST

/* conf metadata without an explicit "response_type" must leave it unset so the client-metadata
 * fallback still runs; conf_parse runs before client_parse, exactly as oidc_metadata_get() does */
START_TEST(test_metadata_conf_then_client_response_type_fallback) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_json_t *j_conf = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, "{}", &j_conf), TRUE);
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j_conf, provider), TRUE);
	/* conf parse must not pin response_type to the default */
	ck_assert_int_eq(oidc_cfg_provider_response_type_is_set(provider), FALSE);
	oidc_json_decref(j_conf);

	oidc_json_t *j_client = NULL;
	/* the global default response_type ("code") is not advertised, so the fallback must apply */
	ck_assert_int_eq(oidc_json_decode_object(r,
						 "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\","
						 "\"response_types\":[\"id_token\",\"id_token token\"]}",
						 &j_client),
			 TRUE);
	ck_assert_int_eq(oidc_metadata_client_parse(r, c, j_client, provider), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_response_type_get(provider), "id_token");
	oidc_json_decref(j_client);
}
END_TEST

/*
 * RFC 8705 in a multi-provider (OIDCMetadataDir) setup: the TLS client certificate and the profile
 * are configured in the .conf metadata of this OP, i.e. nowhere in the global configuration, and
 * must still drive the mutual-TLS endpoint selection - even though the .conf is parsed after the
 * provider metadata that the selection is made in
 */
START_TEST(test_metadata_disk_mtls_aliases_from_conf) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);
	const char *srcdir = getenv("srcdir") ? getenv("srcdir") : ".";

	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), OIDC_TEST_METADATA_PKEY_MTLS);
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.conf", dir),
		       apr_psprintf(r->pool,
				    "{\"scope\":\"openid email\","
				    "\"profile\":\"FAPI20\","
				    "\"id_token_signed_response_alg\":\"PS256\","
				    "\"token_endpoint_tls_client_cert\":\"%s/certificate.pem\","
				    "\"token_endpoint_tls_client_key\":\"%s/private.pem\"}",
				    srcdir, srcdir));
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"rp-test\",\"token_endpoint_auth_method\":\"private_key_jwt\"}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, FALSE), TRUE);

	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider), "private_key_jwt");
	ck_assert_int_eq(oidc_cfg_provider_cert_bound_tokens_get(provider), OIDC_CERT_BOUND_TOKENS_ON);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://mtls.idp.example.com/token");
	ck_assert_str_eq(oidc_cfg_provider_userinfo_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/userinfo");
	ck_assert_str_eq(oidc_cfg_provider_pushed_authorization_request_endpoint_url_get(provider),
			 "https://mtls.idp.example.com/par");

	/* FAPI 2.0 sender-constrains through either mutual-TLS or DPoP: with the access tokens bound to
	 * the certificate and this OP not advertising "dpop_signing_alg_values_supported", DPoP is not
	 * required on top */
	ck_assert_int_eq(oidc_cfg_provider_dpop_supported_get(provider), FALSE);
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_OFF);
	ck_assert_int_eq(oidc_cfg_provider_dpop_mode_get(provider), OIDC_DPOP_MODE_OFF);
}
END_TEST

/* the same OP, now advertising DPoP support: the mutual-TLS endpoints are still selected, but FAPI 2.0
 * keeps requiring DPoP since the OP offers it as the sender-constraining mechanism */
START_TEST(test_metadata_disk_mtls_aliases_from_conf_dpop) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);
	const char *srcdir = getenv("srcdir") ? getenv("srcdir") : ".";
	oidc_json_t *j = NULL;
	char *s_json = NULL;

	/* graft "dpop_signing_alg_values_supported" on to the fixture */
	ck_assert_int_eq(oidc_json_decode_object(r, OIDC_TEST_METADATA_PKEY_MTLS, &j), TRUE);
	oidc_json_object_set_new(j, "dpop_signing_alg_values_supported", oidc_json_array());
	oidc_json_array_append_new(oidc_json_object_get(j, "dpop_signing_alg_values_supported"),
				   oidc_json_string("PS256"));
	s_json = oidc_json_encode(r->pool, j, OIDC_JSON_COMPACT);
	oidc_json_decref(j);

	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), s_json);
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.conf", dir),
		       apr_psprintf(r->pool,
				    "{\"profile\":\"FAPI20\","
				    "\"token_endpoint_tls_client_cert\":\"%s/certificate.pem\","
				    "\"token_endpoint_tls_client_key\":\"%s/private.pem\"}",
				    srcdir, srcdir));
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"rp-test\",\"token_endpoint_auth_method\":\"private_key_jwt\"}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, FALSE), TRUE);

	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://mtls.idp.example.com/token");
	ck_assert_int_eq(oidc_cfg_provider_dpop_supported_get(provider), TRUE);
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_REQUIRED);
}
END_TEST

/* a per-OP "cert_bound_tokens" in the .conf metadata overrides the inferred behaviour */
START_TEST(test_metadata_disk_mtls_aliases_conf_off) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);
	const char *srcdir = getenv("srcdir") ? getenv("srcdir") : ".";

	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), OIDC_TEST_METADATA_PKEY_MTLS);
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.conf", dir),
		       apr_psprintf(r->pool,
				    "{\"cert_bound_tokens\":\"off\","
				    "\"token_endpoint_tls_client_cert\":\"%s/certificate.pem\","
				    "\"token_endpoint_tls_client_key\":\"%s/private.pem\"}",
				    srcdir, srcdir));
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"rp-test\",\"token_endpoint_auth_method\":\"private_key_jwt\"}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, FALSE), TRUE);

	ck_assert_int_eq(oidc_cfg_provider_cert_bound_tokens_get(provider), OIDC_CERT_BOUND_TOKENS_OFF);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_url_get(provider), "https://idp.example.com/token");
}
END_TEST

/* a client secret with an expires_at in the past invalidates the client
 * metadata; without a registration endpoint re-registration then fails */
START_TEST(test_metadata_disk_client_secret_expired) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), VALID_METADATA_JSON);
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\","
		       "\"client_secret_expires_at\":100}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, FALSE), FALSE);
}
END_TEST

/* client_secret_expires_at=0 means the secret never expires */
START_TEST(test_metadata_disk_client_secret_never_expires) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);

	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), VALID_METADATA_JSON);
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"rp-test\",\"client_secret\":\"sekret\","
		       "\"client_secret_expires_at\":0}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, FALSE), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_client_id_get(provider), "rp-test");
}
END_TEST

/* live OpenID Connect Discovery: no cached/disk metadata, so the provider
 * document is fetched from <issuer>/.well-known/openid-configuration and
 * written to the metadata directory */
/*
 * OIDCProviderMetadataRefreshInterval: with it set, a cached provider document is used until it is
 * older than the interval and re-fetched after that. None of that ran, including the part that
 * matters most in production -- what happens when the OP is unreachable at the moment the cached
 * document goes stale.
 */

/* the metadata body a provider at `issuer` would publish */
static const char *e2e_provider_metadata_for(request_rec *r, const char *issuer) {
	return apr_psprintf(r->pool,
			    "{\"issuer\":\"%s\","
			    "\"authorization_endpoint\":\"%s/authorize\","
			    "\"token_endpoint\":\"%s/token\","
			    "\"jwks_uri\":\"%s/jwks\","
			    "\"response_types_supported\":[\"code\"],"
			    "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}",
			    issuer, issuer, issuer, issuer);
}

START_TEST(test_metadata_disk_provider_refresh_within_interval_uses_cache) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);
	const char *issuer = "https://idp.example.com";

	ck_assert_ptr_null(oidc_cmd_provider_metadata_refresh_interval_set(
	    oidc_test_cmd_get("OIDCProviderMetadataRefreshInterval"), NULL, "3600"));

	/* freshly written, so well within the interval: no discovery is attempted, which is what
	 * makes this test's lack of an HTTP server meaningful rather than incidental */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), VALID_METADATA_JSON);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_metadata_provider_get(r, c, issuer, &j, TRUE), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(j, "issuer")), issuer);
	oidc_json_decref(j);
}
END_TEST

START_TEST(test_metadata_disk_provider_refresh_falls_back_to_stale_cache) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	(void)e2e_make_metadata_dir(r);
	apr_finfo_t before, after;

	ck_assert_ptr_null(oidc_cmd_provider_metadata_refresh_interval_set(
	    oidc_test_cmd_get("OIDCProviderMetadataRefreshInterval"), NULL, "60"));

	/* the OP answers the refresh with an error */
	oidc_test_http_response_t resp = {
	    .status_code = 500, .content_type = "text/plain", .body = "upstream is having a bad day"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	const char *issuer = oidc_test_http_server_url(srv, r->pool);

	/* a cached document that has aged past the interval */
	const char *path = oidc_metadata_provider_file_path(r, issuer);
	e2e_write_file(r, path, e2e_provider_metadata_for(r, issuer));
	ck_assert_int_eq(apr_file_mtime_set(path, apr_time_now() - apr_time_from_sec(3600), r->pool), APR_SUCCESS);
	ck_assert_int_eq(apr_stat(&before, path, APR_FINFO_MTIME, r->pool), APR_SUCCESS);

	/* the refresh fails, so the expired document is served rather than the request failing */
	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_metadata_provider_get(r, c, issuer, &j, TRUE), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(j, "issuer")), issuer);
	oidc_json_decref(j);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);

	/* and its timestamp was pushed forward, so the next request does not hammer the failing OP */
	ck_assert_int_eq(apr_stat(&after, path, APR_FINFO_MTIME, r->pool), APR_SUCCESS);
	ck_assert_int_gt((int)apr_time_sec(after.mtime), (int)apr_time_sec(before.mtime));
}
END_TEST

START_TEST(test_metadata_disk_provider_refresh_replaces_stale_cache) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	(void)e2e_make_metadata_dir(r);

	ck_assert_ptr_null(oidc_cmd_provider_metadata_refresh_interval_set(
	    oidc_test_cmd_get("OIDCProviderMetadataRefreshInterval"), NULL, "60"));

	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = "{}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	const char *issuer = oidc_test_http_server_url(srv, r->pool);
	resp.body = e2e_provider_metadata_for(r, issuer);

	/* a stale cached document that names an endpoint the refreshed one does not */
	const char *path = oidc_metadata_provider_file_path(r, issuer);
	e2e_write_file(r, path,
		       apr_psprintf(r->pool,
				    "{\"issuer\":\"%s\","
				    "\"authorization_endpoint\":\"%s/OLD-authorize\","
				    "\"response_types_supported\":[\"code\"]}",
				    issuer, issuer));
	ck_assert_int_eq(apr_file_mtime_set(path, apr_time_now() - apr_time_from_sec(3600), r->pool), APR_SUCCESS);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_metadata_provider_get(r, c, issuer, &j, TRUE), TRUE);
	ck_assert_ptr_nonnull(j);
	/* the refreshed document won, and the stale one was let go rather than leaked */
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(j, "authorization_endpoint")),
			 apr_psprintf(r->pool, "%s/authorize", issuer));
	oidc_json_decref(j);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/*
 * an issuer given without a scheme is discovered over https, so "idp.example.com" and
 * "https://idp.example.com" name the same provider
 */
START_TEST(test_metadata_disk_provider_get_schemeless_issuer) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	(void)e2e_make_metadata_dir(r);

	/* a port with nothing listening, so the https attempt fails at once instead of reaching
	 * the network; what is being checked is which URL was assembled, not that it answered */
	int port = oidc_test_http_free_port(r->pool);
	ck_assert_int_gt(port, 0);
	const char *issuer = apr_psprintf(r->pool, "127.0.0.1:%d", port);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_metadata_provider_get(r, c, issuer, &j, TRUE), FALSE);
	ck_assert_ptr_null(j);
}
END_TEST

START_TEST(test_metadata_disk_provider_get_live_discovery) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	(void)e2e_make_metadata_dir(r);

	/* the metadata body must reference the server's own URL as the issuer,
	 * which is only known after binding; the server keeps a pointer to the
	 * response struct, so the body can be filled in before the first request */
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = "{}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	const char *issuer = oidc_test_http_server_url(srv, r->pool);
	resp.body = apr_psprintf(r->pool,
				 "{\"issuer\":\"%s\","
				 "\"authorization_endpoint\":\"%s/authorize\","
				 "\"token_endpoint\":\"%s/token\","
				 "\"jwks_uri\":\"%s/jwks\","
				 "\"response_types_supported\":[\"code\"],"
				 "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}",
				 issuer, issuer, issuer, issuer);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_metadata_provider_get(r, c, issuer, &j, TRUE), TRUE);
	ck_assert_ptr_nonnull(j);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(j, "issuer")), issuer);
	oidc_json_decref(j);

	/* the discovery request must have hit the well-known path */
	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(_oidc_strstr(cap->path, "/.well-known/openid-configuration") != NULL,
		      "discovery must fetch the well-known path: %s", cap->path);
	oidc_test_http_server_stop(srv);

	/* the retrieved metadata was written to the metadata dir: a second call
	 * with discovery disabled and the server down is served from disk */
	j = NULL;
	ck_assert_int_eq(oidc_metadata_provider_get(r, c, issuer, &j, FALSE), TRUE);
	ck_assert_ptr_nonnull(j);
	oidc_json_decref(j);
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

/* an invalid on-disk .client (expired secret) plus a registration endpoint triggers re-registration;
 * the stale client document read from disk must be released, not leaked (verified under valgrind) */
START_TEST(test_metadata_disk_stale_client_reregistration) {
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
	/* an on-disk client whose secret already expired: read but invalid, forcing re-registration */
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.client", dir),
		       "{\"client_id\":\"old-rp\",\"client_secret\":\"old\",\"client_secret_expires_at\":100}");

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, TRUE), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_client_id_get(provider), "dyn-rp");

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

START_TEST(test_metadata_conf_parse_token_endpoint_auth_alg_inherited) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* the fixture cfg has a (non-NULL) private_keys array, so private_key_jwt with an algorithm validates;
	 * configure the global (primary) provider with a method + algorithm */
	ck_assert_ptr_null(
	    oidc_cfg_provider_token_endpoint_auth_set(r->pool, c, oidc_cfg_provider_get(c), "private_key_jwt:RS256"));
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(oidc_cfg_provider_get(c)), "private_key_jwt");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_alg_get(oidc_cfg_provider_get(c)), "RS256");

	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	/* a .conf that does NOT set token_endpoint_auth must inherit BOTH the method and its algorithm from the
	 * global config, not just the method */
	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, "{\"issuer\":\"https://op.example.com\"}", &j), TRUE);
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j, provider), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider), "private_key_jwt");
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_alg_get(provider), "RS256");
	oidc_json_decref(j);

	/* an explicit token_endpoint_auth in the .conf overrides and does NOT inherit the global algorithm */
	oidc_provider_t *provider2 = oidc_cfg_provider_create(r->pool);
	oidc_json_t *j2 = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, "{\"token_endpoint_auth\":\"client_secret_basic\"}", &j2), TRUE);
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j2, provider2), TRUE);
	ck_assert_str_eq(oidc_cfg_provider_token_endpoint_auth_get(provider2), "client_secret_basic");
	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_auth_alg_get(provider2));
	oidc_json_decref(j2);
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

	/* non-string array elements must be skipped, not pushed as NULL entries */
	oidc_provider_t *provider2 = oidc_cfg_provider_create(r->pool);
	oidc_json_t *j2 = json_pack("{s:[i,s,i]}", "id_token_aud_values", 1, "aud-real", 3);
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j2, provider2), TRUE);
	const apr_array_header_t *auds2 = oidc_cfg_provider_id_token_aud_values_get(provider2);
	ck_assert_ptr_nonnull(auds2);
	ck_assert_int_eq(auds2->nelts, 1);
	ck_assert_str_eq(APR_ARRAY_IDX(auds2, 0, const char *), "aud-real");
	oidc_json_decref(j2);
}
END_TEST

/* inline .conf "keys" wrap heap cjose objects that are not pool-managed; the per-request provider is
 * never cfg_provider_destroy'd, so without a request-pool cleanup they leak one key set per
 * authentication -- valgrind reports the leak without the fix and is clean with it */
START_TEST(test_metadata_conf_parse_inline_keys_no_leak) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r,
						 "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
						 "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
						 "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
						 "\"kid\":\"ectest\"}]}",
						 &j),
			 TRUE);
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j, provider), TRUE);

	const apr_array_header_t *keys = oidc_cfg_provider_client_keys_get(provider);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(keys->nelts, 1);

	oidc_json_decref(j);
}
END_TEST

/* an inline .conf "signed_jwks_uri_key" is parsed into an owned key set that must be released with the
 * request pool (verified under valgrind), the same as the inline "keys" above */
START_TEST(test_metadata_conf_parse_signed_jwks_key_no_leak) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_json_t *j = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r,
						 "{\"signed_jwks_uri_key\":{\"kty\":\"EC\",\"crv\":\"P-256\","
						 "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
						 "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
						 "\"kid\":\"ec1\"}}",
						 &j),
			 TRUE);
	ck_assert_int_eq(oidc_metadata_conf_parse(r, c, j, provider), TRUE);

	const apr_array_header_t *keys = oidc_cfg_provider_signed_jwks_uri_keys_get(provider);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(keys->nelts, 1);

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

/*
 * RFC 8705 section 6.1: with a TLS client certificate configured for token binding only (i.e. not
 * for client authentication) against an OP that advertises support, the registration request asks
 * for certificate-bound access tokens
 */
START_TEST(test_metadata_disk_dyn_registration_cert_bound_tokens) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	const char *dir = e2e_make_metadata_dir(r);
	const char *srcdir = getenv("srcdir") ? getenv("srcdir") : ".";

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
						 "\"tls_client_certificate_bound_access_tokens\":true,"
						 "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}",
						 oidc_test_http_server_url(srv, r->pool));
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.provider", dir), provider_json);
	e2e_write_file(r, apr_psprintf(r->pool, "%s/idp.example.com.conf", dir), "{}");

	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_tls_client_cert_set(
	    r->pool, oidc_cfg_provider_get(c), apr_psprintf(r->pool, "%s/certificate.pem", srcdir)));

	oidc_provider_t *provider = NULL;
	ck_assert_int_eq(oidc_metadata_get(r, c, "https://idp.example.com", &provider, TRUE), TRUE);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_msg(_oidc_strstr(cap->body, "\"tls_client_certificate_bound_access_tokens\"") != NULL,
		      "missing tls_client_certificate_bound_access_tokens in: %s", cap->body);

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
	tcase_add_test(validate, test_metadata_is_valid_rejects_unsupported_capabilities);

	TCase *parse = tcase_create("parse");
	tcase_add_checked_fixture(parse, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(parse, test_metadata_parse_populates_empty_provider);
	tcase_add_test(parse, test_metadata_parse_preserves_existing_values);
	tcase_add_test(parse, test_metadata_parse_no_usable_token_endpoint_auth);
	tcase_add_test(parse, test_metadata_parse_mtls_endpoint_aliases);
	tcase_add_test(parse, test_metadata_parse_mtls_endpoint_aliases_invalid);
	tcase_add_test(parse, test_metadata_parse_cert_bound_tokens_advertised);
	tcase_add_test(parse, test_metadata_parse_cert_bound_tokens_not_advertised);
	tcase_add_test(parse, test_metadata_parse_cert_bound_tokens_off);
	tcase_add_test(parse, test_metadata_parse_cert_bound_tokens_on);
	tcase_add_test(parse, test_metadata_parse_mtls_explicit_endpoint_wins);
	tcase_add_test(parse, test_metadata_parse_mtls_aliases_private_key_jwt);
	tcase_add_test(parse, test_metadata_oauth_provider_parse);
	tcase_add_test(parse, test_metadata_oauth_provider_parse_mtls);

	TCase *retrieve = tcase_create("retrieve");
	tcase_add_checked_fixture(retrieve, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(retrieve, 30);
	tcase_add_test(retrieve, test_metadata_retrieve_success);
	tcase_add_test(retrieve, test_metadata_retrieve_http_failure);
	tcase_add_test(retrieve, test_metadata_retrieve_invalid_metadata);
	tcase_add_test(retrieve, test_metadata_jwks_get_forced_refresh);
	tcase_add_test(retrieve, test_metadata_jwks_get_forced_refresh_throttled);
	tcase_add_test(retrieve, test_metadata_jwks_get_forced_refresh_interval_envvar);
	tcase_add_test(retrieve, test_metadata_jwks_get_http_failure);
	tcase_add_test(retrieve, test_metadata_jwks_get_cache_hit);
	tcase_add_test(retrieve, test_metadata_jwks_get_missing_keys);
	tcase_add_test(retrieve, test_metadata_jwks_get_invalid_json);
	tcase_add_test(retrieve, test_metadata_jwks_get_signed_happy);
	tcase_add_test(retrieve, test_metadata_jwks_get_signed_bad_signature);
	tcase_add_test(retrieve, test_metadata_jwks_get_signed_not_a_jwt);
	tcase_add_test(retrieve, test_metadata_signed_jwks_uri_keys_global_fallback);

	TCase *conf = tcase_create("conf");
	tcase_add_checked_fixture(conf, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(conf, test_metadata_conf_parse_string_fields);
	tcase_add_test(conf, test_metadata_conf_parse_token_endpoint_auth_alg_inherited);
	tcase_add_test(conf, test_metadata_conf_parse_int_fields);
	tcase_add_test(conf, test_metadata_conf_parse_id_token_aud_values);
	tcase_add_test(conf, test_metadata_conf_parse_inline_keys_no_leak);
	tcase_add_test(conf, test_metadata_conf_parse_signed_jwks_key_no_leak);
	tcase_add_test(conf, test_metadata_conf_parse_dpop_and_auth_request_method);
	tcase_add_test(conf, test_metadata_conf_parse_userinfo_token_method);

	TCase *disk = tcase_create("disk");
	tcase_add_checked_fixture(disk, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(disk, test_metadata_disk_list_empty_dir);
	tcase_add_test(disk, test_metadata_disk_get_provider_only);
	tcase_add_test(disk, test_metadata_disk_list_skips_provider_without_client);
	tcase_add_test(disk, test_metadata_disk_get_full);
	tcase_add_test(disk, test_metadata_disk_dyn_registration_post_logout_redirect_uris);
	tcase_add_test(disk, test_metadata_client_parse_response_type_not_advertised);
	tcase_add_test(disk, test_metadata_client_parse_response_type_explicitly_set);
	tcase_add_test(disk, test_metadata_conf_then_client_response_type_fallback);
	tcase_add_test(disk, test_metadata_disk_client_secret_expired);
	tcase_add_test(disk, test_metadata_disk_client_secret_never_expires);
	tcase_add_test(disk, test_metadata_disk_provider_get_live_discovery);
	tcase_add_test(disk, test_metadata_disk_provider_get_schemeless_issuer);
	tcase_add_test(disk, test_metadata_disk_provider_refresh_within_interval_uses_cache);
	tcase_add_test(disk, test_metadata_disk_provider_refresh_falls_back_to_stale_cache);
	tcase_add_test(disk, test_metadata_disk_provider_refresh_replaces_stale_cache);
	tcase_add_test(disk, test_metadata_disk_get_with_empty_conf_file);
	tcase_add_test(disk, test_metadata_disk_get_with_invalid_conf_alg);
	tcase_add_test(disk, test_metadata_disk_dyn_registration_success);
	tcase_add_test(disk, test_metadata_disk_stale_client_reregistration);
	tcase_add_test(disk, test_metadata_disk_dyn_registration_payload_fields);
	tcase_add_test(disk, test_metadata_disk_dyn_registration_cert_bound_tokens);
	tcase_add_test(disk, test_metadata_disk_mtls_aliases_from_conf);
	tcase_add_test(disk, test_metadata_disk_mtls_aliases_from_conf_dpop);
	tcase_add_test(disk, test_metadata_disk_mtls_aliases_conf_off);
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
