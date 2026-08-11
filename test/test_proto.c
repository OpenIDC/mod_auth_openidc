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

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "cfg/cfg_int.h"
#include "check_util.h"
#include "handle/handle.h"
#include "http_server.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"
#include "util/util.h"
#include <jansson.h> /* this test builds JSON fixtures with the backend API directly (no longer pulled in via jose.h) */

START_TEST(test_proto_validate_access_token) {
	request_rec *r = oidc_test_request_get();

	// from http://openid.net/specs/openid-connect-core-1_0.html#id_token-tokenExample
	// A.3  Example using response_type=id_token token
	const char *s = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogIml"
			"zcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ"
			"4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiA"
			"ibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDE"
			"zMTEyODA5NzAsCiAiYXRfaGFzaCI6ICI3N1FtVVB0alBmeld0RjJBbnBLOVJ"
			"RIgp9.F9gRev0Dt2tKcrBkHy72cmRqnLdzw9FLCCSebV7mWs7o_sv2O5s6zM"
			"ky2kmhHTVx9HmdvNnx9GaZ8XMYRFeYk8L5NZ7aYlA5W56nsG1iWOou_-gji0"
			"ibWIuuf4Owaho3YSoi7EvsTuLFz6tq-dLyz0dKABMDsiCmJ5wqkPUDTE3QTX"
			"jzbUmOzUDli-gCh5QPuZAq0cNW3pf_2n4zpvTYtbmj12cVcxGIMZby7TMWES"
			"RjQ9_o3jvhVNcCGcE0KAQXejhA1ocJhNEvQNqMFGlBb6_0RxxKjDZ-Oa329e"
			"GDidOvvp0h5hoES4a8IuGKS7NOcpp-aFwp0qVMDLI-Xnm-Pg";

	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;
	ck_assert_jwt_parses(r->pool, s, jwt, NULL, err);

	const char *access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
	ck_assert_int_eq(oidc_proto_idtoken_validate_access_token(r, NULL, jwt, "id_token token", access_token), TRUE);

	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_validate_code) {
	request_rec *r = oidc_test_request_get();

	// from http://openid.net/specs/openid-connect-core-1_0.html#code-id_tokenExample
	// A.4 Example using response_type=code id_token
	const char *s = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogIml"
			"zcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ"
			"4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiA"
			"ibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDE"
			"zMTEyODA5NzAsCiAiY19oYXNoIjogIkxEa3RLZG9RYWszUGswY25YeENsdEE"
			"iCn0.XW6uhdrkBgcGx6zVIrCiROpWURs-4goO1sKA4m9jhJIImiGg5muPUcN"
			"egx6sSv43c5DSn37sxCRrDZZm4ZPBKKgtYASMcE20SDgvYJdJS0cyuFw7Ijp"
			"_7WnIjcrl6B5cmoM6ylCvsLMwkoQAxVublMwH10oAxjzD6NEFsu9nipkszWh"
			"sPePf_rM4eMpkmCbTzume-fzZIi5VjdWGGEmzTg32h3jiex-r5WTHbj-u5HL"
			"7u_KP3rmbdYNzlzd1xWRYTUs4E8nOTgzAUwvwXkIQhOh5TPcSMBYy6X3E7-_"
			"gr9Ue6n4ND7hTFhtjYs3cjNKIA08qm5cpVYFMFMG6PkhzLQ";

	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;
	ck_assert_jwt_parses(r->pool, s, jwt, NULL, err);

	const char *code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
	ck_assert_int_eq(oidc_proto_idtoken_validate_code(r, NULL, jwt, "code id_token", code), TRUE);

	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_authorization_request) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(r->pool, provider, "client_id");
	oidc_cfg_provider_auth_request_params_set(r->pool, provider, "jan=piet&foo=#");

	const char *redirect_uri = "https://www.example.com/protected/";
	const char *state = "12345";

	oidc_proto_state_t *proto_state = oidc_proto_state_new();
	oidc_proto_state_set_nonce(proto_state, "anonce");
	oidc_proto_state_set_original_url(proto_state, "https://localhost/protected/index.php");
	oidc_proto_state_set_original_method(proto_state, OIDC_METHOD_GET);
	oidc_proto_state_set_issuer(proto_state, oidc_cfg_provider_issuer_get(provider));
	oidc_proto_state_set_response_type(proto_state, oidc_cfg_provider_response_type_get(provider));
	oidc_proto_state_set_timestamp_now(proto_state);

	ck_assert_int_eq(
	    oidc_request_auth(r, c, provider, NULL, redirect_uri, state, proto_state, NULL, NULL, NULL, NULL),
	    HTTP_MOVED_TEMPORARILY);

	ck_assert_table_str(
	    r->headers_out, "Location",
	    "https://idp.example.com/"
	    "authorize?response_type=code&scope=openid&client_id=client_id&state=12345&redirect_uri=https%"
	    "3A%2F%2Fwww.example.com%2Fprotected%2F&nonce=anonce&jan=piet&foo=bar");
}
END_TEST

START_TEST(test_logout_request) {
	request_rec *r = oidc_test_request_get();

	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_session_t *session = NULL;

	oidc_session_load(r, &session);
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)));

	oidc_cfg_provider_end_session_endpoint_set(r->pool, oidc_cfg_provider_get(c),
						   "https://idp.example.com/endsession");
	oidc_cfg_provider_logout_request_params_set(r->pool, oidc_cfg_provider_get(c), "client_id=myclient&foo=bar");

	r->args = "logout=https%3A%2F%2Fwww.example.com%2Floggedout";

	ck_assert_int_eq(oidc_logout(r, c, session), HTTP_MOVED_TEMPORARILY);
	ck_assert_str_eq(
	    apr_table_get(r->headers_out, "Location"),
	    "https://idp.example.com/"
	    "endsession?post_logout_redirect_uri=https%3A%2F%2Fwww.example.com%2Floggedout&client_id=myclient&foo=bar");

	oidc_session_free(r, session);
}
END_TEST

START_TEST(test_proto_validate_nonce) {
	request_rec *r = oidc_test_request_get();

	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	const char *nonce = "avSk7S69G4kEE8Km4bPiOjrfChHt6nO4Z397Lp_bQnc,";

	/*
	 * {
	 *   "typ": "JWT",
	 *   "alg": "RS256",
	 *   "x5t": "Z1NCjojeiHAib-Gm8vFE6ya6lPM"
	 * }
	 * {
	 *   "nonce": "avSk7S69G4kEE8Km4bPiOjrfChHt6nO4Z397Lp_bQnc,",
	 *   "iat": 1411580876,
	 *   "at_hash": "yTqsoONZbuWbN6TbgevuDQ",
	 *   "sub": "6343a29c-5399-44a7-9b35-4990f4377c96",
	 *   "amr": "password",
	 *   "auth_time": 1411577267,
	 *   "idp": "idsrv",
	 *   "name": "ksonaty",
	 *   "iss": "https://agsync.com",
	 *   "aud": "agsync_implicit",
	 *   "exp": 1411584475,
	 *   "nbf": 1411580875
	 * }
	 */
	char *s_jwt = apr_pstrdup(
	    r->pool,
	    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9."
	    "eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYX"
	    "NoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6"
	    "InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly"
	    "9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE0MTE1ODA4NzV9.lEG-"
	    "DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk6"
	    "53bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-"
	    "mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_"
	    "kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEA");
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;
	ck_assert_jwt_parses(r->pool, s_jwt, jwt, NULL, err);

	ck_assert_int_eq(oidc_proto_idtoken_validate_nonce(r, c, oidc_cfg_provider_get(c), nonce, jwt), TRUE);
	ck_assert_int_eq(oidc_proto_idtoken_validate_nonce(r, c, oidc_cfg_provider_get(c), nonce, jwt), FALSE);
	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_validate_jwt) {
	request_rec *r = oidc_test_request_get();

	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;

	const char *s_secret = "mysecretwithmorethan32characters";
	const char *s_issuer = "https://localhost";
	apr_time_t now = apr_time_sec(apr_time_now());

	const char *s_jwt_header = "{"
				   "\"alg\": \"HS256\""
				   "}";

	const char *s_jwt_payload = "{"
				    "\"nonce\": \"543210,\","
				    "\"iat\": %" APR_TIME_T_FMT ","
				    "\"sub\": \"alice\","
				    "\"iss\": \"%s\","
				    "\"aud\": \"bob\","
				    "\"exp\": %" APR_TIME_T_FMT "}";
	s_jwt_payload = apr_psprintf(r->pool, s_jwt_payload, now, s_issuer, now + 600);

	char *s_jwt_header_encoded = NULL;
	oidc_util_base64url_encode(r, &s_jwt_header_encoded, s_jwt_header, (int)_oidc_strlen(s_jwt_header),
				   OIDC_BASE64URL_PADDING_STRIP);

	char *s_jwt_payload_encoded = NULL;
	oidc_util_base64url_encode(r, &s_jwt_payload_encoded, s_jwt_payload, (int)_oidc_strlen(s_jwt_payload),
				   OIDC_BASE64URL_PADDING_STRIP);

	char *s_jwt_message = apr_psprintf(r->pool, "%s.%s", s_jwt_header_encoded, s_jwt_payload_encoded);

	unsigned int md_len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD *digest = EVP_get_digestbyname("sha256");

	ck_assert_ptr_nonnull(HMAC(digest, (const unsigned char *)s_secret, (int)_oidc_strlen(s_secret),
				   (const unsigned char *)s_jwt_message, _oidc_strlen(s_jwt_message), md, &md_len));

	char *s_jwt_signature_encoded = NULL;
	oidc_util_base64url_encode(r, &s_jwt_signature_encoded, (const char *)md, md_len, OIDC_BASE64URL_PADDING_STRIP);

	char *s_jwt =
	    apr_psprintf(r->pool, "%s.%s.%s", s_jwt_header_encoded, s_jwt_payload_encoded, s_jwt_signature_encoded);

	ck_assert_jwt_parses(r->pool, s_jwt, jwt, NULL, err);

	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, s_secret, 0, NULL, TRUE, &jwk), TRUE);
	ck_assert_ptr_nonnull(jwk);

	ck_assert_int_eq(oidc_jwt_verify(r->pool, jwt, oidc_util_key_symmetric_merge(r->pool, NULL, jwk), &err), TRUE);

	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, s_issuer, TRUE, TRUE, 10), TRUE);

	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_nonce_and_jti) {
	request_rec *r = oidc_test_request_get();
	char *nonce = NULL;
	ck_assert_int_eq(oidc_proto_nonce_gen(r, &nonce), TRUE);
	ck_assert_ptr_nonnull(nonce);

	char *jti = oidc_proto_jti_gen(r);
	ck_assert_ptr_nonnull(jti);
	/* jti should be a non-empty string */
	ck_assert_int_ne(_oidc_strlen(jti), 0);
}
END_TEST

START_TEST(test_proto_supported_flows_and_check) {
	apr_pool_t *pool = oidc_test_pool_get();
	apr_array_header_t *flows = oidc_proto_supported_flows(pool);
	ck_assert_ptr_nonnull(flows);
	ck_assert_int_eq(flows->nelts, 6);

	/* known supported flows */
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, "code"), TRUE);
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, "id_token token"), TRUE);
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, "unrecognized flow"), FALSE);
}
END_TEST

START_TEST(test_proto_state_getters_setters_and_string) {
	request_rec *r = oidc_test_request_get();
	oidc_proto_state_t *ps = oidc_proto_state_new();
	ck_assert_ptr_nonnull(ps);

	oidc_proto_state_set_issuer(ps, "https://example.org");
	oidc_proto_state_set_nonce(ps, "mynonce");
	oidc_proto_state_set_original_url(ps, "https://example.org/orig");
	oidc_proto_state_set_original_method(ps, "POST");
	oidc_proto_state_set_response_mode(ps, "fragment");
	oidc_proto_state_set_response_type(ps, "id_token token");
	oidc_proto_state_set_state(ps, "12345");
	oidc_proto_state_set_prompt(ps, "none");
	oidc_proto_state_set_pkce_state(ps, "pkce123");
	oidc_proto_state_set_auth_request_params(ps, "prompt=consent&foo=bar");
	oidc_proto_state_set_path_scope(ps, "openid profile email");
	oidc_proto_state_set_timestamp_now(ps);

	ck_assert_str_eq(oidc_proto_state_get_issuer(ps), "https://example.org");
	ck_assert_str_eq(oidc_proto_state_get_nonce(ps), "mynonce");
	ck_assert_str_eq(oidc_proto_state_get_original_url(ps), "https://example.org/orig");
	ck_assert_str_eq(oidc_proto_state_get_original_method(ps), "POST");
	ck_assert_str_eq(oidc_proto_state_get_response_mode(ps), "fragment");
	ck_assert_str_eq(oidc_proto_state_get_response_type(ps), "id_token token");
	ck_assert_str_eq(oidc_proto_state_get_state(ps), "12345");
	ck_assert_str_eq(oidc_proto_state_get_prompt(ps), "none");
	ck_assert_str_eq(oidc_proto_state_get_pkce_state(ps), "pkce123");
	ck_assert_str_eq(oidc_proto_state_get_auth_request_params(ps), "prompt=consent&foo=bar");
	ck_assert_str_eq(oidc_proto_state_get_path_scope(ps), "openid profile email");
	ck_assert(oidc_proto_state_get_timestamp(ps) > 0);

	char *s = oidc_proto_state_to_string(r, ps);
	ck_assert_ptr_nonnull(s);
	/* basic sanity: string contains the (non-secret) issuer */
	ck_assert_ptr_nonnull(_oidc_strstr(s, "https://example.org"));
	/* the nonce and PKCE code_verifier are security-sensitive and must be redacted */
	ck_assert_ptr_null(_oidc_strstr(s, "mynonce"));
	ck_assert_ptr_null(_oidc_strstr(s, "pkce123"));

	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_state_cookie_roundtrip) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "rndnonce");
	oidc_proto_state_set_state(ps, "s1");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_timestamp_now(ps);

	char *cookie = oidc_proto_state_to_cookie(r, c, ps);
	ck_assert_ptr_nonnull(cookie);

	oidc_proto_state_t *parsed = oidc_proto_state_from_cookie(r, c, cookie);
	ck_assert_ptr_nonnull(parsed);
	ck_assert_str_eq(oidc_proto_state_get_nonce(parsed), "rndnonce");
	ck_assert_str_eq(oidc_proto_state_get_state(parsed), "s1");
	ck_assert_str_eq(oidc_proto_state_get_issuer(parsed), "https://idp.example.com");

	oidc_proto_state_destroy(ps);
	oidc_proto_state_destroy(parsed);
}
END_TEST

START_TEST(test_proto_pkce_plain_and_s256) {
	request_rec *r = oidc_test_request_get();
	char *state_plain = NULL;
	char *challenge_plain = NULL;
	char *verifier_plain = NULL;

	/* plain */
	ck_assert_int_eq(oidc_pkce_plain.state(r, &state_plain), TRUE);
	ck_assert_ptr_nonnull(state_plain);
	ck_assert_int_eq(oidc_pkce_plain.challenge(r, state_plain, &challenge_plain), TRUE);
	ck_assert_ptr_nonnull(challenge_plain);
	ck_assert_str_eq(challenge_plain, state_plain);
	ck_assert_int_eq(oidc_pkce_plain.verifier(r, state_plain, &verifier_plain), TRUE);
	ck_assert_ptr_nonnull(verifier_plain);
	ck_assert_str_eq(verifier_plain, state_plain);

	/* s256 */
	char *state_s256 = NULL;
	char *challenge_s256 = NULL;
	char *verifier_s256 = NULL;
	ck_assert_int_eq(oidc_pkce_s256.state(r, &state_s256), TRUE);
	ck_assert_ptr_nonnull(state_s256);
	ck_assert_int_eq(oidc_pkce_s256.challenge(r, state_s256, &challenge_s256), TRUE);
	ck_assert_ptr_nonnull(challenge_s256);
	ck_assert_int_ne(_oidc_strlen(challenge_s256), 0);
	/* s256 challenge should not equal raw state */
	ck_assert_int_ne(_oidc_strcmp(challenge_s256, state_s256), 0);
	ck_assert_int_eq(oidc_pkce_s256.verifier(r, state_s256, &verifier_s256), TRUE);
	ck_assert_ptr_nonnull(verifier_s256);
	ck_assert_str_eq(verifier_s256, state_s256);
}
END_TEST

START_TEST(test_proto_profile_helpers) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(pool);

	/* default profile: token_endpoint_auth_aud returns token endpoint */
	oidc_cfg_provider_token_endpoint_url_set(pool, provider, "https://idp.example.com/token");
	ck_assert_str_eq(oidc_proto_profile_token_endpoint_auth_aud(provider), "https://idp.example.com/token");

	/* revocation: when val=="token" should return token endpoint */
	oidc_cfg_provider_revocation_endpoint_url_set(pool, provider, "https://idp.example.com/rev");
	ck_assert_str_eq(oidc_proto_profile_revocation_endpoint_auth_aud(provider, "token"),
			 "https://idp.example.com/token");

	/* the post-PAR redirect carries scope=openid */
	ck_assert_str_eq(oidc_proto_profile_request_uri_scope_get(provider), OIDC_PROTO_SCOPE_OPENID);

	/* certificate-bound access tokens are inferred from a certificate as configured, i.e. "auto" */
	ck_assert_int_eq(oidc_proto_profile_cert_bound_tokens_get(provider), OIDC_CERT_BOUND_TOKENS_AUTO);

	/* if profile is FAPI20 behavior changes */
	/* set profile to FAPI20 */
	oidc_cfg_provider_profile_int_set(provider, OIDC_PROFILE_FAPI20);
	/* token endpoint aud should now be issuer */
	oidc_cfg_provider_issuer_set(pool, provider, "https://idp.example.com");
	ck_assert_str_eq(oidc_proto_profile_token_endpoint_auth_aud(provider), "https://idp.example.com");
	/* pkce should be forced to S256 */
	ck_assert_ptr_eq(oidc_proto_profile_pkce_get(provider), &oidc_pkce_s256);
	/* DPoP should be required */
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_REQUIRED);
	/* a configured TLS client certificate is taken to be there for RFC 8705 token binding */
	ck_assert_int_eq(oidc_proto_profile_cert_bound_tokens_get(provider), OIDC_CERT_BOUND_TOKENS_ON);
	/* response require iss should be true */
	ck_assert_int_eq(oidc_proto_profile_response_require_iss_get(provider), 1);
	/* the post-PAR redirect must carry client_id and request_uri only */
	ck_assert_ptr_null(oidc_proto_profile_request_uri_scope_get(provider));

	/* FAPI 2.0 section 5.3.2.1: access tokens are sender-constrained through *either* mutual-TLS or
	 * DPoP, so with the access tokens certificate-bound (as resolved into the provider struct by
	 * oidc_metadata_provider_parse) against an OP that does not support DPoP, DPoP is no longer
	 * mandated and the configured mode applies */
	oidc_cfg_provider_cert_bound_tokens_int_set(provider, OIDC_CERT_BOUND_TOKENS_ON);
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_OFF);
	ck_assert_ptr_null(oidc_cfg_provider_dpop_mode_set(pool, provider, "required"));
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_REQUIRED);
	oidc_cfg_provider_dpop_mode_int_set(provider, OIDC_DPOP_MODE_OFF);

	/* ... but an OP that does advertise DPoP support is taken to sender-constrain with it, even
	 * when it also binds to the certificate: no silent downgrade of an OP that can do both */
	oidc_cfg_provider_dpop_supported_int_set(provider, TRUE);
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_REQUIRED);

	/* without certificate binding DPoP remains mandatory, whatever is configured */
	oidc_cfg_provider_dpop_supported_int_set(provider, FALSE);
	oidc_cfg_provider_cert_bound_tokens_int_set(provider, OIDC_CERT_BOUND_TOKENS_OFF);
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_REQUIRED);

	/* a fully statically configured OP never goes through oidc_metadata_provider_parse, so
	 * cert_bound_tokens is still "auto" here: a configured certificate then decides it, the same way
	 * oidc_profile_fapi20_cert_bound_tokens would have */
	oidc_cfg_provider_cert_bound_tokens_int_set(provider, OIDC_CERT_BOUND_TOKENS_AUTO);
	/* ... with no certificate configured, DPoP stays mandatory */
	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider));
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_REQUIRED);
	/* ... and with one, it is not */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_tls_client_cert_set(
	    pool, provider, apr_psprintf(pool, "%s/certificate.pem", dir)));
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_OFF);
	/* ... unless the OP advertises DPoP support after all */
	oidc_cfg_provider_dpop_supported_int_set(provider, TRUE);
	ck_assert_int_eq(oidc_proto_profile_dpop_mode_get(provider), OIDC_DPOP_MODE_REQUIRED);
}
END_TEST

START_TEST(test_proto_profile_auth_request_method) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(pool);

	/* default profile: the configured method is returned */
	ck_assert_int_eq(oidc_proto_profile_auth_request_method_get(provider), OIDC_AUTH_REQUEST_METHOD_GET);

	/* FAPI20 forces PAR regardless of configuration */
	oidc_cfg_provider_profile_int_set(provider, OIDC_PROFILE_FAPI20);
	ck_assert_int_eq(oidc_proto_profile_auth_request_method_get(provider), OIDC_AUTH_REQUEST_METHOD_PAR);
}
END_TEST

START_TEST(test_proto_profile_id_token_aud_values) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(pool);

	/* default profile, no explicit configuration: returns NULL */
	ck_assert_ptr_null(oidc_proto_profile_id_token_aud_values_get(pool, provider));

	/* FAPI20 with no explicit list: returns a list seeded with the client_id */
	oidc_cfg_provider_client_id_set(pool, provider, "my-client");
	oidc_cfg_provider_profile_int_set(provider, OIDC_PROFILE_FAPI20);
	const apr_array_header_t *arr = oidc_proto_profile_id_token_aud_values_get(pool, provider);
	ck_assert_ptr_nonnull(arr);
	ck_assert_int_eq(arr->nelts, 1);
	ck_assert_str_eq(APR_ARRAY_IDX(arr, 0, const char *), "my-client");

	/* an explicitly configured list takes precedence */
	oidc_cfg_provider_id_token_aud_values_set(pool, provider, "extra-aud");
	arr = oidc_proto_profile_id_token_aud_values_get(pool, provider);
	ck_assert_ptr_nonnull(arr);
	ck_assert_int_eq(arr->nelts, 1);
	ck_assert_str_eq(APR_ARRAY_IDX(arr, 0, const char *), "extra-aud");
}
END_TEST

START_TEST(test_proto_profile_revocation_aud_variants) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(pool);

	oidc_cfg_provider_token_endpoint_url_set(pool, provider, "https://idp.example.com/token");
	oidc_cfg_provider_revocation_endpoint_url_set(pool, provider, "https://idp.example.com/rev");

	/* default: revocation endpoint */
	ck_assert_str_eq(oidc_proto_profile_revocation_endpoint_auth_aud(provider, NULL),
			 "https://idp.example.com/rev");

	/* explicit URL takes precedence */
	ck_assert_str_eq(oidc_proto_profile_revocation_endpoint_auth_aud(provider, "https://override.example.com"),
			 "https://override.example.com");

	/* "token" sentinel resolves to the token endpoint */
	ck_assert_str_eq(oidc_proto_profile_revocation_endpoint_auth_aud(provider, "token"),
			 "https://idp.example.com/token");

	/* FAPI20: issuer wins regardless of val */
	oidc_cfg_provider_issuer_set(pool, provider, "https://idp.example.com");
	oidc_cfg_provider_profile_int_set(provider, OIDC_PROFILE_FAPI20);
	ck_assert_str_eq(oidc_proto_profile_revocation_endpoint_auth_aud(provider, NULL), "https://idp.example.com");
	ck_assert_str_eq(oidc_proto_profile_revocation_endpoint_auth_aud(provider, "token"), "https://idp.example.com");
}
END_TEST

START_TEST(test_proto_pkce_none) {
	ck_assert_str_eq(oidc_pkce_none.method, OIDC_PKCE_METHOD_NONE);
	/* by definition there are no callbacks for the "none" method */
	ck_assert_ptr_null(oidc_pkce_none.state);
	ck_assert_ptr_null(oidc_pkce_none.verifier);
	ck_assert_ptr_null(oidc_pkce_none.challenge);
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_no_client_id) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_t *params = apr_table_make(r->pool, 1);
	char *basic = NULL;
	char *bearer = NULL;

	/* no client_id => no auth needed, return TRUE without touching params/strings */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_CLIENT_SECRET_BASIC, NULL, NULL, "secret",
							NULL, NULL, params, NULL, &basic, &bearer),
			 TRUE);
	ck_assert_ptr_null(basic);
	ck_assert_ptr_null(bearer);
	ck_assert_int_eq(apr_table_elts(params)->nelts, 0);
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_basic_and_post) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_t *params = NULL;
	char *basic = NULL;
	char *bearer = NULL;

	/* client_secret_basic: returns "user:pass" in basic_auth_str */
	params = apr_table_make(r->pool, 1);
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_CLIENT_SECRET_BASIC, NULL, "myclient",
							"mysecret", NULL, NULL, params, NULL, &basic, &bearer),
			 TRUE);
	ck_assert_ptr_nonnull(basic);
	ck_assert_str_eq(basic, "myclient:mysecret");
	ck_assert_ptr_null(bearer);

	/* client_secret_basic without a secret: must fail */
	basic = NULL;
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_CLIENT_SECRET_BASIC, NULL, "myclient", NULL,
							NULL, NULL, params, NULL, &basic, &bearer),
			 TRUE); /* falls through to "public client" path: no secret + not private_key_jwt */
	ck_assert_ptr_null(basic);
	/* the "public client" path sets client_id on the params */
	ck_assert_table_str(params, OIDC_PROTO_CLIENT_ID, "myclient");

	/* client_secret_post: sets client_id and client_secret on the params */
	params = apr_table_make(r->pool, 2);
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_CLIENT_SECRET_POST, NULL, "myclient",
							"mysecret", NULL, NULL, params, NULL, &basic, &bearer),
			 TRUE);
	ck_assert_table_str(params, OIDC_PROTO_CLIENT_ID, "myclient");
	ck_assert_table_str(params, OIDC_PROTO_CLIENT_SECRET, "mysecret");

	/* none: only client_id is set */
	params = apr_table_make(r->pool, 1);
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_ENDPOINT_AUTH_NONE, NULL, "myclient",
							"ignored", NULL, NULL, params, NULL, &basic, &bearer),
			 TRUE);
	ck_assert_table_str(params, OIDC_PROTO_CLIENT_ID, "myclient");
	ck_assert_table_unset(params, OIDC_PROTO_CLIENT_SECRET);
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_bearer) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_t *params = apr_table_make(r->pool, 1);
	char *basic = NULL;
	char *bearer = NULL;

	/* bearer_access_token without a token: must fail */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_BEARER_ACCESS_TOKEN, NULL, "myclient",
							"secret", NULL, NULL, params, NULL, &basic, &bearer),
			 FALSE);
	ck_assert_ptr_null(bearer);

	/* bearer_access_token with a token: must succeed */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_BEARER_ACCESS_TOKEN, NULL, "myclient",
							"secret", NULL, NULL, params, "the-token", &basic, &bearer),
			 TRUE);
	ck_assert_ptr_nonnull(bearer);
	ck_assert_str_eq(bearer, "the-token");
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_mtls) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_t *params = NULL;
	char *basic = NULL;
	char *bearer = NULL;

	/* RFC 8705: authentication occurs at the TLS layer: only the client_id goes into the body */
	params = apr_table_make(r->pool, 1);
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, "tls_client_auth", NULL, "myclient", NULL, NULL, NULL,
							params, NULL, &basic, &bearer),
			 TRUE);
	ck_assert_table_str(params, OIDC_PROTO_CLIENT_ID, "myclient");
	ck_assert_table_unset(params, OIDC_PROTO_CLIENT_SECRET);
	ck_assert_ptr_null(basic);
	ck_assert_ptr_null(bearer);

	/* a configured client_secret must not leak into the request */
	params = apr_table_make(r->pool, 1);
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, "self_signed_tls_client_auth", NULL, "myclient",
							"mysecret", NULL, NULL, params, NULL, &basic, &bearer),
			 TRUE);
	ck_assert_table_str(params, OIDC_PROTO_CLIENT_ID, "myclient");
	ck_assert_table_unset(params, OIDC_PROTO_CLIENT_SECRET);
	ck_assert_ptr_null(basic);
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_unknown_method) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_t *params = apr_table_make(r->pool, 1);
	char *basic = NULL;
	char *bearer = NULL;

	/* unknown method must hit the fall-through error path and return FALSE */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, "totally_bogus_method", NULL, "myclient", "secret", NULL,
							NULL, params, NULL, &basic, &bearer),
			 FALSE);
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_client_secret_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_t *params = apr_table_make(r->pool, 2);
	char *basic = NULL;
	char *bearer = NULL;

	/* client_secret_jwt: HMAC-SHA256 over a JWT signed with the client_secret;
	 * the result is added to params as client_assertion + client_assertion_type */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_CLIENT_SECRET_JWT, NULL, "myclient",
							"mysecretmysecretmysecretmysecret", NULL,
							"https://idp.example.com/token", params, NULL, &basic, &bearer),
			 TRUE);
	const char *assertion_type = apr_table_get(params, OIDC_PROTO_CLIENT_ASSERTION_TYPE);
	ck_assert_ptr_nonnull(assertion_type);
	ck_assert_str_eq(assertion_type, OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER);
	const char *assertion = apr_table_get(params, OIDC_PROTO_CLIENT_ASSERTION);
	ck_assert_ptr_nonnull(assertion);
	/* compact JWS format: <hdr>.<payload>.<sig> */
	const char *dot1 = _oidc_strstr(assertion, ".");
	ck_assert_ptr_nonnull(dot1);
	const char *dot2 = _oidc_strstr(dot1 + 1, ".");
	ck_assert_ptr_nonnull(dot2);
	ck_assert_msg(_oidc_strstr(dot2 + 1, ".") == NULL, "compact JWS must have exactly two dots");
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_private_key_jwt_no_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_t *params = apr_table_make(r->pool, 1);
	char *basic = NULL;
	char *bearer = NULL;

	/* private_key_jwt without any configured private keys must fail; passing
	 * client_secret=NULL also exercises the "no secret + private_key_jwt"
	 * branch that bypasses the public-client short-circuit */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_PRIVATE_KEY_JWT, NULL, "myclient", NULL, NULL,
							"https://idp.example.com/token", params, NULL, &basic, &bearer),
			 FALSE);
	ck_assert_table_unset(params, OIDC_PROTO_CLIENT_ASSERTION);
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_private_key_jwt_with_rsa_key) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	/* load test/private.pem so cfg->private_keys has an RSA key with kid "rsa-1" */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *err = oidc_cmd_private_keys_set(
	    cmd, NULL, apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir)));
	ck_assert_msg(err == NULL, "could not load private key: %s", err);

	apr_table_t *params = apr_table_make(r->pool, 2);
	char *basic = NULL;
	char *bearer = NULL;

	/* private_key_jwt with no explicit algorithm: default for RSA is RS256;
	 * the JWT must land in the params as client_assertion + assertion_type */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, cfg, OIDC_PROTO_PRIVATE_KEY_JWT, NULL, "myclient", NULL,
							NULL, "https://idp.example.com/token", params, NULL, &basic,
							&bearer),
			 TRUE);
	const char *assertion = apr_table_get(params, OIDC_PROTO_CLIENT_ASSERTION);
	ck_assert_ptr_nonnull(assertion);
	ck_assert_table_str(params, OIDC_PROTO_CLIENT_ASSERTION_TYPE, OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER);

	/* confirm alg=RS256 + kid=rsa-1 by parsing the header (oidc_proto_jwt_header_peek)
	 * rather than substring-matching the serialized JSON, whose whitespace varies by cjose version */
	char *alg = NULL, *kid = NULL;
	ck_assert_ptr_nonnull(oidc_proto_jwt_header_peek(r, assertion, &alg, NULL, &kid));
	ck_assert_str_eq(alg, "RS256");
	ck_assert_str_eq(kid, "rsa-1");
}
END_TEST

START_TEST(test_proto_token_endpoint_auth_private_key_jwt_explicit_alg) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	/* load private.pem as above */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *err = oidc_cmd_private_keys_set(
	    cmd, NULL, apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir)));
	ck_assert_msg(err == NULL, "could not load private key: %s", err);

	apr_table_t *params = apr_table_make(r->pool, 2);
	char *basic = NULL;
	char *bearer = NULL;

	/* explicit token_endpoint_auth_alg=RS384 must override the key-derived default */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, cfg, OIDC_PROTO_PRIVATE_KEY_JWT, "RS384", "myclient", NULL,
							NULL, "https://idp.example.com/token", params, NULL, &basic,
							&bearer),
			 TRUE);
	const char *assertion = apr_table_get(params, OIDC_PROTO_CLIENT_ASSERTION);
	ck_assert_ptr_nonnull(assertion);
	char *alg = NULL;
	ck_assert_ptr_nonnull(oidc_proto_jwt_header_peek(r, assertion, &alg, NULL, NULL));
	ck_assert_str_eq(alg, "RS384");
}
END_TEST

/* a per-client signing key (client_keys) takes precedence over the module-wide configured
 * private keys (oidc_proto_endpoint_auth_pick_signing_key's client_keys != empty branch) */
START_TEST(test_proto_token_endpoint_auth_private_key_jwt_client_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	char *priv_path = apr_psprintf(r->pool, "%s/private.pem", dir);
	ck_assert_msg(oidc_jwk_parse_pem_private_key(r->pool, "client-1", priv_path, &jwk, &err) == TRUE,
		      "parse private pem failed");

	apr_array_header_t *client_keys = apr_array_make(r->pool, 1, sizeof(oidc_jwk_t *));
	APR_ARRAY_PUSH(client_keys, oidc_jwk_t *) = jwk;

	apr_table_t *params = apr_table_make(r->pool, 2);
	char *basic = NULL;
	char *bearer = NULL;

	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, cfg, OIDC_PROTO_PRIVATE_KEY_JWT, NULL, "myclient", NULL,
							client_keys, "https://idp.example.com/token", params, NULL,
							&basic, &bearer),
			 TRUE);
	const char *assertion = apr_table_get(params, OIDC_PROTO_CLIENT_ASSERTION);
	ck_assert_ptr_nonnull(assertion);
	char *kid = NULL;
	ck_assert_ptr_nonnull(oidc_proto_jwt_header_peek(r, assertion, NULL, NULL, &kid));
	ck_assert_str_eq(kid, "client-1");

	oidc_jwk_destroy(jwk);
}
END_TEST

/* an empty (but non-NULL) client_secret bypasses the dispatcher's "no secret configured" short
 * circuit yet still cannot be turned into an HMAC key: cjose_jwk_create_oct_spec rejects the
 * zero-length key, so oidc_proto_endpoint_auth_client_secret_jwt's jwk-creation-failed branch fires */
START_TEST(test_proto_token_endpoint_auth_client_secret_jwt_empty_secret) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	apr_table_t *params = apr_table_make(r->pool, 2);
	char *basic = NULL;
	char *bearer = NULL;

	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_CLIENT_SECRET_JWT, NULL, "myclient", "", NULL,
							"https://idp.example.com/token", params, NULL, &basic, &bearer),
			 FALSE);
	ck_assert_table_unset(params, OIDC_PROTO_CLIENT_ASSERTION);
}
END_TEST

/* a client_keys entry that isn't RSA/EC (e.g. an OCT key, which oidc_util_key_list_first still
 * matches since it has no "use" set) is picked, but oidc_jwk_default_jws_alg has no default alg
 * for it, so private_key_jwt without an explicit token_endpoint_auth_alg must fail */
START_TEST(test_proto_token_endpoint_auth_private_key_jwt_unsupported_key_type) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();
	oidc_jose_error_t err;

	unsigned char key[16];
	for (int i = 0; i < 16; i++)
		key[i] = (unsigned char)(i + 1);
	oidc_jwk_t *sym = oidc_jwk_create_symmetric_key(r->pool, "sym-1", key, 16, TRUE, &err);
	ck_assert_ptr_nonnull(sym);

	apr_array_header_t *client_keys = apr_array_make(r->pool, 1, sizeof(oidc_jwk_t *));
	APR_ARRAY_PUSH(client_keys, oidc_jwk_t *) = sym;

	apr_table_t *params = apr_table_make(r->pool, 1);
	char *basic = NULL;
	char *bearer = NULL;

	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, cfg, OIDC_PROTO_PRIVATE_KEY_JWT, NULL, "myclient", NULL,
							client_keys, "https://idp.example.com/token", params, NULL,
							&basic, &bearer),
			 FALSE);
	ck_assert_table_unset(params, OIDC_PROTO_CLIENT_ASSERTION);

	oidc_jwk_destroy(sym);
}
END_TEST

/* number of entries in a table for a given key, i.e. including duplicates that apr_table_get hides */
static int e2e_table_count(const apr_table_t *table, const char *key) {
	const apr_array_header_t *arr = apr_table_elts(table);
	const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;
	int n = 0;
	for (int i = 0; i < arr->nelts; i++)
		if (_oidc_strnatcasecmp(elts[i].key, key) == 0)
			n++;
	return n;
}

/* extract the jti claim from the payload of a compact-serialized JWT */
static const char *e2e_jwt_jti(request_rec *r, const char *s_jwt) {
	const char *dot1 = _oidc_strstr(s_jwt, ".");
	ck_assert_ptr_nonnull(dot1);
	const char *dot2 = _oidc_strstr(dot1 + 1, ".");
	ck_assert_ptr_nonnull(dot2);
	char *s_payload = NULL;
	ck_assert_int_gt(
	    oidc_util_base64url_decode(r->pool, &s_payload, apr_pstrmemdup(r->pool, dot1 + 1, dot2 - (dot1 + 1))), 0);
	oidc_json_t *payload = json_loads(s_payload, 0, NULL);
	ck_assert_ptr_nonnull(payload);
	char *jti = NULL;
	oidc_json_object_get_string(r->pool, payload, OIDC_CLAIM_JTI, &jti, NULL);
	oidc_json_decref(payload);
	ck_assert_ptr_nonnull(jti);
	return jti;
}

/* calling oidc_proto_token_endpoint_auth again on the same params table must replace the credentials
 * it added before (never add a 2nd copy) and mint a fresh assertion: this is what allows a retry
 * (the DPoP nonce retry in oidc_proto_token_endpoint_request) to re-authenticate with a new jti */
START_TEST(test_proto_token_endpoint_auth_idempotent) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *err = oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir));
	ck_assert_msg(err == NULL, "could not load private key: %s", err);

	apr_table_t *params = apr_table_make(r->pool, 2);
	char *basic = NULL;
	char *bearer = NULL;

	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, cfg, OIDC_PROTO_PRIVATE_KEY_JWT, NULL, "myclient", NULL,
							NULL, "https://idp.example.com/token", params, NULL, &basic,
							&bearer),
			 TRUE);
	const char *assertion1 = apr_pstrdup(r->pool, apr_table_get(params, OIDC_PROTO_CLIENT_ASSERTION));
	ck_assert_ptr_nonnull(assertion1);

	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, cfg, OIDC_PROTO_PRIVATE_KEY_JWT, NULL, "myclient", NULL,
							NULL, "https://idp.example.com/token", params, NULL, &basic,
							&bearer),
			 TRUE);
	const char *assertion2 = apr_table_get(params, OIDC_PROTO_CLIENT_ASSERTION);
	ck_assert_ptr_nonnull(assertion2);

	/* exactly one of each, so the form body cannot carry two assertions */
	ck_assert_int_eq(e2e_table_count(params, OIDC_PROTO_CLIENT_ASSERTION), 1);
	ck_assert_int_eq(e2e_table_count(params, OIDC_PROTO_CLIENT_ASSERTION_TYPE), 1);
	ck_assert_table_str(params, OIDC_PROTO_CLIENT_ASSERTION_TYPE, OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER);

	/* and the replacement is a new assertion with a freshly generated jti */
	ck_assert_str_ne(assertion1, assertion2);
	ck_assert_str_ne(e2e_jwt_jti(r, assertion1), e2e_jwt_jti(r, assertion2));

	/* the same must hold for the client_secret_post credentials */
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, cfg, OIDC_PROTO_CLIENT_SECRET_POST, NULL, "myclient",
							"mysecret", NULL, "https://idp.example.com/token", params, NULL,
							&basic, &bearer),
			 TRUE);
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, cfg, OIDC_PROTO_CLIENT_SECRET_POST, NULL, "myclient",
							"mysecret", NULL, "https://idp.example.com/token", params, NULL,
							&basic, &bearer),
			 TRUE);
	ck_assert_int_eq(e2e_table_count(params, OIDC_PROTO_CLIENT_ID), 1);
	ck_assert_int_eq(e2e_table_count(params, OIDC_PROTO_CLIENT_SECRET), 1);
}
END_TEST

START_TEST(test_proto_jwt_validate_edge_cases) {
	request_rec *r = oidc_test_request_get();
	apr_pool_t *pool = r->pool;
	apr_time_t now = apr_time_sec(apr_time_now());
	oidc_jwt_t *jwt = NULL;

	/* missing iss with required iss must fail */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = NULL;
	jwt->payload.iat = now;
	jwt->payload.exp = now + 60;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://expected.example.com", TRUE, TRUE, 10), FALSE);
	oidc_jwt_destroy(jwt);

	/* iss mismatch must fail */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = apr_pstrdup(pool, "https://other.example.com");
	jwt->payload.iat = now;
	jwt->payload.exp = now + 60;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://expected.example.com", TRUE, TRUE, 10), FALSE);
	oidc_jwt_destroy(jwt);

	/* iss==NULL on input means no issuer check; a valid window passes */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = apr_pstrdup(pool, "https://any.example.com");
	jwt->payload.iat = now;
	jwt->payload.exp = now + 60;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, NULL, TRUE, TRUE, 10), TRUE);
	oidc_jwt_destroy(jwt);

	/* expired JWT must fail */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = apr_pstrdup(pool, "https://idp.example.com");
	jwt->payload.iat = now - 7200;
	jwt->payload.exp = now - 3600;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://idp.example.com", TRUE, TRUE, 10), FALSE);
	oidc_jwt_destroy(jwt);

	/* missing exp with exp mandatory must fail */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = apr_pstrdup(pool, "https://idp.example.com");
	jwt->payload.iat = now;
	jwt->payload.exp = OIDC_JWT_CLAIM_TIME_EMPTY;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://idp.example.com", TRUE, TRUE, 10), FALSE);
	/* same JWT, but with exp not mandatory: passes */
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://idp.example.com", FALSE, TRUE, 10), TRUE);
	oidc_jwt_destroy(jwt);

	/* iat in the far future must fail */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = apr_pstrdup(pool, "https://idp.example.com");
	jwt->payload.iat = now + 3600;
	jwt->payload.exp = now + 7200;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://idp.example.com", TRUE, TRUE, 10), FALSE);
	oidc_jwt_destroy(jwt);

	/* missing iat with iat mandatory must fail */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = apr_pstrdup(pool, "https://idp.example.com");
	jwt->payload.iat = OIDC_JWT_CLAIM_TIME_EMPTY;
	jwt->payload.exp = now + 60;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://idp.example.com", TRUE, TRUE, 10), FALSE);
	/* iat not mandatory: passes */
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://idp.example.com", TRUE, FALSE, 10), TRUE);
	oidc_jwt_destroy(jwt);

	/* negative slack disables the iat window check */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = apr_pstrdup(pool, "https://idp.example.com");
	jwt->payload.iat = now - 1000000;
	jwt->payload.exp = now + 60;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://idp.example.com", TRUE, TRUE, -1), TRUE);
	oidc_jwt_destroy(jwt);

	/* iat older than the slack window (with a still-valid exp) must fail */
	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->payload.iss = apr_pstrdup(pool, "https://idp.example.com");
	jwt->payload.iat = now - 7200;
	jwt->payload.exp = now + 3600;
	ck_assert_int_eq(oidc_proto_jwt_validate(r, jwt, "https://idp.example.com", TRUE, TRUE, 10), FALSE);
	oidc_jwt_destroy(jwt);
}
END_TEST

/* build an HS256-signed id_token for the fixture provider (issuer https://idp.example.com,
 * client_id "client_id"); sub and nonce may be NULL to omit those claims for the error paths */
static char *proto_sign_idtoken_hs256(request_rec *r, const char *sub, const char *nonce, const char *secret) {
	apr_pool_t *pool = r->pool;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk), TRUE);
	ck_assert_ptr_nonnull(jwk);

	oidc_jwt_t *jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(pool, "HS256");
	apr_time_t now = apr_time_sec(apr_time_now());
	oidc_json_object_set_new(jwt->payload.value.json, "iss", oidc_json_string("https://idp.example.com"));
	oidc_json_object_set_new(jwt->payload.value.json, "aud", oidc_json_string("client_id"));
	if (sub != NULL)
		oidc_json_object_set_new(jwt->payload.value.json, "sub", oidc_json_string(sub));
	if (nonce != NULL)
		oidc_json_object_set_new(jwt->payload.value.json, "nonce", oidc_json_string(nonce));
	oidc_json_object_set_new(jwt->payload.value.json, "iat", oidc_json_integer(now));
	oidc_json_object_set_new(jwt->payload.value.json, "exp", oidc_json_integer(now + 600));
	jwt->payload.iss = apr_pstrdup(pool, "https://idp.example.com");
	jwt->payload.iat = now;
	jwt->payload.exp = now + 600;

	ck_assert_int_eq(oidc_jwt_sign(pool, jwt, jwk, FALSE, &err), TRUE);
	char *cser = oidc_jose_jwt_serialize(pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
	return cser;
}

/* build an unsigned (alg=none) id_token for the fixture provider; there is no signing step,
 * oidc_jose_jwt_serialize emits the "<hdr>.<payload>." compact form for alg "none" itself */
static char *proto_unsigned_idtoken(request_rec *r, const char *sub, const char *nonce) {
	apr_pool_t *pool = r->pool;
	oidc_jose_error_t err;

	oidc_jwt_t *jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(pool, "none");
	apr_time_t now = apr_time_sec(apr_time_now());
	oidc_json_object_set_new(jwt->payload.value.json, "iss", oidc_json_string("https://idp.example.com"));
	oidc_json_object_set_new(jwt->payload.value.json, "aud", oidc_json_string("client_id"));
	if (sub != NULL)
		oidc_json_object_set_new(jwt->payload.value.json, "sub", oidc_json_string(sub));
	if (nonce != NULL)
		oidc_json_object_set_new(jwt->payload.value.json, "nonce", oidc_json_string(nonce));
	oidc_json_object_set_new(jwt->payload.value.json, "iat", oidc_json_integer(now));
	oidc_json_object_set_new(jwt->payload.value.json, "exp", oidc_json_integer(now + 600));

	char *cser = oidc_jose_jwt_serialize(pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);
	oidc_jwt_destroy(jwt);
	return cser;
}

START_TEST(test_proto_idtoken_parse_alg_none) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_jwt_t *jwt = NULL;
	char *s = NULL;

	oidc_cfg_provider_client_secret_set(r->pool, provider, "idtoken-none-secret-long-enough-1");

	/* an unsigned id_token received over the back-channel ('code' flow) is accepted when no signing
	 * algorithm has been pinned: OpenID Connect Core 1.0 section 3.1.3.7 item 6 lets the TLS server
	 * validation stand in for the signature check */
	s = proto_unsigned_idtoken(r, "alice", NULL);
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, NULL, &jwt, TRUE), TRUE);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_str_eq(jwt->payload.sub, "alice");
	oidc_jwt_destroy(jwt);
	jwt = NULL;

	/* ... and equally when the operator (or the OP's client registration) has pinned "none", which
	 * states that this OP issues unsigned id_tokens rather than demanding a signature */
	ck_assert_ptr_null(oidc_cfg_provider_id_token_signed_response_alg_set(r->pool, provider, "none"));
	s = proto_unsigned_idtoken(r, "alice", NULL);
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, NULL, &jwt, TRUE), TRUE);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_str_eq(jwt->payload.sub, "alice");
	oidc_jwt_destroy(jwt);
	jwt = NULL;

	/* a pinned algorithm other than "none" overrides the exception: the unsigned token is rejected */
	ck_assert_ptr_null(oidc_cfg_provider_id_token_signed_response_alg_set(r->pool, provider, "RS256"));
	s = proto_unsigned_idtoken(r, "alice", NULL);
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, NULL, &jwt, TRUE), FALSE);
	ck_assert_ptr_null(jwt);

	/* the exception is back-channel only: an unsigned id_token delivered through the front channel
	 * (implicit/hybrid) is rejected even with "none" pinned */
	ck_assert_ptr_null(oidc_cfg_provider_id_token_signed_response_alg_set(r->pool, provider, "none"));
	s = proto_unsigned_idtoken(r, "alice", NULL);
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, NULL, &jwt, FALSE), FALSE);
	ck_assert_ptr_null(jwt);
}
END_TEST

START_TEST(test_proto_idtoken_parse_error_paths) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_jwt_t *jwt = NULL;
	const char *secret = "idtoken-parse-secret-long-enough-1";

	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	/* garbage compact serialization fails the JWT parse */
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, "aaa.bbb.ccc", NULL, &jwt, TRUE), FALSE);
	ck_assert_ptr_null(jwt);

	/* a token signed with a different secret fails signature validation */
	char *s = proto_sign_idtoken_hs256(r, "alice", NULL, "not-the-configured-secret-xxxxxx");
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, NULL, &jwt, TRUE), FALSE);
	ck_assert_ptr_null(jwt);

	/* correctly signed but missing the required-by-spec "sub" claim */
	s = proto_sign_idtoken_hs256(r, NULL, NULL, secret);
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, NULL, &jwt, TRUE), FALSE);
	ck_assert_ptr_null(jwt);

	/* the nonce in the token does not match the one from the browser state */
	s = proto_sign_idtoken_hs256(r, "alice", "other-nonce", secret);
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, "expected-nonce", &jwt, TRUE), FALSE);
	ck_assert_ptr_null(jwt);

	/* no nonce claim at all while one is expected */
	s = proto_sign_idtoken_hs256(r, "alice", NULL, secret);
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, "expected-nonce-2", &jwt, TRUE), FALSE);
	ck_assert_ptr_null(jwt);

	/* a fully valid token parses and validates */
	s = proto_sign_idtoken_hs256(r, "alice", "good-nonce", secret);
	ck_assert_int_eq(oidc_proto_idtoken_parse(r, c, provider, s, "good-nonce", &jwt, TRUE), TRUE);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_str_eq(jwt->payload.sub, "alice");
	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_jwt_verify_paths) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;
	oidc_jwks_uri_t jwks_uri;
	_oidc_memset(&jwks_uri, 0, sizeof(jwks_uri));

	/* an explicitly configured algorithm must match the JWT header algorithm */
	jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	ck_assert_int_eq(oidc_proto_jwt_verify(r, c, jwt, &jwks_uri, 1, NULL, "RS256"), FALSE);

	/* without a configured algorithm an unset/none JWT algorithm is refused outright */
	jwt->header.alg = NULL;
	ck_assert_int_eq(oidc_proto_jwt_verify(r, c, jwt, &jwks_uri, 1, NULL, NULL), FALSE);
	oidc_jwt_destroy(jwt);

	/* a JWKs URI that cannot be retrieved fails the verification of an asymmetric signature */
	jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "RS256");
	jwks_uri.uri = "http://127.0.0.1:1/jwks";
	ck_assert_int_eq(oidc_proto_jwt_verify(r, c, jwt, &jwks_uri, 1, NULL, NULL), FALSE);
	oidc_jwt_destroy(jwt);

	/* verify a real HS256 signature against the merged symmetric key, without any JWKs URI
	 * (static keys only) and with a JWKs URI set (skipped for a symmetric signature) */
	const char *secret = "jwt-verify-secret-long-enough-123";
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk), TRUE);
	char *s = proto_sign_idtoken_hs256(r, "alice", NULL, secret);
	ck_assert_jwt_parses(r->pool, s, jwt, NULL, err);
	_oidc_memset(&jwks_uri, 0, sizeof(jwks_uri));
	ck_assert_int_eq(
	    oidc_proto_jwt_verify(r, c, jwt, &jwks_uri, 1, oidc_util_key_symmetric_merge(r->pool, NULL, jwk), NULL),
	    TRUE);
	jwks_uri.uri = "https://idp.example.com/jwks";
	ck_assert_int_eq(
	    oidc_proto_jwt_verify(r, c, jwt, &jwks_uri, 1, oidc_util_key_symmetric_merge(r->pool, NULL, jwk), NULL),
	    TRUE);
	oidc_jwt_destroy(jwt);
	oidc_jwk_destroy(jwk);

	/* the first-segment of the compact serialization must be valid base64url */
	ck_assert_ptr_null(oidc_proto_jwt_header_peek(r, "!!!.x.y", NULL, NULL, NULL));

	/* signing with a key that does not match the algorithm fails sign-and-serialize */
	jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "RS256");
	jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk), TRUE);
	char *cser = NULL;
	ck_assert_int_eq(oidc_proto_jwt_sign_and_serialize(r, jwk, jwt, &cser), FALSE);
	oidc_jwt_destroy(jwt);
	oidc_jwk_destroy(jwk);
}
END_TEST

START_TEST(test_proto_validate_hash_error_paths) {
	request_rec *r = oidc_test_request_get();
	oidc_jwt_t *jwt = NULL;

	/* an at_hash that does not match the access token hash must fail; "YWJjZA" decodes
	 * to 4 bytes which cannot equal the SHA-256 half-length of 16 */
	jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "RS256");
	oidc_json_object_set_new(jwt->payload.value.json, "at_hash", oidc_json_string("YWJjZA"));
	ck_assert_int_eq(oidc_proto_idtoken_validate_access_token(r, NULL, jwt, "id_token token", "an-access-token"),
			 FALSE);
	oidc_jwt_destroy(jwt);

	/* an at_hash that is not valid base64url must fail */
	jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "RS256");
	oidc_json_object_set_new(jwt->payload.value.json, "at_hash", oidc_json_string("!!!"));
	ck_assert_int_eq(oidc_proto_idtoken_validate_access_token(r, NULL, jwt, "id_token token", "an-access-token"),
			 FALSE);
	oidc_jwt_destroy(jwt);

	/* a hash-string failure surfaces when the JWT algorithm is unknown */
	jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "XX999");
	oidc_json_object_set_new(jwt->payload.value.json, "at_hash", oidc_json_string("YWJjZA"));
	ck_assert_int_eq(oidc_proto_idtoken_validate_access_token(r, NULL, jwt, "id_token token", "an-access-token"),
			 FALSE);
	oidc_jwt_destroy(jwt);

	/* a missing at_hash fails for flows that require it but passes for the code flow */
	jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "RS256");
	ck_assert_int_eq(oidc_proto_idtoken_validate_access_token(r, NULL, jwt, "id_token token", "an-access-token"),
			 FALSE);
	ck_assert_int_eq(oidc_proto_idtoken_validate_access_token(r, NULL, jwt, "code", "an-access-token"), TRUE);

	/* a missing c_hash fails for flows that require it */
	ck_assert_int_eq(oidc_proto_idtoken_validate_code(r, NULL, jwt, "code id_token", "a-code"), FALSE);
	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_state_timestamp_and_bad_cookie) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_proto_state_t *ps = NULL;

	/* timestamp unset => returns -1 */
	ps = oidc_proto_state_new();
	ck_assert_ptr_nonnull(ps);
	ck_assert_msg(oidc_proto_state_get_timestamp(ps) == -1, "timestamp must be -1 when not set");
	oidc_proto_state_destroy(ps);

	/* NULL cookie value must not crash and must return NULL */
	ck_assert_ptr_null(oidc_proto_state_from_cookie(r, c, NULL));

	/* garbage cookie value must return NULL */
	ck_assert_ptr_null(oidc_proto_state_from_cookie(r, c, "not-a-jwt-cookie-value"));
}
END_TEST

START_TEST(test_proto_nonce_uniqueness) {
	request_rec *r = oidc_test_request_get();
	char *n1 = NULL, *n2 = NULL;

	ck_assert_int_eq(oidc_proto_nonce_gen(r, &n1), TRUE);
	ck_assert_int_eq(oidc_proto_nonce_gen(r, &n2), TRUE);
	ck_assert_ptr_nonnull(n1);
	ck_assert_ptr_nonnull(n2);
	/* two consecutive nonces should differ (probabilistic but for 32 bytes of randomness essentially certain) */
	ck_assert_int_ne(_oidc_strcmp(n1, n2), 0);
}
END_TEST

START_TEST(test_proto_flow_unsupported) {
	apr_pool_t *pool = oidc_test_pool_get();

	/* empty string must not match */
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, ""), FALSE);
	/* unknown flow */
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, "implicit"), FALSE);
	/* partial token by itself is not a supported flow on its own */
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, "token"), FALSE);
	/* spaced_string_equals ignores order, so "token id_token" should match "id_token token" */
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, "token id_token"), TRUE);
}
END_TEST

START_TEST(test_proto_dpop_create_without_private_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	char *dpop = NULL;

	/* the test fixture configures an empty private_keys array, so DPoP proof creation must fail */
	ck_assert_int_eq(
	    oidc_proto_dpop_create(r, c, "https://idp.example.com/token", "POST", "some-access-token", NULL, &dpop),
	    FALSE);
	ck_assert_ptr_null(dpop);
}
END_TEST

START_TEST(test_proto_dpop_create_embeds_public_key_only) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	char *dpop = NULL;

	/* load test/private.pem so DPoP proof creation has an RSA key to sign with */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *kerr = oidc_cmd_private_keys_set(
	    cmd, NULL, apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir)));
	ck_assert_msg(kerr == NULL, "could not load private key: %s", kerr);

	ck_assert_int_eq(
	    oidc_proto_dpop_create(r, c, "https://idp.example.com/token", "POST", "some-access-token", NULL, &dpop),
	    TRUE);
	ck_assert_ptr_nonnull(dpop);

	/* decode and JSON-parse the protected header (first compact segment) instead of substring-matching the
	 * serialized JSON, whose whitespace varies by cjose version */
	const char *p = _oidc_strstr(dpop, ".");
	ck_assert_ptr_nonnull((void *)p);
	char *header_b64 = apr_pstrmemdup(r->pool, dpop, _oidc_strlen(dpop) - _oidc_strlen(p));
	char *header_json = NULL;
	ck_assert_int_gt(oidc_util_base64url_decode(r->pool, &header_json, header_b64), 0);
	oidc_json_t *header = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, header_json, &header), TRUE);

	/* the DPoP confirmation header must embed the PUBLIC key only: public params present, private absent */
	oidc_json_t *jwk = oidc_json_object_get(header, OIDC_CLAIM_JWK);
	ck_assert_ptr_nonnull(jwk);
	ck_assert_ptr_nonnull(oidc_json_object_get(jwk, "n")); /* RSA public modulus */
	ck_assert_ptr_nonnull(oidc_json_object_get(jwk, "e")); /* RSA public exponent */
	ck_assert_ptr_null(oidc_json_object_get(jwk, "d"));    /* RSA private exponent must NOT be present */
	ck_assert_ptr_null(oidc_json_object_get(jwk, "p"));
	ck_assert_ptr_null(oidc_json_object_get(jwk, "q"));

	oidc_json_decref(header);
}
END_TEST

START_TEST(test_proto_jwt_header_peek) {
	request_rec *r = oidc_test_request_get();
	char *alg = NULL;
	char *enc = NULL;
	char *kid = NULL;
	char *hdr = NULL;

	/* a minimal valid JWT-shaped string: only the first segment is decoded */
	/* header: {"alg":"RS256","kid":"1e9gdk7"} */
	const char *jwt = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.payload.sig";
	hdr = oidc_proto_jwt_header_peek(r, jwt, &alg, &enc, &kid);
	ck_assert_ptr_nonnull(hdr);
	ck_assert_ptr_nonnull(alg);
	ck_assert_str_eq(alg, "RS256");
	ck_assert_ptr_nonnull(kid);
	ck_assert_str_eq(kid, "1e9gdk7");
	/* enc was not present in the header */
	ck_assert_msg(enc == NULL || enc[0] == '\0', "enc should be empty/absent");

	/* NULL input must be tolerated (treated as empty) and return NULL */
	alg = NULL;
	hdr = oidc_proto_jwt_header_peek(r, NULL, &alg, NULL, NULL);
	ck_assert_ptr_null(hdr);

	/* no separator: returns NULL */
	hdr = oidc_proto_jwt_header_peek(r, "not.a.jwt-but-has-dots", &alg, NULL, NULL);
	/* "not.a.jwt-but-has-dots" has dots, but only the first segment is the part before the first dot;
	 * "not" is not a valid base64url-decoded JSON object so alg should not be populated */
	if (hdr != NULL) {
		/* tolerate result depending on base64url-decoding behavior, but alg must not be RS256 here */
		ck_assert_msg(alg == NULL || _oidc_strcmp(alg, "RS256") != 0,
			      "alg must not be RS256 for non-JWT input");
	}

	/* no '.' at all returns NULL */
	hdr = oidc_proto_jwt_header_peek(r, "no-dot-here", NULL, NULL, NULL);
	ck_assert_ptr_null(hdr);
}
END_TEST

START_TEST(test_proto_response_is_post_and_redirect) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	r->method_number = M_POST;
	ck_assert_msg(oidc_proto_response_is_post(r, c) == TRUE, "POST method must be detected");
	ck_assert_msg(oidc_proto_response_is_redirect(r, c) == FALSE,
		      "POST method must not be classified as a redirect response");

	r->method_number = M_GET;
	r->args = "state=abc&foo=bar";
	ck_assert_msg(oidc_proto_response_is_redirect(r, c) == FALSE,
		      "GET without id_token or code must not be a redirect response");
	ck_assert_msg(oidc_proto_response_is_post(r, c) == FALSE, "GET method must not be detected as POST");

	r->args = "code=abc123&state=xyz";
	ck_assert_msg(oidc_proto_response_is_redirect(r, c) == TRUE,
		      "GET with code parameter must be classified as a redirect response");

	r->args = "id_token=eyJ.x.y&state=xyz";
	ck_assert_msg(oidc_proto_response_is_redirect(r, c) == TRUE,
		      "GET with id_token parameter must be classified as a redirect response");
}
END_TEST

START_TEST(test_proto_return_www_authenticate_header) {
	request_rec *r = oidc_test_request_get();
	/* ensure no auth_name in stub (stub returns NULL) */
	int rc = oidc_proto_return_www_authenticate(r, "invalid_token", "bad token");
	ck_assert_int_eq(rc, HTTP_UNAUTHORIZED);
	const char *hdr = apr_table_get(r->err_headers_out, "WWW-Authenticate");
	ck_assert_ptr_nonnull(hdr);
	ck_assert_ptr_nonnull(_oidc_strstr(hdr, "invalid_token"));
	ck_assert_ptr_nonnull(_oidc_strstr(hdr, "bad token"));
}
END_TEST

/*
 * Helper for building a synthetic id_token payload with a given JSON body.
 * Returns a stack-init oidc_jwt_payload_t whose .value.json points to `claims`.
 * Caller owns `claims` (typically `oidc_json_decref` after the test).
 */
static oidc_jwt_payload_t make_payload(oidc_json_t *claims) {
	oidc_jwt_payload_t p = {0};
	p.value.json = claims;
	return p;
}

START_TEST(test_proto_idtoken_validate_aud_string_match) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *claims = json_pack("{s:s}", "aud", "client_id");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), TRUE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_string_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *claims = json_pack("{s:s}", "aud", "different_client");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_array_with_client_id) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* azp is present here so the multi-aud SHOULD warning doesn't fire as a hard error */
	oidc_json_t *claims = json_pack("{s:[s,s],s:s}", "aud", "other-rp", "client_id", "azp", "client_id");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), TRUE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_array_without_client_id) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *claims = json_pack("{s:[s,s]}", "aud", "other-rp", "yet-another");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_missing) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *claims = json_pack("{s:s}", "sub", "alice");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_wrong_type) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *claims = json_pack("{s:i}", "aud", 42);
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	oidc_json_decref(claims);
}
END_TEST

/* configure an explicit OIDCProviderIDTokenAudValues list on the provider; the
 * special "@" value must resolve to the configured client_id */
static void set_provider_aud_values(request_rec *r, oidc_provider_t *provider, const char *v1, const char *v2) {
	apr_array_header_t *list = NULL;
	ck_assert_ptr_null(oidc_cfg_string_list_add(r->pool, &list, v1));
	if (v2 != NULL)
		ck_assert_ptr_null(oidc_cfg_string_list_add(r->pool, &list, v2));
	ck_assert_ptr_null(oidc_cfg_provider_id_token_aud_values_set_str_list(r->pool, provider, list));
}

START_TEST(test_proto_idtoken_validate_aud_values_string_special_at) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	set_provider_aud_values(r, oidc_cfg_provider_get(c), "@", "https://api.example.com");
	/* a single-valued aud matching the client_id via the "@" special value */
	oidc_json_t *claims = json_pack("{s:s}", "aud", "client_id");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), TRUE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_values_string_no_match) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	set_provider_aud_values(r, oidc_cfg_provider_get(c), "@", "https://api.example.com");
	oidc_json_t *claims = json_pack("{s:s}", "aud", "https://untrusted.example.com");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_values_array_exhaustive_match) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	set_provider_aud_values(r, oidc_cfg_provider_get(c), "@", "https://api.example.com");
	/* every configured value present in the aud array and no extra values */
	oidc_json_t *claims =
	    json_pack("{s:[s,s],s:s}", "aud", "client_id", "https://api.example.com", "azp", "client_id");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), TRUE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_values_array_missing_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	set_provider_aud_values(r, oidc_cfg_provider_get(c), "@", "https://api.example.com");
	/* the configured https://api.example.com value is not present in the aud array */
	oidc_json_t *claims = json_pack("{s:[s],s:s}", "aud", "client_id", "azp", "client_id");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_values_array_untrusted_extra) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	set_provider_aud_values(r, oidc_cfg_provider_get(c), "@", NULL);
	/* all configured values are present but the aud array carries an unknown extra value */
	oidc_json_t *claims =
	    json_pack("{s:[s,s],s:s}", "aud", "client_id", "https://evil.example.com", "azp", "client_id");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_azp_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* aud is valid (matches client_id), but azp claims a different party */
	oidc_json_t *claims = json_pack("{s:s,s:s}", "aud", "client_id", "azp", "evil-rp");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	oidc_json_decref(claims);
}
END_TEST

START_TEST(test_proto_dpop_use_nonce_no_error_claim) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *result = json_pack("{s:s}", "active", "true");
	char *dpop = NULL;
	ck_assert_int_eq(oidc_proto_dpop_use_nonce(r, c, result, NULL, "https://idp.example.com/token", "POST",
						   "access-token", &dpop),
			 FALSE);
	ck_assert_ptr_null(dpop);
	oidc_json_decref(result);
}
END_TEST

START_TEST(test_proto_dpop_use_nonce_wrong_error_value) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *result = json_pack("{s:s}", "error", "invalid_request");
	char *dpop = NULL;
	ck_assert_int_eq(oidc_proto_dpop_use_nonce(r, c, result, NULL, "https://idp.example.com/token", "POST",
						   "access-token", &dpop),
			 FALSE);
	ck_assert_ptr_null(dpop);
	oidc_json_decref(result);
}
END_TEST

START_TEST(test_proto_dpop_use_nonce_missing_header) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_json_t *result = json_pack("{s:s}", "error", "use_dpop_nonce");
	apr_hash_t *hdrs = apr_hash_make(r->pool); /* no DPoP-Nonce entry */
	char *dpop = NULL;
	ck_assert_int_eq(oidc_proto_dpop_use_nonce(r, c, result, hdrs, "https://idp.example.com/token", "POST",
						   "access-token", &dpop),
			 FALSE);
	ck_assert_ptr_null(dpop);
	oidc_json_decref(result);
}
END_TEST

START_TEST(test_proto_discovery_account_no_at_sign) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	char *issuer = NULL;
	/* missing '@' is rejected before any HTTP call */
	ck_assert_int_eq(oidc_proto_discovery_account_based(r, c, "not-an-account", &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

START_TEST(test_proto_discovery_account_unreachable_endpoint) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* drive the account → webfinger path against a known-closed loopback port:
	 * exercises the "@" split, resource/domain assembly and the HTTP-failure
	 * return path in oidc_proto_webfinger_discovery without a live server. */
	int port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(port, 0);
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *issuer = NULL;
	const char *acct = apr_psprintf(r->pool, "alice@127.0.0.1:%d", port);
	ck_assert_int_eq(oidc_proto_discovery_account_based(r, c, acct, &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

/* internal helper exposed by src/proto/discovery.c for unit-testing the webfinger response parser */
extern apr_byte_t oidc_proto_webfinger_response_get_issuer(request_rec *r, const char *response, char **issuer);

START_TEST(test_proto_webfinger_response_get_issuer_happy) {
	request_rec *r = oidc_test_request_get();
	const char *resp = "{\"links\":[{\"href\":\"https://idp.example.com\"}]}";
	char *issuer = NULL;
	ck_assert_int_eq(oidc_proto_webfinger_response_get_issuer(r, resp, &issuer), TRUE);
	ck_assert_str_eq(issuer, "https://idp.example.com");
}
END_TEST

START_TEST(test_proto_webfinger_response_get_issuer_invalid_json) {
	request_rec *r = oidc_test_request_get();
	char *issuer = NULL;
	ck_assert_int_eq(oidc_proto_webfinger_response_get_issuer(r, "not json", &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

START_TEST(test_proto_webfinger_response_get_issuer_missing_links) {
	request_rec *r = oidc_test_request_get();
	char *issuer = NULL;
	ck_assert_int_eq(oidc_proto_webfinger_response_get_issuer(r, "{\"foo\":1}", &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

START_TEST(test_proto_webfinger_response_get_issuer_links_not_array) {
	request_rec *r = oidc_test_request_get();
	char *issuer = NULL;
	ck_assert_int_eq(oidc_proto_webfinger_response_get_issuer(r, "{\"links\":\"oops\"}", &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

START_TEST(test_proto_webfinger_response_get_issuer_first_link_not_object) {
	request_rec *r = oidc_test_request_get();
	char *issuer = NULL;
	ck_assert_int_eq(oidc_proto_webfinger_response_get_issuer(r, "{\"links\":[\"oops\"]}", &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

START_TEST(test_proto_webfinger_response_get_issuer_missing_href) {
	request_rec *r = oidc_test_request_get();
	char *issuer = NULL;
	ck_assert_int_eq(oidc_proto_webfinger_response_get_issuer(r, "{\"links\":[{\"rel\":\"x\"}]}", &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

START_TEST(test_proto_webfinger_response_get_issuer_href_not_https) {
	request_rec *r = oidc_test_request_get();
	const char *resp = "{\"links\":[{\"href\":\"http://idp.example.com\"}]}";
	char *issuer = NULL;
	ck_assert_int_eq(oidc_proto_webfinger_response_get_issuer(r, resp, &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

START_TEST(test_proto_discovery_url_unreachable_endpoint) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* same idea against a URL input — exercises apr_uri_parse, the host+port
	 * stitching in oidc_proto_discovery_url_based and the HTTP-failure return
	 * in the shared webfinger helper. */
	int port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(port, 0);
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *issuer = NULL;
	const char *url = apr_psprintf(r->pool, "https://127.0.0.1:%d/alice", port);
	ck_assert_int_eq(oidc_proto_discovery_url_based(r, c, url, &issuer), FALSE);
	ck_assert_ptr_null(issuer);
}
END_TEST

/*
 * End-to-end tests that drive token.c / userinfo.c / request.c against the
 * loopback HTTP server fixture from test/http_server.c. They exercise the
 * curl handoff plus the JSON-response parsing path in each module.
 */

START_TEST(test_proto_token_endpoint_request_success) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 200,
	    .content_type = "application/json",
	    .body = "{\"access_token\":\"AT-1\",\"token_type\":\"Bearer\",\"expires_in\":3600,"
		    "\"refresh_token\":\"RT-1\",\"scope\":\"openid profile\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-code");
	apr_table_setn(params, OIDC_PROTO_REDIRECT_URI, "https://rp.example.com/cb");

	char *id_token = NULL, *access_token = NULL, *token_type = NULL, *refresh_token = NULL, *scope = NULL;
	int expires_in = -1;
	ck_assert_int_eq(oidc_proto_token_endpoint_request(r, c, provider, params, &id_token, &access_token,
							   &token_type, &expires_in, &refresh_token, &scope),
			 TRUE);
	ck_assert_str_eq(access_token, "AT-1");
	ck_assert_str_eq(token_type, "Bearer");
	ck_assert_int_eq(expires_in, 3600);
	ck_assert_str_eq(refresh_token, "RT-1");
	ck_assert_str_eq(scope, "openid profile");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_msg(_oidc_strstr(cap->body, "grant_type=authorization_code") != NULL, "grant_type sent in form body");
	ck_assert_msg(_oidc_strstr(cap->body, "code=the-code") != NULL, "code sent in form body");

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_token_endpoint_request_error) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {.status_code = 400,
					  .content_type = "application/json",
					  .body =
					      "{\"error\":\"invalid_grant\",\"error_description\":\"code expired\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	apr_table_t *params = apr_table_make(r->pool, 1);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE);

	char *id_token = NULL, *access_token = NULL, *token_type = NULL, *refresh_token = NULL, *scope = NULL;
	int expires_in = -1;
	ck_assert_int_eq(oidc_proto_token_endpoint_request(r, c, provider, params, &id_token, &access_token,
							   &token_type, &expires_in, &refresh_token, &scope),
			 FALSE);
	ck_assert_ptr_null(access_token);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_token_refresh_request_success) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 200,
	    .content_type = "application/json",
	    .body = "{\"access_token\":\"AT-NEW\",\"token_type\":\"Bearer\",\"refresh_token\":\"RT-NEW\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_cfg_provider_scope_set(r->pool, provider, "openid");

	char *id_token = NULL, *access_token = NULL, *token_type = NULL, *refresh_token = NULL, *scope = NULL;
	int expires_in = -1;
	ck_assert_int_eq(oidc_proto_token_refresh_request(r, c, provider, "OLD-RT", &id_token, &access_token,
							  &token_type, &expires_in, &refresh_token, &scope),
			 TRUE);
	ck_assert_str_eq(access_token, "AT-NEW");
	ck_assert_str_eq(refresh_token, "RT-NEW");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_msg(_oidc_strstr(cap->body, "grant_type=refresh_token") != NULL,
		      "refresh grant_type sent in form body");
	ck_assert_msg(_oidc_strstr(cap->body, "refresh_token=OLD-RT") != NULL, "old refresh_token sent in form body");

	oidc_test_http_server_stop(srv);
}
END_TEST

/* an unsupported token_type combined with a configured userinfo endpoint makes
 * the token-endpoint response parser drop the access token (not a hard error) */
START_TEST(test_proto_token_endpoint_request_unsupported_token_type) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"access_token\":\"AT-MAC\",\"token_type\":\"mac\","
						  "\"id_token\":\"dummy\",\"expires_in\":3600}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, "https://idp.example.com/userinfo");
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-code");

	char *id_token = NULL, *access_token = NULL, *token_type = NULL, *refresh_token = NULL, *scope = NULL;
	int expires_in = -1;
	ck_assert_int_eq(oidc_proto_token_endpoint_request(r, c, provider, params, &id_token, &access_token,
							   &token_type, &expires_in, &refresh_token, &scope),
			 TRUE);
	ck_assert_ptr_null(access_token);
	ck_assert_ptr_null(token_type);
	ck_assert_ptr_nonnull(id_token);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* OIDCDPoPMode required: a Bearer token-endpoint response must be rejected */
START_TEST(test_proto_token_endpoint_request_dpop_required_but_bearer) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"access_token\":\"AT-1\",\"token_type\":\"Bearer\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	ck_assert_ptr_null(oidc_cfg_provider_dpop_mode_set(r->pool, provider, "required"));
	/* a private key so the DPoP proof for the token request can be created
	 * and the request actually reaches the (Bearer-answering) endpoint */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(
	    oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-dpop-tk#%s/private.pem", dir)));

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-code");

	char *id_token = NULL, *access_token = NULL, *token_type = NULL, *refresh_token = NULL, *scope = NULL;
	int expires_in = -1;
	ck_assert_int_eq(oidc_proto_token_endpoint_request(r, c, provider, params, &id_token, &access_token,
							   &token_type, &expires_in, &refresh_token, &scope),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* OIDCDPoPMode required: a token-endpoint response that omits token_type entirely must be
 * rejected too, and without handing a NULL token_type to the error log's "%s" */
START_TEST(test_proto_token_endpoint_request_dpop_required_but_missing_token_type) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"access_token\":\"AT-1\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	ck_assert_ptr_null(oidc_cfg_provider_dpop_mode_set(r->pool, provider, "required"));
	/* a private key so the DPoP proof for the token request can be created
	 * and the request actually reaches the (token_type-less-answering) endpoint */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(
	    oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-dpop-tk#%s/private.pem", dir)));

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-code");

	char *id_token = NULL, *access_token = NULL, *token_type = NULL, *refresh_token = NULL, *scope = NULL;
	int expires_in = -1;
	ck_assert_int_eq(oidc_proto_token_endpoint_request(r, c, provider, params, &id_token, &access_token,
							   &token_type, &expires_in, &refresh_token, &scope),
			 FALSE);
	ck_assert_ptr_null(token_type);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* the value of a single x-www-form-urlencoded parameter in a captured request body,
 * plus the number of times that parameter occurs in it */
static const char *e2e_form_param(apr_pool_t *pool, const char *body, const char *name, int *count) {
	const char *value = NULL;
	const char *needle = apr_psprintf(pool, "%s=", name);
	const char *p = body;
	*count = 0;
	while ((p != NULL) && (p = _oidc_strstr(p, needle)) != NULL) {
		/* only match at the start of the body or right after a parameter separator */
		if ((p == body) || (*(p - 1) == OIDC_CHAR_AMP)) {
			(*count)++;
			p += _oidc_strlen(needle);
			const char *amp = _oidc_strstr(p, "&");
			if (value == NULL)
				value = (amp != NULL) ? apr_pstrmemdup(pool, p, amp - p) : apr_pstrdup(pool, p);
		} else {
			p += _oidc_strlen(needle);
		}
	}
	return value;
}

/* a "use_dpop_nonce" error must be retried with a nonce-bound DPoP proof *and* with freshly minted
 * client authentication: reusing the client_assertion of the failed attempt replays its one-time jti */
START_TEST(test_proto_token_endpoint_request_dpop_nonce_retry_new_assertion) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	apr_table_t *extra = apr_table_make(r->pool, 1);
	apr_table_set(extra, OIDC_HTTP_HDR_DPOP_NONCE, "nonce-abc");
	oidc_test_http_response_t resp[2] = {
	    {.status_code = 400,
	     .content_type = "application/json",
	     .body = "{\"error\":\"use_dpop_nonce\"}",
	     .extra_headers = extra},
	    {.status_code = 200,
	     .content_type = "application/json",
	     .body = "{\"access_token\":\"AT-2\",\"token_type\":\"DPoP\",\"expires_in\":3600}"}};
	oidc_test_http_server_t *srv = oidc_test_http_server_start_seq(r->pool, resp, 2);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	ck_assert_ptr_null(oidc_cfg_provider_dpop_mode_set(r->pool, provider, "required"));

	/* a private key for both the DPoP proof and the private_key_jwt client assertion */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir)));
	oidc_cfg_provider_client_id_set(r->pool, provider, "myclient");
	ck_assert_ptr_null(oidc_cfg_provider_token_endpoint_auth_set(r->pool, c, provider, OIDC_PROTO_PRIVATE_KEY_JWT));

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_GRANT_TYPE, OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-code");

	char *id_token = NULL, *access_token = NULL, *token_type = NULL, *refresh_token = NULL, *scope = NULL;
	int expires_in = -1;
	ck_assert_int_eq(oidc_proto_token_endpoint_request(r, c, provider, params, &id_token, &access_token,
							   &token_type, &expires_in, &refresh_token, &scope),
			 TRUE);
	/* the retry response is the one that was parsed */
	ck_assert_str_eq(access_token, "AT-2");
	ck_assert_str_eq(token_type, "DPoP");

	ck_assert_int_eq(oidc_test_http_server_request_count(srv), 2);
	const oidc_test_http_captured_t *cap1 = oidc_test_http_server_captured(srv, 0);
	const oidc_test_http_captured_t *cap2 = oidc_test_http_server_captured(srv, 1);
	ck_assert_ptr_nonnull(cap1);
	ck_assert_ptr_nonnull(cap2);

	/* the retry carries the server-provided nonce in its DPoP proof */
	const char *dpop1 = apr_table_get(cap1->headers, OIDC_HTTP_HDR_DPOP);
	const char *dpop2 = apr_table_get(cap2->headers, OIDC_HTTP_HDR_DPOP);
	ck_assert_ptr_nonnull(dpop1);
	ck_assert_ptr_nonnull(dpop2);
	ck_assert_str_ne(dpop1, dpop2);

	/* and a new client assertion, with a new jti, exactly once in the form body */
	int n1 = 0, n2 = 0;
	const char *a1 = e2e_form_param(r->pool, cap1->body, OIDC_PROTO_CLIENT_ASSERTION, &n1);
	const char *a2 = e2e_form_param(r->pool, cap2->body, OIDC_PROTO_CLIENT_ASSERTION, &n2);
	ck_assert_ptr_nonnull(a1);
	ck_assert_ptr_nonnull(a2);
	ck_assert_int_eq(n1, 1);
	ck_assert_msg(n2 == 1, "the retry must carry exactly one client_assertion, found %d: %s", n2, cap2->body);
	ck_assert_str_ne(a1, a2);
	ck_assert_str_ne(e2e_jwt_jti(r, a1), e2e_jwt_jti(r, a2));

	oidc_test_http_server_stop(srv);
}
END_TEST

/* defined further below with the request-object e2e tests */
static oidc_proto_state_t *e2e_make_proto_state(request_rec *r);

/* plain code flow where the token endpoint fails to return an access token:
 * the code-response validation must reject the response */
START_TEST(test_proto_response_code_missing_access_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"id_token\":\"dummy\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	ck_assert_ptr_null(oidc_cfg_provider_pkce_set(r->pool, provider, "none"));

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-code");
	apr_table_setn(params, OIDC_PROTO_STATE, "s-1");

	oidc_jwt_t *jwt = NULL;
	ck_assert_int_eq(oidc_proto_response_code(r, c, ps, provider, params, "query", &jwt), FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_proto_state_destroy(ps);
}
END_TEST

/*
 * Hybrid/implicit fragment-flow handlers. The id_token must carry a valid
 * nonce plus, depending on the flow, valid c_hash (over the code) and at_hash
 * (over the access token) claims.
 */

/* the left-most half of the SHA-256 hash of a value, base64url-encoded, as
 * used by the c_hash/at_hash id_token claims for an HS256-signed id_token */
static const char *e2e_half_hash_b64url(request_rec *r, const char *value) {
	oidc_jose_error_t err;
	char *calc = NULL;
	unsigned int calc_len = 0;
	char *out = NULL;
	ck_assert_int_eq(oidc_jose_hash_string(r->pool, "HS256", value, &calc, &calc_len, &err), TRUE);
	ck_assert_int_gt(
	    oidc_util_base64url_encode(r, &out, calc, oidc_jose_hash_length("HS256") / 2, OIDC_BASE64URL_PADDING_STRIP),
	    0);
	return out;
}

/* build an HS256-signed id_token for the hybrid flows: standard claims plus
 * nonce and optional c_hash/at_hash values */
static char *e2e_sign_hybrid_idtoken(request_rec *r, const char *secret, const char *nonce, const char *code,
				     const char *access_token) {
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk), TRUE);

	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	apr_time_t now = apr_time_sec(apr_time_now());
	oidc_json_object_set_new(jwt->payload.value.json, "iss", oidc_json_string("https://idp.example.com"));
	oidc_json_object_set_new(jwt->payload.value.json, "aud", oidc_json_string("client_id"));
	oidc_json_object_set_new(jwt->payload.value.json, "sub", oidc_json_string("alice"));
	oidc_json_object_set_new(jwt->payload.value.json, "nonce", oidc_json_string(nonce));
	oidc_json_object_set_new(jwt->payload.value.json, "iat", oidc_json_integer(now));
	oidc_json_object_set_new(jwt->payload.value.json, "exp", oidc_json_integer(now + 600));
	if (code != NULL)
		oidc_json_object_set_new(jwt->payload.value.json, "c_hash",
					 oidc_json_string(e2e_half_hash_b64url(r, code)));
	if (access_token != NULL)
		oidc_json_object_set_new(jwt->payload.value.json, "at_hash",
					 oidc_json_string(e2e_half_hash_b64url(r, access_token)));
	jwt->payload.iss = apr_pstrdup(r->pool, "https://idp.example.com");
	jwt->payload.sub = apr_pstrdup(r->pool, "alice");
	jwt->payload.iat = now;
	jwt->payload.exp = now + 600;

	ck_assert_int_eq(oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err), TRUE);
	char *cser = oidc_jose_jwt_serialize(r->pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
	return cser;
}

/* common setup for the hybrid tests: client secret, PKCE off, unique nonce */
static oidc_proto_state_t *e2e_make_hybrid_proto_state(request_rec *r, oidc_cfg_t *c, const char *response_type,
						       const char *nonce, const char *secret) {
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);
	ck_assert_ptr_null(oidc_cfg_provider_pkce_set(r->pool, provider, "none"));
	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	oidc_proto_state_set_response_type(ps, response_type);
	oidc_proto_state_set_nonce(ps, nonce);
	return ps;
}

/* "code id_token": the id_token comes from the authorization response (with a
 * valid c_hash) and the access token from the token endpoint */
START_TEST(test_proto_response_code_idtoken_happy) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "hybrid-flow-shared-secret-code-idtoken";

	oidc_proto_state_t *ps = e2e_make_hybrid_proto_state(r, c, "code id_token", "nonce-hybrid-ci", secret);

	/* the token endpoint returns the access token; the id_token it also
	 * returns is dropped with a warning since the flow carries its own */
	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"access_token\":\"AT-HYBRID-1\",\"token_type\":\"Bearer\","
						  "\"id_token\":\"dropped\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-hybrid-code");
	apr_table_setn(params, OIDC_PROTO_ID_TOKEN,
		       e2e_sign_hybrid_idtoken(r, secret, "nonce-hybrid-ci", "the-hybrid-code", NULL));
	apr_table_setn(params, OIDC_PROTO_STATE, "s-1");

	oidc_jwt_t *jwt = NULL;
	ck_assert_int_eq(oidc_proto_response_code_idtoken(r, c, ps, provider, params, "fragment", &jwt), TRUE);
	ck_assert_ptr_nonnull(jwt);
	ck_assert_str_eq(apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN), "AT-HYBRID-1");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
	oidc_proto_state_destroy(ps);
}
END_TEST

/* "code token": the access token from the authorization response and the
 * id_token from the token endpoint; an access token the token endpoint also
 * returns overrides the fragment one (with a warning) */
START_TEST(test_proto_response_code_token_happy) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "hybrid-flow-shared-secret-code-token1";

	oidc_proto_state_t *ps = e2e_make_hybrid_proto_state(r, c, "code token", "nonce-hybrid-ct", secret);

	const char *body =
	    apr_psprintf(r->pool, "{\"id_token\":\"%s\",\"access_token\":\"AT-BACKCHANNEL\",\"token_type\":\"Bearer\"}",
			 e2e_sign_hybrid_idtoken(r, secret, "nonce-hybrid-ct", NULL, NULL));
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-ct-code");
	apr_table_setn(params, OIDC_PROTO_ACCESS_TOKEN, "AT-FRAGMENT");
	apr_table_setn(params, OIDC_PROTO_TOKEN_TYPE, "Bearer");
	apr_table_setn(params, OIDC_PROTO_STATE, "s-1");

	oidc_jwt_t *jwt = NULL;
	ck_assert_int_eq(oidc_proto_response_code_token(r, c, ps, provider, params, "fragment", &jwt), TRUE);
	ck_assert_ptr_nonnull(jwt);
	/* the access token from the token endpoint overrides the fragment one
	 * (see oidc_proto_resolve_code_and_validate_response) */
	ck_assert_str_eq(apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN), "AT-BACKCHANNEL");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
	oidc_proto_state_destroy(ps);
}
END_TEST

/* "code token" where the token endpoint fails to return the (required)
 * id_token: the code response validation rejects it */
START_TEST(test_proto_response_code_token_missing_id_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "hybrid-flow-shared-secret-code-token2";

	oidc_proto_state_t *ps = e2e_make_hybrid_proto_state(r, c, "code token", "nonce-hybrid-ct2", secret);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"scope\":\"openid\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-ct2-code");
	apr_table_setn(params, OIDC_PROTO_ACCESS_TOKEN, "AT-FRAGMENT2");
	apr_table_setn(params, OIDC_PROTO_TOKEN_TYPE, "Bearer");
	apr_table_setn(params, OIDC_PROTO_STATE, "s-1");

	oidc_jwt_t *jwt = NULL;
	ck_assert_int_eq(oidc_proto_response_code_token(r, c, ps, provider, params, "fragment", &jwt), FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_proto_state_destroy(ps);
}
END_TEST

/* "code id_token token": id_token and access token from the authorization
 * response (validated via c_hash and at_hash), code resolved at the token
 * endpoint */
START_TEST(test_proto_response_code_idtoken_token_happy) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "hybrid-flow-shared-secret-code-it-tok";

	oidc_proto_state_t *ps = e2e_make_hybrid_proto_state(r, c, "code id_token token", "nonce-hybrid-cit", secret);

	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = "{}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_token_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-cit-code");
	apr_table_setn(params, OIDC_PROTO_ACCESS_TOKEN, "AT-CIT");
	apr_table_setn(params, OIDC_PROTO_TOKEN_TYPE, "Bearer");
	apr_table_setn(params, OIDC_PROTO_ID_TOKEN,
		       e2e_sign_hybrid_idtoken(r, secret, "nonce-hybrid-cit", "the-cit-code", "AT-CIT"));
	apr_table_setn(params, OIDC_PROTO_STATE, "s-1");

	oidc_jwt_t *jwt = NULL;
	ck_assert_int_eq(oidc_proto_response_code_idtoken_token(r, c, ps, provider, params, "fragment", &jwt), TRUE);
	ck_assert_ptr_nonnull(jwt);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
	oidc_proto_state_destroy(ps);
}
END_TEST

/* "id_token token": pure implicit flow, no code and no token endpoint call;
 * the access token is validated against the at_hash claim */
START_TEST(test_proto_response_idtoken_token_happy) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "hybrid-flow-shared-secret-idtok-token";

	oidc_proto_state_t *ps = e2e_make_hybrid_proto_state(r, c, "id_token token", "nonce-hybrid-it", secret);

	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_ACCESS_TOKEN, "AT-IMPLICIT");
	apr_table_setn(params, OIDC_PROTO_TOKEN_TYPE, "Bearer");
	apr_table_setn(params, OIDC_PROTO_ID_TOKEN,
		       e2e_sign_hybrid_idtoken(r, secret, "nonce-hybrid-it", NULL, "AT-IMPLICIT"));
	apr_table_setn(params, OIDC_PROTO_STATE, "s-1");

	oidc_jwt_t *jwt = NULL;
	ck_assert_int_eq(oidc_proto_response_idtoken_token(r, c, ps, provider, params, "fragment", &jwt), TRUE);
	ck_assert_ptr_nonnull(jwt);

	oidc_jwt_destroy(jwt);
	oidc_proto_state_destroy(ps);
}
END_TEST

/* response-type mismatches between what was requested and what came back:
 * a missing access_token for a token-carrying flow and an unexpected
 * access_token for a plain code flow are both rejected up front */
START_TEST(test_proto_response_type_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "hybrid-flow-shared-secret-mismatch01";
	oidc_jwt_t *jwt = NULL;

	/* "code token" requested but no access_token in the response */
	oidc_proto_state_t *ps = e2e_make_hybrid_proto_state(r, c, "code token", "nonce-hybrid-mm1", secret);
	apr_table_t *params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-mm-code");
	apr_table_setn(params, OIDC_PROTO_STATE, "s-1");
	ck_assert_int_eq(oidc_proto_response_code_token(r, c, ps, provider, params, "fragment", &jwt), FALSE);
	oidc_proto_state_destroy(ps);

	/* "code" requested but the response carries an access_token */
	ps = e2e_make_hybrid_proto_state(r, c, "code", "nonce-hybrid-mm2", secret);
	params = apr_table_make(r->pool, 4);
	apr_table_setn(params, OIDC_PROTO_CODE, "the-mm2-code");
	apr_table_setn(params, OIDC_PROTO_ACCESS_TOKEN, "AT-UNEXPECTED");
	apr_table_setn(params, OIDC_PROTO_STATE, "s-1");
	ck_assert_int_eq(oidc_proto_response_code(r, c, ps, provider, params, "query", &jwt), FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

/* aggregated (embedded JWT) and distributed (access_token + endpoint) composite
 * claims are resolved into the userinfo claims and the bookkeeping members
 * (_claim_names/_claim_sources) are removed */
START_TEST(test_proto_userinfo_request_composite_claims) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;

	/* build the aggregated/distributed claim JWTs; oidc_jwt_parse only parses
	 * (no signature verification) so any HS256 signing key will do */
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, "0123456789abcdef0123456789abcdef", 0, NULL, FALSE, &jwk),
			 TRUE);
	oidc_jwt_t *jwt1 = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt1->header.alg = apr_pstrdup(r->pool, "HS256");
	oidc_json_object_set_new(jwt1->payload.value.json, "credit_score", oidc_json_integer(700));
	ck_assert_int_eq(oidc_jwt_sign(r->pool, jwt1, jwk, FALSE, &err), TRUE);
	char *src1_jwt = oidc_jose_jwt_serialize(r->pool, jwt1, &err);
	oidc_jwt_t *jwt2 = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt2->header.alg = apr_pstrdup(r->pool, "HS256");
	oidc_json_object_set_new(jwt2->payload.value.json, "shoe_size", oidc_json_integer(42));
	ck_assert_int_eq(oidc_jwt_sign(r->pool, jwt2, jwk, FALSE, &err), TRUE);
	char *src2_jwt = oidc_jose_jwt_serialize(r->pool, jwt2, &err);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt1);
	oidc_jwt_destroy(jwt2);

	/* distributed-claim endpoint: serves the second JWT on demand */
	oidc_test_http_response_t dist_resp = {.status_code = 200, .content_type = "application/jwt", .body = src2_jwt};
	oidc_test_http_server_t *dist_srv = oidc_test_http_server_start(r->pool, &dist_resp);
	ck_assert_ptr_nonnull(dist_srv);

	/* userinfo response with one aggregated and one distributed source */
	const char *userinfo_body = apr_psprintf(r->pool,
						 "{\"sub\":\"alice\","
						 "\"_claim_names\":{\"credit_score\":\"src1\",\"shoe_size\":\"src2\"},"
						 "\"_claim_sources\":{\"src1\":{\"JWT\":\"%s\"},"
						 "\"src2\":{\"access_token\":\"AT-DIST\",\"endpoint\":\"%s\"}}}",
						 src1_jwt, oidc_test_http_server_url(dist_srv, r->pool));
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = userinfo_body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);
	/* both composite claims resolved, bookkeeping members removed */
	ck_assert_int_eq((int)oidc_json_integer_value(oidc_json_object_get(userinfo_claims, "credit_score")), 700);
	ck_assert_int_eq((int)oidc_json_integer_value(oidc_json_object_get(userinfo_claims, "shoe_size")), 42);
	ck_assert_ptr_null(oidc_json_object_get(userinfo_claims, "_claim_names"));
	ck_assert_ptr_null(oidc_json_object_get(userinfo_claims, "_claim_sources"));

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	(void)oidc_test_http_server_wait(dist_srv);
	oidc_test_http_server_stop(dist_srv);
	oidc_json_decref(userinfo_claims);
}
END_TEST

/* a DPoP-bound access token makes the userinfo request carry a DPoP proof */
START_TEST(test_proto_userinfo_request_dpop) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* DPoP proof creation needs an asymmetric signing key */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-dpop#%s/private.pem", dir)));

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"sub\":\"alice\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT-DPOP", "DPoP", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);

	/* the request must carry both the DPoP authorization scheme and a proof header */
	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	const char *auth = apr_table_get(cap->headers, OIDC_HTTP_HDR_AUTHORIZATION);
	ck_assert_ptr_nonnull(auth);
	ck_assert_msg(_oidc_strstr(auth, "DPoP AT-DPOP") == auth, "authorization header must use the DPoP scheme: %s",
		      auth);
	ck_assert_ptr_nonnull(apr_table_get(cap->headers, OIDC_HTTP_HDR_DPOP));

	oidc_test_http_server_stop(srv);
	oidc_json_decref(userinfo_claims);
}
END_TEST

START_TEST(test_proto_userinfo_request_success) {
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

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);
	ck_assert_int_eq(response_code, 200);
	const char *name = oidc_json_string_value(oidc_json_object_get(userinfo_claims, "name"));
	ck_assert_ptr_nonnull(name);
	ck_assert_str_eq(name, "Alice Example");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "GET");
	const char *auth = apr_table_get(cap->headers, OIDC_HTTP_HDR_AUTHORIZATION);
	ck_assert_ptr_nonnull(auth);
	ck_assert_str_eq(auth, "Bearer AT");

	oidc_json_decref(userinfo_claims);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_userinfo_request_sub_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"sub\":\"bob\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	/* id_token_sub is "alice" but userinfo returns "bob" — mismatch must fail */
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_userinfo_request_error) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {.status_code = 401,
					  .content_type = "application/json",
					  .body = "{\"error\":\"invalid_token\",\"error_description\":\"expired\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_userinfo_request_post_method) {
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
	/* switch token presentation to the POST body branch */
	oidc_cfg_provider_userinfo_token_method_int_set(provider, OIDC_USER_INFO_TOKEN_METHOD_POST);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_int_eq(response_code, 200);

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_ptr_nonnull(cap->body);
	ck_assert_msg(_oidc_strstr(cap->body, OIDC_PROTO_ACCESS_TOKEN "=AT") != NULL,
		      "POST body must carry access_token=AT");

	oidc_json_decref(userinfo_claims);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_userinfo_request_missing_sub_required) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* response carries no "sub" claim and OIDC_NO_USERINFO_SUB is not set in the env =>
	 * oidc_proto_userinfo_request_validate_sub rejects with FALSE */
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"name\":\"Alice\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);
	/* claims are freed by the validator on failure */
	ck_assert_ptr_null(userinfo_claims);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_userinfo_request_missing_sub_skipped_via_env) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/json", .body = "{\"name\":\"Alice\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	/* setting OIDC_NO_USERINFO_SUB in the subprocess env opts out of the mandatory-sub
	 * check; pass NULL as id_token_sub so the equality branch is also skipped */
	apr_table_set(r->subprocess_env, "OIDC_NO_USERINFO_SUB", "1");

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, NULL, "AT", "Bearer", &s_userinfo, &userinfo_jwt,
						     &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);

	oidc_json_decref(userinfo_claims);
	apr_table_unset(r->subprocess_env, "OIDC_NO_USERINFO_SUB");
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_userinfo_request_composite_embedded_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* a composite-claims response with an inline alg=none JWT for the "address" source;
	 * the JWT below decodes to {"address":{"street_address":"123 Main St","country":"US"}}.
	 * The dispatcher walks _claim_names → _claim_sources → JWT and merges the payload
	 * back into claims under the "address" key, then strips both meta-keys. */
	const char *address_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
				  "eyJhZGRyZXNzIjp7InN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QiLCJjb3VudHJ5IjoiVVMifX0.";
	const char *body = apr_psprintf(r->pool,
					"{\"sub\":\"alice\",\"_claim_names\":{\"address\":\"src1\"},"
					"\"_claim_sources\":{\"src1\":{\"JWT\":\"%s\"}}}",
					address_jwt);
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);
	/* the composite resolver lifts "address" out of the inline JWT into the claims root */
	oidc_json_t *address = oidc_json_object_get(userinfo_claims, "address");
	ck_assert_ptr_nonnull(address);
	ck_assert_int_eq(oidc_json_is_object(address), 1);
	const char *street = oidc_json_string_value(oidc_json_object_get(address, "street_address"));
	ck_assert_ptr_nonnull(street);
	ck_assert_str_eq(street, "123 Main St");
	const char *country = oidc_json_string_value(oidc_json_object_get(address, "country"));
	ck_assert_ptr_nonnull(country);
	ck_assert_str_eq(country, "US");
	/* the meta-keys are stripped after resolution */
	ck_assert_ptr_null(oidc_json_object_get(userinfo_claims, "_claim_names"));
	ck_assert_ptr_null(oidc_json_object_get(userinfo_claims, "_claim_sources"));
	/* the re-serialized s_userinfo reflects the rewritten payload */
	ck_assert_ptr_nonnull(s_userinfo);
	ck_assert_msg(_oidc_strstr(s_userinfo, "_claim_names") == NULL,
		      "s_userinfo must be re-encoded without _claim_names");

	oidc_json_decref(userinfo_claims);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_userinfo_request_composite_names_without_sources) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* _claim_names present but _claim_sources missing => the composite resolver
	 * short-circuits to FALSE without rewriting the claims; meta keys stay in place */
	const char *body = "{\"sub\":\"alice\",\"_claim_names\":{\"address\":\"src1\"}}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);
	ck_assert_ptr_nonnull(oidc_json_object_get(userinfo_claims, "_claim_names"));

	oidc_json_decref(userinfo_claims);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* sign a {"sub":"alice"} userinfo payload as an HS256 compact JWT with the given secret */
static char *e2e_sign_userinfo_jwt(request_rec *r, const char *secret) {
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk), TRUE);
	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	oidc_json_object_set_new(jwt->payload.value.json, "sub", oidc_json_string("alice"));
	ck_assert_int_eq(oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err), TRUE);
	char *cser = oidc_jose_jwt_serialize(r->pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
	return cser;
}

/* a userinfo response that is neither JSON nor a JWT is rejected */
START_TEST(test_proto_userinfo_response_garbage) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "text/plain", .body = "certainly &not* a JWT"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* a JWT userinfo response without a configured signed response alg is refused */
START_TEST(test_proto_userinfo_response_jwt_no_alg_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "userinfo-jwt-response-secret-32-bytes!";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/jwt", .body = e2e_sign_userinfo_jwt(r, secret)};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* a signed JWT userinfo response verified with the client secret round-trips */
START_TEST(test_proto_userinfo_response_signed_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "userinfo-jwt-response-secret-32-bytes!";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_signed_response_alg_set(r->pool, provider, "HS256"));

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/jwt", .body = e2e_sign_userinfo_jwt(r, secret)};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_jwt);
	ck_assert_ptr_nonnull(userinfo_claims);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(userinfo_claims, "sub")), "alice");

	oidc_json_decref(userinfo_claims);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* a signed JWT userinfo response with a wrong signature is refused */
START_TEST(test_proto_userinfo_response_signed_jwt_bad_signature) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_cfg_provider_client_secret_set(r->pool, provider, "userinfo-jwt-response-secret-32-bytes!");
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_signed_response_alg_set(r->pool, provider, "HS256"));

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/jwt",
					  .body = e2e_sign_userinfo_jwt(r, "another-userinfo-secret-32-bytes!!!")};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* an encrypted (JWE) userinfo response is decrypted with the client-secret-derived
 * key before the inner signed JWT is verified */
START_TEST(test_proto_userinfo_response_encrypted_jwt) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "userinfo-jwt-response-secret-32-bytes!";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_signed_response_alg_set(r->pool, provider, "HS256"));
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_encrypted_response_alg_set(r->pool, provider, "A256KW"));

	/* wrap the signed JWT in a symmetric JWE the same way the module derives its key */
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(
	    oidc_util_key_symmetric_create(r, secret, oidc_alg2keysize("A256KW"), OIDC_JOSE_ALG_SHA256, TRUE, &jwk),
	    TRUE);
	oidc_jwt_t *jwe = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwe->header.alg = apr_pstrdup(r->pool, "A256KW");
	jwe->header.enc = apr_pstrdup(r->pool, "A256GCM");
	char *plaintext = e2e_sign_userinfo_jwt(r, secret);
	char *cser = NULL;
	ck_assert_int_eq(oidc_jwt_encrypt(r->pool, jwe, jwk, plaintext, (int)_oidc_strlen(plaintext), &cser, &err),
			 TRUE);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwe);

	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/jwt", .body = cser};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(userinfo_claims, "sub")), "alice");

	oidc_json_decref(userinfo_claims);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* an expected-encrypted userinfo response that is not actually a JWE fails to decrypt */
START_TEST(test_proto_userinfo_response_encrypted_jwt_decrypt_fails) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *secret = "userinfo-jwt-response-secret-32-bytes!";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_signed_response_alg_set(r->pool, provider, "HS256"));
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_encrypted_response_alg_set(r->pool, provider, "A256KW"));

	/* a plain signed JWT where a JWE was expected */
	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/jwt", .body = e2e_sign_userinfo_jwt(r, secret)};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* composite-claim negatives: an unparsable source JWT, a non-string name value
 * and a name that points at a missing source */
START_TEST(test_proto_userinfo_request_composite_negatives) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {
	    .status_code = 200,
	    .content_type = "application/json",
	    .body = "{\"sub\":\"alice\","
		    "\"_claim_names\":{\"shoe_size\":\"src1\",\"age\":42,\"height\":\"missing_src\"},"
		    "\"_claim_sources\":{\"src1\":{\"JWT\":\"not-a-parsable-jwt\"}}}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	/* the composite decoding failures are logged, the request itself succeeds */
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);

	oidc_json_decref(userinfo_claims);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* a DPoP userinfo request that is answered with use_dpop_nonce is retried with the
 * nonce from the response header */
START_TEST(test_proto_userinfo_request_dpop_nonce_retry) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-dpop#%s/private.pem", dir)));

	apr_table_t *nonce_hdrs = apr_table_make(r->pool, 1);
	apr_table_set(nonce_hdrs, "DPoP-Nonce", "server-nonce-1");
	oidc_test_http_response_t responses[2] = {
	    {.status_code = 400,
	     .content_type = "application/json",
	     .body = "{\"error\":\"use_dpop_nonce\"}",
	     .extra_headers = nonce_hdrs},
	    {.status_code = 200, .content_type = "application/json", .body = "{\"sub\":\"alice\"}"},
	};
	oidc_test_http_server_t *srv = oidc_test_http_server_start_seq(r->pool, responses, 2);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT-DPOP", "DPoP", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(userinfo_claims, "sub")), "alice");

	/* two requests were made */
	ck_assert_int_eq(oidc_test_http_server_request_count(srv), 2);

	oidc_json_decref(userinfo_claims);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* a DPoP retry that still yields an error response is a hard failure */
START_TEST(test_proto_userinfo_request_dpop_nonce_retry_still_error) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-dpop#%s/private.pem", dir)));

	apr_table_t *nonce_hdrs = apr_table_make(r->pool, 1);
	apr_table_set(nonce_hdrs, "DPoP-Nonce", "server-nonce-2");
	oidc_test_http_response_t responses[2] = {
	    {.status_code = 400,
	     .content_type = "application/json",
	     .body = "{\"error\":\"use_dpop_nonce\"}",
	     .extra_headers = nonce_hdrs},
	    {.status_code = 400, .content_type = "application/json", .body = "{\"error\":\"invalid_token\"}"},
	};
	oidc_test_http_server_t *srv = oidc_test_http_server_start_seq(r->pool, responses, 2);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT-DPOP", "DPoP", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	oidc_test_http_server_stop(srv);
}
END_TEST

/* a response with a decodable JWT header but an unparsable body */
START_TEST(test_proto_userinfo_response_jwt_body_unparsable) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_cfg_provider_client_secret_set(r->pool, provider, "userinfo-jwt-response-secret-32-bytes!");
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_signed_response_alg_set(r->pool, provider, "HS256"));

	oidc_test_http_response_t resp = {
	    .status_code = 200, .content_type = "application/jwt", .body = "eyJhbGciOiJIUzI1NiJ9.!not-base64!.c2ln"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* a JWT response cannot be processed when no client secret is configured to derive keys from */
START_TEST(test_proto_userinfo_response_jwt_no_client_secret) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_signed_response_alg_set(r->pool, provider, "HS256"));

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/jwt",
					  .body = e2e_sign_userinfo_jwt(r, "some-random-secret-32-bytes-long!!")};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* POST-method connectivity error and an unsupported token presentation method */
START_TEST(test_proto_userinfo_endpoint_call_negatives) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	int free_port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(free_port, 0);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider,
						    apr_psprintf(r->pool, "http://127.0.0.1:%d/userinfo", free_port));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;

	oidc_cfg_provider_userinfo_token_method_int_set(provider, OIDC_USER_INFO_TOKEN_METHOD_POST);
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	oidc_cfg_provider_userinfo_token_method_int_set(provider, (oidc_userinfo_token_method_t)99);
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);
}
END_TEST

/* a DPoP request answered with a non-nonce error is not retried */
START_TEST(test_proto_userinfo_request_dpop_plain_error) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-dpop#%s/private.pem", dir)));

	oidc_test_http_response_t resp = {
	    .status_code = 400, .content_type = "application/json", .body = "{\"error\":\"invalid_token\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT-DPOP", "DPoP", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);
	ck_assert_int_eq(oidc_test_http_server_request_count(srv), 1);

	oidc_test_http_server_stop(srv);
}
END_TEST

/* a DPoP nonce retry whose second response cannot be decoded at all */
START_TEST(test_proto_userinfo_request_dpop_retry_garbage) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-dpop#%s/private.pem", dir)));

	apr_table_t *nonce_hdrs = apr_table_make(r->pool, 1);
	apr_table_set(nonce_hdrs, "DPoP-Nonce", "server-nonce-3");
	oidc_test_http_response_t responses[2] = {
	    {.status_code = 400,
	     .content_type = "application/json",
	     .body = "{\"error\":\"use_dpop_nonce\"}",
	     .extra_headers = nonce_hdrs},
	    {.status_code = 200, .content_type = "text/plain", .body = "&garbage& that is neither JSON nor JWT"},
	};
	oidc_test_http_server_t *srv = oidc_test_http_server_start_seq(r->pool, responses, 2);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT-DPOP", "DPoP", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);
	ck_assert_int_eq(oidc_test_http_server_request_count(srv), 2);

	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_request_auth_par_redirect) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_test_http_response_t resp = {.status_code = 200,
					  .content_type = "application/json",
					  .body = "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:abc123\","
						  "\"expires_in\":60}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");
	oidc_cfg_provider_pushed_authorization_request_endpoint_url_set(r->pool, provider,
									oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);
	oidc_cfg_provider_auth_request_method_int_set(provider, OIDC_AUTH_REQUEST_METHOD_PAR);

	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "n1");
	oidc_proto_state_set_original_url(ps, "https://rp.example.com/protected/");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_response_type(ps, OIDC_PROTO_RESPONSE_TYPE_CODE);
	oidc_proto_state_set_timestamp_now(ps);

	int rc =
	    oidc_request_auth(r, c, provider, NULL, "https://rp.example.com/cb", "state-1", ps, NULL, NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "https://idp.example.com/authorize") != NULL,
		      "redirect targets the authorization endpoint");
	ck_assert_msg(_oidc_strstr(loc, "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc123") != NULL,
		      "redirect includes the PAR-issued request_uri");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "POST");
	ck_assert_msg(_oidc_strstr(cap->body, "response_type=code") != NULL,
		      "PAR POST body carries response_type=code");

	oidc_test_http_server_stop(srv);
}
END_TEST

/*
 * Tests for proto/jwks.c — drive oidc_proto_jwks_uri_keys against the
 * loopback HTTP server, exercising the kid-match, no-kid-include-any
 * and HTTP-failure branches.
 */

/* build a JWT shell with header.alg + header.kid set so oidc_proto_jwks_uri_keys
 * has enough metadata to pick a key from the JWKS response */
static oidc_jwt_t *e2e_make_jwt_for_kid(apr_pool_t *pool, const char *alg, const char *kid) {
	oidc_jwt_t *jwt = oidc_jwt_new(pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(pool, alg);
	if (kid != NULL)
		jwt->header.kid = apr_pstrdup(pool, kid);
	return jwt;
}

/*
 * Tests for proto/request.c branches not covered by the existing
 * test_proto_authorization_request (GET) or test_proto_request_auth_par_redirect (PAR):
 * the POST method, missing-client-id and unknown-method failure paths.
 */

static oidc_proto_state_t *e2e_make_proto_state(request_rec *r) {
	(void)r;
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_proto_state_set_nonce(ps, "n-1");
	oidc_proto_state_set_state(ps, "s-1");
	oidc_proto_state_set_issuer(ps, "https://idp.example.com");
	oidc_proto_state_set_original_url(ps, "https://www.example.com/protected/");
	oidc_proto_state_set_original_method(ps, OIDC_METHOD_GET);
	oidc_proto_state_set_response_type(ps, OIDC_PROTO_RESPONSE_TYPE_CODE);
	oidc_proto_state_set_timestamp_now(ps);
	return ps;
}

START_TEST(test_proto_private_keys_load_from_pem) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	/* load test/private.pem via the OIDCPrivateKeyFiles cmd setter and verify the
	 * key lands in cfg->private_keys */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *arg = apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir);
	const char *rv = oidc_cmd_private_keys_set(cmd, NULL, apr_pstrdup(r->pool, arg));
	ck_assert_msg(rv == NULL, "could not load private key from %s/private.pem: %s", dir, rv);
	const apr_array_header_t *keys = oidc_cfg_private_keys_get(cfg);
	ck_assert_ptr_nonnull(keys);
	ck_assert_int_eq(keys->nelts, 1);
	oidc_jwk_t *jwk = APR_ARRAY_IDX(keys, 0, oidc_jwk_t *);
	ck_assert_ptr_nonnull(jwk);
	ck_assert_str_eq(jwk->kid, "rsa-1");
}
END_TEST

START_TEST(test_proto_request_auth_with_request_object_none) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* OIDCRequestObject with sign_alg=none — the request_object becomes an
	 * unsigned (alg=none) JWT and is appended as the "request" parameter on
	 * the authorization request URL */
	oidc_cfg_provider_request_object_set(r->pool, provider, "{\"crypto\":{\"sign_alg\":\"none\"}}");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-ro-1", ps, NULL,
				   NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	/* OIDCRequestObject defaults to publishing the request via the redirect_uri
	 * (request_uri=...) rather than embedding the JWT directly (request=...) */
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") != NULL,
		      "request_uri= parameter must appear in the authorization URL: %s", loc);
}
END_TEST

START_TEST(test_proto_request_auth_with_request_object_rs256) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* load a private key first so the RS256-signed request object can be created */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *arg = apr_psprintf(r->pool, "rsa-sig#%s/private.pem", dir);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(cmd, NULL, apr_pstrdup(r->pool, arg)));

	oidc_cfg_provider_request_object_set(r->pool, provider, "{\"crypto\":{\"sign_alg\":\"RS256\"}}");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-ro-2", ps, NULL,
				   NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") != NULL, "request_uri= parameter must appear in the URL");
}
END_TEST

/* drive one authorization request with the given OIDCRequestObject config and hand back the
 * Location header it redirected to */
static const char *e2e_request_object_location(request_rec *r, oidc_cfg_t *c, oidc_provider_t *provider,
					       const char *request_object_config, const char *state) {
	oidc_cfg_provider_request_object_set(r->pool, provider, request_object_config);
	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", state, ps, NULL, NULL,
				   NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	return loc;
}

/*
 * "request_object_type":"request" embeds the JWT in the authorization request itself instead of
 * publishing it behind a request_uri, and the two ways of getting that setting wrong -- a
 * non-string and an unknown value -- must leave the request object off rather than guess
 */
START_TEST(test_proto_request_auth_request_object_type) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *loc = NULL;

	loc = e2e_request_object_location(
	    r, c, provider, "{\"request_object_type\":\"request\",\"crypto\":{\"sign_alg\":\"none\"}}", "state-rot-1");
	ck_assert_msg(_oidc_strstr(loc, "request=") != NULL, "the request object must be embedded: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") == NULL, "it must not also be passed by reference: %s", loc);

	/* explicitly asking for the default is accepted rather than treated as unknown */
	loc = e2e_request_object_location(
	    r, c, provider, "{\"request_object_type\":\"request_uri\",\"crypto\":{\"sign_alg\":\"none\"}}",
	    "state-rot-2");
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") != NULL, "request_uri= must appear: %s", loc);

	/* not a string */
	loc = e2e_request_object_location(
	    r, c, provider, "{\"request_object_type\":42,\"crypto\":{\"sign_alg\":\"none\"}}", "state-rot-3");
	ck_assert_msg(_oidc_strstr(loc, "request") == NULL, "no request object may be attached: %s", loc);

	/* a string, but not one of the two accepted values */
	loc = e2e_request_object_location(r, c, provider,
					  "{\"request_object_type\":\"telepathy\",\"crypto\":{\"sign_alg\":\"none\"}}",
					  "state-rot-4");
	ck_assert_msg(_oidc_strstr(loc, "request") == NULL, "no request object may be attached: %s", loc);
}
END_TEST

/*
 * choosing the key to sign the request object with: the symmetric case, and the three ways it can
 * find no key at all. A failure here must leave the request object off the authorization request
 * rather than sending an unsigned one in its place.
 */
START_TEST(test_proto_request_auth_request_object_signing_keys) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	const char *loc = NULL;

	/* HS256: signed with a key derived from the client secret, no private key needed */
	oidc_cfg_provider_client_secret_set(r->pool, provider, "jar-signing-shared-secret-0123456789");
	loc = e2e_request_object_location(r, c, provider, "{\"crypto\":{\"sign_alg\":\"HS256\"}}", "state-rosk-1");
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") != NULL, "an HS256 request object must be produced: %s", loc);

	/* RS256 with a key list that is present but holds no usable signing key */
	loc = e2e_request_object_location(r, c, provider, "{\"crypto\":{\"sign_alg\":\"RS256\"}}", "state-rosk-2");
	ck_assert_msg(_oidc_strstr(loc, "request") == NULL,
		      "without a usable signing key no request object may be attached: %s", loc);

	/* an algorithm with no key type behind it at all */
	loc = e2e_request_object_location(r, c, provider, "{\"crypto\":{\"sign_alg\":\"XY123\"}}", "state-rosk-3");
	ck_assert_msg(_oidc_strstr(loc, "request") == NULL, "an unsupported alg may not produce one either: %s", loc);

	/* with neither key list configured at all, which is a refusal of its own */
	apr_array_header_t *fixture_keys = (apr_array_header_t *)oidc_cfg_private_keys_get(c);
	c->private_keys = NULL;
	loc = e2e_request_object_location(r, c, provider, "{\"crypto\":{\"sign_alg\":\"RS256\"}}", "state-rosk-4");
	ck_assert_msg(_oidc_strstr(loc, "request") == NULL,
		      "without any configured keys no request object may be attached: %s", loc);
	c->private_keys = fixture_keys;

	/* per-provider client keys are preferred over the global list */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	ck_assert_ptr_null(oidc_cmd_private_keys_set(oidc_test_cmd_get(OIDCPrivateKeyFiles), NULL,
						     apr_psprintf(r->pool, "rsa-client#%s/private.pem", dir)));
	apr_array_header_t *keys = (apr_array_header_t *)oidc_cfg_private_keys_get(c);
	ck_assert_ptr_null(oidc_cfg_provider_client_keys_set_keys(r->pool, provider, keys));
	c->private_keys = NULL;
	loc = e2e_request_object_location(r, c, provider, "{\"crypto\":{\"sign_alg\":\"RS256\"}}", "state-rosk-5");
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") != NULL,
		      "a per-provider client key must be usable for signing: %s", loc);

	/* hand the list back to the config: cfg and the provider each destroy the list they hold, so
	 * exactly one of them may point at it when the fixture tears down */
	ck_assert_ptr_null(oidc_cfg_provider_client_keys_set_keys(r->pool, provider, NULL));
	c->private_keys = keys;
}
END_TEST

/*
 * "url" overrides where the published request object is fetched from, for deployments that resolve
 * it somewhere other than the redirect URI
 */
START_TEST(test_proto_request_auth_request_object_url_override) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	const char *loc = e2e_request_object_location(
	    r, c, provider, "{\"url\":\"https://jar.example.com/resolve\",\"crypto\":{\"sign_alg\":\"none\"}}",
	    "state-rourl-1");
	ck_assert_msg(_oidc_strstr(loc, "jar.example.com%2Fresolve") != NULL,
		      "the configured resolver URL must be used instead of the redirect URI: %s", loc);
}
END_TEST

/* the request object is encrypted (sign_alg=none) with a symmetric key derived
 * from the client_secret: covers the OCT branch of the encryption-JWK resolver
 * and the JWE creation itself */
START_TEST(test_proto_request_auth_with_request_object_encrypted_symmetric) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_cfg_provider_client_secret_set(r->pool, provider, "jar-encryption-shared-secret");
	oidc_cfg_provider_request_object_set(r->pool, provider,
					     "{\"crypto\":{\"sign_alg\":\"none\",\"crypt_alg\":\"A128KW\"}}");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-ro-enc-1", ps,
				   NULL, NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") != NULL,
		      "request_uri= parameter must appear in the authorization URL: %s", loc);
}
END_TEST

/* the request object is encrypted with an RSA key published in the provider's
 * JWKs document: covers oidc_request_uri_encryption_jwk_by_type incl. the
 * use=sig skip, the kty-mismatch skip and the kid-copy into the JWE header */
START_TEST(test_proto_request_auth_with_request_object_encrypted_rsa) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_jose_error_t err;

	/* derive the public encryption JWK from the test RSA private key */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(cmd, NULL, apr_psprintf(r->pool, "rsa-enc#%s/private.pem", dir)));
	oidc_jwk_t *priv = APR_ARRAY_IDX(oidc_cfg_private_keys_get(c), 0, oidc_jwk_t *);
	char *s_pub = NULL;
	ck_assert_int_eq(oidc_jwk_to_public_json(r->pool, priv, &s_pub, &err), TRUE);
	oidc_json_t *j_pub = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, s_pub, &j_pub), TRUE);
	oidc_json_object_set_new(j_pub, "use", oidc_json_string("enc"));
	oidc_json_object_set_new(j_pub, "kid", oidc_json_string("enc-1"));

	/* serve a JWKs doc with a use=sig decoy and a kty-mismatch (oct) decoy in
	 * front of the usable RSA encryption key */
	const char *jwks_body = apr_psprintf(r->pool,
					     "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"sig-1\"},"
					     "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"},%s]}",
					     oidc_json_encode(r->pool, j_pub, OIDC_JSON_COMPACT));
	oidc_json_decref(j_pub);
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks_body};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	ck_assert_ptr_null(oidc_cfg_provider_jwks_uri_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool)));

	oidc_cfg_provider_request_object_set(r->pool, provider,
					     "{\"crypto\":{\"sign_alg\":\"none\",\"crypt_alg\":\"RSA-OAEP\","
					     "\"crypt_enc\":\"A128CBC-HS256\"}}");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-ro-enc-2", ps,
				   NULL, NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") != NULL,
		      "request_uri= parameter must appear in the authorization URL: %s", loc);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

/* an unsupported crypt_alg maps to no key type: request object creation fails
 * and the authorization request is sent without a request_uri parameter */
START_TEST(test_proto_request_auth_with_request_object_encrypt_bad_alg) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_cfg_provider_request_object_set(r->pool, provider,
					     "{\"crypto\":{\"sign_alg\":\"none\",\"crypt_alg\":\"BOGUS\"}}");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-ro-enc-3", ps,
				   NULL, NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") == NULL,
		      "request_uri= must NOT appear when request object encryption fails: %s", loc);
}
END_TEST

START_TEST(test_proto_auth_request_params_cannot_duplicate_ours) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(r->pool, provider, "client_id");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	/* auth_request_params arrives with the request: a key that duplicates one this module
	 * sets itself must be dropped rather than sent alongside ours, since RFC 6749 3.1 does
	 * not allow the parameter twice and the provider decides which one wins */
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-dup", ps, NULL,
				   NULL, "redirect_uri=https%3A%2F%2Fevil.example%2Fcb&acr_values=loa3", NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "evil.example") == NULL,
		      "an injected duplicate redirect_uri must not reach the provider");
	/* a parameter that collides with nothing is still added */
	ck_assert_msg(_oidc_strstr(loc, "acr_values=loa3") != NULL,
		      "a non-colliding extra parameter must still be sent");
}
END_TEST

/*
 * OIDCAuthRequestParams is a configuration directive, so unlike the request-supplied variant above
 * it is allowed to override a parameter this module sets itself: the operator asked for it. A "#"
 * value means "forward the same-named parameter of the current request", which is request-supplied
 * whatever the source of the directive, and so is refused an override.
 */
START_TEST(test_proto_auth_request_params_configured) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(r->pool, provider, "client_id");

	/* "login_hint=#" forwards the request's own login_hint; "prompt=#" asks for one the request
	 * does not carry and is left out rather than sent empty; "scope" overrides ours.
	 * NB: written unescaped because the ap_unescape_url stub does not decode. */
	ck_assert_ptr_null(oidc_cfg_provider_auth_request_params_set(
	    r->pool, provider, "login_hint=#&prompt=#&scope=openid profile&extra=configured"));
	r->args = "login_hint=alice%40example.com";

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-cfgparams", ps,
				   NULL, NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);

	ck_assert_msg(_oidc_strstr(loc, "login_hint=alice%40example.com") != NULL,
		      "a \"#\" value must forward the request's own parameter: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "prompt=") == NULL,
		      "a \"#\" value for a parameter the request does not carry must be left out: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "scope=openid%20profile") != NULL,
		      "a configured parameter must be allowed to override ours: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "scope=openid&") == NULL, "and ours must not also be sent: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "extra=configured") != NULL, "a non-colliding one is added: %s", loc);
}
END_TEST

/*
 * a key repeating within the directive itself is not a collision with a parameter this module
 * owns: some parameters are legitimately sent more than once (RFC 8707 sends "resource" once per
 * audience), so the duplicate guard must only fire against parameters that were already in the
 * request before the directive was processed, and every repeated occurrence must reach the
 * provider
 */
START_TEST(test_proto_auth_request_params_repeated_key) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(r->pool, provider, "client_id");

	/* NB: written unescaped because the ap_unescape_url stub does not decode */
	ck_assert_ptr_null(
	    oidc_cfg_provider_auth_request_params_set(r->pool, provider, "resource=urn:example:a&resource=urn:example:b"));

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-repeated", ps, NULL,
				   NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);

	ck_assert_msg(_oidc_strstr(loc, "resource=urn%3Aexample%3Aa") != NULL,
		      "the first occurrence of a repeated parameter must be sent: %s", loc);
	ck_assert_msg(_oidc_strstr(loc, "resource=urn%3Aexample%3Ab") != NULL,
		      "the second occurrence of a repeated parameter must be sent too: %s", loc);
}
END_TEST

/*
 * a Pushed Authorization Request that cannot be made: the OP never advertised the endpoint, or it
 * answers with an error. Either way the user must get an error page rather than a redirect to an
 * authorization request that was never pushed.
 */
START_TEST(test_proto_request_auth_par_failures) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(r->pool, provider, "client_id");
	oidc_cfg_provider_auth_request_method_int_set(provider, OIDC_AUTH_REQUEST_METHOD_PAR);

	/* PAR is requested but the provider metadata never carried a PAR endpoint */
	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-par-1", ps, NULL,
				   NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);

	/* an endpoint that answers with an OAuth error object */
	oidc_test_http_response_t resp = {
	    .status_code = 400, .content_type = "application/json", .body = "{\"error\":\"invalid_request\"}"};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	ck_assert_ptr_null(oidc_cfg_provider_pushed_authorization_request_endpoint_url_set(
	    r->pool, provider, oidc_test_http_server_url(srv, r->pool)));

	ps = e2e_make_proto_state(r);
	rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-par-2", ps, NULL,
			       NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);
	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
}
END_TEST

START_TEST(test_proto_request_auth_post_html) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);

	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(r->pool, provider, "client_id");
	oidc_cfg_provider_auth_request_method_int_set(provider, OIDC_AUTH_REQUEST_METHOD_POST);

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-1", ps, NULL,
				   NULL, NULL, NULL);
	/* POST returns OK with an auto-submitting form rather than a 302 redirect */
	ck_assert_int_eq(rc, OK);
	ck_assert_table_unset(r->headers_out, "Location");
}
END_TEST

START_TEST(test_proto_request_auth_no_client_id) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* fresh provider without client_id => function returns INTERNAL_SERVER_ERROR early */
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);
	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-1", ps, NULL,
				   NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_request_auth_unknown_method) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_create(r->pool);
	oidc_cfg_provider_issuer_set(r->pool, provider, "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(r->pool, provider, "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(r->pool, provider, "client_id");
	/* an out-of-enum value triggers the default branch in the dispatch switch */
	oidc_cfg_provider_auth_request_method_int_set(provider, 999);

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-1", ps, NULL,
				   NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_INTERNAL_SERVER_ERROR);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_jwks_uri_keys_kid_match) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *jwks =
	    "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"use\":\"sig\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t uri = {0};
	uri.uri = oidc_test_http_server_url(srv, r->pool);
	uri.refresh_interval = 60;

	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "HS256", "k1");
	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), TRUE);
	ck_assert_int_eq(apr_hash_count(keys), 1);
	ck_assert_ptr_nonnull(apr_hash_get(keys, "k1", APR_HASH_KEY_STRING));

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
	oidc_jwk_list_destroy_hash(keys);
}
END_TEST

/*
 * the process-local selection cache: the result of picking a key out of the JWKs is kept per
 * (uri, kid, x5t, kty), so validating a second token signed by the same key needs neither the
 * shared cache nor a parse. The second lookup here is served entirely from that cache - the
 * loopback server is already stopped by the time it runs.
 */
START_TEST(test_proto_jwks_uri_keys_selection_cached) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *jwks =
	    "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"use\":\"sig\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t uri = {0};
	uri.uri = oidc_test_http_server_url(srv, r->pool);
	uri.refresh_interval = 60;

	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "HS256", "k1");
	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;

	/* the forced first pass downloads, selects, and stores the selection */
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), TRUE);
	ck_assert_int_eq(apr_hash_count(keys), 1);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);

	/* the second, unforced pass is answered from the selection cache */
	apr_hash_t *cached = apr_hash_make(r->pool);
	force_refresh = FALSE;
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, cached, &force_refresh), TRUE);
	ck_assert_int_eq(apr_hash_count(cached), 1);
	/* the cache stores the selection serialized, so what comes back is this request's own copy,
	 * parsed out of it and owned exactly like the first pass's result - destroyed the same way */
	ck_assert_ptr_nonnull(apr_hash_get(cached, "k1", APR_HASH_KEY_STRING));

	oidc_jwt_destroy(jwt);
	oidc_jwk_list_destroy_hash(keys);
	oidc_jwk_list_destroy_hash(cached);
}
END_TEST

START_TEST(test_proto_jwks_uri_keys_no_kid_include_matching_kty) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* one sig-usable oct key plus one enc-usable oct key that must be skipped */
	const char *jwks = "{\"keys\":["
			   "{\"kty\":\"oct\",\"kid\":\"sigkey\",\"use\":\"sig\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"},"
			   "{\"kty\":\"oct\",\"kid\":\"enckey\",\"use\":\"enc\",\"k\":\"EBEPDg0MCwoJCAcGBQQDAgEA\"}"
			   "]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t uri = {0};
	uri.uri = oidc_test_http_server_url(srv, r->pool);
	uri.refresh_interval = 60;

	/* no kid in the JWT => "any sig-usable matching kty" branch */
	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "HS256", NULL);
	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), TRUE);
	/* only the sig-usable key is included */
	ck_assert_int_eq(apr_hash_count(keys), 1);
	ck_assert_ptr_nonnull(apr_hash_get(keys, "sigkey", APR_HASH_KEY_STRING));

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
	oidc_jwk_list_destroy_hash(keys);
}
END_TEST

START_TEST(test_proto_jwks_uri_keys_no_match_after_refresh) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* the JWKS has key kid=k1, but the JWT asks for kid=k2 — no match found.
	 * The function refreshes once and then returns TRUE with an empty result. */
	const char *jwks = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t uri = {0};
	uri.uri = oidc_test_http_server_url(srv, r->pool);
	uri.refresh_interval = 60;

	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "HS256", "k2");
	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), TRUE);
	ck_assert_int_eq(apr_hash_count(keys), 0);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_jwks_uri_keys_http_failure) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	int port = oidc_test_http_free_port(r->pool);
	ck_assert_int_ne(port, 0);
	oidc_jwks_uri_t uri = {0};
	uri.uri = apr_psprintf(r->pool, "http://127.0.0.1:%d/jwks", port);
	uri.refresh_interval = 60;

	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "HS256", "k1");
	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;
	/* nothing listening => oidc_metadata_jwks_get returns no JSON => FALSE */
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), FALSE);

	oidc_jwt_destroy(jwt);
}
END_TEST

/* no kid in the JWT and no "kid" on the matching JWKS entry either: oidc_proto_jwks_key_include_any
 * falls back to indexing the result hash by the entry's ordinal position */
START_TEST(test_proto_jwks_uri_keys_no_kid_no_kid_field) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *jwks = "{\"keys\":[{\"kty\":\"oct\",\"use\":\"sig\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t uri = {0};
	uri.uri = oidc_test_http_server_url(srv, r->pool);
	uri.refresh_interval = 60;

	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "HS256", NULL);
	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), TRUE);
	ck_assert_int_eq(apr_hash_count(keys), 1);
	/* indexed by ordinal "0" since neither the JWT nor the JWK entry carries a kid */
	ck_assert_ptr_nonnull(apr_hash_get(keys, "0", APR_HASH_KEY_STRING));

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
	oidc_jwk_list_destroy_hash(keys);
}
END_TEST

/* a JWKS entry that fails to parse (no recognizable "kty") must be skipped rather than aborting
 * the whole lookup; the well-formed sibling entry is still found */
START_TEST(test_proto_jwks_uri_keys_malformed_entry_skipped) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *jwks = "{\"keys\":["
			   "{\"kid\":\"bad1\"},"
			   "{\"kty\":\"oct\",\"kid\":\"k1\",\"use\":\"sig\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}"
			   "]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t uri = {0};
	uri.uri = oidc_test_http_server_url(srv, r->pool);
	uri.refresh_interval = 60;

	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "HS256", "k1");
	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), TRUE);
	ck_assert_int_eq(apr_hash_count(keys), 1);
	ck_assert_ptr_nonnull(apr_hash_get(keys, "k1", APR_HASH_KEY_STRING));

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
	oidc_jwk_list_destroy_hash(keys);
}
END_TEST

/* a JWKS entry whose key type cannot match the JWT's algorithm at all (RS256 => RSA, but the
 * entry is oct) is skipped by the kty guard before the kid is ever compared */
START_TEST(test_proto_jwks_uri_keys_kty_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *jwks =
	    "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"use\":\"sig\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t uri = {0};
	uri.uri = oidc_test_http_server_url(srv, r->pool);
	uri.refresh_interval = 60;

	/* alg=RS256 => the JWT wants an RSA key, but the only JWKS entry is oct */
	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "RS256", "k1");
	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), TRUE);
	ck_assert_int_eq(apr_hash_count(keys), 0);

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_jwt_destroy(jwt);
}
END_TEST

/* a JWT that carries an x5t thumbprint instead of a kid is matched against the JWKS entries'
 * "x5t" fields once the kid comparison fails to find anything */
START_TEST(test_proto_jwks_uri_keys_x5t_match) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *jwks = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"use\":\"sig\",\"x5t\":\"thumb-1\","
			   "\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}]}";
	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/json", .body = jwks};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);

	oidc_jwks_uri_t uri = {0};
	uri.uri = oidc_test_http_server_url(srv, r->pool);
	uri.refresh_interval = 60;

	/* no kid on the JWT, only an x5t that matches the JWKS entry's "x5t" field; oidc_jwt_hdr_get
	 * (unlike the kid comparison, which reads the plain struct field) reads back from the cjose
	 * protected header, so the x5t must actually be signed in rather than just set on the struct */
	oidc_jwt_t *jwt = e2e_make_jwt_for_kid(r->pool, "HS256", NULL);
	jwt->header.x5t = apr_pstrdup(r->pool, "thumb-1");
	oidc_jose_error_t sign_err;
	unsigned char sign_key[32];
	for (int i = 0; i < 32; i++)
		sign_key[i] = (unsigned char)(i + 1);
	oidc_jwk_t *sign_jwk = oidc_jwk_create_symmetric_key(r->pool, NULL, sign_key, 32, FALSE, &sign_err);
	ck_assert_ptr_nonnull(sign_jwk);
	ck_assert_msg(oidc_jwt_sign(r->pool, jwt, sign_jwk, FALSE, &sign_err) == TRUE, "oidc_jwt_sign failed: %s",
		      oidc_jose_e2s(r->pool, sign_err));
	oidc_jwk_destroy(sign_jwk);

	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_byte_t force_refresh = TRUE;
	ck_assert_int_eq(oidc_proto_jwks_uri_keys(r, c, jwt, &uri, 0, keys, &force_refresh), TRUE);
	ck_assert_int_eq(apr_hash_count(keys), 1);
	ck_assert_ptr_nonnull(apr_hash_get(keys, "thumb-1", APR_HASH_KEY_STRING));

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	/* the "thumb-1" hash key is oidc_proto_jwks_key_apply's x5t pointer, which points into jwt's
	 * own protected header (owned by jwt->cjose_jws) -- the hash must be torn down before the jwt
	 * that backs its key, not after */
	oidc_jwk_list_destroy_hash(keys);
	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_supported_flows_exhaustive) {
	apr_pool_t *pool = oidc_test_pool_get();
	/* every documented flow round-trips through flow_is_supported */
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, OIDC_PROTO_RESPONSE_TYPE_CODE), TRUE);
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN), TRUE);
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN), TRUE);
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN), TRUE);
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN), TRUE);
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN), TRUE);
	/* token-only (implicit-only) is not in the supported set */
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, OIDC_PROTO_RESPONSE_TYPE_TOKEN), FALSE);
	/* spacing/order independence: spaced_string_equals normalizes whitespace order */
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, "token id_token"), TRUE);
	ck_assert_int_eq(oidc_proto_flow_is_supported(pool, ""), FALSE);
}
END_TEST

/*
 * Additional response.c / dpop.c tests — exercise the early-failure branches
 * in each response-type handler (where the static validate_response_type_mode_issuer
 * rejects mismatched params) and the happy-path of oidc_proto_dpop_create when
 * a private signing key is available.
 */

START_TEST(test_proto_response_code_idtoken_missing_code) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_jwt_t *jwt = NULL;
	apr_table_t *params = apr_table_make(r->pool, 0);

	/* "code id_token" handler requires both code and id_token in params; empty
	 * params trigger validate_response_type's "missing code" branch => FALSE */
	ck_assert_int_eq(
	    oidc_proto_response_code_idtoken(r, c, ps, provider, params, OIDC_PROTO_RESPONSE_MODE_FRAGMENT, &jwt),
	    FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_response_code_token_missing_code) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_jwt_t *jwt = NULL;
	apr_table_t *params = apr_table_make(r->pool, 0);

	ck_assert_int_eq(
	    oidc_proto_response_code_token(r, c, ps, provider, params, OIDC_PROTO_RESPONSE_MODE_FRAGMENT, &jwt), FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_response_code_idtoken_token_missing_params) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_jwt_t *jwt = NULL;
	apr_table_t *params = apr_table_make(r->pool, 0);

	ck_assert_int_eq(
	    oidc_proto_response_code_idtoken_token(r, c, ps, provider, params, OIDC_PROTO_RESPONSE_MODE_FRAGMENT, &jwt),
	    FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_response_idtoken_token_missing_params) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_jwt_t *jwt = NULL;
	apr_table_t *params = apr_table_make(r->pool, 0);

	ck_assert_int_eq(
	    oidc_proto_response_idtoken_token(r, c, ps, provider, params, OIDC_PROTO_RESPONSE_MODE_FRAGMENT, &jwt),
	    FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_response_code_iss_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_jwt_t *jwt = NULL;

	/* iss in the params does not match the configured provider issuer =>
	 * validate_issuer_client_id rejects it before any other check */
	apr_table_t *params = apr_table_make(r->pool, 2);
	apr_table_set(params, OIDC_PROTO_CODE, "the-code");
	apr_table_set(params, OIDC_PROTO_ISS, "https://wrong.example.com");

	ck_assert_int_eq(oidc_proto_response_code(r, c, ps, provider, params, OIDC_PROTO_RESPONSE_MODE_QUERY, &jwt),
			 FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_response_code_client_id_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_jwt_t *jwt = NULL;

	apr_table_t *params = apr_table_make(r->pool, 2);
	apr_table_set(params, OIDC_PROTO_CODE, "the-code");
	apr_table_set(params, OIDC_PROTO_CLIENT_ID, "wrong-client");

	ck_assert_int_eq(oidc_proto_response_code(r, c, ps, provider, params, OIDC_PROTO_RESPONSE_MODE_QUERY, &jwt),
			 FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_response_code_response_mode_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_jwt_t *jwt = NULL;

	/* request explicitly asks for response_mode=query but the OP responds
	 * via fragment => validate_response_mode rejects */
	oidc_proto_state_set_response_mode(ps, OIDC_PROTO_RESPONSE_MODE_QUERY);
	apr_table_t *params = apr_table_make(r->pool, 1);
	apr_table_set(params, OIDC_PROTO_CODE, "the-code");

	ck_assert_int_eq(oidc_proto_response_code(r, c, ps, provider, params, OIDC_PROTO_RESPONSE_MODE_FRAGMENT, &jwt),
			 FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_response_code_unexpected_id_token) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);
	oidc_proto_state_t *ps = oidc_proto_state_new();
	oidc_jwt_t *jwt = NULL;

	/* "code" response_type must NOT carry an id_token in params — covers the
	 * "response contains an unexpected id_token" branch */
	apr_table_t *params = apr_table_make(r->pool, 2);
	apr_table_set(params, OIDC_PROTO_CODE, "the-code");
	apr_table_set(params, OIDC_PROTO_ID_TOKEN, "unexpected");

	ck_assert_int_eq(oidc_proto_response_code(r, c, ps, provider, params, OIDC_PROTO_RESPONSE_MODE_QUERY, &jwt),
			 FALSE);
	oidc_proto_state_destroy(ps);
}
END_TEST

START_TEST(test_proto_dpop_create_with_rsa_private_key) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	/* load test/private.pem so cfg->private_keys has an RSA signing key */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	const char *err = oidc_cmd_private_keys_set(
	    cmd, NULL, apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir)));
	ck_assert_msg(err == NULL, "could not load private key: %s", err);

	/* DPoP proof with access_token + nonce => exercises both optional branches
	 * (ath claim and nonce claim) on top of the happy-path JWT sign+serialize */
	char *dpop = NULL;
	ck_assert_int_eq(oidc_proto_dpop_create(r, c, "https://idp.example.com/token", "POST", "the-access-token",
						"the-dpop-nonce", &dpop),
			 TRUE);
	ck_assert_ptr_nonnull(dpop);

	/* the serialized JWT has 3 dot-separated segments */
	const char *first = _oidc_strstr(dpop, ".");
	ck_assert_ptr_nonnull(first);
	const char *second = _oidc_strstr(first + 1, ".");
	ck_assert_ptr_nonnull(second);

	/* decode the header and confirm typ=dpop+jwt; parse it as JSON rather than
	 * substring-matching, since cjose's header serialization (e.g. the whitespace
	 * after the colon) differs across cjose versions */
	char *enc_hdr = apr_pstrmemdup(r->pool, dpop, first - dpop);
	char *dec_hdr = NULL;
	ck_assert_int_gt(oidc_util_base64url_decode(r->pool, &dec_hdr, enc_hdr), 0);
	oidc_json_t *hdr_json = NULL;
	ck_assert_int_eq(oidc_json_decode_object(r, dec_hdr, &hdr_json), TRUE);
	ck_assert_str_eq(oidc_json_string_value(oidc_json_object_get(hdr_json, "typ")), "dpop+jwt");
	oidc_json_decref(hdr_json);
}
END_TEST

/* build an HS256-signed JWT payload using the symmetric key derived from `secret`;
 * shared helper for the JWT-userinfo-response test */
static char *e2e_sign_jwt_hs256_payload(request_rec *r, const char *secret, oidc_json_t *payload) {
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	ck_assert_int_eq(oidc_util_key_symmetric_create(r, secret, 0, NULL, TRUE, &jwk), TRUE);
	oidc_jwt_t *jwt = oidc_jwt_new(r->pool, TRUE, TRUE);
	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	json_object_update(jwt->payload.value.json, payload);
	ck_assert_int_eq(oidc_jwt_sign(r->pool, jwt, jwk, FALSE, &err), TRUE);
	char *cser = oidc_jose_jwt_serialize(r->pool, jwt, &err);
	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
	return cser;
}

START_TEST(test_proto_userinfo_request_signed_jwt_response) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* configure HS256 signed userinfo responses; client_secret doubles as the HMAC key */
	const char *secret = "userinfo-signed-response-secret-long";
	oidc_cfg_provider_client_secret_set(r->pool, provider, secret);
	ck_assert_ptr_null(oidc_cfg_provider_userinfo_signed_response_alg_set(r->pool, provider, "HS256"));

	oidc_json_t *payload = json_pack("{s:s,s:s}", "sub", "alice", "name", "Alice JWT");
	char *jwt_str = e2e_sign_jwt_hs256_payload(r, secret, payload);
	oidc_json_decref(payload);

	oidc_test_http_response_t resp = {.status_code = 200, .content_type = "application/jwt", .body = jwt_str};
	oidc_test_http_server_t *srv = oidc_test_http_server_start(r->pool, &resp);
	ck_assert_ptr_nonnull(srv);
	oidc_cfg_provider_userinfo_endpoint_url_set(r->pool, provider, oidc_test_http_server_url(srv, r->pool));
	oidc_cfg_provider_ssl_validate_server_set(r->pool, provider, 0);

	char *s_userinfo = NULL, *userinfo_jwt = NULL;
	oidc_json_t *userinfo_claims = NULL;
	long response_code = 0;
	/* the JWT-decoding path in oidc_proto_userinfo_response_jwt_parse must extract claims */
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);
	ck_assert_ptr_nonnull(userinfo_jwt);
	ck_assert_str_eq(userinfo_jwt, jwt_str);
	const char *name = oidc_json_string_value(oidc_json_object_get(userinfo_claims, "name"));
	ck_assert_ptr_nonnull(name);
	ck_assert_str_eq(name, "Alice JWT");

	(void)oidc_test_http_server_wait(srv);
	oidc_test_http_server_stop(srv);
	oidc_json_decref(userinfo_claims);
}
END_TEST

START_TEST(test_proto_request_auth_with_copy_and_remove_from_request) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	/* same shape as the request_object_rs256 test but with copy_and_remove_from_request
	 * including "state" — this exercises oidc_request_uri_delete_from_request */
	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(
	    cmd, NULL, apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-sig#%s/private.pem", dir))));

	oidc_cfg_provider_request_object_set(
	    r->pool, provider, "{\"crypto\":{\"sign_alg\":\"RS256\"},\"copy_and_remove_from_request\":[\"state\"]}");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "state-to-strip", ps,
				   NULL, NULL, NULL, NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);
	ck_assert_msg(_oidc_strstr(loc, "request_uri=") != NULL, "request_uri= parameter must appear in the URL");
	/* state was marked copy_and_remove => it must have been stripped from the redirect */
	ck_assert_msg(_oidc_strstr(loc, "state=") == NULL, "state= must have been removed from the URL, got: %s", loc);
}
END_TEST

/* run an authorization request with an embedded (request=) unsigned (alg=none) request object
 * that copies the custom "client_ref=1234" parameter and the spec-defined "state=98765"
 * parameter via copy_from_request, then extract the request object from the authorization URL
 * and return its decoded JSON payload */
static oidc_json_t *e2e_request_object_copy_params_payload(request_rec *r) {
	oidc_cfg_t *c = oidc_test_cfg_get();
	oidc_provider_t *provider = oidc_cfg_provider_get(c);

	oidc_cfg_provider_request_object_set(r->pool, provider,
					     "{\"crypto\":{\"sign_alg\":\"none\"},\"request_object_type\":\"request\","
					     "\"copy_from_request\":[\"client_ref\",\"state\"]}");

	oidc_proto_state_t *ps = e2e_make_proto_state(r);
	int rc = oidc_request_auth(r, c, provider, NULL, "https://www.example.com/protected/", "98765", ps, NULL, NULL,
				   "client_ref=1234", NULL);
	ck_assert_int_eq(rc, HTTP_MOVED_TEMPORARILY);
	const char *loc = apr_table_get(r->headers_out, "Location");
	ck_assert_ptr_nonnull(loc);

	/* pull the embedded request object out of the request= parameter */
	const char *jwt = _oidc_strstr(loc, "&request=");
	ck_assert_msg(jwt != NULL, "request= parameter must appear in the authorization URL: %s", loc);
	jwt += _oidc_strlen("&request=");
	const char *amp = _oidc_strstr(jwt, "&");
	if (amp != NULL)
		jwt = apr_pstrmemdup(r->pool, jwt, amp - jwt);

	/* decode the payload section of the (unsigned) compact JWT */
	const char *dot1 = _oidc_strstr(jwt, ".");
	ck_assert_ptr_nonnull(dot1);
	const char *dot2 = _oidc_strstr(dot1 + 1, ".");
	ck_assert_ptr_nonnull(dot2);
	char *s_payload = NULL;
	ck_assert_int_gt(
	    oidc_util_base64url_decode(r->pool, &s_payload, apr_pstrmemdup(r->pool, dot1 + 1, dot2 - (dot1 + 1))), 0);

	oidc_json_t *payload = json_loads(s_payload, 0, NULL);
	ck_assert_ptr_nonnull(payload);
	return payload;
}

START_TEST(test_proto_request_auth_request_object_copy_param_types) {
	request_rec *r = oidc_test_request_get();

	oidc_json_t *payload = e2e_request_object_copy_params_payload(r);

	/* a custom parameter value that parses as JSON is interpreted as its JSON type */
	oidc_json_t *v = oidc_json_object_get(payload, "client_ref");
	ck_assert_ptr_nonnull(v);
	ck_assert_msg(oidc_json_is_integer(v), "copied request parameter must be a JSON integer, got JSON type %d",
		      oidc_json_typeof(v));
	ck_assert_int_eq((int)oidc_json_integer_value(v), 1234);

	/* parameters defined as strings in the OpenID Connect specification (such as "state")
	 * must be copied verbatim as JSON strings, never as another JSON type */
	v = oidc_json_object_get(payload, "state");
	ck_assert_ptr_nonnull(v);
	ck_assert_msg(oidc_json_is_string(v), "copied state parameter must be a JSON string, got JSON type %d",
		      oidc_json_typeof(v));
	ck_assert_str_eq(oidc_json_string_value(v), "98765");

	oidc_json_decref(payload);
}
END_TEST

START_TEST(test_proto_dpop_create_no_access_token_no_nonce) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();

	const char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	cmd_parms *cmd = oidc_test_cmd_get(OIDCPrivateKeyFiles);
	ck_assert_ptr_null(oidc_cmd_private_keys_set(
	    cmd, NULL, apr_pstrdup(r->pool, apr_psprintf(r->pool, "rsa-1#%s/private.pem", dir))));

	/* no access_token, no nonce => skips both optional claims */
	char *dpop = NULL;
	ck_assert_int_eq(oidc_proto_dpop_create(r, c, "https://idp.example.com/token", "POST", NULL, NULL, &dpop),
			 TRUE);
	ck_assert_ptr_nonnull(dpop);
}
END_TEST

int main(void) {
	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(core, test_proto_validate_access_token);
	tcase_add_test(core, test_proto_validate_code);
	tcase_add_test(core, test_proto_authorization_request);
	tcase_add_test(core, test_logout_request);
	tcase_add_test(core, test_proto_validate_nonce);
	tcase_add_test(core, test_proto_validate_jwt);
	tcase_add_test(core, test_proto_nonce_and_jti);
	tcase_add_test(core, test_proto_supported_flows_and_check);
	tcase_add_test(core, test_proto_state_getters_setters_and_string);
	tcase_add_test(core, test_proto_state_cookie_roundtrip);
	tcase_add_test(core, test_proto_pkce_plain_and_s256);
	tcase_add_test(core, test_proto_profile_helpers);
	tcase_add_test(core, test_proto_profile_auth_request_method);
	tcase_add_test(core, test_proto_profile_id_token_aud_values);
	tcase_add_test(core, test_proto_profile_revocation_aud_variants);
	tcase_add_test(core, test_proto_pkce_none);
	tcase_add_test(core, test_proto_token_endpoint_auth_no_client_id);
	tcase_add_test(core, test_proto_token_endpoint_auth_basic_and_post);
	tcase_add_test(core, test_proto_token_endpoint_auth_bearer);
	tcase_add_test(core, test_proto_token_endpoint_auth_mtls);
	tcase_add_test(core, test_proto_token_endpoint_auth_unknown_method);
	tcase_add_test(core, test_proto_token_endpoint_auth_client_secret_jwt);
	tcase_add_test(core, test_proto_token_endpoint_auth_private_key_jwt_no_keys);
	tcase_add_test(core, test_proto_token_endpoint_auth_private_key_jwt_with_rsa_key);
	tcase_add_test(core, test_proto_token_endpoint_auth_private_key_jwt_explicit_alg);
	tcase_add_test(core, test_proto_token_endpoint_auth_private_key_jwt_client_keys);
	tcase_add_test(core, test_proto_token_endpoint_auth_client_secret_jwt_empty_secret);
	tcase_add_test(core, test_proto_token_endpoint_auth_private_key_jwt_unsupported_key_type);
	tcase_add_test(core, test_proto_token_endpoint_auth_idempotent);
	tcase_add_test(core, test_proto_jwt_validate_edge_cases);
	tcase_add_test(core, test_proto_idtoken_parse_error_paths);
	tcase_add_test(core, test_proto_idtoken_parse_alg_none);
	tcase_add_test(core, test_proto_jwt_verify_paths);
	tcase_add_test(core, test_proto_validate_hash_error_paths);
	tcase_add_test(core, test_proto_state_timestamp_and_bad_cookie);
	tcase_add_test(core, test_proto_nonce_uniqueness);
	tcase_add_test(core, test_proto_flow_unsupported);
	tcase_add_test(core, test_proto_dpop_create_without_private_keys);
	tcase_add_test(core, test_proto_dpop_create_embeds_public_key_only);
	tcase_add_test(core, test_proto_jwt_header_peek);
	tcase_add_test(core, test_proto_response_is_post_and_redirect);
	tcase_add_test(core, test_proto_return_www_authenticate_header);
	tcase_add_test(core, test_proto_idtoken_validate_aud_string_match);
	tcase_add_test(core, test_proto_idtoken_validate_aud_string_mismatch);
	tcase_add_test(core, test_proto_idtoken_validate_aud_array_with_client_id);
	tcase_add_test(core, test_proto_idtoken_validate_aud_array_without_client_id);
	tcase_add_test(core, test_proto_idtoken_validate_aud_missing);
	tcase_add_test(core, test_proto_idtoken_validate_aud_wrong_type);
	tcase_add_test(core, test_proto_idtoken_validate_aud_values_string_special_at);
	tcase_add_test(core, test_proto_idtoken_validate_aud_values_string_no_match);
	tcase_add_test(core, test_proto_idtoken_validate_aud_values_array_exhaustive_match);
	tcase_add_test(core, test_proto_idtoken_validate_aud_values_array_missing_configured);
	tcase_add_test(core, test_proto_idtoken_validate_aud_values_array_untrusted_extra);
	tcase_add_test(core, test_proto_idtoken_validate_azp_mismatch);
	tcase_add_test(core, test_proto_dpop_use_nonce_no_error_claim);
	tcase_add_test(core, test_proto_dpop_use_nonce_wrong_error_value);
	tcase_add_test(core, test_proto_dpop_use_nonce_missing_header);
	tcase_add_test(core, test_proto_discovery_account_no_at_sign);
	tcase_add_test(core, test_proto_discovery_account_unreachable_endpoint);
	tcase_add_test(core, test_proto_discovery_url_unreachable_endpoint);
	tcase_add_test(core, test_proto_webfinger_response_get_issuer_happy);
	tcase_add_test(core, test_proto_webfinger_response_get_issuer_invalid_json);
	tcase_add_test(core, test_proto_webfinger_response_get_issuer_missing_links);
	tcase_add_test(core, test_proto_webfinger_response_get_issuer_links_not_array);
	tcase_add_test(core, test_proto_webfinger_response_get_issuer_first_link_not_object);
	tcase_add_test(core, test_proto_webfinger_response_get_issuer_missing_href);
	tcase_add_test(core, test_proto_webfinger_response_get_issuer_href_not_https);
	tcase_add_test(core, test_proto_supported_flows_exhaustive);
	tcase_add_test(core, test_proto_response_code_idtoken_missing_code);
	tcase_add_test(core, test_proto_response_code_token_missing_code);
	tcase_add_test(core, test_proto_response_code_idtoken_token_missing_params);
	tcase_add_test(core, test_proto_response_idtoken_token_missing_params);
	tcase_add_test(core, test_proto_response_code_iss_mismatch);
	tcase_add_test(core, test_proto_response_code_client_id_mismatch);
	tcase_add_test(core, test_proto_response_code_response_mode_mismatch);
	tcase_add_test(core, test_proto_response_code_unexpected_id_token);
	tcase_add_test(core, test_proto_dpop_create_with_rsa_private_key);
	tcase_add_test(core, test_proto_dpop_create_no_access_token_no_nonce);

	TCase *e2e = tcase_create("e2e_proto");
	tcase_add_checked_fixture(e2e, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(e2e, 30);
	tcase_add_test(e2e, test_proto_token_endpoint_request_success);
	tcase_add_test(e2e, test_proto_token_endpoint_request_error);
	tcase_add_test(e2e, test_proto_token_refresh_request_success);
	tcase_add_test(e2e, test_proto_token_endpoint_request_unsupported_token_type);
	tcase_add_test(e2e, test_proto_token_endpoint_request_dpop_required_but_bearer);
	tcase_add_test(e2e, test_proto_token_endpoint_request_dpop_required_but_missing_token_type);
	tcase_add_test(e2e, test_proto_token_endpoint_request_dpop_nonce_retry_new_assertion);
	tcase_add_test(e2e, test_proto_response_code_missing_access_token);
	tcase_add_test(e2e, test_proto_response_code_idtoken_happy);
	tcase_add_test(e2e, test_proto_response_code_token_happy);
	tcase_add_test(e2e, test_proto_response_code_token_missing_id_token);
	tcase_add_test(e2e, test_proto_response_code_idtoken_token_happy);
	tcase_add_test(e2e, test_proto_response_idtoken_token_happy);
	tcase_add_test(e2e, test_proto_response_type_mismatch);
	tcase_add_test(e2e, test_proto_userinfo_request_composite_claims);
	tcase_add_test(e2e, test_proto_userinfo_request_dpop);
	tcase_add_test(e2e, test_proto_userinfo_request_success);
	tcase_add_test(e2e, test_proto_userinfo_request_sub_mismatch);
	tcase_add_test(e2e, test_proto_userinfo_request_error);
	tcase_add_test(e2e, test_proto_userinfo_request_post_method);
	tcase_add_test(e2e, test_proto_userinfo_request_missing_sub_required);
	tcase_add_test(e2e, test_proto_userinfo_request_missing_sub_skipped_via_env);
	tcase_add_test(e2e, test_proto_userinfo_request_composite_embedded_jwt);
	tcase_add_test(e2e, test_proto_userinfo_request_composite_names_without_sources);
	tcase_add_test(e2e, test_proto_userinfo_response_garbage);
	tcase_add_test(e2e, test_proto_userinfo_response_jwt_no_alg_configured);
	tcase_add_test(e2e, test_proto_userinfo_response_signed_jwt);
	tcase_add_test(e2e, test_proto_userinfo_response_signed_jwt_bad_signature);
	tcase_add_test(e2e, test_proto_userinfo_response_encrypted_jwt);
	tcase_add_test(e2e, test_proto_userinfo_response_encrypted_jwt_decrypt_fails);
	tcase_add_test(e2e, test_proto_userinfo_request_composite_negatives);
	tcase_add_test(e2e, test_proto_userinfo_request_dpop_nonce_retry);
	tcase_add_test(e2e, test_proto_userinfo_request_dpop_nonce_retry_still_error);
	tcase_add_test(e2e, test_proto_userinfo_response_jwt_body_unparsable);
	tcase_add_test(e2e, test_proto_userinfo_response_jwt_no_client_secret);
	tcase_add_test(e2e, test_proto_userinfo_endpoint_call_negatives);
	tcase_add_test(e2e, test_proto_userinfo_request_dpop_plain_error);
	tcase_add_test(e2e, test_proto_userinfo_request_dpop_retry_garbage);
	tcase_add_test(e2e, test_proto_request_auth_par_redirect);
	tcase_add_test(e2e, test_proto_private_keys_load_from_pem);
	tcase_add_test(e2e, test_proto_request_auth_with_request_object_none);
	tcase_add_test(e2e, test_proto_request_auth_with_request_object_rs256);
	tcase_add_test(e2e, test_proto_request_auth_request_object_type);
	tcase_add_test(e2e, test_proto_request_auth_request_object_signing_keys);
	tcase_add_test(e2e, test_proto_request_auth_request_object_url_override);
	tcase_add_test(e2e, test_proto_request_auth_with_request_object_encrypted_symmetric);
	tcase_add_test(e2e, test_proto_request_auth_with_request_object_encrypted_rsa);
	tcase_add_test(e2e, test_proto_request_auth_with_request_object_encrypt_bad_alg);
	tcase_add_test(e2e, test_proto_request_auth_with_copy_and_remove_from_request);
	tcase_add_test(e2e, test_proto_request_auth_request_object_copy_param_types);
	tcase_add_test(e2e, test_proto_userinfo_request_signed_jwt_response);
	tcase_add_test(e2e, test_proto_auth_request_params_cannot_duplicate_ours);
	tcase_add_test(e2e, test_proto_auth_request_params_configured);
	tcase_add_test(e2e, test_proto_auth_request_params_repeated_key);
	tcase_add_test(e2e, test_proto_request_auth_par_failures);
	tcase_add_test(e2e, test_proto_request_auth_post_html);
	tcase_add_test(e2e, test_proto_request_auth_no_client_id);
	tcase_add_test(e2e, test_proto_request_auth_unknown_method);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_kid_match);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_selection_cached);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_no_kid_include_matching_kty);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_no_match_after_refresh);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_http_failure);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_no_kid_no_kid_field);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_malformed_entry_skipped);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_kty_mismatch);
	tcase_add_test(e2e, test_proto_jwks_uri_keys_x5t_match);

	Suite *s = suite_create("proto");
	suite_add_tcase(s, core);
	suite_add_tcase(s, e2e);

	return oidc_test_suite_run(s);
}
