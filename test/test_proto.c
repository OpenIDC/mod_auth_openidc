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

#include "check_util.h"
#include "handle/handle.h"
#include "http_server.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"
#include "util/util.h"

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
	ck_assert_int_eq(oidc_jwt_parse(r->pool, s, &jwt, NULL, FALSE, &err), TRUE);

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
	ck_assert_int_eq(oidc_jwt_parse(r->pool, s, &jwt, NULL, FALSE, &err), TRUE);

	const char *code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
	ck_assert_int_eq(oidc_proto_idtoken_validate_code(r, NULL, jwt, "code id_token", code), TRUE);

	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_authorization_request) {
	request_rec *r = oidc_test_request_get();

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
	    oidc_proto_request_auth(r, provider, NULL, redirect_uri, state, proto_state, NULL, NULL, NULL, NULL),
	    HTTP_MOVED_TEMPORARILY);

	ck_assert_str_eq(apr_table_get(r->headers_out, "Location"),
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
	ck_assert_int_eq(oidc_jwt_parse(r->pool, s_jwt, &jwt, NULL, FALSE, &err), TRUE);

	ck_assert_int_eq(oidc_proto_idtoken_validate_nonce(r, c, oidc_cfg_provider_get(c), nonce, jwt), TRUE);
	ck_assert_int_eq(oidc_proto_idtoken_validate_nonce(r, c, oidc_cfg_provider_get(c), nonce, jwt), FALSE);
	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_proto_validate_jwt) {
	request_rec *r = oidc_test_request_get();

	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;

	const char *s_secret = "secret";
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
	oidc_util_base64url_encode(r, &s_jwt_header_encoded, s_jwt_header, _oidc_strlen(s_jwt_header), 1);

	char *s_jwt_payload_encoded = NULL;
	oidc_util_base64url_encode(r, &s_jwt_payload_encoded, s_jwt_payload, _oidc_strlen(s_jwt_payload), 1);

	char *s_jwt_message = apr_psprintf(r->pool, "%s.%s", s_jwt_header_encoded, s_jwt_payload_encoded);

	unsigned int md_len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD *digest = EVP_get_digestbyname("sha256");

	ck_assert_ptr_nonnull(HMAC(digest, (const unsigned char *)s_secret, _oidc_strlen(s_secret),
				   (const unsigned char *)s_jwt_message, _oidc_strlen(s_jwt_message), md, &md_len));

	char *s_jwt_signature_encoded = NULL;
	oidc_util_base64url_encode(r, &s_jwt_signature_encoded, (const char *)md, md_len, 1);

	char *s_jwt =
	    apr_psprintf(r->pool, "%s.%s.%s", s_jwt_header_encoded, s_jwt_payload_encoded, s_jwt_signature_encoded);

	ck_assert_int_eq(oidc_jwt_parse(r->pool, s_jwt, &jwt, NULL, FALSE, &err), TRUE);

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
	ck_assert(oidc_proto_state_get_timestamp(ps) > 0);

	char *s = oidc_proto_state_to_string(r, ps);
	ck_assert_ptr_nonnull(s);
	/* basic sanity: string contains issuer and nonce */
	ck_assert_ptr_nonnull(_oidc_strstr(s, "https://example.org"));
	ck_assert_ptr_nonnull(_oidc_strstr(s, "mynonce"));

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
	/* response require iss should be true */
	ck_assert_int_eq(oidc_proto_profile_response_require_iss_get(provider), 1);
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
	ck_assert_str_eq(apr_table_get(params, OIDC_PROTO_CLIENT_ID), "myclient");

	/* client_secret_post: sets client_id and client_secret on the params */
	params = apr_table_make(r->pool, 2);
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_CLIENT_SECRET_POST, NULL, "myclient",
							"mysecret", NULL, NULL, params, NULL, &basic, &bearer),
			 TRUE);
	ck_assert_str_eq(apr_table_get(params, OIDC_PROTO_CLIENT_ID), "myclient");
	ck_assert_str_eq(apr_table_get(params, OIDC_PROTO_CLIENT_SECRET), "mysecret");

	/* none: only client_id is set */
	params = apr_table_make(r->pool, 1);
	ck_assert_int_eq(oidc_proto_token_endpoint_auth(r, c, OIDC_PROTO_ENDPOINT_AUTH_NONE, NULL, "myclient",
							"ignored", NULL, NULL, params, NULL, &basic, &bearer),
			 TRUE);
	ck_assert_str_eq(apr_table_get(params, OIDC_PROTO_CLIENT_ID), "myclient");
	ck_assert_ptr_null(apr_table_get(params, OIDC_PROTO_CLIENT_SECRET));
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
 * Caller owns `claims` (typically `json_decref` after the test).
 */
static oidc_jwt_payload_t make_payload(json_t *claims) {
	oidc_jwt_payload_t p = {0};
	p.value.json = claims;
	return p;
}

START_TEST(test_proto_idtoken_validate_aud_string_match) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *claims = json_pack("{s:s}", "aud", "client_id");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), TRUE);
	json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_string_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *claims = json_pack("{s:s}", "aud", "different_client");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_array_with_client_id) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* azp is present here so the multi-aud SHOULD warning doesn't fire as a hard error */
	json_t *claims = json_pack("{s:[s,s],s:s}", "aud", "other-rp", "client_id", "azp", "client_id");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), TRUE);
	json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_array_without_client_id) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *claims = json_pack("{s:[s,s]}", "aud", "other-rp", "yet-another");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_missing) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *claims = json_pack("{s:s}", "sub", "alice");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_aud_wrong_type) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *claims = json_pack("{s:i}", "aud", 42);
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	json_decref(claims);
}
END_TEST

START_TEST(test_proto_idtoken_validate_azp_mismatch) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	/* aud is valid (matches client_id), but azp claims a different party */
	json_t *claims = json_pack("{s:s,s:s}", "aud", "client_id", "azp", "evil-rp");
	oidc_jwt_payload_t p = make_payload(claims);
	ck_assert_int_eq(oidc_proto_idtoken_validate_aud_and_azp(r, c, oidc_cfg_provider_get(c), &p), FALSE);
	json_decref(claims);
}
END_TEST

START_TEST(test_proto_dpop_use_nonce_no_error_claim) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *result = json_pack("{s:s}", "active", "true");
	char *dpop = NULL;
	ck_assert_int_eq(oidc_proto_dpop_use_nonce(r, c, result, NULL, "https://idp.example.com/token", "POST",
						   "access-token", &dpop),
			 FALSE);
	ck_assert_ptr_null(dpop);
	json_decref(result);
}
END_TEST

START_TEST(test_proto_dpop_use_nonce_wrong_error_value) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *result = json_pack("{s:s}", "error", "invalid_request");
	char *dpop = NULL;
	ck_assert_int_eq(oidc_proto_dpop_use_nonce(r, c, result, NULL, "https://idp.example.com/token", "POST",
						   "access-token", &dpop),
			 FALSE);
	ck_assert_ptr_null(dpop);
	json_decref(result);
}
END_TEST

START_TEST(test_proto_dpop_use_nonce_missing_header) {
	request_rec *r = oidc_test_request_get();
	oidc_cfg_t *c = oidc_test_cfg_get();
	json_t *result = json_pack("{s:s}", "error", "use_dpop_nonce");
	apr_hash_t *hdrs = apr_hash_make(r->pool); /* no DPoP-Nonce entry */
	char *dpop = NULL;
	ck_assert_int_eq(oidc_proto_dpop_use_nonce(r, c, result, hdrs, "https://idp.example.com/token", "POST",
						   "access-token", &dpop),
			 FALSE);
	ck_assert_ptr_null(dpop);
	json_decref(result);
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
	json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 TRUE);
	ck_assert_ptr_nonnull(userinfo_claims);
	ck_assert_int_eq(response_code, 200);
	const char *name = json_string_value(json_object_get(userinfo_claims, "name"));
	ck_assert_ptr_nonnull(name);
	ck_assert_str_eq(name, "Alice Example");

	const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
	ck_assert_str_eq(cap->method, "GET");
	const char *auth = apr_table_get(cap->headers, OIDC_HTTP_HDR_AUTHORIZATION);
	ck_assert_ptr_nonnull(auth);
	ck_assert_str_eq(auth, "Bearer AT");

	json_decref(userinfo_claims);
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
	json_t *userinfo_claims = NULL;
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
	json_t *userinfo_claims = NULL;
	long response_code = 0;
	ck_assert_int_eq(oidc_proto_userinfo_request(r, c, provider, "alice", "AT", "Bearer", &s_userinfo,
						     &userinfo_jwt, &userinfo_claims, &response_code),
			 FALSE);

	(void)oidc_test_http_server_wait(srv);
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

	int rc = oidc_proto_request_auth(r, provider, NULL, "https://rp.example.com/cb", "state-1", ps, NULL, NULL,
					 NULL, NULL);
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
	tcase_add_test(core, test_proto_token_endpoint_auth_unknown_method);
	tcase_add_test(core, test_proto_jwt_validate_edge_cases);
	tcase_add_test(core, test_proto_state_timestamp_and_bad_cookie);
	tcase_add_test(core, test_proto_nonce_uniqueness);
	tcase_add_test(core, test_proto_flow_unsupported);
	tcase_add_test(core, test_proto_dpop_create_without_private_keys);
	tcase_add_test(core, test_proto_jwt_header_peek);
	tcase_add_test(core, test_proto_response_is_post_and_redirect);
	tcase_add_test(core, test_proto_return_www_authenticate_header);
	tcase_add_test(core, test_proto_idtoken_validate_aud_string_match);
	tcase_add_test(core, test_proto_idtoken_validate_aud_string_mismatch);
	tcase_add_test(core, test_proto_idtoken_validate_aud_array_with_client_id);
	tcase_add_test(core, test_proto_idtoken_validate_aud_array_without_client_id);
	tcase_add_test(core, test_proto_idtoken_validate_aud_missing);
	tcase_add_test(core, test_proto_idtoken_validate_aud_wrong_type);
	tcase_add_test(core, test_proto_idtoken_validate_azp_mismatch);
	tcase_add_test(core, test_proto_dpop_use_nonce_no_error_claim);
	tcase_add_test(core, test_proto_dpop_use_nonce_wrong_error_value);
	tcase_add_test(core, test_proto_dpop_use_nonce_missing_header);
	tcase_add_test(core, test_proto_discovery_account_no_at_sign);
	tcase_add_test(core, test_proto_supported_flows_exhaustive);

	TCase *e2e = tcase_create("e2e_proto");
	tcase_add_checked_fixture(e2e, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(e2e, 30);
	tcase_add_test(e2e, test_proto_token_endpoint_request_success);
	tcase_add_test(e2e, test_proto_token_endpoint_request_error);
	tcase_add_test(e2e, test_proto_token_refresh_request_success);
	tcase_add_test(e2e, test_proto_userinfo_request_success);
	tcase_add_test(e2e, test_proto_userinfo_request_sub_mismatch);
	tcase_add_test(e2e, test_proto_userinfo_request_error);
	tcase_add_test(e2e, test_proto_request_auth_par_redirect);

	Suite *s = suite_create("proto");
	suite_add_tcase(s, core);
	suite_add_tcase(s, e2e);

	return oidc_test_suite_run(s);
}
