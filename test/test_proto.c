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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
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

#include "handle/handle.h"
#include "helper.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
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

int main(void) {
	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(core, test_proto_validate_access_token);
	tcase_add_test(core, test_proto_validate_code);
	tcase_add_test(core, test_proto_authorization_request);
	tcase_add_test(core, test_logout_request);
	tcase_add_test(core, test_proto_validate_nonce);
	tcase_add_test(core, test_proto_validate_jwt);

	Suite *s = suite_create("proto");
	suite_add_tcase(s, core);

	return oidc_test_suite_run(s);
}
