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
 * Copyright (C) 2013-2015 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

#include <stdio.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "apr.h"
#include "apr_errno.h"
#include "apr_general.h"
#include "apr_time.h"
#include "jose/apr_jose.h"
#include "apr_base64.h"

#include "mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

static int test_nr_run = 0;
static char TST_ERR_MSG[512];
static int TST_RC;

#define TST_FORMAT(fmt) \
		" # %s: error in %s: result \"" fmt "\" != expected \"" fmt "\""

#define TST_ASSERT(message, expression) \
		TST_RC = (expression); \
		if (!TST_RC) { \
			sprintf(TST_ERR_MSG, TST_FORMAT("%d"), __FUNCTION__, message, TST_RC, 1); \
			return TST_ERR_MSG; \
		}

#define TST_ASSERT_ERR(message, expression, pool, err) \
		TST_RC = (expression); \
		if (!TST_RC) { \
			sprintf(TST_ERR_MSG, TST_FORMAT("%d") " %s", __FUNCTION__, message, TST_RC, 1, apr_jwt_e2s(pool, err)); \
			return TST_ERR_MSG; \
		}

#define TST_ASSERT_STR(message, result, expected) \
		TST_RC = (result && expected) ? (apr_strnatcmp(result, expected) != 0) : ((result != NULL) || (expected != NULL)); \
		if (TST_RC) { \
			sprintf(TST_ERR_MSG, TST_FORMAT("%s"), __FUNCTION__, message, result ? result : "(null)", expected ? expected : "(null)"); \
			return TST_ERR_MSG; \
		}

#define TST_ASSERT_LONG(message, result, expected) \
		if (result != expected) { \
			sprintf(TST_ERR_MSG, TST_FORMAT("%ld"), __FUNCTION__, message, result, expected); \
			return TST_ERR_MSG; \
		}

#define TST_RUN(test, pool) message = test(pool); test_nr_run++; if (message) return message;

static char *test_jwt_array_has_string(apr_pool_t *pool) {
	apr_array_header_t *haystack = apr_array_make(pool, 3, sizeof(const char*));
	*(const char**) apr_array_push(haystack) = "a";
	*(const char**) apr_array_push(haystack) = "b";
	*(const char**) apr_array_push(haystack) = "c";
	TST_ASSERT("jwt_array_has_string (1)",
			apr_jwt_array_has_string(haystack, "a"));
	TST_ASSERT("jwt_array_has_string (2)",
			apr_jwt_array_has_string(haystack, "d") == FALSE);
	return 0;
}

static char *test_jwt_url_encode_decode(apr_pool_t *pool) {
	char *dst = NULL;
	char *src = "abcd";

	TST_ASSERT("apr_jwt_base64url_encode (1)",
			apr_jwt_base64url_encode(pool, &dst, src, strlen(src), 0));
	TST_ASSERT_STR("apr_jwt_base64url_encode (2)", dst, "YWJjZA");

	src = dst;

	TST_ASSERT("apr_jwt_base64url_decode (1)",
			apr_jwt_base64url_decode(pool, &dst, src, 1));
	TST_ASSERT_STR("apr_jwt_base64url_decode (2)", dst, "abcd");

	return 0;
}

static char *test_jwt_header_to_string(apr_pool_t *pool) {
	const char * s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
	apr_jwt_error_t err;
	const char *dst = apr_jwt_header_to_string(pool, s, &err);
	TST_ASSERT_STR("apr_jwt_header_to_string", dst,
			"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");
	return 0;
}

static char *_jwk_parse(apr_pool_t *pool, const char *s, apr_jwk_t **jwk,
		apr_jwt_error_t *err) {

	json_t *j_jwk = json_loads(s, 0, NULL);
	TST_ASSERT("json_loads", ((j_jwk != NULL) && (json_is_object(j_jwk))));

	TST_ASSERT_ERR("apr_jwk_parse_json",
			apr_jwk_parse_json(pool, j_jwk, jwk, err), pool, (*err));

	json_decref(j_jwk);

	return 0;
}

static char *test_jwt_parse(apr_pool_t *pool) {

	// from http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20
	// 3.1.  Example JWT
	char *s =
			apr_pstrdup(pool,
					"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
					".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
					".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

	apr_jwt_error_t err;
	apr_jwt_t *jwt = NULL;
	TST_ASSERT_ERR("apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, &err),
			pool, err);

	TST_ASSERT_STR("header.alg", jwt->header.alg, "HS256");
	TST_ASSERT_STR("header.enc", jwt->header.enc, NULL);
	TST_ASSERT_STR("header.kid", jwt->header.kid, NULL);

	TST_ASSERT_STR("payload.iss", jwt->payload.iss, "joe");
	TST_ASSERT_LONG("payload.exp", (long )jwt->payload.exp, 1300819380L);

	apr_hash_t *keys = apr_hash_make(pool);
	apr_jwk_t *jwk;
	const char * k =
			"{\"kty\":\"oct\", \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
	jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json", _jwk_parse(pool, k, &jwk, &err) == 0,
			pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);
	TST_ASSERT_ERR("apr_jws_verify", apr_jws_verify(pool, jwt, keys, &err),
			pool, err);
	apr_jwt_destroy(jwt);

	s[5] = '.';
	TST_ASSERT_ERR("corrupted header (1) apr_jwt_parse",
			apr_jwt_parse(pool, s, &jwt, NULL, &err) == FALSE, pool, err);

	apr_jwt_destroy(jwt);

	s[0] = '\0';
	TST_ASSERT_ERR("corrupted header (2) apr_jwt_parse",
			apr_jwt_parse(pool, s, &jwt, NULL, &err) == FALSE, pool, err);

	apr_jwt_destroy(jwt);

	return 0;
}

static char *test_jwt_verify_rsa(apr_pool_t *pool) {
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
	char *s_jwt =
			apr_pstrdup(pool,
					"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9.eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYXNoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE0MTE1ODA4NzV9.lEG-DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk653bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEA");
	apr_jwt_t *jwt = NULL;
	apr_jwt_error_t err;
	TST_ASSERT_ERR("apr_jwt_parse",
			apr_jwt_parse(pool, s_jwt, &jwt, NULL, &err), pool, err);

	char *s_key =
			"{"
			"\"kty\": \"RSA\","
			"\"use\": \"sig\","
			"\"kid\": \"Z1NCjojeiHAib-Gm8vFE6ya6lPM\","
			"\"x5t\": \"Z1NCjojeiHAib-Gm8vFE6ya6lPM\","
			"\"x5c\": ["
			"\"MIIFHTCCBAWgAwIBAgIHJ9VlLewUkDANBgkqhkiG9w0BAQsFADCBtDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjAeFw0xNDA4MTIxNzE0MDdaFw0xNzA4MTgxODI5MjJaMDoxITAfBgNVBAsTGERvbWFpbiBDb250cm9sIFZhbGlkYXRlZDEVMBMGA1UEAwwMKi5hZ3N5bmMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3lDyn/ZvG32Pw5kYbRuVxHsPfe9Xt8s9vOXnt8z7/T+hZZvealNhCxz9VEwTJ7TsZ9CLi5c30FjoEJYFkKddLAdxKo0oOXWc/AWrQvPwht9a+o6dX2fL/9CmXW1hGHXMH0qiLMrFqMSzZeh+GUY6F1woE/eKsAo6LOhP8X77FlEQT2Eu71wu8KC4B3sH/9QTco50KNw14+bRY5j2V2TZelvsXJnvrN4lXtEVYWFkREKeXzMH8DhDyZzh0NcHa7dFBa7rDusyfIHjuP6uAju/Ao6hhdOGjlKePMVtfusWBAI7MWDChLTqiCTvlZnCpkpTTh5m+i7TbE1TwmdbLceq1wIDAQABo4IBqzCCAacwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgWgMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20vZ2RpZzJzMS04Ny5jcmwwUwYDVR0gBEwwSjBIBgtghkgBhv1tAQcXATA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29kYWRkeS5jb20vMEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQYMBaAFEDCvSeOzDSDMKIz1/tss/C0LIDOMCMGA1UdEQQcMBqCDCouYWdzeW5jLmNvbYIKYWdzeW5jLmNvbTAdBgNVHQ4EFgQUxqwQ5mJfzESbA5InigohAq4lhIYwDQYJKoZIhvcNAQELBQADggEBADXv4q7iw3yCDuVS+edPcyWQJPWo3X7xx83g2omcsqDIoEMgsRLGidiINttAhSIAlUyd9Nsp5cGsT/2ZJMbjRFhhVhRHf61O+F60ZYuKPUKWlXB1Nkk4f48/6PGc5Tu/MXdXttpuIP4Jlbpc0dtv59wrrFs9Sf1V7NuHS96IhxfnBO3J1s3ipudoUwjNtBxN/7vUFzfRuHl1+/oQxhmKDxBDpk0v1iLJTeMkMgc+wPGO55gLR6+5l9qWuuE+fIHeS+LHMzchkBBYJMtbmf/KZfwMA8AOsnGXQOXzpf7Sg8VIiVdeaB0NY1eWyRBisQkivk6wm+7G2VYKh9OeVdX4XqQ=\""
			"]"
			"}";

	apr_hash_t *keys = apr_hash_make(pool);
	apr_jwk_t *jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json",
			_jwk_parse(pool, s_key, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	TST_ASSERT_ERR("apr_jws_verify", apr_jws_verify(pool, jwt, keys, &err),
			pool, err);

	apr_jwt_destroy(jwt);

	return 0;
}

static char *test_plaintext_jwt_parse(apr_pool_t *pool) {

	// from http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20
	// 6.1.  Example Plaintext JWT
	char *s =
			apr_pstrdup(pool,
					"eyJhbGciOiJub25lIn0"
					".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
					".");

	apr_jwt_error_t err;
	apr_jwt_t *jwt = NULL;
	TST_ASSERT_ERR("apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, &err),
			pool, err);

	TST_ASSERT_STR("header.alg", jwt->header.alg, "none");

	TST_ASSERT_STR("payload.iss", jwt->payload.iss, "joe");
	TST_ASSERT_LONG("payload.exp", (long )jwt->payload.exp, 1300819380L);

	apr_jwt_destroy(jwt);

	return 0;
}

static char *test_jwt_get_string(apr_pool_t *pool) {
	//apr_jwt_get_string

	const char *s =
			"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
			".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
			".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	apr_jwt_t *jwt = NULL;
	apr_jwt_error_t err;
	TST_ASSERT_ERR("apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, &err),
			pool, err);

	char *dst;

	dst = NULL;
	TST_ASSERT("apr_jwt_get_string (1a)",
			apr_jwt_get_string(pool, jwt->header.value.json, "typ", TRUE, &dst, &err));
	TST_ASSERT_STR("apr_jwt_get_string (1b)", dst, "JWT");

	dst = NULL;
	TST_ASSERT("apr_jwt_get_string (2a)",
			apr_jwt_get_string(pool, jwt->header.value.json, "alg", TRUE, &dst, &err));
	TST_ASSERT_STR("apr_jwt_get_string (2b)", dst, "HS256");

	dst = NULL;
	TST_ASSERT("apr_jwt_get_string (3a)",
			apr_jwt_get_string(pool, jwt->header.value.json, "dummy", FALSE, &dst, &err));
	TST_ASSERT_STR("apr_jwt_get_string (3b)", dst, NULL);

	apr_jwt_destroy(jwt);

	return 0;
}

static char *test_jwk_parse_json(apr_pool_t *pool) {
	const char *s =
			"{\"kty\":\"EC\",\"use\":\"sig\","
			"\"kid\":\"the key\","
			"\"x\":\"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4\","
			"\"y\":\"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co\",\"crv\":\"P-256\"}";

	apr_jwt_error_t err;
	apr_jwk_t *jwk;

	jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json (1)",
			_jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

	// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#appendix-A.3
	// A.3.  Example Symmetric Keys #1
	s = "{"
			"\"kty\":\"oct\","
			"\"alg\":\"A128KW\","
			"\"k\"  :\"GawgguFyGrWKav7AX4VKUg\""
			"}";

	jwk = NULL;
	TST_ASSERT_ERR(
			"apr_jwk_parse_json (draft-ietf-jose-json-web-key-41#appendix-A.3 #1)",
			_jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	TST_ASSERT_LONG("#1 jwk->type", (long )jwk->type, (long )APR_JWK_KEY_OCT);
	TST_ASSERT_LONG("#1 jwk->key.oct->k_len", (long )jwk->key.oct->k_len, 16L);

	// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#appendix-A.3
	// A.3.  Example Symmetric Keys #2
	s =
			"{"
			"\"kty\":\"oct\","
			"\"k\"  :\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\","
			"\"kid\":\"HMAC key used in JWS A.1 example\""
			"}";

	jwk = NULL;
	TST_ASSERT_ERR(
			"apr_jwk_parse_json (draft-ietf-jose-json-web-key-41#appendix-A.3 #2)",
			_jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	TST_ASSERT_LONG("#2 jwk->type", (long )jwk->type, (long )APR_JWK_KEY_OCT);
	TST_ASSERT_LONG("#2 jwk->key.oct->k_len", (long )jwk->key.oct->k_len, 64L);

	// https://tools.ietf.org/html/draft-ietf-jose-cookbook-08#section-3.1
	// 3.1.  EC Public Key
	s =
			"{"
			"\"kty\": \"EC\","
			"\"kid\": \"bilbo.baggins@hobbiton.example\","
			"\"use\": \"sig\","
			"\"crv\": \"P-521\","
			"\"x\": \"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","
			"\"y\": \"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\""
			"}";

	jwk = NULL;
	TST_ASSERT_ERR(
			"apr_jwk_parse_json (draft-ietf-jose-cookbook-08#section-3.1, EC Public Key)",
			_jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

	// https://tools.ietf.org/html/draft-ietf-jose-cookbook-08#section-3.2
	// 3.2.  EC Private Key
	s =
			"{"
			"\"kty\": \"EC\","
			"\"kid\": \"bilbo.baggins@hobbiton.example\","
			"\"use\": \"sig\","
			"\"crv\": \"P-521\","
			"\"x\": \"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","
			"\"y\": \"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\","
			"\"d\": \"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\""
			"}";

	jwk = NULL;
	TST_ASSERT_ERR(
			"apr_jwk_parse_json (draft-ietf-jose-cookbook-08#section-3.2, EC Private Key)",
			_jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

	// https://tools.ietf.org/html/draft-ietf-jose-cookbook-08#section-3.3
	// 3.3.  RSA Public Key
	s = "{"
			"\"kty\": \"RSA\","
			"\"kid\": \"bilbo.baggins@hobbiton.example\","
			"\"use\": \"sig\","
			"\"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
			"-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
			"wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
			"oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
			"3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
			"LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
			"HdrNP5zw\","
			"\"e\": \"AQAB\""
			"}";

	jwk = NULL;
	TST_ASSERT_ERR(
			"apr_jwk_parse_json (draft-ietf-jose-cookbook-08#section-3.3, RSA Public Key)",
			_jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

	// https://tools.ietf.org/html/draft-ietf-jose-cookbook-08#section-3.4
	// 3.4.  RSA Private Key
	s = "{"
			"\"kty\": \"RSA\","
			"\"kid\": \"bilbo.baggins@hobbiton.example\","
			"\"use\": \"sig\","
			"\"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
			"-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
			"wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
			"oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
			"3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
			"LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
			"HdrNP5zw\","
			"\"e\": \"AQAB\","
			"\"d\": \"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e"
			"iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld"
			"Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b"
			"MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU"
			"6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj"
			"d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc"
			"OpBrQzwQ\","
			"\"p\": \"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR"
			"aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG"
			"peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8"
			"bUq0k\","
			"\"q\": \"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT"
			"8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an"
			"V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0"
			"s7pFc\","
			"\"dp\": \"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q"
			"1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn"
			"-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX"
			"59ehik\","
			"\"dq\": \"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr"
			"AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK"
			"bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK"
			"T1cYF8\","
			"\"qi\": \"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N"
			"ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh"
			"jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP"
			"z8aaI4\""
			"}";

	jwk = NULL;
	TST_ASSERT_ERR(
			"apr_jwk_parse_json (draft-ietf-jose-cookbook-08#section-3.4, RSA Private Key)",
			_jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

	return 0;
}

static char *test_plaintext_decrypt(apr_pool_t *pool) {

	// from http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-30
	// A.2.  Example JWE using RSAES-PKCS1-V1_5 and AES_128_CBC_HMAC_SHA_256
	char *s =
			apr_pstrdup(pool,
					"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
					".UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
					".AxY8DCtDaGlsbGljb3RoZQ"
					".KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
					".9hH0vgRfYgPnAHOd8stkvw");

	char * k =
			"{\"kty\":\"RSA\","
			"\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\","
			"\"e\":\"AQAB\","
			"\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\""
			"}";

	apr_jwt_error_t err;
	apr_hash_t *keys = apr_hash_make(pool);
	apr_jwk_t *jwk = NULL;

	TST_ASSERT_ERR("apr_jwk_parse_json", _jwk_parse(pool, k, &jwk, &err) == 0,
			pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	apr_array_header_t *unpacked = NULL;
	apr_jwt_header_t header;
	memset(&header, 0, sizeof(header));
	TST_ASSERT_ERR("apr_jwt_header_parse",
			apr_jwt_header_parse(pool, s, &unpacked, &header, &err), pool, err);

	char *decrypted = NULL;
	TST_ASSERT_ERR("apr_jwe_decrypt_jwt",
			apr_jwe_decrypt_jwt(pool, &header, unpacked, keys, &decrypted,
					&err), pool, err);

	TST_ASSERT_STR("decrypted", decrypted, "Live long and prosper.");

	json_decref(header.value.json);

	return 0;
}

static char *test_plaintext_decrypt2(apr_pool_t *pool) {

	// http://tools.ietf.org/html/draft-ietf-jose-cookbook-08#section-5.1.5
	// 5.1.  Key Encryption using RSA v1.5 and AES-HMAC-SHA2
	char *s =
			apr_pstrdup(pool,
					"eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm"
					"V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
					"."
					"laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF"
					"vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G"
					"Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG"
					"TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl"
					"zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh"
					"MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw"
					"."
					"bbd5sTkYwhAIqfHsx8DayA"
					"."
					"0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r"
					"aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O"
					"WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV"
					"yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0"
					"zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2"
					"O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW"
					"i7lzA6BP430m"
					"."
					"kvKuFBXHe5mQr4lqgobAUg");

	char * k = "{"
			"\"kty\": \"RSA\","
			"\"kid\": \"frodo.baggins@hobbiton.example\","
			"\"use\": \"enc\","
			"\"n\": \"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT"
			"HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx"
			"6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U"
			"NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c"
			"R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy"
			"pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA"
			"VotGlvMQ\","
			"\"e\": \"AQAB\","
			"\"d\": \"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy"
			"bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO"
			"5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6"
			"Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP"
			"1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN"
			"miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v"
			"pzj85bQQ\","
			"\"p\": \"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE"
			"oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH"
			"7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ"
			"2VFmU\","
			"\"q\": \"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V"
			"F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb"
			"9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8"
			"d6Et0\","
			"\"dp\": \"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH"
			"QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV"
			"RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf"
			"lo0rYU\","
			"\"dq\": \"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb"
			"pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A"
			"CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14"
			"TkXlHE\","
			"\"qi\": \"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ"
			"lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7"
			"Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx"
			"2bQ_mM\""
			"}";

	apr_jwt_error_t err;
	apr_hash_t *keys = apr_hash_make(pool);
	apr_jwk_t *jwk = NULL;

	TST_ASSERT_ERR("apr_jwk_parse_json", _jwk_parse(pool, k, &jwk, &err) == 0,
			pool, err);
	apr_hash_set(keys, jwk->kid, APR_HASH_KEY_STRING, jwk);

	apr_array_header_t *unpacked = NULL;
	apr_jwt_header_t header;
	memset(&header, 0, sizeof(header));
	TST_ASSERT_ERR("apr_jwt_header_parse",
			apr_jwt_header_parse(pool, s, &unpacked, &header, &err), pool, err);

	char *decrypted = NULL;
	TST_ASSERT_ERR("apr_jwe_decrypt_jwt",
			apr_jwe_decrypt_jwt(pool, &header, unpacked, keys, &decrypted,
					&err), pool, err);

	TST_ASSERT_STR("decrypted", decrypted,
			"You can trust us to stick with you through thick and "
			"thin\u2013to the bitter end. And you can trust us to "
			"keep any secret of yours\u2013closer than you keep it "
			"yourself. But you cannot trust us to let you face trouble "
			"alone, and go off without a word. We are your friends, Frodo.");

	json_decref(header.value.json);

	return 0;
}

static char *test_plaintext_decrypt_symmetric(apr_pool_t *pool) {
	apr_jwt_error_t err;
	apr_hash_t *keys = apr_hash_make(pool);
	apr_jwk_t *jwk;

	// http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40#appendix-A.3
	// A.3.  Example JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
	const char * k = "{\"kty\":\"oct\", \"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
	jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json", _jwk_parse(pool, k, &jwk, &err) == 0,
			pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	const char *s = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
			"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
			"AxY8DCtDaGlsbGljb3RoZQ."
			"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
			"U0m_YmjN04DJvceFICbCVQ";

	apr_array_header_t *unpacked = NULL;
	apr_jwt_header_t header;
	memset(&header, 0, sizeof(header));
	TST_ASSERT_ERR("apr_jwt_header_parse",
			apr_jwt_header_parse(pool, s, &unpacked, &header, &err), pool, err);

	char *decrypted = NULL;
	TST_ASSERT_ERR("apr_jwe_decrypt_jwt",
			apr_jwe_decrypt_jwt(pool, &header, unpacked, keys, &decrypted,
					&err), pool, err);

	TST_ASSERT_STR("decrypted", decrypted, "Live long and prosper.");

	json_decref(header.value.json);

	return 0;
}

static char *test_jwt_decrypt(apr_pool_t *pool) {

	// https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#appendix-A.1
	// A.2.  Example Nested JWT
	char * s =
			apr_pstrdup(pool,
					"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"
					"In0."
					"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"
					"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"
					"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"
					"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"
					"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"
					"JGTO_z3Wfo5zsqwkxruxwA."
					"UmVkbW9uZCBXQSA5ODA1Mg."
					"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"
					"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"
					"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"
					"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"
					"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"
					"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"
					"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"
					"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"
					"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"
					"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."
					"AVO9iT5AV4CzvDJCdhSFlQ");

	char * ek =
			"{\"kty\":\"RSA\","
			"\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\","
			"\"e\":\"AQAB\","
			"\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\""
			"}";

	char * sk = "{"
			"\"kty\":\"RSA\","
			"\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
			"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
			"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
			"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
			"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
			"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\","
			"\"e\":\"AQAB\","
			"\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
			"jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
			"BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
			"439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
			"CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
			"BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\","
			"\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
			"YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
			"BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\","
			"\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
			"ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
			"-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\","
			"\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
			"CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
			"34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\","
			"\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
			"7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
			"NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\","
			"\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
			"y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
			"W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\""
			"}";

	apr_jwt_error_t err;
	apr_hash_t *keys = apr_hash_make(pool);
	apr_jwk_t *jwk = NULL;
	apr_jwt_t *jwt = NULL;

	TST_ASSERT_ERR("apr_jwk_parse_json (encryption key)",
			_jwk_parse(pool, ek, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	TST_ASSERT_ERR("apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, keys, &err),
			pool, err);

	TST_ASSERT_ERR("apr_jwk_parse_json (signing key)",
			_jwk_parse(pool, sk, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);
	TST_ASSERT_ERR("apr_jws_verify", apr_jws_verify(pool, jwt, keys, &err),
			pool, err);

	TST_ASSERT_STR("header.alg", jwt->header.alg, "RS256");
	TST_ASSERT_STR("payload.iss", jwt->payload.iss, "joe");
	TST_ASSERT_LONG("payload.exp", (long )jwt->payload.exp, 1300819380L);

	apr_jwt_destroy(jwt);

	return 0;
}

#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)

static char *test_jwt_decrypt_gcm(apr_pool_t *pool) {

	// https://tools.ietf.org/html/rfc7516#appendix-A.1
	// A.1.  Example JWE using RSAES-OAEP and AES GCM
	char * s =
			apr_pstrdup(pool,
					"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
					"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
					"ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
					"Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
					"mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
					"1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
					"6UklfCpIMfIjf7iGdXKHzg."
					"48V1_ALb6US04U3b."
					"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
					"SdiwkIr3ajwQzaBtQD_A."
					"XFBoMYUZodetZdvTiFvSkQ");

	char * k =
			"{\"kty\":\"RSA\","
			"\"n\":\"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW"
			  "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S"
			  "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a"
			  "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS"
			  "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj"
			  "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw\","
			"\"e\":\"AQAB\","
			"\"d\":\"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N"
			  "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9"
			  "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk"
			  "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl"
			  "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd"
			  "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ\","
			"\"p\":\"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-"
			  "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf"
			  "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0\","
			"\"q\":\"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm"
			  "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX"
			  "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc\","
			"\"dp\":\"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL"
			  "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827"
			  "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE\","
			"\"dq\":\"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj"
			  "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB"
			  "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis\","
			"\"qi\":\"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7"
			  "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3"
			  "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY\""
			"}";

	apr_jwt_error_t err;
	apr_hash_t *keys = apr_hash_make(pool);
	apr_jwk_t *jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json", _jwk_parse(pool, k, &jwk, &err) == 0,
			pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	apr_array_header_t *unpacked = NULL;
	apr_jwt_header_t header;
	memset(&header, 0, sizeof(header));
	TST_ASSERT_ERR("apr_jwt_header_parse",
			apr_jwt_header_parse(pool, s, &unpacked, &header, &err), pool, err);

	char *decrypted = NULL;
	TST_ASSERT_ERR("apr_jwe_decrypt_jwt",
			apr_jwe_decrypt_jwt(pool, &header, unpacked, keys, &decrypted,
					&err), pool, err);

	TST_ASSERT_STR("decrypted", decrypted, "The true sign of intelligence is not knowledge but imagination.");
	TST_ASSERT_STR("header.alg", header.alg, "RSA-OAEP");

	json_decref(header.value.json);

	return 0;
}

#endif

static char *test_proto_validate_access_token(request_rec *r) {

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

	apr_jwt_error_t err;
	apr_jwt_t *jwt = NULL;
	TST_ASSERT_ERR("apr_jwt_parse", apr_jwt_parse(r->pool, s, &jwt, NULL, &err),
			r->pool, err);

	const char *access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
	TST_ASSERT("oidc_proto_validate_access_token",
			oidc_proto_validate_access_token(r, NULL, jwt, "id_token token", access_token));

	apr_jwt_destroy(jwt);

	return 0;
}

static char *test_proto_validate_code(request_rec *r) {

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

	apr_jwt_error_t err;
	apr_jwt_t *jwt = NULL;
	TST_ASSERT_ERR("apr_jwt_parse", apr_jwt_parse(r->pool, s, &jwt, NULL, &err),
			r->pool, err);

	const char *code =
			"Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
	TST_ASSERT("oidc_proto_validate_code",
			oidc_proto_validate_code(r, NULL, jwt, "code id_token", code));

	apr_jwt_destroy(jwt);

	return 0;
}

static char * test_proto_authorization_request(request_rec *r) {

	oidc_provider_t provider;
	provider.issuer = "https://idp.example.com";
	provider.authorization_endpoint_url = "https://idp.example.com/authorize";
	provider.scope = "openid";
	provider.client_id = "client_id";
	provider.response_type = "code";
	provider.auth_request_params = NULL;
	const char *redirect_uri = "https://www.example.com/protected/";
	const char *state = "12345";

	json_t * proto_state = json_object();
	json_object_set_new(proto_state, "nonce", json_string("anonce"));
	json_object_set_new(proto_state, "original_url", json_string("https://localhost/protected/index.php"));
	json_object_set_new(proto_state, "original_method", json_string("get"));
	json_object_set_new(proto_state, "issuer", json_string(provider.issuer));
	json_object_set_new(proto_state, "response_type", json_string(provider.response_type));
	json_object_set_new(proto_state, "timestamp", json_integer(apr_time_sec(apr_time_now())));

	TST_ASSERT("oidc_proto_authorization_request (1)",
			oidc_proto_authorization_request(r, &provider, NULL, redirect_uri, state, proto_state, NULL, NULL) == HTTP_MOVED_TEMPORARILY);

	TST_ASSERT_STR("oidc_proto_authorization_request (2)",
			apr_table_get(r->headers_out, "Location"),
			"https://idp.example.com/authorize?response_type=code&scope=openid&client_id=client_id&state=12345&redirect_uri=https%3A%2F%2Fwww.example.com%2Fprotected%2F&nonce=anonce");

	return 0;
}

static char * test_proto_validate_nonce(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
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
	char *s_jwt =
			apr_pstrdup(r->pool,
					"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9.eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYXNoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE0MTE1ODA4NzV9.lEG-DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk653bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEA");
	apr_jwt_t *jwt = NULL;
	apr_jwt_error_t err;
	TST_ASSERT_ERR("apr_jwt_parse",
			apr_jwt_parse(r->pool, s_jwt, &jwt, NULL, &err), r->pool, err);

	TST_ASSERT("oidc_proto_validate_nonce (1)",
			oidc_proto_validate_nonce(r, c, &c->provider, nonce, jwt));
	TST_ASSERT("oidc_proto_validate_nonce (2)",
			oidc_proto_validate_nonce( r, c, &c->provider, nonce, jwt) == FALSE);

	apr_jwt_destroy(jwt);

	return 0;
}

static char * test_proto_validate_jwt(request_rec *r) {

	apr_jwt_t *jwt = NULL;
	apr_jwt_error_t err;

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
			"\"exp\": %" APR_TIME_T_FMT
			"}";
	s_jwt_payload = apr_psprintf(r->pool, s_jwt_payload, now, s_issuer,
			now + 600);

	char *s_jwt_header_encoded = NULL;
	oidc_base64url_encode(r, &s_jwt_header_encoded, s_jwt_header,
			strlen(s_jwt_header), 1);

	char *s_jwt_payload_encoded = NULL;
	oidc_base64url_encode(r, &s_jwt_payload_encoded, s_jwt_payload,
			strlen(s_jwt_payload), 1);

	char *s_jwt_message = apr_psprintf(r->pool, "%s.%s", s_jwt_header_encoded,
			s_jwt_payload_encoded);

	unsigned int md_len = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD *digest = EVP_get_digestbyname("sha256");

	TST_ASSERT("HMAC",
			HMAC(digest, (const unsigned char * )s_secret, strlen(s_secret),
					(const unsigned char * )s_jwt_message,
					strlen(s_jwt_message), md, &md_len) != 0);

	char *s_jwt_signature_encoded = NULL;
	oidc_base64url_encode(r, &s_jwt_signature_encoded, (const char *) md,
			md_len, 1);

	char *s_jwt = apr_psprintf(r->pool, "%s.%s.%s", s_jwt_header_encoded,
			s_jwt_payload_encoded, s_jwt_signature_encoded);

	TST_ASSERT_ERR("apr_jwt_parse",
			apr_jwt_parse(r->pool, s_jwt, &jwt, NULL, &err), r->pool, err);

	TST_ASSERT_ERR("apr_jws_verify",
			apr_jws_verify(r->pool, jwt, oidc_util_merge_symmetric_key(r->pool, NULL, s_secret, NULL), &err),
			r->pool, err);

	TST_ASSERT_ERR("oidc_proto_validate_jwt",
			oidc_proto_validate_jwt(r, jwt, s_issuer, TRUE, TRUE, 10), r->pool,
			err);

	apr_jwt_destroy(jwt);

	return 0;
}

static char * all_tests(apr_pool_t *pool, request_rec *r) {
	char *message;
	TST_RUN(test_jwt_array_has_string, pool);
	TST_RUN(test_jwt_url_encode_decode, pool);
	TST_RUN(test_jwt_header_to_string, pool);
	TST_RUN(test_jwt_parse, pool);
	TST_RUN(test_plaintext_jwt_parse, pool);
	TST_RUN(test_jwt_get_string, pool);

	TST_RUN(test_jwk_parse_json, pool);
	TST_RUN(test_plaintext_decrypt, pool);
	TST_RUN(test_plaintext_decrypt2, pool);
	TST_RUN(test_plaintext_decrypt_symmetric, pool);

	TST_RUN(test_jwt_decrypt, pool);
#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)	
	TST_RUN(test_jwt_decrypt_gcm, pool);
#endif
	TST_RUN(test_jwt_verify_rsa, pool);

	TST_RUN(test_proto_validate_access_token, r);
	TST_RUN(test_proto_validate_code, r);

	TST_RUN(test_proto_authorization_request, r);
	TST_RUN(test_proto_validate_nonce, r);
	TST_RUN(test_proto_validate_jwt, r);

	return 0;
}

static request_rec * test_setup(apr_pool_t *pool) {
	const unsigned int kIdx = 0;
	const unsigned int kEls = kIdx + 1;
	request_rec *request = (request_rec *) apr_pcalloc(pool,
			sizeof(request_rec));

	request->pool = pool;

	request->headers_in = apr_table_make(request->pool, 0);
	request->headers_out = apr_table_make(request->pool, 0);
	request->err_headers_out = apr_table_make(request->pool, 0);

	apr_table_set(request->headers_in, "Host", "www.example.com");
	apr_table_set(request->headers_in, "OIDC_foo", "some-value");
	apr_table_set(request->headers_in, "Cookie", "foo=bar; "
			"mod_auth_openidc_session" "=0123456789abcdef; baz=zot");

	request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
	request->server->process = apr_pcalloc(request->pool,
			sizeof(struct process_rec));
	request->server->process->pool = request->pool;
	request->connection = apr_pcalloc(request->pool, sizeof(struct conn_rec));
	request->connection->local_addr = apr_pcalloc(request->pool,
			sizeof(apr_sockaddr_t));

	apr_pool_userdata_set("https", "scheme", NULL, request->pool);
	request->server->server_hostname = "www.example.com";
	request->connection->local_addr->port = 80;
	request->unparsed_uri = "/bla?foo=bar&param1=value1";
	request->args = "foo=bar&param1=value1";
	apr_uri_parse(request->pool,
			"http://www.example.com/bla?foo=bar&param1=value1",
			&request->parsed_uri);

	auth_openidc_module.module_index = kIdx;
	oidc_cfg *cfg = oidc_create_server_config(request->pool, request->server);
	cfg->provider.issuer = "https://idp.example.com";
	cfg->provider.authorization_endpoint_url =
			"https://idp.example.com/authorize";
	cfg->provider.scope = "openid";
	cfg->provider.client_id = "client_id";
	cfg->redirect_uri = "https://www.example.com/protected/";

	oidc_dir_cfg *d_cfg = oidc_create_dir_config(request->pool, NULL);

	request->server->module_config = apr_pcalloc(request->pool,
			sizeof(ap_conf_vector_t *) * kEls);
	request->per_dir_config = apr_pcalloc(request->pool,
			sizeof(ap_conf_vector_t *) * kEls);
	ap_set_module_config(request->server->module_config, &auth_openidc_module,
			cfg);
	ap_set_module_config(request->per_dir_config, &auth_openidc_module, d_cfg);

	cfg->cache = &oidc_cache_shm;
	cfg->cache_cfg = NULL;
	cfg->cache_shm_size_max = 500;
	cfg->cache_shm_entry_size_max = 16384 + 255 + 17;
	cfg->cache->post_config(request->server);

	return request;
}

int main(int argc, char **argv, char **env) {
	if (apr_app_initialize(&argc, (const char * const **) argv,
			(const char * const **) env) != APR_SUCCESS) {
		printf("apr_app_initialize failed\n");
		return -1;
	}

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, NULL);

	request_rec *r = test_setup(pool);

	OpenSSL_add_all_digests();

	char *result = all_tests(pool, r);
	if (result != 0) {
		printf("Failed: %s\n", result);
	} else {
		printf("All %d tests passed!\n", test_nr_run);
	}

	EVP_cleanup();
	apr_pool_destroy(pool);
	apr_terminate();

	return result != 0;
}

