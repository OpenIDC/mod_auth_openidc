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

#include "apr.h"
#include "apr_errno.h"
#include "apr_general.h"
#include "apr_time.h"
#include "jose/apr_jose.h"
#include "apr_base64.h"

/*
#include "mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;
*/

static int test_nr_run = 0;
static char TST_ERR_MSG[512];
static int TST_RC;

#define TST_FORMAT(fmt) \
		" # %s: error in %s: result \"" fmt "\" != expected \"" fmt "\""

#define TST_ASSERT(message, test) \
		if (!(test)) { \
			sprintf(TST_ERR_MSG, TST_FORMAT("%d"), __FUNCTION__, message, test, 1); \
			return TST_ERR_MSG; \
		}

#define TST_ASSERT_ERR(message, test, pool, err) \
		if (!(test)) { \
			sprintf(TST_ERR_MSG, TST_FORMAT("%d") " %s", __FUNCTION__, message, test, 1, apr_jwt_e2s(pool, err)); \
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
	TST_ASSERT_ERR("apr_jwt_parse",
			apr_jwt_parse(pool, s, &jwt, NULL, &err), pool, err);

	TST_ASSERT_STR("header.alg", jwt->header.alg, "HS256");
	TST_ASSERT_STR("header.enc", jwt->header.enc, NULL);
	TST_ASSERT_STR("header.kid", jwt->header.kid, NULL);

	TST_ASSERT_STR("payload.iss", jwt->payload.iss, "joe");
	TST_ASSERT_LONG("payload.exp", (long )jwt->payload.exp, 1300819380L);

	char *str_key =
			"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
	char *raw_key = NULL;
	int raw_key_len = apr_jwt_base64url_decode(pool, &raw_key, str_key, 1);

	TST_ASSERT("apr_jws_verify_hmac",
			apr_jws_verify_hmac(pool, jwt, raw_key, raw_key_len, &err));

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

static char *_jwk_parse(apr_pool_t *pool, const char *s, apr_jwk_t **jwk, apr_jwt_error_t *err) {

	json_t *j_jwk = json_loads(s, 0, NULL);
	TST_ASSERT("json_loads", ((j_jwk != NULL) && (json_is_object(j_jwk))));

	TST_ASSERT_ERR("apr_jwk_parse_json",
			apr_jwk_parse_json(pool, j_jwk, jwk, err), pool, (*err));

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

	apr_jwk_t *jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json", _jwk_parse(pool, s_key, &jwk, &err) == 0, pool, err);

	TST_ASSERT("apr_jws_verify_rsa", apr_jws_verify_rsa(pool, jwt, jwk, &err));

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
	TST_ASSERT_ERR("apr_jwt_parse",
			apr_jwt_parse(pool, s, &jwt, NULL, &err), pool, err);

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
	TST_ASSERT_ERR("apr_jwt_parse",
			apr_jwt_parse(pool, s, &jwt, NULL, &err), pool, err);

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
	TST_ASSERT_ERR("apr_jwk_parse_json (1)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

	// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#appendix-A.3
	// A.3.  Example Symmetric Keys #1
	s = "{"
		"\"kty\":\"oct\","
		"\"alg\":\"A128KW\","
		"\"k\"  :\"GawgguFyGrWKav7AX4VKUg\""
		"}";

	jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json (draft-ietf-jose-json-web-key-41#appendix-A.3 #1)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	TST_ASSERT_LONG("#1 jwk->type",  (long)jwk->type, (long)APR_JWK_KEY_OCT);
	TST_ASSERT_LONG("#1 jwk->key.oct->k_len", (long)jwk->key.oct->k_len, 16L);

	// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#appendix-A.3
	// A.3.  Example Symmetric Keys #2
	s = "{"
		"\"kty\":\"oct\","
		"\"k\"  :\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\","
		"\"kid\":\"HMAC key used in JWS A.1 example\""
		"}";

	jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json (draft-ietf-jose-json-web-key-41#appendix-A.3 #2)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	TST_ASSERT_LONG("#2 jwk->type",  (long)jwk->type, (long)APR_JWK_KEY_OCT);
	TST_ASSERT_LONG("#2 jwk->key.oct->k_len", (long)jwk->key.oct->k_len, 64L);

	// https://tools.ietf.org/html/draft-ietf-jose-cookbook-08#section-3.1
	// 3.1.  EC Public Key
	s = "{"
     "\"kty\": \"EC\","
     "\"kid\": \"bilbo.baggins@hobbiton.example\","
     "\"use\": \"sig\","
     "\"crv\": \"P-521\","
     "\"x\": \"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","
     "\"y\": \"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\""
    "}";

	jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json (draft-ietf-jose-cookbook-08#section-3.1, EC Public Key)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

	// https://tools.ietf.org/html/draft-ietf-jose-cookbook-08#section-3.2
	// 3.2.  EC Private Key
	s = "{"
     "\"kty\": \"EC\","
     "\"kid\": \"bilbo.baggins@hobbiton.example\","
     "\"use\": \"sig\","
     "\"crv\": \"P-521\","
     "\"x\": \"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","
     "\"y\": \"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\","
     "\"d\": \"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\""
     "}";

	jwk = NULL;
	TST_ASSERT_ERR("apr_jwk_parse_json (draft-ietf-jose-cookbook-08#section-3.2, EC Private Key)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

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
	TST_ASSERT_ERR("apr_jwk_parse_json (draft-ietf-jose-cookbook-08#section-3.3, RSA Public Key)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

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
	TST_ASSERT_ERR("apr_jwk_parse_json (draft-ietf-jose-cookbook-08#section-3.4, RSA Private Key)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);

	return 0;
}

static char *test_jwt_decryption(apr_pool_t *pool) {

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

	TST_ASSERT_ERR("apr_jwk_parse_json", _jwk_parse(pool, k, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	apr_array_header_t *unpacked = apr_jwt_compact_deserialize(pool, s);
	TST_ASSERT("apr_jwt_compact_deserialize", unpacked != NULL);
	TST_ASSERT_LONG("unpacked->nelts", (long )unpacked->nelts, 5L);

	apr_jwt_t *jwt = apr_pcalloc(pool, sizeof(apr_jwt_t));
	TST_ASSERT_ERR("apr_jwt_parse_header",
			apr_jwt_parse_header(pool, ((const char** ) unpacked->elts)[0],
					&jwt->header, &err), pool, err);

	char *decrypted = NULL;
	TST_ASSERT("apr_jwe_decrypt_jwt",
			apr_jwe_decrypt_jwt(pool, &jwt->header, unpacked, keys, &decrypted, &err));

	TST_ASSERT_STR("apr_jwe_decrypt_jwt (2)", decrypted,
			"Live long and prosper.");

	apr_jwt_destroy(jwt);

	return 0;
}
/*
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
	TST_ASSERT_ERR("apr_jwt_parse",
			apr_jwt_parse(r->pool, s, &jwt, NULL, NULL, &err), r->pool, err);

	const char *access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
	TST_ASSERT("oidc_proto_validate_access_token",
			oidc_proto_validate_access_token(r, NULL, jwt, "id_token token", access_token, NULL));

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
	TST_ASSERT_ERR("apr_jwt_parse",
			apr_jwt_parse(r->pool, s, &jwt, NULL, NULL, &err), r->pool, err);

	const char *code =
			"Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
	TST_ASSERT("oidc_proto_validate_access_token",
			oidc_proto_validate_code(r, NULL, jwt, "code id_token", code));

	apr_jwt_destroy(jwt);

	return 0;
}
*/
static char * all_tests(apr_pool_t *pool/*, request_rec *r*/) {
	char *message;
	TST_RUN(test_jwt_array_has_string, pool);
	TST_RUN(test_jwt_url_encode_decode, pool);
	TST_RUN(test_jwt_header_to_string, pool);
	TST_RUN(test_jwt_parse, pool);
	TST_RUN(test_plaintext_jwt_parse, pool);
	TST_RUN(test_jwt_get_string, pool);

	TST_RUN(test_jwk_parse_json, pool);
	TST_RUN(test_jwt_decryption, pool);

	TST_RUN(test_jwt_verify_rsa, pool);

	//TST_RUN(test_proto_validate_access_token, r);
	//TST_RUN(test_proto_validate_code, r);

	return 0;
}
/*
static request_rec * test_core_setup(apr_pool_t *pool) {
	const unsigned int kIdx = 0;
	const unsigned int kEls = kIdx + 1;
	apr_uri_t url;
	request_rec *request = (request_rec *) malloc(sizeof(request_rec));

	request->pool = pool;

	request->headers_in = apr_table_make(request->pool, 0);
	request->headers_out = apr_table_make(request->pool, 0);
	request->err_headers_out = apr_table_make(request->pool, 0);

	apr_table_set(request->headers_in, "Host", "www.example.com");
	apr_table_set(request->headers_in, "OIDC_foo", "some-value");
	apr_table_set(request->headers_in, "Cookie", "foo=bar; "
			"mod_auth_openidc_session" "=0123456789abcdef; baz=zot");

	request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
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
	url.scheme = "https";
	url.hostname = "www.example.com";
	url.path = "/protected/";
	memcpy(&cfg->redirect_uri, &url, sizeof(apr_uri_t));

	oidc_dir_cfg *d_cfg = oidc_create_dir_config(request->pool, NULL);

	request->server->module_config = apr_pcalloc(request->pool,
			sizeof(ap_conf_vector_t *) * kEls);
	request->per_dir_config = apr_pcalloc(request->pool,
			sizeof(ap_conf_vector_t *) * kEls);
	ap_set_module_config(request->server->module_config, &auth_openidc_module,
			cfg);
	ap_set_module_config(request->per_dir_config, &auth_openidc_module, d_cfg);

	return request;
}

static void test_core_teardown(request_rec *request) {
	free(request);
}
*/
int main(int argc, char **argv, char **env) {
	if (apr_app_initialize(&argc, (const char * const **) argv,
			(const char * const **) env) != APR_SUCCESS) {
		printf("apr_app_initialize failed\n");
		return -1;
	}

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, NULL);

	//request_rec *r = test_core_setup(pool);

	OpenSSL_add_all_digests();

	char *result = all_tests(pool/*, r*/);
	if (result != 0) {
		printf("Failed: %s\n", result);
	} else {
		printf("All %d tests passed!\n", test_nr_run);
	}

	//test_core_teardown(r);

	EVP_cleanup();
	apr_pool_destroy(pool);
	apr_terminate();

	return result != 0;
}

