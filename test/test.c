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
 * Copyright (C) 2013-2014 Ping Identity Corporation
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

#define TST_ASSERT_STR(message, result, expected) \
	TST_RC = ((!result) || (!expected)) ? (result != expected) : strcmp(result, expected); \
	if (TST_RC) { \
		sprintf(TST_ERR_MSG, TST_FORMAT("%s"), __FUNCTION__, message, result, expected); \
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
	TST_ASSERT("jwt_array_has_string (1)", apr_jwt_array_has_string(haystack, "a"));
	TST_ASSERT("jwt_array_has_string (2)", apr_jwt_array_has_string(haystack, "d") == FALSE);
	return 0;
}

static char *test_jwt_url_encode_decode(apr_pool_t *pool) {
	char *dst = NULL;
	char *src = "abcd";

	TST_ASSERT("apr_jwt_base64url_encode (1)", apr_jwt_base64url_encode(pool, &dst, src, strlen(src), 0));
	TST_ASSERT_STR("apr_jwt_base64url_encode (2)", dst, "YWJjZA");

	src = dst;

	TST_ASSERT("apr_jwt_base64url_decode (1)", apr_jwt_base64url_decode(pool, &dst, src, 1));
	TST_ASSERT_STR("apr_jwt_base64url_decode (2)", dst, "abcd");

	return 0;
}

static char *test_jwt_header_to_string(apr_pool_t *pool) {
	const char * s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
	const char *dst = apr_jwt_header_to_string(pool, s);
	TST_ASSERT_STR("apr_jwt_header_to_string", dst, "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");
	return 0;
}

static char *test_jwt_parse(apr_pool_t *pool) {

	// from http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20
	// 3.1.  Example JWT
	char *s = apr_pstrdup(pool,
			"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" \
			".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" \
			".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

	apr_jwt_t *jwt = NULL;
	TST_ASSERT("apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, NULL));

	TST_ASSERT_STR("header.alg", jwt->header.alg, "HS256");
	TST_ASSERT_STR("header.enc", jwt->header.enc, NULL);
	TST_ASSERT_STR("header.kid", jwt->header.kid, NULL);

	TST_ASSERT_STR("payload.iss", jwt->payload.iss, "joe");
	TST_ASSERT_LONG("payload.exp", (long)apr_time_sec(jwt->payload.exp), 1300819380L);

	char *str_key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
	char *raw_key = NULL;
	int raw_key_len = apr_jwt_base64url_decode(pool, &raw_key, str_key, 1);

	TST_ASSERT("apr_jws_verify_hmac", apr_jws_verify_hmac(pool, jwt, raw_key, raw_key_len));

	s[5] = '.';
	TST_ASSERT("corrupted header (1) apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, NULL) == FALSE);

	s[0] = '\0';
	TST_ASSERT("corrupted header (2) apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, NULL) == FALSE);

	return 0;
}

static char *test_jwt_get_string(apr_pool_t *pool) {
	//apr_jwt_get_string

	const char *s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" \
	".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" \
	".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	apr_jwt_t *jwt = NULL;
	TST_ASSERT("apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, NULL));

	char *dst = NULL;

	TST_ASSERT("apr_jwt_get_string (1a)", apr_jwt_get_string(pool, &jwt->header.value, "typ", &dst));
	TST_ASSERT_STR("apr_jwt_get_string (1b)", dst, "JWT");

	TST_ASSERT("apr_jwt_get_string (2a)", apr_jwt_get_string(pool, &jwt->header.value, "alg", &dst));
	TST_ASSERT_STR("apr_jwt_get_string (2b)", dst, "HS256");

	TST_ASSERT("apr_jwt_get_string (3a)", apr_jwt_get_string(pool, &jwt->header.value, "dummy", &dst));
	TST_ASSERT_STR("apr_jwt_get_string (3b)", dst, NULL);

	return 0;
}

static char *test_jwk_parse_json(apr_pool_t *pool) {
	const char *s = "{\"kty\":\"EC\",\"use\":\"sig\"," \
             "\"kid\":\"the key\"," \
             "\"x\":\"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4\"," \
             "\"y\":\"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co\",\"crv\":\"P-256\"}";

	json_t *j_jwk = NULL;
	json_error_t json_error;
	j_jwk = json_loads(s, 0, &json_error);

	TST_ASSERT("json_loads", ((j_jwk != NULL) && (json_is_object(j_jwk))));

	apr_jwk_t *jwk = NULL;
	TST_ASSERT("apr_jwk_parse_json", apr_jwk_parse_json(pool, j_jwk, s, &jwk));

	return 0;
}

static char *test_jwt_decryption(apr_pool_t *pool) {

	// from http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-30
	// A.2.  Example JWE using RSAES-PKCS1-V1_5 and AES_128_CBC_HMAC_SHA_256
	char *s = apr_pstrdup(pool,
			"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" \
			".UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
			".AxY8DCtDaGlsbGljb3RoZQ" \
		    ".KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY" \
		    ".9hH0vgRfYgPnAHOd8stkvw");

	char * k = "{\"kty\":\"RSA\"," \
      "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," \
      "\"e\":\"AQAB\"," \
      "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"" \
      "}";

	apr_hash_t *keys = apr_hash_make(pool);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, k);

	apr_array_header_t *unpacked = apr_jwt_compact_deserialize(pool, s);
	TST_ASSERT("apr_jwt_compact_deserialize", unpacked != NULL);
	TST_ASSERT_LONG("unpacked->nelts", (long)unpacked->nelts, 5L);

	apr_jwt_t *jwt = apr_pcalloc(pool, sizeof(apr_jwt_t));
	TST_ASSERT("apr_jwt_parse_header", apr_jwt_parse_header(pool, ((const char**) unpacked->elts)[0], &jwt->header));

	char *decrypted = NULL;
	TST_ASSERT("apr_jwe_decrypt_jwt", apr_jwe_decrypt_jwt(pool, &jwt->header, unpacked, keys, NULL, &decrypted));

	TST_ASSERT_STR("apr_jwe_decrypt_jwt (2)", decrypted, "Live long and prosper.");

	return 0;
}


static char * all_tests(apr_pool_t *pool) {
	char *message;
	TST_RUN(test_jwt_array_has_string, pool);
	TST_RUN(test_jwt_url_encode_decode, pool);
	TST_RUN(test_jwt_header_to_string, pool);
	TST_RUN(test_jwt_parse, pool);
	TST_RUN(test_jwt_get_string, pool);

	TST_RUN(test_jwk_parse_json, pool);
	TST_RUN(test_jwt_decryption, pool);

	return 0;
}

int main(int argc, char **argv, char **env) {
	if (apr_app_initialize(&argc, (const char *const **) argv, (const char *const **) env) != APR_SUCCESS) {
		printf("apr_app_initialize failed\n");
		return -1;
	}

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, NULL);;
	OpenSSL_add_all_digests();

	char *result = all_tests(pool);
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

