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
 * Copyright (C) 2013-2017 Ping Identity Corporation
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

#include "handle/handle.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"

#include "cfg/cfg_int.h"
#include "cfg/dir.h"
#include "util/util.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

static int test_nr_run = 0;
static char TST_ERR_MSG[4096];
static int TST_RC;

#define TST_FORMAT(fmt) " # %s: error in %s: result \"" fmt "\" != expected \"" fmt "\""

#define TST_ASSERT(message, expression)                                                                                \
	TST_RC = (expression);                                                                                         \
	if (!TST_RC) {                                                                                                 \
		snprintf(TST_ERR_MSG, 4096, TST_FORMAT("%d"), __FUNCTION__, message, TST_RC, 1);                       \
		return TST_ERR_MSG;                                                                                    \
	}

#define TST_ASSERT_ERR(message, expression, pool, err)                                                                 \
	TST_RC = (expression);                                                                                         \
	if (!TST_RC) {                                                                                                 \
		snprintf(TST_ERR_MSG, 4096, TST_FORMAT("%d") " %s", __FUNCTION__, message, TST_RC, 1,                  \
			 oidc_jose_e2s(pool, err));                                                                    \
		return TST_ERR_MSG;                                                                                    \
	}

#define TST_ASSERT_CJOSE_ERR(message, expression, pool, cjose_err)                                                     \
	TST_RC = (expression);                                                                                         \
	if (!TST_RC) {                                                                                                 \
		snprintf(TST_ERR_MSG, 4096, TST_FORMAT("%d") " %s", __FUNCTION__, message, TST_RC, 1,                  \
			 oidc_cjose_e2s(pool, cjose_err));                                                             \
		return TST_ERR_MSG;                                                                                    \
	}

#define TST_ASSERT_STR(message, result, expected)                                                                      \
	TST_RC =                                                                                                       \
	    (result && expected) ? (_oidc_strcmp(result, expected) != 0) : ((result != NULL) || (expected != NULL));   \
	if (TST_RC) {                                                                                                  \
		snprintf(TST_ERR_MSG, 4096, TST_FORMAT("%s"), __FUNCTION__, message, result ? result : "(null)",       \
			 expected ? expected : "(null)");                                                              \
		return TST_ERR_MSG;                                                                                    \
	}

#define TST_ASSERT_STRN(message, result, expected, len)                                                                \
	TST_RC = (result && expected) ? (_oidc_strncmp(result, expected, len) != 0)                                    \
				      : ((result != NULL) || (expected != NULL));                                      \
	if (TST_RC) {                                                                                                  \
		snprintf(TST_ERR_MSG, 4096, TST_FORMAT("%s"), __FUNCTION__, message, result ? result : "(null)",       \
			 expected ? expected : "(null)");                                                              \
		return TST_ERR_MSG;                                                                                    \
	}

#define TST_ASSERT_LONG(message, result, expected)                                                                     \
	if (result != expected) {                                                                                      \
		snprintf(TST_ERR_MSG, 4096, TST_FORMAT("%ld"), __FUNCTION__, message, result, expected);               \
		return TST_ERR_MSG;                                                                                    \
	}

#define TST_ASSERT_BYTE(message, result, expected)                                                                     \
	if (result != expected) {                                                                                      \
		snprintf(TST_ERR_MSG, 4096, TST_FORMAT("%s"), __FUNCTION__, message, result ? "TRUE" : "FALSE",        \
			 expected ? "TRUE" : "FALSE");                                                                 \
		return TST_ERR_MSG;                                                                                    \
	}

#define TST_RUN(test, pool)                                                                                            \
	message = test(pool);                                                                                          \
	test_nr_run++;                                                                                                 \
	if (message)                                                                                                   \
		return message;

static char *_jwk_parse(apr_pool_t *pool, const char *s, oidc_jwk_t **jwk, oidc_jose_error_t *err) {
	json_error_t json_err;
	json_t *json = json_loads(s, 0, &json_err);
	oidc_jwk_t *k = oidc_jwk_parse(pool, json, err);
	TST_ASSERT_ERR("oidc_jwk_parse", k != NULL, pool, (*err));
	*jwk = k;
	json_decref(json);
	return 0;
}

static char *test_private_key_parse(apr_pool_t *pool) {
	oidc_jose_error_t err = {{'\0'}, 0, {'\0'}, {'\0'}};
	BIO *input = NULL;
	oidc_jwk_t *jwk = NULL;
	int isPrivateKey = 1;
	int result;
	char *json = NULL;

	const char rsaPrivateKeyFile[512];
	const char ecPrivateKeyFile[512];

	char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	snprintf((char *)rsaPrivateKeyFile, 512, "%s/%s", dir, "/private.pem");
	snprintf((char *)ecPrivateKeyFile, 512, "%s/%s", dir, "/ecpriv.key");

	input = BIO_new(BIO_s_file());
	TST_ASSERT_ERR("test_private_key_parse_BIO_new_RSA_private_key", input != NULL, pool, err);

	TST_ASSERT_ERR("test_private_key_parse_BIOread_filename_RSA_private_key",
		       result = BIO_read_filename(input, rsaPrivateKeyFile), pool, err);

	TST_ASSERT_ERR("oidc_jwk_pem_bio_to_jwk", oidc_jwk_pem_bio_to_jwk(pool, input, NULL, &jwk, isPrivateKey, &err),
		       pool, err);
	BIO_free(input);

	TST_ASSERT_ERR("oidc_jwk_to_json with RSA private key", oidc_jwk_to_json(pool, jwk, &json, &err), pool, err);
	TST_ASSERT_STR(
	    "oidc_jwk_to_json with RSA private key output test", json,
	    "{\"kty\":\"RSA\",\"kid\":\"IbLjLR7-C1q0-ypkueZxGIJwBQNaLg46DZMpnPW1kps\",\"e\":\"AQAB\",\"n\":"
	    "\"iGeTXbfV5bMppx7o7qMLCuVIKqbBa_qOzBiNNpe0K8rjg7-1z9GCuSlqbZtM0_5BQ6bGonnSPD--"
	    "PowhFdivS4WNA33O0Kl1tQ0wdH3TOnwueIO9ahfW4q0BGFvMObneK-tjwiNMj1l-cZt8pvuS-3LtTWIzC-"
	    "hTZM4caUmy5olm5PVdmru6C6V5rxkbYBPITFSzl5mpuo_C6RV_MYRwAh60ghs2OEvIWDrJkZnYaF7sjHC9j-"
	    "4kfcM5oY7Zhg8KuHyloudYNzlqjVAPd0MbkLkh1pa8fmHsnN6cgfXYtFK7Z8WjYDUAhTH1JjZCVSFN55A-51dgD4cQNzieLEEkJw\","
	    "\"d\":\"Xc9d-kZERQVC0Dzh1b0sCwJE75Bf1fMr4hHAjJsovjV641ElqRdd4Borp9X2sJVcLTq1wWgmvmjYXgvhdTTg2f-"
	    "vS4dqhPcGjM3VVUhzzPU6wIdZ7W0XzC1PY4E-ozTBJ1Nr-EhujuftnhRhVjYOkAAqU94FXVsaf2mBAKg-"
	    "8WzrWx2MeWjfLcE79DmSL9Iw2areKVRGlKddIIPnHb-Mw9HB7ZCyVTC1v5sqhQPy6qPo8XHdQju_EYRlIOMksU8kcb20R_ezib_"
	    "rHuVwJVlTNk6MvFUIj4ayXdX13Qy4kTBRiQM7pumPaypEE4CrAfTWP0AYnEwz_FGluOpMZNzoAQ\"}");
	oidc_jwk_destroy(jwk);

	input = BIO_new(BIO_s_file());
	TST_ASSERT_ERR("test_private_key_parse_BIO_new_EC_private_key", input != NULL, pool, err);

	TST_ASSERT_ERR("test_private_key_parse_BIOread_filename_EC_private_key",
		       result = BIO_read_filename(input, ecPrivateKeyFile), pool, err);

	TST_ASSERT_ERR("oidc_jwk_pem_bio_to_jwk", oidc_jwk_pem_bio_to_jwk(pool, input, NULL, &jwk, isPrivateKey, &err),
		       pool, err);
	BIO_free(input);

	TST_ASSERT_ERR("oidc_jwk_to_json with EC private key", oidc_jwk_to_json(pool, jwk, &json, &err), pool, err);
	TST_ASSERT_STR(
	    "oidc_jwk_to_json with EC private key output test", json,
	    "{\"kty\":\"EC\",\"kid\":\"-THDTumMGazABrYTb8xJoYOK2OPiWmho3D-nPC1dSYg\",\"crv\":\"P-521\",\"x\":"
	    "\"AR6Eh9VhdLEA-rm5WR0_T0LjKysJuBkSoXaR8GjphHvoOTrljcACRsVlTES9FMkbxbNEs4JdxPgPJl9G-e9WEJTe\",\"y\":"
	    "\"AammgflZaJuSdycK_ccUXkSXjNQd8NsqJuv9LFpk5Ys1OAiirWm6uktXG8ALNSxSffcurBq8zqZyZ141dV6qSzKQ\",\"d\":"
	    "\"AKFwyWAZ2FiTTEofXXOC6I2GBPQeEyCnsVzo075hCOcebYgLpzSj8xWfkTqxsUq8FF5cxlKS3jym3qgsuV0Eb0wd\"}");
	oidc_jwk_destroy(jwk);

	return 0;
}

static char *test_public_key_parse(apr_pool_t *pool) {

	oidc_jose_error_t err = {{'\0'}, 0, {'\0'}, {'\0'}};
	oidc_jwk_t *jwk, *jwkCert = NULL;

	BIO *input, *inputCert = NULL;
	char *json = NULL;

	int isPrivateKey = 0;
	int result;

	const char publicKeyFile[512];
	const char certificateFile[512];
	const char ecCertificateFile[512];
	char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	snprintf((char *)publicKeyFile, 512, "%s/%s", dir, "/public.pem");
	snprintf((char *)certificateFile, 512, "%s/%s", dir, "/certificate.pem");
	snprintf((char *)ecCertificateFile, 512, "%s/%s", dir, "/eccert.pem");

	input = BIO_new(BIO_s_file());
	TST_ASSERT_ERR("test_public_key_parse_BIO_new_public_key", input != NULL, pool, err);

	TST_ASSERT_ERR("test_public_key_parse_BIOread_filename_public_key",
		       result = BIO_read_filename(input, publicKeyFile), pool, err);

	TST_ASSERT_ERR("oidc_jwk_pem_bio_to_jwk", oidc_jwk_pem_bio_to_jwk(pool, input, NULL, &jwk, isPrivateKey, &err),
		       pool, err);
	BIO_free(input);

	inputCert = BIO_new(BIO_s_file());
	TST_ASSERT_ERR("test_public_key_parse_BIO_new_certificate", inputCert != NULL, pool, err);

	TST_ASSERT_ERR("test_public_key_parse_BIOread_filename_certificate",
		       BIO_read_filename(inputCert, certificateFile), pool, err);

	TST_ASSERT_ERR("oidc_jwk_pem_bio_to_jwk",
		       oidc_jwk_pem_bio_to_jwk(pool, inputCert, NULL, &jwkCert, isPrivateKey, &err), pool, err);
	BIO_free(inputCert);

	TST_ASSERT_ERR("oidc_jwk_to_json with public key", oidc_jwk_to_json(pool, jwk, &json, &err), pool, err);
	TST_ASSERT_STR(
	    "oidc_jwk_to_json with public key output test", json,
	    "{\"kty\":\"RSA\",\"kid\":\"IbLjLR7-C1q0-ypkueZxGIJwBQNaLg46DZMpnPW1kps\",\"e\":\"AQAB\",\"n\":"
	    "\"iGeTXbfV5bMppx7o7qMLCuVIKqbBa_qOzBiNNpe0K8rjg7-1z9GCuSlqbZtM0_5BQ6bGonnSPD--"
	    "PowhFdivS4WNA33O0Kl1tQ0wdH3TOnwueIO9ahfW4q0BGFvMObneK-tjwiNMj1l-cZt8pvuS-3LtTWIzC-"
	    "hTZM4caUmy5olm5PVdmru6C6V5rxkbYBPITFSzl5mpuo_C6RV_MYRwAh60ghs2OEvIWDrJkZnYaF7sjHC9j-"
	    "4kfcM5oY7Zhg8KuHyloudYNzlqjVAPd0MbkLkh1pa8fmHsnN6cgfXYtFK7Z8WjYDUAhTH1JjZCVSFN55A-51dgD4cQNzieLEEkJw\"}");
	oidc_jwk_destroy(jwk);

	TST_ASSERT_ERR("oidc_jwk_to_json with certificate", oidc_jwk_to_json(pool, jwkCert, &json, &err), pool, err);
	TST_ASSERT_STR("oidc_jwk_to_json with certificate output test", json,
		       "{\"kty\":\"RSA\",\"kid\":\"IbLjLR7-C1q0-ypkueZxGIJwBQNaLg46DZMpnPW1kps\",\"e\":\"AQAB\",\"n\":"
		       "\"iGeTXbfV5bMppx7o7qMLCuVIKqbBa_qOzBiNNpe0K8rjg7-1z9GCuSlqbZtM0_5BQ6bGonnSPD--"
		       "PowhFdivS4WNA33O0Kl1tQ0wdH3TOnwueIO9ahfW4q0BGFvMObneK-tjwiNMj1l-cZt8pvuS-3LtTWIzC-"
		       "hTZM4caUmy5olm5PVdmru6C6V5rxkbYBPITFSzl5mpuo_C6RV_MYRwAh60ghs2OEvIWDrJkZnYaF7sjHC9j-"
		       "4kfcM5oY7Zhg8KuHyloudYNzlqjVAPd0MbkLkh1pa8fmHsnN6cgfXYtFK7Z8WjYDUAhTH1JjZCVSFN55A-"
		       "51dgD4cQNzieLEEkJw\",\"x5c\":[\"MIICnTCCAYUCBgFuk1+"
		       "FLDANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAd2aW5jZW50MB4XDTE5MTEyMjEzNDcyMVoXDTI5MTEyMjEzNDkwMVowEj"
		       "EQMA4GA1UEAwwHdmluY2VudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIhnk1231eWzKace6O6jCwrlSCqmw"
		       "Wv6jswYjTaXtCvK44O/tc/Rgrkpam2bTNP+QUOmxqJ50jw/"
		       "vj6MIRXYr0uFjQN9ztCpdbUNMHR90zp8LniDvWoX1uKtARhbzDm53ivrY8IjTI9ZfnGbfKb7kvty7U1iMwvoU2TOHGlJsua"
		       "JZuT1XZq7ugulea8ZG2ATyExUs5eZqbqPwukVfzGEcAIetIIbNjhLyFg6yZGZ2Ghe7IxwvY/"
		       "uJH3DOaGO2YYPCrh8paLnWDc5ao1QD3dDG5C5IdaWvH5h7JzenIH12LRSu2fFo2A1AIUx9SY2QlUhTeeQPudXYA+"
		       "HEDc4nixBJCcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfAo40il4qw7DfOkke0p1ZFAgLQQS3J5hYNDSRvVv+vxkk9o/"
		       "N++zTMoHbfcDcU5BdVH6Qsr/12PXPX7Ur5WYDq+bWGAK3MAaGtZlmycFeVhoVRfab4TUWUy43H3VyFUNqjGRAVJ/"
		       "VD1RW3fJ18KrQTN2fcKSd88Jqt5TvjROKghq95+8BQtlhrR/"
		       "sQVrjgYwc+eU9ljWI56MQXbpHstl9IewMXnusSPxKRTbutjaxzKaoXRTUncPL6ga0SSxOTdKksM4ZYpPnq0B93silb+"
		       "0qs8aJraGzjAmLE30opfufP+roth19VJxAfYsW5mgAmXP9kEAF+iWB8FB4/"
		       "Q4noNG8Q==\"],\"x5t#S256\":\"hMVJ55Mqi4uAQIztPKUmL2MSfy6iN1Lr3J1CNGAIBms\",\"x5t\":\"0oN6Bx-"
		       "eh6VAmNw1I7o3Dd9JPwE\"}");
	oidc_jwk_destroy(jwkCert);

	inputCert = BIO_new(BIO_s_file());
	TST_ASSERT_ERR("test_public_key_parse_BIO_new_EC_certificate", inputCert != NULL, pool, err);

	TST_ASSERT_ERR("test_public_key_parse_BIOread_filename_EC_certificate",
		       BIO_read_filename(inputCert, ecCertificateFile), pool, err);

	TST_ASSERT_ERR("oidc_jwk_pem_bio_to_jwk",
		       oidc_jwk_pem_bio_to_jwk(pool, inputCert, NULL, &jwkCert, isPrivateKey, &err), pool, err);
	BIO_free(inputCert);

	TST_ASSERT_ERR("oidc_jwk_to_json with EC certificate", oidc_jwk_to_json(pool, jwkCert, &json, &err), pool, err);
	TST_ASSERT_STR(
	    "oidc_jwk_to_json with EC certificate output test", json,
	    "{\"kty\":\"EC\",\"kid\":\"-THDTumMGazABrYTb8xJoYOK2OPiWmho3D-nPC1dSYg\",\"crv\":\"P-521\",\"x\":"
	    "\"AR6Eh9VhdLEA-rm5WR0_T0LjKysJuBkSoXaR8GjphHvoOTrljcACRsVlTES9FMkbxbNEs4JdxPgPJl9G-e9WEJTe\",\"y\":"
	    "\"AammgflZaJuSdycK_ccUXkSXjNQd8NsqJuv9LFpk5Ys1OAiirWm6uktXG8ALNSxSffcurBq8zqZyZ141dV6qSzKQ\",\"x5c\":["
	    "\"MIICBDCCAWagAwIBAgIUdYpkXaCal7IwjHix3n1PP9/"
	    "O6OcwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIzMDMyMzIwNDU1MFoXDTMzMDMyMDIwNDU1MFowFDESMBAGA1UEA"
	    "wwJbG9jYWxob3N0MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBHoSH1WF0sQD6ublZHT9PQuMrKwm4GRKhdpHwaOmEe+"
	    "g5OuWNwAJGxWVMRL0UyRvFs0Szgl3E+A8mX0b571YQlN4BqaaB+Vlom5J3Jwr9xxReRJeM1B3w2yom6/"
	    "0sWmTlizU4CKKtabq6S1cbwAs1LFJ99y6sGrzOpnJnXjV1XqpLMpCjUzBRMB0GA1UdDgQWBBTKfLLXyRVQpnXFf19Bs7eXRPlRmzAfBgNV"
	    "HSMEGDAWgBTKfLLXyRVQpnXFf19Bs7eXRPlRmzAPBgNVHRMBAf8EBTADAQH/"
	    "MAoGCCqGSM49BAMCA4GLADCBhwJBGkoifMDYwsSLSmnnVdFftqTwxrjdgrtPMRzetz/w/"
	    "D9KkM4Mlufgv5jBXuWcEiP9ray2ZgAGhdkvoOfsc8g1l6ICQgEJ+"
	    "9R5K2WKlDTEydmiHiSYQHSVyS61PFskm537AqrLVSRu80Sezu2W4m8IF2UbbRZiUPaHPIx9Xe3GdpqIEmPFfA==\"],\"x5t#S256\":"
	    "\"yCl_u4GL5GrTkf8xvqdF2aixUIhjDdsMFhLUz7O6gVA\",\"x5t\":\"waxmjjAAhxGY5XvH6ufxVxwYGDw\"}");
	oidc_jwk_destroy(jwkCert);

	return 0;
}

static char *test_jwt_parse(apr_pool_t *pool) {

	// from http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20
	// 3.1.  Example JWT
	char *s = apr_pstrdup(
	    pool, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
		  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
		  ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;
	TST_ASSERT_ERR("oidc_jwt_parse", oidc_jwt_parse(pool, s, &jwt, NULL, FALSE, &err), pool, err);

	TST_ASSERT_STR("header.alg", jwt->header.alg, "HS256");
	TST_ASSERT_STR("header.enc", jwt->header.enc, NULL);
	TST_ASSERT_STR("header.kid", jwt->header.kid, NULL);

	TST_ASSERT_STR("payload.iss", jwt->payload.iss, "joe");
	TST_ASSERT_LONG("payload.exp", (long)jwt->payload.exp, 1300819380L);

	apr_hash_t *keys = apr_hash_make(pool);
	oidc_jwk_t *jwk;
	const char *k =
	    "{\"kty\":\"oct\", "
	    "\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
	jwk = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse", _jwk_parse(pool, k, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);
	TST_ASSERT_ERR("oidc_jwt_verify", oidc_jwt_verify(pool, jwt, keys, &err), pool, err);
	oidc_jwt_destroy(jwt);
	oidc_jwk_destroy(jwk);

	s[5] = OIDC_CHAR_DOT;
	TST_ASSERT_ERR("corrupted header (1) oidc_jwt_parse", oidc_jwt_parse(pool, s, &jwt, NULL, FALSE, &err) == FALSE,
		       pool, err);

	oidc_jwt_destroy(jwt);

	s[0] = '\0';
	TST_ASSERT_ERR("corrupted header (2) oidc_jwt_parse", oidc_jwt_parse(pool, s, &jwt, NULL, FALSE, &err) == FALSE,
		       pool, err);

	oidc_jwt_destroy(jwt);

	return 0;
}

#if (OIDC_JOSE_EC_SUPPORT)

static char *test_jwt_verify_ec(apr_pool_t *pool) {

	// {
	//   "sub": "joe",
	//   "aud": "ac_oic_client",
	//   "jti": "oDWivWPJB47zkjOm2cygDv",
	//   "iss": "https://localhost:9031",
	//   "iat": 1467997207,
	//   "exp": 1467997507,
	//   "nonce": "WLxmv5StYyUk9JlWI8SaXTLPkGZ0Vs8aSTdj_VQ6rao"
	// }

	char *s_jwt =
	    apr_pstrdup(pool, "eyJhbGciOiJFUzI1NiIsImtpZCI6ImY2cXRqIn0."
			      "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoib0RXaXZXUEpCNDd6a2pPbTJjeWdEdiIs"
			      "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2Nzk5NzIwNywiZXhwIjoxNDY3OTk3NTA3"
			      "LCJub25jZSI6IldMeG12NVN0WXlVazlKbFdJOFNhWFRMUGtHWjBWczhhU1Rkal9WUTZyYW8ifQ."
			      "2kqX56QNow37gOlnfLn0SIzwie4mLLIUx_p9OSQa0hiUXKQWQLmMYBjIp5qGh2-R-KPHwNEBxqXwuPgXG4Y7Eg");
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;
	TST_ASSERT_ERR("oidc_jwt_parse (ec0)", oidc_jwt_parse(pool, s_jwt, &jwt, NULL, FALSE, &err), pool, err);

	char *s_key = "{"
		      "\"kty\": \"EC\","
		      "\"kid\": \"f6qtj\","
		      "\"use\": \"sig\","
		      "\"x\": \"iARwFlN3B3xa8Zn_O-CVfqry68tXIhO9DckKo1yrNg0\","
		      "\"y\": \"583S_mPS7YVZtLCjx2O69G_JzQPnMxjieOli-9cc_6Q\","
		      "\"crv\": \"P-256\""
		      "}";

	apr_hash_t *keys = apr_hash_make(pool);
	oidc_jwk_t *jwk = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse", _jwk_parse(pool, s_key, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "f6qtj", APR_HASH_KEY_STRING, jwk);
	TST_ASSERT_ERR("oidc_jwt_verify (ec0)", oidc_jwt_verify(pool, jwt, keys, &err), pool, err);
	oidc_jwt_destroy(jwt);

	s_jwt =
	    apr_pstrdup(pool, "eyJhbGciOiJFUzI1NiIsImtpZCI6ImY2cXRqIn0."
			      "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoib0RXaXZXUEpCNDd6a2pPbTJjeWdEdiIs"
			      "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2Nzk5NzIwNywiZXhwIjoxNDY3OTk3NTA3"
			      "LCJub25jZSI6IldMeG12NVN0WXlVazlKbFdJOFNhWFRMUGtHWjBWczhhU1Rkal9WUTZyYW8ifQ."
			      "2kqX56QNow37gOlnfLn0SIzwie4mLLIUx_p9OSQa0hiUXKQWQLmMYBjIp5qGh2-R-KPHwNEBxqXwuPgXG4Y7EG");
	jwt = NULL;
	TST_ASSERT_ERR("oidc_jwt_parse (ec1)", oidc_jwt_parse(pool, s_jwt, &jwt, NULL, FALSE, &err), pool, err);
	TST_ASSERT_ERR("oidc_jwt_verify (ec1)", oidc_jwt_verify(pool, jwt, keys, &err) == FALSE, pool, err);
	oidc_jwt_destroy(jwt);

	s_jwt =
	    apr_pstrdup(pool, "eyJhbGciOiJFUzI1NiIsImtpZCI6ImY2cXRqIn0."
			      "eyJzdWIiOiJqb2UiLCJHdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoib0RXaXZXUEpCNDd6a2pPbTJjeWdEdiIs"
			      "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2Nzk5NzIwNywiZXhwIjoxNDY3OTk3NTA3"
			      "LCJub25jZSI6IldMeG12NVN0WXlVazlKbFdJOFNhWFRMUGtHWjBWczhhU1Rkal9WUTZyYW8ifQ."
			      "2kqX56QNow37gOlnfLn0SIzwie4mLLIUx_p9OSQa0hiUXKQWQLmMYBjIp5qGh2-R-KPHwNEBxqXwuPgXG4Y7Eg");
	jwt = NULL;
	TST_ASSERT_ERR("oidc_jwt_parse (ec2)", oidc_jwt_parse(pool, s_jwt, &jwt, NULL, FALSE, &err), pool, err);
	TST_ASSERT_ERR("oidc_jwt_verify (ec2)", oidc_jwt_verify(pool, jwt, keys, &err) == FALSE, pool, err);
	oidc_jwt_destroy(jwt);

	oidc_jwk_destroy(jwk);

	return 0;
}

#endif

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
	    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9."
	    "eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYX"
	    "NoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6"
	    "InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly"
	    "9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE0MTE1ODA4NzV9.lEG-"
	    "DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk6"
	    "53bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-"
	    "mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_"
	    "kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEA";

	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;
	TST_ASSERT_ERR("oidc_jwt_parse", oidc_jwt_parse(pool, s_jwt, &jwt, NULL, FALSE, &err), pool, err);

	char *s_key =
	    "{"
	    "\"kty\": \"RSA\","
	    "\"n\": "
	    "\"3lDyn_ZvG32Pw5kYbRuVxHsPfe9Xt8s9vOXnt8z7_T-hZZvealNhCxz9VEwTJ7TsZ9CLi5c30FjoEJYFkKddLAdxKo0oOXWc_"
	    "AWrQvPwht9a-o6dX2fL_9CmXW1hGHXMH0qiLMrFqMSzZeh-GUY6F1woE_eKsAo6LOhP8X77FlEQT2Eu71wu8KC4B3sH_9QTco50KNw14-"
	    "bRY5j2V2TZelvsXJnvrN4lXtEVYWFkREKeXzMH8DhDyZzh0NcHa7dFBa7rDusyfIHjuP6uAju_"
	    "Ao6hhdOGjlKePMVtfusWBAI7MWDChLTqiCTvlZnCpkpTTh5m-i7TbE1TwmdbLceq1w\","
	    "\"e\": \"AQAB\""
	    "}";

	apr_hash_t *keys = apr_hash_make(pool);
	oidc_jwk_t *jwk = NULL;

	TST_ASSERT_ERR("oidc_jwk_parse", _jwk_parse(pool, s_key, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	TST_ASSERT_ERR("oidc_jwt_verify", oidc_jwt_verify(pool, jwt, keys, &err), pool, err);

	oidc_jwt_destroy(jwt);
	jwt = NULL;

	s_jwt =
	    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9."
	    "eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYX"
	    "NoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6"
	    "InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly"
	    "9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE1MTE1ODA4NzV9.lEG-"
	    "DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk6"
	    "53bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-"
	    "mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_"
	    "kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEA";
	TST_ASSERT_ERR("oidc_jwt_parse (rsa1)", oidc_jwt_parse(pool, s_jwt, &jwt, NULL, FALSE, &err), pool, err);

	TST_ASSERT_ERR("oidc_jwt_verify (rsa1)", oidc_jwt_verify(pool, jwt, keys, &err) == FALSE, pool, err);

	oidc_jwt_destroy(jwt);
	jwt = NULL;

	s_jwt =
	    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9."
	    "eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYX"
	    "NoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6"
	    "InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly"
	    "9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE0MTE1ODA4NzV9.lEG-"
	    "DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk6"
	    "53bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-"
	    "mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_"
	    "kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEa";
	TST_ASSERT_ERR("oidc_jwt_parse (rsa2)", oidc_jwt_parse(pool, s_jwt, &jwt, NULL, FALSE, &err), pool, err);

	TST_ASSERT_ERR("oidc_jwt_verify (rsa2)", oidc_jwt_verify(pool, jwt, keys, &err) == FALSE, pool, err);

	oidc_jwt_destroy(jwt);
	oidc_jwk_destroy(jwk);

	return 0;
}

static char *test_jwt_sign_verify(apr_pool_t *pool) {

	oidc_jwt_t *jwt = NULL;
	oidc_jwk_t *jwk = NULL;
	char *cser = NULL;
	oidc_jose_error_t err;

	char *s_key =
	    "{"
	    "\"kty\" : \"RSA\","
	    "\"n\": "
	    "\"ym7jipmB37CgdonwGFVRuZmRfCl3lVh91fmm5CXHcNlUFZNR3D6Q9r63PpGRnfSsX3dOweh8BXd2AJ3mxvcE4z9xH--"
	    "tA5EaOGI7IVF0Ip_i3flGg85xOADlb8rX3ez1NqkqMVJeeJypKhCCDNfvu_MXSdPLglU969YQF5xKAK8VFRfI6EfxxrZ_"
	    "3Dvt2CKDV4LTPPJe9KI2_LuLQFBJ3MzlCTVxY6gyaljrWaDq7q5Lt3GB1KYS0Yd8COEQwsclOLm0Tddhg4cle-"
	    "DfaTMi7xsTZsPKyac5x17Y4N4isHhZULuWHX7o1bs809xcj-_-YCRq6C61je_mzFhuF4pczw\","
	    "\"e\": \"AQAB\","
	    "\"d\": "
	    "\"qvxW_"
	    "e8DoCnUn8uLHUKTsS1hkXqFI4SHZYFl0jeG6m7ncwHolxvR3ljg9tyGHuFX55sizu7MMuHgrkyxbUWgv0ILD2qmvOiHOTDfuRjP-"
	    "58JRW0UfqiVQTSgl3jCNRW9WdoxZU-ptD6_NGSVNLwAJsUB2r4mm4PctaMuHINKjp_TnuD-5vfi9Tj88hbqvX_0j8T62ZaLRdERb1KGDM_"
	    "8bnqQpnLZ0MZQnpLQ8cKIcjj7p0II6pzvqgdO1RqfYx7qG0cbcIRh26rnB9X4rp5BrbvDzKe6NOqacZUcNUmbPzI01-"
	    "hiT0HgJvV592CBOxt2T31ltQ4wCEdzhQeT3n9_wQ\""
	    "}";

	apr_hash_t *keys = apr_hash_make(pool);

	TST_ASSERT_ERR("oidc_jwk_parse", _jwk_parse(pool, s_key, &jwk, &err) == 0, pool, err);

	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	jwt = oidc_jwt_new(pool, TRUE, TRUE);
	json_object_set_new(jwt->payload.value.json, "iss", json_string("https://example.org"));
	json_object_set_new(jwt->payload.value.json, "sub", json_string("https://example.org"));
	json_object_set_new(jwt->payload.value.json, "aud", json_string("sample_client"));
	json_object_set_new(jwt->payload.value.json, "exp", json_integer(apr_time_sec(apr_time_now()) + 60));
	json_object_set_new(jwt->payload.value.json, "iat", json_integer(apr_time_sec(apr_time_now())));

	jwt->header.alg = apr_pstrdup(pool, CJOSE_HDR_ALG_RS256);

	TST_ASSERT_ERR("oidc_jwt_sign (rsa)", oidc_jwt_sign(pool, jwt, jwk, FALSE, &err), pool, err);
	cser = oidc_jose_jwt_serialize(pool, jwt, &err);
	TST_ASSERT_ERR("oidc_jose_jwt_serialize (rsa)", cser != NULL, pool, err);

	oidc_jwt_t *rsa_jwt = NULL;
	TST_ASSERT_ERR("oidc_jwt_parse (rsa)", oidc_jwt_parse(pool, cser, &rsa_jwt, NULL, FALSE, &err), pool, err);
	TST_ASSERT_ERR("oidc_jwt_verify (rsa)", oidc_jwt_verify(pool, rsa_jwt, keys, &err), pool, err);
	oidc_jwt_destroy(rsa_jwt);

	oidc_jwk_destroy(jwk);

	const char *secret = "my_secret4321";
	jwk =
	    oidc_jwk_create_symmetric_key(pool, NULL, (const unsigned char *)secret, _oidc_strlen(secret), FALSE, &err);
	TST_ASSERT_ERR("oidc_jwk_create_symmetric_key", jwk != NULL, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	jwt->header.alg = apr_pstrdup(pool, "HS256");

	TST_ASSERT_ERR("oidc_jwt_sign (hmac)", oidc_jwt_sign(pool, jwt, jwk, FALSE, &err), pool, err);
	cser = oidc_jose_jwt_serialize(pool, jwt, &err);
	TST_ASSERT_ERR("oidc_jose_jwt_serialize (hmac)", cser != NULL, pool, err);

	oidc_jwt_t *hmac_jwt = NULL;
	TST_ASSERT_ERR("oidc_jwt_parse (rsa)", oidc_jwt_parse(pool, cser, &hmac_jwt, NULL, FALSE, &err), pool, err);
	TST_ASSERT_ERR("oidc_jwt_verify (rsa)", oidc_jwt_verify(pool, hmac_jwt, keys, &err), pool, err);
	oidc_jwt_destroy(hmac_jwt);

	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);

	return 0;
}

static char *test_plaintext_jwt_parse(apr_pool_t *pool) {

	// from http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20
	// 6.1.  Example Plaintext JWT
	char *s = apr_pstrdup(
	    pool, "eyJhbGciOiJub25lIn0"
		  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
		  ".");

	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;
	TST_ASSERT_ERR("oidc_jwt_parse", oidc_jwt_parse(pool, s, &jwt, NULL, FALSE, &err), pool, err);

	TST_ASSERT_STR("header.alg", jwt->header.alg, "none");

	TST_ASSERT_STR("payload.iss", jwt->payload.iss, "joe");
	TST_ASSERT_LONG("payload.exp", (long)jwt->payload.exp, 1300819380L);

	oidc_jwt_destroy(jwt);

	return 0;
}

static char *test_jwt_get_string(apr_pool_t *pool) {
	// oidc_jose_get_string

	const char *s =
	    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
	    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;
	TST_ASSERT_ERR("oidc_jwt_parse", oidc_jwt_parse(pool, s, &jwt, NULL, FALSE, &err), pool, err);

	char *dst = NULL;
	TST_ASSERT("oidc_jose_get_string (1a)",
		   oidc_jose_get_string(pool, jwt->header.value.json, "typ", TRUE, &dst, &err));
	TST_ASSERT_STR("oidc_jose_get_string (1b)", dst, "JWT");

	dst = NULL;
	TST_ASSERT("oidc_jose_get_string (2a)",
		   oidc_jose_get_string(pool, jwt->header.value.json, "alg", TRUE, &dst, &err));
	TST_ASSERT_STR("oidc_jose_get_string (2b)", dst, "HS256");

	dst = NULL;
	TST_ASSERT("oidc_jose_get_string (3a)",
		   oidc_jose_get_string(pool, jwt->header.value.json, "dummy", FALSE, &dst, &err));
	TST_ASSERT_STR("oidc_jose_get_string (3b)", dst, NULL);

	oidc_jwt_destroy(jwt);

	return 0;
}

static char *test_jwk_parse_json(apr_pool_t *pool) {
	const char *s = "{\"kty\":\"EC\",\"use\":\"sig\","
			"\"kid\":\"the key\","
			"\"x\":\"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4\","
			"\"y\":\"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co\",\"crv\":\"P-256\"}";

	oidc_jose_error_t err;
	oidc_jwk_t *jwk;

	jwk = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse (1)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	oidc_jwk_destroy(jwk);

	// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#appendix-A.3
	// A.3.  Example Symmetric Keys #1
	s = "{"
	    "\"kty\":\"oct\","
	    "\"alg\":\"A128KW\","
	    "\"k\"  :\"GawgguFyGrWKav7AX4VKUg\""
	    "}";

	jwk = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse (draft-ietf-jose-json-web-key-41#appendix-A.3 #1)",
		       _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	oidc_jwk_destroy(jwk);
	// TST_ASSERT_LONG("#1 jwk->type", (long )jwk->type, (long )APR_JWK_KEY_OCT);
	// TST_ASSERT_LONG("#1 jwk->key.oct->k_len", (long )jwk->key.oct->k_len, 16L);

	// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#appendix-A.3
	// A.3.  Example Symmetric Keys #2
	s = "{"
	    "\"kty\":\"oct\","
	    "\"k\"  :\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\","
	    "\"kid\":\"HMAC key used in JWS A.1 example\""
	    "}";

	jwk = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse (draft-ietf-jose-json-web-key-41#appendix-A.3 #2)",
		       _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	oidc_jwk_destroy(jwk);
	// TST_ASSERT_LONG("#2 jwk->type", (long )jwk->type, (long )APR_JWK_KEY_OCT);
	// TST_ASSERT_LONG("#2 jwk->key.oct->k_len", (long )jwk->key.oct->k_len, 64L);

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
	TST_ASSERT_ERR("oidc_jwk_parse (draft-ietf-jose-cookbook-08#section-3.1, EC Public Key)",
		       _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	oidc_jwk_destroy(jwk);

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
	TST_ASSERT_ERR("oidc_jwk_parse (draft-ietf-jose-cookbook-08#section-3.2, EC Private Key)",
		       _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	oidc_jwk_destroy(jwk);

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
	TST_ASSERT_ERR("oidc_jwk_parse (draft-ietf-jose-cookbook-08#section-3.3, RSA Public Key)",
		       _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	oidc_jwk_destroy(jwk);

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
	TST_ASSERT_ERR("oidc_jwk_parse (draft-ietf-jose-cookbook-08#section-3.4, RSA Private Key)",
		       _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	oidc_jwk_destroy(jwk);

	s = "{\"kty\":\"RSA\",\"kid\":\"IbLjLR7-C1q0-ypkueZxGIJwBQNaLg46DZMpnPW1kps\",\"e\":\"AQAB\",\"n\":"
	    "\"iGeTXbfV5bMppx7o7qMLCuVIKqbBa_qOzBiNNpe0K8rjg7-1z9GCuSlqbZtM0_5BQ6bGonnSPD--"
	    "PowhFdivS4WNA33O0Kl1tQ0wdH3TOnwueIO9ahfW4q0BGFvMObneK-tjwiNMj1l-cZt8pvuS-3LtTWIzC-"
	    "hTZM4caUmy5olm5PVdmru6C6V5rxkbYBPITFSzl5mpuo_C6RV_MYRwAh60ghs2OEvIWDrJkZnYaF7sjHC9j-"
	    "4kfcM5oY7Zhg8KuHyloudYNzlqjVAPd0MbkLkh1pa8fmHsnN6cgfXYtFK7Z8WjYDUAhTH1JjZCVSFN55A-"
	    "51dgD4cQNzieLEEkJw\",\"x5c\":[\"MIICnTCCAYUCBgFuk1+"
	    "FLDANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAd2aW5jZW50MB4XDTE5MTEyMjEzNDcyMVoXDTI5MTEyMjEzNDkwMVowEj"
	    "EQMA4GA1UEAwwHdmluY2VudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIhnk1231eWzKace6O6jCwrlSCqmw"
	    "Wv6jswYjTaXtCvK44O/tc/Rgrkpam2bTNP+QUOmxqJ50jw/"
	    "vj6MIRXYr0uFjQN9ztCpdbUNMHR90zp8LniDvWoX1uKtARhbzDm53ivrY8IjTI9ZfnGbfKb7kvty7U1iMwvoU2TOHGlJsua"
	    "JZuT1XZq7ugulea8ZG2ATyExUs5eZqbqPwukVfzGEcAIetIIbNjhLyFg6yZGZ2Ghe7IxwvY/"
	    "uJH3DOaGO2YYPCrh8paLnWDc5ao1QD3dDG5C5IdaWvH5h7JzenIH12LRSu2fFo2A1AIUx9SY2QlUhTeeQPudXYA+"
	    "HEDc4nixBJCcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfAo40il4qw7DfOkke0p1ZFAgLQQS3J5hYNDSRvVv+vxkk9o/"
	    "N++zTMoHbfcDcU5BdVH6Qsr/12PXPX7Ur5WYDq+bWGAK3MAaGtZlmycFeVhoVRfab4TUWUy43H3VyFUNqjGRAVJ/"
	    "VD1RW3fJ18KrQTN2fcKSd88Jqt5TvjROKghq95+8BQtlhrR/"
	    "sQVrjgYwc+eU9ljWI56MQXbpHstl9IewMXnusSPxKRTbutjaxzKaoXRTUncPL6ga0SSxOTdKksM4ZYpPnq0B93silb+"
	    "0qs8aJraGzjAmLE30opfufP+roth19VJxAfYsW5mgAmXP9kEAF+iWB8FB4/"
	    "Q4noNG8Q==\"],\"x5t#S256\":\"hMVJ55Mqi4uAQIztPKUmL2MSfy6iN1Lr3J1CNGAIBms\",\"x5t\":\"0oN6Bx-"
	    "eh6VAmNw1I7o3Dd9JPwE\"}";

	jwk = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse (x5c)", _jwk_parse(pool, s, &jwk, &err) == 0, pool, err);
	TST_ASSERT_STR("oidc_jwk_parse (x5c)", APR_ARRAY_IDX(jwk->x5c, 0, char *),
		       "MIICnTCCAYUCBgFuk1+"
		       "FLDANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAd2aW5jZW50MB4XDTE5MTEyMjEzNDcyMVoXDTI5MTEyMjEzNDkwMVowEj"
		       "EQMA4GA1UEAwwHdmluY2VudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIhnk1231eWzKace6O6jCwrlSCqmw"
		       "Wv6jswYjTaXtCvK44O/tc/Rgrkpam2bTNP+QUOmxqJ50jw/"
		       "vj6MIRXYr0uFjQN9ztCpdbUNMHR90zp8LniDvWoX1uKtARhbzDm53ivrY8IjTI9ZfnGbfKb7kvty7U1iMwvoU2TOHGlJsua"
		       "JZuT1XZq7ugulea8ZG2ATyExUs5eZqbqPwukVfzGEcAIetIIbNjhLyFg6yZGZ2Ghe7IxwvY/"
		       "uJH3DOaGO2YYPCrh8paLnWDc5ao1QD3dDG5C5IdaWvH5h7JzenIH12LRSu2fFo2A1AIUx9SY2QlUhTeeQPudXYA+"
		       "HEDc4nixBJCcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfAo40il4qw7DfOkke0p1ZFAgLQQS3J5hYNDSRvVv+vxkk9o/"
		       "N++zTMoHbfcDcU5BdVH6Qsr/12PXPX7Ur5WYDq+bWGAK3MAaGtZlmycFeVhoVRfab4TUWUy43H3VyFUNqjGRAVJ/"
		       "VD1RW3fJ18KrQTN2fcKSd88Jqt5TvjROKghq95+8BQtlhrR/"
		       "sQVrjgYwc+eU9ljWI56MQXbpHstl9IewMXnusSPxKRTbutjaxzKaoXRTUncPL6ga0SSxOTdKksM4ZYpPnq0B93silb+"
		       "0qs8aJraGzjAmLE30opfufP+roth19VJxAfYsW5mgAmXP9kEAF+iWB8FB4/"
		       "Q4noNG8Q==");
	oidc_jwk_destroy(jwk);

	return 0;
}

static char *test_jwk_copy(apr_pool_t *pool) {
	oidc_jose_error_t err;
	char *s = NULL;
	oidc_jwk_t *jwk1 = NULL;
	oidc_jwk_t *jwk2 = NULL;

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
	    "\"x5t\": \"myx5t\","
	    "\"x5t#S256\": \"myx5t#S256\""
	    "}";

	jwk1 = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse", _jwk_parse(pool, s, &jwk1, &err) == 0, pool, err);
	jwk2 = oidc_jwk_copy(pool, jwk1);

	TST_ASSERT_STR("oidc_jwk_parse (x5t)", jwk1->x5t, "myx5t");
	TST_ASSERT_STR("oidc_jwk_parse (x5t#S256)", jwk1->x5t_S256, "myx5t#S256");
	TST_ASSERT_STR("oidc_jwk_copy (x5t)", jwk2->x5t, "myx5t");
	TST_ASSERT_STR("oidc_jwk_copy (x5t#S256)", jwk2->x5t_S256, "myx5t#S256");

	oidc_jwk_destroy(jwk2);
	oidc_jwk_destroy(jwk1);

	return 0;
}
static char *test_plaintext_decrypt_symmetric(apr_pool_t *pool) {
	oidc_jose_error_t err;
	apr_hash_t *keys = apr_hash_make(pool);
	oidc_jwk_t *jwk;

	// http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40#appendix-A.3
	// A.3.  Example JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
	const char *k = "{\"kty\":\"oct\", \"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
	jwk = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse", _jwk_parse(pool, k, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	const char *s = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
			"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
			"AxY8DCtDaGlsbGljb3RoZQ."
			"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
			"U0m_YmjN04DJvceFICbCVQ";

	cjose_err cjose_err;
	cjose_jwe_t *jwe = cjose_jwe_import(s, _oidc_strlen(s), &cjose_err);
	TST_ASSERT_CJOSE_ERR("cjose_jwe_import", jwe != NULL, pool, cjose_err);

	size_t content_len = 0;
	uint8_t *decrypted = cjose_jwe_decrypt(jwe, jwk->cjose_jwk, &content_len, &cjose_err);
	TST_ASSERT_CJOSE_ERR("cjose_jwe_decrypt", decrypted != NULL, pool, cjose_err);

	TST_ASSERT_STRN("decrypted", (const char *)decrypted, "Live long and prosper.", content_len);

	cjose_get_dealloc()(decrypted);
	oidc_jwk_destroy(jwk);
	cjose_jwe_release(jwe);

	return 0;
}

#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)

static char *test_jwt_decrypt_gcm(apr_pool_t *pool) {

	// https://tools.ietf.org/html/rfc7516#appendix-A.1
	// A.1.  Example JWE using RSAES-OAEP and AES GCM
	char *s = apr_pstrdup(pool, "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
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

	char *k = "{\"kty\":\"RSA\","
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

	oidc_jose_error_t err;
	apr_hash_t *keys = apr_hash_make(pool);
	oidc_jwk_t *jwk = NULL;
	TST_ASSERT_ERR("oidc_jwk_parse", _jwk_parse(pool, k, &jwk, &err) == 0, pool, err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	cjose_err cjose_err;
	cjose_jwe_t *jwe = cjose_jwe_import(s, _oidc_strlen(s), &cjose_err);
	TST_ASSERT_CJOSE_ERR("cjose_jwe_import", jwe != NULL, pool, cjose_err);

	size_t content_len = 0;
	uint8_t *decrypted = cjose_jwe_decrypt(jwe, jwk->cjose_jwk, &content_len, &cjose_err);
	TST_ASSERT_CJOSE_ERR("cjose_jwe_decrypt", decrypted != NULL, pool, cjose_err);

	TST_ASSERT_STRN("decrypted", (const char *)decrypted,
			"The true sign of intelligence is not knowledge but imagination.", content_len);

	cjose_get_dealloc()(decrypted);
	cjose_jwe_release(jwe);
	oidc_jwk_destroy(jwk);

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

	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;
	TST_ASSERT_ERR("oidc_jwt_parse", oidc_jwt_parse(r->pool, s, &jwt, NULL, FALSE, &err), r->pool, err);

	const char *access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
	TST_ASSERT("oidc_proto_validate_access_token",
		   oidc_proto_idtoken_validate_access_token(r, NULL, jwt, "id_token token", access_token));

	oidc_jwt_destroy(jwt);

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

	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;
	TST_ASSERT_ERR("oidc_jwt_parse", oidc_jwt_parse(r->pool, s, &jwt, NULL, FALSE, &err), r->pool, err);

	const char *code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
	TST_ASSERT("oidc_proto_validate_code", oidc_proto_idtoken_validate_code(r, NULL, jwt, "code id_token", code));

	oidc_jwt_destroy(jwt);

	return 0;
}

static char *test_proto_authorization_request(request_rec *r) {

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

	TST_ASSERT("oidc_proto_request_auth (1)",
		   oidc_proto_request_auth(r, provider, NULL, redirect_uri, state, proto_state, NULL, NULL, NULL,
					   NULL) == HTTP_MOVED_TEMPORARILY);

	TST_ASSERT_STR("oidc_proto_request_auth (2)", apr_table_get(r->headers_out, "Location"),
		       "https://idp.example.com/"
		       "authorize?response_type=code&scope=openid&client_id=client_id&state=12345&redirect_uri=https%"
		       "3A%2F%2Fwww.example.com%2Fprotected%2F&nonce=anonce&jan=piet&foo=bar");

	return 0;
}

static char *test_logout_request(request_rec *r) {

	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_session_t *session = NULL;

	oidc_session_load(r, &session);
	oidc_session_set_issuer(r, session, oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)));

	oidc_cfg_provider_end_session_endpoint_set(r->pool, oidc_cfg_provider_get(c),
						   "https://idp.example.com/endsession");
	oidc_cfg_provider_logout_request_params_set(r->pool, oidc_cfg_provider_get(c), "client_id=myclient&foo=bar");

	r->args = "logout=https%3A%2F%2Fwww.example.com%2Floggedout";

	TST_ASSERT("oidc_handle_logout (1)", oidc_logout(r, c, session) == HTTP_MOVED_TEMPORARILY);
	TST_ASSERT_STR(
	    "oidc_handle_logout (2)", apr_table_get(r->headers_out, "Location"),
	    "https://idp.example.com/"
	    "endsession?post_logout_redirect_uri=https%3A%2F%2Fwww.example.com%2Floggedout&client_id=myclient&foo=bar");

	oidc_session_free(r, session);

	return 0;
}

static char *test_proto_validate_nonce(request_rec *r) {

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
	TST_ASSERT_ERR("oidc_jwt_parse", oidc_jwt_parse(r->pool, s_jwt, &jwt, NULL, FALSE, &err), r->pool, err);

	TST_ASSERT("oidc_proto_idtoken_validate_nonce (1)",
		   oidc_proto_idtoken_validate_nonce(r, c, oidc_cfg_provider_get(c), nonce, jwt));
	TST_ASSERT("oidc_proto_idtoken_validate_nonce (2)",
		   oidc_proto_idtoken_validate_nonce(r, c, oidc_cfg_provider_get(c), nonce, jwt) == FALSE);

	oidc_jwt_destroy(jwt);

	return 0;
}

static char *test_proto_validate_jwt(request_rec *r) {

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

	TST_ASSERT("HMAC", HMAC(digest, (const unsigned char *)s_secret, _oidc_strlen(s_secret),
				(const unsigned char *)s_jwt_message, _oidc_strlen(s_jwt_message), md, &md_len) != 0);

	char *s_jwt_signature_encoded = NULL;
	oidc_util_base64url_encode(r, &s_jwt_signature_encoded, (const char *)md, md_len, 1);

	char *s_jwt =
	    apr_psprintf(r->pool, "%s.%s.%s", s_jwt_header_encoded, s_jwt_payload_encoded, s_jwt_signature_encoded);

	TST_ASSERT_ERR("oidc_jwt_parse", oidc_jwt_parse(r->pool, s_jwt, &jwt, NULL, FALSE, &err), r->pool, err);

	oidc_jwk_t *jwk = NULL;
	TST_ASSERT_ERR("oidc_util_create_symmetric_key",
		       oidc_util_key_symmetric_create(r, s_secret, 0, NULL, TRUE, &jwk) == TRUE, r->pool, err);
	TST_ASSERT_ERR("oidc_util_create_symmetric_key (jwk)", jwk != NULL, r->pool, err);

	TST_ASSERT_ERR("oidc_jwt_verify",
		       oidc_jwt_verify(r->pool, jwt, oidc_util_key_symmetric_merge(r->pool, NULL, jwk), &err), r->pool,
		       err);

	TST_ASSERT_ERR("oidc_proto_validate_jwt", oidc_proto_jwt_validate(r, jwt, s_issuer, TRUE, TRUE, 10), r->pool,
		       err);

	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);

	return 0;
}

static char *test_current_url(request_rec *r) {

	char *url = NULL;

	r->uri = "/test";
	r->unparsed_uri = apr_pstrcat(r->pool, r->uri, "?", r->args, NULL);

	url = oidc_util_url_cur(r, 0);
	TST_ASSERT_STR("test_current_url (1)", url, "https://www.example.com/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Host", "www.outer.com");
	url = oidc_util_url_cur(r, 0);
	TST_ASSERT_STR("test_current_url (2a)", url, "https://www.example.com/test?foo=bar&param1=value1");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST);
	TST_ASSERT_STR("test_current_url (2b)", url, "https://www.outer.com/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Host", "www.outer.com:654");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST);
	TST_ASSERT_STR("test_current_url (3)", url, "https://www.outer.com:654/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Port", "321");
	url = oidc_util_url_cur(r, 0);
	TST_ASSERT_STR("test_current_url (4a)", url, "https://www.example.com/test?foo=bar&param1=value1");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST);
	TST_ASSERT_STR("test_current_url (4b)", url, "https://www.outer.com:654/test?foo=bar&param1=value1");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT);
	TST_ASSERT_STR("test_current_url (4)", url, "https://www.outer.com:321/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Proto", "http");
	url = oidc_util_url_cur(r, 0);
	TST_ASSERT_STR("test_current_url (5a)", url, "https://www.example.com/test?foo=bar&param1=value1");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST);
	TST_ASSERT_STR("test_current_url (5b)", url, "https://www.outer.com:654/test?foo=bar&param1=value1");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT);
	TST_ASSERT_STR("test_current_url (5c)", url, "https://www.outer.com:321/test?foo=bar&param1=value1");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT | OIDC_HDR_X_FORWARDED_PROTO);
	TST_ASSERT_STR("test_current_url (5d)", url, "http://www.outer.com:321/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Proto", "https , http");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_HOST | OIDC_HDR_X_FORWARDED_PORT | OIDC_HDR_X_FORWARDED_PROTO);
	TST_ASSERT_STR("test_current_url (6)", url, "https://www.outer.com:321/test?foo=bar&param1=value1");

	apr_table_unset(r->headers_in, "X-Forwarded-Host");
	apr_table_unset(r->headers_in, "X-Forwarded-Port");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO);
	TST_ASSERT_STR("test_current_url (7)", url, "https://www.example.com/test?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "X-Forwarded-Proto", "http ");
	apr_table_set(r->headers_in, "Host", "remotehost:8380");
	r->uri = "http://remotehost:8380/private/";
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO);
	TST_ASSERT_STR("test_current_url (8)", url, "http://remotehost:8380/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Host", "[fd04:41b1:1170:28:16b0:446b:9fb7:7118]:8380");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO);
	TST_ASSERT_STR("test_current_url (9)", url,
		       "http://[fd04:41b1:1170:28:16b0:446b:9fb7:7118]:8380/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Host", "[fd04:41b1:1170:28:16b0:446b:9fb7:7118]");
	url = oidc_util_url_cur(r, OIDC_HDR_X_FORWARDED_PROTO);
	TST_ASSERT_STR("test_current_url (10)", url,
		       "http://[fd04:41b1:1170:28:16b0:446b:9fb7:7118]/private/?foo=bar&param1=value1");

	apr_table_unset(r->headers_in, "X-Forwarded-Proto");
	apr_table_unset(r->headers_in, "Host");

	apr_table_set(r->headers_in, "Forwarded", "host=www.outer.com");
	url = oidc_util_url_cur(r, OIDC_HDR_FORWARDED);
	TST_ASSERT_STR("test_current_url (11)", url, "https://www.outer.com/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Forwarded", "proto=http");
	url = oidc_util_url_cur(r, OIDC_HDR_FORWARDED);
	TST_ASSERT_STR("test_current_url (12)", url, "http://www.example.com/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Forwarded", "host=www.outer.com:8443");
	url = oidc_util_url_cur(r, OIDC_HDR_FORWARDED);
	TST_ASSERT_STR("test_current_url (13)", url, "https://www.outer.com:8443/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Forwarded", "proto=http; host=www.outer.com:8080");
	url = oidc_util_url_cur(r, OIDC_HDR_FORWARDED);
	TST_ASSERT_STR("test_current_url (14)", url, "http://www.outer.com:8080/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Forwarded", "host=www.outer.com:8080; proto=http");
	url = oidc_util_url_cur(r, OIDC_HDR_FORWARDED);
	TST_ASSERT_STR("test_current_url (15)", url, "http://www.outer.com:8080/private/?foo=bar&param1=value1");

	apr_table_unset(r->headers_in, "Forwarded");

	// it should not crash when Forwarded is not present
	url = oidc_util_url_cur(r, OIDC_HDR_FORWARDED);
	TST_ASSERT_STR("test_current_url (16)", url, "https://www.example.com/private/?foo=bar&param1=value1");

	apr_table_set(r->headers_in, "Host", "www.example.com");

	return 0;
}

static char *test_accept(request_rec *r) {

	// ie 9/10/11
	apr_table_set(r->headers_in, "Accept", "text/html, application/xhtml+xml, */*");
	TST_ASSERT("Accept: text/html (ie 9/10/11)", oidc_http_hdr_in_accept_contains(r, "text/html") != 0);
	TST_ASSERT("Accept: application/json (ie 9/10/11)",
		   oidc_http_hdr_in_accept_contains(r, "application/json") == 0);

	// firefox
	apr_table_set(r->headers_in, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	TST_ASSERT("Accept: text/html (firefox)", oidc_http_hdr_in_accept_contains(r, "text/html") != 0);
	TST_ASSERT("Accept: application/json (firefox)", oidc_http_hdr_in_accept_contains(r, "application/json") == 0);

	// chrome/safari
	apr_table_set(r->headers_in, "Accept",
		      "application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5");
	TST_ASSERT("Accept: text/html (chrome/safari)", oidc_http_hdr_in_accept_contains(r, "text/html") != 0);
	TST_ASSERT("Accept: application/json (chrome/safari)",
		   oidc_http_hdr_in_accept_contains(r, "application/json") == 0);

	// safari 5
	apr_table_set(r->headers_in, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	TST_ASSERT("Accept: text/html (safari 5)", oidc_http_hdr_in_accept_contains(r, "text/html") != 0);
	TST_ASSERT("Accept: application/json (safari 5)", oidc_http_hdr_in_accept_contains(r, "application/json") == 0);

	// ie 8
	apr_table_set(r->headers_in, "Accept",
		      "image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, "
		      "application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*");
	TST_ASSERT("Accept: text/html (ie 8)", oidc_http_hdr_in_accept_contains(r, "text/html") == 0);
	TST_ASSERT("Accept: */* (ie 8)", oidc_http_hdr_in_accept_contains(r, "*/*") != 0);
	TST_ASSERT("Accept: application/json (ie 8)", oidc_http_hdr_in_accept_contains(r, "application/json") == 0);

	// edge
	apr_table_set(r->headers_in, "Accept", "text/html, application/xhtml+xml, image/jxr, */*");
	TST_ASSERT("Accept: text/html (edge)", oidc_http_hdr_in_accept_contains(r, "text/html") != 0);
	TST_ASSERT("Accept: application/json (edge)", oidc_http_hdr_in_accept_contains(r, "application/json") == 0);

	// opera
	apr_table_set(r->headers_in, "Accept",
		      "text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, "
		      "image/gif, image/x-xbitmap, */*;q=0.1");
	TST_ASSERT("Accept: text/html (opera)", oidc_http_hdr_in_accept_contains(r, "text/html") != 0);
	TST_ASSERT("Accept: application/json (opera)", oidc_http_hdr_in_accept_contains(r, "application/json") == 0);

	// xmlhttprequest
	apr_table_set(r->headers_in, "Accept", "application/json");
	TST_ASSERT("Accept: text/html (opera)", oidc_http_hdr_in_accept_contains(r, "text/html") == 0);
	TST_ASSERT("Accept: application/json (opera)", oidc_http_hdr_in_accept_contains(r, "application/json") != 0);

	return 0;
}

#if HAVE_APACHE_24

static char *test_authz_worker(request_rec *r) {
	authz_status rc;
	char *require_args = NULL;
	ap_expr_info_t *parsed_require_args = (ap_expr_info_t *)apr_pcalloc(r->pool, sizeof(ap_expr_info_t));
	;
	json_error_t err;
	json_t *json = NULL;
	char *claims = NULL;

	r->user = "dummy";

	// clang-format off

	claims =
"{"
	"\"sub\": \"stef\","
	"\"areal\": 1.1,"
	"\"anull\": null,"
	"\"anint\": 99,"
	"\"anegativeint\": -99,"
	"\"aminusoneint\": -1,"
	"\"nested\": {"
		"\"level1\": {"
			"\"level2\": \"hans\""
		"},"
		"\"nestedarray\": ["
			"\"b\","
			"\"c\","
			"true,"
			"\"false\","
			"["
				"\"d\","
				"\"e\""
			"]"
		"],"
		"\"somebool\": false"
	"},"
	"\"somearray\": ["
		"\"one\","
		"\"two\","
		"\"three\""
	"],"
	"\"somebool\": false,"
	"\"realm_access\": {"
		"\"roles\": ["
			"\"someRole1\","
			"\"someRole2\""
		"]"
	"},"
	"\"resource_access\": {"
		"\"someClient\": {"
			"\"roles\": ["
				"\"someRole3\","
				"\"someRole4\""
			"]"
		"}"
	"},"
	"\"https://test.com/pay\": \"alot\","
	"\"https://company.com/productAccess\": ["
		"\"snake2\","
		"\"snake2ref\","
		"\"fxt\""
	"]"
"}"
;

	// clang-format on

	json = json_loads(claims, 0, &err);
	TST_ASSERT(apr_psprintf(r->pool, "JSON parsed [%s]", json ? "ok" : err.text), json != NULL);

	require_args = "Require claim sub:hans";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (1: simple sub claim)", rc == AUTHZ_DENIED);

	require_args = "Require claim sub:stef";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (2: simple sub claim)", rc == AUTHZ_GRANTED);

	require_args = "Require claim nested.level1.level2:hans";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (3: nested claim)", rc == AUTHZ_GRANTED);

	require_args = "Require claim nested.nestedarray:a";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (4: nested array)", rc == AUTHZ_DENIED);

	require_args = "Require claim nested.nestedarray:c";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (5: nested array)", rc == AUTHZ_GRANTED);

	require_args = "Require claim nested.level1:a";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (6: nested non-string)", rc == AUTHZ_DENIED);

	require_args = "Require claim somebool:a";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (7: non-array)", rc == AUTHZ_DENIED);

	require_args = "Require claim somebool.level1:a";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (8: nested non-array)", rc == AUTHZ_DENIED);

	require_args = "Require claim realm_access.roles:someRole1";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (9: keycloak sample 1)", rc == AUTHZ_GRANTED);

	require_args = "Require claim resource_access.someClient.roles:someRole4";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (10: keycloak sample 2)", rc == AUTHZ_GRANTED);

	require_args = "Require claim https://test.com/pay:alot";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (11: namespaced key)", rc == AUTHZ_GRANTED);

	require_args = "Require claim nested.level1.level2~.an.";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (12: nested pcre expression)", rc == AUTHZ_GRANTED);

	require_args = "Require claim nested.level1.level2~zan.";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (13: nested pcre expression)", rc == AUTHZ_DENIED);

	require_args = "Require claim nested.nestedarray~.";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (14: nested array pcre expression)", rc == AUTHZ_GRANTED);

	require_args = "Require claim nested.nestedarray~.b";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (15: nested array pcre expression)", rc == AUTHZ_DENIED);

	require_args = "Require claim email~...$";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (16: pcre expression)", rc == AUTHZ_DENIED);

	require_args = "Require claim sub~...$";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (17: pcre expression)", rc == AUTHZ_GRANTED);

	require_args = "Require claim https://company.com/productAccess:snake2";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (18: key in namespaced array)", rc == AUTHZ_GRANTED);

	require_args = "Require claim areal:1.1";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (19: simple real claim)", rc == AUTHZ_GRANTED);

	require_args = "Require claim anull:null";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (20: simple null claim)", rc == AUTHZ_GRANTED);

	require_args = "Require claim areal:null";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (21: simple not null claim)", rc == AUTHZ_DENIED);

	require_args = "Require claim anint:99";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (22: simple int claim)", rc == AUTHZ_GRANTED);

	require_args = "Require claim anint:100";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (23: simple int claim)", rc == AUTHZ_DENIED);

	require_args = "Require claim anegativeint:-99";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (24: simple negative int claim)", rc == AUTHZ_GRANTED);

	require_args = "Require claim anegativeint:$99";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (25: simple int parse error claim)", rc == AUTHZ_DENIED);

	require_args = "Require claim aminusoneint:-1";
	parsed_require_args->filename = require_args;
	rc = oidc_authz_24_worker(r, json, require_args, parsed_require_args, oidc_authz_match_claim);
	TST_ASSERT("auth status (26: simple -1 int claim)", rc == AUTHZ_GRANTED);

	json_decref(json);

	return 0;
}

#endif

static char *test_decode_json_object(request_rec *r) {
	apr_byte_t rc = FALSE;
	json_t *json = NULL;
	rc = oidc_util_json_decode_object(r, "nojson", &json);
	TST_ASSERT("test invalid JSON", rc == FALSE);
	rc = oidc_util_json_decode_object(r, "{ \"n\": \"\\u0000<?php echo 'Hello' ?>\"}", &json);
	TST_ASSERT("test JSON with NULL value", rc == FALSE);
	rc = oidc_util_json_decode_object(
	    r,
	    "tmjcbnuvyrtygbtbyizkfuabiddgixcvnvupjuwnvxznpspmjaqrlpgmggixxovrpwntkvsvxjtkjjggnevyfyemdrlxtnmzjstmjuyquy"
	    "yjzzwsfrazgzbdojkcfaeiqawltqsiwwzzgpiikpqoxixhsqtnfbchrcgxbgiaynkscvbvfnpuddrpjbgdtxxlebrswrtukzxqyyfrmwrr"
	    "tfhcxhjfdoswjzvcchlufkqdaiqakvhyssegikcdkxvqxjrxukllhjduhokudtmhkqhqjheedxnlpbtybpwwogynneilkyffixdchdcjop"
	    "xtdnhgsinwwktpqxfhmlfwucbtlbojaatocwqxsivdwwxrscsviwtllrqakzyogvseiackzzkkioactssxcglqqgavcpxmfokufechkdjk"
	    "wbvdcnyboqbinbitixuqxeafdhrzndljsnqdlvxwvzggltmelmdcfouthhhzjuehfoejfyjvrpakmgmhaigkidmpmjtwrgezmwyvkgirhk"
	    "xwrakbaizldjrcjbwieewdnxmrlgcmnuvhidvkqdokguvphmzywgqgfuwshouxcadbtkoxesyoqikuotloiowjpvztunkguyyrnbmsnwbp"
	    "ghharmvkoqjjoanbejbwdlewiebwkzsuxpxozqzteuozboxdaukiwbqduhdhdlgiewmgeeqwtgyvhexcsdthriprrxvpuqvlcgqlldpnjd"
	    "tbcuxncoikjxxistytsdlzdmtevmxhoafdcwqqixzxnxnrcoqlkwosdxsktgdejqsopuzaqourcixwktuwjzqagtdjheqgkpeavaoxpech"
	    "kkdxcrwdtuxvdwpyjgjtsgppnoudyjyslwzxcqtbeqdtppeoelefkumpaamkxjnmdbuzotdzjrwzjspgabxczvxiuogvtmkmvxitdezsrq"
	    "skorsybwndftfoqrylgsnhetyksfjdctmmarhtxpjukhwxhzjorxgnbpskdzgmskiumcsyquuwknrmkvdxhwgztbbbgiogeynlertjprol"
	    "kavghiatjaddwlacrlibdnbbhykaqepwujqkmylnnqcfmxqanfvxgmitmsgwotolcwqrxgaftsryrmvlnabnouwqubtocwhkerhvsyzgir"
	    "kitehbpcvitmjndqwerqopsdhwenihhkybemtmrafhcqbbfrfhemzvklvzxykkczjdokblktoxknolzxgblsjplggysbutvddygjgaqntc"
	    "avbopwanbdvijawdwuepvzcaoesbkdaaqevbaupyokttlgcplpfijaubzphwutmslimkdxtrgwrfhhvdygznabvhvfhhpuuzwkhaxurnnq"
	    "rmrhmddkckxzrmzxavvfpyuagjfyjorlfwprlpmwyjbtyzidvabtjckfqesnumqddnrdkunxljarqxcokikkqvrwxfedfumbadugcvzigb"
	    "dulrcmzihpepztbplwrcvunyrhlwdutawmroajvomwtnbntcdgeqnyjxqlgjcdkaxlezmrldewjvyfjljeskmebuepmbzlhludyzwfnjom"
	    "fnbgdcseqvqdlxrsuyyakdfsssiobahylumrwzsztpwxvfxyqfhtubamboeykqjltmpdjzhrsdjfebwjhlsyrafmvhefyddxhkchaqxptr"
	    "qewevrnqftswhhxezdxyowtstejeexrgiujxbxvrvukotxdtlbgdpmorbaglozcmkzyrgnsjauxybuwvozcatacoyrvuxpiqkppoiogpui"
	    "ykdpxkefxvqwutsbdeerbhztiidxqxsahcbbbrhlqwwnstpsefwtunismgvhbcpholzedkivglyjoperxpfavaxqohcxrcmnfvlzqtflrs"
	    "lurdbxnyoswimovpteleifarnhrivasnxetxnwyumoiwomilmnmpnpfekpwiwpmlqumkfagjbxpswraxctsyvsfspoesfhfdifcexfknbb"
	    "szjfznpwkftkescltnmmodctjmkwdlrgorauknioeqexwwqdkdhdielfewwenuhsosehfksfaybktumfaprcjgvgenfdffbgduawryrvlb"
	    "phdjsryjzpspymqhflowqzvesljaasfjvheeqikfocyxuopsgsojcqmyfkwkspnspjewmsxljvezucnpuobfqblakqwbixswbbtuboneix"
	    "djhdbzdckkcarsswtutwhkjijwdtsyjirdcibtavigjnehntnpdpdugwryxybsqoboayifiwxyuiqlbjksjpuhwdglymyisjdhkovwexkr"
	    "oooorosiudclbrldesiolbrbeusyrpuuypioziymwdguquitxuiaxeayabeccbrislwinxxyumylbncyshsywkzdyqoaqtwbulnseyngho"
	    "omiypzefykoexnzhwdcqoctptqabzbuiwxyahaptodtufofabylxtlggldckhuicuqdbueuuoknehkkuypnjwqfhocshmofgbmokiuxvcd"
	    "onwuwqbjxgdukuubswwvxxqugjxnngnbnvtcophhamvbcuxdfkqubfiftrtfyljjulmansvnhnaoczrmxlqokbovddmpydamzicfzkmwcg"
	    "ecljucaezvhrcssupxkleiximldarmtszakjuficulnaefldyogmnavrfscsptejaexghcrqtnluzmxvxrixxgjtyujoruzzzrfgtymtfs"
	    "dyrmhvvggyeeykdaglptsuqmqbknimmxnuftjjolcvhpdumqehmyevqlsotrsldgedxmuablgarjfwoqyuakqxbqewdlsfkamxrteaebqw"
	    "wcsupefoshtwlghkqtqjddikfrwjilzuqfwpcxalauddfotnwlsdwpxynlqjpfcuodeyubenztxsjwxycrdhlluauutfrvgqzacvnfawqi"
	    "bftocxrksltmjvlnyjfeagoxpcepioattazmuuklhjxhpbughkmyjdgrxwqwdafgbnerlhlngeqojhjuvwwmqdradedjuugcqzkfozddct"
	    "ctckaqoruksjsqjpzdbvmocutxpnacbkihboujejmjdhorkpyzubhaxpksjfpzmwauwxkwyjisfsqdjdkvsifgxjygclbdtzultcejefye"
	    "phhhgbazkqqdvhtkkllyopdcsnbqjcpyvienhqqkwyxfvjrgsymuxxsejqerumcldjuitavdgogcsvjgbwllaijavuaeqxvndvzyrlmmzr"
	    "hijywctihqizqmjfosrddqqdyilnfzyvwkkqgnnhlajqgdsnhhzpphfjtkeafxlgaarcfdapicfmukyyzvbgoatibulenkkwtyrnzgbmcy"
	    "tazrieabuerwkxoffzuohdhqqhfbxqmqestunudduaywtrmdmbvidyvterebgvxwbhlbsqmghcktujvhfwmhralmodiywvyzvurzghwcpx"
	    "qtzwmhnderhpognxnynmrfraklflrgppszmuxtwddrkzvqyvvmhlwcnzmspekcwhphabtmzdgvfyrvdzimpxbrkjbntiixkgxhepzqrugn"
	    "mjyfbkcacbdgxbhraauoagihygwkiikuyximjjdnvslnfaouofwgdacnndhramvxazuzksploibonvneeixkykpwjmrlwkvbesxaklqkoa"
	    "ulskwdfstelqxyyrpvnzkjcmhvxbjvbmrgdoyiwlzubaovirtciwcptmrdggpcgtxptkfwjsnhbxprqjiezncmmypjfbgljzrawwdikhoa"
	    "qggoizoixpnykwyotofdrduvgfcwxvzjuacxolorrfpunnkzltgbdkztiwjctjedtupmckbjajwcjnkbmywilylfhckksaowsbvhnktfek"
	    "laekpflbtsqpyxhrcwmjjgnqtmoumvcswredhtexnaojzjagrvwcieizjfvvmzzxmzwwvqthmrqvtviuyiqffjdpqmeknhwylmteliysia"
	    "enkhkiuojxdwscvtacbwfixhrcaxlfeakidxgrmgitrmrzdzhwjyazzikrclajgksENDxxxx",
	    &json);
	TST_ASSERT("test invalid long JSON", rc == FALSE);
	rc = oidc_util_json_decode_object(r, "{}", &json);
	TST_ASSERT("test valid JSON", rc == TRUE);
	json_decref(json);
	return 0;
}

static char *test_remote_user(request_rec *r) {
	apr_byte_t rc = FALSE;
	char *remote_user = NULL;
	char *s = NULL;
	json_t *json = NULL;

	s = "{\"upn\":\"nneul@umsystem.edu\"}";
	rc = oidc_util_json_decode_object(r, s, &json);
	TST_ASSERT("test remote user (1) valid JSON", rc == TRUE);
	rc = oidc_get_remote_user(r, "upn", "^(.*)@umsystem\\.edu", NULL, json, &remote_user);
	TST_ASSERT_STR("remote_user (0) string", remote_user, "nneul");
	rc = oidc_get_remote_user(r, "upn", "^(.*)@umsystem\\.edu", "$1", json, &remote_user);
	TST_ASSERT("test remote user (1) function result", rc == TRUE);
	TST_ASSERT_STR("remote_user (1) string", remote_user, "nneul");
	json_decref(json);

	s = "{\"email\":\"nneul@umsystem.edu\"}";
	rc = oidc_util_json_decode_object(r, s, &json);
	TST_ASSERT("test remote user (2) valid JSON", rc == TRUE);
	rc = oidc_get_remote_user(r, "email", "^(.*)@([^.]+)\\..+$", "$2\\$1", json, &remote_user);
	TST_ASSERT("test remote user (2) function result", rc == TRUE);
	TST_ASSERT_STR("remote_user (2) string", remote_user, "umsystem\\nneul");
	json_decref(json);

	s = "{ \"name\": \"Dominik František Bučík\" }";
	rc = oidc_util_json_decode_object(r, s, &json);
	TST_ASSERT("test remote user (3) valid JSON", rc == TRUE);
	rc = oidc_get_remote_user(r, "name", "^(.*)$", "$1@test.com", json, &remote_user);
	TST_ASSERT("test remote user (3) function result", rc == TRUE);
	TST_ASSERT_STR("remote_user (3) string", remote_user, "Dominik František Bučík@test.com");
	json_decref(json);

	s = "{ \"preferred_username\": \"dbucik\" }";
	rc = oidc_util_json_decode_object(r, s, &json);
	TST_ASSERT("test remote user (4) valid JSON", rc == TRUE);
	rc = oidc_get_remote_user(r, "preferred_username", "^(.*)$", "$1@test.com", json, &remote_user);
	TST_ASSERT("test remote user (4) function result", rc == TRUE);
	TST_ASSERT_STR("remote_user (4) string", remote_user, "dbucik@test.com");
	json_decref(json);

	return 0;
}

static char *test_is_auth_capable_request(request_rec *r) {
	apr_byte_t rc = FALSE;

	apr_table_set(r->headers_in, "Accept", "*/*");
	rc = oidc_is_auth_capable_request(r);
	TST_ASSERT("test oidc_is_auth_capable_request (1)", rc == TRUE);

	apr_table_set(r->headers_in, "X-Requested-With", "XMLHttpRequest");
	rc = oidc_is_auth_capable_request(r);
	TST_ASSERT("test oidc_is_auth_capable_request (2)", rc == FALSE);
	apr_table_unset(r->headers_in, "X-Requested-With");

	apr_table_set(r->headers_in, "Sec-Fetch-Mode", "navigate");
	rc = oidc_is_auth_capable_request(r);
	TST_ASSERT("test oidc_is_auth_capable_request (3)", rc == TRUE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Mode");

	apr_table_set(r->headers_in, "Sec-Fetch-Mode", "cors");
	rc = oidc_is_auth_capable_request(r);
	TST_ASSERT("test oidc_is_auth_capable_request (4)", rc == FALSE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Mode");

	apr_table_set(r->headers_in, "Sec-Fetch-Dest", "iframe");
	rc = oidc_is_auth_capable_request(r);
	TST_ASSERT("test oidc_is_auth_capable_request (5)", rc == FALSE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Dest");

	apr_table_set(r->headers_in, "Sec-Fetch-Dest", "image");
	rc = oidc_is_auth_capable_request(r);
	TST_ASSERT("test oidc_is_auth_capable_request (6)", rc == FALSE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Dest");

	apr_table_set(r->headers_in, "Sec-Fetch-Dest", "document");
	rc = oidc_is_auth_capable_request(r);
	TST_ASSERT("test oidc_is_auth_capable_request (7)", rc == TRUE);
	apr_table_unset(r->headers_in, "Sec-Fetch-Dest");

	apr_table_set(r->headers_in, "Accept", "application/json");
	rc = oidc_is_auth_capable_request(r);
	TST_ASSERT("test oidc_is_auth_capable_request (8)", rc == FALSE);
	apr_table_unset(r->headers_in, "Accept");

	return 0;
}

#define TST_OPEN_REDIRECT(url, result)                                                                                 \
	err_str = NULL;                                                                                                \
	err_desc = NULL;                                                                                               \
	rc = oidc_validate_redirect_url(r, c, url, TRUE, &err_str, &err_desc);                                         \
	msg = apr_psprintf(r->pool, "test validate_redirect_url (%s): %s: %s", url, err_str, err_desc);                \
	TST_ASSERT_BYTE(msg, rc, result);

static char *test_open_redirect(request_rec *r) {
	apr_byte_t rc = FALSE;
	char *err_str = NULL;
	char *err_desc = NULL;
	const char *msg = NULL;
	const char *filename = NULL;
	char line_buf[8096];
	apr_file_t *f;
	size_t line_s;
	char *ptr = line_buf;

	char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	// https://github.com/payloadbox/open-redirect-payload-list
	filename = apr_psprintf(r->pool, "%s/%s", dir, "/open-redirect-payload-list.txt");

	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	TST_OPEN_REDIRECT("https://www.example.com/somewhere", TRUE);
	TST_OPEN_REDIRECT("https://evil.example.com/somewhere", FALSE);

	apr_file_open(&f, filename, APR_READ, APR_OS_DEFAULT, r->pool);
	while (1) {
		if (apr_file_gets(line_buf, sizeof(line_buf), f) != APR_SUCCESS)
			break;
		line_s = _oidc_strlen(ptr);
		line_buf[--line_s] = '\0';
		TST_OPEN_REDIRECT(line_buf, FALSE);
	}
	apr_file_close(f);

	return 0;
}

static char *test_set_app_infos(request_rec *r) {
	apr_byte_t rc = FALSE;
	json_t *claims = NULL;

	rc = oidc_util_json_decode_object(r,
					  "{"
					  "\"simple\":\"hans\","
					  "\"name\": \"GÜnther\","
					  "\"dagger\": \"D†gger\""
					  "}",
					  &claims);
	TST_ASSERT("valid JSON", rc == TRUE);

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS, OIDC_APPINFO_ENCODING_NONE);
	TST_ASSERT_STR("header plain simple", apr_table_get(r->headers_in, "OIDC_CLAIM_simple"), "hans");
	TST_ASSERT_STR("header plain name", apr_table_get(r->headers_in, "OIDC_CLAIM_name"), "G\u00DCnther");
	TST_ASSERT_STR("header plain dagger", apr_table_get(r->headers_in, "OIDC_CLAIM_dagger"), "D\u2020gger");

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS,
				  OIDC_APPINFO_ENCODING_BASE64URL);
	TST_ASSERT_STR("header base64url simple", apr_table_get(r->headers_in, "OIDC_CLAIM_simple"), "aGFucw");
	TST_ASSERT_STR("header base64url name", apr_table_get(r->headers_in, "OIDC_CLAIM_name"), "R8OcbnRoZXI");
	TST_ASSERT_STR("header base64url dagger", apr_table_get(r->headers_in, "OIDC_CLAIM_dagger"), "ROKAoGdnZXI");

	oidc_util_appinfo_set_all(r, claims, "OIDC_CLAIM_", ",", OIDC_APPINFO_PASS_HEADERS,
				  OIDC_APPINFO_ENCODING_LATIN1);
	TST_ASSERT_STR("header latin1 simple", apr_table_get(r->headers_in, "OIDC_CLAIM_simple"), "hans");
	TST_ASSERT_STR("header latin1 name", apr_table_get(r->headers_in, "OIDC_CLAIM_name"), "G\xDCnther");
	TST_ASSERT_STR("header latin1 dagger", apr_table_get(r->headers_in, "OIDC_CLAIM_dagger"), "D?gger");

	json_decref(claims);

	return 0;
}

static char *test_check_cookie_domain(request_rec *r) {
	apr_byte_t rv = FALSE;
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	oidc_session_t *session = NULL;

	oidc_session_load(r, &session);
	oidc_session_set_cookie_domain(r, session, "ab001sb161djbn.xyz.com");
	apr_table_set(r->headers_in, "Host", "ab001SB161djbn.xyz.com");

	rv = oidc_check_cookie_domain(r, c, session);
	TST_ASSERT_BYTE("oidc_check_cookie_domain", rv, TRUE);

	rv = oidc_request_check_cookie_domain(r, c, "https://WWW.example.com/protected/index.html");
	TST_ASSERT_BYTE("oidc_request_check_cookie_domain", rv, TRUE);

	c->cookie_domain = ".XYZ.com";
	rv = oidc_request_check_cookie_domain(r, c, "https://ab001sb161djbn.xyz.com/protected/index.html");
	TST_ASSERT_BYTE("oidc_request_check_cookie_domain", rv, TRUE);

	c->cookie_domain = "ab001SB161djbn.xyz.com";
	rv = oidc_request_check_cookie_domain(r, c, "https://ab001sb161djbn.xyz.com/protected/index.html");
	TST_ASSERT_BYTE("oidc_request_check_cookie_domain", rv, TRUE);

	c->cookie_domain = NULL;
	oidc_session_free(r, session);

	return 0;
}

static char *all_tests(apr_pool_t *pool, request_rec *r) {
	char *message;
	TST_RUN(test_private_key_parse, pool);
	TST_RUN(test_public_key_parse, pool);

	TST_RUN(test_jwt_parse, pool);
	TST_RUN(test_plaintext_jwt_parse, pool);
	TST_RUN(test_jwt_get_string, pool);

	TST_RUN(test_jwk_parse_json, pool);
	TST_RUN(test_jwk_copy, pool);
	TST_RUN(test_plaintext_decrypt_symmetric, pool);

#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)
	TST_RUN(test_jwt_decrypt_gcm, pool);
#endif
#if (OIDC_JOSE_EC_SUPPORT)
	TST_RUN(test_jwt_verify_ec, pool);
#endif

	TST_RUN(test_jwt_verify_rsa, pool);
	TST_RUN(test_jwt_sign_verify, pool);

	TST_RUN(test_proto_validate_access_token, r);
	TST_RUN(test_proto_validate_code, r);

	TST_RUN(test_proto_authorization_request, r);
	TST_RUN(test_proto_validate_nonce, r);
	TST_RUN(test_proto_validate_jwt, r);

	TST_RUN(test_current_url, r);
	TST_RUN(test_accept, r);

	TST_RUN(test_decode_json_object, r);

	TST_RUN(test_remote_user, r);
	TST_RUN(test_is_auth_capable_request, r);
	TST_RUN(test_open_redirect, r);
	TST_RUN(test_set_app_infos, r);

#if HAVE_APACHE_24
	TST_RUN(test_authz_worker, r);
#endif

	TST_RUN(test_logout_request, r);
	TST_RUN(test_check_cookie_domain, r);

	return 0;
}

static request_rec *test_setup(apr_pool_t *pool) {
	const unsigned int kIdx = 0;
	const unsigned int kEls = kIdx + 1;
	request_rec *request = (request_rec *)apr_pcalloc(pool, sizeof(request_rec));

	request->pool = pool;
	request->subprocess_env = apr_table_make(request->pool, 0);

	request->headers_in = apr_table_make(request->pool, 0);
	request->headers_out = apr_table_make(request->pool, 0);
	request->err_headers_out = apr_table_make(request->pool, 0);

	apr_table_set(request->headers_in, "Host", "www.example.com");
	apr_table_set(request->headers_in, "OIDC_foo", "some-value");
	apr_table_set(request->headers_in, "Cookie",
		      "foo=bar; "
		      "mod_auth_openidc_session"
		      "=0123456789abcdef; baz=zot");

	request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
	request->server->process = apr_pcalloc(request->pool, sizeof(struct process_rec));
	request->server->process->pool = request->pool;
	request->server->process->pconf = request->pool;
	request->connection = apr_pcalloc(request->pool, sizeof(struct conn_rec));
	request->connection->bucket_alloc = apr_bucket_alloc_create(request->pool);
	request->connection->local_addr = apr_pcalloc(request->pool, sizeof(apr_sockaddr_t));

	apr_pool_userdata_set("https", "scheme", NULL, request->pool);
	request->server->server_hostname = "www.example.com";
	request->connection->local_addr->port = 443;
	request->unparsed_uri = "/bla?foo=bar&param1=value1";
	request->args = "foo=bar&param1=value1";
	apr_uri_parse(request->pool, "https://www.example.com/bla?foo=bar&param1=value1", &request->parsed_uri);

	auth_openidc_module.module_index = kIdx;
	oidc_cfg_t *cfg = oidc_cfg_server_create(request->pool, request->server);

	oidc_cfg_provider_issuer_set(pool, oidc_cfg_provider_get(cfg), "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(pool, oidc_cfg_provider_get(cfg),
							 "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(pool, oidc_cfg_provider_get(cfg), "client_id");

	cfg->redirect_uri = "https://www.example.com/protected/";

	oidc_dir_cfg_t *d_cfg = oidc_cfg_dir_config_create(request->pool, NULL);

	// coverity[suspicious_sizeof]
	request->server->module_config = apr_pcalloc(request->pool, sizeof(void *) * kEls);
	// coverity[suspicious_sizeof]
	request->per_dir_config = apr_pcalloc(request->pool, sizeof(void *) * kEls);
	ap_set_module_config(request->server->module_config, &auth_openidc_module, cfg);
	ap_set_module_config(request->per_dir_config, &auth_openidc_module, d_cfg);

	cfg->crypto_passphrase.secret1 = "12345678901234567890123456789012";
	cfg->cache.impl = &oidc_cache_shm;
	cfg->cache.cfg = NULL;
	cfg->cache.shm_size_max = 500;
	cfg->cache.shm_entry_size_max = 16384 + 255 + 17;
	cfg->cache.encrypt = 1;
	if (cfg->cache.impl->post_config(request->server) != OK) {
		printf("cfg->cache.impl->post_config failed!\n");
		exit(-1);
	}

	return request;
}

int main(int argc, char **argv, char **env) {
	if (apr_app_initialize(&argc, (const char *const **)argv, (const char *const **)env) != APR_SUCCESS) {
		printf("apr_app_initialize failed\n");
		return -1;
	}

	oidc_pre_config_init();

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, NULL);
	request_rec *r = test_setup(pool);

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
