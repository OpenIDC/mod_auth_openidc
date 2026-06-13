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

#include "check_util.h"
#include "jose.h"
#include "util.h"

#include "util/util.h"
#include <cjose/cjose.h> /* this JOSE-layer test exercises the cjose API directly (no longer pulled in via jose.h) */

/* shared helper: parse a JWK from a JSON string into the supplied outparam */
static void _jose_test_jwk_parse(apr_pool_t *pool, const char *s, oidc_jwk_t **jwk, oidc_jose_error_t *err) {
	json_error_t json_err;
	json_t *json = json_loads(s, 0, &json_err);
	ck_assert_msg(json != NULL, "JSON parse failed: %s", json_err.text);
	*jwk = oidc_jwk_parse(pool, json, err);
	oidc_jose_error_t err_val = *err;
	ck_assert_msg(*jwk != NULL, "oidc_jwk_parse failed: %s", oidc_jose_e2s(pool, err_val));
	json_decref(json);
}

// supported

START_TEST(test_jose_jws_supported_algorithms) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jws_supported_algorithms(oidc_test_pool_get());
	ck_assert_msg(arr != NULL, "list of supported signing algorithms is empty");
}
END_TEST

START_TEST(test_jose_jws_algorithm_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jws_algorithm_is_supported(oidc_test_pool_get(), "RS256");
	ck_assert_msg(rv == TRUE, "algorithm RS256 is not supported");
	rv = oidc_jose_jws_algorithm_is_supported(oidc_test_pool_get(), "NO256");
	ck_assert_msg(rv == FALSE, "algorithm NO256 should not be supported");
#ifdef OIDC_JOSE_EC_SUPPORT
	rv = oidc_jose_jws_algorithm_is_supported(oidc_test_pool_get(), "ES256");
	ck_assert_msg(rv == TRUE, "algorithm ES256 is not supported");
#endif
}
END_TEST

START_TEST(test_jose_jwe_supported_algorithms) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jwe_supported_algorithms(oidc_test_pool_get());
	ck_assert_msg(arr != NULL, "list of supported encryption algorithms is empty");
}
END_TEST

START_TEST(test_jose_jwe_algorithm_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jwe_algorithm_is_supported(oidc_test_pool_get(), "A128KW");
	ck_assert_msg(rv == TRUE, "algorithm A128KW is not supported");
}
END_TEST

START_TEST(test_jose_jwe_supported_encryptions) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jwe_supported_encryptions(oidc_test_pool_get());
	ck_assert_msg(arr != NULL, "list of supported encryption ciphers is empty");
}
END_TEST

START_TEST(test_jose_jwe_encryption_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jwe_encryption_is_supported(oidc_test_pool_get(), "A128CBC-HS256");
	ck_assert_msg(rv == TRUE, "cipher A128CBC-HS256 is not supported");
#if (OIDC_JOSE_GCM_SUPPORT)
	rv = oidc_jose_jwe_encryption_is_supported(oidc_test_pool_get(), "A256GCM");
	ck_assert_msg(rv == TRUE, "cipher A256GCM is not supported");
#endif
}
END_TEST

START_TEST(test_jose_hash_and_base64_and_length) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	char *hash = NULL;
	unsigned int hash_len = 0;

	ck_assert_msg(oidc_jose_hash_string(pool, CJOSE_HDR_ALG_RS256, "hello", &hash, &hash_len, &err) == TRUE,
		      "oidc_jose_hash_string failed");
	ck_assert_msg(hash != NULL, "hash is NULL");
	ck_assert_msg((int)hash_len == oidc_jose_hash_length(CJOSE_HDR_ALG_RS256), "hash length mismatch");

	char *b64 = NULL;
	ck_assert_msg(oidc_jose_hash_and_base64url_encode(pool, OIDC_JOSE_ALG_SHA256, "hello", 5, &b64, &err) == TRUE,
		      "oidc_jose_hash_and_base64url_encode failed");
	ck_assert_msg(b64 != NULL, "base64url output is NULL");
	ck_assert_str_eq(b64, "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ");
}
END_TEST

START_TEST(test_jose_get_string_and_timestamps) {
	apr_pool_t *pool = oidc_test_pool_get();
	json_t *j = json_object();
	json_object_set_new(j, "k1", json_string("v1"));
	json_object_set_new(j, "num", json_integer(123));
	json_object_set_new(j, "t1", json_real(4.5));
	char *s = NULL;
	oidc_jose_error_t err;

	ck_assert_msg(oidc_jose_get_string(pool, j, "k1", TRUE, &s, &err) == TRUE,
		      "get string failed for existing key");
	ck_assert_msg(_oidc_strcmp(s, "v1") == 0, "unexpected value");

	char *s2 = NULL;
	ck_assert_msg(oidc_jose_get_string(pool, j, "missing", TRUE, &s2, &err) == FALSE,
		      "get string should have failed for missing mandatory key");

	double ts = 0;
	ck_assert_msg(oidc_jose_get_timestamp(pool, j, "t1", TRUE, &ts, &err) == TRUE,
		      "get timestamp failed for existing key");
	ck_assert_msg(ts == 4.5, "unexpected value");

	double ts2 = 0;
	ck_assert_msg(oidc_jose_get_timestamp(pool, j, "tsmissing", TRUE, &ts2, &err) == FALSE,
		      "get timestamp should have failed for missing mandatory key");

	json_decref(j);
}
END_TEST

START_TEST(test_jose_compress_uncompress) {
	apr_pool_t *pool = oidc_test_pool_get();
	const char *input = "the quick brown fox jumps over the lazy dog";
	int input_len = (int)_oidc_strlen(input);
	char *out = NULL;
	int out_len = 0;
	oidc_jose_error_t err;
	ck_assert_msg(oidc_jose_compress(pool, input, input_len, &out, &out_len, &err) == TRUE, "compress failed");
	ck_assert_msg(out != NULL, "compress returned NULL output");

	char *un = NULL;
	int un_len = 0;
	ck_assert_msg(oidc_jose_uncompress(pool, out, out_len, &un, &un_len, &err) == TRUE, "uncompress failed");
	ck_assert_msg(un != NULL, "uncompress returned NULL output");
	ck_assert_msg(un_len == input_len, "uncompressed length mismatch");
	ck_assert_msg(memcmp(un, input, input_len) == 0, "uncompressed data differs from original");
}
END_TEST

START_TEST(test_jose_jwk_and_json_and_copy_lists) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	const char *src_file = __FILE__;
	char *dir = NULL;
	const char *slash = strrchr(src_file, '/');
	if (slash)
		dir = apr_pstrndup(pool, src_file, (int)(slash - src_file));
	else
		dir = apr_pstrdup(pool, ".");
	char *pub_path = apr_psprintf(pool, "%s/public.pem", dir);

	oidc_jwk_t *pub = NULL;
	if (oidc_jwk_parse_pem_public_key(pool, NULL, pub_path, &pub, &err) != TRUE) {
		char *e = oidc_jose_e2s(pool, err);
		ck_abort_msg("oidc_jwk_parse_pem_public_key failed: %s", e);
	}
	ck_assert_ptr_nonnull(pub);
	ck_assert_ptr_nonnull(pub->kid);

	char *s_json = NULL;
	ck_assert_msg(oidc_jwk_to_json(pool, pub, &s_json, &err) == TRUE, "oidc_jwk_to_json failed");
	ck_assert_ptr_nonnull(s_json);
	oidc_jwk_destroy(pub);
	json_error_t je;
	json_t *j = json_loads(s_json, 0, &je);
	ck_assert_ptr_nonnull(j);
	json_t *kty = json_object_get(j, "kty");
	ck_assert_ptr_nonnull(kty);
	json_decref(j);

	unsigned char key[32];
	for (int i = 0; i < 32; i++)
		key[i] = (unsigned char)i;
	oidc_jwk_t *sym = oidc_jwk_create_symmetric_key(pool, "symkid", key, 32, TRUE, &err);
	ck_assert_ptr_nonnull(sym);
	ck_assert_ptr_nonnull(sym->kid);

	oidc_jwk_t *sym_copy = oidc_jwk_copy(pool, sym);
	ck_assert_ptr_nonnull(sym_copy);
	ck_assert_ptr_nonnull(sym_copy->kid);
	oidc_jwk_destroy(sym_copy);

	apr_array_header_t *arr = apr_array_make(pool, 1, sizeof(const oidc_jwk_t *));
	APR_ARRAY_PUSH(arr, const oidc_jwk_t *) = sym;
	apr_array_header_t *arr_copy = oidc_jwk_list_copy(pool, arr);
	ck_assert_msg(arr_copy != NULL && arr_copy->nelts == 1, "oidc_jwk_list_copy failed");
	oidc_jwk_list_destroy(arr_copy);

	apr_hash_t *h = apr_hash_make(pool);
	apr_hash_set(h, sym->kid, APR_HASH_KEY_STRING, sym);
	oidc_jwk_list_destroy_hash(h);
	ck_assert_int_eq(apr_hash_count(h), 0);

	oidc_jwk_list_destroy(arr);
	ck_assert_int_eq(arr->nelts, 0);
}
END_TEST

START_TEST(test_jose_jwe_decrypt_plaintext) {
	apr_pool_t *pool = oidc_test_pool_get();
	char *plaintext = NULL;
	int plaintext_len = 0;
	oidc_jose_error_t err;
	ck_assert_msg(oidc_jwe_decrypt(pool, "plain-text-data", NULL, &plaintext, &plaintext_len, &err, FALSE) == TRUE,
		      "oidc_jwe_decrypt passthrough failed");
	ck_assert_ptr_nonnull(plaintext);
	ck_assert_msg(plaintext_len == (int)_oidc_strlen("plain-text-data"), "plaintext len mismatch");
	ck_assert_msg(_oidc_strcmp(plaintext, "plain-text-data") == 0, "plaintext content mismatch");
}
END_TEST

START_TEST(test_jwt_sign_verify_and_encrypt_decrypt) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	unsigned char key[32];
	for (int i = 0; i < 32; i++)
		key[i] = (unsigned char)(i + 1);
	oidc_jwk_t *sym = oidc_jwk_create_symmetric_key(pool, "hskid", key, 32, TRUE, &err);
	ck_assert_ptr_nonnull(sym);

	oidc_jwt_t *jwt = oidc_jwt_new(pool, 1, 1);
	json_object_set_new(jwt->payload.value.json, "iss", json_string("unit-test"));
	jwt->header.alg = apr_pstrdup(pool, CJOSE_HDR_ALG_HS256);

	ck_assert_msg(oidc_jwt_sign(pool, jwt, sym, FALSE, &err) == TRUE, "oidc_jwt_sign failed");
	ck_assert_ptr_nonnull(jwt->cjose_jws);

	apr_hash_t *keys = apr_hash_make(pool);
	apr_hash_set(keys, sym->kid, APR_HASH_KEY_STRING, sym);
	ck_assert_msg(oidc_jwt_verify(pool, jwt, keys, &err) == TRUE, "oidc_jwt_verify failed");

	oidc_jwk_destroy(sym);
	oidc_jwt_destroy(jwt);

	oidc_jwt_t *none_jwt = oidc_jwt_new(pool, 1, 1);
	json_object_set_new(none_jwt->payload.value.json, "hello", json_string("world"));
	none_jwt->header.alg = apr_pstrdup(pool, CJOSE_HDR_ALG_NONE);
	char *s = oidc_jose_jwt_serialize(pool, none_jwt, &err);
	ck_assert_ptr_nonnull(s);
	oidc_jwt_destroy(none_jwt);

	char *dot = strchr(s, '.');
	ck_assert_ptr_nonnull(dot);
	int hdr_len = (int)(dot - s);
	char *hdr_b64 = apr_pstrndup(pool, s, hdr_len);
	unsigned char *decoded = NULL;
	size_t decoded_len = 0;
	cjose_err cjose_err_local;
	if (cjose_base64url_decode(hdr_b64, _oidc_strlen(hdr_b64), &decoded, &decoded_len, &cjose_err_local) == FALSE) {
		ck_abort_msg("cjose_base64url_decode failed: %s", cjose_err_local.message);
	}
	char *hdr_json = apr_pstrmemdup(pool, (const char *)decoded, decoded_len);
	cjose_get_dealloc()(decoded);
	json_error_t jerr;
	json_t *hdr_obj = json_loads(hdr_json, 0, &jerr);
	ck_assert_ptr_nonnull(hdr_obj);
	json_t *alg = json_object_get(hdr_obj, "alg");
	ck_assert_ptr_nonnull(alg);
	ck_assert_msg(json_is_string(alg) && _oidc_strcmp(json_string_value(alg), "none") == 0, "alg is not 'none'");
	json_decref(hdr_obj);

	const char *src_file = __FILE__;
	char *dir = NULL;
	const char *slash = strrchr(src_file, '/');
	if (slash)
		dir = apr_pstrndup(pool, src_file, (int)(slash - src_file));
	else
		dir = apr_pstrdup(pool, ".");
	char *pub_path = apr_psprintf(pool, "%s/public.pem", dir);
	char *priv_path = apr_psprintf(pool, "%s/private.pem", dir);

	oidc_jwk_t *pub = NULL;
	if (oidc_jwk_parse_pem_public_key(pool, NULL, pub_path, &pub, &err) != TRUE) {
		char *e = oidc_jose_e2s(pool, err);
		ck_abort_msg("parse public pem failed: %s", e);
	}
	ck_assert_ptr_nonnull(pub);
	oidc_jwk_t *priv = NULL;
	if (oidc_jwk_parse_pem_private_key(pool, NULL, priv_path, &priv, &err) != TRUE) {
		char *e = oidc_jose_e2s(pool, err);
		ck_abort_msg("parse private pem failed: %s", e);
	}
	ck_assert_ptr_nonnull(priv);

	oidc_jwt_t *jwe = oidc_jwt_new(pool, 1, 0);
	jwe->header.alg = apr_pstrdup(pool, CJOSE_HDR_ALG_RSA_OAEP);
	jwe->header.enc = apr_pstrdup(pool, CJOSE_HDR_ENC_A128CBC_HS256);
	jwe->header.kid = apr_pstrdup(pool, pub->kid);

	char *serialized = NULL;
	const char *payload = "this is a secret";
	ck_assert_msg(oidc_jwt_encrypt(pool, jwe, pub, payload, (int)_oidc_strlen(payload), &serialized, &err) == TRUE,
		      "oidc_jwt_encrypt failed");
	ck_assert_ptr_nonnull(serialized);
	oidc_jwk_destroy(pub);
	oidc_jwt_destroy(jwe);

	apr_hash_t *dec_keys = apr_hash_make(pool);
	apr_hash_set(dec_keys, priv->kid, APR_HASH_KEY_STRING, priv);
	char *dec_plain = NULL;
	int dec_plain_len = 0;
	ck_assert_msg(oidc_jwe_decrypt(pool, serialized, dec_keys, &dec_plain, &dec_plain_len, &err, TRUE) == TRUE,
		      "oidc_jwe_decrypt failed");
	ck_assert_msg(dec_plain_len == (int)_oidc_strlen(payload), "decrypted length mismatch");
	ck_assert_msg(memcmp(dec_plain, payload, dec_plain_len) == 0, "decrypted plaintext mismatch");

	oidc_jwk_list_destroy_hash(dec_keys);
}
END_TEST

START_TEST(test_jose_hash_bytes) {
	apr_pool_t *pool = oidc_test_pool_get();
	unsigned char *out = NULL;
	unsigned int out_len = 0;
	oidc_jose_error_t err;

	ck_assert_msg(oidc_jose_hash_bytes(pool, OIDC_JOSE_ALG_SHA256, (const unsigned char *)"abc", 3, &out, &out_len,
					   &err) == TRUE,
		      "oidc_jose_hash_bytes failed");
	ck_assert_msg(out != NULL, "hash output is NULL");
	ck_assert_msg((int)out_len == oidc_jose_hash_length(CJOSE_HDR_ALG_RS256), "hash length mismatch");
}
END_TEST

START_TEST(test_jwk_json_parse_and_jwks) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	const char *src_file = __FILE__;
	char *dir = NULL;
	const char *slash = strrchr(src_file, '/');
	if (slash)
		dir = apr_pstrndup(pool, src_file, (int)(slash - src_file));
	else
		dir = apr_pstrdup(pool, ".");
	char *pub_path = apr_psprintf(pool, "%s/public.pem", dir);

	oidc_jwk_t *pub = NULL;
	if (oidc_jwk_parse_pem_public_key(pool, NULL, pub_path, &pub, &err) != TRUE) {
		char *e = oidc_jose_e2s(pool, err);
		ck_abort_msg("oidc_jwk_parse_pem_public_key failed: %s", e);
	}
	ck_assert_ptr_nonnull(pub);

	char *s_json = NULL;
	ck_assert_msg(oidc_jwk_to_json(pool, pub, &s_json, &err) == TRUE, "oidc_jwk_to_json failed");
	oidc_jwk_destroy(pub);
	json_error_t je;
	json_t *j = json_loads(s_json, 0, &je);
	ck_assert_ptr_nonnull(j);

	oidc_jwk_t *parsed = oidc_jwk_parse(pool, j, &err);
	ck_assert_ptr_nonnull(parsed);
	ck_assert_ptr_nonnull(parsed->kid);
	oidc_jwk_destroy(parsed);

	ck_assert_msg(oidc_is_jwk(j) == TRUE, "oidc_is_jwk false for JWK json");

	json_t *jwks = json_object();
	json_t *arr = json_array();
	json_array_append_new(arr, json_deep_copy(j));
	json_object_set_new(jwks, "keys", arr);
	apr_array_header_t *jwk_list = NULL;
	ck_assert_msg(oidc_jwks_parse_json(pool, jwks, &jwk_list, &err) == TRUE, "oidc_jwks_parse_json failed");
	ck_assert_msg(jwk_list != NULL && jwk_list->nelts == 1, "jwks parse returned wrong number of keys");
	ck_assert_msg(oidc_is_jwks(jwks) == TRUE, "oidc_is_jwks false for jwks json");

	json_decref(j);
	json_decref(jwks);
	oidc_jwk_list_destroy(jwk_list);
}
END_TEST

START_TEST(test_jwk_json_x5c_parse) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err = {{'\0'}, 0, {'\0'}, {'\0'}};
	json_error_t json_err = {0, 0, 0, {'\0'}, {'\0'}};

	// https://datatracker.ietf.org/doc/html/rfc7517#appendix-, n and e removed
	const char *s_json =
	    "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1b94c\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/"
	    "FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIE"
	    "lkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNV"
	    "BAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5Ccm"
	    "lhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/"
	    "449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/"
	    "A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"
	    "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+"
	    "oyVVkaZdklLQp2Btgt9qr21m42f4wTw+"
	    "Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+"
	    "9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+"
	    "Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/"
	    "RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+"
	    "N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]}";

	json_t *j = json_loads(s_json, 0, &json_err);
	ck_assert_ptr_nonnull(j);
	ck_assert_int_eq(oidc_is_jwk(j), TRUE);

	jwk = oidc_jwk_parse(pool, j, &err);
	ck_assert_msg(jwk != NULL, "oidc_jwk_parse failed: %s", oidc_jose_e2s(pool, err));
	ck_assert_ptr_nonnull(jwk->kid);
	ck_assert_int_eq(jwk->x5c->nelts, 1);

	json_decref(j);
	oidc_jwk_destroy(jwk);
}
END_TEST

START_TEST(test_jwk_public_key_parse) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err = {{'\0'}, 0, {'\0'}, {'\0'}};
	oidc_jwk_t *jwk = NULL, *jwkCert = NULL;
	BIO *input = NULL, *inputCert = NULL;
	char *json = NULL;
	apr_byte_t isPrivateKey = FALSE;

	const char publicKeyFile[512];
	const char certificateFile[512];
	const char ecCertificateFile[512];
	char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	snprintf((char *)publicKeyFile, 512, "%s/%s", dir, "/public.pem");
	snprintf((char *)certificateFile, 512, "%s/%s", dir, "/certificate.pem");
	snprintf((char *)ecCertificateFile, 512, "%s/%s", dir, "/eccert.pem");

	input = BIO_new(BIO_s_file());
	ck_assert_ptr_nonnull(input);
	ck_assert_int_eq(BIO_read_filename(input, publicKeyFile), 1);
	ck_assert_int_eq(oidc_jwk_pem_bio_to_jwk(pool, input, NULL, &jwk, isPrivateKey, &err), TRUE);
	BIO_free(input);

	inputCert = BIO_new(BIO_s_file());
	ck_assert_ptr_nonnull(inputCert);
	ck_assert_int_eq(BIO_read_filename(inputCert, certificateFile), 1);
	apr_byte_t rv = oidc_jwk_pem_bio_to_jwk(pool, inputCert, NULL, &jwkCert, isPrivateKey, &err);
	ck_assert_msg(rv == TRUE, "oidc_jwk_pem_bio_to_jwk failed: %s\n", oidc_jose_e2s(pool, err));
	BIO_free(inputCert);

	ck_assert_int_eq(oidc_jwk_to_json(pool, jwk, &json, &err), TRUE);
	ck_assert_str_eq(
	    json,
	    "{\"kty\":\"RSA\",\"kid\":\"IbLjLR7-C1q0-ypkueZxGIJwBQNaLg46DZMpnPW1kps\",\"e\":\"AQAB\",\"n\":"
	    "\"iGeTXbfV5bMppx7o7qMLCuVIKqbBa_qOzBiNNpe0K8rjg7-1z9GCuSlqbZtM0_5BQ6bGonnSPD--"
	    "PowhFdivS4WNA33O0Kl1tQ0wdH3TOnwueIO9ahfW4q0BGFvMObneK-tjwiNMj1l-cZt8pvuS-3LtTWIzC-"
	    "hTZM4caUmy5olm5PVdmru6C6V5rxkbYBPITFSzl5mpuo_C6RV_MYRwAh60ghs2OEvIWDrJkZnYaF7sjHC9j-"
	    "4kfcM5oY7Zhg8KuHyloudYNzlqjVAPd0MbkLkh1pa8fmHsnN6cgfXYtFK7Z8WjYDUAhTH1JjZCVSFN55A-51dgD4cQNzieLEEkJw\"}");
	oidc_jwk_destroy(jwk);

	ck_assert_int_eq(oidc_jwk_to_json(pool, jwkCert, &json, &err), TRUE);
	ck_assert_str_eq(
	    json, "{\"kty\":\"RSA\",\"kid\":\"IbLjLR7-C1q0-ypkueZxGIJwBQNaLg46DZMpnPW1kps\",\"e\":\"AQAB\",\"n\":"
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
	ck_assert_ptr_nonnull(inputCert);
	ck_assert_int_eq(BIO_read_filename(inputCert, ecCertificateFile), 1);
	ck_assert_int_eq(oidc_jwk_pem_bio_to_jwk(pool, inputCert, NULL, &jwkCert, isPrivateKey, &err), TRUE);
	BIO_free(inputCert);

	ck_assert_int_eq(oidc_jwk_to_json(pool, jwkCert, &json, &err), TRUE);
	ck_assert_str_eq(
	    json,
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
}
END_TEST

START_TEST(test_jwk_private_key_parse) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err = {{'\0'}, 0, {'\0'}, {'\0'}};
	oidc_jwk_t *jwk = NULL;
	BIO *input = NULL;
	char *json = NULL;
	apr_byte_t isPrivateKey = TRUE;

	const char rsaPrivateKeyFile[512];
	const char ecPrivateKeyFile[512];

	char *dir = getenv("srcdir") ? getenv("srcdir") : ".";
	snprintf((char *)rsaPrivateKeyFile, 512, "%s/%s", dir, "/private.pem");
	snprintf((char *)ecPrivateKeyFile, 512, "%s/%s", dir, "/ecpriv.key");

	input = BIO_new(BIO_s_file());
	ck_assert_ptr_nonnull(input);
	ck_assert_int_eq(BIO_read_filename(input, rsaPrivateKeyFile), 1);
	ck_assert_int_eq(oidc_jwk_pem_bio_to_jwk(pool, input, NULL, &jwk, isPrivateKey, &err), TRUE);
	BIO_free(input);

	ck_assert_int_eq(oidc_jwk_to_json(pool, jwk, &json, &err), TRUE);
	ck_assert_str_eq(
	    json,
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
	ck_assert_ptr_nonnull(input);
	ck_assert_int_eq(BIO_read_filename(input, ecPrivateKeyFile), 1);
	ck_assert_int_eq(oidc_jwk_pem_bio_to_jwk(pool, input, NULL, &jwk, isPrivateKey, &err), TRUE);
	BIO_free(input);

	ck_assert_int_eq(oidc_jwk_to_json(pool, jwk, &json, &err), TRUE);
	ck_assert_str_eq(
	    json, "{\"kty\":\"EC\",\"kid\":\"-THDTumMGazABrYTb8xJoYOK2OPiWmho3D-nPC1dSYg\",\"crv\":\"P-521\",\"x\":"
		  "\"AR6Eh9VhdLEA-rm5WR0_T0LjKysJuBkSoXaR8GjphHvoOTrljcACRsVlTES9FMkbxbNEs4JdxPgPJl9G-e9WEJTe\",\"y\":"
		  "\"AammgflZaJuSdycK_ccUXkSXjNQd8NsqJuv9LFpk5Ys1OAiirWm6uktXG8ALNSxSffcurBq8zqZyZ141dV6qSzKQ\",\"d\":"
		  "\"AKFwyWAZ2FiTTEofXXOC6I2GBPQeEyCnsVzo075hCOcebYgLpzSj8xWfkTqxsUq8FF5cxlKS3jym3qgsuV0Eb0wd\"}");
	oidc_jwk_destroy(jwk);
}
END_TEST

START_TEST(test_jwk_list_destroy) {
	apr_pool_t *pool = oidc_test_pool_get();
	apr_array_header_t *arr = apr_array_make(pool, 2, sizeof(const oidc_jwk_t *));
	oidc_jose_error_t err;
	unsigned char key[32] = {0};
	for (int i = 0; i < 2; i++) {
		char kid[8];
		snprintf(kid, sizeof(kid), "k%02d", i);
		oidc_jwk_t *sym = oidc_jwk_create_symmetric_key(pool, kid, key, 32, TRUE, &err);
		APR_ARRAY_PUSH(arr, const oidc_jwk_t *) = sym;
	}
	oidc_jwk_list_destroy(arr);
	ck_assert_int_eq(arr->nelts, 0);
}
END_TEST

START_TEST(test_alg2keysize_and_hdr_get_and_jwt_parse) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	ck_assert_msg(oidc_alg2keysize(CJOSE_HDR_ALG_A128KW) == 16, "A128KW keysize wrong");
	ck_assert_msg(oidc_alg2keysize(CJOSE_HDR_ALG_A256KW) == 32, "A256KW keysize wrong");
	ck_assert_msg(oidc_alg2keysize(CJOSE_HDR_ALG_RS256) == 32, "RS256 keysize wrong");

	unsigned char key[32];
	for (int i = 0; i < 32; i++)
		key[i] = (unsigned char)(i + 2);
	oidc_jwk_t *sym = oidc_jwk_create_symmetric_key(pool, "parsekid", key, 32, TRUE, &err);
	ck_assert_ptr_nonnull(sym);

	oidc_jwt_t *jwt = oidc_jwt_new(pool, 1, 1);
	json_object_set_new(jwt->payload.value.json, "sub", json_string("subject"));
	jwt->header.alg = apr_pstrdup(pool, CJOSE_HDR_ALG_HS256);
	ck_assert_msg(oidc_jwt_sign(pool, jwt, sym, FALSE, &err) == TRUE, "oidc_jwt_sign failed");
	char *s = oidc_jose_jwt_serialize(pool, jwt, &err);
	ck_assert_ptr_nonnull(s);

	oidc_jwt_destroy(jwt);

	apr_hash_t *keys = apr_hash_make(pool);
	apr_hash_set(keys, sym->kid, APR_HASH_KEY_STRING, sym);
	oidc_jwt_t *parsed = NULL;
	ck_assert_jwt_parses(pool, s, parsed, keys, err);
	ck_assert_ptr_nonnull(parsed);

	oidc_jwk_destroy(sym);

	const char *alg = oidc_jwt_hdr_get(parsed, "alg");
	ck_assert_ptr_nonnull(alg);
	ck_assert_msg(_oidc_strcmp(alg, CJOSE_HDR_ALG_HS256) == 0, "parsed alg mismatch");
	oidc_jwt_destroy(parsed);
}
END_TEST

/*
 * Tests migrated from the legacy test/test.c TST_ASSERT-based suite. They
 * exercise JOSE/JWT/JWK parsing and (de)cryption against the spec-supplied
 * RFC vectors used by the original tests.
 */

START_TEST(test_jose_legacy_jwt_parse_hs256) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;

	/* from draft-ietf-oauth-json-web-token-20 §3.1 */
	char *s = apr_pstrdup(pool, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
				    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19y"
				    "b290Ijp0cnVlfQ"
				    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

	ck_assert_jwt_parses(pool, s, jwt, NULL, err);
	ck_assert_str_eq(jwt->header.alg, "HS256");
	ck_assert_ptr_null(jwt->header.enc);
	ck_assert_ptr_null(jwt->header.kid);
	ck_assert_str_eq(jwt->payload.iss, "joe");
	ck_assert_int_eq((long)jwt->payload.exp, 1300819380L);

	apr_hash_t *keys = apr_hash_make(pool);
	oidc_jwk_t *jwk = NULL;
	_jose_test_jwk_parse(pool,
			     "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-"
			     "1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}",
			     &jwk, &err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);
	ck_assert_msg(oidc_jwt_verify(pool, jwt, keys, &err) == TRUE, "oidc_jwt_verify: %s", oidc_jose_e2s(pool, err));
	oidc_jwt_destroy(jwt);
	oidc_jwk_destroy(jwk);

	/* corrupt the header byte then re-parse: both forms must fail */
	s[5] = OIDC_CHAR_DOT;
	jwt = NULL;
	ck_assert_int_eq(oidc_jwt_parse(pool, s, &jwt, NULL, FALSE, &err), FALSE);
	oidc_jwt_destroy(jwt);

	s[0] = '\0';
	jwt = NULL;
	ck_assert_int_eq(oidc_jwt_parse(pool, s, &jwt, NULL, FALSE, &err), FALSE);
	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_jose_legacy_plaintext_jwt_parse) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;

	/* from draft-ietf-oauth-json-web-token-20 §6.1 */
	char *s = apr_pstrdup(
	    pool, "eyJhbGciOiJub25lIn0"
		  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
		  ".");

	ck_assert_jwt_parses(pool, s, jwt, NULL, err);
	ck_assert_str_eq(jwt->header.alg, "none");
	ck_assert_str_eq(jwt->payload.iss, "joe");
	ck_assert_int_eq((long)jwt->payload.exp, 1300819380L);

	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_jose_legacy_jwt_get_string_claims) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;
	const char *s =
	    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
	    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	ck_assert_jwt_parses(pool, s, jwt, NULL, err);

	char *dst = NULL;
	ck_assert_int_eq(oidc_jose_get_string(pool, jwt->header.value.json, "typ", TRUE, &dst, &err), TRUE);
	ck_assert_str_eq(dst, "JWT");

	dst = NULL;
	ck_assert_int_eq(oidc_jose_get_string(pool, jwt->header.value.json, "alg", TRUE, &dst, &err), TRUE);
	ck_assert_str_eq(dst, "HS256");

	dst = NULL;
	/* a non-mandatory missing claim must return TRUE and leave *dst NULL */
	ck_assert_int_eq(oidc_jose_get_string(pool, jwt->header.value.json, "dummy", FALSE, &dst, &err), TRUE);
	ck_assert_ptr_null(dst);

	oidc_jwt_destroy(jwt);
}
END_TEST

START_TEST(test_jose_legacy_jwk_parse_collection) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;

	/* basic EC key */
	_jose_test_jwk_parse(pool,
			     "{\"kty\":\"EC\",\"use\":\"sig\",\"kid\":\"the key\","
			     "\"x\":\"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4\","
			     "\"y\":\"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co\",\"crv\":\"P-256\"}",
			     &jwk, &err);
	oidc_jwk_destroy(jwk);

	/* draft-ietf-jose-json-web-key-41 §A.3 example symmetric key #1 */
	_jose_test_jwk_parse(pool, "{\"kty\":\"oct\",\"alg\":\"A128KW\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}", &jwk, &err);
	oidc_jwk_destroy(jwk);

	/* §A.3 example symmetric key #2 */
	_jose_test_jwk_parse(
	    pool,
	    "{\"kty\":\"oct\","
	    "\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\","
	    "\"kid\":\"HMAC key used in JWS A.1 example\"}",
	    &jwk, &err);
	oidc_jwk_destroy(jwk);

	/* draft-ietf-jose-cookbook-08 §3.1 — EC public key (P-521) */
	_jose_test_jwk_parse(
	    pool,
	    "{\"kty\":\"EC\",\"kid\":\"bilbo.baggins@hobbiton.example\",\"use\":\"sig\",\"crv\":\"P-521\","
	    "\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","
	    "\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\"}",
	    &jwk, &err);
	oidc_jwk_destroy(jwk);

	/* §3.2 — EC private key (P-521) */
	_jose_test_jwk_parse(
	    pool,
	    "{\"kty\":\"EC\",\"kid\":\"bilbo.baggins@hobbiton.example\",\"use\":\"sig\",\"crv\":\"P-521\","
	    "\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","
	    "\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\","
	    "\"d\":\"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\"}",
	    &jwk, &err);
	oidc_jwk_destroy(jwk);

	/* §3.3 — RSA public key */
	_jose_test_jwk_parse(pool,
			     "{\"kty\":\"RSA\",\"kid\":\"bilbo.baggins@hobbiton.example\",\"use\":\"sig\","
			     "\"n\":\"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7n"
			     "qQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ"
			     "6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQb"
			     "S0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc"
			     "5gHdrNP5zw\","
			     "\"e\":\"AQAB\"}",
			     &jwk, &err);
	oidc_jwk_destroy(jwk);

	/* a JWK with an x5c chain is preserved through parsing */
	_jose_test_jwk_parse(
	    pool,
	    "{\"kty\":\"RSA\",\"kid\":\"k1\",\"e\":\"AQAB\","
	    "\"n\":\"iGeTXbfV5bMppx7o7qMLCuVIKqbBa_qOzBiNNpe0K8rjg7-1z9GCuSlqbZtM0_5BQ6bGonnSPD--PowhFdivS4WNA33"
	    "O0Kl1tQ0wdH3TOnwueIO9ahfW4q0BGFvMObneK-tjwiNMj1l-cZt8pvuS-3LtTWIzC-hTZM4caUmy5olm5PVdmru6C6V5rxkbYBP"
	    "ITFSzl5mpuo_C6RV_MYRwAh60ghs2OEvIWDrJkZnYaF7sjHC9j-4kfcM5oY7Zhg8KuHyloudYNzlqjVAPd0MbkLkh1pa8fmHsnN6"
	    "cgfXYtFK7Z8WjYDUAhTH1JjZCVSFN55A-51dgD4cQNzieLEEkJw\","
	    "\"x5c\":[\"MIICnTCCAYUCBgFuk1+FLDANBgkqhkiG9w0BAQsF\"]}",
	    &jwk, &err);
	ck_assert_ptr_nonnull(jwk->x5c);
	ck_assert_str_eq(APR_ARRAY_IDX(jwk->x5c, 0, char *), "MIICnTCCAYUCBgFuk1+FLDANBgkqhkiG9w0BAQsF");
	oidc_jwk_destroy(jwk);
}
END_TEST

START_TEST(test_jose_legacy_jwk_copy_preserves_x5t) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwk_t *jwk1 = NULL;

	_jose_test_jwk_parse(pool,
			     "{\"kty\":\"RSA\",\"kid\":\"k1\",\"use\":\"sig\",\"e\":\"AQAB\","
			     "\"n\":\"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7n"
			     "qQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ"
			     "6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQb"
			     "S0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc"
			     "5gHdrNP5zw\","
			     "\"x5t\":\"myx5t\",\"x5t#S256\":\"myx5t#S256\"}",
			     &jwk1, &err);
	ck_assert_str_eq(jwk1->x5t, "myx5t");
	ck_assert_str_eq(jwk1->x5t_S256, "myx5t#S256");

	oidc_jwk_t *jwk2 = oidc_jwk_copy(pool, jwk1);
	ck_assert_ptr_nonnull(jwk2);
	ck_assert_str_eq(jwk2->x5t, "myx5t");
	ck_assert_str_eq(jwk2->x5t_S256, "myx5t#S256");

	oidc_jwk_destroy(jwk2);
	oidc_jwk_destroy(jwk1);
}
END_TEST

START_TEST(test_jose_legacy_jwe_decrypt_symmetric_aes_kw) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;

	/* draft-ietf-jose-json-web-encryption-40 §A.3 — AES Key Wrap + AES_128_CBC_HMAC_SHA_256 */
	_jose_test_jwk_parse(pool, "{\"kty\":\"oct\", \"k\":\"GawgguFyGrWKav7AX4VKUg\"}", &jwk, &err);
	const char *s = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
			"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
			"AxY8DCtDaGlsbGljb3RoZQ."
			"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
			"U0m_YmjN04DJvceFICbCVQ";

	cjose_err cjose_err;
	cjose_jwe_t *jwe = cjose_jwe_import(s, _oidc_strlen(s), &cjose_err);
	ck_assert_ptr_nonnull(jwe);

	size_t content_len = 0;
	uint8_t *decrypted = cjose_jwe_decrypt(jwe, jwk->cjose_jwk, &content_len, &cjose_err);
	ck_assert_ptr_nonnull(decrypted);
	ck_assert_int_eq(_oidc_strncmp((const char *)decrypted, "Live long and prosper.", content_len), 0);

	cjose_get_dealloc()(decrypted);
	oidc_jwk_destroy(jwk);
	cjose_jwe_release(jwe);
}
END_TEST

#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)
START_TEST(test_jose_legacy_jwt_decrypt_rsa_oaep_gcm) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;

	/* RFC 7516 §A.1 — RSAES-OAEP and AES GCM */
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

	char *k =
	    "{\"kty\":\"RSA\","
	    "\"n\":\"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4D"
	    "FqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72Uw"
	    "xrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYg"
	    "yD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw\","
	    "\"e\":\"AQAB\","
	    "\"d\":\"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT"
	    "9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfC"
	    "s6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVT"
	    "IznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ\","
	    "\"p\":\"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPT"
	    "PjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0\","
	    "\"q\":\"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cR"
	    "UoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc\","
	    "\"dp\":\"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjV"
	    "w_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE\","
	    "\"dq\":\"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8"
	    "g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis\","
	    "\"qi\":\"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOyd"
	    "B61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY\"}";

	oidc_jwk_t *jwk = NULL;
	_jose_test_jwk_parse(pool, k, &jwk, &err);

	cjose_err cjose_err;
	cjose_jwe_t *jwe = cjose_jwe_import(s, _oidc_strlen(s), &cjose_err);
	ck_assert_ptr_nonnull(jwe);

	size_t content_len = 0;
	uint8_t *decrypted = cjose_jwe_decrypt(jwe, jwk->cjose_jwk, &content_len, &cjose_err);
	ck_assert_ptr_nonnull(decrypted);
	ck_assert_int_eq(_oidc_strncmp((const char *)decrypted,
				       "The true sign of intelligence is not knowledge but imagination.", content_len),
			 0);

	cjose_get_dealloc()(decrypted);
	cjose_jwe_release(jwe);
	oidc_jwk_destroy(jwk);
}
END_TEST
#endif

#if (OIDC_JOSE_EC_SUPPORT)
START_TEST(test_jose_legacy_jwt_verify_ec) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;

	/* canonical good JWT */
	char *s_jwt =
	    apr_pstrdup(pool, "eyJhbGciOiJFUzI1NiIsImtpZCI6ImY2cXRqIn0."
			      "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoib0RXaXZXUEpCNDd6a2pPbTJjeWdEdiIs"
			      "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2Nzk5NzIwNywiZXhwIjoxNDY3OTk3NTA3"
			      "LCJub25jZSI6IldMeG12NVN0WXlVazlKbFdJOFNhWFRMUGtHWjBWczhhU1Rkal9WUTZyYW8ifQ."
			      "2kqX56QNow37gOlnfLn0SIzwie4mLLIUx_p9OSQa0hiUXKQWQLmMYBjIp5qGh2-R-KPHwNEBxqXwuPgXG4Y7Eg");
	ck_assert_jwt_parses(pool, s_jwt, jwt, NULL, err);

	oidc_jwk_t *jwk = NULL;
	_jose_test_jwk_parse(pool,
			     "{\"kty\":\"EC\",\"kid\":\"f6qtj\",\"use\":\"sig\","
			     "\"x\":\"iARwFlN3B3xa8Zn_O-CVfqry68tXIhO9DckKo1yrNg0\","
			     "\"y\":\"583S_mPS7YVZtLCjx2O69G_JzQPnMxjieOli-9cc_6Q\",\"crv\":\"P-256\"}",
			     &jwk, &err);
	apr_hash_t *keys = apr_hash_make(pool);
	apr_hash_set(keys, "f6qtj", APR_HASH_KEY_STRING, jwk);
	ck_assert_int_eq(oidc_jwt_verify(pool, jwt, keys, &err), TRUE);
	oidc_jwt_destroy(jwt);

	/* tampered signature byte (capitalised final g) must not verify */
	s_jwt =
	    apr_pstrdup(pool, "eyJhbGciOiJFUzI1NiIsImtpZCI6ImY2cXRqIn0."
			      "eyJzdWIiOiJqb2UiLCJhdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoib0RXaXZXUEpCNDd6a2pPbTJjeWdEdiIs"
			      "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2Nzk5NzIwNywiZXhwIjoxNDY3OTk3NTA3"
			      "LCJub25jZSI6IldMeG12NVN0WXlVazlKbFdJOFNhWFRMUGtHWjBWczhhU1Rkal9WUTZyYW8ifQ."
			      "2kqX56QNow37gOlnfLn0SIzwie4mLLIUx_p9OSQa0hiUXKQWQLmMYBjIp5qGh2-R-KPHwNEBxqXwuPgXG4Y7EG");
	jwt = NULL;
	ck_assert_jwt_parses(pool, s_jwt, jwt, NULL, err);
	ck_assert_int_eq(oidc_jwt_verify(pool, jwt, keys, &err), FALSE);
	oidc_jwt_destroy(jwt);

	/* tampered payload byte must not verify */
	s_jwt =
	    apr_pstrdup(pool, "eyJhbGciOiJFUzI1NiIsImtpZCI6ImY2cXRqIn0."
			      "eyJzdWIiOiJqb2UiLCJHdWQiOiJhY19vaWNfY2xpZW50IiwianRpIjoib0RXaXZXUEpCNDd6a2pPbTJjeWdEdiIs"
			      "ImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQ2Nzk5NzIwNywiZXhwIjoxNDY3OTk3NTA3"
			      "LCJub25jZSI6IldMeG12NVN0WXlVazlKbFdJOFNhWFRMUGtHWjBWczhhU1Rkal9WUTZyYW8ifQ."
			      "2kqX56QNow37gOlnfLn0SIzwie4mLLIUx_p9OSQa0hiUXKQWQLmMYBjIp5qGh2-R-KPHwNEBxqXwuPgXG4Y7Eg");
	jwt = NULL;
	ck_assert_jwt_parses(pool, s_jwt, jwt, NULL, err);
	ck_assert_int_eq(oidc_jwt_verify(pool, jwt, keys, &err), FALSE);
	oidc_jwt_destroy(jwt);

	oidc_jwk_destroy(jwk);
}
END_TEST
#endif

START_TEST(test_jose_legacy_jwt_verify_rsa) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwt_t *jwt = NULL;

	/* canonical good JWT signed RS256 */
	const char *s_good =
	    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9."
	    "eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYX"
	    "NoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6"
	    "InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly"
	    "9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE0MTE1ODA4NzV9.lEG-"
	    "DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk6"
	    "53bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-"
	    "mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_"
	    "kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEA";
	ck_assert_jwt_parses(pool, s_good, jwt, NULL, err);

	const char *s_key =
	    "{\"kty\":\"RSA\",\"e\":\"AQAB\","
	    "\"n\":\"3lDyn_ZvG32Pw5kYbRuVxHsPfe9Xt8s9vOXnt8z7_T-hZZvealNhCxz9VEwTJ7TsZ9CLi5c30FjoEJYFkKdd"
	    "LAdxKo0oOXWc_AWrQvPwht9a-o6dX2fL_9CmXW1hGHXMH0qiLMrFqMSzZeh-GUY6F1woE_eKsAo6LOhP8X77FlEQT2Eu"
	    "71wu8KC4B3sH_9QTco50KNw14-bRY5j2V2TZelvsXJnvrN4lXtEVYWFkREKeXzMH8DhDyZzh0NcHa7dFBa7rDusyfIHj"
	    "uP6uAju_Ao6hhdOGjlKePMVtfusWBAI7MWDChLTqiCTvlZnCpkpTTh5m-i7TbE1TwmdbLceq1w\"}";
	apr_hash_t *keys = apr_hash_make(pool);
	oidc_jwk_t *jwk = NULL;
	_jose_test_jwk_parse(pool, s_key, &jwk, &err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);
	ck_assert_int_eq(oidc_jwt_verify(pool, jwt, keys, &err), TRUE);
	oidc_jwt_destroy(jwt);

	/* tampered payload (nbf changed from 14... to 15...) must NOT verify */
	const char *s_bad_payload =
	    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9."
	    "eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYX"
	    "NoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6"
	    "InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly"
	    "9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE1MTE1ODA4NzV9.lEG-"
	    "DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk6"
	    "53bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-"
	    "mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_"
	    "kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEA";
	jwt = NULL;
	ck_assert_jwt_parses(pool, s_bad_payload, jwt, NULL, err);
	ck_assert_int_eq(oidc_jwt_verify(pool, jwt, keys, &err), FALSE);
	oidc_jwt_destroy(jwt);

	/* tampered signature byte (final 'A' → 'a') must NOT verify */
	const char *s_bad_sig =
	    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IloxTkNqb2plaUhBaWItR204dkZFNnlhNmxQTSJ9."
	    "eyJub25jZSI6ImF2U2s3UzY5RzRrRUU4S200YlBpT2pyZkNoSHQ2bk80WjM5N0xwX2JRbmMsIiwiaWF0IjoxNDExNTgwODc2LCJhdF9oYX"
	    "NoIjoieVRxc29PTlpidVdiTjZUYmdldnVEUSIsInN1YiI6IjYzNDNhMjljLTUzOTktNDRhNy05YjM1LTQ5OTBmNDM3N2M5NiIsImFtciI6"
	    "InBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDExNTc3MjY3LCJpZHAiOiJpZHNydiIsIm5hbWUiOiJrc29uYXR5IiwiaXNzIjoiaHR0cHM6Ly"
	    "9hZ3N5bmMuY29tIiwiYXVkIjoiYWdzeW5jX2ltcGxpY2l0IiwiZXhwIjoxNDExNTg0NDc1LCJuYmYiOjE0MTE1ODA4NzV9.lEG-"
	    "DgHHa0JuOEuOTBvCqyexjRVcKXBnJJm289o2HyTgclpH80DsOMED9RlXCFfuDY7nw9i2cxUmIMAV42AdTxkMPomK3chytcajvpAZJirlk6"
	    "53bo9GTDXJSKZr5fwyEu--qahsoT5t9qvoWyFdYkvmMHFw1-"
	    "mAHDGgVe23voc9jPuFFIhRRqIn4e8ikzN4VQeEV1UXJD02kYYFn2TRWURgiFyVeTr2r0MTn-auCEsFS_AfR1Bl_"
	    "kmpMfqwrsicf5MTBvfPJeuSMt3t3d3LOGBkg36_z21X-ZRN7wy1KTjagr7iQ_y5csIpmtqs_QM55TTB9dW1HIosJPhiuMEJEa";
	jwt = NULL;
	ck_assert_jwt_parses(pool, s_bad_sig, jwt, NULL, err);
	ck_assert_int_eq(oidc_jwt_verify(pool, jwt, keys, &err), FALSE);
	oidc_jwt_destroy(jwt);

	oidc_jwk_destroy(jwk);
}
END_TEST

START_TEST(test_jose_legacy_jwt_sign_verify_rsa_and_hmac) {
	apr_pool_t *pool = oidc_test_pool_get();
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	char *cser = NULL;

	const char *s_key =
	    "{\"kty\":\"RSA\",\"e\":\"AQAB\","
	    "\"n\":\"ym7jipmB37CgdonwGFVRuZmRfCl3lVh91fmm5CXHcNlUFZNR3D6Q9r63PpGRnfSsX3dOweh8BXd2AJ3mxvcE4z9xH--tA5EaO"
	    "GI7IVF0Ip_i3flGg85xOADlb8rX3ez1NqkqMVJeeJypKhCCDNfvu_MXSdPLglU969YQF5xKAK8VFRfI6EfxxrZ_3Dvt2CKDV4LTPPJe9KI"
	    "2_LuLQFBJ3MzlCTVxY6gyaljrWaDq7q5Lt3GB1KYS0Yd8COEQwsclOLm0Tddhg4cle-DfaTMi7xsTZsPKyac5x17Y4N4isHhZULuWHX7o1"
	    "bs809xcj-_-YCRq6C61je_mzFhuF4pczw\","
	    "\"d\":\"qvxW_e8DoCnUn8uLHUKTsS1hkXqFI4SHZYFl0jeG6m7ncwHolxvR3ljg9tyGHuFX55sizu7MMuHgrkyxbUWgv0ILD2qmvOiHOT"
	    "DfuRjP-58JRW0UfqiVQTSgl3jCNRW9WdoxZU-ptD6_NGSVNLwAJsUB2r4mm4PctaMuHINKjp_TnuD-5vfi9Tj88hbqvX_0j8T62ZaLRdER"
	    "b1KGDM_8bnqQpnLZ0MZQnpLQ8cKIcjj7p0II6pzvqgdO1RqfYx7qG0cbcIRh26rnB9X4rp5BrbvDzKe6NOqacZUcNUmbPzI01-hiT0HgJv"
	    "V592CBOxt2T31ltQ4wCEdzhQeT3n9_wQ\"}";

	apr_hash_t *keys = apr_hash_make(pool);
	_jose_test_jwk_parse(pool, s_key, &jwk, &err);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);

	oidc_jwt_t *jwt = oidc_jwt_new(pool, TRUE, TRUE);
	json_object_set_new(jwt->payload.value.json, "iss", json_string("https://example.org"));
	json_object_set_new(jwt->payload.value.json, "sub", json_string("https://example.org"));
	json_object_set_new(jwt->payload.value.json, "aud", json_string("sample_client"));
	json_object_set_new(jwt->payload.value.json, "exp", json_integer(apr_time_sec(apr_time_now()) + 60));
	json_object_set_new(jwt->payload.value.json, "iat", json_integer(apr_time_sec(apr_time_now())));
	jwt->header.alg = apr_pstrdup(pool, CJOSE_HDR_ALG_RS256);

	ck_assert_int_eq(oidc_jwt_sign(pool, jwt, jwk, FALSE, &err), TRUE);
	cser = oidc_jose_jwt_serialize(pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);

	oidc_jwt_t *rsa_jwt = NULL;
	ck_assert_jwt_parses(pool, cser, rsa_jwt, NULL, err);
	ck_assert_int_eq(oidc_jwt_verify(pool, rsa_jwt, keys, &err), TRUE);
	oidc_jwt_destroy(rsa_jwt);

	oidc_jwk_destroy(jwk);

	/* HMAC roundtrip with the same payload */
	const char *secret = "mysecretwithmorethan32characters";
	jwk =
	    oidc_jwk_create_symmetric_key(pool, NULL, (const unsigned char *)secret, _oidc_strlen(secret), FALSE, &err);
	ck_assert_ptr_nonnull(jwk);
	apr_hash_set(keys, "dummy", APR_HASH_KEY_STRING, jwk);
	jwt->header.alg = apr_pstrdup(pool, "HS256");

	ck_assert_int_eq(oidc_jwt_sign(pool, jwt, jwk, FALSE, &err), TRUE);
	cser = oidc_jose_jwt_serialize(pool, jwt, &err);
	ck_assert_ptr_nonnull(cser);

	oidc_jwt_t *hmac_jwt = NULL;
	ck_assert_jwt_parses(pool, cser, hmac_jwt, NULL, err);
	ck_assert_int_eq(oidc_jwt_verify(pool, hmac_jwt, keys, &err), TRUE);
	oidc_jwt_destroy(hmac_jwt);

	oidc_jwk_destroy(jwk);
	oidc_jwt_destroy(jwt);
}
END_TEST

int main(void) {
	TCase *sup = tcase_create("supported");
	tcase_add_checked_fixture(sup, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(sup, test_jose_jws_supported_algorithms);
	tcase_add_test(sup, test_jose_jws_algorithm_is_supported);
	tcase_add_test(sup, test_jose_jwe_supported_algorithms);
	tcase_add_test(sup, test_jose_jwe_algorithm_is_supported);
	tcase_add_test(sup, test_jose_jwe_supported_encryptions);
	tcase_add_test(sup, test_jose_jwe_encryption_is_supported);

	TCase *core = tcase_create("core");
	tcase_add_checked_fixture(core, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(core, test_jose_hash_and_base64_and_length);
	tcase_add_test(core, test_jose_get_string_and_timestamps);
	tcase_add_test(core, test_jose_compress_uncompress);
	tcase_add_test(core, test_jose_jwk_and_json_and_copy_lists);
	tcase_add_test(core, test_jose_jwe_decrypt_plaintext);
	tcase_add_test(core, test_jwt_sign_verify_and_encrypt_decrypt);
	tcase_add_test(core, test_jose_hash_bytes);
	tcase_add_test(core, test_jwk_json_parse_and_jwks);
	tcase_add_test(core, test_jwk_list_destroy);
	tcase_add_test(core, test_alg2keysize_and_hdr_get_and_jwt_parse);
	tcase_add_test(core, test_jwk_json_x5c_parse);
	tcase_add_test(core, test_jwk_public_key_parse);
	tcase_add_test(core, test_jwk_private_key_parse);

	TCase *legacy = tcase_create("legacy");
	tcase_add_checked_fixture(legacy, oidc_test_setup, oidc_test_teardown);
	tcase_add_test(legacy, test_jose_legacy_jwt_parse_hs256);
	tcase_add_test(legacy, test_jose_legacy_plaintext_jwt_parse);
	tcase_add_test(legacy, test_jose_legacy_jwt_get_string_claims);
	tcase_add_test(legacy, test_jose_legacy_jwk_parse_collection);
	tcase_add_test(legacy, test_jose_legacy_jwk_copy_preserves_x5t);
	tcase_add_test(legacy, test_jose_legacy_jwe_decrypt_symmetric_aes_kw);
#if (OPENSSL_VERSION_NUMBER >= 0x1000100f)
	tcase_add_test(legacy, test_jose_legacy_jwt_decrypt_rsa_oaep_gcm);
#endif
#if (OIDC_JOSE_EC_SUPPORT)
	tcase_add_test(legacy, test_jose_legacy_jwt_verify_ec);
#endif
	tcase_add_test(legacy, test_jose_legacy_jwt_verify_rsa);
	tcase_add_test(legacy, test_jose_legacy_jwt_sign_verify_rsa_and_hmac);

	Suite *s = suite_create("jose");
	suite_add_tcase(s, sup);
	suite_add_tcase(s, core);
	suite_add_tcase(s, legacy);

	return oidc_test_suite_run(s);
}
