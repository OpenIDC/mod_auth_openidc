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

#include "check_util.h"
#include "jose.h"
#include "util.h"

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
	char *slash = strrchr(src_file, '/');
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
		ck_abort_msg("cjose_base64url_decode failed: %s", oidc_cjose_e2s(pool, cjose_err_local));
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
	char *slash = strrchr(src_file, '/');
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
	char *slash = strrchr(src_file, '/');
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

START_TEST(test_jwk_list_destroy) {
	apr_pool_t *pool = oidc_test_pool_get();
	apr_array_header_t *arr = apr_array_make(pool, 2, sizeof(const oidc_jwk_t *));
	oidc_jose_error_t err;
	unsigned char key[16] = {0};
	for (int i = 0; i < 2; i++) {
		char kid[8];
		snprintf(kid, sizeof(kid), "k%02d", i);
		oidc_jwk_t *sym = oidc_jwk_create_symmetric_key(pool, kid, key, 16, TRUE, &err);
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
	ck_assert_msg(oidc_jwt_parse(pool, s, &parsed, keys, FALSE, &err) == TRUE, "oidc_jwt_parse failed");
	ck_assert_ptr_nonnull(parsed);

	oidc_jwk_destroy(sym);

	const char *alg = oidc_jwt_hdr_get(parsed, "alg");
	ck_assert_ptr_nonnull(alg);
	ck_assert_msg(_oidc_strcmp(alg, CJOSE_HDR_ALG_HS256) == 0, "parsed alg mismatch");
	oidc_jwt_destroy(parsed);
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

	Suite *s = suite_create("jose");
	suite_add_tcase(s, sup);
	suite_add_tcase(s, core);

	return oidc_test_suite_run(s);
}
