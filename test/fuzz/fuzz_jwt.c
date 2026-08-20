/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Copyright (C) 2017-2026 ZmartZone Holding BV - hans.zandbelt@openidc.com
 *
 * Fuzz target for oidc_jwt_parse() + oidc_jwt_verify(): parsing of
 * attacker-controlled compact JWT/JWS/JWE serializations, followed by
 * signature verification against a fixed key set. The key set is the one the
 * unit tests carry for their RFC vectors, so the seeds in corpus/jwt that are
 * real tokens verify successfully and the success paths past the signature
 * check -- claim extraction, re-serialization -- stay reachable (the two JWE
 * vectors decrypt, but carry a plain-text rather than a JSON payload, so they
 * stop at the payload decode; they still drive the key-unwrap and AEAD code):
 *
 *   oct   HS256  draft-ietf-oauth-json-web-token-20 §3.1 (no kid)
 *   EC    ES256  kid "f6qtj"
 *   RSA   RS256  the x5t-headed id_token vector (no kid)
 *   RSA   RSA-OAEP private key, RFC 7516 §A.1 (JWE decryption)
 *   oct   A128KW, draft-ietf-jose-json-web-encryption-40 §A.3 (JWE decryption)
 *
 * A token without a kid is tried against every key of a compatible type, so
 * mutations of the seeds keep hitting the verification code rather than only
 * the kid lookup.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_metadata.c */
/* clang-format off */
#include "util.h"      /* test fixture */
#include "json.h"
#include "jose.h"
#include "util/util.h" /* oidc_json_decode_object */
/* clang-format on */

#include <apr_hash.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <stdlib.h>

static int g_ready = 0;
static apr_hash_t *g_keys = NULL;

/*
 * LeakSanitizer anchors for the key objects.
 *
 * The JWKs are pool-allocated and point at cjose/OpenSSL objects on the heap.
 * APR allocates its pool nodes with mmap() on the distributions the sanitizer
 * builds run on, and LSan does not scan anonymous mappings for pointers, so
 * from its point of view those heap objects are referenced by nothing. That is
 * harmless until libFuzzer runs its mid-run leak check -- which it does after
 * any input whose malloc count exceeded its free count, and an RSA verify
 * does exactly that the first time it caches a Montgomery context on the key
 * -- and then every key, and everything lazily attached to it, is reported as
 * a leak and the run stops. Keeping the heap handles in a global (a root LSan
 * does scan) makes the whole key graph reachable again; the keys are released
 * from an atexit handler so the end-of-run check stays clean as well.
 */
#define FUZZ_JWT_MAX_KEYS 8
static void *g_cjose_keys[FUZZ_JWT_MAX_KEYS];

static void fuzz_jwt_keys_destroy(void) {
	if (g_keys != NULL)
		oidc_jwk_list_destroy_hash(g_keys);
	g_keys = NULL;
	for (int i = 0; i < FUZZ_JWT_MAX_KEYS; i++)
		g_cjose_keys[i] = NULL;
}

static const struct {
	const char *name; /* hash key: the kid where the token carries one, descriptive otherwise */
	const char *json;
} fuzz_jwt_keys[] = {
    {"hs256", "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-"
	      "1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}"},
    {"f6qtj", "{\"kty\":\"EC\",\"kid\":\"f6qtj\",\"use\":\"sig\","
	      "\"x\":\"iARwFlN3B3xa8Zn_O-CVfqry68tXIhO9DckKo1yrNg0\","
	      "\"y\":\"583S_mPS7YVZtLCjx2O69G_JzQPnMxjieOli-9cc_6Q\",\"crv\":\"P-256\"}"},
    {"rs256",
     "{\"kty\":\"RSA\",\"e\":\"AQAB\","
     "\"n\":\"3lDyn_ZvG32Pw5kYbRuVxHsPfe9Xt8s9vOXnt8z7_T-hZZvealNhCxz9VEwTJ7TsZ9CLi5c30FjoEJYFkKdd"
     "LAdxKo0oOXWc_AWrQvPwht9a-o6dX2fL_9CmXW1hGHXMH0qiLMrFqMSzZeh-GUY6F1woE_eKsAo6LOhP8X77FlEQT2Eu"
     "71wu8KC4B3sH_9QTco50KNw14-bRY5j2V2TZelvsXJnvrN4lXtEVYWFkREKeXzMH8DhDyZzh0NcHa7dFBa7rDusyfIHj"
     "uP6uAju_Ao6hhdOGjlKePMVtfusWBAI7MWDChLTqiCTvlZnCpkpTTh5m-i7TbE1TwmdbLceq1w\"}"},
    {"rsa-oaep",
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
     "B61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY\"}"},
    {"a128kw", "{\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}"},
    {NULL, NULL},
};

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		/* the keys live for the whole run, in the fixture's pool */
		apr_pool_t *pool = oidc_test_pool_get();
		request_rec *r = oidc_test_request_get();
		g_keys = apr_hash_make(pool);
		for (int i = 0; (fuzz_jwt_keys[i].name != NULL) && (i < FUZZ_JWT_MAX_KEYS); i++) {
			oidc_json_t *json = NULL;
			oidc_jwk_t *jwk = NULL;
			oidc_jose_error_t err;
			if ((oidc_json_decode_object(r, fuzz_jwt_keys[i].json, &json) == TRUE) && (json != NULL)) {
				if ((oidc_jwk_parse_json(pool, json, &jwk, &err) == TRUE) && (jwk != NULL)) {
					apr_hash_set(g_keys, fuzz_jwt_keys[i].name, APR_HASH_KEY_STRING, jwk);
					g_cjose_keys[i] = jwk->cjose_jwk;
				}
				oidc_json_decref(json);
			}
		}
		atexit(fuzz_jwt_keys_destroy);
		g_ready = 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	char *s = apr_pstrmemdup(pool, (const char *)data, size);
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;

	/* parse (and decrypt, when the input is a JWE for one of the keys) ... */
	if ((oidc_jwt_parse(pool, s, &jwt, g_keys, FALSE, &err) == TRUE) && (jwt != NULL)) {
		/* ... then verify the signature against the key set, and run the claim
		 * accessors and the serializer over the parsed token either way */
		oidc_jwt_verify(pool, jwt, g_keys, &err);
		oidc_jwt_hdr_get(jwt, "typ");
		oidc_jwt_hdr_get(jwt, "cty");
		char *value = NULL;
		oidc_jose_get_string(pool, jwt->payload.value.json, "aud", FALSE, &value, &err);
		oidc_jose_get_string(pool, jwt->payload.value.json, "nonce", FALSE, &value, &err);
		double ts = 0;
		oidc_jose_get_timestamp(jwt->payload.value.json, "nbf", FALSE, &ts, &err);
		oidc_jose_jwt_serialize(pool, jwt, &err);
	}
	/* a JWT wraps cjose/OpenSSL objects allocated outside the pool */
	if (jwt != NULL)
		oidc_jwt_destroy(jwt);

	apr_pool_destroy(pool);
	return 0;
}
