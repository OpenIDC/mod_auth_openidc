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
 * Fuzz target for the JWK / JWK Set parsers: a JWKS document is fetched from
 * the provider's jwks_uri, so its contents are under the control of whoever
 * answers at that URL -- the OP, or anyone who can influence the document in
 * a multi-provider (discovery / dynamic registration) setup. The same parser
 * handles the JWKs a client_secret-less client publishes for its own keys.
 *
 * The decoded JSON is routed the way the module routes it: a "keys" array is
 * parsed as a set (oidc_jwks_parse_json), a bare "kty" object as a single key
 * (oidc_jwk_parse_json). That covers the per-kty material parsing in
 * jose/jwk.c -- RSA n/e/d, EC crv/x/y, oct k, the optional x5c certificate
 * chain and x5t thumbprints -- and the re-serialization and default-alg
 * helpers are run over every key that parsed, so the round trip is stressed
 * with whatever the parser accepted rather than only with what it rejects.
 */

#include "fuzz.h"
/* util.h pulls in const.h before any Apache header does, so config.h's
 * PACKAGE_* defines win the race against Apache's own (empty) ones in
 * ap_config_auto.h -- json.h includes httpd.h directly; keep util.h ahead
 * of it (clang-format's include sorting would undo exactly that, hence the
 * guard) */
/* clang-format off */
#include "util.h"      /* test fixture */
#include "json.h"
#include "jose.h"
#include "util/util.h" /* oidc_json_decode_object */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>

static int g_ready = 0;

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		g_ready = 1;
	}
	return 0;
}

/* run the helpers that consume a parsed key: serialization (full and public-only) and the default-alg lookup */
static void fuzz_jwk_use(apr_pool_t *pool, const oidc_jwk_t *jwk) {
	char *s_json = NULL;
	oidc_jose_error_t err;
	oidc_jwk_to_json(pool, jwk, &s_json, &err);
	oidc_jwk_to_public_json(pool, jwk, &s_json, &err);
	oidc_jwk_default_jws_alg(jwk);
	/* a copy duplicates the OpenSSL key material outside the pool; destroy it the same way */
	oidc_jwk_t *copy = oidc_jwk_copy(pool, jwk);
	if (copy != NULL)
		oidc_jwk_destroy(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	request_rec r = *oidc_test_request_get();
	r.pool = pool;

	char *s = apr_pstrmemdup(pool, (const char *)data, size);
	oidc_json_t *json = NULL;
	if ((oidc_json_decode_object(&r, s, &json) == TRUE) && (json != NULL)) {
		oidc_jose_error_t err;
		if (oidc_is_jwks(json) == TRUE) {
			apr_array_header_t *jwk_list = NULL;
			apr_byte_t ok = oidc_jwks_parse_json(pool, json, &jwk_list, &err);
			if ((ok == TRUE) && (jwk_list != NULL))
				for (int i = 0; i < jwk_list->nelts; i++)
					fuzz_jwk_use(pool, APR_ARRAY_IDX(jwk_list, i, const oidc_jwk_t *));
			/* the keys wrap cjose/OpenSSL objects allocated outside the pool */
			if (jwk_list != NULL)
				oidc_jwk_list_destroy(jwk_list);
		} else if (oidc_is_jwk(json) == TRUE) {
			oidc_jwk_t *jwk = NULL;
			if ((oidc_jwk_parse_json(pool, json, &jwk, &err) == TRUE) && (jwk != NULL)) {
				fuzz_jwk_use(pool, jwk);
				oidc_jwk_destroy(jwk);
			}
		}
		oidc_json_decref(json); /* jansson value is refcounted, not pooled */
	}

	apr_pool_destroy(pool);
	return 0;
}
