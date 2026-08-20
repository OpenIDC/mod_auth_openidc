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
 * Fuzz target for the key-file configuration path that OIDCPublicKeyFiles /
 * OIDCPrivateKeyFiles (and the per-provider client key directives) go through:
 * oidc_cfg_parse_key_record() tokenizes the
 * "[<use>:][<alg>[+<alg>...]@][<kid>#]<filename>" record, and the named file is
 * then read as PEM and converted to a JWK. Key files are administrator-supplied,
 * so this is not an attack surface in the way the JWKS parser is; it is here
 * because the PEM/X.509-to-JWK conversion (oidc_jwk_pem_bio_to_jwk, shared with
 * the certificate-chain handling) and the record tokenizer are the two pieces of
 * cfg/parse.c that handle free-form bytes, and a broken parse there fails at
 * startup with a message rather than by corrupting memory.
 *
 * The same input is used two ways: as the record string (both the pair and the
 * triplet record formats, with and without the algorithm-list extension), and
 * as the contents of the key file, handed to the PEM reader through a memory
 * BIO so that no file is written per iteration -- first as a public key /
 * certificate, then as a private key.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_metadata.c */
/* clang-format off */
#include "util.h"        /* test fixture */
#include "cfg/parse.h"   /* oidc_cfg_parse_key_record */
#include "jose.h"        /* oidc_jwk_pem_bio_to_jwk */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <openssl/bio.h>

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

static void fuzz_pem(apr_pool_t *pool, const uint8_t *data, size_t size, apr_byte_t is_private) {
	BIO *bio = BIO_new_mem_buf(data, (int)size);
	if (bio == NULL)
		return;
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	if ((oidc_jwk_pem_bio_to_jwk(pool, bio, "fuzz", &jwk, is_private, &err) == TRUE) && (jwk != NULL)) {
		char *s_json = NULL;
		oidc_jwk_to_json(pool, jwk, &s_json, &err);
		oidc_jwk_to_public_json(pool, jwk, &s_json, &err);
		oidc_jwk_default_jws_alg(jwk);
		/* the JWK wraps cjose/OpenSSL objects allocated outside the pool */
		oidc_jwk_destroy(jwk);
	}
	BIO_free(bio);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	/* an int-sized BIO is all OpenSSL takes; keys are never that large anyway */
	if (size > 1024 * 1024)
		return 0;

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	/* 1. the record syntax */
	char *s = apr_pstrmemdup(pool, (const char *)data, size);
	char *kid = NULL, *key = NULL, *use = NULL, *alg = NULL;
	int key_len = 0;
	oidc_cfg_parse_key_record(pool, s, &kid, &key, &key_len, &use, &alg, OIDC_KEY_RECORD_PAIR);
	oidc_cfg_parse_key_record(pool, s, &kid, &key, &key_len, &use, NULL, OIDC_KEY_RECORD_PAIR);
	oidc_cfg_parse_key_record(pool, s, &kid, &key, &key_len, &use, &alg, OIDC_KEY_RECORD_TRIPLET);
	oidc_cfg_parse_key_record(pool, s, &kid, &key, &key_len, NULL, NULL, OIDC_KEY_RECORD_TRIPLET);

	/* 2. the key material */
	fuzz_pem(pool, data, size, FALSE);
	fuzz_pem(pool, data, size, TRUE);

	apr_pool_destroy(pool);
	return 0;
}
