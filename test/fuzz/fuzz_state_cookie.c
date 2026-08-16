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
 * Fuzz target for oidc_proto_state_from_cookie(): parsing of the
 * attacker-supplied state cookie value -- compact JWE header peek, alg/enc
 * check, A256GCM decryption against the fixture's passphrase-derived key,
 * inflate-on-read decompression and JSON decoding of the payload, plus the
 * typed getters and re-serialization over whatever survives.
 *
 * The corpus seed "valid" is a real oidc_proto_state_to_cookie() round-trip
 * cut with the fixture's OIDCCryptoPassphrase, so the success path past the
 * AEAD tag stays exercised on every replay; it silently degrades to a
 * failed-decrypt input if that passphrase (or the key derivation) ever
 * changes -- re-cut it then.
 */

#include "fuzz.h"
#include "proto/proto.h"
#include "util.h" /* test fixture */

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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	request_rec r = *oidc_test_request_get();
	r.pool = pool;

	char *s = apr_pstrmemdup(pool, (const char *)data, size);
	oidc_proto_state_t *proto_state = oidc_proto_state_from_cookie(&r, oidc_test_cfg_get(), s);
	if (proto_state != NULL) {
		oidc_proto_state_get_issuer(proto_state);
		oidc_proto_state_get_nonce(proto_state);
		oidc_proto_state_get_state(proto_state);
		oidc_proto_state_get_timestamp(proto_state);
		oidc_proto_state_get_original_url(proto_state);
		oidc_proto_state_get_original_method(proto_state);
		oidc_proto_state_get_response_type(proto_state);
		oidc_proto_state_get_response_mode(proto_state);
		oidc_proto_state_get_prompt(proto_state);
		oidc_proto_state_get_pkce_state(proto_state);
		oidc_proto_state_get_auth_request_params(proto_state);
		oidc_proto_state_get_path_scope(proto_state);
		oidc_proto_state_to_string(&r, proto_state);
		/* a proto_state is a refcounted jansson value, not pooled */
		oidc_proto_state_destroy(proto_state);
	}

	apr_pool_destroy(pool);
	return 0;
}
