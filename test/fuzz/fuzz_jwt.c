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
 * Fuzz target for oidc_jwt_parse(): parsing of attacker-controlled compact
 * JWT/JWS/JWE serializations (no key set, so this exercises the structural
 * parse and base64url/JSON decoding of the header and payload, not signature
 * verification).
 */

#include "fuzz.h"
#include "jose.h"
#include "util.h" /* test fixture */

#include <apr_hash.h>
#include <apr_pools.h>
#include <apr_strings.h>

static int g_ready = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready) {
		oidc_test_setup();
		g_ready = 1;
	}

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	char *s = apr_pstrmemdup(pool, (const char *)data, size);
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;
	apr_hash_t *keys = apr_hash_make(pool);

	oidc_jwt_parse(pool, s, &jwt, keys, FALSE, &err);
	/* a JWT wraps cjose/OpenSSL objects allocated outside the pool */
	if (jwt != NULL)
		oidc_jwt_destroy(jwt);

	apr_pool_destroy(pool);
	return 0;
}
