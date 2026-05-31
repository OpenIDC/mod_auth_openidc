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
 * Fuzz target for oidc_util_base64url_decode(): base64url decoding of
 * attacker-controlled strings (cookies, state, JWT segments all flow through
 * here).
 */

#include "fuzz.h"
#include "util.h"      /* test fixture: oidc_test_setup / oidc_test_pool_get */
#include "util/util.h" /* oidc_util_base64url_decode */

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

	/* the decoder takes a NUL-terminated C string */
	char *src = apr_pstrmemdup(pool, (const char *)data, size);
	char *dst = NULL;
	oidc_util_base64url_decode(pool, &dst, src);

	apr_pool_destroy(pool);
	return 0;
}
