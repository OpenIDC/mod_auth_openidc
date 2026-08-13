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
 * Fuzz target for oidc_http_get_cookie(): tokenizing the raw browser-supplied
 * Cookie request header. This is as directly attacker-controlled as input
 * gets -- any client sets it -- and its sibling reassembly function,
 * oidc_http_get_chunked_cookie(), is what a missing-chunk truncation bug was
 * fixed in (see commit "fix: return NULL when a chunked cookie is missing a
 * chunk").
 */

#include "fuzz.h"
/* util.h pulls in const.h before any Apache header does, so config.h's
 * PACKAGE_* defines win the race against Apache's own (empty) ones in
 * ap_config_auto.h; keep it ahead of http.h, see cfg/cfg.h's own ordering
 * (clang-format's include sorting would undo exactly that, hence the guard) */
/* clang-format off */
#include "util.h" /* test fixture */
#include "http.h" /* oidc_http_get_cookie */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

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

	/* shallow-copy the fixture request and give it a per-input pool, plus a
	 * fresh headers_in table so the fuzzed Cookie value never touches the
	 * shared fixture's table (which would otherwise leak across inputs) */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.headers_in = apr_table_make(pool, 1);
	apr_table_set(r.headers_in, "Cookie", apr_pstrmemdup(pool, (const char *)data, size));

	oidc_http_get_cookie(&r, "mod_auth_openidc_session");

	apr_pool_destroy(pool);
	return 0;
}
