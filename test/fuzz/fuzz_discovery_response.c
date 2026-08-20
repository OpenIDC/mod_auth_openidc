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
 * Fuzz target for oidc_discovery_response(): the handler behind the discovery
 * page's form and behind 3rd-party initiated SSO, i.e. an unauthenticated
 * endpoint whose every input -- iss, disc_user, target_link_uri, login_hint,
 * scopes, auth_request_params, the x_csrf cookie/parameter pair -- is chosen
 * by whoever can make a browser hit the redirect URI.
 *
 * Input layout: the bytes up to the first newline become the query string
 * (r->args); anything after it becomes the Cookie request header, so the CSRF
 * cookie/parameter comparison and the expired-state-cookie sweep that the
 * authentication request performs both see fuzzer-controlled data.
 *
 * The fixture is a static single-provider configuration without an
 * OIDCMetadataDir, which keeps the handler on the static path: parameter
 * parsing, CSRF check, target_link_uri validation (configured-URL match plus
 * the open-redirect guard), issuer comparison, then the full authorization
 * request construction -- state cookie (JWE) creation, nonce/PKCE, cookie
 * header assembly and the 302 or auto-submit form. The multi-provider path is
 * deliberately out of reach: it resolves user identifiers over webfinger/HTTP,
 * which a fuzz target must never do.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_metadata.c */
/* clang-format off */
#include "util.h"          /* test fixture */
#include "handle/handle.h" /* oidc_discovery_response */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <string.h>

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

	/* shallow copy of the fixture request with a per-input pool; the handler
	 * writes response headers and cookies, so it gets its own header tables
	 * rather than accumulating into the fixture's across iterations */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.headers_in = apr_table_copy(pool, r.headers_in);
	r.headers_out = apr_table_make(pool, 8);
	r.err_headers_out = apr_table_make(pool, 8);
	/* the ap_pass_brigade stub captures the response body into the request
	 * state of the filter's request: point it at this copy so that lands in
	 * the per-input pool too */
	ap_filter_t filter;
	memset(&filter, 0, sizeof(filter));
	filter.r = &r;
	r.output_filters = &filter;

	const uint8_t *nl = memchr(data, '\n', size);
	size_t args_len = nl ? (size_t)(nl - data) : size;
	r.args = apr_pstrmemdup(pool, (const char *)data, args_len);
	if (nl != NULL) {
		const char *cookie = apr_pstrmemdup(pool, (const char *)nl + 1, size - args_len - 1);
		apr_table_set(r.headers_in, "Cookie", cookie);
	}

	oidc_discovery_response(&r, oidc_test_cfg_get());

	apr_pool_destroy(pool);
	return 0;
}
