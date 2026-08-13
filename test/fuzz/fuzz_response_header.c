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
 * Fuzz target for oidc_http_response_header(): the libcurl
 * CURLOPT_HEADERFUNCTION callback that parses raw HTTP response header lines
 * coming back from the OP (token/userinfo/discovery endpoints), one line at
 * a time, as the module's client trust boundary against a malicious or
 * compromised OP. This is the exact function a CR/LF-trim under-read
 * (empty header value reading before the start of the buffer) was fixed in
 * today; feeding it directly, one raw wire line at a time, is what would
 * have caught that.
 */

#include "fuzz.h"
/* util.h pulls in const.h before any Apache header does, so config.h's
 * PACKAGE_* defines win the race against Apache's own (empty) ones in
 * ap_config_auto.h; keep it ahead of http.h, see cfg/cfg.h's own ordering
 * (clang-format's include sorting would undo exactly that, hence the guard) */
/* clang-format off */
#include "util.h"     /* test fixture */
#include "http.h"     /* oidc_http_response_header */
#include "http_int.h" /* oidc_curl_resp_hdr_ctx_t */
/* clang-format on */

#include <apr_hash.h>
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

	/* seed with a couple of header names the module actually looks for, the
	 * way real callers do (an empty-string sentinel per wanted header) */
	apr_hash_t *hdrs = apr_hash_make(pool);
	apr_hash_set(hdrs, OIDC_HTTP_HDR_DPOP_NONCE, APR_HASH_KEY_STRING, "");
	apr_hash_set(hdrs, OIDC_HTTP_HDR_CONTENT_TYPE, APR_HASH_KEY_STRING, "");
	oidc_curl_resp_hdr_ctx_t ctx = {&r, hdrs};

	/* the callback receives one wire line at a time, NOT zero-terminated; the
	 * fuzz input plays that role directly (nitems=size, size=1) */
	oidc_http_response_header((const char *)data, 1, size, &ctx);

	apr_pool_destroy(pool);
	return 0;
}
