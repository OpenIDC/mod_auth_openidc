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
 * Fuzz target for oidc_validate_redirect_url(): the open-redirect guard that
 * vets attacker-supplied return-to / post_logout_redirect / target_link_uri
 * values before the module redirects to them. Seed corpus:
 * test/open-redirect-payload-list.txt (replayed line by line).
 *
 * Every input is validated three times, against the three configurations the
 * guard distinguishes: same-host scope (the logout/return-to case), any-host
 * scope (the target_link_uri case once it has passed the configured-URL
 * match), and same-host scope with an OIDCRedirectURLsAllowed list -- which
 * switches the guard from hostname comparison to regex matching, a branch the
 * fixture's plain configuration never takes. The allow-list copy of the
 * fixture config is made once at startup; the fixture itself is not changed.
 */

#include "cfg/cfg_int.h" /* oidc_cfg_t members, for the allow-list */
#include "fuzz.h"
#include "mod_auth_openidc.h" /* oidc_validate_redirect_url */
#include "util.h"	      /* test fixture */

#include <apr_hash.h>
#include <apr_pools.h>
#include <apr_strings.h>

static int g_ready = 0;
static oidc_cfg_t *g_cfg_allowed = NULL;

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		/* a second server config carrying an allow-list: one anchored host
		 * pattern and one deliberately loose one, so both the match and the
		 * no-match legs of the regex loop see traffic. Allocated by the library
		 * rather than declared here by value: sizeof(oidc_cfg_t) depends on the
		 * USE_* feature macros, so a by-value instance in this TU is only as big
		 * as the harness build flags make it, not as big as the library expects. */
		apr_pool_t *pool = oidc_test_pool_get();
		g_cfg_allowed = oidc_cfg_server_create(pool, oidc_test_request_get()->server);
		g_cfg_allowed->redirect_urls_allowed = apr_hash_make(pool);
		const char *anchored = "^https://www\\.example\\.com/";
		const char *loose = "example\\.org/.*callback";
		apr_hash_set(g_cfg_allowed->redirect_urls_allowed, anchored, APR_HASH_KEY_STRING, anchored);
		apr_hash_set(g_cfg_allowed->redirect_urls_allowed, loose, APR_HASH_KEY_STRING, loose);
		g_ready = 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	/* shallow-copy the fixture request and give it a per-input pool so all
	 * allocations made while validating are reclaimed each iteration */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	char *url = apr_pstrmemdup(pool, (const char *)data, size);
	char *err_str = NULL;
	char *err_desc = NULL;
	oidc_validate_redirect_url(&r, cfg, url, OIDC_REDIRECT_URL_SAME_HOST, &err_str, &err_desc);
	oidc_validate_redirect_url(&r, cfg, url, OIDC_REDIRECT_URL_ANY_HOST, &err_str, &err_desc);
	oidc_validate_redirect_url(&r, g_cfg_allowed, url, OIDC_REDIRECT_URL_SAME_HOST, &err_str, &err_desc);

	apr_pool_destroy(pool);
	return 0;
}
