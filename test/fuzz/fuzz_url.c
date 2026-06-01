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
 */

#include "fuzz.h"
#include "mod_auth_openidc.h" /* oidc_validate_redirect_url */
#include "util.h"	      /* test fixture */

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

	/* shallow-copy the fixture request and give it a per-input pool so all
	 * allocations made while validating are reclaimed each iteration */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	char *url = apr_pstrmemdup(pool, (const char *)data, size);
	char *err_str = NULL;
	char *err_desc = NULL;
	oidc_validate_redirect_url(&r, cfg, url, TRUE, &err_str, &err_desc);

	apr_pool_destroy(pool);
	return 0;
}
