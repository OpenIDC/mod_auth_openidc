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
 * Fuzz target for oidc_util_read_form_encoded_params(): the '&'/'='-encoded
 * parameter parser used for both the front-channel authorization response
 * (query string: code, state, error, ...) and the back-channel logout
 * request body (logout_token) -- per its own comment, "the values include
 * the authorization code and bare tokens". Both are fully attacker/OP
 * controlled on the wire.
 */

#include "fuzz.h"
/* util.h pulls in const.h before any Apache header does, so config.h's
 * PACKAGE_* defines win the race against Apache's own (empty) ones in
 * ap_config_auto.h; keep it ahead of http.h, see cfg/cfg.h's own ordering */
#include "util.h" /* test fixture */
#include "http.h" /* oidc_util_read_form_encoded_params */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

static int g_ready = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready) {
		oidc_test_setup();
		g_ready = 1;
	}

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	request_rec r = *oidc_test_request_get();
	r.pool = pool;

	/* the parser takes a NUL-terminated C string */
	char *params = apr_pstrmemdup(pool, (const char *)data, size);
	apr_table_t *table = apr_table_make(pool, 5);
	oidc_util_read_form_encoded_params(&r, table, params);

	apr_pool_destroy(pool);
	return 0;
}
