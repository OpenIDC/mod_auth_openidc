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
 * Fuzz target for oidc_json_decode_object(): decoding of
 * attacker-controlled JSON (token responses, userinfo, metadata documents all
 * pass through here).
 */

#include "fuzz.h"
#include "util.h"      /* test fixture */
#include "util/util.h" /* oidc_json_decode_object */

#include "json.h"
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

	request_rec r = *oidc_test_request_get();
	r.pool = pool;

	char *s = apr_pstrmemdup(pool, (const char *)data, size);
	oidc_json_t *json = NULL;
	if ((oidc_json_decode_object(&r, s, &json) == TRUE) && (json != NULL))
		oidc_json_decref(json); /* jansson value is refcounted, not pooled */

	apr_pool_destroy(pool);
	return 0;
}
