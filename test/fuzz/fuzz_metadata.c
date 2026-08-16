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
 * Fuzz target for the metadata parsers: a provider metadata document is
 * remote-attacker-influenced input (OP discovery responses, possibly via
 * user-supplied discovery in multi-provider setups), and the client/conf
 * documents share the same typed field extraction. The decoded JSON is fed
 * to oidc_metadata_provider_is_valid() and then to the three parsers in the
 * order oidc_metadata_get() applies them, so the same document stresses the
 * provider, conf and client key sets plus the url/array/boolean validators
 * they share (metadata/util.c, cfg/provider.c setters).
 */

#include "fuzz.h"
/* util.h pulls in const.h before any Apache header does, so config.h's
 * PACKAGE_* defines win the race against Apache's own (empty) ones in
 * ap_config_auto.h -- json.h includes httpd.h directly; keep util.h ahead
 * of it, see cfg/cfg.h's own ordering (clang-format's include sorting
 * would undo exactly that, hence the guard) */
/* clang-format off */
#include "util.h"      /* test fixture */
#include "json.h"
#include "metadata.h"
#include "util/util.h" /* oidc_json_decode_object */
/* clang-format on */

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
	oidc_cfg_t *cfg = oidc_test_cfg_get();

	char *s = apr_pstrmemdup(pool, (const char *)data, size);
	oidc_json_t *json = NULL;
	if ((oidc_json_decode_object(&r, s, &json) == TRUE) && (json != NULL)) {
		oidc_provider_t *provider = oidc_cfg_provider_create(pool);
		oidc_metadata_provider_is_valid(&r, cfg, json, NULL);
		oidc_metadata_provider_parse(&r, cfg, json, provider);
		oidc_metadata_conf_parse(&r, cfg, json, provider);
		oidc_metadata_client_parse(&r, cfg, json, provider);
		oidc_json_decref(json); /* jansson value is refcounted, not pooled */
	}

	apr_pool_destroy(pool);
	return 0;
}
