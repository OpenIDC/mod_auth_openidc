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
 * Fuzz target for "Require claim" authorization (src/handle/authz.c):
 * oidc_authz_24_checker_claim, the authz provider Apache calls for every
 * request to a location that has one. It matches the claims the user was
 * authenticated with -- the userinfo claims, the id_token claims and the scope
 * returned by the token endpoint, which the provider issues and, for many
 * claims, the user picks -- against the Require arguments, with a hand-rolled
 * walk: "." recursing into nested objects, ":" comparing against every JSON
 * type and into arrays, "~" compiling a PCRE per request and running it over
 * strings and string arrays, and the shortest-claim-name rule that keeps a
 * provider-chosen claim name such as "iss:https" from satisfying
 * "Require claim iss:https://op.example.com". A denied request then takes the
 * OIDCUnAutzAction path: the error page, the 302 meta refresh, the bearer
 * scope error for AuthType oauth20, or the step-up authentication request.
 *
 * Input layout: the first byte selects the variation
 *   bits 0-1  OIDCUnAutzAction: unset (403), 401, 302 <url>, auth
 *   bit 2     AuthType oauth20
 *   bit 3     an anonymous user (r->user ""), which the pass/OPTIONS/content
 *             handler short-cuts apply to
 *   bit 4     OIDCUnAuthAction pass
 *   bit 5     an OPTIONS request
 *   bit 6     the Require arguments given as an expression (the test stubs
 *             evaluate an expression to its own text)
 *   bit 7     a browser navigation (Accept: text/html), so OIDCUnAutzAction
 *             auth issues the authentication request instead of a 401
 * and the rest holds up to four newline-separated sections:
 *   the Require claim arguments, tokenized like the configuration line
 *   the scope from the token endpoint (empty: none)
 *   the id_token claims, a JSON object on one line (empty or not an object: none)
 *   the userinfo claims, a JSON object: the rest of the input, newlines and all
 *
 * The step-up authentication request runs against the fixture's static
 * provider, offline, as in fuzz_discovery_response.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_metadata.c */
/* clang-format off */
#include "util.h"               /* test fixture */
#include "cfg/dir.h"            /* oidc_cfg_dir_config_create, oidc_cmd_dir_unautz_action_set, ... */
#include "cfg/directives.h"     /* OIDCUnAutzAction, OIDCUnAuthAction */
#include "handle/handle.h"      /* oidc_authz_24_checker_claim */
#include "mod_auth_openidc.h"   /* auth_openidc_module */
#include "util/request_state.h" /* oidc_request_state_set, oidc_request_state_json_set_new */
#include "util/util.h"          /* oidc_json_decode_object */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <string.h>

/* the OIDCUnAutzAction 302 target */
#define FUZZ_UNAUTZ_URL "https://www.example.com/denied"

/*
 * The largest input whose Require arguments may contain a "~" regex. The
 * module runs a Require regex with PCRE2's default match limit (10 million),
 * once per string claim, so a catastrophically backtracking pattern such as
 * "(a+)+$" costs some 0.2s per claim value: a 4KB input with a 120-element
 * array took over 20s, which ClusterFuzz would file as a timeout although the
 * pattern is the administrator's choice. At 512 bytes the worst case stays at
 * a few seconds, while the compile/exec/free handling of the regex path is
 * still fuzzed.
 */
#define FUZZ_AUTHZ_REGEX_MAX_INPUT 512

static int g_ready = 0;

/* a cmd_parms on the given pool, the way the fixture's oidc_test_cmd_get builds one */
static cmd_parms *fuzz_cmd(apr_pool_t *pool, request_rec *r, const char *directive) {
	cmd_parms *cmd = apr_pcalloc(pool, sizeof(cmd_parms));
	cmd->server = r->server;
	cmd->pool = pool;
	cmd->temp_pool = pool;
	cmd->directive = apr_pcalloc(pool, sizeof(ap_directive_t));
	cmd->directive->directive = directive;
	return cmd;
}

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

/* a JSON object section into the request state, where the authentication phase leaves the claims */
static void fuzz_authz_claims_set(request_rec *r, const char *key, const char *s_json) {
	oidc_json_t *json = NULL;
	if ((s_json == NULL) || (s_json[0] == '\0'))
		return;
	if ((oidc_json_decode_object(r, s_json, &json) == TRUE) && (json != NULL))
		oidc_request_state_json_set_new(r, key, json);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	/* a regex in the Require arguments (the first section, after the selector byte): bound the
	 * input, see above */
	if (size > FUZZ_AUTHZ_REGEX_MAX_INPUT) {
		const uint8_t *args = data + 1;
		const uint8_t *nl = memchr(args, '\n', size - 1);
		if (memchr(args, '~', nl ? (size_t)(nl - args) : size - 1) != NULL)
			return 0;
	}

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	/* shallow copy of the fixture request with a per-input pool and its own header and environment
	 * tables: a denied request sets response headers, the authz error variable and cookies */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.user = "alice";
	r.method = "GET";
	r.method_number = M_GET;
	r.headers_in = apr_table_copy(pool, r.headers_in);
	r.headers_out = apr_table_make(pool, 8);
	r.err_headers_out = apr_table_make(pool, 8);
	r.subprocess_env = apr_table_make(pool, 8);
	/* the ap_pass_brigade stub captures the response body into the request state of the
	 * filter's request: point it at this copy so that lands in the per-input pool too */
	ap_filter_t filter;
	memset(&filter, 0, sizeof(filter));
	filter.r = &r;
	r.output_filters = &filter;

	const unsigned int sel = (size > 0) ? data[0] : 0;

	/* a per-input location config, installed in place of the fixture's for this input */
	oidc_dir_cfg_t *saved = ap_get_module_config(r.per_dir_config, &auth_openidc_module);
	oidc_dir_cfg_t *dir_cfg = oidc_cfg_dir_config_create(pool, NULL);
	cmd_parms *cmd = fuzz_cmd(pool, &r, OIDCUnAutzAction);
	switch (sel & 3) {
	case 1:
		oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "401", NULL);
		break;
	case 2:
		oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "302", FUZZ_UNAUTZ_URL);
		break;
	case 3:
		oidc_cmd_dir_unautz_action_set(cmd, dir_cfg, "auth", NULL);
		break;
	default:
		break;
	}
	if (sel & 16)
		oidc_cmd_dir_unauth_action_set(fuzz_cmd(pool, &r, OIDCUnAuthAction), dir_cfg, "pass", NULL);
	ap_set_module_config(r.per_dir_config, &auth_openidc_module, dir_cfg);

	oidc_test_set_auth_type((sel & 4) ? "oauth20" : NULL);
	if (sel & 8)
		r.user = "";
	if (sel & 32) {
		r.method = "OPTIONS";
		r.method_number = M_OPTIONS;
	}
	if (sel & 128)
		apr_table_set(r.headers_in, "Accept", "text/html");

	/* the four sections */
	char *sections[4] = {NULL, NULL, NULL, NULL};
	sections[0] = (size > 0) ? fuzz_strndup(pool, data + 1, size - 1) : fuzz_strndup(pool, data, 0);
	for (int i = 1; i < 4; i++) {
		char *nl = strchr(sections[i - 1], '\n');
		if (nl == NULL)
			break;
		*nl = '\0';
		sections[i] = nl + 1;
	}
	const char *require_args = sections[0];
	if ((sections[1] != NULL) && (sections[1][0] != '\0'))
		oidc_request_state_set(&r, OIDC_REQUEST_STATE_KEY_SCOPE, sections[1]);
	fuzz_authz_claims_set(&r, OIDC_REQUEST_STATE_KEY_IDTOKEN, sections[2]);
	fuzz_authz_claims_set(&r, OIDC_REQUEST_STATE_KEY_CLAIMS, sections[3]);

	ap_expr_info_t *expr = NULL;
	if (sel & 64) {
		expr = apr_pcalloc(pool, sizeof(ap_expr_info_t));
		expr->filename = require_args;
	}

	oidc_authz_24_checker_claim(&r, require_args, expr);

	oidc_test_set_auth_type(NULL);
	ap_set_module_config(r.per_dir_config, &auth_openidc_module, saved);

	apr_pool_destroy(pool);
	return 0;
}
