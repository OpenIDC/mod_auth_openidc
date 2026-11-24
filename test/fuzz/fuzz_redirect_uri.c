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
 * Fuzz target for the redirect_uri dispatcher (oidc_handle_redirect_uri_request)
 * and the content-handler phase behind it (oidc_content_handler): one query
 * string, chosen by whoever can make a browser hit the redirect URI, selects
 * and parameterizes every sub-feature the module hangs off that one URL --
 * the authorization response (GET and POST), front- and back-channel logout
 * (?logout=, sid, iss), the session-management commands (?session=),
 * access-token refresh (?refresh=, access_token), the request_uri cache
 * lookup (?request_uri=), the introspection-cache and session revocations
 * (?remove_at_cache=, ?revoke_session=), the info hook (?info=, its interval
 * and extend-session parameters), the JWKS and DPoP endpoints and the bare
 * implicit-flow relay page. The other targets go deep on the two biggest of
 * these; this one goes wide, across the routing and every handler's own
 * parameter parsing, so nothing hanging off the redirect URI is left out.
 *
 * Input layout: the first byte selects the method (bit 0: form POST),
 * whether the request carries an authenticated session with tokens in it
 * (bit 1), which the info, refresh and session-management handlers require
 * or behave differently with, and whether that session was issued for
 * another host than the one that is requested (bit 2), which the info hook
 * refuses before it looks at anything else; the rest is the query string
 * (which the test stubs also serve as the POST body).
 *
 * The fixture provider has no token, userinfo, end-session or JWKS
 * endpoint, so every path that would call out fails at once and offline on
 * the missing URL, with retries disabled so it does not sleep.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_cookie.c */
/* clang-format off */
#include "util.h"             /* test fixture */
#include "cfg/cfg_int.h"      /* oidc_cfg_t members, for the HTTP retry counts */
#include "cfg/provider.h"     /* oidc_cfg_provider_client_secret_set */
#include "handle/handle.h"    /* oidc_content_handler */
#include "mod_auth_openidc.h" /* oidc_session_t */
#include "util/util_cfg.h"    /* oidc_util_url_cur_host */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <string.h>

/* the top-level dispatch entry lives in mod_auth_openidc.c and has no public header */
extern int oidc_handle_redirect_uri_request(request_rec *r, oidc_cfg_t *c, oidc_session_t *session);

/* a host that the fixture does not serve */
#define FUZZ_OTHER_HOST "other.example.com"

static int g_ready = 0;

/* the cookie domain that a login stores in the session: see oidc_response_save_in_session */
static const char *fuzz_session_cookie_domain(request_rec *r, oidc_cfg_t *cfg) {
	return oidc_cfg_cookie_domain_get(cfg) ? oidc_cfg_cookie_domain_get(cfg)
					       : oidc_util_url_cur_host(r, oidc_cfg_x_forwarded_headers_get(cfg));
}

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		oidc_cfg_t *cfg = oidc_test_cfg_get();
		/* a client_secret so the handlers that derive a symmetric key from it get past that step */
		oidc_cfg_provider_client_secret_set(oidc_test_pool_get(), oidc_cfg_provider_get(cfg),
						    "fuzz-redirect-uri-shared-secret");
		/* no endpoint is configured, so a path that ends in an outbound HTTP call hands curl a
		 * NULL URL and fails at once, offline; drop the retries so it does not sleep either */
		cfg->http_timeout_long.retries = 0;
		cfg->http_timeout_short.retries = 0;
		/* OIDCInfoHook with every data element: with none configured the info hook has nothing
		 * to return and says so, before it reads its parameters or builds a response */
		static const char *const info_hook_data[] = {
		    OIDC_HOOK_INFO_TIMESTAMP,		OIDC_HOOK_INFO_ACCES_TOKEN, OIDC_HOOK_INFO_ACCES_TOKEN_EXP,
		    OIDC_HOOK_INFO_ID_TOKEN_HINT,	OIDC_HOOK_INFO_ID_TOKEN,    OIDC_HOOK_INFO_USER_INFO,
		    OIDC_HOOK_INFO_REFRESH_TOKEN,	OIDC_HOOK_INFO_SESSION_EXP, OIDC_HOOK_INFO_SESSION_TIMEOUT,
		    OIDC_HOOK_INFO_SESSION_REMOTE_USER, OIDC_HOOK_INFO_SESSION};
		for (size_t i = 0; i < sizeof(info_hook_data) / sizeof(info_hook_data[0]); i++)
			oidc_cmd_info_hook_data_set(oidc_test_cmd_get(OIDCInfoHook), NULL, info_hook_data[i]);
		g_ready = 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());
	/* the http-scheme stub reads the scheme from pool userdata */
	apr_pool_userdata_set("https", "scheme", NULL, pool);

	oidc_cfg_t *cfg = oidc_test_cfg_get();

	/* shallow copy of the fixture request with a per-input pool and its own header, environment
	 * and notes tables, so nothing the handlers set accumulates across inputs */
	request_rec r = *oidc_test_request_get();
	r.pool = pool;
	r.user = NULL;
	r.headers_in = apr_table_copy(pool, r.headers_in);
	r.headers_out = apr_table_make(pool, 8);
	r.err_headers_out = apr_table_make(pool, 8);
	r.subprocess_env = r.subprocess_env ? apr_table_copy(pool, r.subprocess_env) : apr_table_make(pool, 8);
	r.notes = r.notes ? apr_table_copy(pool, r.notes) : apr_table_make(pool, 8);
	/* the ap_pass_brigade stub captures any response body into the request state of the
	 * filter's request: point it at this copy so that lands in the per-input pool too */
	ap_filter_t filter;
	memset(&filter, 0, sizeof(filter));
	filter.r = &r;
	r.output_filters = &filter;

	const unsigned int sel = (size > 0) ? data[0] : 0;
	r.args = ((size > 0) ? fuzz_strndup(pool, data + 1, size - 1) : fuzz_strndup(pool, data, 0));

	/* the request is to the configured redirect URI: the content handler matches on the path */
	r.uri = "/protected/";
	r.unparsed_uri = apr_pstrcat(pool, r.uri, "?", r.args, NULL);
	r.parsed_uri.path = r.uri;
	r.parsed_uri.query = r.args;

	if (sel & 1) {
		r.method_number = M_POST;
		r.method = "POST";
		apr_table_set(r.headers_in, "Content-Type", "application/x-www-form-urlencoded");
		/* the test stubs serve the POST body out of r->args */
		r.remaining = (apr_off_t)strlen(r.args);
	} else {
		r.method_number = M_GET;
		r.method = "GET";
		r.remaining = 0;
	}

	oidc_session_t *session = NULL;
	oidc_session_load(&r, &session);
	if (sel & 2) {
		/* an authenticated session with the tokens the refresh/info/session handlers look for */
		session->remote_user = apr_pstrdup(pool, "alice");
		oidc_session_set_issuer(&r, session, "https://idp.example.com");
		oidc_session_set_access_token(&r, session, "AT-1");
		oidc_session_set_access_token_type(&r, session, "Bearer");
		oidc_session_set_access_token_expires(&r, session, 3600);
		oidc_session_set_refresh_token(&r, session, "RT-1");
		oidc_session_set_idtoken(&r, session, "eyJhbGciOiJub25lIn0.e30.");
		oidc_session_set_session_state(&r, session, "session-state-1");
		oidc_session_set_original_url(&r, session, "https://www.example.com/protected/index.html");
		oidc_session_set_session_expires(&r, session, apr_time_now() + apr_time_from_sec(3600));
		/* the host that the session was issued for: without the one that is requested here, the
		 * info hook takes the session for one that is replayed against another host and refuses
		 * it, so that nothing behind that check would run -- the checks on the session, the
		 * refreshes that are due and the info response itself */
		oidc_session_set_cookie_domain(&r, session,
					       (sel & 4) ? FUZZ_OTHER_HOST : fuzz_session_cookie_domain(&r, cfg));
	}

	int rc = oidc_handle_redirect_uri_request(&r, cfg, session);
	/* the phase that renders what the handler prepared, and the sub-features that run there */
	if ((rc == OK) || (rc == DECLINED))
		oidc_content_handler(&r);

	oidc_session_free(&r, session);

	apr_pool_destroy(pool);
	return 0;
}
