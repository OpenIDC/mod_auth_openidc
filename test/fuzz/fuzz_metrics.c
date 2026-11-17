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
 * Fuzz target for the metrics subsystem (src/metrics.c). What the module
 * records about a request is partly chosen by others: the claim.id_token and
 * claim.userinfo counters (OIDCMetricsData claim.id_token.<name>) are keyed by
 * claim name and labelled with the claim value, i.e. data the provider issues
 * and, for a display name or an e-mail address, data the user picks. Each input
 * records counter and timing samples, flushes them into the shared-memory JSON
 * document the way the per-child flush thread does -- merging into whatever an
 * earlier flush, possibly another process's, left there -- and then renders
 * that document through every OIDCMetricsPublish format: prometheus (label
 * escaping, name normalization, both histogram families), json, internal and
 * status (the server_name/counter/name/value selectors and the readiness
 * probe), plus the fuzzer's own publish request with its reset parameter.
 *
 * Input layout: the first line is the publish request's query string (format,
 * reset, server_name, counter, name, value); every following line is one
 * operation, selected by its first character:
 *   c<type>\t<name>\t<value>  oidc_metrics_counter_inc(type, name, value);
 *                             "c<type>\t<value>" records without a name, and
 *                             a bare "c<type>" without a value either
 *   t<type>\t<elapsed>        oidc_metrics_timing_add(type, elapsed), in
 *                             microseconds; negative and huge values included
 *   f                         flush the samples recorded so far
 *   j<json>                   replace the shared-memory document with <json>
 *                             as-is: what other processes' flushes left behind,
 *                             or a corrupted segment, which the key lookups
 *                             promise not to index out of bounds on
 * <type> is taken modulo the number of counter or timing types, since the
 * module only ever passes an enum value. Other lines are ignored. Whatever is
 * left unflushed at the end is flushed before the rendering.
 *
 * Why metrics.c is #included rather than linked: the flush
 * (oidc_metrics_store) and the shared-memory accessors are static, and in the
 * module only the background thread that oidc_metrics_child_init starts calls
 * them -- asynchronously, on a timer, which a fuzz target cannot use. Compiling
 * the file into this translation unit gives the target synchronous access to
 * them without exporting test hooks from the module. Every external symbol of
 * metrics.o is then already defined here, so the linker never pulls metrics.o
 * out of libauth_openidc.a: there is one copy of the code and of its globals.
 * Only oidc_metrics_post_config runs, never child_init, so there is no thread.
 */

#include "fuzz.h"
/* util.h first: see the include-order note in fuzz_metadata.c */
/* clang-format off */
#include "util.h"              /* test fixture */
#include "../../src/metrics.c" /* the code under test, statics included: see above */
/* clang-format on */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The shared-memory segment size (OIDCMetricsCacheJsonMax). Small, so that a
 * few KB of input can outgrow it and reach the "json value too large" flush
 * error; with the 1 MB default that path would be out of the fuzzer's reach.
 */
#define FUZZ_METRICS_JSON_MAX "4096"

static int g_ready = 0;

/* engine-called one-time init, pre-forkserver on AFL++: see fuzz.h */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc;
	(void)argv;
	if (!g_ready) {
		oidc_test_setup();
		request_rec *r = oidc_test_request_get();
		/* read once, by the first _oidc_metrics_shm_size() call in post_config */
		oidc_test_setenv(oidc_test_pool_get(), OIDC_METRICS_CACHE_JSON_MAX_ENV_VAR, FUZZ_METRICS_JSON_MAX);
		/* the segment, the local tables and both mutexes; no flush thread */
		if (oidc_metrics_post_config(r->server->process->pconf, r->server) != TRUE) {
			fprintf(stderr, "fuzz_metrics: oidc_metrics_post_config failed\n");
			abort();
		}
		g_ready = 1;
	}
	return 0;
}

/* a decimal type number at *p, reduced to one of n enum values; *p is advanced past it */
static unsigned int fuzz_metrics_type(char **p, unsigned int n) {
	char *end = NULL;
	unsigned long v = strtoul(*p, &end, 10);
	*p = end;
	return (unsigned int)(v % n);
}

/* what the flush thread does on each tick (oidc_metrics_thread_run), minus the timer */
static void fuzz_metrics_flush(server_rec *s) {
	if (oidc_metrics_store(s) == TRUE)
		oidc_metrics_local_reset(s);
}

static void fuzz_metrics_op(request_rec *r, char *line) {
	char *p = line + 1;
	switch (line[0]) {
	case 'c': {
		unsigned int type = fuzz_metrics_type(&p, OM_NUMBER_OF_COUNTERS);
		char *name = NULL;
		char *value = NULL;
		char *tab = strchr(p, '\t');
		if (tab != NULL) {
			value = tab + 1;
			tab = strchr(value, '\t');
			if (tab != NULL) {
				*tab = '\0';
				name = value;
				value = tab + 1;
			}
		}
		oidc_metrics_counter_inc(r, (oidc_metrics_counter_type_t)type, name, value);
		break;
	}
	case 't': {
		unsigned int type = fuzz_metrics_type(&p, OM_NUMBER_OF_TIMINGS);
		apr_time_t elapsed = (*p == '\t') ? (apr_time_t)strtoll(p + 1, NULL, 10) : 0;
		oidc_metrics_timing_add(r, (oidc_metrics_timing_type_t)type, elapsed);
		break;
	}
	case 'f':
		fuzz_metrics_flush(r->server);
		break;
	case 'j':
		_oidc_metrics_storage_set(r->server, p);
		break;
	default:
		break;
	}
}

/* the fixed publish requests every input is rendered through, before the fuzzer's own */
static const char *const fuzz_metrics_formats[] = {"format=prometheus", "format=json", "format=internal",
						   "format=status"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (!g_ready)
		LLVMFuzzerInitialize(NULL, NULL);

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, oidc_test_pool_get());

	/* shallow copy of the fixture request with a per-input pool, and of its server and process
	 * records: the subsystem allocates its flush scratch pool and the numbers in its overflow
	 * warning from the process pool, and oidc_slog formats every server-level log line into
	 * pconf; neither is cleared between requests in the module, so here both are the per-input
	 * pool too, or each overflowing input would grow the fixture's pools for good */
	request_rec r = *oidc_test_request_get();
	process_rec process = *r.server->process;
	process.pool = pool;
	process.pconf = pool;
	server_rec server = *r.server;
	server.process = &process;
	r.server = &server;
	r.pool = pool;
	r.headers_in = apr_table_copy(pool, r.headers_in);
	r.headers_out = apr_table_make(pool, 8);
	r.err_headers_out = apr_table_make(pool, 8);
	/* the ap_pass_brigade stub captures the response body into the request state of the
	 * filter's request: point it at this copy so that lands in the per-input pool too */
	ap_filter_t filter;
	memset(&filter, 0, sizeof(filter));
	filter.r = &r;
	r.output_filters = &filter;

	/* nothing carries over between inputs: an empty segment, a zeroed self-health header and
	 * empty local tables */
	memset(_oidc_metrics_shm_hdr(), 0, sizeof(oidc_metrics_shm_hdr_t));
	_oidc_metrics_storage_set(&server, NULL);
	oidc_metrics_local_reset(&server);

	char *query = fuzz_strndup(pool, data, size);
	char *rest = strchr(query, '\n');
	if (rest != NULL)
		*rest++ = '\0';
	while (rest != NULL) {
		char *line = rest;
		rest = strchr(line, '\n');
		if (rest != NULL)
			*rest++ = '\0';
		fuzz_metrics_op(&r, line);
	}
	fuzz_metrics_flush(&server);

	for (size_t i = 0; i < sizeof(fuzz_metrics_formats) / sizeof(fuzz_metrics_formats[0]); i++) {
		r.args = (char *)fuzz_metrics_formats[i];
		oidc_metrics_handle_request(&r);
	}
	r.args = query;
	oidc_metrics_handle_request(&r);

	apr_pool_destroy(pool);
	return 0;
}
