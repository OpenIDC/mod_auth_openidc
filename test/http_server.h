/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2017-2026 ZmartZone Holding BV
 * All rights reserved.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

/*
 * Plaintext HTTP/1.0 loopback fixture used by the Check-based unit tests to
 * drive `oidc_http_get/post_form/post_json` end-to-end without depending on a
 * network service. The server binds to 127.0.0.1 on a kernel-assigned free
 * port and serves one connection per scripted response, in order, capturing
 * each request; with a single response it accepts one connection and exits.
 * Serving a sequence (oidc_test_http_server_start_seq) enables multi-request
 * flows such as a 401-then-retry or refresh-then-userinfo exchange.
 *
 * Typical usage in a test:
 *
 *     oidc_test_http_response_t resp = {.status_code = 200,
 *                                       .content_type = "application/json",
 *                                       .body = "{}"};
 *     oidc_test_http_server_t *srv = oidc_test_http_server_start(pool, &resp);
 *     // drive oidc_http_get(...) against oidc_test_http_server_url(srv, pool)
 *     const oidc_test_http_captured_t *cap = oidc_test_http_server_wait(srv);
 *     // assert on cap->method, cap->path, cap->headers, cap->body
 *     oidc_test_http_server_stop(srv);
 *
 * Plaintext only — TLS coverage is out of scope for this fixture.
 */

#ifndef _MOD_AUTH_OPENIDC_TEST_HTTP_SERVER_H_
#define _MOD_AUTH_OPENIDC_TEST_HTTP_SERVER_H_

#include <apr_pools.h>
#include <apr_tables.h>

typedef struct oidc_test_http_response_t {
	int status_code;	    /* e.g. 200, 404 */
	const char *content_type;   /* nullable; if set, emitted as Content-Type response header */
	const char *body;	    /* nullable response body (treated as 0-length when NULL) */
	apr_table_t *extra_headers; /* nullable; emitted as additional response headers */
} oidc_test_http_response_t;

typedef struct oidc_test_http_captured_t {
	char *method;	      /* "GET", "POST", ... */
	char *path;	      /* request-target, e.g. "/p?a=1" */
	apr_table_t *headers; /* request headers, name preserved */
	char *body;	      /* request body bytes (may be NULL) */
	apr_size_t body_len;  /* length of body in bytes */
} oidc_test_http_captured_t;

typedef struct oidc_test_http_server_t oidc_test_http_server_t;

/*
 * Start a loopback HTTP server that will handle exactly one connection
 * with the given response. Returns NULL on bind/listen failure. The
 * returned handle is allocated in `pool`.
 */
oidc_test_http_server_t *oidc_test_http_server_start(apr_pool_t *pool, const oidc_test_http_response_t *response);

/*
 * Start a loopback HTTP server that serves `n_responses` connections, replying
 * with responses[i] to the i-th request and capturing each one. Use this to
 * test flows that issue more than one outbound request. The test must drive
 * exactly `n_responses` requests: accept() blocks, so a test that issues fewer
 * will stall at teardown until the libcheck per-test timeout fires. Returns
 * NULL on bad arguments or bind/listen failure.
 */
oidc_test_http_server_t *oidc_test_http_server_start_seq(apr_pool_t *pool, const oidc_test_http_response_t *responses,
							 int n_responses);

/* The kernel-assigned port the server bound to. */
int oidc_test_http_server_port(const oidc_test_http_server_t *s);

/* "http://127.0.0.1:<port>" allocated in `pool`. */
const char *oidc_test_http_server_url(const oidc_test_http_server_t *s, apr_pool_t *pool);

/*
 * Wait for the server thread to finish handling the request and return
 * the captured request. Returns NULL on accept/read failure. Safe to
 * call multiple times; subsequent calls return the same pointer.
 */
const oidc_test_http_captured_t *oidc_test_http_server_wait(oidc_test_http_server_t *s);

/*
 * Join the server thread (if needed) and return the request captured for the
 * `index`-th scripted response, or NULL if that request was never made. wait()
 * is equivalent to captured(s, 0).
 */
const oidc_test_http_captured_t *oidc_test_http_server_captured(oidc_test_http_server_t *s, int index);

/* Join the server thread (if needed) and return the number of requests handled. */
int oidc_test_http_server_request_count(oidc_test_http_server_t *s);

/* Join the server thread (calls wait internally) and release resources. */
void oidc_test_http_server_stop(oidc_test_http_server_t *s);

/*
 * Bind+release a loopback TCP port and return the (now likely-free) port
 * number. Use this to drive curl at a port that has nothing listening,
 * e.g. to test the connect-refused retry path. Returns 0 on failure.
 */
int oidc_test_http_free_port(apr_pool_t *pool);

#endif /* _MOD_AUTH_OPENIDC_TEST_HTTP_SERVER_H_ */
