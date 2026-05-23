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

#include "http_server.h"

#include <apr_network_io.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>

#include <stdio.h>
#include <string.h>

#define OIDC_TEST_SRV_READ_BUF 8192
#define OIDC_TEST_SRV_BACKLOG 1

struct oidc_test_http_server_t {
	apr_pool_t *pool;
	apr_socket_t *listen_sock;
	apr_port_t port;
	apr_thread_t *thread;
	const oidc_test_http_response_t *response;
	oidc_test_http_captured_t captured;
	int captured_ok;
	int stopped;
};

/* read until \r\n\r\n; on success returns header length (incl. terminator), -1 on failure */
static apr_ssize_t srv_read_headers(apr_socket_t *sock, char *buf, apr_size_t cap, apr_size_t *received_total) {
	apr_size_t total = 0;
	while (total < cap) {
		apr_size_t want = cap - total;
		apr_status_t rv = apr_socket_recv(sock, buf + total, &want);
		if (rv != APR_SUCCESS || want == 0)
			return -1;
		total += want;
		/* look for end of header block */
		if (total >= 4) {
			for (apr_size_t i = 3; i < total; i++) {
				if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n') {
					*received_total = total;
					return (apr_ssize_t)(i + 1);
				}
			}
		}
	}
	return -1;
}

static void srv_parse_request(oidc_test_http_server_t *s, char *headers, apr_size_t headers_len,
			      const char *trailing_body, apr_size_t trailing_body_len, apr_socket_t *sock) {
	apr_pool_t *p = s->pool;
	s->captured.headers = apr_table_make(p, 16);

	/* request line: METHOD<sp>PATH<sp>HTTP/1.x\r\n */
	char *eol = strstr(headers, "\r\n");
	if (eol == NULL)
		return;
	*eol = '\0';
	char *sp1 = strchr(headers, ' ');
	if (sp1 == NULL)
		return;
	*sp1 = '\0';
	char *sp2 = strchr(sp1 + 1, ' ');
	if (sp2 == NULL)
		return;
	*sp2 = '\0';
	s->captured.method = apr_pstrdup(p, headers);
	s->captured.path = apr_pstrdup(p, sp1 + 1);

	/* header lines until empty line */
	char *line = eol + 2;
	apr_size_t content_length = 0;
	while (line < headers + headers_len) {
		char *next = strstr(line, "\r\n");
		if (next == line)
			break;
		if (next == NULL)
			break;
		*next = '\0';
		char *colon = strchr(line, ':');
		if (colon != NULL) {
			*colon = '\0';
			char *name = line;
			char *value = colon + 1;
			while (*value == ' ' || *value == '\t')
				value++;
			apr_table_set(s->captured.headers, name, value);
			if (strcasecmp(name, "Content-Length") == 0)
				content_length = (apr_size_t)apr_atoi64(value);
		}
		line = next + 2;
	}

	/* body: anything past headers we already read, plus more reads if needed */
	if (content_length > 0) {
		char *body = apr_palloc(p, content_length + 1);
		apr_size_t got = 0;
		if (trailing_body_len > 0) {
			apr_size_t take = trailing_body_len < content_length ? trailing_body_len : content_length;
			memcpy(body, trailing_body, take);
			got = take;
		}
		while (got < content_length) {
			apr_size_t want = content_length - got;
			apr_status_t rv = apr_socket_recv(sock, body + got, &want);
			if (rv != APR_SUCCESS || want == 0)
				break;
			got += want;
		}
		body[got] = '\0';
		s->captured.body = body;
		s->captured.body_len = got;
	}
}

static const char *srv_reason(int code) {
	switch (code) {
	case 200:
		return "OK";
	case 201:
		return "Created";
	case 204:
		return "No Content";
	case 400:
		return "Bad Request";
	case 401:
		return "Unauthorized";
	case 403:
		return "Forbidden";
	case 404:
		return "Not Found";
	case 500:
		return "Internal Server Error";
	case 502:
		return "Bad Gateway";
	case 503:
		return "Service Unavailable";
	default:
		return "Unknown";
	}
}

/* iterate apr_table_t with apr_table_do; appends "Name: value\r\n" to *acc */
typedef struct {
	apr_pool_t *pool;
	char *acc;
} srv_hdr_acc_t;

static int srv_append_hdr(void *rec, const char *key, const char *value) {
	srv_hdr_acc_t *a = (srv_hdr_acc_t *)rec;
	a->acc = apr_psprintf(a->pool, "%s%s: %s\r\n", a->acc ? a->acc : "", key, value);
	return 1;
}

static void srv_send_response(oidc_test_http_server_t *s, apr_socket_t *sock) {
	const oidc_test_http_response_t *r = s->response;
	apr_size_t body_len = r->body ? strlen(r->body) : 0;
	srv_hdr_acc_t acc = {s->pool, NULL};
	if (r->extra_headers != NULL)
		apr_table_do(srv_append_hdr, &acc, r->extra_headers, NULL);

	char *head =
	    apr_psprintf(s->pool,
			 "HTTP/1.0 %d %s\r\n"
			 "%s%s%s"
			 "Content-Length: %u\r\n"
			 "Connection: close\r\n"
			 "\r\n",
			 r->status_code, srv_reason(r->status_code), r->content_type ? "Content-Type: " : "",
			 r->content_type ? r->content_type : "", r->content_type ? "\r\n" : "", (unsigned int)body_len);
	if (acc.acc) {
		/* splice extra headers in before the blank line */
		head = apr_pstrcat(
		    s->pool, apr_psprintf(s->pool, "HTTP/1.0 %d %s\r\n", r->status_code, srv_reason(r->status_code)),
		    r->content_type ? apr_psprintf(s->pool, "Content-Type: %s\r\n", r->content_type) : "", acc.acc,
		    apr_psprintf(s->pool, "Content-Length: %u\r\n", (unsigned int)body_len),
		    "Connection: close\r\n\r\n", NULL);
	}

	apr_size_t hl = strlen(head);
	apr_socket_send(sock, head, &hl);
	if (body_len > 0) {
		apr_size_t bl = body_len;
		apr_socket_send(sock, r->body, &bl);
	}
}

static void *APR_THREAD_FUNC srv_run(apr_thread_t *t, void *data) {
	oidc_test_http_server_t *s = (oidc_test_http_server_t *)data;
	apr_socket_t *conn = NULL;

	apr_status_t rv = apr_socket_accept(&conn, s->listen_sock, s->pool);
	if (rv != APR_SUCCESS) {
		/* accept timeout (no client) is a legitimate shutdown path for tests that
		 * never connect to the server, so we exit quietly */
		apr_thread_exit(t, APR_SUCCESS);
		return NULL;
	}

	/* short timeouts so a misbehaving test doesn't hang the suite */
	apr_socket_timeout_set(conn, apr_time_from_sec(5));

	char *buf = apr_palloc(s->pool, OIDC_TEST_SRV_READ_BUF);
	apr_size_t received_total = 0;
	apr_ssize_t hdr_end = srv_read_headers(conn, buf, OIDC_TEST_SRV_READ_BUF, &received_total);
	if (hdr_end < 0) {
		apr_socket_close(conn);
		apr_thread_exit(t, APR_EGENERAL);
		return NULL;
	}
	/* NUL-terminate inside the header block (replacing the final '\n' of the
	 * "\r\n\r\n" terminator). This bounds the header-parser's strstr calls
	 * without touching the first byte of any inline body bytes at buf[hdr_end]. */
	buf[hdr_end - 1] = '\0';
	apr_size_t trailing_len = received_total - (apr_size_t)hdr_end;
	const char *trailing = (trailing_len > 0) ? (buf + hdr_end) : NULL;

	srv_parse_request(s, buf, (apr_size_t)hdr_end, trailing, trailing_len, conn);
	s->captured_ok = (s->captured.method != NULL && s->captured.path != NULL);

	srv_send_response(s, conn);

	apr_socket_close(conn);
	apr_thread_exit(t, APR_SUCCESS);
	return NULL;
}

oidc_test_http_server_t *oidc_test_http_server_start(apr_pool_t *pool, const oidc_test_http_response_t *response) {
	oidc_test_http_server_t *s = apr_pcalloc(pool, sizeof(*s));
	s->pool = pool;
	s->response = response;

	apr_sockaddr_t *sa = NULL;
	if (apr_sockaddr_info_get(&sa, "127.0.0.1", APR_INET, 0, 0, pool) != APR_SUCCESS)
		return NULL;
	if (apr_socket_create(&s->listen_sock, sa->family, SOCK_STREAM, APR_PROTO_TCP, pool) != APR_SUCCESS)
		return NULL;
	apr_socket_opt_set(s->listen_sock, APR_SO_REUSEADDR, 1);
	if (apr_socket_bind(s->listen_sock, sa) != APR_SUCCESS)
		return NULL;
	if (apr_socket_listen(s->listen_sock, OIDC_TEST_SRV_BACKLOG) != APR_SUCCESS)
		return NULL;

	/* recover the actual bound port */
	apr_sockaddr_t *bound = NULL;
	if (apr_socket_addr_get(&bound, APR_LOCAL, s->listen_sock) != APR_SUCCESS)
		return NULL;
	s->port = bound->port;

	if (apr_thread_create(&s->thread, NULL, srv_run, s, pool) != APR_SUCCESS)
		return NULL;
	return s;
}

int oidc_test_http_server_port(const oidc_test_http_server_t *s) {
	return s ? (int)s->port : 0;
}

const char *oidc_test_http_server_url(const oidc_test_http_server_t *s, apr_pool_t *pool) {
	if (s == NULL)
		return NULL;
	return apr_psprintf(pool, "http://127.0.0.1:%d", (int)s->port);
}

const oidc_test_http_captured_t *oidc_test_http_server_wait(oidc_test_http_server_t *s) {
	if (s == NULL || s->thread == NULL)
		return NULL;
	if (!s->stopped) {
		apr_status_t status = APR_SUCCESS;
		apr_thread_join(&status, s->thread);
		s->stopped = 1;
	}
	return s->captured_ok ? &s->captured : NULL;
}

void oidc_test_http_server_stop(oidc_test_http_server_t *s) {
	if (s == NULL)
		return;
	(void)oidc_test_http_server_wait(s);
	if (s->listen_sock != NULL) {
		apr_socket_close(s->listen_sock);
		s->listen_sock = NULL;
	}
}

int oidc_test_http_free_port(apr_pool_t *pool) {
	apr_sockaddr_t *sa = NULL;
	apr_socket_t *sock = NULL;
	if (apr_sockaddr_info_get(&sa, "127.0.0.1", APR_INET, 0, 0, pool) != APR_SUCCESS)
		return 0;
	if (apr_socket_create(&sock, sa->family, SOCK_STREAM, APR_PROTO_TCP, pool) != APR_SUCCESS)
		return 0;
	apr_socket_opt_set(sock, APR_SO_REUSEADDR, 1);
	if (apr_socket_bind(sock, sa) != APR_SUCCESS) {
		apr_socket_close(sock);
		return 0;
	}
	apr_sockaddr_t *bound = NULL;
	int port = 0;
	if (apr_socket_addr_get(&bound, APR_LOCAL, sock) == APR_SUCCESS)
		port = bound->port;
	apr_socket_close(sock);
	return port;
}
