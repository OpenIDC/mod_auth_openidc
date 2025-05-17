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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
 * All rights reserved.
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "util/util.h"

#include <http_protocol.h>

/*
 * get the URL scheme that is currently being accessed
 */
static const char *_oidc_util_url_cur_scheme(const request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers) {
	/* first see if there's a proxy/load-balancer in front of us */
	const char *scheme_str = NULL;

	if (x_forwarded_headers & OIDC_HDR_FORWARDED)
		scheme_str = oidc_http_hdr_forwarded_get(r, "proto");
	if ((scheme_str == NULL) && (x_forwarded_headers & OIDC_HDR_X_FORWARDED_PROTO))
		scheme_str = oidc_http_hdr_in_x_forwarded_proto_get(r);

	/* if not we'll determine the scheme used to connect to this server */
	if (scheme_str == NULL) {
#ifdef APACHE2_0
		scheme_str = (char *)ap_http_method(r);
#else
		scheme_str = ap_http_scheme(r);
#endif
	}
	if ((scheme_str == NULL) ||
	    ((_oidc_strnatcasecmp(scheme_str, "http") != 0) && (_oidc_strnatcasecmp(scheme_str, "https") != 0))) {
		oidc_warn(r,
			  "detected HTTP scheme \"%s\" is not \"http\" nor \"https\"; perhaps your reverse proxy "
			  "passes a wrongly configured \"%s\" header: falling back to default \"https\"",
			  scheme_str, OIDC_HTTP_HDR_X_FORWARDED_PROTO);
		scheme_str = "https";
	}
	return scheme_str;
}

/*
 * get the port from a Host or X-Forwarded-Host header
 */
static const char *_oidc_util_url_port_from_host_hdr(const char *host_hdr) {
	const char *p = NULL;

	// check for an IPv6 literal addresses
	if (host_hdr && host_hdr[0] == '[')
		p = strchr(host_hdr, ']');
	else
		p = host_hdr;

	if (p) {
		p = strchr(p, OIDC_CHAR_COLON);
		// skip over the ":" to point to the actual port number
		if (p)
			p++;
	}

	return p;
}

/*
 * get the URL port that is currently being accessed
 */
static const char *_oidc_util_url_cur_port(const request_rec *r, const char *scheme_str, int x_forwarded_headers) {

	const char *host_hdr = NULL;
	const char *port_str = NULL;

	/*
	 * first see if there's a proxy/load-balancer in front of us
	 * that sets X-Forwarded-Port
	 */

	if (x_forwarded_headers & OIDC_HDR_X_FORWARDED_PORT)
		port_str = oidc_http_hdr_in_x_forwarded_port_get(r);

	if (port_str)
		return port_str;

	/*
	 * see if we can get the port from the "X-Forwarded-Host" or "Forwarded" header
	 * and if that header was set we'll assume defaults
	 */

	if (x_forwarded_headers & OIDC_HDR_FORWARDED)
		host_hdr = oidc_http_hdr_forwarded_get(r, "host");
	if ((host_hdr == NULL) && (x_forwarded_headers & OIDC_HDR_X_FORWARDED_HOST))
		host_hdr = oidc_http_hdr_in_x_forwarded_host_get(r);

	if (host_hdr)
		return _oidc_util_url_port_from_host_hdr(host_hdr);

	/*
	 * see if we can get the port from the "Host" header; if not
	 * we'll determine the port locally
	 */
	host_hdr = oidc_http_hdr_in_host_get(r);
	if (host_hdr)
		return _oidc_util_url_port_from_host_hdr(host_hdr);

	/*
	 * if X-Forwarded-Proto assume the default port otherwise the
	 * port should have been set in the X-Forwarded-Port header
	 */
	if ((x_forwarded_headers & OIDC_HDR_X_FORWARDED_PROTO) && (oidc_http_hdr_in_x_forwarded_proto_get(r)))
		return NULL;

	/*
	 * do the same for the Forwarded: proto= header
	 */
	if ((x_forwarded_headers & OIDC_HDR_FORWARDED) && (oidc_http_hdr_forwarded_get(r, "proto")))
		return NULL;

	/*
	 * if no port was set in the Host header and no X-Forwarded-Proto was set, we'll
	 * determine the port locally and don't print it when it's the default for the protocol
	 */
	const apr_port_t port = r->connection->local_addr->port;
	if ((_oidc_strnatcasecmp(scheme_str, "https") == 0) && port == 443)
		return NULL;
	else if ((_oidc_strnatcasecmp(scheme_str, "http") == 0) && port == 80)
		return NULL;

	port_str = apr_psprintf(r->pool, "%u", port);
	return port_str;
}

/*
 * get the hostname part of the URL that is currently being accessed
 */
const char *oidc_util_url_cur_host(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers) {
	const char *host_str = NULL;
	char *p = NULL;

	if (x_forwarded_headers & OIDC_HDR_FORWARDED)
		host_str = oidc_http_hdr_forwarded_get(r, "host");
	if ((host_str == NULL) && (x_forwarded_headers & OIDC_HDR_X_FORWARDED_HOST))
		host_str = oidc_http_hdr_in_x_forwarded_host_get(r);

	if (host_str == NULL)
		host_str = oidc_http_hdr_in_host_get(r);
	if (host_str) {
		host_str = apr_pstrdup(r->pool, host_str);

		if (host_str[0] == '[') {
			p = strchr(host_str, ']');
			if (p)
				p = strchr(p, OIDC_CHAR_COLON);
		} else {
			p = strchr(host_str, OIDC_CHAR_COLON);
		}

		if (p != NULL)
			*p = '\0';
	} else {
		/* no Host header, HTTP 1.0 */
		host_str = ap_get_server_name(r);
	}

	return host_str;
}

/*
 * get the base part of the current URL (scheme + host (+ port))
 */
static const char *_oidc_util_url_base_cur(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers) {

	const char *scheme_str = NULL;
	const char *host_str = NULL;
	const char *port_str = NULL;

	oidc_cfg_x_forwarded_headers_check(r, x_forwarded_headers);

	scheme_str = _oidc_util_url_cur_scheme(r, x_forwarded_headers);
	host_str = oidc_util_url_cur_host(r, x_forwarded_headers);
	port_str = _oidc_util_url_cur_port(r, scheme_str, x_forwarded_headers);
	port_str = port_str ? apr_psprintf(r->pool, ":%s", port_str) : "";

	char *url = apr_pstrcat(r->pool, scheme_str, "://", host_str, port_str, NULL);

	return url;
}

/*
 * get the URL that is currently being accessed
 */
char *oidc_util_url_cur(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers) {
	char *url = NULL;
	char *path = NULL;
	apr_uri_t uri;

	path = r->uri;

	/* check if we're dealing with a forward proxying secenario i.e. a non-relative URL */
	if ((path) && (path[0] != '/')) {
		_oidc_memset(&uri, 0, sizeof(apr_uri_t));
		if (apr_uri_parse(r->pool, r->uri, &uri) == APR_SUCCESS)
			path = apr_pstrcat(r->pool, uri.path, (r->args != NULL && *r->args != '\0' ? "?" : ""), r->args,
					   NULL);
		else
			oidc_warn(r, "apr_uri_parse failed on non-relative URL: %s", r->uri);
	} else {
		/* make sure we retain URL-encoded characters original URL that we send the user back to */
		path = r->unparsed_uri;
	}

	url = apr_pstrcat(r->pool, _oidc_util_url_base_cur(r, x_forwarded_headers), path, NULL);

	oidc_debug(r, "current URL '%s'", url);

	return url;
}

/*
 * infer a full absolute URL from the (optional) relative one
 */
const char *oidc_util_url_abs(request_rec *r, oidc_cfg_t *cfg, const char *url) {
	if ((url != NULL) && (url[0] == OIDC_CHAR_FORWARD_SLASH)) {
		url = apr_pstrcat(r->pool, _oidc_util_url_base_cur(r, oidc_cfg_x_forwarded_headers_get(cfg)), url,
				  NULL);
		oidc_debug(r, "determined absolute url: %s", url);
	}
	return url;
}

/*
 * check if the request is on a secure HTTPs (TLS) connection
 */
apr_byte_t oidc_util_url_cur_is_secure(request_rec *r, oidc_cfg_t *c) {
	return (_oidc_strnatcasecmp("https", _oidc_util_url_cur_scheme(r, oidc_cfg_x_forwarded_headers_get(c))) ==
		0);
}

/*
 * return absolute Redirect URI
 */
const char *oidc_util_url_redirect_uri(request_rec *r, oidc_cfg_t *cfg) {
	return oidc_util_url_abs(r, cfg, oidc_cfg_redirect_uri_get(cfg));
}

/*
 * see if the currently accessed path matches a path from a defined URL
 */
apr_byte_t oidc_util_url_cur_matches(request_rec *r, const char *url) {
	apr_uri_t uri;
	_oidc_memset(&uri, 0, sizeof(apr_uri_t));
	if ((url == NULL) || (apr_uri_parse(r->pool, url, &uri) != APR_SUCCESS))
		return FALSE;
	oidc_debug(r, "comparing \"%s\"==\"%s\"", r->parsed_uri.path, uri.path);
	if ((r->parsed_uri.path == NULL) || (uri.path == NULL))
		return (r->parsed_uri.path == uri.path);
	return (_oidc_strcmp(r->parsed_uri.path, uri.path) == 0);
}

/*
 * see if the currently accessed path has a certain query parameter
 */
apr_byte_t oidc_util_url_has_parameter(request_rec *r, const char *param) {
	if (r->args == NULL)
		return FALSE;
	const char *option1 = apr_psprintf(r->pool, "%s=", param);
	const char *option2 = apr_psprintf(r->pool, "&%s=", param);
	return ((_oidc_strstr(r->args, option1) == r->args) || (_oidc_strstr(r->args, option2) != NULL)) ? TRUE : FALSE;
}

/*
 * get a query parameter
 */
apr_byte_t oidc_util_url_parameter_get(request_rec *r, char *name, char **value) {
	char *tokenizer_ctx = NULL;
	char *p = NULL;
	char *args = NULL;
	const char *k_param = apr_psprintf(r->pool, "%s=", name);
	const size_t k_param_sz = _oidc_strlen(k_param);

	*value = NULL;

	if (r->args == NULL || _oidc_strlen(r->args) == 0)
		return FALSE;

	/* not sure why we do this, but better be safe than sorry */
	args = apr_pstrmemdup(r->pool, r->args, _oidc_strlen(r->args));

	p = apr_strtok(args, OIDC_STR_AMP, &tokenizer_ctx);
	do {
		if (p && _oidc_strncmp(p, k_param, k_param_sz) == 0) {
			*value = apr_pstrdup(r->pool, p + k_param_sz);
			*value = oidc_http_url_decode(r, *value);
		}
		p = apr_strtok(NULL, OIDC_STR_AMP, &tokenizer_ctx);
	} while (p);

	return (*value != NULL ? TRUE : FALSE);
}
