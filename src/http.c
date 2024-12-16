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
 * Copyright (C) 2017-2024 ZmartZone Holding BV
 * Copyright (C) 2013-2017 Ping Identity Corporation
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

#include <stddef.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include <apr_strings.h>

#include <curl/curl.h>
#include <openssl/opensslv.h>

#include "cfg/dir.h"
#include "const.h"
#include "http.h"
#include "metrics.h"
#include "proto/proto.h"
#include "util.h"

/*
 * URL-encode a string
 */
char *oidc_http_url_encode(const request_rec *r, const char *str) {
	/*
	 * cuRL does not allow us to share the same handle in multiple threads
	 * see: https://curl.se/libcurl/c/threadsafe.html
	 * so we can not not use a global variable here and optimize performance
	 */
	char *rv = "";
	char *result = NULL;
	CURL *curl = NULL;

	if (str == NULL)
		goto end;

	curl = curl_easy_init();
	if (curl == NULL) {
		oidc_error(r, "curl_easy_init() error");
		goto end;
	}

	result = curl_easy_escape(curl, str, 0);
	if (result == NULL) {
		oidc_error(r, "curl_easy_escape() error");
		goto end;
	}

	rv = apr_pstrdup(r->pool, result);

end:

	if (result)
		curl_free(result);
	if (curl)
		curl_easy_cleanup(curl);

	return rv;
}

/*
 * URL-decode a string
 */
char *oidc_http_url_decode(const request_rec *r, const char *str) {
	char *rv = "";
	char *result = NULL;
	CURL *curl = NULL;
	int counter = 0;
	char *replaced = NULL;

	if (str == NULL)
		goto end;

	curl = curl_easy_init();
	if (curl == NULL) {
		oidc_error(r, "curl_easy_init() error");
		goto end;
	}

	replaced = (char *)str;
	while (str[counter] != '\0') {
		if (str[counter] == '+') {
			replaced[counter] = ' ';
		}
		counter++;
	}

	result = curl_easy_unescape(curl, replaced, 0, 0);

	if (result == NULL) {
		oidc_error(r, "curl_easy_unescape() error");
		goto end;
	}

	rv = apr_pstrdup(r->pool, result);

	// oidc_debug(r, "input=\"%s\", output=\"%s\"", str, rv);

end:

	if (result)
		curl_free(result);
	if (curl)
		curl_easy_cleanup(curl);

	return rv;
}

/*
 * obtain a HTTP request header value
 */
static const char *oidc_http_hdr_in_get(const request_rec *r, const char *name) {
	const char *value = apr_table_get(r->headers_in, name);
	if (value)
		oidc_debug(r, "%s=%s", name, value);
	return value;
}

/*
 * obtain the left-most element of a multi-valued HTTP header value
 */
static const char *oidc_http_hdr_in_get_left_most_only(const request_rec *r, const char *name, const char *separator) {
	char *last = NULL;
	const char *value = oidc_http_hdr_in_get(r, name);
	if (value)
		return apr_strtok(apr_pstrdup(r->pool, value), separator, &last);
	return NULL;
}

/*
 * check if a multi-valued HTTP request header contains a specified value
 */
static apr_byte_t oidc_http_hdr_in_contains(const request_rec *r, const char *name, const char *separator,
					    const char postfix_separator, const char *needle) {
	char *ctx = NULL, *elem = NULL;
	const char *value = oidc_http_hdr_in_get(r, name);
	apr_byte_t rc = FALSE;
	if (value) {
		elem = apr_strtok(apr_pstrdup(r->pool, value), separator, &ctx);
		while (elem != NULL) {
			while (*elem == OIDC_CHAR_SPACE)
				elem++;
			if ((_oidc_strncmp(elem, needle, _oidc_strlen(needle)) == 0) &&
			    ((elem[_oidc_strlen(needle)] == '\0') ||
			     (elem[_oidc_strlen(needle)] == postfix_separator))) {
				rc = TRUE;
				break;
			}
			elem = apr_strtok(NULL, separator, &ctx);
		}
	}
	return rc;
}

/*
 * set a HTTP response header; table could be headers_out or err_headers_out
 */
static void oidc_http_hdr_table_set(const request_rec *r, apr_table_t *table, const char *name, const char *value) {

	if (value != NULL) {

		char *s_value = apr_pstrdup(r->pool, value);

		/*
		 * sanitize the header value by replacing line feeds with spaces
		 * just like the Apache header input algorithms do for incoming headers
		 *
		 * this makes it impossible to have line feeds in values but that is
		 * compliant with RFC 7230 (and impossible for regular headers due to Apache's
		 * parsing of headers anyway) and fixes a security vulnerability on
		 * overwriting/setting outgoing headers when used in proxy mode
		 */
		char *p = NULL;
		while ((p = strchr(s_value, '\n')))
			*p = OIDC_CHAR_SPACE;

		oidc_debug(r, "%s: %s", name, s_value);
		apr_table_set(table, name, s_value);

	} else {

		oidc_debug(r, "unset %s", name);
		apr_table_unset(table, name);
	}
}

/*
 * set a (regular) HTTP response header
 */
static void oidc_http_hdr_out_set(const request_rec *r, const char *name, const char *value) {
	oidc_http_hdr_table_set(r, r->headers_out, name, value);
}

/*
 * obtain a HTTP response header value
 */
static const char *oidc_http_hdr_out_get(const request_rec *r, const char *name) {
	return apr_table_get(r->headers_out, name);
}

/*
 * set a HTTP response header on all responses, included errors and redirects
 */
void oidc_http_hdr_err_out_add(const request_rec *r, const char *name, const char *value) {
	oidc_debug(r, "%s: %s", name, value);
	apr_table_add(r->err_headers_out, name, value);
}

/*
 * set an HTTP request header
 */
void oidc_http_hdr_in_set(const request_rec *r, const char *name, const char *value) {
	oidc_http_hdr_table_set(r, r->headers_in, name, value);
}

/*
 * obtain a HTTP request cookie value
 */
const char *oidc_http_hdr_in_cookie_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_COOKIE);
}

/*
 * set a HTTP request cookie value
 */
void oidc_http_hdr_in_cookie_set(const request_rec *r, const char *value) {
	oidc_http_hdr_in_set(r, OIDC_HTTP_HDR_COOKIE, value);
}

/*
 * obtain the User-Agent header value from the HTTP request
 */
const char *oidc_http_hdr_in_user_agent_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_USER_AGENT);
}

/*
 * obtain the X-Forwarded-For header value from the HTTP request
 */
const char *oidc_http_hdr_in_x_forwarded_for_get(const request_rec *r) {
	return oidc_http_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_X_FORWARDED_FOR, OIDC_STR_COMMA OIDC_STR_SPACE);
}

/*
 * obtain the Content-Type header value from the HTTP request
 */
const char *oidc_http_hdr_in_content_type_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_CONTENT_TYPE);
}

/*
 * obtain the Content-Length header value from the HTTP request
 */
const char *oidc_http_hdr_in_content_length_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_CONTENT_LENGTH);
}

/*
 * obtain the X-Requested-With header value from the HTTP request
 */
const char *oidc_http_hdr_in_x_requested_with_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_X_REQUESTED_WITH);
}

/*
 * obtain the Sec-Fetch-Mode header value from the HTTP request
 */
const char *oidc_http_hdr_in_sec_fetch_mode_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_SEC_FETCH_MODE);
}

/*
 * obtain the Sec-Fetch-Dest header value from the HTTP request
 */
const char *oidc_http_hdr_in_sec_fetch_dest_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_SEC_FETCH_DEST);
}

/*
 * obtain the Accept header value from the HTTP request
 */
const char *oidc_http_hdr_in_accept_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_ACCEPT);
}

/*
 * check if a specified value exists in the HTTP Accept request header
 */
apr_byte_t oidc_http_hdr_in_accept_contains(const request_rec *r, const char *needle) {
	return oidc_http_hdr_in_contains(r, OIDC_HTTP_HDR_ACCEPT, OIDC_STR_COMMA, OIDC_CHAR_SEMI_COLON, needle);
}

/*
 * obtain the Authorization header value from the HTTP request
 */
const char *oidc_http_hdr_in_authorization_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_AUTHORIZATION);
}

/*
 * obtain the X-Forwarded-Proto header value from the HTTP request
 */
const char *oidc_http_hdr_in_x_forwarded_proto_get(const request_rec *r) {
	return oidc_http_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_X_FORWARDED_PROTO, OIDC_STR_COMMA OIDC_STR_SPACE);
}

/*
 * obtain the X-Forwarded-Port header value from the HTTP request
 */
const char *oidc_http_hdr_in_x_forwarded_port_get(const request_rec *r) {
	return oidc_http_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_X_FORWARDED_PORT, OIDC_STR_COMMA OIDC_STR_SPACE);
}

/*
 * obtain the X-Forwarded-Host header value from the HTTP request
 */
const char *oidc_http_hdr_in_x_forwarded_host_get(const request_rec *r) {
	return oidc_http_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_X_FORWARDED_HOST, OIDC_STR_COMMA OIDC_STR_SPACE);
}

/*
 * obtain the Forwarded header value from the HTTP request
 */
const char *oidc_http_hdr_in_forwarded_get(const request_rec *r) {
	return oidc_http_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_FORWARDED, OIDC_STR_COMMA);
}

/*
 * obtain the Host header value from the HTTP request
 */
const char *oidc_http_hdr_in_host_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_HOST);
}

/*
 * obtain the traceparent header value from the HTTP request
 */
const char *oidc_http_hdr_in_traceparent_get(const request_rec *r) {
	return oidc_http_hdr_in_get(r, OIDC_HTTP_HDR_TRACE_PARENT);
}

/*
 * set the Location header value in the HTTP response
 */
void oidc_http_hdr_out_location_set(const request_rec *r, const char *value) {
	oidc_http_hdr_out_set(r, OIDC_HTTP_HDR_LOCATION, value);
}

/*
 * obtain the Location header value from the HTTP response
 */
const char *oidc_http_hdr_out_location_get(const request_rec *r) {
	return oidc_http_hdr_out_get(r, OIDC_HTTP_HDR_LOCATION);
}

/*
 * obtain a specified value from the Forwarded header in the HTTP request
 */
const char *oidc_http_hdr_forwarded_get(const request_rec *r, const char *elem) {
	const char *value = NULL;
	char *ptr = NULL;
	const char *item = apr_psprintf(r->pool, "%s=", elem);
	value = oidc_http_hdr_in_forwarded_get(r);
	value = oidc_util_strcasestr(value, item);
	if (value) {
		value += _oidc_strlen(item);
		ptr = _oidc_strstr(value, ";");
		if (ptr)
			*ptr = '\0';
		ptr = _oidc_strstr(value, " ");
		if (ptr)
			*ptr = '\0';
	}
	return value ? apr_pstrdup(r->pool, value) : NULL;
}

/*
 * normalize a string for use as an HTTP Header Name.  Any invalid
 * characters (per http://tools.ietf.org/html/rfc2616#section-4.2 and
 * http://tools.ietf.org/html/rfc2616#section-2.2) are replaced with
 * a dash ('-') character.
 */
char *oidc_http_hdr_normalize_name(const request_rec *r, const char *str) {
	/* token = 1*<any CHAR except CTLs or separators>
	 * CTL = <any US-ASCII control character
	 *          (octets 0 - 31) and DEL (127)>
	 * separators = "(" | ")" | "<" | ">" | "@"
	 *              | "," | ";" | ":" | "\" | <">
	 *              | "/" | "[" | "]" | "?" | "="
	 *              | "{" | "}" | SP | HT */
	const char *separators = "()<>@,;:\\\"/[]?={} \t";

	char *ns = apr_pstrdup(r->pool, str);
	size_t i;
	for (i = 0; i < _oidc_strlen(ns); i++) {
		if (ns[i] < 32 || ns[i] == 127)
			ns[i] = '-';
		else if (strchr(separators, ns[i]) != NULL)
			ns[i] = '-';
	}
	return ns;
}

/* buffer to hold HTTP call responses */
typedef struct oidc_curl_resp_data_ctx_t {
	request_rec *r;
	char *memory;
	size_t size;
} oidc_curl_resp_data_ctx_t;

/* maximum acceptable size of HTTP responses: 10 Mb */
#define OIDC_CURL_RESPONSE_DATA_SIZE_MAX 1024 * 1024 * 10

/*
 * callback for CURL to write bytes that come back from an HTTP call
 */
static size_t oidc_http_response_data(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	oidc_curl_resp_data_ctx_t *mem = (oidc_curl_resp_data_ctx_t *)userp;

	/* check if we don't run over the maximum buffer/memory size for HTTP responses */
	if (mem->size + realsize > OIDC_CURL_RESPONSE_DATA_SIZE_MAX) {
		oidc_error(
		    mem->r,
		    "HTTP response larger than maximum allowed size: current size=%ld, additional size=%ld, max=%d",
		    (long)mem->size, (long)realsize, OIDC_CURL_RESPONSE_DATA_SIZE_MAX);
		return 0;
	}

	/* allocate the new buffer for the current + new response bytes */
	char *newptr = apr_palloc(mem->r->pool, mem->size + realsize + 1);
	if (newptr == NULL) {
		oidc_error(mem->r, "memory allocation for new buffer of %ld bytes failed",
			   (long)(mem->size + realsize + 1));
		return 0;
	}

	/* copy over the data from current memory plus the cURL buffer */
	_oidc_memcpy(newptr, mem->memory, mem->size);
	_oidc_memcpy(&(newptr[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory = newptr;
	mem->memory[mem->size] = 0;

	return realsize;
}

/* buffer to hold HTTP response headers */
typedef struct oidc_curl_resp_hdr_ctx_t {
	request_rec *r;
	apr_hash_t *hdrs;
} oidc_curl_resp_hdr_ctx_t;

/*
 * callback for CURL to write response headers that come back from an HTTP call
 */
static size_t oidc_http_response_header(char *buffer, size_t size, size_t nitems, void *userdata) {
	/* received header is nitems * size long in 'buffer' NOT ZERO TERMINATED */
	oidc_curl_resp_hdr_ctx_t *ctx = (oidc_curl_resp_hdr_ctx_t *)userdata;
	char *hdr = NULL, *value = NULL, *h_name = NULL;
	apr_hash_index_t *hi = NULL;
	apr_ssize_t h_len = 0;
	int i = 0;

	/* see if there is a header to search for */
	if ((ctx->hdrs == NULL) || (apr_hash_count(ctx->hdrs) == 0))
		goto end;

	/* make hdr a \0 terminated string for easier processing */
	hdr = apr_pstrndup(ctx->r->pool, buffer, nitems * size);

	/* search for a name: value pair */
	value = _oidc_strstr(hdr, OIDC_STR_COLON);
	if (value == NULL)
		goto end;

	/* split the header name and value */
	*value = '\0';

	/* see if there's any header value characters at all after the colon */
	if (_oidc_strlen(hdr) < nitems * size) {
		value++;
		/* skip spaces after the colon */
		while (*value == ' ')
			value++;
		/* remove trailing /r/n */
		i = _oidc_strlen(value) - 1;
		while ((value[i] == '\r') || (value[i] == '\n'))
			value[i--] = '\0';
	}

	// TODO: would be faster to use all lowercase keys

	/* check if the caller is interested in the value of the current response header */
	for (hi = apr_hash_first(NULL, ctx->hdrs); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, (const void **)&h_name, &h_len, NULL);
		if (_oidc_strnatcasecmp(hdr, h_name) == 0) {
			oidc_debug(ctx->r, "returning response header: %s: %s", h_name, value);
			apr_hash_set(ctx->hdrs, h_name, APR_HASH_KEY_STRING, apr_pstrdup(ctx->r->pool, value));
			break;
		}
	}

end:

	return nitems * size;
}

/* context structure for encoding parameters */
typedef struct oidc_http_encode_t {
	request_rec *r;
	char *encoded_params;
} oidc_http_encode_t;

/*
 * add a url-form-encoded name/value pair
 */
static int oidc_http_add_form_url_encoded_param(void *rec, const char *key, const char *value) {
	oidc_http_encode_t *ctx = (oidc_http_encode_t *)rec;
	oidc_debug(ctx->r, "processing: %s=%s", key,
		   (_oidc_strncmp(key, OIDC_PROTO_CLIENT_SECRET, _oidc_strlen(OIDC_PROTO_CLIENT_SECRET)) == 0)
		       ? "***"
		       : (value ? value : ""));
	const char *sep = ctx->encoded_params ? OIDC_STR_AMP : "";
	ctx->encoded_params = apr_psprintf(ctx->r->pool, "%s%s%s=%s", ctx->encoded_params ? ctx->encoded_params : "",
					   sep, oidc_http_url_encode(ctx->r, key), oidc_http_url_encode(ctx->r, value));
	return 1;
}

/*
 * construct a URL with query parameters
 */
char *oidc_http_query_encoded_url(request_rec *r, const char *url, const apr_table_t *params) {
	char *result = NULL;
	if (url == NULL) {
		oidc_error(r, "URL is NULL");
		return NULL;
	}
	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		oidc_http_encode_t data = {r, NULL};
		apr_table_do(oidc_http_add_form_url_encoded_param, &data, params, NULL);
		const char *sep = NULL;
		if (data.encoded_params)
			sep = strchr(url, OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP : OIDC_STR_QUERY;
		result = apr_psprintf(r->pool, "%s%s%s", url, sep ? sep : "",
				      data.encoded_params ? data.encoded_params : "");
	} else {
		result = apr_pstrdup(r->pool, url);
	}
	oidc_debug(r, "url=%s", result);
	return result;
}

/*
 * construct form-encoded POST data
 */
char *oidc_http_form_encoded_data(request_rec *r, const apr_table_t *params) {
	char *data = NULL;
	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		oidc_http_encode_t encode_data = {r, NULL};
		apr_table_do(oidc_http_add_form_url_encoded_param, &encode_data, params, NULL);
		data = encode_data.encoded_params;
	}
	oidc_debug(r, "data=%s", data);
	return data;
}

/*
 * call curl_easy_setopt with error checking and reporting
 */
#define OIDC_HTTP_CURL_SETOPT_PARMS(r, curl, code, option, ...)                                                        \
	code = curl_easy_setopt(curl, option, __VA_ARGS__);                                                            \
	if (code != CURLE_OK)                                                                                          \
	oidc_error(r, "curl_easy_setopt(%s) failed with: %s", #option, curl_easy_strerror(code))

#define OIDC_HTTP_CURL_SETOPT(...) OIDC_HTTP_CURL_SETOPT_PARMS(r, curl, code, __VA_ARGS__)

/*
 * set libcurl SSL options
 */

#define OIDC_CURLOPT_SSL_OPTIONS_ENV_VAR_NAME "CURLOPT_SSL_OPTIONS"

#define OIDC_HTTP_CURL_SETOPT_SSL(option, value)                                                                       \
	if (_oidc_strstr(env_var_value, #value) != NULL) {                                                             \
		oidc_debug(r, "curl_easy_setopt(%s): %s (%d)", #option, #value, value);                                \
		OIDC_HTTP_CURL_SETOPT(option, value);                                                                  \
	}

static void oidc_http_set_curl_ssl_options(request_rec *r, CURL *curl) {
	// NB: the variable names r, curl, code and env_var_value are used in the OIDC_HTTP_CURL_SETOPT_SSL macro
	const char *env_var_value = NULL;
	CURLcode code = CURLE_OK;
	if (r->subprocess_env != NULL)
		env_var_value = apr_table_get(r->subprocess_env, OIDC_CURLOPT_SSL_OPTIONS_ENV_VAR_NAME);
	if (env_var_value == NULL)
		return;
	oidc_debug(r, "SSL options environment variable %s=%s found", OIDC_CURLOPT_SSL_OPTIONS_ENV_VAR_NAME,
		   env_var_value);
#if LIBCURL_VERSION_NUM >= 0x071900
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSL_OPTIONS, CURLSSLOPT_ALLOW_BEAST);
#endif
#if LIBCURL_VERSION_NUM >= 0x072c00
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE)
#endif
#if LIBCURL_VERSION_NUM >= 0x074400
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_PARTIALCHAIN)
#endif
#if LIBCURL_VERSION_NUM >= 0x074600
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSL_OPTIONS, CURLSSLOPT_REVOKE_BEST_EFFORT)
#endif
#if LIBCURL_VERSION_NUM >= 0x074700
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA)
#endif
#if LIBCURL_VERSION_NUM >= 0x072200
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0)
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_1)
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2)
#endif
#if LIBCURL_VERSION_NUM >= 0x073400
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3)
#endif
#if LIBCURL_VERSION_NUM >= 0x073600
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSLVERSION, CURL_SSLVERSION_MAX_TLSv1_0)
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSLVERSION, CURL_SSLVERSION_MAX_TLSv1_1)
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSLVERSION, CURL_SSLVERSION_MAX_TLSv1_2)
	OIDC_HTTP_CURL_SETOPT_SSL(CURLOPT_SSLVERSION, CURL_SSLVERSION_MAX_TLSv1_3)
#endif
}

#define OIDC_USER_AGENT_ENV_VAR "OIDC_USER_AGENT"

/*
 * construct our User-Agent header for outgoing requests
 */
static const char *oidc_http_user_agent(request_rec *r) {
	const char *s_useragent = apr_table_get(r->subprocess_env, OIDC_USER_AGENT_ENV_VAR);
	if (s_useragent == NULL) {
		s_useragent = apr_psprintf(r->pool, "[%s:%u:%lu] %s", r->server->server_hostname,
					   r->connection->local_addr->port, (unsigned long)getpid(), NAMEVERSION);
		s_useragent = apr_psprintf(r->pool, "%s libcurl-%s %s", s_useragent, LIBCURL_VERSION,
					   oidc_util_openssl_version(r->pool));
	}
	return s_useragent;
}

#define OIDC_CURL_INTERFACE_ENV_VAR "OIDC_CURL_INTERFACE"

/*
 * construct our local address/interface for outgoing requests
 */
static const char *oidc_http_interface(request_rec *r) {
	return apr_table_get(r->subprocess_env, OIDC_CURL_INTERFACE_ENV_VAR);
}

/*
 * execute a HTTP (GET or POST) request
 */
static apr_byte_t oidc_http_request(request_rec *r, const char *url, const char *data, const char *content_type,
				    const char *basic_auth, const char *access_token, const char *dpop,
				    int ssl_validate_server, char **response, long *response_code,
				    apr_hash_t *response_hdrs, oidc_http_timeout_t *http_timeout,
				    const oidc_http_outgoing_proxy_t *outgoing_proxy,
				    const apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key,
				    const char *ssl_key_pwd) {

	// NB: the variable names r, curl, and code are used in the OIDC_HTTP_CURL_SETOPT macro
	CURL *curl = NULL;
	CURLcode code = CURLE_OK;
	char curl_err[CURL_ERROR_SIZE];
	oidc_curl_resp_data_ctx_t d_buf = {r, NULL, 0};
	oidc_curl_resp_hdr_ctx_t h_buf = {r, response_hdrs};
	struct curl_slist *h_list = NULL;
	int i = 0;
	CURLcode res = CURLE_OK;
	long http_code = 0;
	apr_byte_t rv = FALSE;
	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	/* do some logging about the inputs */
	oidc_debug(r,
		   "url=%s, data=%s, content_type=%s, basic_auth=%s, access_token=%s, dpop=%s, ssl_validate_server=%d, "
		   "request_timeout=%d, connect_timeout=%d, retries=%d, retry_interval=%d, outgoing_proxy=%s:%s:%d, "
		   "pass_cookies=%pp, ssl_cert=%s, ssl_key=%s, ssl_key_pwd=%s",
		   url, data, content_type, basic_auth ? "****" : "null", access_token, dpop, ssl_validate_server,
		   http_timeout->request_timeout, http_timeout->connect_timeout, http_timeout->retries,
		   http_timeout->retry_interval, outgoing_proxy->host_port,
		   outgoing_proxy->username_password ? "****" : "(null)", (int)outgoing_proxy->auth_type, pass_cookies,
		   ssl_cert, ssl_key, ssl_key_pwd ? "****" : "(null)");

	curl = curl_easy_init();
	if (curl == NULL) {
		oidc_error(r, "curl_easy_init() error");
		goto end;
	}

	/* set the error buffer as empty before performing a request */
	curl_err[0] = 0;

	/* some of these are not really required */
	OIDC_HTTP_CURL_SETOPT(CURLOPT_HEADER, 0L);
	OIDC_HTTP_CURL_SETOPT(CURLOPT_NOPROGRESS, 1L);
	OIDC_HTTP_CURL_SETOPT(CURLOPT_NOSIGNAL, 1L);
	OIDC_HTTP_CURL_SETOPT(CURLOPT_ERRORBUFFER, curl_err);
	OIDC_HTTP_CURL_SETOPT(CURLOPT_FOLLOWLOCATION, 1L);
	OIDC_HTTP_CURL_SETOPT(CURLOPT_MAXREDIRS, 5L);

	/* set the timeouts */
	OIDC_HTTP_CURL_SETOPT(CURLOPT_TIMEOUT, http_timeout->request_timeout);
	OIDC_HTTP_CURL_SETOPT(CURLOPT_CONNECTTIMEOUT, http_timeout->connect_timeout);

	/* setup the buffer where the response data will be written to */
	OIDC_HTTP_CURL_SETOPT(CURLOPT_WRITEFUNCTION, oidc_http_response_data);
	// coverity[suspicious_sizeof]
	OIDC_HTTP_CURL_SETOPT(CURLOPT_WRITEDATA, &d_buf);

	/* setup the buffer where the response headers will be written to */
	OIDC_HTTP_CURL_SETOPT(CURLOPT_HEADERFUNCTION, oidc_http_response_header);
	// coverity[suspicious_sizeof]
	OIDC_HTTP_CURL_SETOPT(CURLOPT_HEADERDATA, &h_buf);

#ifndef LIBCURL_NO_CURLPROTO
#if LIBCURL_VERSION_NUM >= 0x075500
	OIDC_HTTP_CURL_SETOPT(CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
	OIDC_HTTP_CURL_SETOPT(CURLOPT_PROTOCOLS_STR, "http,https");
#else
	OIDC_HTTP_CURL_SETOPT(CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
	OIDC_HTTP_CURL_SETOPT(CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
#endif

	/* set the options for validating the SSL server certificate that the remote site presents */
	OIDC_HTTP_CURL_SETOPT(CURLOPT_SSL_VERIFYPEER, (ssl_validate_server != FALSE ? 1L : 0L));
	OIDC_HTTP_CURL_SETOPT(CURLOPT_SSL_VERIFYHOST, (ssl_validate_server != FALSE ? 2L : 0L));

	oidc_http_set_curl_ssl_options(r, curl);

	if (oidc_cfg_ca_bundle_path_get(c) != NULL) {
		OIDC_HTTP_CURL_SETOPT(CURLOPT_CAINFO, oidc_cfg_ca_bundle_path_get(c));
	}

#ifdef WIN32
	else {
		DWORD buflen;
		char *ptr = NULL;
		char *retval = (char *)malloc(sizeof(TCHAR) * (MAX_PATH + 1));
		retval[0] = '\0';
		buflen = SearchPath(NULL, "curl-ca-bundle.crt", NULL, MAX_PATH + 1, retval, &ptr);
		if (buflen > 0) {
			OIDC_HTTP_CURL_SETOPT(CURLOPT_CAINFO, retval);
		} else {
			oidc_warn(r, "no curl-ca-bundle.crt file found in path");
		}
		free(retval);
	}
#endif

	/* identify this HTTP client */
	const char *s_useragent = oidc_http_user_agent(r);
	if ((s_useragent != NULL) && (_oidc_strcmp(s_useragent, "") != 0)) {
		oidc_debug(r, "set HTTP request header User-Agent to: %s", s_useragent);
		OIDC_HTTP_CURL_SETOPT(CURLOPT_USERAGENT, s_useragent);
	}

	/* set the local interface if defined */
	const char *s_interface = oidc_http_interface(r);
	if ((s_interface != NULL) && (_oidc_strcmp(s_interface, "") != 0)) {
#if LIBCURL_VERSION_NUM >= 0x073000
		oidc_debug(r, "set local interface to: %s", s_interface);
		OIDC_HTTP_CURL_SETOPT(CURLOPT_INTERFACE, s_interface);
#else
		oidc_warn(
		    r, "local interface is configured to %s, but the cURL version in use does not support setting this",
		    s_interface);
#endif
	}

	/* set optional outgoing proxy for the local network */
	if (outgoing_proxy->host_port) {
		OIDC_HTTP_CURL_SETOPT(CURLOPT_PROXY, outgoing_proxy->host_port);
		if (outgoing_proxy->username_password) {
			OIDC_HTTP_CURL_SETOPT(CURLOPT_PROXYUSERPWD, outgoing_proxy->username_password);
		}
		if (outgoing_proxy->auth_type != OIDC_CONFIG_POS_INT_UNSET) {
			OIDC_HTTP_CURL_SETOPT(CURLOPT_PROXYAUTH, outgoing_proxy->auth_type);
		}
	}

	/* see if we need to add token in the Bearer/DPoP Authorization header */
	if (access_token != NULL) {
		h_list = curl_slist_append(h_list, apr_psprintf(r->pool, "%s: %s %s", OIDC_HTTP_HDR_AUTHORIZATION,
								dpop ? "DPoP" : "Bearer", access_token));
	}

	/* see if we need to perform HTTP basic authentication to the remote site */
	if (basic_auth != NULL) {
		OIDC_HTTP_CURL_SETOPT(CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		OIDC_HTTP_CURL_SETOPT(CURLOPT_USERPWD, basic_auth);
	}

	if (ssl_cert != NULL) {
		OIDC_HTTP_CURL_SETOPT(CURLOPT_SSLCERT, ssl_cert);
	}
	if (ssl_key != NULL) {
		OIDC_HTTP_CURL_SETOPT(CURLOPT_SSLKEY, ssl_key);
	}
	if (ssl_key_pwd != NULL) {
		OIDC_HTTP_CURL_SETOPT(CURLOPT_KEYPASSWD, ssl_key_pwd);
	}

	if (data != NULL) {
		/* set POST data */
		OIDC_HTTP_CURL_SETOPT(CURLOPT_POSTFIELDS, data);
		/* set HTTP method to POST */
		OIDC_HTTP_CURL_SETOPT(CURLOPT_POST, 1);
	}

	if (content_type != NULL) {
		/* set content type */
		h_list = curl_slist_append(h_list,
					   apr_psprintf(r->pool, "%s: %s", OIDC_HTTP_HDR_CONTENT_TYPE, content_type));
	}

	const char *traceparent = oidc_http_hdr_in_traceparent_get(r);
	if (traceparent && oidc_cfg_trace_parent_get(c) != OIDC_TRACE_PARENT_OFF) {
		oidc_debug(r, "propagating traceparent header: %s", traceparent);
		h_list =
		    curl_slist_append(h_list, apr_psprintf(r->pool, "%s: %s", OIDC_HTTP_HDR_TRACE_PARENT, traceparent));
	}

	if (dpop != NULL) {
		oidc_debug(r, "appending DPoP header (len=%d)", (int)_oidc_strlen(dpop));
		h_list = curl_slist_append(h_list, apr_psprintf(r->pool, "%s: %s", OIDC_HTTP_HDR_DPOP, dpop));
	}

	/* see if we need to add any custom headers */
	if (h_list != NULL) {
		OIDC_HTTP_CURL_SETOPT(CURLOPT_HTTPHEADER, h_list);
	}

	if (pass_cookies != NULL) {
		/* gather cookies that we need to pass on from the incoming request */
		char *cookie_string = NULL;
		for (i = 0; i < pass_cookies->nelts; i++) {
			const char *cookie_name = APR_ARRAY_IDX(pass_cookies, i, const char *);
			char *cookie_value = oidc_http_get_cookie(r, cookie_name);
			if (cookie_value != NULL) {
				cookie_string =
				    (cookie_string == NULL)
					? apr_psprintf(r->pool, "%s=%s", cookie_name, cookie_value)
					: apr_psprintf(r->pool, "%s; %s=%s", cookie_string, cookie_name, cookie_value);
			}
		}

		/* see if we need to pass any cookies */
		if (cookie_string != NULL) {
			oidc_debug(r, "passing browser cookies on backend call: %s", cookie_string);
			OIDC_HTTP_CURL_SETOPT(CURLOPT_COOKIE, cookie_string);
		}
	}

	/* set the target URL */
	OIDC_HTTP_CURL_SETOPT(CURLOPT_URL, url);

	/* call it and record the result */
	for (i = 0; i <= http_timeout->retries; i++) {
		res = curl_easy_perform(curl);
		if (res == CURLE_OK) {
			rv = TRUE;
			break;
		}
		if (res == CURLE_OPERATION_TIMEDOUT) {
			/* in case of a request/transfer timeout (which includes the connect timeout) we'll not
			 * retry */
			oidc_error(r, "curl_easy_perform failed with a timeout for %s: [%s]; won't retry", url,
				   curl_err[0] ? curl_err : "<n/a>");
			OIDC_METRICS_COUNTER_INC_SPEC(r, c, OM_PROVIDER_CONNECT_ERROR,
						      curl_err[0] ? curl_err : "timeout")
			break;
		}
		oidc_error(r, "curl_easy_perform(%d/%d) failed for %s with: [%s]", i + 1, http_timeout->retries + 1,
			   url, curl_err[0] ? curl_err : "<n/a>");
		OIDC_METRICS_COUNTER_INC_SPEC(r, c, OM_PROVIDER_CONNECT_ERROR, curl_err[0] ? curl_err : "undefined")
		/* in case of a connectivity/network glitch we'll back off before retrying */
		if (i < http_timeout->retries)
			apr_sleep(apr_time_from_msec(http_timeout->retry_interval));
	}
	if (rv == FALSE)
		goto end;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	oidc_debug(r, "HTTP response code=%ld", http_code);

	OIDC_METRICS_COUNTER_INC_SPEC(r, c, OM_PROVIDER_HTTP_RESPONSE_CODE, apr_psprintf(r->pool, "%ld", http_code));

	*response = apr_pstrmemdup(r->pool, d_buf.memory, d_buf.size);
	if (response_code)
		*response_code = http_code;

	/* set and log the response */
	oidc_debug(r, "response=%s", *response ? *response : "");

end:

	/* cleanup and return the result */
	if (h_list != NULL)
		curl_slist_free_all(h_list);
	if (curl != NULL)
		curl_easy_cleanup(curl);

	return rv;
}

/*
 * execute HTTP GET request
 */
apr_byte_t oidc_http_get(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth,
			 const char *access_token, const char *dpop, int ssl_validate_server, char **response,
			 long *response_code, apr_hash_t *response_hdrs, oidc_http_timeout_t *http_timeout,
			 const oidc_http_outgoing_proxy_t *outgoing_proxy, const apr_array_header_t *pass_cookies,
			 const char *ssl_cert, const char *ssl_key, const char *ssl_key_pwd) {
	char *query_url = oidc_http_query_encoded_url(r, url, params);
	return oidc_http_request(r, query_url, NULL, NULL, basic_auth, access_token, dpop, ssl_validate_server,
				 response, response_code, response_hdrs, http_timeout, outgoing_proxy, pass_cookies,
				 ssl_cert, ssl_key, ssl_key_pwd);
}

/*
 * execute HTTP POST request with form-encoded data
 */
apr_byte_t oidc_http_post_form(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth,
			       const char *access_token, const char *dpop, int ssl_validate_server, char **response,
			       long *response_code, apr_hash_t *response_hdrs, oidc_http_timeout_t *http_timeout,
			       const oidc_http_outgoing_proxy_t *outgoing_proxy, const apr_array_header_t *pass_cookies,
			       const char *ssl_cert, const char *ssl_key, const char *ssl_key_pwd) {
	char *data = oidc_http_form_encoded_data(r, params);
	return oidc_http_request(r, url, data, OIDC_HTTP_CONTENT_TYPE_FORM_ENCODED, basic_auth, access_token, dpop,
				 ssl_validate_server, response, response_code, response_hdrs, http_timeout,
				 outgoing_proxy, pass_cookies, ssl_cert, ssl_key, ssl_key_pwd);
}

/*
 * execute HTTP POST request with JSON-encoded data
 */
apr_byte_t oidc_http_post_json(request_rec *r, const char *url, json_t *json, const char *basic_auth,
			       const char *access_token, const char *dpop, int ssl_validate_server, char **response,
			       long *response_code, apr_hash_t *response_hdrs, oidc_http_timeout_t *http_timeout,
			       const oidc_http_outgoing_proxy_t *outgoing_proxy, const apr_array_header_t *pass_cookies,
			       const char *ssl_cert, const char *ssl_key, const char *ssl_key_pwd) {
	char *data = json != NULL ? oidc_util_encode_json(r->pool, json, JSON_PRESERVE_ORDER | JSON_COMPACT) : NULL;
	return oidc_http_request(r, url, data, OIDC_HTTP_CONTENT_TYPE_JSON, basic_auth, access_token, dpop,
				 ssl_validate_server, response, response_code, response_hdrs, http_timeout,
				 outgoing_proxy, pass_cookies, ssl_cert, ssl_key, ssl_key_pwd);
}

/*
 * get the current path from the request in a normalized way
 */
static char *oidc_http_get_path(request_rec *r) {
	size_t i;
	char *p;
	p = r->parsed_uri.path;
	if ((p == NULL) || (p[0] == '\0'))
		return apr_pstrdup(r->pool, OIDC_STR_FORWARD_SLASH);
	for (i = _oidc_strlen(p) - 1; i > 0; i--)
		if (p[i] == OIDC_CHAR_FORWARD_SLASH)
			break;
	return apr_pstrndup(r->pool, p, i + 1);
}

/*
 * get the cookie path setting and check that it matches the request path; cook it up if it is not set
 */
static const char *oidc_http_get_cookie_path(request_rec *r) {
	const char *rv = NULL;
	char *requestPath = oidc_http_get_path(r);
	const char *cookie_path = oidc_cfg_dir_cookie_path_get(r);
	if (cookie_path != NULL) {
		if (_oidc_strncmp(cookie_path, requestPath, _oidc_strlen(cookie_path)) == 0)
			rv = cookie_path;
		else {
			oidc_warn(r,
				  "" OIDCCookiePath
				  " (%s) is not a substring of request path, using request path (%s) for cookie",
				  cookie_path, requestPath);
			rv = requestPath;
		}
	} else {
		rv = requestPath;
	}
	return rv;
}

#define OIDC_HTTP_COOKIE_FLAG_DOMAIN "Domain"
#define OIDC_HTTP_COOKIE_FLAG_PATH "Path"
#define OIDC_HTTP_COOKIE_FLAG_EXPIRES "Expires"
#define OIDC_HTTP_COOKIE_FLAG_SECURE "Secure"
#define OIDC_HTTP_COOKIE_FLAG_HTTP_ONLY "HttpOnly"

#define OIDC_HTTP_COOKIE_MAX_SIZE 4093

#define OIDC_SET_COOKIE_APPEND_ENV_VAR "OIDC_SET_COOKIE_APPEND"

/*
 * obtain the value configured in the OIDC_SET_COOKIE_APPEND environment variable
 * which is to be added to the HTTP Set-Cookie response header
 */
static const char *oidc_http_set_cookie_append_value(request_rec *r) {
	const char *env_var_value = NULL;

	if (r->subprocess_env != NULL)
		env_var_value = apr_table_get(r->subprocess_env, OIDC_SET_COOKIE_APPEND_ENV_VAR);

	if (env_var_value == NULL) {
		oidc_debug(r, "no cookie append environment variable %s found", OIDC_SET_COOKIE_APPEND_ENV_VAR);
		return NULL;
	}

	oidc_debug(r, "cookie append environment variable %s=%s found", OIDC_SET_COOKIE_APPEND_ENV_VAR, env_var_value);

	return env_var_value;
}

/*
 * set a cookie in the HTTP response headers
 */
void oidc_http_set_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires,
			  const char *ext) {

	oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	char *headerString = NULL;
	char *expiresString = NULL;
	const char *appendString = NULL;

	/* see if we need to clear the cookie */
	if (_oidc_strcmp(cookieValue, "") == 0)
		expires = 0;

	/* construct the expire value */
	if (expires != -1) {
		expiresString = (char *)apr_pcalloc(r->pool, APR_RFC822_DATE_LEN);
		if (apr_rfc822_date(expiresString, expires) != APR_SUCCESS) {
			oidc_error(r, "could not set cookie expiry date");
		}
	}

	/* construct the cookie value */
	headerString = apr_psprintf(r->pool, "%s=%s", cookieName, cookieValue);

	headerString =
	    apr_psprintf(r->pool, "%s; %s=%s", headerString, OIDC_HTTP_COOKIE_FLAG_PATH, oidc_http_get_cookie_path(r));

	if (expiresString != NULL)
		headerString =
		    apr_psprintf(r->pool, "%s; %s=%s", headerString, OIDC_HTTP_COOKIE_FLAG_EXPIRES, expiresString);

	if (oidc_cfg_cookie_domain_get(c) != NULL)
		headerString = apr_psprintf(r->pool, "%s; %s=%s", headerString, OIDC_HTTP_COOKIE_FLAG_DOMAIN,
					    oidc_cfg_cookie_domain_get(c));

	if (oidc_util_request_is_secure(r, c))
		headerString = apr_psprintf(r->pool, "%s; %s", headerString, OIDC_HTTP_COOKIE_FLAG_SECURE);

	if (oidc_cfg_cookie_http_only_get(c) != FALSE)
		headerString = apr_psprintf(r->pool, "%s; %s", headerString, OIDC_HTTP_COOKIE_FLAG_HTTP_ONLY);

	appendString = oidc_http_set_cookie_append_value(r);
	if (appendString != NULL)
		headerString = apr_psprintf(r->pool, "%s; %s", headerString, appendString);
	else if (ext != NULL)
		headerString = apr_psprintf(r->pool, "%s; %s", headerString, ext);

	/* sanity check on overall cookie value size */
	if (_oidc_strlen(headerString) > OIDC_HTTP_COOKIE_MAX_SIZE) {
		oidc_warn(r,
			  "the length of the cookie value (%d) is greater than %d(!) bytes, this may not work "
			  "with all browsers/server combinations: consider switching to a server side caching!",
			  (int)_oidc_strlen(headerString), OIDC_HTTP_COOKIE_MAX_SIZE);
	}

	/* use r->err_headers_out so we always print our headers (even on 302 redirect) - headers_out only
	 * prints on 2xx responses */
	oidc_http_hdr_err_out_add(r, OIDC_HTTP_HDR_SET_COOKIE, headerString);
}

/*
 * get a cookie from the HTTP request
 */
char *oidc_http_get_cookie(request_rec *r, const char *cookieName) {
	char *cookie = NULL;
	char *tokenizerCtx = NULL;
	char *rv = NULL;

	/* get the Cookie value */
	char *cookies = apr_pstrdup(r->pool, oidc_http_hdr_in_cookie_get(r));

	if (cookies != NULL) {

		/* tokenize on ; to find the cookie we want */
		cookie = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &tokenizerCtx);

		while (cookie != NULL) {

			while (*cookie == OIDC_CHAR_SPACE)
				cookie++;

			/* see if we've found the cookie that we're looking for */
			if ((_oidc_strncmp(cookie, cookieName, _oidc_strlen(cookieName)) == 0) &&
			    (cookie[_oidc_strlen(cookieName)] == OIDC_CHAR_EQUAL)) {

				/* skip to the meat of the parameter (the value after the '=') */
				cookie += (_oidc_strlen(cookieName) + 1);
				rv = apr_pstrdup(r->pool, cookie);

				break;
			}

			/* go to the next cookie */
			cookie = apr_strtok(NULL, OIDC_STR_SEMI_COLON, &tokenizerCtx);
		}
	}

	/* log what we've found */
	oidc_debug(r, "returning \"%s\" = %s", cookieName, rv ? apr_psprintf(r->pool, "\"%s\"", rv) : "<null>");

	return rv;
}

#define OIDC_HTTP_COOKIE_CHUNKS_SEPARATOR "_"
#define OIDC_HTTP_COOKIE_CHUNKS_POSTFIX "chunks"

/*
 * get the name of the cookie that contains the number of chunks
 */
static char *oidc_http_get_chunk_count_name(request_rec *r, const char *cookieName) {
	return apr_psprintf(r->pool, "%s%s%s", cookieName, OIDC_HTTP_COOKIE_CHUNKS_SEPARATOR,
			    OIDC_HTTP_COOKIE_CHUNKS_POSTFIX);
}

/*
 * get the number of cookie chunks set by the browser
 */
static int oidc_http_get_chunked_count(request_rec *r, const char *cookieName) {
	int chunkCount = 0;
	char *chunkCountValue = oidc_http_get_cookie(r, oidc_http_get_chunk_count_name(r, cookieName));
	chunkCount = _oidc_str_to_int(chunkCountValue, 0);
	return chunkCount;
}

/*
 * get the name of a chunk
 */
static char *oidc_http_get_chunk_cookie_name(request_rec *r, const char *cookieName, int i) {
	return apr_psprintf(r->pool, "%s%s%d", cookieName, OIDC_HTTP_COOKIE_CHUNKS_SEPARATOR, i);
}

/*
 * get a cookie value that is split over a number of chunked cookies
 */
char *oidc_http_get_chunked_cookie(request_rec *r, const char *cookieName, int chunkSize) {
	char *cookieValue = NULL, *chunkValue = NULL;
	int chunkCount = 0, i = 0;
	if (chunkSize == 0)
		return oidc_http_get_cookie(r, cookieName);
	chunkCount = oidc_http_get_chunked_count(r, cookieName);
	if (chunkCount == 0)
		return oidc_http_get_cookie(r, cookieName);
	if ((chunkCount < 0) || (chunkCount > 99)) {
		oidc_warn(r, "chunk count out of bounds: %d", chunkCount);
		return NULL;
	}
	for (i = 0; i < chunkCount; i++) {
		chunkValue = oidc_http_get_cookie(r, oidc_http_get_chunk_cookie_name(r, cookieName, i));
		if (chunkValue == NULL) {
			oidc_warn(r, "could not find chunk %d; aborting", i);
			break;
		}
		cookieValue = apr_psprintf(r->pool, "%s%s", cookieValue ? cookieValue : "", chunkValue);
	}
	return cookieValue;
}

/*
 * unset all chunked cookies, including the counter cookie, if they exist
 */
static void oidc_http_clear_chunked_cookie(request_rec *r, const char *cookieName, apr_time_t expires,
					   const char *ext) {
	int i = 0;
	int chunkCount = oidc_http_get_chunked_count(r, cookieName);
	if (chunkCount > 0) {
		for (i = 0; i < chunkCount; i++)
			oidc_http_set_cookie(r, oidc_http_get_chunk_cookie_name(r, cookieName, i), "", expires, ext);
		oidc_http_set_cookie(r, oidc_http_get_chunk_count_name(r, cookieName), "", expires, ext);
	}
}

/*
 * set a cookie value that is split over a number of chunked cookies
 */
void oidc_http_set_chunked_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires,
				  int chunkSize, const char *ext) {
	int i = 0;
	int cookieLength = _oidc_strlen(cookieValue);
	char *chunkValue = NULL;

	/* see if we need to chunk at all */
	if ((chunkSize == 0) || ((cookieLength > 0) && (cookieLength < chunkSize))) {
		oidc_http_set_cookie(r, cookieName, cookieValue, expires, ext);
		oidc_http_clear_chunked_cookie(r, cookieName, expires, ext);
		return;
	}

	/* see if we need to clear a possibly chunked cookie */
	if (cookieLength == 0) {
		oidc_http_set_cookie(r, cookieName, "", expires, ext);
		oidc_http_clear_chunked_cookie(r, cookieName, expires, ext);
		return;
	}

	/* set a chunked cookie */
	int chunkCountValue = cookieLength / chunkSize + 1;
	const char *ptr = cookieValue;
	for (i = 0; i < chunkCountValue; i++) {
		chunkValue = apr_pstrndup(r->pool, ptr, chunkSize);
		ptr += chunkSize;
		oidc_http_set_cookie(r, oidc_http_get_chunk_cookie_name(r, cookieName, i), chunkValue, expires, ext);
	}
	oidc_http_set_cookie(r, oidc_http_get_chunk_count_name(r, cookieName),
			     apr_psprintf(r->pool, "%d", chunkCountValue), expires, ext);
	oidc_http_set_cookie(r, cookieName, "", expires, ext);
}

/*
 * construct the HTTP outgoing proxy options
 */
const char **oidc_http_proxy_auth_options(void) {
	static const char *options[] = {OIDC_HTTP_PROXY_AUTH_BASIC,
					OIDC_HTTP_PROXY_AUTH_DIGEST,
					OIDC_HTTP_PROXY_AUTH_NTLM,
					OIDC_HTTP_PROXY_AUTH_ANY,
#ifdef CURLAUTH_NEGOTIATE
					OIDC_HTTP_PROXY_AUTH_NEGOTIATE,
#endif
					NULL};
	return options;
}

/*
 * return the CURL enum value for the HTTP outgoing proxy options
 */
unsigned long oidc_http_proxy_s2auth(const char *arg) {
	if (_oidc_strcmp(arg, OIDC_HTTP_PROXY_AUTH_BASIC) == 0)
		return CURLAUTH_BASIC;
	if (_oidc_strcmp(arg, OIDC_HTTP_PROXY_AUTH_DIGEST) == 0)
		return CURLAUTH_DIGEST;
	if (_oidc_strcmp(arg, OIDC_HTTP_PROXY_AUTH_NTLM) == 0)
		return CURLAUTH_NTLM;
	if (_oidc_strcmp(arg, OIDC_HTTP_PROXY_AUTH_ANY) == 0)
		return CURLAUTH_ANY;
#ifdef CURLAUTH_NEGOTIATE
	if (_oidc_strcmp(arg, OIDC_HTTP_PROXY_AUTH_NEGOTIATE) == 0)
		return CURLAUTH_NEGOTIATE;
#endif
	return CURLAUTH_NONE;
}

/*
 * initialize the HTTP/cURL environment
 */
void oidc_http_init(void) {
	curl_global_init(CURL_GLOBAL_ALL);
}

/*
 * clean up the HTTP/cURL environment
 */
void oidc_http_cleanup(void) {
	curl_global_cleanup();
}
