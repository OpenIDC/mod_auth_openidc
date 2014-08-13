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
 * Copyright (C) 2013-2014 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include "http_protocol.h"

#include <curl/curl.h>

#include "mod_auth_openidc.h"

/* hrm, should we get rid of this by adding parameters to the (3) functions? */
extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/*
 * base64url encode a string
 */
int oidc_base64url_encode(request_rec *r, char **dst, const char *src,
		int src_len, int remove_padding) {
	if ((src == NULL) || (src_len <= 0)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_base64url_encode: not encoding anything; src=NULL and/or src_len<1");
		return -1;
	}
	int enc_len = apr_base64_encode_len(src_len);
	char *enc = apr_palloc(r->pool, enc_len);
	apr_base64_encode(enc, (const char *) src, src_len);
	int i = 0;
	while (enc[i] != '\0') {
		if (enc[i] == '+')
			enc[i] = '-';
		if (enc[i] == '/')
			enc[i] = '_';
		if (enc[i] == '=')
			enc[i] = ',';
		i++;
	}
	if (remove_padding) {
		/* remove /0 and padding */
		enc_len--;
		if (enc[enc_len - 1] == ',')
			enc_len--;
		if (enc[enc_len - 1] == ',')
			enc_len--;
		enc[enc_len] = '\0';
	}
	*dst = enc;
	return enc_len;
}

/*
 * base64url decode a string
 */
int oidc_base64url_decode(request_rec *r, char **dst, const char *src,
		int add_padding) {
	if (src == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_base64url_decode: not decoding anything; src=NULL");
		return -1;
	}
	char *dec = apr_pstrdup(r->pool, src);
	int i = 0;
	while (dec[i] != '\0') {
		if (dec[i] == '-')
			dec[i] = '+';
		if (dec[i] == '_')
			dec[i] = '/';
		if (dec[i] == ',')
			dec[i] = '=';
		i++;
	}
	if (add_padding == 1) {
		switch (strlen(dec) % 4) {
		case 0:
			break;
		case 2:
			dec = apr_pstrcat(r->pool, dec, "==", NULL);
			break;
		case 3:
			dec = apr_pstrcat(r->pool, dec, "=", NULL);
			break;
		default:
			return 0;
		}
	}
	int dlen = apr_base64_decode_len(dec);
	*dst = apr_palloc(r->pool, dlen);
	return apr_base64_decode(*dst, dec);
}

/*
 * encrypt and base64url encode a string
 */
int oidc_encrypt_base64url_encode_string(request_rec *r, char **dst,
		const char *src) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	int crypted_len = strlen(src) + 1;
	unsigned char *crypted = oidc_crypto_aes_encrypt(r, c,
			(unsigned char *) src, &crypted_len);
	if (crypted == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_encrypt_base64url_encode_string: oidc_crypto_aes_encrypt failed");
		return -1;
	}
	return oidc_base64url_encode(r, dst, (const char *) crypted, crypted_len, 1);
}

/*
 * decrypt and base64url decode a string
 */
int oidc_base64url_decode_decrypt_string(request_rec *r, char **dst,
		const char *src) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	char *decbuf = NULL;
	int dec_len = oidc_base64url_decode(r, &decbuf, src, 1);
	if (dec_len <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_base64url_decode_decrypt_string: oidc_base64url_decode failed");
		return -1;
	}
	*dst = (char *) oidc_crypto_aes_decrypt(r, c, (unsigned char *) decbuf,
			&dec_len);
	if (*dst == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_base64url_decode_decrypt_string: oidc_crypto_aes_decrypt failed");
		return -1;
	}
	return dec_len;
}

/*
 * convert a character to an ENVIRONMENT-variable-safe variant
 */
int oidc_char_to_env(int c) {
	return apr_isalnum(c) ? apr_toupper(c) : '_';
}

/*
 * compare two strings based on how they would be converted to an
 * environment variable, as per oidc_char_to_env. If len is specified
 * as less than zero, then the full strings will be compared. Returns
 * less than, equal to, or greater than zero based on whether the
 * first argument's conversion to an environment variable is less
 * than, equal to, or greater than the second.
 */
int oidc_strnenvcmp(const char *a, const char *b, int len) {
	int d, i = 0;
	while (1) {
		/* If len < 0 then we don't stop based on length */
		if (len >= 0 && i >= len)
			return 0;

		/* If we're at the end of both strings, they're equal */
		if (!*a && !*b)
			return 0;

		/* If the second string is shorter, pick it: */
		if (*a && !*b)
			return 1;

		/* If the first string is shorter, pick it: */
		if (!*a && *b)
			return -1;

		/* Normalize the characters as for conversion to an
		 * environment variable. */
		d = oidc_char_to_env(*a) - oidc_char_to_env(*b);
		if (d)
			return d;

		a++;
		b++;
		i++;
	}
	return 0;
}

/*
 * escape a string
 */
char *oidc_util_escape_string(const request_rec *r, const char *str) {
	CURL *curl = curl_easy_init();
	if (curl == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_escape_string: curl_easy_init() error");
		return NULL;
	}
	char *result = curl_easy_escape(curl, str, 0);
	if (result == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_escape_string: curl_easy_escape() error");
		return NULL;
	}
	char *rv = apr_pstrdup(r->pool, result);
	curl_free(result);
	curl_easy_cleanup(curl);
	return rv;
}

/*
 * escape a string
 */
char *oidc_util_unescape_string(const request_rec *r, const char *str) {
	CURL *curl = curl_easy_init();
	if (curl == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_unescape_string: curl_easy_init() error");
		return NULL;
	}
	char *result = curl_easy_unescape(curl, str, 0, 0);
	if (result == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_unescape_string: curl_easy_unescape() error");
		return NULL;
	}
	char *rv = apr_pstrdup(r->pool, result);
	curl_free(result);
	curl_easy_cleanup(curl);
	//ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_util_unescape_string: input=\"%s\", output=\"%s\"", str, rv);
	return rv;
}

/*
 * get the URL scheme that is currently being accessed
 */
static const char *oidc_get_current_url_scheme(const request_rec *r) {
	/* first see if there's a proxy/load-balancer in front of us */
	const char *scheme_str = apr_table_get(r->headers_in, "X-Forwarded-Proto");
	/* if not we'll determine the scheme used to connect to this server */
	if (scheme_str == NULL) {
#ifdef APACHE2_0
		scheme_str = (char *) ap_http_method(r);
#else
		scheme_str = (char *) ap_http_scheme(r);
#endif
	}
	return scheme_str;
}

/*
 * get the URL port that is currently being accessed
 */
static const char *oidc_get_current_url_port(const request_rec *r,
		const oidc_cfg *c, const char *scheme_str) {
	/* first see if there's a proxy/load-balancer in front of us */
	const char *port_str = apr_table_get(r->headers_in, "X-Forwarded-Port");
	if (port_str == NULL) {
		/* if not we'll take the port from the Host header (as set by the client or ProxyPreserveHost) */
		const char *host_hdr = apr_table_get(r->headers_in, "Host");
		port_str = strchr(host_hdr, ':');
		if (port_str == NULL) {
			/* if no port was set in the Host header we'll determine it locally */
			const apr_port_t port = r->connection->local_addr->port;
			apr_byte_t print_port = TRUE;
			if ((apr_strnatcmp(scheme_str, "https") == 0) && port == 443)
				print_port = FALSE;
			else if ((apr_strnatcmp(scheme_str, "http") == 0) && port == 80)
				print_port = FALSE;
			if (print_port)
				port_str = apr_psprintf(r->pool, "%u", port);
		} else {
			port_str++;
		}
	}
	return port_str;
}

/*
 * get the URL that is currently being accessed
 */
char *oidc_get_current_url(const request_rec *r, const oidc_cfg *c) {

	const char *scheme_str = oidc_get_current_url_scheme(r);

	const char *port_str = oidc_get_current_url_port(r, c, scheme_str);
	port_str = port_str ? apr_psprintf(r->pool, ":%s", port_str) : "";

	const char *host_str = apr_table_get(r->headers_in, "Host");
	char *p = strchr(host_str, ':');
	if (p != NULL)
		*p = '\0';

	char *url = apr_pstrcat(r->pool, scheme_str, "://", host_str, port_str,
			r->uri, (r->args != NULL && *r->args != '\0' ? "?" : ""), r->args,
			NULL);

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_get_current_url: current URL '%s'", url);

	return url;
}

/* maximum size of any response returned in HTTP calls */
#define OIDC_CURL_MAX_RESPONSE_SIZE 65536

/* buffer to hold HTTP call responses */
typedef struct oidc_curl_buffer {
	char buf[OIDC_CURL_MAX_RESPONSE_SIZE];
	size_t written;
} oidc_curl_buffer;

/*
 * callback for CURL to write bytes that come back from an HTTP call
 */
size_t oidc_curl_write(const void *ptr, size_t size, size_t nmemb, void *stream) {
	oidc_curl_buffer *curlBuffer = (oidc_curl_buffer *) stream;

	if ((nmemb * size) + curlBuffer->written >= OIDC_CURL_MAX_RESPONSE_SIZE)
		return 0;

	memcpy((curlBuffer->buf + curlBuffer->written), ptr, (nmemb * size));
	curlBuffer->written += (nmemb * size);

	return (nmemb * size);
}

/* context structure for encoding parameters */
typedef struct oidc_http_encode_t {
	request_rec *r;
	const char *encoded_params;
} oidc_http_encode_t;

/*
 * add a url-form-encoded name/value pair
 */
static int oidc_http_add_form_url_encoded_param(void* rec, const char* key,
		const char* value) {
	oidc_http_encode_t *ctx = (oidc_http_encode_t*) rec;
	const char *sep = apr_strnatcmp(ctx->encoded_params, "") == 0 ? "" : "&";
	ctx->encoded_params = apr_psprintf(ctx->r->pool, "%s%s%s=%s",
			ctx->encoded_params, sep, oidc_util_escape_string(ctx->r, key),
			oidc_util_escape_string(ctx->r, value));
	return 1;
}

/*
 * execute a HTTP (GET or POST) request
 */
static apr_byte_t oidc_util_http_call(request_rec *r, const char *url,
		const char *data, const char *content_type, const char *basic_auth,
		const char *bearer_token, int ssl_validate_server,
		const char **response, int timeout, const char *outgoing_proxy) {
	char curlError[CURL_ERROR_SIZE];
	oidc_curl_buffer curlBuffer;
	CURL *curl;
	struct curl_slist *h_list = NULL;

	/* do some logging about the inputs */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_util_http_call: url=%s, data=%s, content_type=%s, basic_auth=%s, bearer_token=%s, ssl_validate_server=%d",
			url, data, content_type, basic_auth, bearer_token,
			ssl_validate_server);

	curl = curl_easy_init();
	if (curl == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_http_call: curl_easy_init() error");
		return FALSE;
	}

	/* some of these are not really required */
	curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlError);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

	/* set the timeout */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

	/* setup the buffer where the response will be written to */
	curlBuffer.written = 0;
	memset(curlBuffer.buf, '\0', sizeof(curlBuffer.buf));
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curlBuffer);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oidc_curl_write);

#ifndef LIBCURL_NO_CURLPROTO
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
			CURLPROTO_HTTP|CURLPROTO_HTTPS);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);
#endif

	/* set the options for validating the SSL server certificate that the remote site presents */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
			(ssl_validate_server != FALSE ? 1L : 0L));
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
			(ssl_validate_server != FALSE ? 2L : 0L));

	/* identify this HTTP client */
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "mod_auth_openidc");

	/* set optional outgoing proxy for the local network */
	if (outgoing_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, outgoing_proxy);
	}

	/* see if we need to add token in the Bearer Authorization header */
	if (bearer_token != NULL) {
		h_list = curl_slist_append(h_list,
				apr_psprintf(r->pool, "Authorization: Bearer %s",
						bearer_token));
	}

	/* see if we need to perform HTTP basic authentication to the remote site */
	if (basic_auth != NULL) {
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_easy_setopt(curl, CURLOPT_USERPWD, basic_auth);
	}

	if (data != NULL) {
		/* set POST data */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		/* set HTTP method to POST */
		curl_easy_setopt(curl, CURLOPT_POST, 1);
	}

	if (content_type != NULL) {
		/* set content type */
		h_list = curl_slist_append(h_list,
				apr_psprintf(r->pool, "Content-type: %s", content_type));
	}

	/* see if we need to add any custom headers */
	if (h_list != NULL)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, h_list);

	/* set the target URL */
	curl_easy_setopt(curl, CURLOPT_URL, url);

	/* call it and record the result */
	int rv = TRUE;
	if (curl_easy_perform(curl) != CURLE_OK) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_http_call: curl_easy_perform() failed on: %s (%s)",
				url, curlError);
		rv = FALSE;
		goto out;
	}

	*response = apr_pstrndup(r->pool, curlBuffer.buf, curlBuffer.written);

	/* set and log the response */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_util_http_call: response=%s", *response);

	out:

	/* cleanup and return the result */
	if (h_list != NULL)
		curl_slist_free_all(h_list);
	curl_easy_cleanup(curl);

	return rv;
}

/*
 * execute HTTP GET request
 */
apr_byte_t oidc_util_http_get(request_rec *r, const char *url,
		const apr_table_t *params, const char *basic_auth,
		const char *bearer_token, int ssl_validate_server,
		const char **response, int timeout, const char *outgoing_proxy) {

	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		oidc_http_encode_t data = { r, "" };
		apr_table_do(oidc_http_add_form_url_encoded_param, &data, params, NULL);
		const char *sep = strchr(url, '?') != NULL ? "&" : "?";
		url = apr_psprintf(r->pool, "%s%s%s", url, sep, data.encoded_params);
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_util_http_get: get URL=\"%s\"", url);
	}

	return oidc_util_http_call(r, url, NULL, NULL, basic_auth, bearer_token,
			ssl_validate_server, response, timeout, outgoing_proxy);
}

/*
 * execute HTTP POST request with form-encoded data
 */
apr_byte_t oidc_util_http_post_form(request_rec *r, const char *url,
		const apr_table_t *params, const char *basic_auth,
		const char *bearer_token, int ssl_validate_server,
		const char **response, int timeout, const char *outgoing_proxy) {

	const char *data = NULL;
	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		oidc_http_encode_t encode_data = { r, "" };
		apr_table_do(oidc_http_add_form_url_encoded_param, &encode_data, params,
				NULL);
		data = encode_data.encoded_params;
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_util_http_post_form: post data=\"%s\"", data);
	}

	return oidc_util_http_call(r, url, data,
			"application/x-www-form-urlencoded", basic_auth, bearer_token,
			ssl_validate_server, response, timeout, outgoing_proxy);
}

/*
 * execute HTTP POST request with JSON-encoded data
 */
apr_byte_t oidc_util_http_post_json(request_rec *r, const char *url,
		const json_t *json, const char *basic_auth, const char *bearer_token,
		int ssl_validate_server, const char **response, int timeout,
		const char *outgoing_proxy) {

	char *data = NULL;
	if (json != NULL) {
		char *s_value = json_dumps(json, 0);
		data = apr_pstrdup(r->pool, s_value);
		free(s_value);
	}

	return oidc_util_http_call(r, url, data, "application/json", basic_auth,
			bearer_token, ssl_validate_server, response, timeout,
			outgoing_proxy);
}

/*
 * get the current path from the request in a normalized way
 */
static char *oidc_util_get_path(request_rec *r) {
	size_t i;
	char *p;
	p = r->parsed_uri.path;
	if (p[0] == '\0')
		return apr_pstrdup(r->pool, "/");
	for (i = strlen(p) - 1; i > 0; i--)
		if (p[i] == '/')
			break;
	return apr_pstrndup(r->pool, p, i + 1);
}

/*
 * get the cookie path setting and check that it matches the request path; cook it up if it is not set
 */
static char *oidc_util_get_cookie_path(request_rec *r) {
	char *rv = NULL, *requestPath = oidc_util_get_path(r);
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (d->cookie_path != NULL) {
		if (strncmp(d->cookie_path, requestPath, strlen(d->cookie_path)) == 0)
			rv = d->cookie_path;
		else {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_util_get_cookie_path: OIDCCookiePath (%s) not a substring of request path, using request path (%s) for cookie",
					d->cookie_path, requestPath);
			rv = requestPath;
		}
	} else {
		rv = requestPath;
	}
	return (rv);
}

/*
 * set a cookie in the HTTP response headers
 */
void oidc_util_set_cookie(request_rec *r, const char *cookieName,
		const char *cookieValue) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	char *headerString, *currentCookies;
	/* construct the cookie value */
	headerString = apr_psprintf(r->pool, "%s=%s;%s;Path=%s%s", cookieName,
			cookieValue,
			((apr_strnatcasecmp("https", oidc_get_current_url_scheme(r)) == 0) ?
					";Secure" : ""), oidc_util_get_cookie_path(r),
			c->cookie_domain != NULL ?
					apr_psprintf(r->pool, ";Domain=%s", c->cookie_domain) : "");

	/* see if we need to clear the cookie */
	if (apr_strnatcmp(cookieValue, "") == 0)
		headerString = apr_psprintf(r->pool, "%s;expires=0;Max-Age=0",
				headerString);

	/* use r->err_headers_out so we always print our headers (even on 302 redirect) - headers_out only prints on 2xx responses */
	apr_table_add(r->err_headers_out, "Set-Cookie", headerString);

	/* see if we need to add it to existing cookies */
	if ((currentCookies = (char *) apr_table_get(r->headers_in, "Cookie"))
			== NULL)
		apr_table_add(r->headers_in, "Cookie", headerString);
	else
		apr_table_set(r->headers_in, "Cookie",
				(apr_pstrcat(r->pool, headerString, ";", currentCookies, NULL)));

	/* do some logging */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_util_set_cookie: adding outgoing header: Set-Cookie: %s",
			headerString);
}

/*
 * get a cookie from the HTTP request
 */
char *oidc_util_get_cookie(request_rec *r, char *cookieName) {
	char *cookie, *tokenizerCtx, *rv = NULL;

	/* get the Cookie value */
	char *cookies = apr_pstrdup(r->pool,
			(char *) apr_table_get(r->headers_in, "Cookie"));

	if (cookies != NULL) {

		/* tokenize on ; to find the cookie we want */
		cookie = apr_strtok(cookies, ";", &tokenizerCtx);

		do {

			while (cookie != NULL && *cookie == ' ')
				cookie++;

			/* see if we've found the cookie that we're looking for */
			if (strncmp(cookie, cookieName, strlen(cookieName)) == 0) {

				/* skip to the meat of the parameter (the value after the '=') */
				cookie += (strlen(cookieName) + 1);
				rv = apr_pstrdup(r->pool, cookie);

				break;
			}

			/* go to the next cookie */
			cookie = apr_strtok(NULL, ";", &tokenizerCtx);

		} while (cookie != NULL);
	}

	/* log what we've found */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_get_cookie: returning %s",
			rv);

	return rv;
}

/*
 * normalize a string for use as an HTTP Header Name.  Any invalid
 * characters (per http://tools.ietf.org/html/rfc2616#section-4.2 and
 * http://tools.ietf.org/html/rfc2616#section-2.2) are replaced with
 * a dash ('-') character.
 */
char *oidc_normalize_header_name(const request_rec *r, const char *str) {
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
	for (i = 0; i < strlen(ns); i++) {
		if (ns[i] < 32 || ns[i] == 127)
			ns[i] = '-';
		else if (strchr(separators, ns[i]) != NULL)
			ns[i] = '-';
	}
	return ns;
}

/*
 * see if the currently accessed path matches a path from a defined URL
 */
apr_byte_t oidc_util_request_matches_url(request_rec *r, const char *url) {
	apr_uri_t uri;
	apr_uri_parse(r->pool, url, &uri);
	apr_byte_t rc =
			(apr_strnatcmp(r->parsed_uri.path, uri.path) == 0) ? TRUE : FALSE;
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_request_matches_url: comparing \"%s\"==\"%s\" (%d)",
			r->parsed_uri.path, uri.path, rc);
	return rc;
}

/*
 * see if the currently accessed path has a certain query parameter
 */
apr_byte_t oidc_util_request_has_parameter(request_rec *r, const char* param) {
	if (r->args == NULL)
		return FALSE;
	const char *option1 = apr_psprintf(r->pool, "%s=", param);
	const char *option2 = apr_psprintf(r->pool, "&%s=", param);
	return ((strstr(r->args, option1) == r->args)
			|| (strstr(r->args, option2) != NULL)) ? TRUE : FALSE;
}

/*
 * get a query parameter
 */
apr_byte_t oidc_util_get_request_parameter(request_rec *r, char *name,
		char **value) {
	// TODO: we should really check with ? and & and avoid any <bogus>code= stuff to trigger true
	char *tokenizer_ctx, *p, *args;
	const char *k_param = apr_psprintf(r->pool, "%s=", name);
	const size_t k_param_sz = strlen(k_param);

	*value = NULL;

	if (r->args == NULL || strlen(r->args) == 0)
		return FALSE;

	/* not sure why we do this, but better be safe than sorry */
	args = apr_pstrndup(r->pool, r->args, strlen(r->args));

	p = apr_strtok(args, "&", &tokenizer_ctx);
	do {
		if (p && strncmp(p, k_param, k_param_sz) == 0) {
			*value = apr_pstrdup(r->pool, p + k_param_sz);
			*value = oidc_util_unescape_string(r, *value);
		}
		p = apr_strtok(NULL, "&", &tokenizer_ctx);
	} while (p);

	return (*value != NULL ? TRUE : FALSE);
}

/*
 * printout a JSON string value
 */
static apr_byte_t oidc_util_json_string_print(request_rec *r, json_t *result,
		const char *key, const char *log) {
	json_t *value = json_object_get(result, key);
	if (value != NULL) {
		if (json_is_string(value)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"%s: response contained a \"%s\" key with string value: \"%s\"",
					log, key, json_string_value(value));
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"%s: response contained an \"%s\" key but no string value",
					log, key);
		}
		return TRUE;
	}
	return FALSE;
}

/*
 * check a JSON object for "error" results and printout
 */
static apr_byte_t oidc_util_check_json_error(request_rec *r, json_t *json) {
	if (oidc_util_json_string_print(r, json, "error",
			"oidc_util_check_json_error") == TRUE) {
		oidc_util_json_string_print(r, json, "error_description",
				"oidc_util_check_json_error");
		return TRUE;
	}
	return FALSE;
}

/*
 * decode a JSON string, check for "error" results and printout
 */
apr_byte_t oidc_util_decode_json_and_check_error(request_rec *r,
		const char *str, json_t **json) {

	json_error_t json_error;
	*json = json_loads(str, 0, &json_error);

	/* decode the JSON contents of the buffer */
	if (*json == NULL) {
		/* something went wrong */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_check_json_error: JSON parsing returned an error: %s",
				json_error.text);
		return FALSE;
	}

	if (!json_is_object(*json)) {
		/* oops, no JSON */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_check_json_error: parsed JSON did not contain a JSON object");
		json_decref(*json);
		*json = NULL;
		return FALSE;
	}

	// see if it is not an error response somehow
	if (oidc_util_check_json_error(r, *json) == TRUE) {
		json_decref(*json);
		*json = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * sends HTML content to the user agent
 */
int oidc_util_http_sendstring(request_rec *r, const char *html,
		int success_rvalue) {
	ap_set_content_type(r, "text/html");
	apr_bucket_brigade *bb = apr_brigade_create(r->pool,
			r->connection->bucket_alloc);
	apr_bucket *b = apr_bucket_transient_create(html, strlen(html),
			r->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, b);
	b = apr_bucket_eos_create(r->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, b);
	if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS)
		return HTTP_INTERNAL_SERVER_ERROR;
	//r->status = success_rvalue;
	return success_rvalue;
}

/*
 * read all bytes from the HTTP request
 */
static apr_byte_t oidc_util_read(request_rec *r, const char **rbuf) {

	if (ap_setup_client_block(r, REQUEST_CHUNKED_ERROR) != OK)
		return FALSE;

	if (ap_should_client_block(r)) {

		char argsbuffer[HUGE_STRING_LEN];
		int rsize, len_read, rpos = 0;
		long length = r->remaining;
		*rbuf = apr_pcalloc(r->pool, length + 1);

		while ((len_read = ap_get_client_block(r, argsbuffer,
				sizeof(argsbuffer))) > 0) {
			if ((rpos + len_read) > length) {
				rsize = length - rpos;
			} else {
				rsize = len_read;
			}
			memcpy((char*) *rbuf + rpos, argsbuffer, rsize);
			rpos += rsize;
		}
	}

	return TRUE;
}

/*
 * read the POST parameters in to a table
 */
apr_byte_t oidc_util_read_post(request_rec *r, apr_table_t *table) {
	const char *data = NULL;
	const char *key, *val;

	if (r->method_number != M_POST)
		return FALSE;

	if (oidc_util_read(r, &data) != TRUE)
		return FALSE;

	while (data && *data && (val = ap_getword(r->pool, &data, '&'))) {
		key = ap_getword(r->pool, &val, '=');
		key = oidc_util_unescape_string(r, key);
		val = oidc_util_unescape_string(r, val);
		//ap_unescape_url((char*) key);
		//ap_unescape_url((char*) val);
		apr_table_set(table, key, val);
	}

	return TRUE;
}

// TODO: check return values
apr_byte_t oidc_util_generate_random_base64url_encoded_value(request_rec *r,
		int randomLen, char **randomB64) {
	unsigned char *brnd = apr_pcalloc(r->pool, randomLen);
	apr_generate_random_bytes((unsigned char *) brnd, randomLen);
	*randomB64 = apr_palloc(r->pool, apr_base64_encode_len(randomLen) + 1);
	char *enc = *randomB64;
	apr_base64_encode(enc, (const char *) brnd, randomLen);
	int i = 0;
	while (enc[i] != '\0') {
		if (enc[i] == '+')
			enc[i] = '-';
		if (enc[i] == '/')
			enc[i] = '_';
		if (enc[i] == '=')
			enc[i] = ',';
		i++;
	}
	return TRUE;
}

/*
 * read a file from a path on disk
 */
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, char **result) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];
	apr_finfo_t finfo;

	/* open the file if it exists */
	if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED,
	APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_util_file_read: no file found at: \"%s\"", path);
		return FALSE;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the cache file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* get the file info so we know its size */
	if ((rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_file_read: error calling apr_file_info_get on file: \"%s\" (%s)",
				path, apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* now that we have the size of the file, allocate a buffer that can contain its contents */
	*result = apr_palloc(r->pool, finfo.size + 1);

	/* read the file in to the buffer */
	apr_size_t bytes_read = 0;
	if ((rc = apr_file_read_full(fd, *result, finfo.size, &bytes_read))
			!= APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_file_read: apr_file_read_full on (%s) returned an error: %s",
				path, apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* just to be sure, we set a \0 (we allocated space for it anyway) */
	(*result)[bytes_read] = '\0';

	/* check that we've got all of it */
	if (bytes_read != finfo.size) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_file_read: apr_file_read_full on (%s) returned less bytes (%" APR_SIZE_T_FMT ") than expected: (%" APR_OFF_T_FMT ")",
				path, bytes_read, finfo.size);
		goto error_close;
	}

	/* we're done, unlock and close the file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log successful content retrieval */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_util_file_read: file read successfully \"%s\"", path);

	return TRUE;

	error_close:

	apr_file_unlock(fd);
	apr_file_close(fd);

	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"oidc_util_file_read: returning error");

	return FALSE;
}

/*
 * see if two provided issuer identifiers match (cq. ignore trailing slash)
 */
apr_byte_t oidc_util_issuer_match(const char *a, const char *b) {

	/* check the "issuer" value against the one configure for the provider we got this id_token from */
	if (strcmp(a, b) != 0) {

		/* no strict match, but we are going to accept if the difference is only a trailing slash */
		int n1 = strlen(a);
		int n2 = strlen(b);
		int n = ((n1 == n2 + 1) && (a[n1 - 1] == '/')) ?
				n2 : (((n2 == n1 + 1) && (b[n2 - 1] == '/')) ? n1 : 0);
		if ((n == 0) || (strncmp(a, b, n) != 0))
			return FALSE;
	}

	return TRUE;
}

/*
 * send a user-facing error to the browser
 * TODO: more templating
 */
int oidc_util_html_send_error(request_rec *r, const char *error,
		const char *description, int status_code) {
	char *msg = "<p>the OpenID Connect Provider returned an error:</p><p>";

	if (error != NULL) {
		msg = apr_psprintf(r->pool, "%s<p>Error: <pre>%s</pre></p>", msg,
				error);
	}
	if (description != NULL) {
		msg = apr_psprintf(r->pool, "%s<p>Description: <pre>%s</pre></p>", msg,
				description);
	}

	return oidc_util_http_sendstring(r, msg, status_code);
}

/*
 * see if a certain string value is part of a JSON array with string elements
 */
apr_byte_t oidc_util_json_array_has_value(request_rec *r, json_t *haystack,
		const char *needle) {

	if ((haystack == NULL) || (!json_is_array(haystack)))
		return FALSE;

	int i;
	for (i = 0; i < json_array_size(haystack); i++) {
		json_t *elem = json_array_get(haystack, i);
		if (!json_is_string(elem)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_util_json_array_has_value: unhandled in-array JSON non-string object type [%d]",
					elem->type);
			continue;
		}
		if (strcmp(json_string_value(elem), needle) == 0) {
			break;
		}
	}

//	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
//			"oidc_util_json_array_has_value: returning (%d=%d)", i,
//			haystack->value.array->nelts);

	return (i == json_array_size(haystack)) ? FALSE : TRUE;
}

/*
 * set an HTTP header to pass information to the application
 */
void oidc_util_set_app_header(request_rec *r, const char *s_key,
		const char *s_value, const char *claim_prefix) {

	/* construct the header name, cq. put the prefix in front of a normalized key name */
	const char *s_name = apr_psprintf(r->pool, "%s%s", claim_prefix,
			oidc_normalize_header_name(r, s_key));

	/* do some logging about this event */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_util_set_app_header: setting header \"%s: %s\"", s_name,
			s_value);

	/* now set the actual header name/value */
	apr_table_set(r->headers_in, s_name, s_value);
}

/*
 * set the user/claims information from the session in HTTP headers passed on to the application
 */
void oidc_util_set_app_headers(request_rec *r, const json_t *j_attrs,
		const char *claim_prefix, const char *claim_delimiter) {

	char s_int[255];
	json_t *j_value = NULL;
	const char *s_key = NULL;

	/* if not attributes are set, nothing needs to be done */
	if (j_attrs == NULL) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_util_set_app_headers: no attributes to set");
		return;
	}

	/* loop over the claims in the JSON structure */
	void *iter = json_object_iter((json_t*) j_attrs);
	while (iter) {

		/* get the next key/value entry */
		s_key = json_object_iter_key(iter);
		j_value = json_object_iter_value(iter);

//		char *s_value= json_dumps(j_value, JSON_ENCODE_ANY);
//		oidc_util_set_app_header(r, s_key, s_value, claim_prefix);
//		free(s_value);

		/* check if it is a single value string */
		if (json_is_string(j_value)) {

			/* set the single string in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_header(r, s_key, json_string_value(j_value),
					claim_prefix);

		} else if (json_is_boolean(j_value)) {

			/* set boolean value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_header(r, s_key,
			json_is_true(j_value) ? "1" : "0", claim_prefix);

		} else if (json_is_integer(j_value)) {

			if (sprintf(s_int, "%" JSON_INTEGER_FORMAT,
					json_integer_value(j_value)) > 0) {
				/* set long value in the application header whose name is based on the key and the prefix */
				oidc_util_set_app_header(r, s_key, s_int, claim_prefix);
			} else {
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
						"oidc_util_set_app_headers: could not convert JSON number to string (> 255 characters?), skipping");
			}

		} else if (json_is_real(j_value)) {

			/* set float value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_header(r, s_key,
					apr_psprintf(r->pool, "%lf", json_real_value(j_value)),
					claim_prefix);

		} else if (json_is_object(j_value)) {

			/* set json value in the application header whose name is based on the key and the prefix */
			char *s_value = json_dumps(j_value, 0);
			oidc_util_set_app_header(r, s_key, s_value, claim_prefix);
			free(s_value);

			/* check if it is a multi-value string */
		} else if (json_is_array(j_value)) {

			/* some logging about what we're going to do */
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_util_set_app_headers: parsing attribute array for key \"%s\" (#nr-of-elems: %zu)",
					s_key, json_array_size(j_value));

			/* string to hold the concatenated array string values */
			char *s_concat = apr_pstrdup(r->pool, "");
			int i = 0;

			/* loop over the array */
			for (i = 0; i < json_array_size(j_value); i++) {

				/* get the current element */
				json_t *elem = json_array_get(j_value, i);

				/* check if it is a string */
				if (json_is_string(elem)) {

					/* concatenate the string to the s_concat value using the configured separator char */
					// TODO: escape the delimiter in the values (maybe reuse/extract url-formatted code from oidc_session_identity_encode)
					if (apr_strnatcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat,
								claim_delimiter, json_string_value(elem));
					} else {
						s_concat = apr_psprintf(r->pool, "%s",
								json_string_value(elem));
					}

				} else if (json_is_boolean(elem)) {

					if (apr_strnatcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat,
								claim_delimiter,
								json_is_true(elem) ? "1" : "0");
					} else {
						s_concat = apr_psprintf(r->pool, "%s",
						json_is_true(elem) ? "1" : "0");
					}

				} else {

					/* don't know how to handle a non-string array element */
					ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
							"oidc_util_set_app_headers: unhandled in-array JSON object type [%d] for key \"%s\" when parsing claims array elements",
							elem->type, s_key);
				}
			}

			/* set the concatenated string */
			oidc_util_set_app_header(r, s_key, s_concat, claim_prefix);

		} else {

			/* no string and no array, so unclear how to handle this */
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_util_set_app_headers: unhandled JSON object type [%d] for key \"%s\" when parsing claims",
					j_value->type, s_key);
		}

		iter = json_object_iter_next((json_t *) j_attrs, iter);
	}
}

/*
 * parse a space separated string in to a hash table
 */
apr_hash_t *oidc_util_spaced_string_to_hashtable(apr_pool_t *pool,
		const char *str) {
	char *val;
	const char *data = apr_pstrdup(pool, str);
	apr_hash_t *result = apr_hash_make(pool);
	while (*data && (val = ap_getword_white(pool, &data))) {
		apr_hash_set(result, val, APR_HASH_KEY_STRING, val);
	}
	return result;
}

/*
 * compare two space separated value types
 */
apr_byte_t oidc_util_spaced_string_equals(apr_pool_t *pool, const char *a,
		const char *b) {

	/* parse both entries as hash tables */
	apr_hash_t *ht_a = oidc_util_spaced_string_to_hashtable(pool, a);
	apr_hash_t *ht_b = oidc_util_spaced_string_to_hashtable(pool, b);

	/* first compare the length of both response_types */
	if (apr_hash_count(ht_a) != apr_hash_count(ht_b))
		return FALSE;

	/* then loop over all entries */
	apr_hash_index_t *hi;
	for (hi = apr_hash_first(NULL, ht_a); hi; hi = apr_hash_next(hi)) {
		const char *k;
		const char *v;
		apr_hash_this(hi, (const void**) &k, NULL, (void**) &v);
		if (apr_hash_get(ht_b, k, APR_HASH_KEY_STRING) == NULL)
			return FALSE;
	}

	/* if we've made it this far, a an b are equal in length and every element in a is in b */
	return TRUE;
}

/*
 * see if a particular value is part of a space separated value
 */
apr_byte_t oidc_util_spaced_string_contains(apr_pool_t *pool,
		const char *response_type, const char *match) {
	apr_hash_t *ht = oidc_util_spaced_string_to_hashtable(pool, response_type);
	return (apr_hash_get(ht, match, APR_HASH_KEY_STRING) != NULL);
}

/*
 * get (optional) string from a JSON object
 */
apr_byte_t oidc_json_object_get_string(apr_pool_t *pool, json_t *json,
		const char *name, char **value, const char *default_value) {
	*value = default_value ? apr_pstrdup(pool, default_value) : NULL;
	if (json != NULL) {
		json_t *v = json_object_get(json, name);
		if ((v != NULL) && (json_is_string(v))) {
			*value = apr_pstrdup(pool, json_string_value(v));
		}
	}
	return TRUE;
}

/*
 * get (optional) int from a JSON object
 */
apr_byte_t oidc_json_object_get_int(apr_pool_t *pool, json_t *json,
		const char *name, int *value, const int default_value) {
	*value = default_value;
	if (json != NULL) {
		json_t *v = json_object_get(json, name);
		if ((v != NULL) && (json_is_integer(v))) {
			*value = json_integer_value(v);
		}
	}
	return TRUE;
}
