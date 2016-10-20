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
 * Copyright (C) 2013-2016 Ping Identity Corporation
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

#include <pcre.h>

/* hrm, should we get rid of this by adding parameters to the (3) functions? */
extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/*
 * base64url encode a string
 */
int oidc_base64url_encode(request_rec *r, char **dst, const char *src,
		int src_len, int remove_padding) {
	if ((src == NULL) || (src_len <= 0)) {
		oidc_error(r, "not encoding anything; src=NULL and/or src_len<1");
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
int oidc_base64url_decode(apr_pool_t *pool, char **dst, const char *src) {
	if (src == NULL) {
		return -1;
	}
	char *dec = apr_pstrdup(pool, src);
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
	switch (strlen(dec) % 4) {
	case 0:
		break;
	case 2:
		dec = apr_pstrcat(pool, dec, "==", NULL);
		break;
	case 3:
		dec = apr_pstrcat(pool, dec, "=", NULL);
		break;
	default:
		return 0;
	}
	int dlen = apr_base64_decode_len(dec);
	*dst = apr_palloc(pool, dlen);
	return apr_base64_decode(*dst, dec);
}

apr_byte_t oidc_util_jwt_create(request_rec *r, const char *secret,
		json_t *payload, char **compact_encoded_jwt) {

	apr_byte_t rv = FALSE;
	oidc_jose_error_t err;

	oidc_jwk_t *jwk = NULL;
	oidc_jwt_t *jwt = NULL;
	oidc_jwt_t *jwe = NULL;

	if (oidc_util_create_symmetric_key(r, secret, 0, "sha256", FALSE,
			&jwk) == FALSE)
		goto end;

	jwt = oidc_jwt_new(r->pool, TRUE, FALSE);
	if (jwt == NULL) {
		oidc_error(r, "creating JWT failed");
		goto end;
	}

	jwt->header.alg = apr_pstrdup(r->pool, "HS256");
	jwt->payload.value.json = payload;

	if (oidc_jwt_sign(r->pool, jwt, jwk, &err) == FALSE) {
		oidc_error(r, "signing JWT failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	jwe = oidc_jwt_new(r->pool, TRUE, FALSE);
	if (jwe == NULL) {
		oidc_error(r, "creating JWE failed");
		goto end;
	}

	jwe->header.alg = "dir";
	jwe->header.enc = "A256GCM";

	const char *cser = oidc_jwt_serialize(r->pool, jwt, &err);
	if (oidc_jwt_encrypt(r->pool, jwe, jwk, cser, compact_encoded_jwt,
			&err) == FALSE) {
		oidc_error(r, "encrypting JWT failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	rv = TRUE;

	end:

	if (jwe != NULL)
		oidc_jwt_destroy(jwe);
	if (jwk != NULL)
		oidc_jwk_destroy(jwk);
	if (jwt != NULL) {
		jwt->payload.value.json = NULL;
		oidc_jwt_destroy(jwt);
	}

	return rv;
}

apr_byte_t oidc_util_jwt_verify(request_rec *r, const char *secret,
		const char *compact_encoded_jwt, json_t **result) {

	oidc_debug(r, "enter: JWT header=%s",
			oidc_proto_peek_jwt_header(r, compact_encoded_jwt, NULL));

	apr_byte_t rv = FALSE;
	oidc_jose_error_t err;

	oidc_jwk_t *jwk = NULL;
	oidc_jwt_t *jwt = NULL;

	if (oidc_util_create_symmetric_key(r, secret, 0, "sha256", FALSE,
			&jwk) == FALSE)
		goto end;

	apr_hash_t *keys = apr_hash_make(r->pool);
	apr_hash_set(keys, "", APR_HASH_KEY_STRING, jwk);

	if (oidc_jwt_parse(r->pool, compact_encoded_jwt, &jwt, keys, &err) == FALSE) {
		oidc_error(r, "parsing JWT failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	if (oidc_jwt_verify(r->pool, jwt, keys, &err) == FALSE) {
		oidc_error(r, "verifying JWT failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	*result = json_deep_copy(jwt->payload.value.json);

	rv = TRUE;

	end:

	if (jwk != NULL)
		oidc_jwk_destroy(jwk);
	if (jwt != NULL)
		oidc_jwt_destroy(jwt);

	return rv;
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
		oidc_error(r, "curl_easy_init() error");
		return NULL;
	}
	char *result = curl_easy_escape(curl, str, 0);
	if (result == NULL) {
		oidc_error(r, "curl_easy_escape() error");
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
		oidc_error(r, "curl_easy_init() error");
		return NULL;
	}
	char *result = curl_easy_unescape(curl, str, 0, 0);
	if (result == NULL) {
		oidc_error(r, "curl_easy_unescape() error");
		return NULL;
	}
	char *rv = apr_pstrdup(r->pool, result);
	curl_free(result);
	curl_easy_cleanup(curl);
	//oidc_debug(r, "input=\"%s\", output=\"%s\"", str, rv);
	return rv;
}

/*
 * HTML escape a string
 */
char *oidc_util_html_escape(apr_pool_t *pool, const char *s) {
	// TODO: this has performance/memory issues for large chunks of HTML
	const char chars[6] = { '&', '\'', '\"', '>', '<', '\0' };
	const char * const replace[] =
	{ "&amp;", "&apos;", "&quot;", "&gt;", "&lt;", };
	unsigned int i, j = 0, k, n = 0, len = strlen(chars);
	int m = 0;
	char *r = apr_pcalloc(pool, strlen(s) * 6);
	for (i = 0; i < strlen(s); i++) {
		for (n = 0; n < len; n++) {
			if (s[i] == chars[n]) {
				m = strlen(replace[n]);
				for (k = 0; k < m; k++)
					r[j + k] = replace[n][k];
				j += m;
				break;
			}
		}
		if (n == len) {
			r[j] = s[i];
			j++;
		}
	}
	r[j] = '\0';
	return apr_pstrdup(pool, r);
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
		const char *scheme_str) {
	/* first see if there's a proxy/load-balancer in front of us */
	const char *port_str = apr_table_get(r->headers_in, "X-Forwarded-Port");
	if (port_str == NULL) {
		/* see if we can get the port from the "X-Forwarded-Host" header */
		const char *host_hdr = apr_table_get(r->headers_in, "X-Forwarded-Host");
		if (host_hdr) {
			port_str = strchr(host_hdr, ':');
			if (port_str)
				port_str++;
		} else {
			host_hdr = apr_table_get(r->headers_in, "Host");
			if (host_hdr)
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
	}
	return port_str;
}

/*
 * get the hostname part of the URL that is currently being accessed
 */
const char *oidc_get_current_url_host(request_rec *r) {
	const char *host_str = apr_table_get(r->headers_in, "X-Forwarded-Host");
	if (host_str == NULL)
		host_str = apr_table_get(r->headers_in, "Host");
	if (host_str) {
		host_str = apr_pstrdup(r->pool, host_str);
		char *p = strchr(host_str, ':');
		if (p != NULL)
			*p = '\0';
	} else {
		/* no Host header, HTTP 1.0 */
		host_str = ap_get_server_name(r);
	}
	return host_str;
}

/*
 * get the URL that is currently being accessed
 */
char *oidc_get_current_url(request_rec *r) {

	const char *scheme_str = oidc_get_current_url_scheme(r);
	const char *host_str = oidc_get_current_url_host(r);
	const char *port_str = oidc_get_current_url_port(r, scheme_str);
	port_str = port_str ? apr_psprintf(r->pool, ":%s", port_str) : "";

	char *url = apr_pstrcat(r->pool, scheme_str, "://", host_str, port_str,
			r->uri, (r->args != NULL && *r->args != '\0' ? "?" : ""), r->args,
			NULL);

	oidc_debug(r, "current URL '%s'", url);

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
		const char **response, int timeout, const char *outgoing_proxy,
		apr_array_header_t *pass_cookies, const char *ssl_cert,
		const char *ssl_key) {
	char curlError[CURL_ERROR_SIZE];
	oidc_curl_buffer curlBuffer;
	CURL *curl;
	struct curl_slist *h_list = NULL;
	int i;

	/* do some logging about the inputs */
	oidc_debug(r,
			"url=%s, data=%s, content_type=%s, basic_auth=%s, bearer_token=%s, ssl_validate_server=%d",
			url, data, content_type, basic_auth, bearer_token,
			ssl_validate_server);

	curl = curl_easy_init();
	if (curl == NULL) {
		oidc_error(r, "curl_easy_init() error");
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

#ifdef WIN32
	DWORD buflen;
	char *ptr = NULL;
	char *retval = (char *) malloc(sizeof (TCHAR) * (MAX_PATH + 1));
	retval[0] = '\0';
	buflen = SearchPath(NULL, "curl-ca-bundle.crt", NULL, MAX_PATH+1, retval, &ptr);
	if (buflen > 0)
		curl_easy_setopt(curl, CURLOPT_CAINFO, retval);
	else
		oidc_warn(r, "no curl-ca-bundle.crt file found in path");
	free(retval);
#endif

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

	if (ssl_cert != NULL)
		curl_easy_setopt(curl, CURLOPT_SSLCERT, ssl_cert);
	if (ssl_key != NULL)
		curl_easy_setopt(curl, CURLOPT_SSLKEY, ssl_key);

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

	if (pass_cookies != NULL) {
		/* gather cookies that we need to pass on from the incoming request */
		char *cookie_string = NULL;
		for (i = 0; i < pass_cookies->nelts; i++) {
			const char *cookie_name = ((const char**) pass_cookies->elts)[i];
			char *cookie_value = oidc_util_get_cookie(r, cookie_name);
			if (cookie_value != NULL) {
				cookie_string =
						(cookie_string == NULL) ?
								apr_psprintf(r->pool, "%s=%s", cookie_name,
										cookie_value) :
										apr_psprintf(r->pool, "%s; %s=%s",
												cookie_string, cookie_name,
												cookie_value);
			}
		}

		/* see if we need to pass any cookies */
		if (cookie_string != NULL) {
			oidc_debug(r, "passing browser cookies on backend call: %s",
					cookie_string);
			curl_easy_setopt(curl, CURLOPT_COOKIE, cookie_string);
		}
	}

	/* set the target URL */
	curl_easy_setopt(curl, CURLOPT_URL, url);

	/* call it and record the result */
	int rv = TRUE;
	if (curl_easy_perform(curl) != CURLE_OK) {
		oidc_error(r, "curl_easy_perform() failed on: %s (%s)", url, curlError);
		rv = FALSE;
		goto out;
	}

	long response_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	oidc_debug(r, "HTTP response code=%ld", response_code);

	*response = apr_pstrndup(r->pool, curlBuffer.buf, curlBuffer.written);

	/* set and log the response */
	oidc_debug(r, "response=%s", *response);

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
		const char **response, int timeout, const char *outgoing_proxy,
		apr_array_header_t *pass_cookies, const char *ssl_cert,
		const char *ssl_key) {

	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		oidc_http_encode_t data = { r, "" };
		apr_table_do(oidc_http_add_form_url_encoded_param, &data, params, NULL);
		const char *sep = strchr(url, '?') != NULL ? "&" : "?";
		url = apr_psprintf(r->pool, "%s%s%s", url, sep, data.encoded_params);
		oidc_debug(r, "get URL=\"%s\"", url);
	}

	return oidc_util_http_call(r, url, NULL, NULL, basic_auth, bearer_token,
			ssl_validate_server, response, timeout, outgoing_proxy,
			pass_cookies, ssl_cert, ssl_key);
}

/*
 * execute HTTP POST request with form-encoded data
 */
apr_byte_t oidc_util_http_post_form(request_rec *r, const char *url,
		const apr_table_t *params, const char *basic_auth,
		const char *bearer_token, int ssl_validate_server,
		const char **response, int timeout, const char *outgoing_proxy,
		apr_array_header_t *pass_cookies, const char *ssl_cert,
		const char *ssl_key) {

	const char *data = NULL;
	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		oidc_http_encode_t encode_data = { r, "" };
		apr_table_do(oidc_http_add_form_url_encoded_param, &encode_data, params,
				NULL);
		data = encode_data.encoded_params;
		oidc_debug(r, "post data=\"%s\"", data);
	}

	return oidc_util_http_call(r, url, data,
			"application/x-www-form-urlencoded", basic_auth, bearer_token,
			ssl_validate_server, response, timeout, outgoing_proxy,
			pass_cookies, ssl_cert, ssl_key);
}

/*
 * execute HTTP POST request with JSON-encoded data
 */
apr_byte_t oidc_util_http_post_json(request_rec *r, const char *url,
		const json_t *json, const char *basic_auth, const char *bearer_token,
		int ssl_validate_server, const char **response, int timeout,
		const char *outgoing_proxy, apr_array_header_t *pass_cookies,
		const char *ssl_cert, const char *ssl_key) {

	char *data = NULL;
	if (json != NULL) {
		char *s_value = json_dumps(json, 0);
		data = apr_pstrdup(r->pool, s_value);
		free(s_value);
	}

	return oidc_util_http_call(r, url, data, "application/json", basic_auth,
			bearer_token, ssl_validate_server, response, timeout,
			outgoing_proxy, pass_cookies, ssl_cert, ssl_key);
}

/*
 * get the current path from the request in a normalized way
 */
static char *oidc_util_get_path(request_rec *r) {
	size_t i;
	char *p;
	p = r->parsed_uri.path;
	if ((p == NULL) || (p[0] == '\0'))
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
	char *cookie_path = oidc_cfg_dir_cookie_path(r);
	if (cookie_path != NULL) {
		if (strncmp(cookie_path, requestPath, strlen(cookie_path)) == 0)
			rv = cookie_path;
		else {
			oidc_warn(r,
					"OIDCCookiePath (%s) not a substring of request path, using request path (%s) for cookie",
					cookie_path, requestPath);
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
		const char *cookieValue, apr_time_t expires) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	char *headerString, *expiresString = NULL;

	/* see if we need to clear the cookie */
	if (apr_strnatcmp(cookieValue, "") == 0)
		expires = 0;

	/* construct the expire value */
	if (expires != -1) {
		expiresString = (char *) apr_pcalloc(r->pool, APR_RFC822_DATE_LEN);
		if (apr_rfc822_date(expiresString, expires) != APR_SUCCESS) {
			oidc_error(r, "could not set cookie expiry date");
		}
	}

	/* construct the cookie value */
	headerString = apr_psprintf(r->pool, "%s=%s;Path=%s%s%s%s%s", cookieName,
			cookieValue, oidc_util_get_cookie_path(r),
			(expiresString == NULL) ?
					"" : apr_psprintf(r->pool, "; expires=%s", expiresString),
					c->cookie_domain != NULL ?
							apr_psprintf(r->pool, ";Domain=%s", c->cookie_domain) : "",
							((apr_strnatcasecmp("https", oidc_get_current_url_scheme(r)) == 0) ?
									";Secure" : ""),
									c->cookie_http_only != FALSE ? ";HttpOnly" : "");

	/* sanity check on overall cookie value size */
	if (strlen(headerString) > 4093) {
		oidc_warn(r,
				"the length of the cookie value (%lu) is greater than 4093(!) bytes, this may not work with all browsers/server combinations: consider switching to a server side caching!",
				(unsigned long )strlen(headerString));
	}

	/* use r->err_headers_out so we always print our headers (even on 302 redirect) - headers_out only prints on 2xx responses */
	apr_table_add(r->err_headers_out, "Set-Cookie", headerString);

	/* do some logging */
	oidc_debug(r, "adding outgoing header: Set-Cookie: %s", headerString);
}

/*
 * get a cookie from the HTTP request
 */
char *oidc_util_get_cookie(request_rec *r, const char *cookieName) {
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
			if ((strncmp(cookie, cookieName, strlen(cookieName)) == 0)
					&& (cookie[strlen(cookieName)] == '=')) {

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
	oidc_debug(r, "returning \"%s\" = %s", cookieName,
			rv ? apr_psprintf(r->pool, "\"%s\"", rv) : "<null>");

	return rv;
}

#define OIDC_COOKIE_CHUNKS_SEPARATOR "_"
#define OIDC_COOKIE_CHUNKS_POSTFIX "chunks"

/*
 * get a cookie value that is split over a number of chunked cookies
 */
char *oidc_util_get_chunked_cookie(request_rec *r, const char *cookieName,
		int chunkSize) {
	char *cookieValue = NULL;
	int i = 0;
	if (chunkSize == 0) {
		cookieValue = oidc_util_get_cookie(r, cookieName);
	} else {
		char *chunkCountName = apr_psprintf(r->pool, "%s%s%s", cookieName,
				OIDC_COOKIE_CHUNKS_SEPARATOR,
				OIDC_COOKIE_CHUNKS_POSTFIX);
		char* chunkCountValue = oidc_util_get_cookie(r, chunkCountName);
		if (chunkCountValue != NULL) {
			cookieValue = NULL;
			char *endptr = NULL;
			long chunkCount = strtol(chunkCountValue, &endptr, 10);
			if ((*chunkCountValue != '\0') && (*endptr == '\0')) {
				cookieValue = "";
				for (i = 0; i < chunkCount; i++) {
					char *chunkName = apr_psprintf(r->pool, "%s%s%d",
							cookieName, OIDC_COOKIE_CHUNKS_SEPARATOR, i);
					char *chunkValue = oidc_util_get_cookie(r, chunkName);
					cookieValue = apr_psprintf(r->pool, "%s%s", cookieValue,
							chunkValue);
				}
			}
		} else {
			cookieValue = oidc_util_get_cookie(r, cookieName);
		}
	}
	return cookieValue;
}

/*
 * set a cookie value that is split over a number of chunked cookies
 */
void oidc_util_set_chunked_cookie(request_rec *r, const char *cookieName,
		const char *cookieValue, apr_time_t expires, int chunkSize) {
	int i = 0;
	int cookieLength = strlen(cookieValue);
	if ((chunkSize == 0) || (cookieLength < chunkSize)) {
		oidc_util_set_cookie(r, cookieName, cookieValue, expires);
	} else {
		int chunkCountValue = cookieLength / chunkSize + 1;
		const char *ptr = cookieValue;
		for (i = 0; i < chunkCountValue; i++) {
			char *chunkName = apr_psprintf(r->pool, "%s%s%d", cookieName,
					OIDC_COOKIE_CHUNKS_SEPARATOR, i);
			char *chunkValue = apr_pstrndup(r->pool, ptr, chunkSize);
			ptr += chunkSize;
			oidc_util_set_cookie(r, chunkName, chunkValue, expires);
		};
		char *chunkCountName = apr_psprintf(r->pool, "%s%s%s", cookieName,
				OIDC_COOKIE_CHUNKS_SEPARATOR, OIDC_COOKIE_CHUNKS_POSTFIX);
		oidc_util_set_cookie(r, chunkCountName,
				apr_psprintf(r->pool, "%d", chunkCountValue), expires);
	}
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
	memset(&uri, 0, sizeof(apr_uri_t));
	apr_uri_parse(r->pool, url, &uri);
	oidc_debug(r, "comparing \"%s\"==\"%s\"", r->parsed_uri.path, uri.path);
	if ((r->parsed_uri.path == NULL) || (uri.path == NULL))
		return (r->parsed_uri.path == uri.path);
	return (apr_strnatcmp(r->parsed_uri.path, uri.path) == 0);
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
	if (value != NULL && !json_is_null(value)) {
		char *s_value = json_dumps(value, JSON_ENCODE_ANY);
		oidc_error(r,
				"%s: response contained an \"%s\" entry with value: \"%s\"",
				log, key, s_value);
		free(s_value);
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
 * parse a JSON object
 */
apr_byte_t oidc_util_decode_json_object(request_rec *r, const char *str, json_t **json) {

	json_error_t json_error;
	*json = json_loads(str, 0, &json_error);

	/* decode the JSON contents of the buffer */
	if (*json == NULL) {
		/* something went wrong */
		oidc_error(r, "JSON parsing returned an error: %s (%s)", json_error.text, str);
		return FALSE;
	}

	if (!json_is_object(*json)) {
		/* oops, no JSON */
		oidc_error(r, "parsed JSON did not contain a JSON object");
		json_decref(*json);
		*json = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * decode a JSON string, check for "error" results and printout
 */
apr_byte_t oidc_util_decode_json_and_check_error(request_rec *r,
		const char *str, json_t **json) {

	if (oidc_util_decode_json_object(r, str, json) == FALSE)
		return FALSE;

	// see if it is not an error response somehow
	if (oidc_util_check_json_error(r, *json) == TRUE) {
		json_decref(*json);
		*json = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * sends content to the user agent
 */
int oidc_util_http_send(request_rec *r, const char *data, int data_len,
		const char *content_type, int success_rvalue) {
	ap_set_content_type(r, content_type);
	apr_bucket_brigade *bb = apr_brigade_create(r->pool,
			r->connection->bucket_alloc);
	apr_bucket *b = apr_bucket_transient_create(data, data_len,
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
 * send HTML content to the user agent
 */
int oidc_util_html_send(request_rec *r, const char *title,
		const char *html_head, const char *on_load, const char *html_body,
		int status_code) {

	char *html =
			"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n"
			"<html>\n"
			"  <head>\n"
			"    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n"
			"    <title>%s</title>\n"
			"    %s\n"
			"  </head>\n"
			"  <body%s>\n"
			"%s\n"
			"  </body>\n"
			"</html>\n";

	html = apr_psprintf(r->pool, html,
			title ? oidc_util_html_escape(r->pool, title) : "",
					html_head ? html_head : "",
							on_load ? apr_psprintf(r->pool, " onload=\"%s()\"", on_load) : "",
									html_body ? html_body : "<p></p>");

	return oidc_util_http_send(r, html, strlen(html), "text/html", status_code);
}

static char *html_error_template_contents = NULL;

/*
 * send a user-facing error to the browser
 */
int oidc_util_html_send_error(request_rec *r, const char *html_template,
		const char *error, const char *description, int status_code) {

	char *html = "";

	if (html_template != NULL) {

		if (html_error_template_contents == NULL) {
			int rc = oidc_util_file_read(r, html_template,
					r->server->process->pool, &html_error_template_contents);
			if (rc == FALSE) {
				oidc_error(r, "could not read HTML error template: %s",
						html_template);
				html_error_template_contents = NULL;
			}
		}

		if (html_error_template_contents) {
			html = apr_psprintf(r->pool, html_error_template_contents,
					oidc_util_html_escape(r->pool, error ? error : ""),
					oidc_util_html_escape(r->pool,
							description ? description : ""));

			return oidc_util_http_send(r, html, strlen(html), "text/html",
					status_code);
		}
	}

	if (error != NULL) {
		html = apr_psprintf(r->pool, "%s<p>Error: <pre>%s</pre></p>", html,
				oidc_util_html_escape(r->pool, error));
	}
	if (description != NULL) {
		html = apr_psprintf(r->pool, "%s<p>Description: <pre>%s</pre></p>",
				html, oidc_util_html_escape(r->pool, description));
	}

	return oidc_util_html_send(r, "Error", NULL, NULL, html, status_code);
}

/*
 * read all bytes from the HTTP request
 */
static apr_byte_t oidc_util_read(request_rec *r, char **rbuf) {
	apr_size_t bytes_read;
	apr_size_t bytes_left;
	apr_size_t len;
	long read_length;

	if (ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK) != OK)
		return FALSE;

	len = ap_should_client_block(r) ? r->remaining : 0;

	if (len > OIDC_MAX_POST_DATA_LEN) {
		oidc_error(r, "POST parameter value is too large: %lu bytes (max=%d)",
				(unsigned long ) len, OIDC_MAX_POST_DATA_LEN);
		return FALSE;
	}

	*rbuf = (char *) apr_palloc(r->pool, len + 1);
	if (*rbuf == NULL) {
		oidc_error(r, "could not allocate memory for %lu bytes of POST data.",
				(unsigned long )len);
		return FALSE;
	}
	(*rbuf)[len] = '\0';

	bytes_read = 0;
	bytes_left = len;
	while (bytes_left > 0) {
		read_length = ap_get_client_block(r, &(*rbuf)[bytes_read], bytes_left);
		if (read_length == 0) {
			(*rbuf)[bytes_read] = '\0';
			break;
		} else if (read_length < 0) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"Failed to read POST data from client.");
			return FALSE;
		}
		bytes_read += read_length;
		bytes_left -= read_length;
	}

	return TRUE;
}

/*
 * read form-encoded parameters from a string in to a table
 */
apr_byte_t oidc_util_read_form_encoded_params(request_rec *r,
		apr_table_t *table, char *data) {
	const char *key, *val, *p = data;

	while (p && *p && (val = ap_getword(r->pool, &p, '&'))) {
		key = ap_getword(r->pool, &val, '=');
		key = oidc_util_unescape_string(r, key);
		val = oidc_util_unescape_string(r, val);
		apr_table_set(table, key, val);
	}

	oidc_debug(r, "parsed: %lu bytes in to %d elements",
			data ? (unsigned long )strlen(data) : 0 , apr_table_elts(table)->nelts);

	return TRUE;
}

/*
 * read the POST parameters in to a table
 */
apr_byte_t oidc_util_read_post_params(request_rec *r, apr_table_t *table) {
	char *data = NULL;

	if (r->method_number != M_POST)
		return FALSE;

	if (oidc_util_read(r, &data) != TRUE)
		return FALSE;

	return oidc_util_read_form_encoded_params(r, table, data);
}

/*
 * read a file from a path on disk
 */
apr_byte_t oidc_util_file_read(request_rec *r, const char *path,
		apr_pool_t *pool, char **result) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];
	apr_finfo_t finfo;

	/* open the file if it exists */
	if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED,
			APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
		oidc_warn(r, "no file found at: \"%s\"", path);
		return FALSE;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the cache file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* get the file info so we know its size */
	if ((rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd)) != APR_SUCCESS) {
		oidc_error(r, "error calling apr_file_info_get on file: \"%s\" (%s)",
				path, apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* now that we have the size of the file, allocate a buffer that can contain its contents */
	*result = apr_palloc(pool, finfo.size + 1);

	/* read the file in to the buffer */
	apr_size_t bytes_read = 0;
	if ((rc = apr_file_read_full(fd, *result, finfo.size, &bytes_read))
			!= APR_SUCCESS) {
		oidc_error(r, "apr_file_read_full on (%s) returned an error: %s", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* just to be sure, we set a \0 (we allocated space for it anyway) */
	(*result)[bytes_read] = '\0';

	/* check that we've got all of it */
	if (bytes_read != finfo.size) {
		oidc_error(r,
				"apr_file_read_full on (%s) returned less bytes (%" APR_SIZE_T_FMT ") than expected: (%" APR_OFF_T_FMT ")",
				path, bytes_read, finfo.size);
		goto error_close;
	}

	/* we're done, unlock and close the file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log successful content retrieval */
	oidc_debug(r, "file read successfully \"%s\"", path);

	return TRUE;

error_close:

	apr_file_unlock(fd);
	apr_file_close(fd);

	oidc_error(r, "return error");

	return FALSE;
}

/*
 * see if two provided issuer identifiers match (cq. ignore trailing slash)
 */
apr_byte_t oidc_util_issuer_match(const char *a, const char *b) {

	/* check the "issuer" value against the one configure for the provider we got this id_token from */
	if (apr_strnatcmp(a, b) != 0) {

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
			oidc_error(r, "unhandled in-array JSON non-string object type [%d]",
					elem->type);
			continue;
		}
		if (apr_strnatcmp(json_string_value(elem), needle) == 0) {
			break;
		}
	}

	//	oidc_debug(r,
	//			"returning (%d=%d)", i,
	//			haystack->value.array->nelts);

	return (i == json_array_size(haystack)) ? FALSE : TRUE;
}

/*
 * set a HTTP header
 */
void oidc_util_set_header(request_rec *r, const char *s_name,
		const char *s_value) {
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
		*p = ' ';

	/* do some logging about this event */
	oidc_debug(r, "setting header \"%s: %s\"", s_name, s_value);

	/* now set the actual header name/value */
	apr_table_set(r->headers_in, s_name, s_value);
}

/*
 * set a HTTP header and/or environment variable to pass information to the application
 */
void oidc_util_set_app_info(request_rec *r, const char *s_key,
		const char *s_value, const char *claim_prefix, apr_byte_t as_header,
		apr_byte_t as_env_var) {

	apr_table_t *env = NULL;

	/* construct the header name, cq. put the prefix in front of a normalized key name */
	const char *s_name = apr_psprintf(r->pool, "%s%s", claim_prefix,
			oidc_normalize_header_name(r, s_key));

	if (as_header)
		oidc_util_set_header(r, s_name, s_value);

	if (as_env_var) {

		/* do some logging about this event */
		oidc_debug(r, "setting environment variable \"%s: %s\"", s_name,
				s_value);

		apr_pool_userdata_get((void **) &env, OIDC_USERDATA_ENV_KEY, r->pool);
		if (env == NULL)
			env = apr_table_make(r->pool, 10);
		apr_table_set(env, s_name, s_value);
		apr_pool_userdata_set(env, OIDC_USERDATA_ENV_KEY, NULL, r->pool);
	}
}

/*
 * set the user/claims information from the session in HTTP headers passed on to the application
 */
void oidc_util_set_app_infos(request_rec *r, const json_t *j_attrs,
		const char *claim_prefix, const char *claim_delimiter,
		apr_byte_t as_header, apr_byte_t as_env_var) {

	char s_int[255];
	json_t *j_value = NULL;
	const char *s_key = NULL;

	/* if not attributes are set, nothing needs to be done */
	if (j_attrs == NULL) {
		oidc_debug(r, "no attributes to set");
		return;
	}

	/* loop over the claims in the JSON structure */
	void *iter = json_object_iter((json_t*) j_attrs);
	while (iter) {

		/* get the next key/value entry */
		s_key = json_object_iter_key(iter);
		j_value = json_object_iter_value(iter);

		//		char *s_value= json_dumps(j_value, JSON_ENCODE_ANY);
		//		oidc_util_set_app_info(r, s_key, s_value, claim_prefix);
		//		free(s_value);

		/* check if it is a single value string */
		if (json_is_string(j_value)) {

			/* set the single string in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(r, s_key, json_string_value(j_value),
					claim_prefix, as_header, as_env_var);

		} else if (json_is_boolean(j_value)) {

			/* set boolean value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(r, s_key,
					(json_is_true(j_value) ? "1" : "0"), claim_prefix,
					as_header, as_env_var);

		} else if (json_is_integer(j_value)) {

			if (sprintf(s_int, "%ld", (long) json_integer_value(j_value)) > 0) {
				/* set long value in the application header whose name is based on the key and the prefix */
				oidc_util_set_app_info(r, s_key, s_int, claim_prefix, as_header,
						as_env_var);
			} else {
				oidc_warn(r,
						"could not convert JSON number to string (> 255 characters?), skipping");
			}

		} else if (json_is_real(j_value)) {

			/* set float value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(r, s_key,
					apr_psprintf(r->pool, "%lf", json_real_value(j_value)),
					claim_prefix, as_header, as_env_var);

		} else if (json_is_object(j_value)) {

			/* set json value in the application header whose name is based on the key and the prefix */
			char *s_value = json_dumps(j_value, 0);
			oidc_util_set_app_info(r, s_key, s_value, claim_prefix, as_header,
					as_env_var);
			free(s_value);

			/* check if it is a multi-value string */
		} else if (json_is_array(j_value)) {

			/* some logging about what we're going to do */
			oidc_debug(r,
					"parsing attribute array for key \"%s\" (#nr-of-elems: %llu)",
					s_key, (unsigned long long )json_array_size(j_value));

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
					oidc_warn(r,
							"unhandled in-array JSON object type [%d] for key \"%s\" when parsing claims array elements",
							elem->type, s_key);
				}
			}

			/* set the concatenated string */
			oidc_util_set_app_info(r, s_key, s_concat, claim_prefix, as_header,
					as_env_var);

		} else {

			/* no string and no array, so unclear how to handle this */
			oidc_warn(r,
					"unhandled JSON object type [%d] for key \"%s\" when parsing claims",
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
apr_byte_t oidc_util_spaced_string_contains(apr_pool_t *pool, const char *str,
		const char *match) {
	apr_hash_t *ht = oidc_util_spaced_string_to_hashtable(pool, str);
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

/*
 * merge two JSON objects
 */
apr_byte_t oidc_util_json_merge(json_t *src, json_t *dst) {

	const char *key;
	json_t *value = NULL;
	void *iter = NULL;

	if ((src == NULL) || (dst == NULL))
		return FALSE;

	iter = json_object_iter(src);
	while (iter) {
		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		json_object_set(dst, key, value);
		iter = json_object_iter_next(src, iter);
	}

	return TRUE;
}

/*
 * add query encoded parameters to a table
 */
void oidc_util_table_add_query_encoded_params(apr_pool_t *pool,
		apr_table_t *table, const char *params) {
	if (params != NULL) {
		const char *key, *val;
		const char *p = params;
		while (*p && (val = ap_getword(pool, &p, '&'))) {
			key = ap_getword(pool, &val, '=');
			ap_unescape_url((char *) key);
			ap_unescape_url((char *) val);
			apr_table_addn(table, key, val);
		}
	}
}

/*
 * create a symmetric key from a client_secret
 */
apr_byte_t oidc_util_create_symmetric_key(request_rec *r,
		const char *client_secret, int r_key_len, const char *hash_algo,
		apr_byte_t set_kid, oidc_jwk_t **jwk) {
	oidc_jose_error_t err;
	unsigned char *key = NULL;
	unsigned int key_len;

	if ((client_secret != NULL) && (strlen(client_secret) > 0)) {

		if (hash_algo == NULL) {
			key = (unsigned char *) client_secret;
			key_len = strlen(client_secret);
		} else {
			/* hash the client_secret first, this is OpenID Connect specific */
			oidc_jose_hash_bytes(r->pool, hash_algo,
					(const unsigned char *) client_secret,
					strlen(client_secret), &key, &key_len, &err);
		}

		if ((key != NULL) && (key_len > 0)) {
			if ((r_key_len != 0) && (key_len >= r_key_len))
				key_len = r_key_len;
			oidc_debug(r, "key_len=%d", key_len);
			*jwk = oidc_jwk_create_symmetric_key(r->pool, NULL, key, key_len,
					set_kid, &err);
		}

		if (*jwk == NULL) {
			oidc_error(r,
					"could not create JWK from the provided secret %s: %s",
					client_secret, oidc_jose_e2s(r->pool, err));
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * merge provided keys and client secret in to a single hashtable
 */
apr_hash_t * oidc_util_merge_symmetric_key(apr_pool_t *pool, apr_hash_t *keys,
		oidc_jwk_t *jwk) {
	apr_hash_t *result =
			(keys != NULL) ? apr_hash_copy(pool, keys) : apr_hash_make(pool);
	if (jwk != NULL) {
		apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
	}
	return result;
}

/*
 * openssl hash and base64 encode
 */
apr_byte_t oidc_util_hash_string_and_base64url_encode(request_rec *r,
		const char *openssl_hash_algo, const char *input, char **output) {
	oidc_jose_error_t err;
	unsigned char *hashed = NULL;
	unsigned int hashed_len = 0;
	if (oidc_jose_hash_bytes(r->pool, openssl_hash_algo,
			(const unsigned char *) input, strlen(input), &hashed, &hashed_len,
			&err) == FALSE) {
		oidc_error(r, "oidc_jose_hash_bytes returned an error: %s", err.text);
		return FALSE;
	}

	if (oidc_base64url_encode(r, output, (const char *) hashed, hashed_len,
			TRUE) <= 0) {
		oidc_error(r, "oidc_base64url_encode returned an error: %s", err.text);
		return FALSE;
	}
	return TRUE;
}

/*
 * merge two key sets
 */
apr_hash_t * oidc_util_merge_key_sets(apr_pool_t *pool, apr_hash_t *k1,
		apr_hash_t *k2) {
	if (k1 == NULL) {
		if (k2 == NULL)
			return apr_hash_make(pool);
		return k2;
	}
	if (k2 == NULL)
		return k1;
	return apr_hash_overlay(pool, k1, k2);
}

/*
 * regexp match
 */
#define OIDC_UTIL_REGEXP_MATCH_SIZE 30
#define OIDC_UTIL_REGEXP_MATCH_NR 1

apr_byte_t oidc_util_regexp_first_match(apr_pool_t *pool, const char *input,
		const char *regexp, char **output, char **error_str) {
	const char *errorptr;
	int erroffset;
	pcre *preg;
	int subStr[OIDC_UTIL_REGEXP_MATCH_SIZE];
	const char *psubStrMatchStr;

	preg = pcre_compile(regexp, 0, &errorptr, &erroffset, NULL);

	if (preg == NULL) {
		*error_str = apr_psprintf(pool,
				"pattern [%s] is not a valid regular expression", regexp);
		pcre_free(preg);
		return FALSE;
	}

	int rc = 0;
	if ((rc = pcre_exec(preg, NULL, input, (int) strlen(input), 0, 0, subStr,
			OIDC_UTIL_REGEXP_MATCH_SIZE)) < 0) {
		switch (rc) {
		case PCRE_ERROR_NOMATCH:
			*error_str = apr_pstrdup(pool, "string did not match the pattern");
			break;
		case PCRE_ERROR_NULL:
			*error_str = apr_pstrdup(pool, "something was null");
			break;
		case PCRE_ERROR_BADOPTION:
			*error_str = apr_pstrdup(pool, "a bad option was passed");
			break;
		case PCRE_ERROR_BADMAGIC:
			*error_str = apr_pstrdup(pool,
					"magic number bad (compiled re corrupt?)");
			break;
		case PCRE_ERROR_UNKNOWN_NODE:
			*error_str = apr_pstrdup(pool,
					"something kooky in the compiled re");
			break;
		case PCRE_ERROR_NOMEMORY:
			*error_str = apr_pstrdup(pool, "ran out of memory");
			break;
		default:
			*error_str = apr_psprintf(pool, "unknown error: %d", rc);
			break;
		}
		pcre_free(preg);
		return FALSE;
	}

	if (pcre_get_substring(input, subStr, rc, OIDC_UTIL_REGEXP_MATCH_NR,
			&(psubStrMatchStr)) <= 0) {
		*error_str = apr_psprintf(pool, "pcre_get_substring failed (rc=%d)",
				rc);
		pcre_free(preg);
		return FALSE;
	}

	*output = apr_pstrdup(pool, psubStrMatchStr);

	pcre_free_substring(psubStrMatchStr);
	pcre_free(preg);

	return TRUE;
}

int oidc_util_cookie_domain_valid(const char *hostname, char *cookie_domain) {
	char *p = NULL;
	char *check_cookie = cookie_domain;
	// Skip past the first char of a cookie_domain that starts
	// with a ".", ASCII 46
	if (check_cookie[0] == 46) {
		p = strstr(hostname, ++check_cookie);
	} else {
		p = strstr(hostname, check_cookie);
	}
	if ((p == NULL) || (apr_strnatcmp(check_cookie, p) != 0)) {
		return FALSE;
	}
	return TRUE;
}
