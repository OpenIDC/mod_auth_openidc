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
 * The contents of this file are the property of Ping Identity Corporation.
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
		int src_len) {
	// TODO: always padded now, do we need an option to remove the padding?
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
	*dst = enc;
	return enc_len;
}

/*
 * base64url decode a string
 */
int oidc_base64url_decode(request_rec *r, char **dst, const char *src,
		int padding) {
	// TODO: check base64url decoding/encoding code and look for alternatives?
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
	if (padding == 1) {
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
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	int crypted_len = strlen(src) + 1;
	unsigned char *crypted = oidc_crypto_aes_encrypt(r, c,
			(unsigned char *) src, &crypted_len);
	if (crypted == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_encrypt_base64url_encode_string: oidc_crypto_aes_encrypt failed");
		return -1;
	}
	return oidc_base64url_encode(r, dst, (const char *) crypted, crypted_len);
}

/*
 * decrypt and base64url decode a string
 */
int oidc_base64url_decode_decrypt_string(request_rec *r, char **dst,
		const char *src) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	char *decbuf = NULL;
	int dec_len = oidc_base64url_decode(r, &decbuf, src, 0);
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
 * get the URL that is currently being accessed
 * TODO: seems hard enough, maybe look for other existing code...?
 */
char *oidc_get_current_url(const request_rec *r, const oidc_cfg *c) {
	const apr_port_t port = r->connection->local_addr->port;
	char *scheme, *port_str = "", *url;
	apr_byte_t print_port = TRUE;
#ifdef APACHE2_0
	scheme = (char *) ap_http_method(r);
#else
	scheme = (char *) ap_http_scheme(r);
#endif
	if ((apr_strnatcmp(scheme, "https") == 0) && port == 443)
		print_port = FALSE;
	else if ((apr_strnatcmp(scheme, "http") == 0) && port == 80)
		print_port = FALSE;
	if (print_port)
		port_str = apr_psprintf(r->pool, ":%u", port);
	url = apr_pstrcat(r->pool, scheme, "://",
			apr_table_get(r->headers_in, "Host"), port_str, r->uri,
			(r->args != NULL && *r->args != '\0' ? "?" : ""), r->args, NULL);
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

	memcpy((curlBuffer->buf + curlBuffer->written), ptr, (nmemb*size));
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
	// TODO: handle arrays of strings?
	oidc_http_encode_t *ctx = (oidc_http_encode_t*) rec;
	const char *sep = apr_strnatcmp(ctx->encoded_params, "") == 0 ? "" : "&";
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, ctx->r,
			"oidc_http_add_post_param: adding parameter: %s=%s to %s (sep=%s)",
			key, value, ctx->encoded_params, sep);
	ctx->encoded_params = apr_psprintf(ctx->r->pool, "%s%s%s=%s",
			ctx->encoded_params, sep, oidc_util_escape_string(ctx->r, key),
			oidc_util_escape_string(ctx->r, value));
	return 1;
}

/*
 * add a JSON name/value pair
 */
static int oidc_http_add_json_param(void* rec, const char* key,
		const char* value) {
	oidc_http_encode_t *ctx = (oidc_http_encode_t*) rec;
	const char *sep = apr_strnatcmp(ctx->encoded_params, "") == 0 ? "" : ",";
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, ctx->r,
			"oidc_http_add_json_param: adding parameter: %s=%s to %s", key,
			value, ctx->encoded_params);
	if (value[0] == '[') {
		// TODO hacky hacky, we need an array so we already encoded it :-)
		ctx->encoded_params = apr_psprintf(ctx->r->pool, "%s%s\"%s\" : %s",
				ctx->encoded_params, sep, key, value);
	} else {
		ctx->encoded_params = apr_psprintf(ctx->r->pool, "%s%s\"%s\": \"%s\"",
				ctx->encoded_params, sep, key, value);
	}
	return 1;
}

/*
 * execute a HTTP (GET or POST) request
 */
apr_byte_t oidc_util_http_call(request_rec *r, const char *url, int action,
		const apr_table_t *params, const char *basic_auth,
		const char *bearer_token, int ssl_validate_server,
		const char **response, int timeout) {
	char curlError[CURL_ERROR_SIZE];
	oidc_curl_buffer curlBuffer;
	CURL *curl;
	struct curl_slist *h_list = NULL;
	int nr_of_params = (params != NULL) ? apr_table_elts(params)->nelts : 0;

	/* do some logging about the inputs */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_util_http_call: entering, url=%s, action=%d, #params=%d, basic_auth=%s, bearer_token=%s, ssl_validate_server=%d",
			url, action, nr_of_params, basic_auth, bearer_token,
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

	/* see if we need to add token in the Bearer Authorization header */
	if (bearer_token != NULL) {
		struct curl_slist *headers = NULL;
		headers = curl_slist_append(headers,
				apr_psprintf(r->pool, "Authorization: Bearer %s",
						bearer_token));
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	}

	/* see if we need to perform HTTP basic authentication to the remote site */
	if (basic_auth != NULL) {
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_easy_setopt(curl, CURLOPT_USERPWD, basic_auth);
	}

	/* the POST contents */
	oidc_http_encode_t data = { r, "" };

	if (action == OIDC_HTTP_POST_JSON) {

		/* POST JSON data */

		if (nr_of_params > 0) {

			/* add the parameters in JSON formatting */
			apr_table_do(oidc_http_add_json_param, &data, params, NULL);
			/* surround it by brackets to make it a valid JSON object */
			data.encoded_params = apr_psprintf(r->pool, "{ %s }",
					data.encoded_params);

			/* set the data and log the event */
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_util_http_call: setting JSON parameters: %s",
					data.encoded_params);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.encoded_params);
		}

		/* set HTTP method to POST */
		curl_easy_setopt(curl, CURLOPT_POST, 1);

		/* and overwrite the default url-form-encoded content-type */
//		h_list = curl_slist_append(h_list,
//				"Content-type: application/json; charset=UTF-8");
		h_list = curl_slist_append(h_list,
						"Content-type: application/json");

	} else if (action == OIDC_HTTP_POST_FORM) {

		/* POST url-form-encoded data */

		if (nr_of_params > 0) {

			apr_table_do(oidc_http_add_form_url_encoded_param, &data, params,
					NULL);

			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_util_http_call: setting post parameters: %s",
					data.encoded_params);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.encoded_params);
		} // else: probably should warn here...

		/* CURLOPT_POST needed at least to set: Content-Type: application/x-www-form-urlencoded */
		curl_easy_setopt(curl, CURLOPT_POST, 1);

	} else if (nr_of_params > 0) {

		/* HTTP GET with #params > 0 */

		apr_table_do(oidc_http_add_form_url_encoded_param, &data, params, NULL);
		const char *sep = strchr(url, '?') != NULL ? "&" : "?";
		url = apr_psprintf(r->pool, "%s%s%s", url, sep, data.encoded_params);

		/* log that the URL has changed now */
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_util_http_call: added query parameters to URL: %s", url);
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
 * set a cookie in the HTTP response headers
 */
void oidc_set_cookie(request_rec *r, const char *cookieName, const char *cookieValue) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	char *headerString, *currentCookies;

	/* construct the cookie value */
	headerString = apr_psprintf(r->pool, "%s=%s;Secure;Path=%s%s", cookieName,
			cookieValue, oidc_get_cookie_path(r),
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
			"oidc_set_cookie: adding outgoing header: Set-Cookie: %s",
			headerString);
}

/*
 * get a cookie from the HTTP request
 */
char *oidc_get_cookie(request_rec *r, char *cookieName) {
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
static apr_byte_t oidc_util_json_string_print(request_rec *r,
		apr_json_value_t *result, const char *key, const char *log) {
	apr_json_value_t *value = apr_hash_get(result->value.object, key,
			APR_HASH_KEY_STRING);
	if (value != NULL) {
		if (value->type == APR_JSON_STRING) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"%s: response contained a \"%s\" key with string value: \"%s\"",
					log, key, value->value.string.p);
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
static apr_byte_t oidc_util_check_json_error(request_rec *r,
		apr_json_value_t *json) {
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
		const char *str, apr_json_value_t **json) {

	/* decode the JSON contents of the buffer */
	if (apr_json_decode(json, str, strlen(str), r->pool) != APR_SUCCESS) {
		/* something went wrong */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_check_json_error: JSON parsing returned an error");
		return FALSE;
	}

	if ((*json == NULL) || ((*json)->type != APR_JSON_OBJECT)) {
		/* oops, no JSON */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_util_check_json_error: parsed JSON did not contain a JSON object");
		return FALSE;
	}

	// see if it is not an error response somehow
	if (oidc_util_check_json_error(r, *json) == TRUE)
		return FALSE;

	return TRUE;
}

/*
 * sends HTML content to the user agent
 */
int oidc_util_http_sendstring(request_rec *r, const char *html, int success_rvalue) {
	ap_set_content_type(r, "text/html");
	apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	apr_bucket *b = apr_bucket_transient_create(html, strlen(html), r->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, b);
	b = apr_bucket_eos_create(r->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, b);
	if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS)
		return HTTP_INTERNAL_SERVER_ERROR;
	//r->status = success_rvalue;
	return success_rvalue;
}

int oidc_base64url_decode_rsa_verify(request_rec *r, const char *alg, const char *signature, const char *message, const char *modulus, const char *exponent) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_base64url_decode_rsa_verify: alg = \"%s\"", alg);
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_base64url_decode_rsa_verify: signature = \"%s\"", signature);
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_base64url_decode_rsa_verify: message = \"%s\"", message);
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_base64url_decode_rsa_verify: modulus = \"%s\"", modulus);
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_base64url_decode_rsa_verify: exponent = \"%s\"", exponent);

	unsigned char *mod = NULL;
	int mod_len = oidc_base64url_decode(r, (char **)&mod, modulus, 1);

	unsigned char *exp = NULL;
	int exp_len = oidc_base64url_decode(r, (char **)&exp, exponent, 1);

	unsigned char *sig = NULL;
	int sig_len = oidc_base64url_decode(r, (char **)&sig, signature, 1);

	return oidc_crypto_rsa_verify(r, alg, sig, sig_len, (unsigned char *)message, strlen(message), mod, mod_len, exp, exp_len);
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
			memcpy((char*)*rbuf + rpos, argsbuffer, rsize);
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
 apr_byte_t oidc_util_generate_random_base64url_encoded_value(request_rec *r, int randomLen, char **randomB64) {
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
apr_byte_t oidc_util_file_read(request_rec *r, const char *path,
 		char **result) {
 	apr_file_t *fd = NULL;
 	apr_status_t rc = APR_SUCCESS;
 	char s_err[128];
 	apr_finfo_t finfo;

 	/* open the file if it exists */
 	if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED,
 			APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
 		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
 				"oidc_util_file_read: no file found at: \"%s\"",
 				path);
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
int oidc_util_html_send_error(request_rec *r, const char *error, const char *description, int status_code) {
	char *msg = "<p>the OpenID Connect Provider returned an error:</p><p>";

	if (error != NULL) {
		msg = apr_psprintf(r->pool, "%s<p>Error: <pre>%s</pre></p>", msg,
				error);
	}
	if (description != NULL) {
		msg = apr_psprintf(r->pool, "%s<p>Description: <pre>%s</pre></p>",
				msg, description);
	}

	return oidc_util_http_sendstring(r, msg, status_code);
}

/*
 * see if a certain string value is part of a JSON array with string elements
 */
apr_byte_t oidc_util_json_array_has_value(request_rec *r,
		apr_json_value_t *haystack, const char *needle) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_util_json_array_has_value: entering (%s)", needle);

	if ( (haystack == NULL) || (haystack->type != APR_JSON_ARRAY) ) return FALSE;

	int i;
	for (i = 0; i < haystack->value.array->nelts; i++) {
		apr_json_value_t *elem = APR_ARRAY_IDX(haystack->value.array, i,
				apr_json_value_t *);
		if (elem->type != APR_JSON_STRING) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_util_json_array_has_value: unhandled in-array JSON non-string object type [%d]",
					elem->type);
			continue;
		}
		if (strcmp(elem->value.string.p, needle) == 0) {
			break;
		}
	}

//	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
//			"oidc_util_json_array_has_value: returning (%d=%d)", i,
//			haystack->value.array->nelts);

	return (i == haystack->value.array->nelts) ? FALSE : TRUE;
}
