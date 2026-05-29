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

#include "mod_auth_openidc.h"
#include "util/util.h"

#include "http.h"

/*
 * return the HTML escape sequence for a character, or NULL if the character passes through unchanged
 */
static const char *oidc_util_html_escape_char(char c) {
	switch (c) {
	case '&':
		return "&amp;";
	case '\'':
		return "&apos;";
	case '"':
		return "&quot;";
	case '>':
		return "&gt;";
	case '<':
		return "&lt;";
	default:
		return NULL;
	}
}

/*
 * HTML escape a string
 */
char *oidc_util_html_escape(apr_pool_t *pool, const char *s) {
	const char *cp = NULL;
	size_t outputlen = 0;
	size_t i = 0;

	if (s == NULL)
		s = "";

	/* first pass: compute the length of the escaped output */
	for (cp = s; *cp; cp++) {
		const char *esc = oidc_util_html_escape_char(*cp);
		outputlen += esc ? _oidc_strlen(esc) : 1;
	}

	/* second pass: write the escaped output, preserving the bounds-checked write idiom */
	char *output = apr_pcalloc(pool, outputlen + 1);
	for (cp = s; *cp; cp++) {
		const char *esc = oidc_util_html_escape_char(*cp);
		if (esc == NULL) {
			if (i + 1 <= outputlen)
				output[i] = *cp;
			i += 1;
			continue;
		}
		size_t n = _oidc_strlen(esc);
		if (i + n <= outputlen)
			(void)_oidc_strcpy(&output[i], esc);
		i += n;
	}
	output[i] = '\0';
	return output;
}

/*
 * return the JavaScript escape sequence for a character, or NULL if the character passes through unchanged
 */
static const char *oidc_util_html_javascript_escape_char(char c) {
	switch (c) {
	case '\'':
		return "\\'";
	case '"':
		return "\\\"";
	case '\\':
		return "\\\\";
	case '/':
		return "\\/";
	case 0x0D:
		return "\\r";
	case 0x0A:
		return "\\n";
	case '<':
		return "\\x3c";
	case '>':
		return "\\x3e";
	default:
		return NULL;
	}
}

/*
 * JavaScript escape a string
 */
char *oidc_util_html_javascript_escape(apr_pool_t *pool, const char *s) {
	const char *cp = NULL;
	size_t outputlen = 0;
	size_t i = 0;

	if (s == NULL)
		return NULL;

	/* first pass: compute the length of the escaped output */
	for (cp = s; *cp; cp++) {
		const char *esc = oidc_util_html_javascript_escape_char(*cp);
		outputlen += esc ? _oidc_strlen(esc) : 1;
	}

	/* second pass: write the escaped output, preserving the bounds-checked write idiom */
	char *output = apr_pcalloc(pool, outputlen + 1);
	for (cp = s; *cp; cp++) {
		const char *esc = oidc_util_html_javascript_escape_char(*cp);
		if (esc == NULL) {
			if (i + 1 <= outputlen)
				output[i] = *cp;
			i += 1;
			continue;
		}
		size_t n = _oidc_strlen(esc);
		if (i + n <= outputlen)
			(void)_oidc_strcpy(&output[i], esc);
		i += n;
	}
	output[i] = '\0';
	return output;
}

/*
 * send HTML content to the user agent
 */
int oidc_util_html_send(request_rec *r, const char *title, const char *html_head, const char *on_load,
			const char *html_body, int status_code) {

	static const char html_tmpl[] =
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

	/*
	 * on_load is rendered as the value of an HTML onload="..." attribute. The
	 * caller is expected to pass trusted JavaScript (a function call literal),
	 * but HTML-escape it as defense-in-depth: HTML entities in attribute
	 * values are decoded by the browser before the JS is executed, so
	 * legitimate values keep working while a stray quote can't break out of
	 * the attribute into the surrounding markup.
	 */
	char *html = apr_psprintf(
	    r->pool, html_tmpl, title ? oidc_util_html_escape(r->pool, title) : "", html_head ? html_head : "",
	    on_load ? apr_psprintf(r->pool, " onload=\"%s\"", oidc_util_html_escape(r->pool, on_load)) : "",
	    html_body ? html_body : "<p></p>");

	return oidc_util_http_send(r, html, _oidc_strlen(html), OIDC_HTTP_CONTENT_TYPE_TEXT_HTML, status_code);
}

/*
 * called from the authentication handler:
 * prepares HTML to be sent to the user agent in the content handler
 */
int oidc_util_html_content_prep(request_rec *r, const char *request_state_key, const char *title, const char *html_head,
				const char *on_load, const char *html_body) {
	/* store title, head, on_load function and body in the request state, possibly deleting leftovers from a
	 * previous request */
	oidc_request_state_set(r, "title", NULL);
	if (title)
		oidc_request_state_set(r, "title", title);
	oidc_request_state_set(r, "head", NULL);
	if (html_head)
		oidc_request_state_set(r, "head", html_head);
	oidc_request_state_set(r, "on_load", NULL);
	if (on_load)
		oidc_request_state_set(r, "on_load", on_load);
	oidc_request_state_set(r, "body", NULL);
	if (html_body)
		oidc_request_state_set(r, "body", html_body);
	/* signal that there's HTML data for a specific routine to be sent in the content handler */
	oidc_request_state_set(r, request_state_key, "");
	/* make sure that we pass the authorization phase since we have to return data from the content handler */
	r->user = "";
	/* return OK to make sure that we continue in the content handler */
	return OK;
}

/*
 * called from the content handler:
 * sends HTML content that was prepared in oidc_util_html_content_prep to the user agent
 */
int oidc_util_html_content_send(request_rec *r) {
	const char *title = oidc_request_state_get(r, "title");
	const char *html_head = oidc_request_state_get(r, "head");
	const char *on_load = oidc_request_state_get(r, "on_load");
	const char *html_body = oidc_request_state_get(r, "body");
	return oidc_util_html_send(r, title, html_head, on_load, html_body, OK);
}

/*
 * escape characters in an HTML/Javascript template
 */
static char *oidc_util_template_escape(request_rec *r, const char *arg, int escape) {
	char *rv = NULL;
	if (escape == OIDC_POST_PRESERVE_ESCAPE_HTML) {
		rv = oidc_util_html_escape(r->pool, arg ? arg : "");
	} else if (escape == OIDC_POST_PRESERVE_ESCAPE_JAVASCRIPT) {
		rv = oidc_util_html_javascript_escape(r->pool, arg ? arg : "");
	} else {
		rv = apr_pstrdup(r->pool, arg);
	}
	return rv;
}

/*
 * verify that a template contains only safe printf-style specifiers (%s and
 * %%) and exactly the expected number of %s placeholders; reject anything
 * else to avoid passing surprising specifiers (%n, %x, ...) to apr_psprintf
 */
static apr_byte_t oidc_util_template_format_valid(const char *tpl, int expected_s_count) {
	int s_count = 0;
	const char *p;
	for (p = tpl; *p; p++) {
		if (*p != '%')
			continue;
		p++;
		if (*p == '%')
			continue;
		if (*p == 's') {
			s_count++;
			continue;
		}
		return FALSE;
	}
	return (s_count == expected_s_count) ? TRUE : FALSE;
}

/*
 * fill and send a HTML template
 */
int oidc_util_html_send_in_template(request_rec *r, const char *filename, char **static_template_content,
				    const char *arg1, int arg1_esc, const char *arg2, int arg2_esc) {
	char *html = NULL;
	int rc = OK;
	if (*static_template_content == NULL) {
		// NB: templates go into the server process pool
		if (oidc_util_file_read(r, filename, r->server->process->pool, static_template_content) == FALSE) {
			oidc_error(r, "could not read template: %s", filename);
			*static_template_content = NULL;
		}
	}
	if (*static_template_content) {
		if (oidc_util_template_format_valid(*static_template_content, (arg2 == NULL) ? 1 : 2) == FALSE) {
			oidc_error(r,
				   "template %s contains format specifiers other than two \"%%s\" placeholders; "
				   "refusing to render",
				   filename);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		html = apr_psprintf(r->pool, *static_template_content, oidc_util_template_escape(r, arg1, arg1_esc),
				    (arg2 != NULL) ? oidc_util_template_escape(r, arg2, arg2_esc) : "");
		rc = oidc_util_http_content_prep(r, html, _oidc_strlen(html), OIDC_HTTP_CONTENT_TYPE_TEXT_HTML);
	}
	return rc;
}

/*
 * send a user-facing error to the browser
 */
int oidc_util_html_send_error(request_rec *r, const char *error, const char *description, int status_code) {

	oidc_debug(r, "setting " OIDC_ERROR_ENVVAR " environment variable to: %s", error);
	apr_table_set(r->subprocess_env, OIDC_ERROR_ENVVAR, error ? error : "");

	oidc_debug(r, "setting " OIDC_ERROR_DESC_ENVVAR " environment variable to: %s", description);
	apr_table_set(r->subprocess_env, OIDC_ERROR_DESC_ENVVAR, description ? description : "");

	return status_code;
}
