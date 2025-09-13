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

#include "mod_auth_openidc.h"
#include "util/util.h"

#include "http.h"

/*
 * HTML escape a string
 */
char *oidc_util_html_escape(apr_pool_t *pool, const char *s) {
	// TODO: this has performance/memory issues for large chunks of HTML
	const char chars[6] = {'&', '\'', '\"', '>', '<', '\0'};
	const char *const replace[] = {
	    "&amp;", "&apos;", "&quot;", "&gt;", "&lt;",
	};
	unsigned int i = 0;
	unsigned int j = 0;
	unsigned int k = 0;
	unsigned int n = 0;
	unsigned int m = 0;
	const char *ptr = chars;
	unsigned int len = _oidc_strlen(ptr);
	char *r = apr_pcalloc(pool, _oidc_strlen(s) * 6 + 1);
	for (i = 0; i < _oidc_strlen(s); i++) {
		for (n = 0; n < len; n++) {
			if (s[i] == chars[n]) {
				m = (unsigned int)_oidc_strlen(replace[n]);
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
 * JavaScript escape a string
 */
char *oidc_util_html_javascript_escape(apr_pool_t *pool, const char *s) {
	const char *cp = NULL;
	char *output = NULL;
	int outputlen = 0;
	int i = 0;

	if (s == NULL) {
		return NULL;
	}

	outputlen = 0;
	for (cp = s; *cp; cp++) {
		switch (*cp) {
		case '\'':
		case '"':
		case '\\':
		case '/':
		case 0x0D:
		case 0x0A:
			outputlen += 2;
			break;
		case '<':
		case '>':
			outputlen += 4;
			break;
		default:
			outputlen += 1;
			break;
		}
	}

	i = 0;
	output = apr_pcalloc(pool, outputlen + 1);
	for (cp = s; *cp; cp++) {
		switch (*cp) {
		case '\'':
			if (i <= outputlen - 2)
				(void)_oidc_strcpy(&output[i], "\\'");
			i += 2;
			break;
		case '"':
			if (i <= outputlen - 2)
				(void)_oidc_strcpy(&output[i], "\\\"");
			i += 2;
			break;
		case '\\':
			if (i <= outputlen - 2)
				(void)_oidc_strcpy(&output[i], "\\\\");
			i += 2;
			break;
		case '/':
			if (i <= outputlen - 2)
				(void)_oidc_strcpy(&output[i], "\\/");
			i += 2;
			break;
		case 0x0D:
			if (i <= outputlen - 2)
				(void)_oidc_strcpy(&output[i], "\\r");
			i += 2;
			break;
		case 0x0A:
			if (i <= outputlen - 2)
				(void)_oidc_strcpy(&output[i], "\\n");
			i += 2;
			break;
		case '<':
			if (i <= outputlen - 4)
				(void)_oidc_strcpy(&output[i], "\\x3c");
			i += 4;
			break;
		case '>':
			if (i <= outputlen - 4)
				(void)_oidc_strcpy(&output[i], "\\x3e");
			i += 4;
			break;
		default:
			if (i <= outputlen - 1)
				output[i] = *cp;
			i += 1;
			break;
		}
	}
	output[i] = '\0';
	return output;
}

/*
 * send HTML content to the user agent
 */
int oidc_util_html_send(request_rec *r, const char *title, const char *html_head, const char *on_load,
			const char *html_body, int status_code) {

	char *html = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n"
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

	html = apr_psprintf(r->pool, html, title ? oidc_util_html_escape(r->pool, title) : "",
			    html_head ? html_head : "", on_load ? apr_psprintf(r->pool, " onload=\"%s\"", on_load) : "",
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
		html = apr_psprintf(r->pool, *static_template_content, oidc_util_template_escape(r, arg1, arg1_esc),
				    oidc_util_template_escape(r, arg2, arg2_esc));
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
