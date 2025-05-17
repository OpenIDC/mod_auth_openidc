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

#include "util/util.h"
#include "mod_auth_openidc.h"

#include <apr_lib.h>

#include <http_protocol.h>

/*
 * convert a character to an ENVIRONMENT-variable-safe variant
 */
static int oidc_util_char_to_env(int c) {
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
int oidc_util_strnenvcmp(const char *a, const char *b, int len) {
	int d = 0;
	int i = 0;
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
		d = oidc_util_char_to_env(*a) - oidc_util_char_to_env(*b);
		if (d)
			return d;

		a++;
		b++;
		i++;
	}
}

/*
 * JavaScript escape a string
 */
char *oidc_util_javascript_escape(apr_pool_t *pool, const char *s) {
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
 * find a needle (s2) in a haystack (s1) using case-insensitive string compare
 */
const char *oidc_util_strcasestr(const char *s1, const char *s2) {
	const char *s = s1;
	const char *p = s2;
	if ((s == NULL) || (p == NULL))
		return NULL;
	do {
		if (!*p)
			return s1;
		if ((*p == *s) || (tolower(*p) == tolower(*s))) {
			++p;
			++s;
		} else {
			p = s2;
			if (!*s)
				return NULL;
			s = ++s1;
		}
	} while (1);
}

/*
 * sends data to the user agent
 */
int oidc_util_http_send(request_rec *r, const char *data, size_t data_len, const char *content_type,
			int success_rvalue) {
	ap_set_content_type(r, content_type);
	apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	apr_bucket *b = apr_bucket_transient_create(data, data_len, r->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, b);
	b = apr_bucket_eos_create(r->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, b);
	int rc = ap_pass_brigade(r->output_filters, bb);
	if (rc != APR_SUCCESS) {
		oidc_error(r,
			   "ap_pass_brigade returned an error: %d; if you're using this module combined with "
			   "mod_deflate try make an exception for the " OIDCRedirectURI
			   " e.g. using SetEnvIf Request_URI <url> no-gzip",
			   rc);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	/*
	 *r->status = success_rvalue;
	 */

	if ((success_rvalue == OK) && (r->user == NULL)) {
		/*
		 * satisfy Apache 2.4 mod_authz_core:
		 * prevent it to return HTTP 500 after sending content
		 */
		r->user = "";
	}

	return success_rvalue;
}

/*
 * called from the authentication handler:
 * prepares data to be sent to the user agent in the content handler
 */
int oidc_util_http_content_prep(request_rec *r, const char *data, size_t data_len, const char *content_type) {
	/* store data, data_len and content-type in the request state, possibly deleting leftovers from a previous
	 * request */
	oidc_request_state_set(r, "data", NULL);
	if (data)
		oidc_request_state_set(r, "data", data);
	oidc_request_state_set(r, "data_len", NULL);
	if (data_len)
		oidc_request_state_set(r, "data_len", apr_psprintf(r->pool, "%d", (int)data_len));
	oidc_request_state_set(r, "content_type", NULL);
	if (content_type)
		oidc_request_state_set(r, "content_type", content_type);
	/* signal that there's HTTP data to be sent in the content handler */
	oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_HTTP, "");
	/* make sure that we pass the authorization phase since we have to return data from the content handler */
	r->user = "";
	/* return OK to make sure that we continue in the content handler */
	return OK;
}

/*
 * called from the content handler:
 * sends data that was prepared in oidc_util_http_content_prep to the user agent
 */
int oidc_util_http_content_send(request_rec *r) {
	const char *data = oidc_request_state_get(r, "data");
	int data_len = _oidc_str_to_int(oidc_request_state_get(r, "data_len"), 0);
	const char *content_type = oidc_request_state_get(r, "content_type");
	return oidc_util_http_send(r, data, data_len, content_type, OK);
}

/* the maximum size of data that we accept in a single POST value: 1MB */
#define OIDC_MAX_POST_DATA_LEN 1024 * 1024

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
		oidc_error(r, "POST parameter value is too large: %lu bytes (max=%d)", (unsigned long)len,
			   OIDC_MAX_POST_DATA_LEN);
		return FALSE;
	}

	*rbuf = (char *)apr_palloc(r->pool, len + 1);
	if (*rbuf == NULL) {
		oidc_error(r, "could not allocate memory for %lu bytes of POST data.", (unsigned long)len);
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
			oidc_error(r, "failed to read POST data from client");
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
apr_byte_t oidc_util_read_form_encoded_params(request_rec *r, apr_table_t *table, char *data) {
	const char *key = NULL;
	const char *val = NULL;
	const char *p = data;

	while (p && (*p)) {
		val = ap_getword(r->pool, &p, OIDC_CHAR_AMP);
		if (val == NULL)
			break;
		key = ap_getword(r->pool, &val, OIDC_CHAR_EQUAL);
		key = oidc_http_url_decode(r, key);
		val = oidc_http_url_decode(r, val);
		oidc_debug(r, "read: %s=%s", key, val);
		apr_table_set(table, key, val);
	}

	oidc_debug(r, "parsed: %d bytes into %d elements", data ? (int)_oidc_strlen(data) : 0,
		   apr_table_elts(table)->nelts);

	return TRUE;
}

static void oidc_util_userdata_set_post_param(request_rec *r, const char *post_param_name,
					      const char *post_param_value) {
	apr_table_t *userdata_post_params = NULL;
	apr_pool_userdata_get((void **)&userdata_post_params, OIDC_USERDATA_POST_PARAMS_KEY, r->pool);
	if (userdata_post_params == NULL)
		userdata_post_params = apr_table_make(r->pool, 1);
	apr_table_set(userdata_post_params, post_param_name, post_param_value);
	apr_pool_userdata_set(userdata_post_params, OIDC_USERDATA_POST_PARAMS_KEY, NULL, r->pool);
}

/*
 * read the POST parameters in to a table
 */
apr_byte_t oidc_util_read_post_params(request_rec *r, apr_table_t *table, apr_byte_t propagate,
				      const char *strip_param_name) {
	apr_byte_t rc = FALSE;
	char *data = NULL;
	const apr_array_header_t *arr = NULL;
	const apr_table_entry_t *elts = NULL;
	int i = 0;
	const char *content_type = NULL;

	content_type = oidc_http_hdr_in_content_type_get(r);
	if ((r->method_number != M_POST) || (content_type == NULL) ||
	    (_oidc_strstr(content_type, OIDC_HTTP_CONTENT_TYPE_FORM_ENCODED) != content_type)) {
		oidc_debug(r, "required content-type %s not found", OIDC_HTTP_CONTENT_TYPE_FORM_ENCODED);
		goto end;
	}

	if (oidc_util_read(r, &data) != TRUE)
		goto end;

	rc = oidc_util_read_form_encoded_params(r, table, data);
	if (rc != TRUE)
		goto end;

	if (propagate == FALSE)
		goto end;

	arr = apr_table_elts(table);
	elts = (const apr_table_entry_t *)arr->elts;
	for (i = 0; i < arr->nelts; i++)
		if (_oidc_strcmp(elts[i].key, strip_param_name) != 0)
			oidc_util_userdata_set_post_param(r, elts[i].key, elts[i].val);

end:

	return rc;
}

/*
 * read a file from a path on disk
 */
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, apr_pool_t *pool, char **result) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];
	apr_finfo_t finfo;

	/* open the file if it exists */
	if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED, APR_OS_DEFAULT, r->pool)) !=
	    APR_SUCCESS) {
		oidc_warn(r, "no file found at: \"%s\" (%s)", path, apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the cache file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* get the file info so we know its size */
	if ((rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd)) != APR_SUCCESS) {
		oidc_error(r, "error calling apr_file_info_get on file: \"%s\" (%s)", path,
			   apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* now that we have the size of the file, allocate a buffer that can contain its contents */
	*result = apr_palloc(pool, finfo.size + 1);

	/* read the file in to the buffer */
	apr_size_t bytes_read = 0;
	if ((rc = apr_file_read_full(fd, *result, finfo.size, &bytes_read)) != APR_SUCCESS) {
		oidc_error(r, "apr_file_read_full on (%s) returned an error: %s", path,
			   apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* just to be sure, we set a \0 (we allocated space for it anyway) */
	(*result)[bytes_read] = '\0';

	/* check that we've got all of it */
	if (bytes_read != finfo.size) {
		oidc_error(r,
			   "apr_file_read_full on (%s) returned less bytes (%" APR_SIZE_T_FMT
			   ") than expected: (%" APR_OFF_T_FMT ")",
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
 * write data to a file
 */
apr_byte_t oidc_util_file_write(request_rec *r, const char *path, const char *data) {

	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_written = 0;
	char s_err[128];

	/* try to open the metadata file for writing, creating it if it does not exist */
	if ((rc = apr_file_open(&fd, path, (APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE), APR_OS_DEFAULT,
				r->pool)) != APR_SUCCESS) {
		oidc_error(r, "file \"%s\" could not be opened (%s)", path, apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* lock the file and move the write pointer to the start of it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* calculate the length of the data, which is a string length */
	apr_size_t len = _oidc_strlen(data);

	/* (blocking) write the number of bytes in the buffer */
	rc = apr_file_write_full(fd, data, len, &bytes_written);

	/* check for a system error */
	if (rc != APR_SUCCESS) {
		oidc_error(r, "could not write to: \"%s\" (%s)", path, apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* check that all bytes from the header were written */
	if (bytes_written != len) {
		oidc_error(r,
			   "could not write enough bytes to: \"%s\", bytes_written (%" APR_SIZE_T_FMT
			   ") != len (%" APR_SIZE_T_FMT ")",
			   path, bytes_written, len);
		return FALSE;
	}

	/* unlock and close the written file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	oidc_debug(r, "file \"%s\" written; number of bytes (%" APR_SIZE_T_FMT ")", path, len);

	return TRUE;
}

/*
 * see if two provided issuer identifiers match (cq. ignore trailing slash)
 */
apr_byte_t oidc_util_issuer_match(const char *a, const char *b) {

	/* check the "issuer" value against the one configure for the provider we got this id_token from */
	if (_oidc_strcmp(a, b) != 0) {

		/* no strict match, but we are going to accept if the difference is only a trailing slash */
		int n1 = _oidc_strlen(a);
		int n2 = _oidc_strlen(b);
		int n = ((n1 == n2 + 1) && (a[n1 - 1] == OIDC_CHAR_FORWARD_SLASH))
			    ? n2
			    : (((n2 == n1 + 1) && (b[n2 - 1] == OIDC_CHAR_FORWARD_SLASH)) ? n1 : 0);
		if ((n == 0) || (_oidc_strncmp(a, b, n) != 0))
			return FALSE;
	}

	return TRUE;
}

/*
 * convert a claim value from UTF-8 to the Latin1 character set
 */
static char *oidc_util_utf8_to_latin1(request_rec *r, const char *src) {
	char *dst = NULL;
	unsigned int cp = 0;
	unsigned char ch;
	int i = 0;
	if (src == NULL)
		return NULL;
	dst = apr_pcalloc(r->pool, _oidc_strlen(src) + 1);
	while (*src != '\0') {
		ch = (unsigned char)(*src);
		if (ch <= 0x7f)
			cp = ch;
		else if (ch <= 0xbf)
			cp = (cp << 6) | (ch & 0x3f);
		else if (ch <= 0xdf)
			cp = ch & 0x1f;
		else if (ch <= 0xef)
			cp = ch & 0x0f;
		else
			cp = ch & 0x07;
		++src;
		if (((*src & 0xc0) != 0x80) && (cp <= 0x10ffff)) {
			if (cp <= 255) {
				dst[i] = (unsigned char)cp;
			} else {
				// no encoding possible
				dst[i] = '?';
			}
			i++;
		}
	}
	dst[i] = '\0';
	return dst;
}

/*
 * set a HTTP header and/or environment variable to pass information to the application
 */
void oidc_util_set_app_info(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix,
			    oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding) {

	/* construct the header name, cq. put the prefix in front of a normalized key name */
	const char *s_name = apr_psprintf(r->pool, "%s%s", claim_prefix, oidc_http_hdr_normalize_name(r, s_key));
	char *d_value = NULL;

	if (s_value != NULL) {
		if (encoding == OIDC_APPINFO_ENCODING_BASE64URL) {
			oidc_util_base64url_encode(r, &d_value, s_value, _oidc_strlen(s_value), TRUE);
		} else if (encoding == OIDC_APPINFO_ENCODING_LATIN1) {
			d_value = oidc_util_utf8_to_latin1(r, s_value);
		}
	}

	if (pass_in & OIDC_APPINFO_PASS_HEADERS) {
		oidc_http_hdr_in_set(r, s_name, (d_value != NULL) ? d_value : s_value);
	}

	if (pass_in & OIDC_APPINFO_PASS_ENVVARS) {

		/* do some logging about this event */
		oidc_debug(r, "setting environment variable \"%s: %s\"", s_name, (d_value != NULL) ? d_value : s_value);

		apr_table_set(r->subprocess_env, s_name, (d_value != NULL) ? d_value : s_value);
	}
}

/*
 * set the user/claims information from the session in HTTP headers passed on to the application
 */
void oidc_util_set_app_infos(request_rec *r, json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter,
			     oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding) {

	char s_int[255];
	json_t *j_value = NULL;
	const char *s_key = NULL;

	/* if not attributes are set, nothing needs to be done */
	if (j_attrs == NULL) {
		oidc_debug(r, "no attributes to set");
		return;
	}

	/* loop over the claims in the JSON structure */
	void *iter = json_object_iter((json_t *)j_attrs);
	while (iter) {

		/* get the next key/value entry */
		s_key = json_object_iter_key(iter);
		j_value = json_object_iter_value(iter);

		/* check if it is a single value string */
		if (json_is_string(j_value)) {

			/* set the single string in the application header whose name is based on the key and the prefix
			 */
			oidc_util_set_app_info(r, s_key, json_string_value(j_value), claim_prefix, pass_in, encoding);

		} else if (json_is_boolean(j_value)) {

			/* set boolean value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(r, s_key, (json_is_true(j_value) ? "1" : "0"), claim_prefix, pass_in,
					       encoding);

		} else if (json_is_integer(j_value)) {

			if (snprintf(s_int, 255, "%ld", (long)json_integer_value(j_value)) > 0) {
				/* set long value in the application header whose name is based on the key and the
				 * prefix */
				oidc_util_set_app_info(r, s_key, s_int, claim_prefix, pass_in, encoding);
			} else {
				oidc_warn(r, "could not convert JSON number to string (> 255 characters?), skipping");
			}

		} else if (json_is_real(j_value)) {

			/* set float value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(r, s_key, apr_psprintf(r->pool, "%lf", json_real_value(j_value)),
					       claim_prefix, pass_in, encoding);

		} else if (json_is_object(j_value)) {

			/* set json value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(
			    r, s_key, oidc_util_json_encode(r->pool, j_value, JSON_PRESERVE_ORDER | JSON_COMPACT),
			    claim_prefix, pass_in, encoding);

			/* check if it is a multi-value string */
		} else if (json_is_array(j_value)) {

			/* some logging about what we're going to do */
			oidc_debug(r, "parsing attribute array for key \"%s\" (#nr-of-elems: %lu)", s_key,
				   (unsigned long)json_array_size(j_value));

			/* string to hold the concatenated array string values */
			char *s_concat = apr_pstrdup(r->pool, "");
			size_t i = 0;

			/* loop over the array */
			for (i = 0; i < json_array_size(j_value); i++) {

				/* get the current element */
				json_t *elem = json_array_get(j_value, i);

				/* check if it is a string */
				if (json_is_string(elem)) {

					/* concatenate the string to the s_concat value using the configured separator
					 * char */
					// TODO: escape the delimiter in the values (maybe reuse/extract url-formatted
					// code from oidc_session_identity_encode)
					if (_oidc_strcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat, claim_delimiter,
									json_string_value(elem));
					} else {
						s_concat = apr_psprintf(r->pool, "%s", json_string_value(elem));
					}

				} else if (json_is_boolean(elem)) {

					if (_oidc_strcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat, claim_delimiter,
									json_is_true(elem) ? "1" : "0");
					} else {
						s_concat = apr_psprintf(r->pool, "%s", json_is_true(elem) ? "1" : "0");
					}

				} else {

					/* don't know how to handle a non-string array element */
					oidc_debug(r,
						   "unhandled in-array JSON object type [%d] for key \"%s\" when "
						   "parsing claims array elements",
						   elem->type, s_key);
				}
			}

			/* set the concatenated string */
			oidc_util_set_app_info(r, s_key, s_concat, claim_prefix, pass_in, encoding);

		} else {

			/* no string and no array, so unclear how to handle this */
			oidc_debug(r, "unhandled JSON object type [%d] for key \"%s\" when parsing claims",
				   j_value->type, s_key);
		}

		iter = json_object_iter_next(j_attrs, iter);
	}
}

/*
 * parse a space separated string in to a hash table
 */
apr_hash_t *oidc_util_spaced_string_to_hashtable(apr_pool_t *pool, const char *str) {
	char *val;
	const char *data = apr_pstrdup(pool, str);
	apr_hash_t *result = apr_hash_make(pool);
	while (data && (*data)) {
		val = ap_getword_white(pool, &data);
		if (val == NULL)
			break;
		apr_hash_set(result, val, APR_HASH_KEY_STRING, val);
	}
	return result;
}

/*
 * compare two space separated value types
 */
apr_byte_t oidc_util_spaced_string_equals(apr_pool_t *pool, const char *a, const char *b) {

	const void *k = NULL;
	void *v = NULL;

	/* parse both entries as hash tables */
	apr_hash_t *ht_a = oidc_util_spaced_string_to_hashtable(pool, a);
	apr_hash_t *ht_b = oidc_util_spaced_string_to_hashtable(pool, b);

	/* first compare the length of both response_types */
	if (apr_hash_count(ht_a) != apr_hash_count(ht_b))
		return FALSE;

	/* then loop over all entries */
	apr_hash_index_t *hi;
	for (hi = apr_hash_first(NULL, ht_a); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, &k, NULL, &v);
		if (apr_hash_get(ht_b, k, APR_HASH_KEY_STRING) == NULL)
			return FALSE;
	}

	/* if we've made it this far, a an b are equal in length and every element in a is in b */
	return TRUE;
}

/*
 * see if a particular value is part of a space separated value
 */
apr_byte_t oidc_util_spaced_string_contains(apr_pool_t *pool, const char *str, const char *match) {
	apr_hash_t *ht = oidc_util_spaced_string_to_hashtable(pool, str);
	return (apr_hash_get(ht, match, APR_HASH_KEY_STRING) != NULL);
}

/*
 * add query encoded parameters to a table
 */
void oidc_util_table_add_query_encoded_params(apr_pool_t *pool, apr_table_t *table, const char *params) {
	char *key = NULL;
	char *value = NULL;
	const char *v = NULL;
	const char *p = params;
	while (p && (*p)) {
		v = ap_getword(pool, &p, OIDC_CHAR_AMP);
		if (v == NULL)
			break;
		key = apr_pstrdup(pool, ap_getword(pool, &v, OIDC_CHAR_EQUAL));
		ap_unescape_url(key);
		value = apr_pstrdup(pool, v);
		ap_unescape_url(value);
		apr_table_addn(table, key, value);
	}
}

/*
 * openssl hash and base64 encode
 */
apr_byte_t oidc_util_hash_string_and_base64url_encode(request_rec *r, const char *openssl_hash_algo, const char *input,
						      char **output) {
	oidc_jose_error_t err;
	unsigned char *hashed = NULL;
	unsigned int hashed_len = 0;
	if (oidc_jose_hash_bytes(r->pool, openssl_hash_algo, (const unsigned char *)input, _oidc_strlen(input), &hashed,
				 &hashed_len, &err) == FALSE) {
		oidc_error(r, "oidc_jose_hash_bytes returned an error: %s", err.text);
		return FALSE;
	}

	if (oidc_util_base64url_encode(r, output, (const char *)hashed, hashed_len, TRUE) <= 0) {
		oidc_error(r, "oidc_base64url_encode returned an error: %s", err.text);
		return FALSE;
	}
	return TRUE;
}

/*
 * check if the provided cookie domain value is valid
 */
apr_byte_t oidc_util_cookie_domain_valid(const char *hostname, const char *cookie_domain) {
	const char *p = NULL;
	const char *check_cookie = cookie_domain;
	// Skip past the first char of a cookie_domain that starts
	// with a ".", ASCII 46
	if (check_cookie[0] == 46)
		check_cookie++;
	p = oidc_util_strcasestr(hostname, check_cookie);

	if ((p == NULL) || (_oidc_strnatcasecmp(check_cookie, p) != 0)) {
		return FALSE;
	}
	return TRUE;
}

#define OIDC_TP_TRACE_ID_LEN 16
#define OIDC_TP_PARENT_ID_LEN 8

/*
The following version-format definition is used for version 00.
version-format   = trace-id "-" parent-id "-" trace-flags
trace-id         = 32HEXDIGLC  ; 16 bytes array identifier. All zeroes forbidden
parent-id        = 16HEXDIGLC  ; 8 bytes array identifier. All zeroes forbidden
trace-flags      = 2HEXDIGLC   ; 8 bit flags. Currently, only one bit is used.
 */
void oidc_util_set_trace_parent(request_rec *r, oidc_cfg_t *c, const char *span) {
	// apr_table_get(r->subprocess_env, "UNIQUE_ID");
	unsigned char trace_id[OIDC_TP_TRACE_ID_LEN];
	unsigned char parent_id[OIDC_TP_PARENT_ID_LEN];
	unsigned char trace_flags = 0;
	char *s_parent_id = "", *s_trace_id = "";
	const char *v = NULL;
	int i = 0;
	char *hostname = "localhost";
	const uint64_t P1 = 7;
	const uint64_t P2 = 31;
	uint64_t hash = P1;

	if (oidc_cfg_trace_parent_get(c) != OIDC_TRACE_PARENT_GENERATE)
		return;

	if (r->server->server_hostname)
		hostname = r->server->server_hostname;

	v = oidc_request_state_get(r, OIDC_REQUEST_STATE_TRACE_ID);

	if (span == NULL) {
		_oidc_memset(parent_id, 0, OIDC_TP_PARENT_ID_LEN);
		_oidc_memcpy(parent_id, hostname,
			     _oidc_strlen(hostname) < OIDC_TP_PARENT_ID_LEN ? _oidc_strlen(hostname)
									    : OIDC_TP_PARENT_ID_LEN);
	} else {
		if (v == NULL)
			oidc_warn(r, "parameter \"span\" is set, but no \"trace-id\" [%s] found in the request state",
				  OIDC_REQUEST_STATE_TRACE_ID);
		else
			oidc_debug(r, "changing \"parent-id\" of current traceparent");
		for (const char *p = span; *p != 0; p++)
			hash = hash * P2 + *p;
		_oidc_memcpy(parent_id, &hash, OIDC_TP_PARENT_ID_LEN);
	}
	for (i = 0; i < OIDC_TP_PARENT_ID_LEN; i++)
		s_parent_id = apr_psprintf(r->pool, "%s%02x", s_parent_id, parent_id[i]);

	if (v == NULL) {
		apr_generate_random_bytes(trace_id, OIDC_TP_TRACE_ID_LEN);
		for (i = 0; i < OIDC_TP_TRACE_ID_LEN; i++)
			s_trace_id = apr_psprintf(r->pool, "%s%02x", s_trace_id, trace_id[i]);
		oidc_request_state_set(r, OIDC_REQUEST_STATE_TRACE_ID, s_trace_id);
	} else {
		s_trace_id = apr_pstrdup(r->pool, v);
	}

	if (oidc_cfg_metrics_hook_data_get(c) != NULL)
		trace_flags = trace_flags | 0x01;

	oidc_http_hdr_in_set(r, OIDC_HTTP_HDR_TRACE_PARENT,
			     apr_psprintf(r->pool, "00-%s-%s-%02x", s_trace_id, s_parent_id, trace_flags));
}

/*
 * clear the contents of a hash table (used for older versions of libapr missing this)
 */
void oidc_util_apr_hash_clear(apr_hash_t *ht) {
	apr_hash_index_t *hi = NULL;
	const void *key = NULL;
	apr_ssize_t klen = 0;
	for (hi = apr_hash_first(NULL, ht); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, &key, &klen, NULL);
		apr_hash_set(ht, key, klen, NULL);
	}
}

/*
 * return the OpenSSL version we compiled against
 */
char *oidc_util_openssl_version(apr_pool_t *pool) {
	char *s_version = NULL;
#ifdef OPENSSL_VERSION_STR
	s_version = apr_psprintf(pool, "openssl-%s", OPENSSL_VERSION_STR);
#else
	s_version = OPENSSL_VERSION_TEXT;
#endif
	return s_version;
}
