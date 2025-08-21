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

#include "cfg/parse.h"
#include "cfg/dir.h"
#include "const.h"
#include "proto/proto.h"
#include "util/util.h"
#include <apr_base64.h>
#include <apr_file_io.h>
#include <apr_strings.h>

/* separators used in "flattened" string/option lists */
#define OIDC_LIST_OPTIONS_START "["
#define OIDC_LIST_OPTIONS_END "]"
#define OIDC_LIST_OPTIONS_SEPARATOR "|"
#define OIDC_LIST_OPTIONS_QUOTE "'"

/*
 * flatten the provided list of string options
 */
char *oidc_cfg_parse_flatten_options(apr_pool_t *pool, const char *options[]) {
	int i = 0;
	char *result = OIDC_LIST_OPTIONS_START;
	while (options[i] != NULL) {
		if (i == 0)
			result = apr_psprintf(pool, "%s%s%s%s", OIDC_LIST_OPTIONS_START, OIDC_LIST_OPTIONS_QUOTE,
					      options[i], OIDC_LIST_OPTIONS_QUOTE);
		else
			result = apr_psprintf(pool, "%s%s%s%s%s", result, OIDC_LIST_OPTIONS_SEPARATOR,
					      OIDC_LIST_OPTIONS_QUOTE, options[i], OIDC_LIST_OPTIONS_QUOTE);
		i++;
	}
	result = apr_psprintf(pool, "%s%s", result, OIDC_LIST_OPTIONS_END);
	return result;
}

/*
 * check if arg is a valid option in the list of provided string options
 */
const char *oidc_cfg_parse_is_valid_option(apr_pool_t *pool, const char *arg, const char *options[]) {
	int i = 0;
	while (options[i] != NULL) {
		if (_oidc_strcmp(arg, options[i]) == 0)
			break;
		i++;
	}
	if (options[i] == NULL) {
		return apr_psprintf(pool, "invalid value %s%s%s, must be one of %s", OIDC_LIST_OPTIONS_QUOTE, arg,
				    OIDC_LIST_OPTIONS_QUOTE, oidc_cfg_parse_flatten_options(pool, options));
	}
	return NULL;
}

/*
 * flatten the provided list of n options
 */
char *oidc_cfg_parse_options_flatten(apr_pool_t *pool, const oidc_cfg_option_t options[], int n) {
	char *result = apr_psprintf(pool, "%s%s%s%s", OIDC_LIST_OPTIONS_QUOTE, options[--n].str,
				    OIDC_LIST_OPTIONS_QUOTE, OIDC_LIST_OPTIONS_END);
	for (--n; n >= 0; --n)
		result = apr_psprintf(pool, "%s%s%s%s%s", OIDC_LIST_OPTIONS_QUOTE, options[n].str,
				      OIDC_LIST_OPTIONS_QUOTE, OIDC_LIST_OPTIONS_SEPARATOR, result);
	return apr_psprintf(pool, "%s%s", OIDC_LIST_OPTIONS_START, result);
}

/*
 * parse an value provided as an option string into the corresponding integer/enum
 */
static char *oidc_cfg_parse_option_impl(apr_pool_t *pool, const oidc_cfg_option_t options[], int n, const char *arg,
					int *v, int (*fstrcmp)(const char *, const char *)) {
	int i = 0;
	while ((i < n) && (fstrcmp(arg, options[i].str) != 0))
		i++;
	if (i < n) {
		*v = options[i].val;
		return NULL;
	}
	return apr_psprintf(pool, "invalid value %s%s%s, must be one of %s", OIDC_LIST_OPTIONS_QUOTE, arg,
			    OIDC_LIST_OPTIONS_QUOTE, oidc_cfg_parse_options_flatten(pool, options, n));
}

/*
 * parse an value provided as an option string into the corresponding integer/enum case sensitive
 */
char *oidc_cfg_parse_option(apr_pool_t *pool, const oidc_cfg_option_t options[], int n, const char *arg, int *v) {
	return oidc_cfg_parse_option_impl(pool, options, n, arg, v, _oidc_strcmp);
}

/*
 * parse an value provided as an option string into the corresponding integer/enum case insensitive
 */
char *oidc_cfg_parse_option_ignore_case(apr_pool_t *pool, const oidc_cfg_option_t options[], int n, const char *arg,
					int *v) {
	return oidc_cfg_parse_option_impl(pool, options, n, arg, v, _oidc_strnatcasecmp);
}

/*
 * check if the provided integer value is between a specified minimum and maximum
 */
const char *oidc_cfg_parse_is_valid_int(apr_pool_t *pool, int value, int min_value, int max_value) {
	if (value < min_value) {
		return apr_psprintf(pool, "integer value %d is smaller than the minimum allowed value %d", value,
				    min_value);
	}
	if (value > max_value) {
		return apr_psprintf(pool, "integer value %d is greater than the maximum allowed value %d", value,
				    max_value);
	}
	return NULL;
}

/*
 * parse a string into a boolean
 */
const char *oidc_cfg_parse_boolean(apr_pool_t *pool, const char *arg, int *bool_value) {
	if ((_oidc_strnatcasecmp(arg, "true") == 0) || (_oidc_strnatcasecmp(arg, "on") == 0) ||
	    (_oidc_strnatcasecmp(arg, "yes") == 0) || (_oidc_strnatcasecmp(arg, "1") == 0)) {
		*bool_value = TRUE;
		return NULL;
	}
	if ((_oidc_strnatcasecmp(arg, "false") == 0) || (_oidc_strnatcasecmp(arg, "off") == 0) ||
	    (_oidc_strnatcasecmp(arg, "no") == 0) || (_oidc_strnatcasecmp(arg, "0") == 0)) {
		*bool_value = FALSE;
		return NULL;
	}
	return apr_psprintf(pool, "oidc_parse_boolean: could not parse boolean value from \"%s\"", arg);
}

/*
 * parse a string into an integer
 */
const char *oidc_cfg_parse_int(apr_pool_t *pool, const char *arg, int *int_value) {
	int v = -1;
	if ((arg == NULL) || (*arg == '\0') || (_oidc_strcmp(arg, "") == 0))
		return apr_psprintf(pool, "no integer value");
	if (sscanf(arg, "%d", &v) != 1)
		return apr_psprintf(pool, "invalid integer value: %s", arg);
	*int_value = v;
	return NULL;
}

/*
 * parse a string into an integer if it is in a valid min/max range
 */
const char *oidc_cfg_parse_int_min_max(apr_pool_t *pool, const char *arg, int *int_value, int min_value,
				       int max_value) {
	int v = 0;
	const char *rv = NULL;
	rv = oidc_cfg_parse_int(pool, arg, &v);
	if (rv != NULL)
		return rv;
	rv = oidc_cfg_parse_is_valid_int(pool, v, min_value, max_value);
	if (rv != NULL)
		return rv;
	*int_value = v;
	return NULL;
}

/*
 * parse a timeout string via ap_timeout_parameter_parse into an
 * apr_interval_time_t if it is in a valid min/max range
 */
const char *oidc_cfg_parse_timeout_min_max(apr_pool_t *pool, const char *arg, apr_interval_time_t *timeout_value,
					   apr_interval_time_t min_value, apr_interval_time_t max_value) {
#if AP_MODULE_MAGIC_AT_LEAST(20080920, 2)
	apr_interval_time_t timeout;
#else
	char *endptr;
	apr_int64_t timeout;
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20080920, 2)
	if (ap_timeout_parameter_parse(arg, &timeout, "s") != APR_SUCCESS) {
		return apr_psprintf(pool, "not a valid timeout parameter: %s", arg);
	}
#else
	timeout = apr_strtoi64(arg, &endptr, 10);
	if (errno != 0 || *endptr != '\0') {
		return apr_psprintf(pool, "not a valid timeout parameter: %s", arg);
	}
	timeout = apr_time_from_sec(timeout);
#endif

	if (timeout < min_value) {
		return apr_psprintf(pool,
				    "timeout value %" APR_TIME_T_FMT
				    " is smaller than the minimum allowed value %" APR_TIME_T_FMT,
				    timeout, min_value);
	}
	if (timeout > max_value) {
		return apr_psprintf(pool,
				    "timeout value %" APR_TIME_T_FMT
				    " is greater than the maximum allowed value %" APR_TIME_T_FMT,
				    timeout, max_value);
	}
	*timeout_value = (int)timeout;
	return NULL;
}

/*
 * check if a string is a valid URL starting with either scheme1 or scheme2 (if not NULL)
 */
static const char *oidc_cfg_parse_is_valid_url_scheme(apr_pool_t *pool, const char *arg, const char *scheme1,
						      const char *scheme2) {

	apr_uri_t uri;

	if (arg == NULL)
		return apr_psprintf(pool, "input cannot be empty");

	if (apr_uri_parse(pool, arg, &uri) != APR_SUCCESS)
		return apr_psprintf(pool, "'%s' cannot be parsed as a URL", arg);

	if (uri.scheme == NULL)
		return apr_psprintf(pool, "'%s' cannot be parsed as a URL (no scheme set)", arg);

	if ((scheme1 != NULL) && (_oidc_strnatcasecmp(uri.scheme, scheme1) != 0)) {
		if ((scheme2 != NULL) && (_oidc_strnatcasecmp(uri.scheme, scheme2) != 0)) {
			return apr_psprintf(pool, "'%s' cannot be parsed as a \"%s\" or \"%s\" URL (scheme == %s)!",
					    arg, scheme1, scheme2, uri.scheme);
		} else if (scheme2 == NULL) {
			return apr_psprintf(pool, "'%s' cannot be parsed as a \"%s\" URL (scheme == %s)!", arg, scheme1,
					    uri.scheme);
		}
	}

	if (uri.hostname == NULL)
		return apr_psprintf(pool, "'%s' cannot be parsed as a valid URL (no hostname set, check your slashes)",
				    arg);

	return NULL;
}

/*
 * check if a string is a valid URL string with the specified scheme
 */
const char *oidc_cfg_parse_is_valid_url(apr_pool_t *pool, const char *arg, const char *scheme) {
	return oidc_cfg_parse_is_valid_url_scheme(pool, arg, scheme, NULL);
}

/*
 * check if a string is a valid http or https URL
 */
const char *oidc_cfg_parse_is_valid_http_url(apr_pool_t *pool, const char *arg) {
	return oidc_cfg_parse_is_valid_url_scheme(pool, arg, "https", "http");
}

#define OIDC_CFG_PARSE_STR_ERROR_MAX 128

/*
 * return an error retrieved from apr_strerror as a config error
 */
static const char *oidc_cfg_parse_io_error(apr_pool_t *pool, const char *action, const char *type, const char *name,
					   apr_status_t rc) {
	char s_err[OIDC_CFG_PARSE_STR_ERROR_MAX];
	return apr_psprintf(pool, "cannot %s %s %s: %s", action, type, name,
			    apr_strerror(rc, s_err, OIDC_CFG_PARSE_STR_ERROR_MAX));
}

/*
 * parse a string into a directory name if it exists and is accessible
 */
const char *oidc_cfg_parse_dirname(apr_pool_t *pool, const char *arg, char **value) {
	apr_status_t rc = APR_SUCCESS;
	apr_dir_t *dir = NULL;
	if (arg == NULL)
		return apr_psprintf(pool, "directory name cannot be empty");
	if ((rc = apr_dir_open(&dir, arg, pool)) != APR_SUCCESS)
		return oidc_cfg_parse_io_error(pool, "access", "directory", arg, rc);
	if ((rc = apr_dir_close(dir)) != APR_SUCCESS)
		return oidc_cfg_parse_io_error(pool, "close", "directory", arg, rc);
	*value = apr_pstrdup(pool, arg);
	return NULL;
}

/*
 * parse a string into a file name if it exists and is accessible
 */
const char *oidc_cfg_parse_filename(apr_pool_t *pool, const char *arg, char **value) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	if (arg == NULL)
		return apr_psprintf(pool, "file name cannot be empty");
	const char *filename = ap_server_root_relative(pool, arg);
	if ((rc = apr_file_open(&fd, filename, APR_FOPEN_READ, APR_OS_DEFAULT, pool)) != APR_SUCCESS)
		return oidc_cfg_parse_io_error(pool, "access", "file", filename, rc);
	if ((rc = apr_file_close(fd)) != APR_SUCCESS)
		return oidc_cfg_parse_io_error(pool, "close", "file", filename, rc);
	*value = apr_pstrdup(pool, filename);
	return NULL;
}

/*
 * parse a string a relative path or an absolute http/https URL
 */
const char *oidc_cfg_parse_relative_or_absolute_url(apr_pool_t *pool, const char *arg, char **value) {
	const char *rv = NULL;
	apr_uri_t uri;

	if (arg == NULL)
		return "input cannot be empty";

	if (arg[0] == OIDC_CHAR_FORWARD_SLASH) {
		// relative uri
		if (apr_uri_parse(pool, arg, &uri) == APR_SUCCESS)
			*value = apr_pstrdup(pool, arg);
		else
			rv = apr_psprintf(pool, "could not parse relative URI \"%s\"", arg);
	} else {
		// absolute uri
		rv = oidc_cfg_parse_is_valid_http_url(pool, arg);
		if (rv == NULL)
			*value = apr_pstrdup(pool, arg);
	}
	return rv;
}

/*
 * check if the provided OAuth/OIDC response type is supported
 */
const char *oidc_cfg_parse_is_valid_response_type(apr_pool_t *pool, const char *arg) {
	if (oidc_proto_flow_is_supported(pool, arg) == FALSE) {
		return apr_psprintf(pool, "oidc_valid_response_type: type must be one of %s",
				    apr_array_pstrcat(pool, oidc_proto_supported_flows(pool), OIDC_CHAR_PIPE));
	}
	return NULL;
}

/*
 * check if the provided OAuth 2.0 response mode is supported
 */
const char *oidc_cfg_parse_is_valid_response_mode(apr_pool_t *pool, const char *arg) {
	static const char *options[] = {OIDC_PROTO_RESPONSE_MODE_FRAGMENT, OIDC_PROTO_RESPONSE_MODE_QUERY,
					OIDC_PROTO_RESPONSE_MODE_FORM_POST, NULL};
	return oidc_cfg_parse_is_valid_option(pool, arg, options);
}

/*
 * check if the provided JWT signature algorithm is supported
 */
const char *oidc_cfg_parse_is_valid_signed_response_alg(apr_pool_t *pool, const char *arg) {
	if (oidc_jose_jws_algorithm_is_supported(pool, arg) == FALSE) {
		return apr_psprintf(pool, "unsupported/invalid signing algorithm '%s'; must be one of [%s]", arg,
				    apr_array_pstrcat(pool, oidc_jose_jws_supported_algorithms(pool), OIDC_CHAR_PIPE));
	}
	return NULL;
}

/*
 * check if the provided JWT content key encryption algorithm is supported
 */
const char *oidc_cfg_parse_is_valid_encrypted_response_alg(apr_pool_t *pool, const char *arg) {
	if (oidc_jose_jwe_algorithm_is_supported(pool, arg) == FALSE) {
		return apr_psprintf(pool, "unsupported/invalid encryption algorithm '%s'; must be one of [%s]", arg,
				    apr_array_pstrcat(pool, oidc_jose_jwe_supported_algorithms(pool), OIDC_CHAR_PIPE));
	}
	return NULL;
}

/*
 * check if the provided JWT encryption cipher is supported
 */
const char *oidc_cfg_parse_is_valid_encrypted_response_enc(apr_pool_t *pool, const char *arg) {
	if (oidc_jose_jwe_encryption_is_supported(pool, arg) == FALSE) {
		return apr_psprintf(pool, "unsupported/invalid encryption type '%s'; must be one of [%s]", arg,
				    apr_array_pstrcat(pool, oidc_jose_jwe_supported_encryptions(pool), OIDC_CHAR_PIPE));
	}
	return NULL;
}

/*
 * parse a base64url encoded binary value from the provided string
 */
static char *oidc_cfg_parse_base64url(apr_pool_t *pool, const char *input, char **output, int *output_len) {
	*output_len = oidc_util_base64url_decode(pool, output, input);
	if (*output_len <= 0)
		return apr_psprintf(pool, "base64url-decoding of \"%s\" failed", input);
	return NULL;
}

/*
 * parse a hexadecimal encoded binary value from the provided string
 */
static char *oidc_cfg_parse_hex(apr_pool_t *pool, const char *input, char **output, int *output_len) {
	*output_len = _oidc_strlen(input) / 2;
	const char *pos = input;
	unsigned char *val = apr_pcalloc(pool, *output_len);
	size_t count = 0;
	for (count = 0; (count < (*output_len) / sizeof(unsigned char)) && (pos != NULL); count++) {
		sscanf(pos, "%2hhx", &val[count]);
		pos += 2;
	}
	*output = (char *)val;
	return NULL;
}

#define OIDC_KEY_ENCODING_BASE64 "b64"
#define OIDC_KEY_ENCODING_BASE64_URL "b64url"
#define OIDC_KEY_ENCODING_HEX "hex"
#define OIDC_KEY_ENCODING_PLAIN "plain"

/*
 * parse a key value based on the provided encoding: b64|b64url|hex|plain
 */
static const char *oidc_cfg_parse_key_value(apr_pool_t *pool, const char *enc, const char *input, char **key,
					    int *key_len) {
	static const char *options[] = {OIDC_KEY_ENCODING_BASE64, OIDC_KEY_ENCODING_BASE64_URL, OIDC_KEY_ENCODING_HEX,
					OIDC_KEY_ENCODING_PLAIN, NULL};
	if (_oidc_strcmp(enc, OIDC_KEY_ENCODING_BASE64) == 0)
		return oidc_util_base64_decode(pool, input, key, key_len);
	if (_oidc_strcmp(enc, OIDC_KEY_ENCODING_BASE64_URL) == 0)
		return oidc_cfg_parse_base64url(pool, input, key, key_len);
	if (_oidc_strcmp(enc, OIDC_KEY_ENCODING_HEX) == 0)
		return oidc_cfg_parse_hex(pool, input, key, key_len);
	if (_oidc_strcmp(enc, OIDC_KEY_ENCODING_PLAIN) == 0) {
		*key = apr_pstrdup(pool, input);
		*key_len = _oidc_strlen(*key);
		return NULL;
	}
	// NB: when we get here we'll return an error displaying the valid options
	return oidc_cfg_parse_is_valid_option(pool, enc, options);
}

#define OIDC_KEY_TUPLE_SEPARATOR "#"
#define OIDC_KEY_SIG_PREFIX OIDC_JOSE_JWK_SIG_STR ":"
#define OIDC_KEY_ENC_PREFIX OIDC_JOSE_JWK_ENC_STR ":"

/*
 * parse a <use>:<encoding>#<key-identifier>#<key> tuple
 */
const char *oidc_cfg_parse_key_record(apr_pool_t *pool, const char *tuple, char **kid, char **key, int *key_len,
				      char **use, apr_byte_t triplet) {
	const char *rv = NULL;
	char *s = NULL, *p = NULL, *q = NULL, *enc = NULL;

	if ((tuple == NULL) || (_oidc_strcmp(tuple, "") == 0))
		return "tuple value not set";

	if (use) {
		if (_oidc_strstr(tuple, OIDC_KEY_SIG_PREFIX) == tuple) {
			*use = OIDC_JOSE_JWK_SIG_STR;
			tuple += _oidc_strlen(OIDC_KEY_SIG_PREFIX);
		} else if (_oidc_strstr(tuple, OIDC_KEY_ENC_PREFIX) == tuple) {
			*use = OIDC_JOSE_JWK_ENC_STR;
			tuple += _oidc_strlen(OIDC_KEY_ENC_PREFIX);
		}
	}

	s = apr_pstrdup(pool, tuple);
	p = _oidc_strstr(s, OIDC_KEY_TUPLE_SEPARATOR);
	if (p && triplet)
		q = _oidc_strstr(p + 1, OIDC_KEY_TUPLE_SEPARATOR);

	if (p) {
		if (q) {
			*p = '\0';
			*q = '\0';
			enc = s;
			p++;
			if (p != q)
				*kid = apr_pstrdup(pool, p);
			rv = oidc_cfg_parse_key_value(pool, enc, q + 1, key, key_len);
		} else {
			*p = '\0';
			*kid = s;
			*key = p + 1;
			*key_len = _oidc_strlen(*key);
		}
	} else {
		*kid = NULL;
		*key = s;
		*key_len = _oidc_strlen(*key);
	}

	return rv;
}

#define OIDC_ON_ERROR_502_STR "502_on_error"
#define OIDC_ON_ERROR_LOGOUT_STR "logout_on_error"
#define OIDC_ON_ERROR_AUTH_STR "authenticate_on_error"

/*
 * parse an "on access token refresh error" value from the provided strings
 */
const char *oidc_cfg_parse_action_on_error_refresh_as(apr_pool_t *pool, const char *arg,
						      oidc_on_error_action_t *action) {
	static const oidc_cfg_option_t options[] = {{OIDC_ON_ERROR_502, OIDC_ON_ERROR_502_STR},
						    {OIDC_ON_ERROR_LOGOUT, OIDC_ON_ERROR_LOGOUT_STR},
						    {OIDC_ON_ERROR_AUTH, OIDC_ON_ERROR_AUTH_STR}};
	return oidc_cfg_parse_option(pool, options, OIDC_CFG_OPTIONS_SIZE(options), arg, (int *)action);
}

#if !(HAVE_APACHE_24)
static char *ap_get_exec_line(apr_pool_t *p, const char *cmd, const char *const *argv) {
	char buf[MAX_STRING_LEN];
	apr_procattr_t *procattr;
	apr_proc_t *proc;
	apr_file_t *fp;
	apr_size_t nbytes = 1;
	char c;
	int k;

	if (apr_procattr_create(&procattr, p) != APR_SUCCESS)
		return NULL;
	if (apr_procattr_io_set(procattr, APR_FULL_BLOCK, APR_FULL_BLOCK, APR_FULL_BLOCK) != APR_SUCCESS)
		return NULL;
	if (apr_procattr_dir_set(procattr, ap_make_dirstr_parent(p, cmd)) != APR_SUCCESS)
		return NULL;
	if (apr_procattr_cmdtype_set(procattr, APR_PROGRAM) != APR_SUCCESS)
		return NULL;
	proc = apr_pcalloc(p, sizeof(apr_proc_t));
	if (apr_proc_create(proc, cmd, argv, NULL, procattr, p) != APR_SUCCESS)
		return NULL;
	fp = proc->out;

	if (fp == NULL)
		return NULL;
	/* XXX: we are reading 1 byte at a time here */
	for (k = 0; apr_file_read(fp, &c, &nbytes) == APR_SUCCESS && nbytes == 1 && (k < MAX_STRING_LEN - 1);) {
		if (c == '\n' || c == '\r')
			break;
		buf[k++] = c;
	}
	buf[k] = '\0';
	apr_file_close(fp);

	return apr_pstrndup(p, buf, k);
}
#endif

/*
 * set a string value in the server config with exec support
 */
const char *oidc_cfg_parse_passphrase(apr_pool_t *pool, const char *arg, char **passphrase) {
	char **argv = NULL;
	char *result = NULL;
	int arglen = _oidc_strlen(arg);
	/* Based on code from mod_session_crypto. */
	if (arglen > 5 && _oidc_strncmp(arg, "exec:", 5) == 0) {
		if (apr_tokenize_to_argv(arg + 5, &argv, pool) != APR_SUCCESS) {
			return apr_pstrcat(pool, "Unable to parse exec arguments from ", arg + 5, NULL);
		}
		argv[0] = ap_server_root_relative(pool, argv[0]);
		if (!argv[0]) {
			return apr_pstrcat(pool, "Invalid exec location:", arg + 5, NULL);
		}
		result = ap_get_exec_line(pool, argv[0], (const char *const *)argv);
		if (!result) {
			return apr_pstrcat(pool, "Unable to get passphrase from exec of ", arg + 5, NULL);
		}
		if (_oidc_strlen(result) == 0)
			return apr_pstrdup(pool, "the output of the  passphrase generation command is empty "
						 "(perhaps you need to pass it to bash -c \"<cmd>\"?)");
		*passphrase = apr_pstrdup(pool, result);
	} else {
		*passphrase = apr_pstrdup(pool, arg);
	}
	return NULL;
}

/*
 * add a public key from an X.509 file to our list of JWKs with public keys
 */
const char *oidc_cfg_parse_public_key_files(apr_pool_t *pool, const char *arg, apr_array_header_t **keys) {
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;
	char *use = NULL;

	char *kid = NULL, *name = NULL, *fname = NULL;
	int fname_len;
	const char *rv = oidc_cfg_parse_key_record(pool, arg, &kid, &name, &fname_len, &use, FALSE);
	if (rv != NULL)
		return rv;

	rv = oidc_cfg_parse_filename(pool, name, &fname);
	if (rv != NULL)
		return rv;

	if (oidc_jwk_parse_pem_public_key(pool, kid, fname, &jwk, &err) == FALSE) {
		return apr_psprintf(pool, "oidc_jwk_parse_pem_public_key failed for (kid=%s) \"%s\": %s", kid, fname,
				    oidc_jose_e2s(pool, err));
	}

	if (*keys == NULL)
		*keys = apr_array_make(pool, 4, sizeof(oidc_jwk_t *));
	if (use)
		jwk->use = apr_pstrdup(pool, use);
	APR_ARRAY_PUSH(*keys, oidc_jwk_t *) = jwk;

	return NULL;
}

/*
 * parse a triplet of 3 provided config values into a remote_user_claim struct
 */
const char *oidc_parse_remote_user_claim(apr_pool_t *pool, const char *v1, const char *v2, const char *v3,
					 oidc_remote_user_claim_t *remote_user_claim) {
	remote_user_claim->claim_name = v1;
	if (v2)
		remote_user_claim->reg_exp = v2;
	if (v3)
		remote_user_claim->replace = v3;
	return NULL;
}

/*
 * parse a triplet of 3 provided config values into a http_timeout struct
 */
const char *oidc_cfg_parse_http_timeout(apr_pool_t *pool, const char *arg1, const char *arg2, const char *arg3,
					oidc_http_timeout_t *http_timeout) {
	char *s = NULL, *p = NULL;
	if (arg1)
		http_timeout->request_timeout = _oidc_str_to_int(arg1, http_timeout->request_timeout);
	if (arg2)
		http_timeout->connect_timeout = _oidc_str_to_int(arg2, http_timeout->connect_timeout);
	if (arg3) {
		s = apr_pstrdup(pool, arg3);
		p = _oidc_strstr(s, OIDC_STR_COLON);
		if (p) {
			*p = '\0';
			p++;
			http_timeout->retry_interval = _oidc_str_to_int(p, http_timeout->retry_interval);
		}
		http_timeout->retries = _oidc_str_to_int(s, http_timeout->retries);
	}
	return NULL;
}
