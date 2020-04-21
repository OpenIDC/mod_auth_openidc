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
 * Copyright (C) 2017-2020 ZmartZone IAM
 * Copyright (C) 2013-2017 Ping Identity Corporation
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
 * Validation and parsing of configuration values.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#include <apr_base64.h>
#include "mod_auth_openidc.h"
#include "parse.h"
#include "jose.h"

/*
 * parse a URL according to one of two schemes (NULL for any)
 */
static const char * oidc_valid_url_scheme(apr_pool_t *pool, const char *arg,
		const char *scheme1, const char *scheme2) {

	apr_uri_t uri;

	if (apr_uri_parse(pool, arg, &uri) != APR_SUCCESS) {
		return apr_psprintf(pool, "'%s' cannot be parsed as a URL", arg);
	}

	if (uri.scheme == NULL) {
		return apr_psprintf(pool,
				"'%s' cannot be parsed as a URL (no scheme set)", arg);
	}

	if ((scheme1 != NULL) && (apr_strnatcmp(uri.scheme, scheme1) != 0)) {
		if ((scheme2 != NULL) && (apr_strnatcmp(uri.scheme, scheme2) != 0)) {
			return apr_psprintf(pool,
					"'%s' cannot be parsed as a \"%s\" or \"%s\" URL (scheme == %s)!",
					arg, scheme1, scheme2, uri.scheme);
		} else if (scheme2 == NULL) {
			return apr_psprintf(pool,
					"'%s' cannot be parsed as a \"%s\" URL (scheme == %s)!",
					arg, scheme1, uri.scheme);
		}
	}

	if (uri.hostname == NULL) {
		return apr_psprintf(pool,
				"'%s' cannot be parsed as a valid URL (no hostname set, check your slashes)",
				arg);
	}

	return NULL;
}

/*
 * parse a URL according to a scheme
 */
const char *oidc_valid_url(apr_pool_t *pool, const char *arg,
		const char *scheme) {
	return oidc_valid_url_scheme(pool, arg, scheme, NULL);
}

/*
 * parse a URL that should conform to any HTTP scheme (http/https)
 */
const char *oidc_valid_http_url(apr_pool_t *pool, const char *arg) {
	return oidc_valid_url_scheme(pool, arg, "https", "http");
}

#define STR_ERROR_MAX 128

/*
 * check if arg is a valid directory on the file system
 */
const char *oidc_valid_dir(apr_pool_t *pool, const char *arg) {
	char s_err[STR_ERROR_MAX];
	apr_dir_t *dir = NULL;
	apr_status_t rc = APR_SUCCESS;

	/* ensure the directory exists */
	if ((rc = apr_dir_open(&dir, arg, pool)) != APR_SUCCESS) {
		return apr_psprintf(pool, "cannot access directory '%s' (%s)", arg,
				apr_strerror(rc, s_err, STR_ERROR_MAX));
	}

	/* and cleanup... */
	if ((rc = apr_dir_close(dir)) != APR_SUCCESS) {
		return apr_psprintf(pool, "cannot close directory '%s' (%s)", arg,
				apr_strerror(rc, s_err, STR_ERROR_MAX));
	}

	return NULL;
}

/*
 * check if arg is a valid cookie domain value
 */
const char *oidc_valid_cookie_domain(apr_pool_t *pool, const char *arg) {
	size_t sz, limit;
	char d;
	limit = strlen(arg);
	for (sz = 0; sz < limit; sz++) {
		d = arg[sz];
		if ((d < '0' || d > '9') && (d < 'a' || d > 'z') && (d < 'A' || d > 'Z')
				&& d != '.' && d != '-') {
			return (apr_psprintf(pool,
					"invalid character '%c' in cookie domain value: %s", d, arg));
		}
	}
	return NULL;
}

/*
 * parse an integer value from a string
 */
const char *oidc_parse_int(apr_pool_t *pool, const char *arg, int *int_value) {
	char *endptr;
	int v = strtol(arg, &endptr, 10);
	if ((*arg == '\0') || (*endptr != '\0')) {
		return apr_psprintf(pool, "invalid integer value: %s", arg);
	}
	*int_value = v;
	return NULL;
}

/*
 * check if the provided integer value is between a specified minimum and maximum
 */
static const char *oidc_valid_int_min_max(apr_pool_t *pool, int value,
		int min_value, int max_value) {
	if (value < min_value) {
		return apr_psprintf(pool,
				"integer value %d is smaller than the minimum allowed value %d",
				value, min_value);
	}
	if (value > max_value) {
		return apr_psprintf(pool,
				"integer value %d is greater than the maximum allowed value %d",
				value, max_value);
	}
	return NULL;
}

/*
 * parse an integer and check validity
 */
static const char *oidc_parse_int_valid(apr_pool_t *pool, const char *arg,
		int *int_value, oidc_valid_int_function_t valid_int_function) {
	int v = 0;
	const char *rv = NULL;
	rv = oidc_parse_int(pool, arg, &v);
	if (rv != NULL)
		return rv;
	rv = valid_int_function(pool, v);
	if (rv != NULL)
		return rv;
	*int_value = v;
	return NULL;
}

/*
 * parse an integer value from a string that must be between a specified minimum and maximum
 */
static const char *oidc_parse_int_min_max(apr_pool_t *pool, const char *arg,
		int *int_value, int min_value, int max_value) {
	int v = 0;
	const char *rv = NULL;
	rv = oidc_parse_int(pool, arg, &v);
	if (rv != NULL)
		return rv;
	rv = oidc_valid_int_min_max(pool, v, min_value, max_value);
	if (rv != NULL)
		return rv;
	*int_value = v;
	return NULL;
}

#define OIDC_LIST_OPTIONS_START     "["
#define OIDC_LIST_OPTIONS_END       "]"
#define OIDC_LIST_OPTIONS_SEPARATOR "|"
#define OIDC_LIST_OPTIONS_QUOTE     "'"

/*
 * flatten the list of string options, separated by the specified separator char
 */
static char *oidc_flatten_list_options(apr_pool_t *pool, char *options[]) {
	int i = 0;
	char *result = OIDC_LIST_OPTIONS_START;
	while (options[i] != NULL) {
		if (i == 0)
			result = apr_psprintf(pool, "%s%s%s%s", OIDC_LIST_OPTIONS_START,
					OIDC_LIST_OPTIONS_QUOTE, options[i],
					OIDC_LIST_OPTIONS_QUOTE);
		else
			result = apr_psprintf(pool, "%s%s%s%s%s", result,
					OIDC_LIST_OPTIONS_SEPARATOR, OIDC_LIST_OPTIONS_QUOTE, options[i],
					OIDC_LIST_OPTIONS_QUOTE);
		i++;
	}
	result = apr_psprintf(pool, "%s%s", result, OIDC_LIST_OPTIONS_END);
	return result;
}

/*
 * check if arg is a valid option in the list of provided string options
 */
static const char *oidc_valid_string_option(apr_pool_t *pool, const char *arg,
		char *options[]) {
	int i = 0;
	while (options[i] != NULL) {
		if (apr_strnatcmp(arg, options[i]) == 0)
			break;
		i++;
	}
	if (options[i] == NULL) {
		return apr_psprintf(pool, "invalid value %s%s%s, must be one of %s",
				OIDC_LIST_OPTIONS_QUOTE, arg, OIDC_LIST_OPTIONS_QUOTE,
				oidc_flatten_list_options(pool, options));
	}
	return NULL;
}

#define OIDC_CACHE_TYPE_SHM      "shm"
#define OIDC_CACHE_TYPE_MEMCACHE "memcache"
#define OIDC_CACHE_TYPE_REDIS    "redis"
#define OIDC_CACHE_TYPE_FILE     "file"

/*
 * parse the cache backend type
 */
const char *oidc_parse_cache_type(apr_pool_t *pool, const char *arg,
		oidc_cache_t **type) {
	static char *options[] = {
			OIDC_CACHE_TYPE_SHM,
#ifdef USE_MEMCACHE
			OIDC_CACHE_TYPE_MEMCACHE,
#endif
#ifdef USE_LIBHIREDIS
			OIDC_CACHE_TYPE_REDIS,
#endif
			OIDC_CACHE_TYPE_FILE,
			NULL };
	const char *rv = oidc_valid_string_option(pool, arg, options);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_CACHE_TYPE_SHM) == 0) {
		*type = &oidc_cache_shm;
#ifdef USE_MEMCACHE
	} else if (apr_strnatcmp(arg, OIDC_CACHE_TYPE_MEMCACHE) == 0) {
		*type = &oidc_cache_memcache;
#endif
	} else if (apr_strnatcmp(arg, OIDC_CACHE_TYPE_FILE) == 0) {
		*type = &oidc_cache_file;
#ifdef USE_LIBHIREDIS
	} else if (apr_strnatcmp(arg, OIDC_CACHE_TYPE_REDIS) == 0) {
		*type = &oidc_cache_redis;
#endif
	}

	return NULL;
}

#define OIDC_SESSION_TYPE_SERVER_CACHE_STR  "server-cache"
#define OIDC_SESSION_TYPE_CLIENT_COOKIE_STR "client-cookie"
#define OIDC_SESSION_TYPE_PERSISTENT        "persistent"
#define OIDC_SESSION_TYPE_SEPARATOR         ":"

/*
 * parse the session mechanism type and the cookie persistency property
 */
const char *oidc_parse_session_type(apr_pool_t *pool, const char *arg,
		int *type, int *persistent) {
	static char *options[] =
	{
			OIDC_SESSION_TYPE_SERVER_CACHE_STR,
			OIDC_SESSION_TYPE_SERVER_CACHE_STR OIDC_SESSION_TYPE_SEPARATOR OIDC_SESSION_TYPE_PERSISTENT,
			OIDC_SESSION_TYPE_CLIENT_COOKIE_STR,
			OIDC_SESSION_TYPE_CLIENT_COOKIE_STR OIDC_SESSION_TYPE_SEPARATOR OIDC_SESSION_TYPE_PERSISTENT,
			NULL };
	const char *rv = oidc_valid_string_option(pool, arg, options);
	if (rv != NULL)
		return rv;

	char *s = apr_pstrdup(pool, arg);
	char *p = strstr(s, OIDC_SESSION_TYPE_SEPARATOR);

	if (p) {
		*persistent = 1;
		*p = '\0';
	}

	if (apr_strnatcmp(s, OIDC_SESSION_TYPE_SERVER_CACHE_STR) == 0) {
		*type = OIDC_SESSION_TYPE_SERVER_CACHE;
	} else if (apr_strnatcmp(s, OIDC_SESSION_TYPE_CLIENT_COOKIE_STR) == 0) {
		*type = OIDC_SESSION_TYPE_CLIENT_COOKIE;
	}
	return NULL;
}

/* minimum size of a SHM cache entry */
#define OIDC_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX 8192 + 512 + 17 // 8Kb plus overhead
/* maximum size of a SHM cache entry */
#define OIDC_MAXIMUM_CACHE_SHM_ENTRY_SIZE_MAX 1024 * 512     // 512Kb incl. overhead

/*
 * parse the slot size of a SHM cache entry
 */
const char *oidc_parse_cache_shm_entry_size_max(apr_pool_t *pool,
		const char *arg, int *int_value) {
	return oidc_parse_int_min_max(pool, arg, int_value,
			OIDC_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX,
			OIDC_MAXIMUM_CACHE_SHM_ENTRY_SIZE_MAX);
}

/*
 * parse a boolean value from a provided string
 */
const char *oidc_parse_boolean(apr_pool_t *pool, const char *arg,
		int *bool_value) {
	if ((apr_strnatcasecmp(arg, "true") == 0)
			|| (apr_strnatcasecmp(arg, "on") == 0)
			|| (apr_strnatcasecmp(arg, "yes") == 0)
			|| (apr_strnatcasecmp(arg, "1") == 0)) {
		*bool_value = TRUE;
		return NULL;
	}
	if ((apr_strnatcasecmp(arg, "false") == 0)
			|| (apr_strnatcasecmp(arg, "off") == 0)
			|| (apr_strnatcasecmp(arg, "no") == 0)
			|| (apr_strnatcasecmp(arg, "0") == 0)) {
		*bool_value = FALSE;
		return NULL;
	}
	return apr_psprintf(pool,
			"oidc_parse_boolean: could not parse boolean value from \"%s\"",
			arg);
}

#define OIDC_ENDPOINT_AUTH_CLIENT_SECRET_POST  "client_secret_post"
#define OIDC_ENDPOINT_AUTH_CLIENT_SECRET_JWT   "client_secret_jwt"
#define OIDC_ENDPOINT_AUTH_PRIVATE_KEY_JWT     "private_key_jwt"
#define OIDC_ENDPOINT_AUTH_BEARER_ACCESS_TOKEN "bearer_access_token"
#define OIDC_ENDPOINT_AUTH_NONE                "none"

/*
 * check if the provided endpoint authentication method is supported
 */
static const char *oidc_valid_endpoint_auth_method_impl(apr_pool_t *pool,
		const char *arg, apr_byte_t has_private_key) {
	static char *options[] = {
			OIDC_ENDPOINT_AUTH_CLIENT_SECRET_POST,
			OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC,
			OIDC_ENDPOINT_AUTH_CLIENT_SECRET_JWT,
			OIDC_ENDPOINT_AUTH_NONE,
			OIDC_ENDPOINT_AUTH_BEARER_ACCESS_TOKEN,
			NULL,
			NULL };
	if (has_private_key)
		options[5] = OIDC_ENDPOINT_AUTH_PRIVATE_KEY_JWT;

	return oidc_valid_string_option(pool, arg, options);
}

const char *oidc_valid_endpoint_auth_method(apr_pool_t *pool, const char *arg) {
	return oidc_valid_endpoint_auth_method_impl(pool, arg, TRUE);
}

const char *oidc_valid_endpoint_auth_method_no_private_key(apr_pool_t *pool,
		const char *arg) {
	return oidc_valid_endpoint_auth_method_impl(pool, arg, FALSE);
}

/*
 * check if the provided OAuth/OIDC response type is supported
 */
const char *oidc_valid_response_type(apr_pool_t *pool, const char *arg) {
	if (oidc_proto_flow_is_supported(pool, arg) == FALSE) {
		return apr_psprintf(pool,
				"oidc_valid_response_type: type must be one of %s",
				apr_array_pstrcat(pool, oidc_proto_supported_flows(pool),
						OIDC_CHAR_PIPE));
	}
	return NULL;
}

/*
 * check if the provided PKCE method is supported
 */
const char *oidc_valid_pkce_method(apr_pool_t *pool, const char *arg) {
	static char *options[] = {
			OIDC_PKCE_METHOD_PLAIN,
			OIDC_PKCE_METHOD_S256,
			OIDC_PKCE_METHOD_REFERRED_TB,
			NULL };
	return oidc_valid_string_option(pool, arg, options);
}

#define OIDC_RESPONSE_TYPE_FRAGMENT   "fragment"
#define OIDC_RESPONSE_TYPE_QUERY      "query"
#define OIDC_RESPONSE_TYPE_FORM_POST  "form_post"

/*
 * check if the provided OAuth 2.0 response mode is supported
 */
const char *oidc_valid_response_mode(apr_pool_t *pool, const char *arg) {
	static char *options[] = {
			OIDC_RESPONSE_TYPE_FRAGMENT,
			OIDC_RESPONSE_TYPE_QUERY,
			OIDC_RESPONSE_TYPE_FORM_POST,
			NULL };
	return oidc_valid_string_option(pool, arg, options);
}

/*
 * check if the provided JWT signature algorithm is supported
 */
const char *oidc_valid_signed_response_alg(apr_pool_t *pool, const char *arg) {
	if (oidc_jose_jws_algorithm_is_supported(pool, arg) == FALSE) {
		return apr_psprintf(pool,
				"unsupported/invalid signing algorithm '%s'; must be one of [%s]",
				arg,
				apr_array_pstrcat(pool,
						oidc_jose_jws_supported_algorithms(pool),
						OIDC_CHAR_PIPE));
	}
	return NULL;
}

/*
 * check if the provided JWT content key encryption algorithm is supported
 */
const char *oidc_valid_encrypted_response_alg(apr_pool_t *pool, const char *arg) {
	if (oidc_jose_jwe_algorithm_is_supported(pool, arg) == FALSE) {
		return apr_psprintf(pool,
				"unsupported/invalid encryption algorithm '%s'; must be one of [%s]",
				arg,
				apr_array_pstrcat(pool,
						oidc_jose_jwe_supported_algorithms(pool),
						OIDC_CHAR_PIPE));
	}
	return NULL;
}

/*
 * check if the provided JWT encryption cipher is supported
 */
const char *oidc_valid_encrypted_response_enc(apr_pool_t *pool, const char *arg) {
	if (oidc_jose_jwe_encryption_is_supported(pool, arg) == FALSE) {
		return apr_psprintf(pool,
				"unsupported/invalid encryption type '%s'; must be one of [%s]",
				arg,
				apr_array_pstrcat(pool,
						oidc_jose_jwe_supported_encryptions(pool),
						OIDC_CHAR_PIPE));
	}
	return NULL;
}

#define OIDC_SESSION_INACTIVITY_TIMEOUT_MIN 10
#define OIDC_SESSION_INACTIVITY_TIMEOUT_MAX 3600 * 24 * 365

/*
 * parse a session inactivity timeout value from the provided string
 */
const char *oidc_parse_session_inactivity_timeout(apr_pool_t *pool,
		const char *arg, int *int_value) {
	return oidc_parse_int_min_max(pool, arg, int_value,
			OIDC_SESSION_INACTIVITY_TIMEOUT_MIN,
			OIDC_SESSION_INACTIVITY_TIMEOUT_MAX);
}

#define OIDC_SESSION_MAX_DURATION_MIN 15
#define OIDC_SESSION_MAX_DURATION_MAX 3600 * 24 * 365

/*
 * check the boundaries for session max lifetime
 */
const char *oidc_valid_session_max_duration(apr_pool_t *pool, int v) {
	if (v == 0) {
		return NULL;
	}
	if (v < OIDC_SESSION_MAX_DURATION_MIN) {
		return apr_psprintf(pool, "value must not be less than %d seconds",
				OIDC_SESSION_MAX_DURATION_MIN);
	}
	if (v > OIDC_SESSION_MAX_DURATION_MAX) {
		return apr_psprintf(pool, "value must not be greater than %d seconds",
				OIDC_SESSION_MAX_DURATION_MAX);
	}
	return NULL;
}

#define OIDC_MAX_NUMBER_OF_STATE_COOKIES_MIN  0
#define OIDC_MAX_NUMBER_OF_STATE_COOKIES_MAX  255

/*
 * check the maximum number of parallel state cookies
 */
const char *oidc_valid_max_number_of_state_cookies(apr_pool_t *pool, int v) {
	if (v == 0) {
		return NULL;
	}
	if (v < OIDC_MAX_NUMBER_OF_STATE_COOKIES_MIN) {
		return apr_psprintf(pool, "maximum must not be less than %d",
				OIDC_MAX_NUMBER_OF_STATE_COOKIES_MIN);
	}
	if (v > OIDC_MAX_NUMBER_OF_STATE_COOKIES_MAX) {
		return apr_psprintf(pool, "maximum must not be greater than %d",
				OIDC_MAX_NUMBER_OF_STATE_COOKIES_MAX);
	}
	return NULL;
}

/*
 * parse a session max duration value from the provided string
 */
const char *oidc_parse_session_max_duration(apr_pool_t *pool, const char *arg,
		int *int_value) {
	return oidc_parse_int_valid(pool, arg, int_value,
			oidc_valid_session_max_duration);
}

/*
 * parse a base64 encoded binary value from the provided string
 */
char *oidc_parse_base64(apr_pool_t *pool, const char *input, char **output,
		int *output_len) {
	int len = apr_base64_decode_len(input);
	*output = apr_palloc(pool, len);
	*output_len = apr_base64_decode(*output, input);
	if (*output_len <= 0)
		return apr_psprintf(pool, "base64-decoding of \"%s\" failed", input);
	return NULL;
}

/*
 * parse a base64url encoded binary value from the provided string
 */
static char *oidc_parse_base64url(apr_pool_t *pool, const char *input,
		char **output, int *output_len) {
	*output_len = oidc_base64url_decode(pool, output, input);
	if (*output_len <= 0)
		return apr_psprintf(pool, "base64url-decoding of \"%s\" failed", input);
	return NULL;
}

/*
 * parse a hexadecimal encoded binary value from the provided string
 */
static char *oidc_parse_hex(apr_pool_t *pool, const char *input, char **output,
		int *output_len) {
	*output_len = strlen(input) / 2;
	const char *pos = input;
	unsigned char *val = apr_palloc(pool, *output_len);
	size_t count = 0;
	for (count = 0; count < (*output_len) / sizeof(unsigned char); count++) {
		sscanf(pos, "%2hhx", &val[count]);
		pos += 2;
	}
	*output = (char*) val;
	return NULL;
}

#define OIDC_KEY_ENCODING_BASE64     "b64"
#define OIDC_KEY_ENCODING_BASE64_URL "b64url"
#define OIDC_KEY_ENCODING_HEX        "hex"
#define OIDC_KEY_ENCODING_PLAIN      "plain"

/*
 * parse a key value based on the provided encoding: b64|b64url|hex|plain
 */
static const char *oidc_parse_key_value(apr_pool_t *pool, const char *enc,
		const char *input, char **key, int *key_len) {
	static char *options[] = {
			OIDC_KEY_ENCODING_BASE64,
			OIDC_KEY_ENCODING_BASE64_URL,
			OIDC_KEY_ENCODING_HEX,
			OIDC_KEY_ENCODING_PLAIN,
			NULL };
	const char *rv = oidc_valid_string_option(pool, enc, options);
	if (rv != NULL)
		return rv;
	if (apr_strnatcmp(enc, OIDC_KEY_ENCODING_BASE64) == 0)
		return oidc_parse_base64(pool, input, key, key_len);
	if (apr_strnatcmp(enc, OIDC_KEY_ENCODING_BASE64_URL) == 0)
		return oidc_parse_base64url(pool, input, key, key_len);
	if (apr_strnatcmp(enc, OIDC_KEY_ENCODING_HEX) == 0)
		return oidc_parse_hex(pool, input, key, key_len);
	if (apr_strnatcmp(enc, OIDC_KEY_ENCODING_PLAIN) == 0) {
		*key = apr_pstrdup(pool, input);
		*key_len = strlen(*key);
	}
	return NULL;
}

#define OIDC_KEY_TUPLE_SEPARATOR "#"

/*
 * parse a <encoding>#<key-identifier>#<key> tuple
 */
const char *oidc_parse_enc_kid_key_tuple(apr_pool_t *pool, const char *tuple,
		char **kid, char **key, int *key_len, apr_byte_t triplet) {
	const char *rv = NULL;
	char *s = NULL, *p = NULL, *q = NULL, *enc = NULL;

	if ((tuple == NULL) || (apr_strnatcmp(tuple, "") == 0))
		return "tuple value not set";

	s = apr_pstrdup(pool, tuple);
	p = strstr(s, OIDC_KEY_TUPLE_SEPARATOR);
	if (p && triplet)
		q = strstr(p + 1, OIDC_KEY_TUPLE_SEPARATOR);

	if (p) {
		if (q) {
			*p = '\0';
			*q = '\0';
			enc = s;
			p++;
			if (p != q)
				*kid = apr_pstrdup(pool, p);
			rv = oidc_parse_key_value(pool, enc, q + 1, key, key_len);
		} else {
			*p = '\0';
			*kid = s;
			*key = p + 1;
			*key_len = strlen(*key);
		}
	} else {
		*kid = NULL;
		*key = s;
		*key_len = strlen(*key);
	}

	return rv;
}

#define OIDC_PASS_ID_TOKEN_AS_CLAIMS_STR    "claims"
#define OIDC_PASS_IDTOKEN_AS_PAYLOAD_STR    "payload"
#define OIDC_PASS_IDTOKEN_AS_SERIALIZED_STR "serialized"

/*
 * convert a "pass id token as" value to an integer
 */
static int oidc_parse_pass_idtoken_as_str2int(const char *v) {
	if (apr_strnatcmp(v, OIDC_PASS_ID_TOKEN_AS_CLAIMS_STR) == 0)
		return OIDC_PASS_IDTOKEN_AS_CLAIMS;
	if (apr_strnatcmp(v, OIDC_PASS_IDTOKEN_AS_PAYLOAD_STR) == 0)
		return OIDC_PASS_IDTOKEN_AS_PAYLOAD;
	if (apr_strnatcmp(v, OIDC_PASS_IDTOKEN_AS_SERIALIZED_STR) == 0)
		return OIDC_PASS_IDTOKEN_AS_SERIALIZED;
	return -1;
}

/*
 * parse a "pass id token as" value from the provided strings
 */
const char *oidc_parse_pass_idtoken_as(apr_pool_t *pool, const char *v1,
		const char *v2, const char *v3, int *int_value) {
	static char *options[] = {
			OIDC_PASS_ID_TOKEN_AS_CLAIMS_STR,
			OIDC_PASS_IDTOKEN_AS_PAYLOAD_STR,
			OIDC_PASS_IDTOKEN_AS_SERIALIZED_STR,
			NULL };
	const char *rv = NULL;
	rv = oidc_valid_string_option(pool, v1, options);
	if (rv != NULL)
		return rv;
	*int_value = oidc_parse_pass_idtoken_as_str2int(v1);

	if (v2 == NULL)
		return NULL;

	rv = oidc_valid_string_option(pool, v2, options);
	if (rv != NULL)
		return rv;
	*int_value |= oidc_parse_pass_idtoken_as_str2int(v2);

	if (v3 == NULL)
		return NULL;

	rv = oidc_valid_string_option(pool, v3, options);
	if (rv != NULL)
		return rv;
	*int_value |= oidc_parse_pass_idtoken_as_str2int(v3);

	return NULL;
}

#define OIDC_PASS_USERINFO_AS_CLAIMS_STR      "claims"
#define OIDC_PASS_USERINFO_AS_JSON_OBJECT_STR "json"
#define OIDC_PASS_USERINFO_AS_JWT_STR         "jwt"

/*
 * convert a "pass userinfo as" value to an integer
 */
static int oidc_parse_pass_userinfo_as_str2int(const char *v) {
	if (apr_strnatcmp(v, OIDC_PASS_USERINFO_AS_CLAIMS_STR) == 0)
		return OIDC_PASS_USERINFO_AS_CLAIMS;
	if (apr_strnatcmp(v, OIDC_PASS_USERINFO_AS_JSON_OBJECT_STR) == 0)
		return OIDC_PASS_USERINFO_AS_JSON_OBJECT;
	if (apr_strnatcmp(v, OIDC_PASS_USERINFO_AS_JWT_STR) == 0)
		return OIDC_PASS_USERINFO_AS_JWT;
	return -1;
}

/*
 * parse a "pass id token as" value from the provided strings
 */
const char *oidc_parse_pass_userinfo_as(apr_pool_t *pool, const char *v1,
		const char *v2, const char *v3, int *int_value) {
	static char *options[] = {
			OIDC_PASS_USERINFO_AS_CLAIMS_STR,
			OIDC_PASS_USERINFO_AS_JSON_OBJECT_STR,
			OIDC_PASS_USERINFO_AS_JWT_STR,
			NULL };
	const char *rv = NULL;
	rv = oidc_valid_string_option(pool, v1, options);
	if (rv != NULL)
		return rv;
	*int_value = oidc_parse_pass_userinfo_as_str2int(v1);

	if (v2 == NULL)
		return NULL;

	rv = oidc_valid_string_option(pool, v2, options);
	if (rv != NULL)
		return rv;
	*int_value |= oidc_parse_pass_userinfo_as_str2int(v2);

	if (v3 == NULL)
		return NULL;

	rv = oidc_valid_string_option(pool, v3, options);
	if (rv != NULL)
		return rv;
	*int_value |= oidc_parse_pass_userinfo_as_str2int(v3);

	return NULL;
}

#define OIDC_LOGOUT_ON_ERROR_REFRESH_STR "logout_on_error"

/*
 * convert a "logout_on_error" to an integer
 */
static int oidc_parse_logout_on_error_refresh_as_str2int(const char *v) {
	if (apr_strnatcmp(v, OIDC_LOGOUT_ON_ERROR_REFRESH_STR) == 0)
		return OIDC_LOGOUT_ON_ERROR_REFRESH;
	return OIDC_CONFIG_POS_INT_UNSET;
}

/*
 * parse a "logout_on_error" value from the provided strings
 */
const char *oidc_parse_logout_on_error_refresh_as(apr_pool_t *pool, const char *v1,
		int *int_value) {
	static char *options[] = {
			OIDC_LOGOUT_ON_ERROR_REFRESH_STR,
			NULL };
	const char *rv = NULL;
	rv = oidc_valid_string_option(pool, v1, options);
	if (rv != NULL)
		return rv;
	*int_value = oidc_parse_logout_on_error_refresh_as_str2int(v1);

	return NULL;
}

#define OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER_STR "header"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_POST_STR   "post"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY_STR  "query"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_STR "cookie"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC_STR  "basic"

/*
 * convert an "accept OAuth 2.0 token in" byte value to a string representation
 */
const char *oidc_accept_oauth_token_in2str(apr_pool_t *pool, apr_byte_t v) {
	static char *options[] = { NULL, NULL, NULL, NULL, NULL };
	int i = 0;
	if (v & OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER) {
		options[i] = OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER_STR;
		i++;
	}
	if (v & OIDC_OAUTH_ACCEPT_TOKEN_IN_POST) {
		options[i] = OIDC_OAUTH_ACCEPT_TOKEN_IN_POST_STR;
		i++;
	}
	if (v & OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY) {
		options[i] = OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY_STR;
		i++;
	}
	if (v & OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE) {
		options[i] = OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_STR;
		i++;
	}
	if (v & OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC) {
		options[i] = OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC_STR;
		i++;
	}
	return oidc_flatten_list_options(pool, options);
}

/*
 * convert an "accept OAuth 2.0 token in" value to an integer
 */
static apr_byte_t oidc_parse_oauth_accept_token_in_str2byte(const char *v) {
	if (apr_strnatcmp(v, OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER_STR) == 0)
		return OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER;
	if (apr_strnatcmp(v, OIDC_OAUTH_ACCEPT_TOKEN_IN_POST_STR) == 0)
		return OIDC_OAUTH_ACCEPT_TOKEN_IN_POST;
	if (apr_strnatcmp(v, OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY_STR) == 0)
		return OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY;
	if (strstr(v, OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_STR) == v)
		return OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE;
	if (strstr(v, OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC_STR) == v)
		return OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC;
	return OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT;
}

#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_NAME_DEFAULT "PA.global"
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_SEPARATOR    ":"

/*
 * parse an "accept OAuth 2.0 token in" value from the provided string
 */
const char *oidc_parse_accept_oauth_token_in(apr_pool_t *pool, const char *arg,
		int *b_value, apr_hash_t *list_options) {
	static char *options[] = {
			OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER_STR,
			OIDC_OAUTH_ACCEPT_TOKEN_IN_POST_STR,
			OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY_STR,
			OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_STR,
			OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC_STR,
			NULL };
	const char *rv = NULL;

	const char *s = apr_pstrdup(pool, arg);
	char *p = strstr(s, OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_SEPARATOR);

	if (p != NULL) {
		*p = '\0';
		p++;
	} else {
		p = OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE_NAME_DEFAULT;
	}

	rv = oidc_valid_string_option(pool, s, options);
	if (rv != NULL)
		return rv;

	int v = oidc_parse_oauth_accept_token_in_str2byte(s);
	if (*b_value == OIDC_CONFIG_POS_INT_UNSET)
		*b_value = v;
	else
		*b_value |= v;

	if (v == OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE) {
		apr_hash_set(list_options,
				OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME,
				APR_HASH_KEY_STRING, p);
	}

	return NULL;
}

/*
 * check if the specified string is a valid claim formatting configuration value
 */
const char *oidc_valid_claim_format(apr_pool_t *pool, const char *arg) {
	static char *options[] = {
			OIDC_CLAIM_FORMAT_RELATIVE,
			OIDC_CLAIM_FORMAT_ABSOLUTE,
			NULL };
	return oidc_valid_string_option(pool, arg, options);
}

/*
 * parse a "claim required" value from the provided string
 */
const char *oidc_parse_claim_required(apr_pool_t *pool, const char *arg,
		int *is_required) {
	static char *options[] = {
			OIDC_CLAIM_REQUIRED_MANDATORY,
			OIDC_CLAIM_REQUIRED_OPTIONAL,
			NULL };
	const char *rv = oidc_valid_string_option(pool, arg, options);
	if (rv != NULL)
		return rv;
	*is_required = (apr_strnatcmp(arg, OIDC_CLAIM_REQUIRED_MANDATORY) == 0);
	return NULL;
}

/*
 * check if the provided string is a valid HTTP method for the OAuth token introspection endpoint
 */
const char *oidc_valid_introspection_method(apr_pool_t *pool, const char *arg) {
	static char *options[] = {
			OIDC_INTROSPECTION_METHOD_GET,
			OIDC_INTROSPECTION_METHOD_POST,
			NULL };
	return oidc_valid_string_option(pool, arg, options);
}

#define OIDC_PASS_CLAIMS_AS_BOTH    "both"
#define OIDC_PASS_CLAIMS_AS_HEADERS "headers"
#define OIDC_PASS_CLAIMS_AS_ENV     "environment"
#define OIDC_PASS_CLAIMS_AS_NONE    "none"

/*
 * parse a "set claims as" value from the provided string
 */
const char *oidc_parse_set_claims_as(apr_pool_t *pool, const char *arg,
		int *in_headers, int *in_env_vars) {
	static char *options[] = {
			OIDC_PASS_CLAIMS_AS_BOTH,
			OIDC_PASS_CLAIMS_AS_HEADERS,
			OIDC_PASS_CLAIMS_AS_ENV,
			OIDC_PASS_CLAIMS_AS_NONE,
			NULL };
	const char *rv = oidc_valid_string_option(pool, arg, options);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_PASS_CLAIMS_AS_BOTH) == 0) {
		*in_headers = 1;
		*in_env_vars = 1;
	} else if (apr_strnatcmp(arg, OIDC_PASS_CLAIMS_AS_HEADERS) == 0) {
		*in_headers = 1;
		*in_env_vars = 0;
	} else if (apr_strnatcmp(arg, OIDC_PASS_CLAIMS_AS_ENV) == 0) {
		*in_headers = 0;
		*in_env_vars = 1;
	} else if (apr_strnatcmp(arg, OIDC_PASS_CLAIMS_AS_NONE) == 0) {
		*in_headers = 0;
		*in_env_vars = 0;
	}

	return NULL;
}

#define OIDC_UNAUTH_ACTION_AUTH_STR "auth"
#define OIDC_UNAUTH_ACTION_PASS_STR "pass"
#define OIDC_UNAUTH_ACTION_401_STR  "401"
#define OIDC_UNAUTH_ACTION_407_STR  "407"
#define OIDC_UNAUTH_ACTION_410_STR  "410"

/*
 * parse an "unauthenticated action" value from the provided string
 */
const char *oidc_parse_unauth_action(apr_pool_t *pool, const char *arg,
		int *action) {
	static char *options[] = {
			OIDC_UNAUTH_ACTION_AUTH_STR,
			OIDC_UNAUTH_ACTION_PASS_STR,
			OIDC_UNAUTH_ACTION_401_STR,
			OIDC_UNAUTH_ACTION_407_STR,
			OIDC_UNAUTH_ACTION_410_STR,
			NULL };
	const char *rv = oidc_valid_string_option(pool, arg, options);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_UNAUTH_ACTION_AUTH_STR) == 0)
		*action = OIDC_UNAUTH_AUTHENTICATE;
	else if (apr_strnatcmp(arg, OIDC_UNAUTH_ACTION_PASS_STR) == 0)
		*action = OIDC_UNAUTH_PASS;
	else if (apr_strnatcmp(arg, OIDC_UNAUTH_ACTION_401_STR) == 0)
		*action = OIDC_UNAUTH_RETURN401;
	else if (apr_strnatcmp(arg, OIDC_UNAUTH_ACTION_407_STR) == 0)
		*action = OIDC_UNAUTH_RETURN407;
	else if (apr_strnatcmp(arg, OIDC_UNAUTH_ACTION_410_STR) == 0)
		*action = OIDC_UNAUTH_RETURN410;

	return NULL;
}

#define OIDC_UNAUTZ_ACTION_AUTH_STR "auth"
#define OIDC_UNAUTZ_ACTION_401_STR  "401"
#define OIDC_UNAUTZ_ACTION_403_STR  "403"

/*
 * parse an "unauthorized action" value from the provided string
 */
const char *oidc_parse_unautz_action(apr_pool_t *pool, const char *arg,
		int *action) {
	static char *options[] = {
			OIDC_UNAUTZ_ACTION_AUTH_STR,
			OIDC_UNAUTZ_ACTION_401_STR,
			OIDC_UNAUTZ_ACTION_403_STR,
			NULL };
	const char *rv = oidc_valid_string_option(pool, arg, options);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_UNAUTZ_ACTION_AUTH_STR) == 0)
		*action = OIDC_UNAUTZ_AUTHENTICATE;
	else if (apr_strnatcmp(arg, OIDC_UNAUTZ_ACTION_401_STR) == 0)
		*action = OIDC_UNAUTZ_RETURN401;
	else if (apr_strnatcmp(arg, OIDC_UNAUTZ_ACTION_403_STR) == 0)
		*action = OIDC_UNAUTZ_RETURN403;

	return NULL;
}

/*
 * check if there's a valid entry in a string of arrays, with a preference
 */
const char *oidc_valid_string_in_array(apr_pool_t *pool, json_t *json,
		const char *key, oidc_valid_function_t valid_function, char **value,
		apr_byte_t optional, const char *preference) {
	int i = 0;
	json_t *json_arr = json_object_get(json, key);
	apr_byte_t found = FALSE;
	if ((json_arr != NULL) && (json_is_array(json_arr))) {
		for (i = 0; i < json_array_size(json_arr); i++) {
			json_t *elem = json_array_get(json_arr, i);
			if (!json_is_string(elem)) {
				return apr_psprintf(pool,
						"unhandled in-array JSON non-string object type [%d]",
						elem->type);
				continue;
			}
			if (valid_function(pool, json_string_value(elem)) == NULL) {
				found = TRUE;
				if (value != NULL) {
					if ((preference != NULL)
							&& (apr_strnatcmp(json_string_value(elem),
									preference) == 0)) {
						*value = apr_pstrdup(pool, json_string_value(elem));
						break;
					}
					if (*value == NULL) {
						*value = apr_pstrdup(pool, json_string_value(elem));
					}
				}
			}
		}
		if (found == FALSE) {
			return apr_psprintf(pool,
					"could not find a valid array string element for entry \"%s\"",
					key);
		}
	} else if (optional == FALSE) {
		return apr_psprintf(pool, "JSON object did not contain a \"%s\" array",
				key);
	}
	return NULL;
}

#define OIDC_JWKS_REFRESH_INTERVAL_MIN 300
#define OIDC_JWKS_REFRESH_INTERVAL_MAX 3600 * 24 * 365

/*
 * check the boundaries for JWKs refresh interval
 */
const char *oidc_valid_jwks_refresh_interval(apr_pool_t *pool, int v) {
	return oidc_valid_int_min_max(pool, v, OIDC_JWKS_REFRESH_INTERVAL_MIN,
			OIDC_JWKS_REFRESH_INTERVAL_MAX);
}

/*
 * parse a JWKs refresh interval from the provided string
 */
const char *oidc_parse_jwks_refresh_interval(apr_pool_t *pool, const char *arg,
		int *int_value) {
	return oidc_parse_int_valid(pool, arg, int_value,
			oidc_valid_jwks_refresh_interval);
}

#define OIDC_IDTOKEN_IAT_SLACK_MIN 0
#define OIDC_IDTOKEN_IAT_SLACK_MAX 3600

/*
 * check the boundaries for ID token "issued-at" (iat) timestamp slack
 */
const char *oidc_valid_idtoken_iat_slack(apr_pool_t *pool, int v) {
	return oidc_valid_int_min_max(pool, v, OIDC_IDTOKEN_IAT_SLACK_MIN,
			OIDC_IDTOKEN_IAT_SLACK_MAX);
}

/*
 * parse an ID token "iat" slack interval
 */
const char *oidc_parse_idtoken_iat_slack(apr_pool_t *pool, const char *arg,
		int *int_value) {
	return oidc_parse_int_valid(pool, arg, int_value,
			oidc_valid_idtoken_iat_slack);
}

#define OIDC_USERINFO_REFRESH_INTERVAL_MIN 0
#define OIDC_USERINFO_REFRESH_INTERVAL_MAX 3600 * 24 * 365

/*
 * check the boundaries for the userinfo refresh interval
 */
const char *oidc_valid_userinfo_refresh_interval(apr_pool_t *pool, int v) {
	return oidc_valid_int_min_max(pool, v, OIDC_USERINFO_REFRESH_INTERVAL_MIN,
			OIDC_USERINFO_REFRESH_INTERVAL_MAX);
}

/*
 * parse a userinfo refresh interval from the provided string
 */
const char *oidc_parse_userinfo_refresh_interval(apr_pool_t *pool,
		const char *arg, int *int_value) {
	return oidc_parse_int_valid(pool, arg, int_value,
			oidc_valid_userinfo_refresh_interval);
}

#define OIDC_USER_INFO_TOKEN_METHOD_HEADER_STR "authz_header"
#define OIDC_USER_INFO_TOKEN_METHOD_POST_STR   "post_param"

/*
 * check if the provided string is a valid userinfo token presentation method
 */
const char *oidc_valid_userinfo_token_method(apr_pool_t *pool, const char *arg) {
	static char *options[] = {
			OIDC_USER_INFO_TOKEN_METHOD_HEADER_STR,
			OIDC_USER_INFO_TOKEN_METHOD_POST_STR,
			NULL };
	return oidc_valid_string_option(pool, arg, options);
}

/*
 * parse a userinfo token method string value to an integer
 */
const char *oidc_parse_userinfo_token_method(apr_pool_t *pool, const char *arg,
		int *int_value) {
	const char *rv = oidc_valid_userinfo_token_method(pool, arg);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_USER_INFO_TOKEN_METHOD_HEADER_STR) == 0)
		*int_value = OIDC_USER_INFO_TOKEN_METHOD_HEADER;
	if (apr_strnatcmp(arg, OIDC_USER_INFO_TOKEN_METHOD_POST_STR) == 0)
		*int_value = OIDC_USER_INFO_TOKEN_METHOD_POST;

	return NULL;
}

/*
 * parse an "info hook data" value from the provided string
 */
const char *oidc_parse_info_hook_data(apr_pool_t *pool, const char *arg,
		apr_hash_t **hook_data) {
	static char *options[] = {
			OIDC_HOOK_INFO_TIMESTAMP,
			OIDC_HOOK_INFO_ACCES_TOKEN,
			OIDC_HOOK_INFO_ACCES_TOKEN_EXP,
			OIDC_HOOK_INFO_ID_TOKEN,
			OIDC_HOOK_INFO_USER_INFO,
			OIDC_HOOK_INFO_REFRESH_TOKEN,
			OIDC_HOOK_INFO_SESSION,
			NULL };
	const char *rv = oidc_valid_string_option(pool, arg, options);
	if (rv != NULL)
		return rv;
	if (*hook_data == NULL)
		*hook_data = apr_hash_make(pool);
	apr_hash_set(*hook_data, arg, APR_HASH_KEY_STRING, arg);

	return NULL;
}

#define OIDC_TOKEN_BINDING_POLICY_DISABLED_STR "disabled"
#define OIDC_TOKEN_BINDING_POLICY_OPTIONAL_STR "optional"
#define OIDC_TOKEN_BINDING_POLICY_REQUIRED_STR "required"
#define OIDC_TOKEN_BINDING_POLICY_ENFORCED_STR "enforced"

const char *oidc_token_binding_policy2str(apr_pool_t *pool, int v) {
	if (v == OIDC_TOKEN_BINDING_POLICY_DISABLED)
		return OIDC_TOKEN_BINDING_POLICY_DISABLED;
	if (v == OIDC_TOKEN_BINDING_POLICY_OPTIONAL)
		return OIDC_TOKEN_BINDING_POLICY_OPTIONAL_STR;
	if (v == OIDC_TOKEN_BINDING_POLICY_REQUIRED)
		return OIDC_TOKEN_BINDING_POLICY_REQUIRED_STR;
	if (v == OIDC_TOKEN_BINDING_POLICY_ENFORCED)
		return OIDC_TOKEN_BINDING_POLICY_ENFORCED_STR;
	return NULL;
}

/*
 * check token binding policy string value
 */
const char *oidc_valid_token_binding_policy(apr_pool_t *pool, const char *arg) {
	static char *options[] = {
			OIDC_TOKEN_BINDING_POLICY_DISABLED_STR,
			OIDC_TOKEN_BINDING_POLICY_OPTIONAL_STR,
			OIDC_TOKEN_BINDING_POLICY_REQUIRED_STR,
			OIDC_TOKEN_BINDING_POLICY_ENFORCED_STR,
			NULL };
	return oidc_valid_string_option(pool, arg, options);
}

/*
 * parse token binding policy
 */
const char *oidc_parse_token_binding_policy(apr_pool_t *pool, const char *arg,
		int *policy) {
	const char *rv = oidc_valid_token_binding_policy(pool, arg);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_TOKEN_BINDING_POLICY_DISABLED_STR) == 0)
		*policy = OIDC_TOKEN_BINDING_POLICY_DISABLED;
	else if (apr_strnatcmp(arg, OIDC_TOKEN_BINDING_POLICY_OPTIONAL_STR) == 0)
		*policy = OIDC_TOKEN_BINDING_POLICY_OPTIONAL;
	else if (apr_strnatcmp(arg, OIDC_TOKEN_BINDING_POLICY_REQUIRED_STR) == 0)
		*policy = OIDC_TOKEN_BINDING_POLICY_REQUIRED;
	else if (apr_strnatcmp(arg, OIDC_TOKEN_BINDING_POLICY_ENFORCED_STR) == 0)
		*policy = OIDC_TOKEN_BINDING_POLICY_ENFORCED;

	return NULL;
}

#define OIDC_AUTH_REQUEST_METHOD_GET_STR  "GET"
#define OIDC_AUTH_REQEUST_METHOD_POST_STR "POST"

/*
 * parse method for sending the authentication request
 */
const char *oidc_valid_auth_request_method(apr_pool_t *pool, const char *arg) {
	static char *options[] = {
			OIDC_AUTH_REQUEST_METHOD_GET_STR,
			OIDC_AUTH_REQEUST_METHOD_POST_STR,
			NULL };
	return oidc_valid_string_option(pool, arg, options);
}

/*
 * parse method for sending the authentication request
 */
const char *oidc_parse_auth_request_method(apr_pool_t *pool, const char *arg,
		int *method) {
	const char *rv = oidc_valid_auth_request_method(pool, arg);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_AUTH_REQUEST_METHOD_GET_STR) == 0)
		*method = OIDC_AUTH_REQUEST_METHOD_GET;
	else if (apr_strnatcmp(arg, OIDC_AUTH_REQEUST_METHOD_POST_STR) == 0)
		*method = OIDC_AUTH_REQUEST_METHOD_POST;

	return NULL;
}

/*
 * parse the maximum number of parallel state cookies
 */
const char *oidc_parse_max_number_of_state_cookies(apr_pool_t *pool,
		const char *arg1, const char *arg2, int *int_value, int *bool_value) {
	const char *rv = NULL;

	rv = oidc_parse_int_valid(pool, arg1, int_value,
			oidc_valid_max_number_of_state_cookies);
	if ((rv == NULL) && (arg2 != NULL))
		rv = oidc_parse_boolean(pool, arg2, bool_value);
	return rv;
}

#define OIDC_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY_MIN 0
#define OIDC_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY_MAX 3600 * 24 * 365

/*
 * check the boundaries for the refresh access token expiry TTL
 */
const char *oidc_valid_refresh_access_token_before_expiry(apr_pool_t *pool,
		int v) {
	return oidc_valid_int_min_max(pool, v,
			OIDC_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY_MIN,
			OIDC_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY_MAX);
}

/*
 * parse an access token expiry TTL from the provided string
 */
const char *oidc_parse_refresh_access_token_before_expiry(apr_pool_t *pool,
		const char *arg, int *int_value) {
	return oidc_parse_int_valid(pool, arg, int_value,
			oidc_valid_refresh_access_token_before_expiry);
}

#define OIDC_STATE_INPUT_HEADERS_AS_BOTH            "both"
#define OIDC_STATE_INPUT_HEADERS_AS_USER_AGENT      "user-agent"
#define OIDC_STATE_INPUT_HEADERS_AS_X_FORWARDED_FOR "x-forwarded-for"
#define OIDC_STATE_INPUT_HEADERS_AS_NONE            "none"

/*
 * parse a "set state input headers as" value from the provided string
 */
const char *oidc_parse_set_state_input_headers_as(apr_pool_t *pool, const char *arg,
		apr_byte_t *state_input_headers) {
	static char *options[] = {
			OIDC_STATE_INPUT_HEADERS_AS_BOTH,
			OIDC_STATE_INPUT_HEADERS_AS_USER_AGENT,
			OIDC_STATE_INPUT_HEADERS_AS_X_FORWARDED_FOR,
			OIDC_STATE_INPUT_HEADERS_AS_NONE,
			NULL };
	const char *rv = oidc_valid_string_option(pool, arg, options);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_STATE_INPUT_HEADERS_AS_BOTH) == 0) {
		*state_input_headers = OIDC_STATE_INPUT_HEADERS_USER_AGENT | OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR;
	} else if (apr_strnatcmp(arg, OIDC_STATE_INPUT_HEADERS_AS_USER_AGENT) == 0) {
		*state_input_headers = OIDC_STATE_INPUT_HEADERS_USER_AGENT;
	} else if (apr_strnatcmp(arg, OIDC_STATE_INPUT_HEADERS_AS_X_FORWARDED_FOR) == 0) {
		*state_input_headers = OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR;
	} else if (apr_strnatcmp(arg, OIDC_STATE_INPUT_HEADERS_AS_NONE) == 0) {
		*state_input_headers = 0;
	}

	return NULL;
}