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

#include "mod_auth_openidc.h"

#include "metrics.h"
#include "pcre_subst.h"
#include <curl/curl.h>
#ifndef WIN32
#include <unistd.h>
#endif
#ifdef USE_LIBJQ
#include "jq.h"
#endif

/* hrm, should we get rid of this by adding parameters to the (3) functions? */
extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

apr_byte_t oidc_util_random_bytes(unsigned char *buf, apr_size_t length) {
	apr_byte_t rv = TRUE;

#ifndef USE_URANDOM

	rv = (apr_generate_random_bytes(buf, length) == APR_SUCCESS);

#else

	int fd = -1;

	do {
		apr_ssize_t rc;

		if (fd == -1) {
			fd = open(DEV_RANDOM, O_RDONLY);
			if (fd == -1)
				return errno;
		}

		do {
			rc = read(fd, buf, length);
		} while (rc == -1 && errno == EINTR);

		if (rc < 0) {
			int errnum = errno;
			close(fd);
			return errnum;
		} else if (rc == 0) {
			close(fd);
			fd = -1; /* force open() again */
		} else {
			buf += rc;
			length -= rc;
		}
	} while (length > 0);

	close(fd);

	rv = TRUE;

#endif

	return rv;
}

apr_byte_t oidc_util_generate_random_bytes(request_rec *r, unsigned char *buf, apr_size_t length) {
	apr_byte_t rv = TRUE;
	const char *gen = NULL;
#ifndef USE_URANDOM
	gen = "apr";
#else
	gen = DEV_RANDOM;
#endif
	oidc_debug(r, "oidc_util_random_bytes [%s] call for %" APR_SIZE_T_FMT " bytes", gen, length);
	rv = oidc_util_random_bytes(buf, length);
	oidc_debug(r, "oidc_util_random_bytes returned: %d", rv);

	return rv;
}

apr_byte_t oidc_proto_generate_random_hex_string(request_rec *r, char **hex_str, int byte_len) {
	unsigned char *bytes = apr_pcalloc(r->pool, byte_len);
	int i = 0;
	if (oidc_util_generate_random_bytes(r, bytes, byte_len) != TRUE) {
		oidc_error(r, "oidc_util_generate_random_bytes returned an error");
		return FALSE;
	}
	*hex_str = "";
	for (i = 0; i < byte_len; i++)
		*hex_str = apr_psprintf(r->pool, "%s%02x", *hex_str, bytes[i]);

	return TRUE;
}

/*
 * base64url encode a string
 */
int oidc_base64url_encode(request_rec *r, char **dst, const char *src, int src_len, int remove_padding) {
	if ((src == NULL) || (src_len <= 0)) {
		oidc_error(r, "not encoding anything; src=NULL and/or src_len<1");
		return -1;
	}
	unsigned int enc_len = apr_base64_encode_len(src_len);
	char *enc = apr_palloc(r->pool, enc_len);
	apr_base64_encode(enc, src, src_len);
	unsigned int i = 0;
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
		if (enc_len > 0)
			enc_len--;
		if ((enc_len > 0) && (enc[enc_len - 1] == ','))
			enc_len--;
		if ((enc_len > 0) && (enc[enc_len - 1] == ','))
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
	switch (_oidc_strlen(dec) % 4) {
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

static const char *oidc_util_get__oidc_jwt_hdr_dir_a256gcm(request_rec *r, char *input) {
	char *compact_encoded_jwt = NULL;
	char *p = NULL;
	static const char *_oidc_jwt_hdr_dir_a256gcm = NULL;
	static oidc_crypto_passphrase_t passphrase;

	if (_oidc_jwt_hdr_dir_a256gcm != NULL)
		return _oidc_jwt_hdr_dir_a256gcm;

	if (input == NULL) {
		passphrase.secret1 = "needs_non_empty_string";
		passphrase.secret2 = NULL;
		oidc_util_jwt_create(r, &passphrase, "some_string", &compact_encoded_jwt);
	} else {
		compact_encoded_jwt = input;
	}

	p = strstr(compact_encoded_jwt, "..");
	if (p) {
		_oidc_jwt_hdr_dir_a256gcm = apr_pstrndup(r->server->process->pconf, compact_encoded_jwt,
							 _oidc_strlen(compact_encoded_jwt) - _oidc_strlen(p) + 2);
		oidc_debug(r, "saved _oidc_jwt_hdr_dir_a256gcm header: %s", _oidc_jwt_hdr_dir_a256gcm);
	}
	return _oidc_jwt_hdr_dir_a256gcm;
}

static apr_byte_t oidc_util_env_var_override(request_rec *r, const char *env_var_name, apr_byte_t return_when_set) {
	const char *s = NULL;
	if (r->subprocess_env == NULL)
		return !return_when_set;
	s = apr_table_get(r->subprocess_env, env_var_name);
	return (s != NULL) && (_oidc_strcmp(s, "true") == 0) ? return_when_set : !return_when_set;
}

#define OIDC_JWT_INTERNAL_NO_COMPRESS_ENV_VAR "OIDC_JWT_INTERNAL_NO_COMPRESS"

static apr_byte_t oidc_util_jwt_internal_compress(request_rec *r) {
	// avoid compressing JWTs that need to be compatible with external producers/consumers
	return oidc_util_env_var_override(r, OIDC_JWT_INTERNAL_NO_COMPRESS_ENV_VAR, FALSE);
}

#define OIDC_JWT_INTERNAL_STRIP_HDR_ENV_VAR "OIDC_JWT_INTERNAL_STRIP_HDR"

static apr_byte_t oidc_util_jwt_internal_strip_header(request_rec *r) {
	// avoid stripping JWT headers that need to be compatible with external producers/consumers
	return oidc_util_env_var_override(r, OIDC_JWT_INTERNAL_STRIP_HDR_ENV_VAR, TRUE);
}

apr_byte_t oidc_util_jwt_create(request_rec *r, const oidc_crypto_passphrase_t *passphrase, const char *s_payload,
				char **compact_encoded_jwt) {

	apr_byte_t rv = FALSE;
	oidc_jose_error_t err;
	char *cser = NULL;
	int cser_len = 0;

	oidc_jwk_t *jwk = NULL;
	oidc_jwt_t *jwe = NULL;

	if (passphrase->secret1 == NULL) {
		oidc_error(r, "secret is not set");
		goto end;
	}

	if (oidc_util_create_symmetric_key(r, passphrase->secret1, 0, OIDC_JOSE_ALG_SHA256, FALSE, &jwk) == FALSE)
		goto end;

	if (oidc_util_jwt_internal_compress(r)) {
		if (oidc_jose_compress(r->pool, s_payload, _oidc_strlen(s_payload), &cser, &cser_len, &err) == FALSE) {
			oidc_error(r, "oidc_jose_compress failed: %s", oidc_jose_e2s(r->pool, err));
			goto end;
		}
	} else {
		cser = apr_pstrdup(r->pool, s_payload);
		cser_len = _oidc_strlen(s_payload);
	}

	jwe = oidc_jwt_new(r->pool, TRUE, FALSE);
	if (jwe == NULL) {
		oidc_error(r, "creating JWE failed");
		goto end;
	}

	jwe->header.alg = apr_pstrdup(r->pool, CJOSE_HDR_ALG_DIR);
	jwe->header.enc = apr_pstrdup(r->pool, CJOSE_HDR_ENC_A256GCM);
	if (passphrase->secret2 != NULL)
		jwe->header.kid = apr_pstrdup(r->pool, "1");

	if (oidc_jwt_encrypt(r->pool, jwe, jwk, cser, cser_len, compact_encoded_jwt, &err) == FALSE) {
		oidc_error(r, "encrypting JWT failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	if ((*compact_encoded_jwt != NULL) && (oidc_util_jwt_internal_strip_header(r)))
		*compact_encoded_jwt += _oidc_strlen(oidc_util_get__oidc_jwt_hdr_dir_a256gcm(r, *compact_encoded_jwt));

	rv = TRUE;

end:

	if (jwe != NULL)
		oidc_jwt_destroy(jwe);
	if (jwk != NULL)
		oidc_jwk_destroy(jwk);

	return rv;
}

apr_byte_t oidc_util_jwt_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
				const char *compact_encoded_jwt, char **s_payload) {

	apr_byte_t rv = FALSE;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	oidc_jwt_t *jwt = NULL;
	char *payload = NULL;
	int payload_len = 0;
	char *plaintext = NULL;
	int plaintext_len = 0;
	apr_hash_t *keys = NULL;
	char *alg = NULL;
	char *enc = NULL;
	char *kid = NULL;

	if (oidc_util_jwt_internal_strip_header(r))
		compact_encoded_jwt =
		    apr_pstrcat(r->pool, oidc_util_get__oidc_jwt_hdr_dir_a256gcm(r, NULL), compact_encoded_jwt, NULL);

	oidc_proto_peek_jwt_header(r, compact_encoded_jwt, &alg, &enc, &kid);
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_DIR) != 0) || (_oidc_strcmp(enc, CJOSE_HDR_ENC_A256GCM) != 0)) {
		oidc_error(r, "corrupted JWE header, alg=\"%s\" enc=\"%s\"", alg, enc);
		goto end;
	}

	keys = apr_hash_make(r->pool);

	if ((passphrase->secret2 != NULL) && (kid == NULL)) {
		if (oidc_util_create_symmetric_key(r, passphrase->secret2, 0, OIDC_JOSE_ALG_SHA256, FALSE, &jwk) ==
		    FALSE)
			goto end;
	} else {
		if (oidc_util_create_symmetric_key(r, passphrase->secret1, 0, OIDC_JOSE_ALG_SHA256, FALSE, &jwk) ==
		    FALSE)
			goto end;
	}
	apr_hash_set(keys, "1", APR_HASH_KEY_STRING, jwk);

	if (oidc_jwe_decrypt(r->pool, compact_encoded_jwt, keys, &plaintext, &plaintext_len, &err, FALSE) == FALSE) {
		oidc_error(r, "decrypting JWE failed: %s", oidc_jose_e2s(r->pool, err));
		goto end;
	}

	if (oidc_util_jwt_internal_compress(r)) {

		if (oidc_jose_uncompress(r->pool, (char *)plaintext, plaintext_len, &payload, &payload_len, &err) ==
		    FALSE) {
			oidc_error(r, "oidc_jose_uncompress failed: %s", oidc_jose_e2s(r->pool, err));
			goto end;
		}

	} else {

		payload = plaintext;
		payload_len = plaintext_len;
	}

	*s_payload = apr_pstrndup(r->pool, payload, payload_len);

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
		d = oidc_char_to_env(*a) - oidc_char_to_env(*b);
		if (d)
			return d;

		a++;
		b++;
		i++;
	}
}

/*
 * escape a string
 */
char *oidc_util_escape_string(const request_rec *r, const char *str) {
	CURL *curl = NULL;
	if (str == NULL)
		return "";
	curl = curl_easy_init();
	if (curl == NULL) {
		oidc_error(r, "curl_easy_init() error");
		return "";
	}
	char *result = curl_easy_escape(curl, str, 0);
	if (result == NULL) {
		oidc_error(r, "curl_easy_escape() error");
		return "";
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
	CURL *curl = NULL;

	if (str == NULL)
		return "";

	curl = curl_easy_init();
	if (curl == NULL) {
		oidc_error(r, "curl_easy_init() error");
		return "";
	}
	int counter = 0;
	char *replaced = (char *)str;
	while (str[counter] != '\0') {
		if (str[counter] == '+') {
			replaced[counter] = ' ';
		}
		counter++;
	}
	char *result = curl_easy_unescape(curl, replaced, 0, 0);
	if (result == NULL) {
		oidc_error(r, "curl_easy_unescape() error");
		return "";
	}
	char *rv = apr_pstrdup(r->pool, result);
	curl_free(result);
	curl_easy_cleanup(curl);
	// oidc_debug(r, "input=\"%s\", output=\"%s\"", str, rv);
	return rv;
}

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
	char *r = apr_pcalloc(pool, _oidc_strlen(s) * 6);
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
char *oidc_util_javascript_escape(apr_pool_t *pool, const char *s) {
	const char *cp = NULL;
	char *output = NULL;
	size_t outputlen = 0;
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

static const char *oidc_util_hdr_forwarded_get(const request_rec *r, const char *elem) {
	const char *value = NULL;
	char *ptr = NULL;
	const char *item = apr_psprintf(r->pool, "%s=", elem);
	value = oidc_util_hdr_in_forwarded_get(r);
	value = oidc_util_strcasestr(value, item);
	if (value) {
		value += _oidc_strlen(item);
		ptr = strstr(value, ";");
		if (ptr)
			*ptr = '\0';
		ptr = strstr(value, " ");
		if (ptr)
			*ptr = '\0';
	}
	return value ? apr_pstrdup(r->pool, value) : NULL;
}

/*
 * get the URL scheme that is currently being accessed
 */
static const char *oidc_get_current_url_scheme(const request_rec *r, const apr_byte_t x_forwarded_headers) {
	/* first see if there's a proxy/load-balancer in front of us */
	const char *scheme_str = NULL;

	if (x_forwarded_headers & OIDC_HDR_FORWARDED)
		scheme_str = oidc_util_hdr_forwarded_get(r, "proto");
	else if (x_forwarded_headers & OIDC_HDR_X_FORWARDED_PROTO)
		scheme_str = oidc_util_hdr_in_x_forwarded_proto_get(r);

	/* if not we'll determine the scheme used to connect to this server */
	if (scheme_str == NULL) {
#ifdef APACHE2_0
		scheme_str = (char *)ap_http_method(r);
#else
		scheme_str = ap_http_scheme(r);
#endif
	}
	if ((scheme_str == NULL) ||
	    ((_oidc_strcmp(scheme_str, "http") != 0) && (_oidc_strcmp(scheme_str, "https") != 0))) {
		oidc_warn(r,
			  "detected HTTP scheme \"%s\" is not \"http\" nor \"https\"; perhaps your reverse proxy "
			  "passes a wrongly configured \"%s\" header: falling back to default \"https\"",
			  scheme_str, OIDC_HTTP_HDR_X_FORWARDED_PROTO);
		scheme_str = "https";
	}
	return scheme_str;
}

/*
 * get the Port part that is currently being accessed
 */
static const char *oidc_get_port_from_host(const char *host_hdr) {
	char *p = NULL;
	char *i = NULL;

	if (host_hdr) {
		if (host_hdr[0] == '[') {
			i = strchr(host_hdr, ']');
			p = strchr(i, OIDC_CHAR_COLON);
		} else {
			p = strchr(host_hdr, OIDC_CHAR_COLON);
		}
	}
	if (p)
		return p;
	else
		return NULL;
}

/*
 * get the URL port that is currently being accessed
 */
static const char *oidc_get_current_url_port(const request_rec *r, const char *scheme_str,
					     const apr_byte_t x_forwarded_headers) {

	const char *host_hdr = NULL;
	const char *port_str = NULL;

	/*
	 * first see if there's a proxy/load-balancer in front of us
	 * that sets X-Forwarded-Port
	 */

	if (x_forwarded_headers & OIDC_HDR_X_FORWARDED_PORT)
		port_str = oidc_util_hdr_in_x_forwarded_port_get(r);

	if (port_str)
		return port_str;

	/*
	 * see if we can get the port from the "X-Forwarded-Host" or "Forwarded" header
	 * and if that header was set we'll assume defaults
	 */

	if (x_forwarded_headers & OIDC_HDR_FORWARDED)
		host_hdr = oidc_util_hdr_forwarded_get(r, "host");
	else if (x_forwarded_headers & OIDC_HDR_X_FORWARDED_HOST)
		host_hdr = oidc_util_hdr_in_x_forwarded_host_get(r);

	if (host_hdr) {
		port_str = oidc_get_port_from_host(host_hdr);
		if (port_str)
			port_str++;
		return port_str;
	}

	/*
	 * see if we can get the port from the "Host" header; if not
	 * we'll determine the port locally
	 */
	host_hdr = oidc_util_hdr_in_host_get(r);
	if (host_hdr) {
		port_str = oidc_get_port_from_host(host_hdr);
		if (port_str) {
			port_str++;
			return port_str;
		}
	}

	/*
	 * if X-Forwarded-Proto assume the default port otherwise the
	 * port should have been set in the X-Forwarded-Port header
	 */
	if ((x_forwarded_headers & OIDC_HDR_X_FORWARDED_PROTO) && (oidc_util_hdr_in_x_forwarded_proto_get(r)))
		return NULL;

	/*
	 * do the same for the Forwarded: proto= header
	 */
	if ((x_forwarded_headers & OIDC_HDR_FORWARDED) && (oidc_util_hdr_forwarded_get(r, "proto")))
		return NULL;

	/*
	 * if no port was set in the Host header and no X-Forwarded-Proto was set, we'll
	 * determine the port locally and don't print it when it's the default for the protocol
	 */
	const apr_port_t port = r->connection->local_addr->port;
	if ((_oidc_strcmp(scheme_str, "https") == 0) && port == 443)
		return NULL;
	else if ((_oidc_strcmp(scheme_str, "http") == 0) && port == 80)
		return NULL;

	port_str = apr_psprintf(r->pool, "%u", port);
	return port_str;
}

/*
 * get the hostname part of the URL that is currently being accessed
 */
const char *oidc_get_current_url_host(request_rec *r, const apr_byte_t x_forwarded_headers) {
	const char *host_str = NULL;
	char *p = NULL;
	char *i = NULL;

	if (x_forwarded_headers & OIDC_HDR_FORWARDED)
		host_str = oidc_util_hdr_forwarded_get(r, "host");
	else if (x_forwarded_headers & OIDC_HDR_X_FORWARDED_HOST)
		host_str = oidc_util_hdr_in_x_forwarded_host_get(r);

	if (host_str == NULL)
		host_str = oidc_util_hdr_in_host_get(r);
	if (host_str) {
		host_str = apr_pstrdup(r->pool, host_str);

		if (host_str[0] == '[') {
			i = strchr(host_str, ']');
			p = strchr(i, OIDC_CHAR_COLON);
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
static const char *oidc_get_current_url_base(request_rec *r, const apr_byte_t x_forwarded_headers) {

	const char *scheme_str = NULL;
	const char *host_str = NULL;
	const char *port_str = NULL;

	oidc_config_check_x_forwarded(r, x_forwarded_headers);

	scheme_str = oidc_get_current_url_scheme(r, x_forwarded_headers);
	host_str = oidc_get_current_url_host(r, x_forwarded_headers);
	port_str = oidc_get_current_url_port(r, scheme_str, x_forwarded_headers);
	port_str = port_str ? apr_psprintf(r->pool, ":%s", port_str) : "";

	char *url = apr_pstrcat(r->pool, scheme_str, "://", host_str, port_str, NULL);

	return url;
}

/*
 * get the URL that is currently being accessed
 */
char *oidc_get_current_url(request_rec *r, const apr_byte_t x_forwarded_headers) {
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

	url = apr_pstrcat(r->pool, oidc_get_current_url_base(r, x_forwarded_headers), path, NULL);

	oidc_debug(r, "current URL '%s'", url);

	return url;
}

/*
 * infer a full absolute URL from the (optional) relative one
 */
const char *oidc_get_absolute_url(request_rec *r, oidc_cfg *cfg, const char *url) {
	if ((url != NULL) && (url[0] == OIDC_CHAR_FORWARD_SLASH)) {
		url = apr_pstrcat(r->pool, oidc_get_current_url_base(r, cfg->x_forwarded_headers), url, NULL);
		oidc_debug(r, "determined absolute url: %s", url);
	}
	return url;
}

/*
 * determine absolute Redirect URI
 */
const char *oidc_get_redirect_uri(request_rec *r, oidc_cfg *cfg) {
	return oidc_get_absolute_url(r, cfg, cfg->redirect_uri);
}

/*
 * determine absolute redirect uri that is issuer specific
 */
const char *oidc_get_redirect_uri_iss(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider) {
	const char *redirect_uri = oidc_get_redirect_uri(r, cfg);
	if (redirect_uri == NULL) {
		oidc_error(r, "redirect URI is NULL");
		return NULL;
	}
	if (provider->issuer_specific_redirect_uri != 0) {
		redirect_uri =
		    apr_psprintf(r->pool, "%s%s%s=%s", redirect_uri,
				 strchr(redirect_uri, OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP : OIDC_STR_QUERY,
				 OIDC_PROTO_ISS, oidc_util_escape_string(r, provider->issuer));
		oidc_debug(r, "determined issuer specific redirect uri: %s", redirect_uri);
	}
	return redirect_uri;
}

/* buffer to hold HTTP call responses */
typedef struct oidc_curl_buffer {
	request_rec *r;
	char *memory;
	size_t size;
} oidc_curl_buffer;

/* maximum acceptable size of HTTP responses: 10 Mb */
#define OIDC_CURL_MAX_RESPONSE_SIZE 1024 * 1024 * 10

/*
 * callback for CURL to write bytes that come back from an HTTP call
 */
size_t oidc_curl_write(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	oidc_curl_buffer *mem = (oidc_curl_buffer *)userp;

	/* check if we don't run over the maximum buffer/memory size for HTTP responses */
	if (mem->size + realsize > OIDC_CURL_MAX_RESPONSE_SIZE) {
		oidc_error(
		    mem->r,
		    "HTTP response larger than maximum allowed size: current size=%ld, additional size=%ld, max=%d",
		    (long)mem->size, (long)realsize, OIDC_CURL_MAX_RESPONSE_SIZE);
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

/* context structure for encoding parameters */
typedef struct oidc_http_encode_t {
	request_rec *r;
	char *encoded_params;
} oidc_http_encode_t;

/*
 * add a url-form-encoded name/value pair
 */
static int oidc_util_http_add_form_url_encoded_param(void *rec, const char *key, const char *value) {
	oidc_http_encode_t *ctx = (oidc_http_encode_t *)rec;
	oidc_debug(ctx->r, "processing: %s=%s", key,
		   (_oidc_strncmp(key, OIDC_PROTO_CLIENT_SECRET, _oidc_strlen(OIDC_PROTO_CLIENT_SECRET)) == 0)
		       ? "***"
		       : (value ? value : ""));
	const char *sep = ctx->encoded_params ? OIDC_STR_AMP : "";
	ctx->encoded_params =
	    apr_psprintf(ctx->r->pool, "%s%s%s=%s", ctx->encoded_params ? ctx->encoded_params : "", sep,
			 oidc_util_escape_string(ctx->r, key), oidc_util_escape_string(ctx->r, value));
	return 1;
}

/*
 * construct a URL with query parameters
 */
char *oidc_util_http_query_encoded_url(request_rec *r, const char *url, const apr_table_t *params) {
	char *result = NULL;
	if (url == NULL) {
		oidc_error(r, "URL is NULL");
		return NULL;
	}
	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		oidc_http_encode_t data = {r, NULL};
		apr_table_do(oidc_util_http_add_form_url_encoded_param, &data, params, NULL);
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
char *oidc_util_http_form_encoded_data(request_rec *r, const apr_table_t *params) {
	char *data = NULL;
	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		oidc_http_encode_t encode_data = {r, NULL};
		apr_table_do(oidc_util_http_add_form_url_encoded_param, &encode_data, params, NULL);
		data = encode_data.encoded_params;
	}
	oidc_debug(r, "data=%s", data);
	return data;
}

/*
 * set libcurl SSL options
 */

#define OIDC_CURLOPT_SSL_OPTIONS "CURLOPT_SSL_OPTIONS"

#define OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, option, key, val)                                            \
	if (strstr(env_var_value, option) != NULL) {                                                                   \
		oidc_debug(r, "curl_easy_setopt (%d) %s (%d)", key, option, val);                                      \
		curl_easy_setopt(curl, key, val);                                                                      \
	}

static void oidc_util_set_curl_ssl_options(request_rec *r, CURL *curl) {
	const char *env_var_value = NULL;
	if (r->subprocess_env != NULL)
		env_var_value = apr_table_get(r->subprocess_env, OIDC_CURLOPT_SSL_OPTIONS);
	if (env_var_value == NULL)
		return;
	oidc_debug(r, "SSL options environment variable %s=%s found", OIDC_CURLOPT_SSL_OPTIONS, env_var_value);
#if LIBCURL_VERSION_NUM >= 0x071900
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURLSSLOPT_ALLOW_BEAST", CURLOPT_SSL_OPTIONS,
				  CURLSSLOPT_ALLOW_BEAST)
#endif
#if LIBCURL_VERSION_NUM >= 0x072c00
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURLSSLOPT_NO_REVOKE", CURLOPT_SSL_OPTIONS,
				  CURLSSLOPT_NO_REVOKE)
#endif
#if LIBCURL_VERSION_NUM >= 0x074400
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURLSSLOPT_NO_PARTIALCHAIN", CURLOPT_SSL_OPTIONS,
				  CURLSSLOPT_NO_PARTIALCHAIN)
#endif
#if LIBCURL_VERSION_NUM >= 0x074600
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURLSSLOPT_REVOKE_BEST_EFFORT", CURLOPT_SSL_OPTIONS,
				  CURLSSLOPT_REVOKE_BEST_EFFORT)
#endif
#if LIBCURL_VERSION_NUM >= 0x074700
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURLSSLOPT_NATIVE_CA", CURLOPT_SSL_OPTIONS,
				  CURLSSLOPT_NATIVE_CA)
#endif
#if LIBCURL_VERSION_NUM >= 0x072200
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURL_SSLVERSION_TLSv1_0", CURLOPT_SSLVERSION,
				  CURL_SSLVERSION_TLSv1_0)
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURL_SSLVERSION_TLSv1_1", CURLOPT_SSLVERSION,
				  CURL_SSLVERSION_TLSv1_1)
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURL_SSLVERSION_TLSv1_2", CURLOPT_SSLVERSION,
				  CURL_SSLVERSION_TLSv1_2)
#endif
#if LIBCURL_VERSION_NUM >= 0x073400
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURL_SSLVERSION_TLSv1_3", CURLOPT_SSLVERSION,
				  CURL_SSLVERSION_TLSv1_3)
#endif
#if LIBCURL_VERSION_NUM >= 0x073600
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURL_SSLVERSION_MAX_TLSv1_0", CURLOPT_SSLVERSION,
				  CURL_SSLVERSION_MAX_TLSv1_0)
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURL_SSLVERSION_MAX_TLSv1_1", CURLOPT_SSLVERSION,
				  CURL_SSLVERSION_MAX_TLSv1_1)
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURL_SSLVERSION_MAX_TLSv1_2", CURLOPT_SSLVERSION,
				  CURL_SSLVERSION_MAX_TLSv1_2)
	OIDC_UTIL_SET_CURL_OPTION(r, curl, env_var_value, "CURL_SSLVERSION_MAX_TLSv1_3", CURLOPT_SSLVERSION,
				  CURL_SSLVERSION_MAX_TLSv1_3)
#endif
}

char *oidc_util_openssl_version(apr_pool_t *pool) {
	char *s_version = NULL;
#ifdef OPENSSL_VERSION_STR
	s_version = apr_psprintf(pool, "openssl-%s", OPENSSL_VERSION_STR);
#else
	s_version = OPENSSL_VERSION_TEXT;
#endif
	return s_version;
}

#define OIDC_USER_AGENT_ENV_VAR "OIDC_USER_AGENT"

static const char *oidc_util_user_agent(request_rec *r) {
	const char *s_useragent = apr_table_get(r->subprocess_env, OIDC_USER_AGENT_ENV_VAR);
	if (s_useragent == NULL) {
		s_useragent = apr_psprintf(r->pool, "[%s:%u:%lu] %s", r->server->server_hostname,
					   r->connection->local_addr->port, (unsigned long)getpid(), NAMEVERSION);
		s_useragent = apr_psprintf(r->pool, "%s libcurl-%s %s", s_useragent, LIBCURL_VERSION,
					   oidc_util_openssl_version(r->pool));
	}
	return s_useragent;
}

/*
 * execute a HTTP (GET or POST) request
 */
static apr_byte_t oidc_util_http_call(request_rec *r, const char *url, const char *data, const char *content_type,
				      const char *basic_auth, const char *bearer_token, int ssl_validate_server,
				      char **response, oidc_http_timeout_t *http_timeout,
				      const oidc_outgoing_proxy_t *outgoing_proxy, apr_array_header_t *pass_cookies,
				      const char *ssl_cert, const char *ssl_key, const char *ssl_key_pwd) {

	char curlError[CURL_ERROR_SIZE];
	oidc_curl_buffer curlBuffer;
	CURL *curl = NULL;
	struct curl_slist *h_list = NULL;
	int i = 0;
	CURLcode res = CURLE_OK;
	long response_code = 0;
	apr_byte_t rv = FALSE;
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	/* do some logging about the inputs */
	oidc_debug(r,
		   "url=%s, data=%s, content_type=%s, basic_auth=%s, bearer_token=%s, ssl_validate_server=%d, "
		   "request_timeout=%d, connect_timeout=%d, retries=%d, retry_interval=%d, outgoing_proxy=%s:%s:%d, "
		   "pass_cookies=%pp, ssl_cert=%s, ssl_key=%s, ssl_key_pwd=%s",
		   url, data, content_type, basic_auth ? "****" : "null", bearer_token, ssl_validate_server,
		   http_timeout->request_timeout, http_timeout->connect_timeout, http_timeout->retries,
		   (int)http_timeout->retry_interval, outgoing_proxy->host_port,
		   outgoing_proxy->username_password ? "****" : "(null)", (int)outgoing_proxy->auth_type, pass_cookies,
		   ssl_cert, ssl_key, ssl_key_pwd ? "****" : "(null)");

	curl = curl_easy_init();
	if (curl == NULL) {
		oidc_error(r, "curl_easy_init() error");
		goto end;
	}

	/* set the error buffer as empty before performing a request */
	curlError[0] = 0;

	/* some of these are not really required */
	curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlError);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

	/* set the timeouts */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, http_timeout->request_timeout);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, http_timeout->connect_timeout);

	/* setup the buffer where the response will be written to */
	curlBuffer.r = r;
	curlBuffer.memory = NULL;
	curlBuffer.size = 0;
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oidc_curl_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curlBuffer);

#ifndef LIBCURL_NO_CURLPROTO
#if LIBCURL_VERSION_NUM >= 0x075500
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
#endif

	/* set the options for validating the SSL server certificate that the remote site presents */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (ssl_validate_server != FALSE ? 1L : 0L));
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (ssl_validate_server != FALSE ? 2L : 0L));

	oidc_util_set_curl_ssl_options(r, curl);

	if (c->ca_bundle_path != NULL)
		curl_easy_setopt(curl, CURLOPT_CAINFO, c->ca_bundle_path);

#ifdef WIN32
	else {
		DWORD buflen;
		char *ptr = NULL;
		char *retval = (char *)malloc(sizeof(TCHAR) * (MAX_PATH + 1));
		retval[0] = '\0';
		buflen = SearchPath(NULL, "curl-ca-bundle.crt", NULL, MAX_PATH + 1, retval, &ptr);
		if (buflen > 0)
			curl_easy_setopt(curl, CURLOPT_CAINFO, retval);
		else
			oidc_warn(r, "no curl-ca-bundle.crt file found in path");
		free(retval);
	}
#endif

	/* identify this HTTP client */
	const char *useragent = oidc_util_user_agent(r);
	if ((useragent != NULL) && (_oidc_strcmp(useragent, "") != 0)) {
		oidc_debug(r, "set HTTP request header User-Agent to: %s", useragent);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, useragent);
	}

	/* set optional outgoing proxy for the local network */
	if (outgoing_proxy->host_port) {
		curl_easy_setopt(curl, CURLOPT_PROXY, outgoing_proxy->host_port);
		if (outgoing_proxy->username_password)
			curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, outgoing_proxy->username_password);
		if (outgoing_proxy->auth_type != OIDC_CONFIG_POS_INT_UNSET)
			curl_easy_setopt(curl, CURLOPT_PROXYAUTH, outgoing_proxy->auth_type);
	}

	/* see if we need to add token in the Bearer Authorization header */
	if (bearer_token != NULL) {
		h_list = curl_slist_append(h_list, apr_psprintf(r->pool, "Authorization: Bearer %s", bearer_token));
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
	if (ssl_key_pwd != NULL)
		curl_easy_setopt(curl, CURLOPT_KEYPASSWD, ssl_key_pwd);

	if (data != NULL) {
		/* set POST data */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		/* set HTTP method to POST */
		curl_easy_setopt(curl, CURLOPT_POST, 1);
	}

	if (content_type != NULL) {
		/* set content type */
		h_list = curl_slist_append(h_list,
					   apr_psprintf(r->pool, "%s: %s", OIDC_HTTP_HDR_CONTENT_TYPE, content_type));
	}

	const char *traceparent = oidc_util_hdr_in_traceparent_get(r);
	if (traceparent && c->trace_parent != OIDC_TRACE_PARENT_OFF) {
		oidc_debug(r, "propagating traceparent header: %s", traceparent);
		h_list =
		    curl_slist_append(h_list, apr_psprintf(r->pool, "%s: %s", OIDC_HTTP_HDR_TRACE_PARENT, traceparent));
	}

	/* see if we need to add any custom headers */
	if (h_list != NULL)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, h_list);

	if (pass_cookies != NULL) {
		/* gather cookies that we need to pass on from the incoming request */
		char *cookie_string = NULL;
		for (i = 0; i < pass_cookies->nelts; i++) {
			const char *cookie_name = APR_ARRAY_IDX(pass_cookies, i, const char *);
			char *cookie_value = oidc_util_get_cookie(r, cookie_name);
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
			curl_easy_setopt(curl, CURLOPT_COOKIE, cookie_string);
		}
	}

	/* set the target URL */
	curl_easy_setopt(curl, CURLOPT_URL, url);

	/* call it and record the result */
	for (i = 0; i <= http_timeout->retries; i++) {
		res = curl_easy_perform(curl);
		if (res == CURLE_OK) {
			rv = TRUE;
			break;
		}
		if (res == CURLE_OPERATION_TIMEDOUT) {
			/* in case of a request/transfer timeout (which includes the connect timeout) we'll not retry */
			oidc_error(r, "curl_easy_perform failed with a timeout for %s: [%s]; won't retry", url,
				   curlError[0] ? curlError : "<n/a>");
			OIDC_METRICS_COUNTER_INC_SPEC(r, c, OM_PROVIDER_CONNECT_ERROR,
						      curlError[0] ? curlError : "timeout")
			break;
		}
		oidc_error(r, "curl_easy_perform(%d/%d) failed for %s with: [%s]", i + 1, http_timeout->retries + 1,
			   url, curlError[0] ? curlError : "<n/a>");
		OIDC_METRICS_COUNTER_INC_SPEC(r, c, OM_PROVIDER_CONNECT_ERROR, curlError[0] ? curlError : "undefined")
		/* in case of a connectivity/network glitch we'll back off before retrying */
		if (i < http_timeout->retries)
			apr_sleep(http_timeout->retry_interval);
	}
	if (rv == FALSE)
		goto end;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	oidc_debug(r, "HTTP response code=%ld", response_code);

	OIDC_METRICS_COUNTER_INC_SPEC(r, c, OM_PROVIDER_HTTP_RESPONSE_CODE,
				      apr_psprintf(r->pool, "%ld", response_code));

	*response = apr_pstrmemdup(r->pool, curlBuffer.memory, curlBuffer.size);

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
apr_byte_t oidc_util_http_get(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth,
			      const char *bearer_token, int ssl_validate_server, char **response,
			      oidc_http_timeout_t *http_timeout, const oidc_outgoing_proxy_t *outgoing_proxy,
			      apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key,
			      const char *ssl_key_pwd) {
	char *query_url = oidc_util_http_query_encoded_url(r, url, params);
	return oidc_util_http_call(r, query_url, NULL, NULL, basic_auth, bearer_token, ssl_validate_server, response,
				   http_timeout, outgoing_proxy, pass_cookies, ssl_cert, ssl_key, ssl_key_pwd);
}

/*
 * execute HTTP POST request with form-encoded data
 */
apr_byte_t oidc_util_http_post_form(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth,
				    const char *bearer_token, int ssl_validate_server, char **response,
				    oidc_http_timeout_t *http_timeout, const oidc_outgoing_proxy_t *outgoing_proxy,
				    apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key,
				    const char *ssl_key_pwd) {
	char *data = oidc_util_http_form_encoded_data(r, params);
	return oidc_util_http_call(r, url, data, OIDC_CONTENT_TYPE_FORM_ENCODED, basic_auth, bearer_token,
				   ssl_validate_server, response, http_timeout, outgoing_proxy, pass_cookies, ssl_cert,
				   ssl_key, ssl_key_pwd);
}

/*
 * execute HTTP POST request with JSON-encoded data
 */
apr_byte_t oidc_util_http_post_json(request_rec *r, const char *url, json_t *json, const char *basic_auth,
				    const char *bearer_token, int ssl_validate_server, char **response,
				    oidc_http_timeout_t *http_timeout, const oidc_outgoing_proxy_t *outgoing_proxy,
				    apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key,
				    const char *ssl_key_pwd) {
	char *data = json != NULL ? oidc_util_encode_json_object(r, json, JSON_COMPACT) : NULL;
	return oidc_util_http_call(r, url, data, OIDC_CONTENT_TYPE_JSON, basic_auth, bearer_token, ssl_validate_server,
				   response, http_timeout, outgoing_proxy, pass_cookies, ssl_cert, ssl_key,
				   ssl_key_pwd);
}

/*
 * get the current path from the request in a normalized way
 */
static char *oidc_util_get_path(request_rec *r) {
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
static char *oidc_util_get_cookie_path(request_rec *r) {
	char *rv = NULL;
	char *requestPath = oidc_util_get_path(r);
	char *cookie_path = oidc_cfg_dir_cookie_path(r);
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

#define OIDC_COOKIE_FLAG_DOMAIN "Domain"
#define OIDC_COOKIE_FLAG_PATH "Path"
#define OIDC_COOKIE_FLAG_EXPIRES "Expires"
#define OIDC_COOKIE_FLAG_SECURE "Secure"
#define OIDC_COOKIE_FLAG_HTTP_ONLY "HttpOnly"

#define OIDC_COOKIE_MAX_SIZE 4093

#define OIDC_SET_COOKIE_APPEND_ENV_VAR "OIDC_SET_COOKIE_APPEND"

const char *oidc_util_set_cookie_append_value(request_rec *r) {
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

apr_byte_t oidc_util_request_is_secure(request_rec *r, const oidc_cfg *c) {
	return (_oidc_strnatcasecmp("https", oidc_get_current_url_scheme(r, c->x_forwarded_headers)) == 0);
}

/*
 * set a cookie in the HTTP response headers
 */
void oidc_util_set_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires,
			  const char *ext) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
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
	    apr_psprintf(r->pool, "%s; %s=%s", headerString, OIDC_COOKIE_FLAG_PATH, oidc_util_get_cookie_path(r));

	if (expiresString != NULL)
		headerString =
		    apr_psprintf(r->pool, "%s; %s=%s", headerString, OIDC_COOKIE_FLAG_EXPIRES, expiresString);

	if (c->cookie_domain != NULL)
		headerString =
		    apr_psprintf(r->pool, "%s; %s=%s", headerString, OIDC_COOKIE_FLAG_DOMAIN, c->cookie_domain);

	if (oidc_util_request_is_secure(r, c))
		headerString = apr_psprintf(r->pool, "%s; %s", headerString, OIDC_COOKIE_FLAG_SECURE);

	if (c->cookie_http_only != FALSE)
		headerString = apr_psprintf(r->pool, "%s; %s", headerString, OIDC_COOKIE_FLAG_HTTP_ONLY);

	appendString = oidc_util_set_cookie_append_value(r);
	if (appendString != NULL)
		headerString = apr_psprintf(r->pool, "%s; %s", headerString, appendString);
	else if (ext != NULL)
		headerString = apr_psprintf(r->pool, "%s; %s", headerString, ext);

	/* sanity check on overall cookie value size */
	if (_oidc_strlen(headerString) > OIDC_COOKIE_MAX_SIZE) {
		oidc_warn(r,
			  "the length of the cookie value (%d) is greater than %d(!) bytes, this may not work with all "
			  "browsers/server combinations: consider switching to a server side caching!",
			  (int)_oidc_strlen(headerString), OIDC_COOKIE_MAX_SIZE);
	}

	/* use r->err_headers_out so we always print our headers (even on 302 redirect) - headers_out only prints on 2xx
	 * responses */
	oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_SET_COOKIE, headerString);
}

/*
 * get a cookie from the HTTP request
 */
char *oidc_util_get_cookie(request_rec *r, const char *cookieName) {
	char *cookie = NULL;
	char *tokenizerCtx = NULL;
	char *rv = NULL;

	/* get the Cookie value */
	char *cookies = apr_pstrdup(r->pool, oidc_util_hdr_in_cookie_get(r));

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

#define OIDC_COOKIE_CHUNKS_SEPARATOR "_"
#define OIDC_COOKIE_CHUNKS_POSTFIX "chunks"

/*
 * get the name of the cookie that contains the number of chunks
 */
static char *oidc_util_get_chunk_count_name(request_rec *r, const char *cookieName) {
	return apr_psprintf(r->pool, "%s%s%s", cookieName, OIDC_COOKIE_CHUNKS_SEPARATOR, OIDC_COOKIE_CHUNKS_POSTFIX);
}

/*
 * get the number of cookie chunks set by the browser
 */
static int oidc_util_get_chunked_count(request_rec *r, const char *cookieName) {
	int chunkCount = 0;
	char *chunkCountValue = oidc_util_get_cookie(r, oidc_util_get_chunk_count_name(r, cookieName));
	if (chunkCountValue != NULL) {
		chunkCount = _oidc_str_to_int(chunkCountValue);
		if (*chunkCountValue == '\0')
			chunkCount = 0;
	}
	return chunkCount;
}

/*
 * get the name of a chunk
 */
static char *oidc_util_get_chunk_cookie_name(request_rec *r, const char *cookieName, int i) {
	return apr_psprintf(r->pool, "%s%s%d", cookieName, OIDC_COOKIE_CHUNKS_SEPARATOR, i);
}

/*
 * get a cookie value that is split over a number of chunked cookies
 */
char *oidc_util_get_chunked_cookie(request_rec *r, const char *cookieName, int chunkSize) {
	char *cookieValue = NULL, *chunkValue = NULL;
	int chunkCount = 0, i = 0;
	if (chunkSize == 0)
		return oidc_util_get_cookie(r, cookieName);
	chunkCount = oidc_util_get_chunked_count(r, cookieName);
	if (chunkCount == 0)
		return oidc_util_get_cookie(r, cookieName);
	if ((chunkCount < 0) || (chunkCount > 99)) {
		oidc_warn(r, "chunk count out of bounds: %d", chunkCount);
		return NULL;
	}
	for (i = 0; i < chunkCount; i++) {
		chunkValue = oidc_util_get_cookie(r, oidc_util_get_chunk_cookie_name(r, cookieName, i));
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
static void oidc_util_clear_chunked_cookie(request_rec *r, const char *cookieName, apr_time_t expires,
					   const char *ext) {
	int i = 0;
	int chunkCount = oidc_util_get_chunked_count(r, cookieName);
	if (chunkCount > 0) {
		for (i = 0; i < chunkCount; i++)
			oidc_util_set_cookie(r, oidc_util_get_chunk_cookie_name(r, cookieName, i), "", expires, ext);
		oidc_util_set_cookie(r, oidc_util_get_chunk_count_name(r, cookieName), "", expires, ext);
	}
}

/*
 * set a cookie value that is split over a number of chunked cookies
 */
void oidc_util_set_chunked_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires,
				  int chunkSize, const char *ext) {
	int i = 0;
	int cookieLength = _oidc_strlen(cookieValue);
	char *chunkValue = NULL;

	/* see if we need to chunk at all */
	if ((chunkSize == 0) || ((cookieLength > 0) && (cookieLength < chunkSize))) {
		oidc_util_set_cookie(r, cookieName, cookieValue, expires, ext);
		oidc_util_clear_chunked_cookie(r, cookieName, expires, ext);
		return;
	}

	/* see if we need to clear a possibly chunked cookie */
	if (cookieLength == 0) {
		oidc_util_set_cookie(r, cookieName, "", expires, ext);
		oidc_util_clear_chunked_cookie(r, cookieName, expires, ext);
		return;
	}

	/* set a chunked cookie */
	int chunkCountValue = cookieLength / chunkSize + 1;
	const char *ptr = cookieValue;
	for (i = 0; i < chunkCountValue; i++) {
		chunkValue = apr_pstrndup(r->pool, ptr, chunkSize);
		ptr += chunkSize;
		oidc_util_set_cookie(r, oidc_util_get_chunk_cookie_name(r, cookieName, i), chunkValue, expires, ext);
	}
	oidc_util_set_cookie(r, oidc_util_get_chunk_count_name(r, cookieName),
			     apr_psprintf(r->pool, "%d", chunkCountValue), expires, ext);
	oidc_util_set_cookie(r, cookieName, "", expires, ext);
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
	for (i = 0; i < _oidc_strlen(ns); i++) {
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
apr_byte_t oidc_util_request_has_parameter(request_rec *r, const char *param) {
	if (r->args == NULL)
		return FALSE;
	const char *option1 = apr_psprintf(r->pool, "%s=", param);
	const char *option2 = apr_psprintf(r->pool, "&%s=", param);
	return ((strstr(r->args, option1) == r->args) || (strstr(r->args, option2) != NULL)) ? TRUE : FALSE;
}

/*
 * get a query parameter
 */
apr_byte_t oidc_util_get_request_parameter(request_rec *r, char *name, char **value) {
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
			*value = oidc_util_unescape_string(r, *value);
		}
		p = apr_strtok(NULL, OIDC_STR_AMP, &tokenizer_ctx);
	} while (p);

	return (*value != NULL ? TRUE : FALSE);
}

/*
 * printout a JSON string value
 */
static apr_byte_t oidc_util_json_string_print(request_rec *r, json_t *result, const char *key, const char *log) {
	json_t *value = json_object_get(result, key);
	if (value != NULL && !json_is_null(value)) {
		oidc_error(r, "%s: response contained an \"%s\" entry with value: \"%s\"", log, key,
			   oidc_util_encode_json_object(r, value, JSON_ENCODE_ANY));
		return TRUE;
	}
	return FALSE;
}

/*
 * check a JSON object for "error" results and printout
 */
static apr_byte_t oidc_util_check_json_error(request_rec *r, json_t *json) {
	if (oidc_util_json_string_print(r, json, OIDC_PROTO_ERROR, "oidc_util_check_json_error") == TRUE) {
		oidc_util_json_string_print(r, json, OIDC_PROTO_ERROR_DESCRIPTION, "oidc_util_check_json_error");
		return TRUE;
	}
	return FALSE;
}

#define OIDC_JSON_MAX_ERROR_STR 4096

/*
 * parse a JSON object
 */
apr_byte_t oidc_util_decode_json_object(request_rec *r, const char *str, json_t **json) {

	if (str == NULL)
		return FALSE;

	json_error_t json_error;
	*json = json_loads(str, 0, &json_error);

	/* decode the JSON contents of the buffer */
	if (*json == NULL) {
		/* something went wrong */
#if JANSSON_VERSION_HEX >= 0x020B00
		if (json_error_code(&json_error) == json_error_null_character) {
			oidc_error(r, "JSON parsing returned an error: %s", json_error.text);
		} else {
#endif
			oidc_error(r, "JSON parsing returned an error: %s (%s)", json_error.text,
				   apr_pstrndup(r->pool, str, OIDC_JSON_MAX_ERROR_STR));
#if JANSSON_VERSION_HEX >= 0x020B00
		}
#endif
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
 * encode a JSON object
 */
char *oidc_util_encode_json_object(request_rec *r, json_t *json, size_t flags) {
	char *s = json_dumps(json, flags);
	char *s_value = apr_pstrdup(r->pool, s);
	free(s);
	return s_value;
}

/*
 * decode a JSON string, check for "error" results and printout
 */
apr_byte_t oidc_util_decode_json_and_check_error(request_rec *r, const char *str, json_t **json) {

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

	html = apr_psprintf(
	    r->pool, html, title ? oidc_util_html_escape(r->pool, title) : "", html_head ? html_head : "",
	    on_load ? apr_psprintf(r->pool, " onload=\"%s()\"", on_load) : "", html_body ? html_body : "<p></p>");

	return oidc_util_http_send(r, html, _oidc_strlen(html), OIDC_CONTENT_TYPE_TEXT_HTML, status_code);
}

static char *html_error_template_contents = NULL;

/*
 * get the full path to a file based on an (already) absolute filename or a filename
 * that is relative to the Apache root directory
 */
char *oidc_util_get_full_path(apr_pool_t *pool, const char *abs_or_rel_filename) {
	return abs_or_rel_filename ? ap_server_root_relative(pool, abs_or_rel_filename) : NULL;
}

/*
 * escape characters in an HTML/Javascript template
 */
static char *oidc_util_template_escape(request_rec *r, const char *arg, int escape) {
	char *rv = NULL;
	if (escape == OIDC_POST_PRESERVE_ESCAPE_HTML) {
		rv = oidc_util_html_escape(r->pool, arg ? arg : "");
	} else if (escape == OIDC_POST_PRESERVE_ESCAPE_JAVASCRIPT) {
		rv = oidc_util_javascript_escape(r->pool, arg ? arg : "");
	} else {
		rv = apr_pstrdup(r->pool, arg);
	}
	return rv;
}

/*
 * fill and send a HTML template
 */
apr_byte_t oidc_util_html_send_in_template(request_rec *r, const char *filename, char **static_template_content,
					   const char *arg1, int arg1_esc, const char *arg2, int arg2_esc,
					   int status_code) {
	char *fullname = NULL;
	char *html = NULL;
	int rc = status_code;
	if (*static_template_content == NULL) {
		fullname = oidc_util_get_full_path(r->pool, filename);
		// NB: templates go into the server process pool
		if (oidc_util_file_read(r, fullname, r->server->process->pool, static_template_content) == FALSE) {
			oidc_error(r, "could not read template: %s", fullname);
			*static_template_content = NULL;
		}
	}
	if (static_template_content) {
		html = apr_psprintf(r->pool, *static_template_content, oidc_util_template_escape(r, arg1, arg1_esc),
				    oidc_util_template_escape(r, arg2, arg2_esc));
		rc = oidc_util_http_send(r, html, _oidc_strlen(html), OIDC_CONTENT_TYPE_TEXT_HTML, status_code);
	}
	return rc;
}

/*
 * send a user-facing error to the browser
 */
int oidc_util_html_send_error(request_rec *r, const char *html_template, const char *error, const char *description,
			      int status_code) {

	char *html = "";
	int rc = status_code;

	if (html_template != NULL) {

		if (_oidc_strcmp(html_template, "deprecated") != 0) {

			rc = oidc_util_html_send_in_template(r, html_template, &html_error_template_contents, error,
							     OIDC_POST_PRESERVE_ESCAPE_HTML, description,
							     OIDC_POST_PRESERVE_ESCAPE_HTML, status_code);

		} else {

			if (error != NULL) {
				html = apr_psprintf(r->pool, "%s<p>Error: <pre>%s</pre></p>", html,
						    oidc_util_html_escape(r->pool, error));
			}
			if (description != NULL) {
				html = apr_psprintf(r->pool, "%s<p>Description: <pre>%s</pre></p>", html,
						    oidc_util_html_escape(r->pool, description));
			}

			rc = oidc_util_html_send(r, "Error", NULL, NULL, html, status_code);
		}
	}

	oidc_debug(r, "setting " OIDC_ERROR_ENVVAR " environment variable to: %s", error);
	apr_table_set(r->subprocess_env, OIDC_ERROR_ENVVAR, error ? error : "");

	oidc_debug(r, "setting " OIDC_ERROR_DESC_ENVVAR " environment variable to: %s", description);
	apr_table_set(r->subprocess_env, OIDC_ERROR_DESC_ENVVAR, description ? description : "");

	return rc;
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

	while (p && *p && (val = ap_getword(r->pool, &p, OIDC_CHAR_AMP))) {
		key = ap_getword(r->pool, &val, OIDC_CHAR_EQUAL);
		key = oidc_util_unescape_string(r, key);
		val = oidc_util_unescape_string(r, val);
		oidc_debug(r, "read: %s=%s", key, val);
		apr_table_set(table, key, val);
	}

	oidc_debug(r, "parsed: %d bytes into %d elements", data ? (int)_oidc_strlen(data) : 0,
		   apr_table_elts(table)->nelts);

	return TRUE;
}

static void oidc_userdata_set_post_param(request_rec *r, const char *post_param_name, const char *post_param_value) {
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

	content_type = oidc_util_hdr_in_content_type_get(r);
	if ((r->method_number != M_POST) || (content_type == NULL) ||
	    (strstr(content_type, OIDC_CONTENT_TYPE_FORM_ENCODED) != content_type)) {
		oidc_debug(r, "required content-type %s not found", OIDC_CONTENT_TYPE_FORM_ENCODED);
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
			oidc_userdata_set_post_param(r, elts[i].key, elts[i].val);

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
 * see if a certain string value is part of a JSON array with string elements
 */
apr_byte_t oidc_util_json_array_has_value(request_rec *r, json_t *haystack, const char *needle) {

	if ((haystack == NULL) || (!json_is_array(haystack)))
		return FALSE;

	int i;
	for (i = 0; i < json_array_size(haystack); i++) {
		json_t *elem = json_array_get(haystack, i);
		if (!json_is_string(elem)) {
			oidc_error(r, "unhandled in-array JSON non-string object type [%d]", elem->type);
			continue;
		}
		if (_oidc_strcmp(json_string_value(elem), needle) == 0) {
			break;
		}
	}

	/*	oidc_debug(r,
	 *			"returning (%d=%d)", i,
	 *			haystack->value.array->nelts);
	 */

	return (i == json_array_size(haystack)) ? FALSE : TRUE;
}

static char *oidc_util_utf8_to_latin1(request_rec *r, const char *src) {
	char *dst = "";
	unsigned int cp = 0;
	unsigned char ch;
	int i = 0;
	if (src == NULL)
		return NULL;
	dst = apr_pcalloc(r->pool, strlen(src) + 1);
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
			    apr_byte_t as_header, apr_byte_t as_env_var, int pass_as) {

	/* construct the header name, cq. put the prefix in front of a normalized key name */
	const char *s_name = apr_psprintf(r->pool, "%s%s", claim_prefix, oidc_normalize_header_name(r, s_key));
	char *d_value = NULL;

	if (s_value != NULL) {
		if (pass_as == OIDC_PASS_APP_INFO_AS_BASE64URL) {
			oidc_base64url_encode(r, &d_value, s_value, _oidc_strlen(s_value), TRUE);
		} else if (pass_as == OIDC_PASS_APP_INFO_AS_LATIN1) {
			d_value = oidc_util_utf8_to_latin1(r, s_value);
		}
	}

	if (as_header) {
		oidc_util_hdr_in_set(r, s_name, (d_value != NULL) ? d_value : s_value);
	}

	if (as_env_var) {

		/* do some logging about this event */
		oidc_debug(r, "setting environment variable \"%s: %s\"", s_name, (d_value != NULL) ? d_value : s_value);

		apr_table_set(r->subprocess_env, s_name, (d_value != NULL) ? d_value : s_value);
	}
}

/*
 * set the user/claims information from the session in HTTP headers passed on to the application
 */
void oidc_util_set_app_infos(request_rec *r, json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter,
			     apr_byte_t as_header, apr_byte_t as_env_var, int pass_as) {

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

		//		char *s_value= json_dumps(j_value, JSON_ENCODE_ANY);
		//		oidc_util_set_app_info(r, s_key, s_value, claim_prefix);
		//		free(s_value);

		/* check if it is a single value string */
		if (json_is_string(j_value)) {

			/* set the single string in the application header whose name is based on the key and the prefix
			 */
			oidc_util_set_app_info(r, s_key, json_string_value(j_value), claim_prefix, as_header,
					       as_env_var, pass_as);

		} else if (json_is_boolean(j_value)) {

			/* set boolean value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(r, s_key, (json_is_true(j_value) ? "1" : "0"), claim_prefix, as_header,
					       as_env_var, pass_as);

		} else if (json_is_integer(j_value)) {

			if (snprintf(s_int, 255, "%ld", (long)json_integer_value(j_value)) > 0) {
				/* set long value in the application header whose name is based on the key and the
				 * prefix */
				oidc_util_set_app_info(r, s_key, s_int, claim_prefix, as_header, as_env_var, pass_as);
			} else {
				oidc_warn(r, "could not convert JSON number to string (> 255 characters?), skipping");
			}

		} else if (json_is_real(j_value)) {

			/* set float value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(r, s_key, apr_psprintf(r->pool, "%lf", json_real_value(j_value)),
					       claim_prefix, as_header, as_env_var, pass_as);

		} else if (json_is_object(j_value)) {

			/* set json value in the application header whose name is based on the key and the prefix */
			oidc_util_set_app_info(r, s_key, oidc_util_encode_json_object(r, j_value, 0), claim_prefix,
					       as_header, as_env_var, pass_as);

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
					oidc_warn(r,
						  "unhandled in-array JSON object type [%d] for key \"%s\" when "
						  "parsing claims array elements",
						  elem->type, s_key);
				}
			}

			/* set the concatenated string */
			oidc_util_set_app_info(r, s_key, s_concat, claim_prefix, as_header, as_env_var, pass_as);

		} else {

			/* no string and no array, so unclear how to handle this */
			oidc_warn(r, "unhandled JSON object type [%d] for key \"%s\" when parsing claims",
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
	while (*data && (val = ap_getword_white(pool, &data))) {
		apr_hash_set(result, val, APR_HASH_KEY_STRING, val);
	}
	return result;
}

/*
 * compare two space separated value types
 */
apr_byte_t oidc_util_spaced_string_equals(apr_pool_t *pool, const char *a, const char *b) {

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
		apr_hash_this(hi, (const void **)&k, NULL, (void **)&v);
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
 * get (optional) string from a JSON object
 */
apr_byte_t oidc_json_object_get_string(apr_pool_t *pool, json_t *json, const char *name, char **value,
				       const char *default_value) {
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
apr_byte_t oidc_json_object_get_int(const json_t *json, const char *name, int *value, const int default_value) {
	const json_t *v = NULL;
	*value = default_value;
	if (json != NULL) {
		v = json_object_get(json, name);
		if ((v != NULL) && (json_is_integer(v))) {
			*value = json_integer_value(v);
		}
	}
	return TRUE;
}

/*
 * get (optional) boolean from a JSON object
 */
apr_byte_t oidc_json_object_get_bool(const json_t *json, const char *name, int *value, const int default_value) {
	const json_t *v = NULL;
	*value = default_value;
	if (json != NULL) {
		v = json_object_get(json, name);
		if ((v != NULL) && (json_is_boolean(v))) {
			*value = json_is_true(v);
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * merge two JSON objects
 */
apr_byte_t oidc_util_json_merge(request_rec *r, json_t *src, json_t *dst) {

	const char *key;
	json_t *value = NULL;
	void *iter = NULL;

	if ((src == NULL) || (dst == NULL))
		return FALSE;

	oidc_debug(r, "src=%s, dst=%s", oidc_util_encode_json_object(r, src, JSON_COMPACT),
		   oidc_util_encode_json_object(r, dst, JSON_COMPACT));

	iter = json_object_iter(src);
	while (iter) {
		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		json_object_set(dst, key, value);
		iter = json_object_iter_next(src, iter);
	}

	oidc_debug(r, "result dst=%s", oidc_util_encode_json_object(r, dst, JSON_COMPACT));

	return TRUE;
}

/*
 * add query encoded parameters to a table
 */
void oidc_util_table_add_query_encoded_params(apr_pool_t *pool, apr_table_t *table, const char *params) {
	if (params != NULL) {
		char *key = NULL;
		const char *val = NULL;
		const char *p = params;
		while (*p && (val = ap_getword(pool, &p, OIDC_CHAR_AMP))) {
			key = ap_getword(pool, &val, OIDC_CHAR_EQUAL);
			ap_unescape_url((char *)key);
			ap_unescape_url((char *)val);
			apr_table_add(table, key, val);
		}
	}
}

/*
 * create a symmetric key from a client_secret
 */
apr_byte_t oidc_util_create_symmetric_key(request_rec *r, const char *client_secret, unsigned int r_key_len,
					  const char *hash_algo, apr_byte_t set_kid, oidc_jwk_t **jwk) {
	oidc_jose_error_t err;
	unsigned char *key = NULL;
	unsigned int key_len;

	if ((client_secret != NULL) && (_oidc_strlen(client_secret) > 0)) {

		if (hash_algo == NULL) {
			key = (unsigned char *)client_secret;
			key_len = _oidc_strlen(client_secret);
		} else {
			/* hash the client_secret first, this is OpenID Connect specific */
			oidc_jose_hash_bytes(r->pool, hash_algo, (const unsigned char *)client_secret,
					     _oidc_strlen(client_secret), &key, &key_len, &err);
		}

		if ((key != NULL) && (key_len > 0)) {
			if ((r_key_len != 0) && (key_len >= r_key_len))
				key_len = r_key_len;
			oidc_debug(r, "key_len=%d", key_len);
			*jwk = oidc_jwk_create_symmetric_key(r->pool, NULL, key, key_len, set_kid, &err);
		}

		if (*jwk == NULL) {
			oidc_error(r, "could not create JWK from the provided secret: %s", oidc_jose_e2s(r->pool, err));
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * merge provided keys and client secret in to a single hashtable
 */
apr_hash_t *oidc_util_merge_symmetric_key(apr_pool_t *pool, const apr_array_header_t *keys, oidc_jwk_t *jwk) {
	apr_hash_t *result = apr_hash_make(pool);
	const oidc_jwk_t *elem = NULL;
	int i = 0;
	if (keys != NULL) {
		for (i = 0; i < keys->nelts; i++) {
			elem = APR_ARRAY_IDX(keys, i, oidc_jwk_t *);
			apr_hash_set(result, elem->kid, APR_HASH_KEY_STRING, elem);
		}
	}
	if (jwk != NULL) {
		apr_hash_set(result, jwk->kid, APR_HASH_KEY_STRING, jwk);
	}
	return result;
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

	if (oidc_base64url_encode(r, output, (const char *)hashed, hashed_len, TRUE) <= 0) {
		oidc_error(r, "oidc_base64url_encode returned an error: %s", err.text);
		return FALSE;
	}
	return TRUE;
}

/*
 * merge two key sets
 */
apr_hash_t *oidc_util_merge_key_sets(apr_pool_t *pool, apr_hash_t *k1, const apr_array_header_t *k2) {
	apr_hash_t *rv = k1 ? apr_hash_copy(pool, k1) : apr_hash_make(pool);
	const oidc_jwk_t *jwk = NULL;
	int i = 0;
	if (k2 != NULL) {
		for (i = 0; i < k2->nelts; i++) {
			jwk = APR_ARRAY_IDX(k2, i, oidc_jwk_t *);
			apr_hash_set(rv, jwk->kid, APR_HASH_KEY_STRING, jwk);
		}
	}
	return rv;
}

apr_hash_t *oidc_util_merge_key_sets_hash(apr_pool_t *pool, apr_hash_t *k1, apr_hash_t *k2) {
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
 * regexp substitute
 *   Example:
 *     regex: "^.*([0-9]+).*$"
 *     replace: "$1"
 *     text_original: "match 292 numbers"
 *     text_replaced: "292"
 */
apr_byte_t oidc_util_regexp_substitute(apr_pool_t *pool, const char *input, const char *regexp, const char *replace,
				       char **output, char **error_str) {

	char *substituted = NULL;
	apr_byte_t rc = FALSE;

	struct oidc_pcre *preg = oidc_pcre_compile(pool, regexp, error_str);
	if (preg == NULL) {
		*error_str =
		    apr_psprintf(pool, "pattern [%s] is not a valid regular expression: %s", regexp, *error_str);
		goto out;
	}

	if (_oidc_strlen(input) >= OIDC_PCRE_MAXCAPTURE - 1) {
		*error_str =
		    apr_psprintf(pool, "string length (%d) is larger than the maximum allowed for pcre_subst (%d)",
				 (int)_oidc_strlen(input), OIDC_PCRE_MAXCAPTURE - 1);
		goto out;
	}

	substituted = oidc_pcre_subst(pool, preg, input, (int)_oidc_strlen(input), replace);
	if (substituted == NULL) {
		*error_str = apr_psprintf(
		    pool, "unknown error could not match string [%s] using pattern [%s] and replace matches in [%s]",
		    input, regexp, replace);
		goto out;
	}

	*output = apr_pstrdup(pool, substituted);
	rc = TRUE;

out:

	if (preg)
		oidc_pcre_free(preg);

	return rc;
}

/*
 * regexp match
 */

apr_byte_t oidc_util_regexp_first_match(apr_pool_t *pool, const char *input, const char *regexp, char **output,
					char **error_str) {
	apr_byte_t rv = FALSE;
	int rc = 0;

	struct oidc_pcre *preg = oidc_pcre_compile(pool, regexp, error_str);
	if (preg == NULL) {
		*error_str =
		    apr_psprintf(pool, "pattern [%s] is not a valid regular expression: %s", regexp, *error_str);
		goto out;
	}

	if ((rc = oidc_pcre_exec(pool, preg, input, (int)_oidc_strlen(input), error_str)) < 0)
		goto out;

	if (output && (oidc_pcre_get_substring(pool, preg, input, rc, output, error_str) <= 0)) {
		*error_str = apr_psprintf(pool, "pcre_get_substring failed: %s", *error_str);
		goto out;
	}

	rv = TRUE;

out:

	if (preg)
		oidc_pcre_free(preg);

	return rv;
}

int oidc_util_cookie_domain_valid(const char *hostname, char *cookie_domain) {
	char *p = NULL;
	char *check_cookie = cookie_domain;
	// Skip past the first char of a cookie_domain that starts
	// with a ".", ASCII 46
	if (check_cookie[0] == 46)
		check_cookie++;
	p = strstr(hostname, check_cookie);

	if ((p == NULL) || (_oidc_strcmp(check_cookie, p) != 0)) {
		return FALSE;
	}
	return TRUE;
}

static const char *oidc_util_hdr_in_get(const request_rec *r, const char *name) {
	const char *value = apr_table_get(r->headers_in, name);
	if (value)
		oidc_debug(r, "%s=%s", name, value);
	return value;
}

static const char *oidc_util_hdr_in_get_left_most_only(const request_rec *r, const char *name, const char *separator) {
	char *last = NULL;
	const char *value = oidc_util_hdr_in_get(r, name);
	if (value)
		return apr_strtok(apr_pstrdup(r->pool, value), separator, &last);
	return NULL;
}

static apr_byte_t oidc_util_hdr_in_contains(const request_rec *r, const char *name, const char *separator,
					    const char postfix_separator, const char *needle) {
	char *ctx = NULL, *elem = NULL;
	const char *value = oidc_util_hdr_in_get(r, name);
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

static void oidc_util_hdr_table_set(const request_rec *r, apr_table_t *table, const char *name, const char *value) {

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

static void oidc_util_hdr_out_set(const request_rec *r, const char *name, const char *value) {
	oidc_util_hdr_table_set(r, r->headers_out, name, value);
}

static const char *oidc_util_hdr_out_get(const request_rec *r, const char *name) {
	return apr_table_get(r->headers_out, name);
}

void oidc_util_hdr_err_out_add(const request_rec *r, const char *name, const char *value) {
	oidc_debug(r, "%s: %s", name, value);
	apr_table_add(r->err_headers_out, name, value);
}

void oidc_util_hdr_in_set(const request_rec *r, const char *name, const char *value) {
	oidc_util_hdr_table_set(r, r->headers_in, name, value);
}

const char *oidc_util_hdr_in_cookie_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_COOKIE);
}

void oidc_util_hdr_in_cookie_set(const request_rec *r, const char *value) {
	oidc_util_hdr_in_set(r, OIDC_HTTP_HDR_COOKIE, value);
}

const char *oidc_util_hdr_in_user_agent_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_USER_AGENT);
}

const char *oidc_util_hdr_in_x_forwarded_for_get(const request_rec *r) {
	return oidc_util_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_X_FORWARDED_FOR, OIDC_STR_COMMA OIDC_STR_SPACE);
}

const char *oidc_util_hdr_in_content_type_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_CONTENT_TYPE);
}

const char *oidc_util_hdr_in_content_length_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_CONTENT_LENGTH);
}

const char *oidc_util_hdr_in_x_requested_with_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_X_REQUESTED_WITH);
}

const char *oidc_util_hdr_in_sec_fetch_mode_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_SEC_FETCH_MODE);
}

const char *oidc_util_hdr_in_sec_fetch_dest_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_SEC_FETCH_DEST);
}

const char *oidc_util_hdr_in_accept_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_ACCEPT);
}

apr_byte_t oidc_util_hdr_in_accept_contains(const request_rec *r, const char *needle) {
	return oidc_util_hdr_in_contains(r, OIDC_HTTP_HDR_ACCEPT, OIDC_STR_COMMA, OIDC_CHAR_SEMI_COLON, needle);
}

const char *oidc_util_hdr_in_authorization_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_AUTHORIZATION);
}

const char *oidc_util_hdr_in_x_forwarded_proto_get(const request_rec *r) {
	return oidc_util_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_X_FORWARDED_PROTO, OIDC_STR_COMMA OIDC_STR_SPACE);
}

const char *oidc_util_hdr_in_x_forwarded_port_get(const request_rec *r) {
	return oidc_util_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_X_FORWARDED_PORT, OIDC_STR_COMMA OIDC_STR_SPACE);
}

const char *oidc_util_hdr_in_x_forwarded_host_get(const request_rec *r) {
	return oidc_util_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_X_FORWARDED_HOST, OIDC_STR_COMMA OIDC_STR_SPACE);
}

const char *oidc_util_hdr_in_forwarded_get(const request_rec *r) {
	return oidc_util_hdr_in_get_left_most_only(r, OIDC_HTTP_HDR_FORWARDED, OIDC_STR_COMMA);
}

const char *oidc_util_hdr_in_host_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_HOST);
}

const char *oidc_util_hdr_in_traceparent_get(const request_rec *r) {
	return oidc_util_hdr_in_get(r, OIDC_HTTP_HDR_TRACE_PARENT);
}

void oidc_util_hdr_out_location_set(const request_rec *r, const char *value) {
	oidc_util_hdr_out_set(r, OIDC_HTTP_HDR_LOCATION, value);
}

const char *oidc_util_hdr_out_location_get(const request_rec *r) {
	return oidc_util_hdr_out_get(r, OIDC_HTTP_HDR_LOCATION);
}

oidc_jwk_t *oidc_util_key_list_first(const apr_array_header_t *key_list, int kty, const char *use) {
	oidc_jwk_t *rv = NULL;
	int i = 0;
	oidc_jwk_t *jwk = NULL;
	for (i = 0; (key_list) && (i < key_list->nelts); i++) {
		jwk = APR_ARRAY_IDX(key_list, i, oidc_jwk_t *);
		if ((kty != -1) && (jwk->kty != kty))
			continue;
		if (((use == NULL) || (jwk->use == NULL) || (_oidc_strncmp(jwk->use, use, _oidc_strlen(use)) == 0))) {
			rv = jwk;
			break;
		}
	}
	return rv;
}

#ifdef USE_LIBJQ

static const char *oidc_util_jq_exec(request_rec *r, jq_state *jq, struct jv_parser *parser) {
	const char *rv = NULL;
	jv value, elem, str, msg;

	while (jv_is_valid((value = jv_parser_next(parser)))) {
		jq_start(jq, value, 0);
		while (jv_is_valid(elem = jq_next(jq))) {
			str = jv_dump_string(elem, 0);
			rv = apr_pstrdup(r->pool, jv_string_value(str));
			oidc_debug(r, "jv_dump_string: %s", rv);
			jv_free(str);
		}
		jv_free(elem);
	}

	if (jv_invalid_has_msg(jv_copy(value))) {
		msg = jv_invalid_get_msg(value);
		oidc_error(r, "invalid: %s", jv_string_value(msg));
		jv_free(msg);
	} else {
		jv_free(value);
	}

	return rv;
}

#endif

const char *oidc_util_jq_filter(request_rec *r, const char *input, const char *filter) {
	const char *result = input;
#ifdef USE_LIBJQ
	jq_state *jq = NULL;
	struct jv_parser *parser = NULL;
	int ttl = 0;
	char *key = NULL;
	char *value = NULL;

	if (filter == NULL) {
		oidc_debug(r, "filter is NULL, abort");
		goto end;
	}

	if (input == NULL) {
		oidc_debug(r, "input is NULL, set to empty object");
		input = "{}";
	}

	oidc_debug(r, "processing input: %s", input);
	oidc_debug(r, "processing filter: %s", filter);

	ttl = oidc_jq_filter_cache_ttl(r);
	if (ttl != 0) {
		if (oidc_util_hash_string_and_base64url_encode(
			r, OIDC_JOSE_ALG_SHA256, apr_pstrcat(r->pool, input, filter, NULL), &key) == FALSE) {
			oidc_error(r, "oidc_util_hash_string_and_base64url_encode returned an error");
			goto end;
		}
		oidc_cache_get_jq_filter(r, key, &value);
		if (value != NULL) {
			oidc_debug(r, "return cached result: %s", value);
			result = value;
			goto end;
		}
	}

	jq = jq_init();
	if (jq == NULL) {
		oidc_error(r, "jq_init returned NULL");
		goto end;
	}

	if (jq_compile(jq, filter) == 0) {
		oidc_error(r, "jq_compile returned an error");
		goto end;
	}

	parser = jv_parser_new(0);
	if (parser == NULL) {
		oidc_error(r, "jv_parser_new returned NULL");
		goto end;
	}

	jv_parser_set_buf(parser, input, _oidc_strlen(input), 0);

	result = oidc_util_jq_exec(r, jq, parser);

	if ((result != NULL) && (ttl != 0)) {
		oidc_debug(r, "caching result: %s", result);
		oidc_cache_set_jq_filter(r, key, result, apr_time_now() + apr_time_from_sec(ttl));
	}

end:

	if (parser)
		jv_parser_free(parser);
	if (jq)
		jq_teardown(&jq);
#endif

	return result;
}

char *oidc_util_apr_expr_parse(cmd_parms *cmd, const char *str, oidc_apr_expr_t **expr, apr_byte_t result_is_str) {
	char *rv = NULL;
	if ((str == NULL) || (expr == NULL))
		return NULL;
	*expr = apr_pcalloc(cmd->pool, sizeof(oidc_apr_expr_t));
	(*expr)->str = apr_pstrdup(cmd->pool, str);
#if HAVE_APACHE_24
	const char *expr_err = NULL;
	unsigned int flags = AP_EXPR_FLAG_DONT_VARY & AP_EXPR_FLAG_RESTRICTED;
	if (result_is_str)
		flags += AP_EXPR_FLAG_STRING_RESULT;
	(*expr)->expr = ap_expr_parse_cmd(cmd, str, flags, &expr_err, NULL);
	if (expr_err != NULL) {
		rv = apr_pstrcat(cmd->temp_pool, "cannot parse expression: ", expr_err, NULL);
		*expr = NULL;
	}
#endif
	return rv;
}

const char *oidc_util_apr_expr_exec(request_rec *r, const oidc_apr_expr_t *expr, apr_byte_t result_is_str) {
	const char *expr_result = NULL;
	if (expr == NULL)
		return NULL;
#if HAVE_APACHE_24
	const char *expr_err = NULL;
	if (result_is_str) {
		expr_result = ap_expr_str_exec(r, expr->expr, &expr_err);
	} else {
		expr_result = ap_expr_exec(r, expr->expr, &expr_err) ? "" : NULL;
	}
	if (expr_err) {
		oidc_error(r, "executing expression \"%s\" failed: %s", expr->str, expr_err);
		expr_result = NULL;
	}
#else
	expr_result = expr->str;
#endif
	return expr_result;
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
void oidc_util_set_trace_parent(request_rec *r, oidc_cfg *c, const char *span) {
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

	if (c->trace_parent != OIDC_TRACE_PARENT_GENERATE)
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

	if (c->metrics_hook_data != NULL)
		trace_flags = trace_flags | 0x01;

	oidc_util_hdr_in_set(r, OIDC_HTTP_HDR_TRACE_PARENT,
			     apr_psprintf(r->pool, "00-%s-%s-%02x", s_trace_id, s_parent_id, trace_flags));
}
