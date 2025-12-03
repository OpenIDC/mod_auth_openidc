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
 *
 **************************************************************************/

#include "cfg/cfg.h"
#include "cfg/cfg_int.h"
#include "cfg/dir.h"
#include "cfg/provider.h"
#include "jose.h"
#include "session.h"
#include "util.h"
#include "util/util.h"
#include <apr_base64.h>
#include <openssl/pem.h>

int usage(int argc, char **argv, const char *msg) {
	fprintf(stderr, "Usage: %s %s\n", argv[0],
		msg ? msg
		    : "[ sign | verify | decrypt | key2jwk | enckey | hash_base64url | timestamp | uuid ] <options>");
	return -1;
}

int file_read(apr_pool_t *pool, const char *path, char **rbuf) {
	apr_file_t *fd = NULL;
	char s_err[128];
	int rc;
	apr_size_t bytes_read = 0;
	apr_finfo_t finfo;
	apr_size_t len;

	rc = apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED, APR_OS_DEFAULT, pool);
	if (rc != APR_SUCCESS) {
		fprintf(stderr, "could not open file %s: %s", path, apr_strerror(rc, s_err, sizeof(s_err)));
		return -1;
	}

	apr_file_info_get(&finfo, APR_FINFO_NORM, fd);
	len = (apr_size_t)finfo.size;
	*rbuf = apr_pcalloc(pool, len + 1);

	rc = apr_file_read_full(fd, *rbuf, len, &bytes_read);
	if ((rc != APR_SUCCESS) || (bytes_read < 1)) {
		fprintf(stderr, "could not read file %s: %s", path, apr_strerror(rc, s_err, sizeof(s_err)));
		return -1;
	}

	(*rbuf)[bytes_read] = '\0';

	bytes_read--;
	while ((bytes_read > 0) && ((*rbuf)[bytes_read] == '\n')) {
		(*rbuf)[bytes_read] = '\0';
		bytes_read--;
	}

	apr_file_close(fd);

	return 0;
}

int sign(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 4)
		return usage(argc, argv, "sign <algo> <jwt-file> <jwk-file>");

	char *s_jwt = NULL, *s_jwk = NULL;
	const char *cser = NULL;

	if (file_read(pool, argv[3], &s_jwt) != 0)
		return -1;
	if (file_read(pool, argv[4], &s_jwk) != 0)
		return -1;

	cjose_err cjose_err;

	cjose_header_t *hdr = cjose_header_new(&cjose_err);
	cjose_header_set(hdr, "alg", argv[2], &cjose_err);

	cjose_jwk_t *jwk = cjose_jwk_import(s_jwk, _oidc_strlen(s_jwk), &cjose_err);
	if (jwk == NULL) {
		fprintf(stderr, "could not import JWK: %s [file: %s, function: %s, line: %ld]\n", cjose_err.message,
			cjose_err.file, cjose_err.function, cjose_err.line);
		return -1;
	}

	cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, (const uint8_t *)s_jwt, _oidc_strlen(s_jwt), &cjose_err);
	if (jws == NULL) {
		fprintf(stderr, "could not sign JWS: %s [file: %s, function: %s, line: %ld]\n", cjose_err.message,
			cjose_err.file, cjose_err.function, cjose_err.line);
		return -1;
	}

	if (cjose_jws_export(jws, &cser, &cjose_err) == FALSE) {
		fprintf(stderr, "could not serialize JWS: %s [file: %s, function: %s, line: %ld]\n", cjose_err.message,
			cjose_err.file, cjose_err.function, cjose_err.line);
		return -1;
	}

	fprintf(stdout, "%s", cser);

	cjose_jws_release(jws);
	cjose_jwk_release(jwk);

	return 0;
}

int verify(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 3)
		return usage(argc, argv, "verify <serialized-jwt-file> <jwk-file>");

	char *s_jwt = NULL, *s_jwk = NULL;

	if (file_read(pool, argv[2], &s_jwt) != 0)
		return -1;
	if (file_read(pool, argv[3], &s_jwk) != 0)
		return -1;

	cjose_err cjose_err;

	cjose_jws_t *jws = cjose_jws_import(s_jwt, _oidc_strlen(s_jwt), &cjose_err);
	if (jws == NULL) {
		fprintf(stderr, "could not import JWS: %s [file: %s, function: %s, line: %ld]\n", cjose_err.message,
			cjose_err.file, cjose_err.function, cjose_err.line);
		return -1;
	}

	json_error_t json_error;
	json_t *json = json_loads(s_jwk, 0, &json_error);

	oidc_jose_error_t oidc_err;
	oidc_jwk_t *jwk = oidc_jwk_parse(pool, json, &oidc_err);
	if (jwk == NULL) {
		fprintf(stderr, "could not import JWK: %s [file: %s, function: %s, line: %d]\n", oidc_err.text,
			oidc_err.source, oidc_err.function, oidc_err.line);
		return -1;
	}

	if (cjose_jws_verify(jws, jwk->cjose_jwk, &cjose_err) == FALSE) {
		fprintf(stderr, "could not verify JWS: %s [file: %s, function: %s, line: %ld]\n", cjose_err.message,
			cjose_err.file, cjose_err.function, cjose_err.line);
		return -1;
	}

	uint8_t *plaintext = NULL;
	size_t plaintext_len = 0;
	if (cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &cjose_err) == FALSE) {
		fprintf(stderr, "could not get plaintext: %s [file: %s, function: %s, line: %ld]\n", cjose_err.message,
			cjose_err.file, cjose_err.function, cjose_err.line);
		return -1;
	}

	fprintf(stdout, "%s", plaintext);

	cjose_jws_release(jws);
	oidc_jwk_destroy(jwk);
	json_decref(json);

	return 0;
}

int decrypt(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 3)
		return usage(argc, argv, "decrypt <serialized-jwt-file> <jwk-file>");

	char *s_jwt = NULL, *s_jwk = NULL;

	if (file_read(pool, argv[2], &s_jwt) != 0)
		return -1;
	if (file_read(pool, argv[3], &s_jwk) != 0)
		return -1;

	apr_hash_t *keys = apr_hash_make(pool);

	json_error_t json_error;
	json_t *json = json_loads(s_jwk, 0, &json_error);

	oidc_jose_error_t oidc_err;
	oidc_jwk_t *jwk = oidc_jwk_parse(pool, json, &oidc_err);
	if (jwk == NULL) {
		fprintf(stderr, "could not import JWK: %s [file: %s, function: %s, line: %d]\n", oidc_err.text,
			oidc_err.source, oidc_err.function, oidc_err.line);
		return -1;
	}

	apr_hash_set(keys, jwk->kid ? jwk->kid : "dummy", APR_HASH_KEY_STRING, jwk);

	char *plaintext = NULL;
	if (oidc_jwe_decrypt(pool, s_jwt, keys, &plaintext, NULL, &oidc_err, TRUE) == FALSE) {
		fprintf(stderr, "oidc_jwe_decrypt failed: %s [file: %s, function: %s, line: %d]\n", oidc_err.text,
			oidc_err.source, oidc_err.function, oidc_err.line);
		return -1;
	}

	fprintf(stdout, "%s", plaintext);
	oidc_jwk_destroy(jwk);
	json_decref(json);

	return 0;
}

int key2jwk(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 2)
		return usage(argc, argv, "key2jwk <pem-file> <is_private_key>");

	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;

	int is_private_key = (argc > 3);

	if (is_private_key) {
		if (oidc_jwk_parse_pem_private_key(pool, NULL, argv[2], &jwk, &err) == FALSE) {
			fprintf(stderr, "oidc_jwk_parse_pem_private_key failed: %s", oidc_jose_e2s(pool, err));
			return -1;
		}
	} else {
		if (oidc_jwk_parse_pem_public_key(pool, NULL, argv[2], &jwk, &err) == FALSE) {
			fprintf(stderr, "oidc_jwk_parse_pem_public_key failed: %s", oidc_jose_e2s(pool, err));
			return -1;
		}
	}

	char *s_json = NULL;
	if (oidc_jwk_to_json(pool, jwk, &s_json, &err) == FALSE) {
		fprintf(stderr, "oidc_jwk_to_json failed: %s", oidc_jose_e2s(pool, err));
		return -1;
	}

	fprintf(stdout, "%s", s_json);

	oidc_jwk_destroy(jwk);

	return 0;
}

int enckey(int argc, char **argv, apr_pool_t *pool) {

	if (argc <= 2)
		return usage(argc, argv, "enckey <secret> [hash] [key-length]");

	request_rec *r = oidc_test_request_get();

	oidc_jwk_t *jwk = NULL;
	if (oidc_util_key_symmetric_create(r, argv[2], argc > 4 ? _oidc_str_to_int(argv[4], 0) : 0,
					   argc > 3 ? argv[3] : NULL, FALSE, &jwk) == FALSE) {
		fprintf(stderr, "oidc_util_create_symmetric_key failed");
		return -1;
	}

	oidc_jose_error_t err;
	char *s_json = NULL;
	if (oidc_jwk_to_json(pool, jwk, &s_json, &err) == FALSE) {
		fprintf(stderr, "oidc_jwk_to_json failed");
		return -1;
	}

	cjose_err cjose_err;
	int src_len = cjose_jwk_get_keysize(jwk->cjose_jwk, &cjose_err) / 8;
	int enc_len = apr_base64_encode_len(src_len);
	char *b64 = apr_palloc(r->pool, enc_len);
	apr_base64_encode(b64, (const char *)cjose_jwk_get_keydata(jwk->cjose_jwk, &cjose_err), src_len);

	fprintf(stdout, "\nJWK:\n%s\n\nbase64:\n%s\n\n", s_json, b64);

	return 0;
}

int hash_base64url(int argc, char **argv, apr_pool_t *pool) {
	if (argc <= 2)
		return usage(argc, argv, "hash_base64url <string> [algo] [base64url-decode-first]");

	char *algo = argc > 3 ? argv[3] : "sha256";
	int base64url_decode_first = argc > 4 ? (_oidc_strcmp(argv[4], "yes") == 0) : 0;
	char *output = NULL;

	request_rec *r = oidc_test_request_get();

	if (base64url_decode_first) {

		uint8_t *bytes = NULL;
		size_t outlen = 0;
		cjose_err cjose_err;
		if (cjose_base64url_decode(argv[2], _oidc_strlen(argv[2]), &bytes, &outlen, &cjose_err) == FALSE) {
			fprintf(stderr, "cjose_base64_decode failed: %s", cjose_err.message);
			return -1;
		}
		oidc_jose_error_t err;
		if (oidc_jose_hash_and_base64url_encode(r->pool, algo, (const char *)bytes, outlen, &output, &err) ==
		    FALSE) {
			fprintf(stderr, "oidc_jose_hash_and_base64url_encode failed: %s", err.text);
			return -1;
		}
	} else {
		if (oidc_util_hash_string_and_base64url_encode(r, algo, argv[2], &output) == FALSE) {
			fprintf(stderr, "oidc_util_hash_string_and_base64url_encode failed");
			return -1;
		}
	}

	fprintf(stdout, "%s\n", output);

	return 0;
}

int timestamp(int argc, char **argv, apr_pool_t *pool) {
	if (argc <= 2)
		return usage(argc, argv, "timestamp <seconds>");
	int delta = _oidc_str_to_int(argv[2], 0);
	apr_time_t t1 = apr_time_now() + apr_time_from_sec(delta);
	char *s = apr_psprintf(pool, "%" APR_TIME_T_FMT, t1);
	fprintf(stderr, "timestamp (1) = %s\n", s);

	apr_time_t t2 = _oidc_str_to_time(s, -1);
	fprintf(stderr, "timestamp (2) = %" APR_TIME_T_FMT "\n", t2);

	char buf[APR_RFC822_DATE_LEN + 1];
	apr_rfc822_date(buf, t2);
	fprintf(stderr, "timestamp (3): %s (%" APR_TIME_T_FMT " secs from now)\n", buf,
		apr_time_sec(t2 - apr_time_now()));

	return 0;
}

int uuid(int argc, char **argv, apr_pool_t *pool) {
	const unsigned long e = 1000000;
	unsigned long n = 25000000;
	unsigned long i = 0;
	oidc_session_t z;

	if (argc > 2) {
		n = _oidc_str_to_int(argv[2], n);
		if (n > 25000000 * 10)
			n = 25000000;
	}

	request_rec *r = oidc_test_request_get();

	apr_hash_t *entries = apr_hash_make(pool);
	while (i < n) {
		z.uuid = NULL;
		oidc_session_id_new(r, &z);
		if (apr_hash_get(entries, (const void *)&z.uuid, APR_HASH_KEY_STRING) != NULL) {
			fprintf(stderr, "duplicate found: %s\n", z.uuid);
			exit(-1);
		} else {
			apr_hash_set(entries, (const void *)apr_pstrdup(pool, z.uuid), APR_HASH_KEY_STRING,
				     (const void *)1);
		}
		i++;
		if (i % e == 0)
			fprintf(stderr, "\r %lu  (%s)", i / e, z.uuid);
	}
	fprintf(stderr, "\n");
	return 0;
}
int main(int argc, char **argv, char **env) {

	int rc = 0;

	if (argc <= 1)
		return usage(argc, argv, NULL);

	oidc_test_setup();

	apr_pool_t *pool = oidc_test_pool_get();

	if (_oidc_strcmp(argv[1], "sign") == 0)
		rc = sign(argc, argv, pool);

	else if (_oidc_strcmp(argv[1], "verify") == 0)
		rc = verify(argc, argv, pool);

	else if (_oidc_strcmp(argv[1], "decrypt") == 0)
		rc = decrypt(argc, argv, pool);

	else if (_oidc_strcmp(argv[1], "key2jwk") == 0)
		rc = key2jwk(argc, argv, pool);

	else if (_oidc_strcmp(argv[1], "enckey") == 0)
		rc = enckey(argc, argv, pool);

	else if (_oidc_strcmp(argv[1], "hash_base64url") == 0)
		rc = hash_base64url(argc, argv, pool);

	else if (_oidc_strcmp(argv[1], "timestamp") == 0)
		rc = timestamp(argc, argv, pool);

	else if (_oidc_strcmp(argv[1], "uuid") == 0)
		rc = uuid(argc, argv, pool);

	else
		rc = usage(argc, argv, NULL);

	oidc_test_teardown();

	return rc;
}
