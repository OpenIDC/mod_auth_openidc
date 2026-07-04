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
 * JSON Web Token handling
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include <apr_base64.h>
#define APR_WANT_BYTEFUNC
#include <apr_want.h>

#ifdef USE_LIBBROTLI
#include <brotli/decode.h>
#include <brotli/encode.h>
#elif USE_ZLIB
#include <zlib.h>
#endif

#include "jose.h"

/*
 * jose.c is the cjose seam: cjose's public API is defined in terms of the JSON backend's value
 * type (jansson's json_t, identical to oidc_json_t), so this is the one translation unit besides
 * json.c that includes the backend header directly and uses the raw json_* API
 */
#include <jansson.h>

#include <cjose/cjose.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "util/util.h"

#include "jose/internal.h"

/*
 * assemble an error report
 */
void _oidc_jose_error_set(oidc_jose_error_t *error, const char *source, const int line, const char *function,
			  const char *fmt, ...) {
	if (error == NULL)
		return;
	snprintf(error->source, OIDC_JOSE_ERROR_SOURCE_LENGTH, "%s", source);
	error->line = line;
	snprintf(error->function, OIDC_JOSE_ERROR_FUNCTION_LENGTH, "%s", function);
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(error->text, OIDC_JOSE_ERROR_TEXT_LENGTH, fmt ? fmt : "(null)", ap);
	va_end(ap);
}

/*
 * hash a sequence of bytes with a specific algorithm and return the result as a base64url-encoded \0 terminated string
 */
apr_byte_t oidc_jose_hash_and_base64url_encode(apr_pool_t *pool, const char *openssl_hash_algo, const char *input,
					       int input_len, char **output, oidc_jose_error_t *err) {
	unsigned char *hashed = NULL;
	unsigned int hashed_len = 0;
	if (oidc_jose_hash_bytes(pool, openssl_hash_algo, (const unsigned char *)input, input_len, &hashed, &hashed_len,
				 err) == FALSE)
		return FALSE;
	char *out = NULL;
	size_t out_len;
	cjose_err cjose_err;
	if (cjose_base64url_encode(hashed, hashed_len, &out, &out_len, &cjose_err) == FALSE) {
		oidc_jose_error(err, "cjose_base64url_encode failed: %s", oidc_cjose_e2s(pool, cjose_err));
		return FALSE;
	}
	*output = apr_pstrmemdup(pool, out, out_len);
	cjose_get_dealloc()(out);
	return TRUE;
}

/*
 * check if a string is an element of an array of strings
 */
static apr_byte_t oidc_jose_array_has_string(apr_array_header_t *haystack, const char *needle) {
	int i = 0;
	while (i < haystack->nelts) {
		if (_oidc_strcmp(APR_ARRAY_IDX(haystack, i, const char *), needle) == 0)
			return TRUE;
		i++;
	}
	return FALSE;
}

/*
 * return all supported signing algorithms
 */
apr_array_header_t *oidc_jose_jws_supported_algorithms(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 12, sizeof(const char *));
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RS256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RS384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RS512;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_PS256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_PS384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_PS512;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_HS256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_HS384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_HS512;
#if (OIDC_JOSE_EC_SUPPORT)
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_ES256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_ES384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_ES512;
#endif
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_NONE;
	return result;
}

/*
 * check if the provided signing algorithm is supported
 */
apr_byte_t oidc_jose_jws_algorithm_is_supported(apr_pool_t *pool, const char *alg) {
	return oidc_jose_array_has_string(oidc_jose_jws_supported_algorithms(pool), alg);
}

/*
 * return all supported content encryption key algorithms
 */
apr_array_header_t *oidc_jose_jwe_supported_algorithms(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 4, sizeof(const char *));
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_A128KW;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_A192KW;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_A256KW;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ALG_RSA_OAEP;
	return result;
}

/*
 * check if the provided content encryption key algorithm is supported
 */
apr_byte_t oidc_jose_jwe_algorithm_is_supported(apr_pool_t *pool, const char *alg) {
	return oidc_jose_array_has_string(oidc_jose_jwe_supported_algorithms(pool), alg);
}

/*
 * return all supported encryption algorithms
 */
apr_array_header_t *oidc_jose_jwe_supported_encryptions(apr_pool_t *pool) {
	apr_array_header_t *result = apr_array_make(pool, 5, sizeof(const char *));
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ENC_A128CBC_HS256;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ENC_A192CBC_HS384;
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ENC_A256CBC_HS512;
#if (OIDC_JOSE_GCM_SUPPORT)
	APR_ARRAY_PUSH(result, const char *) = CJOSE_HDR_ENC_A256GCM;
#endif
	return result;
}

/*
 * check if the provided encryption algorithm is supported
 */
apr_byte_t oidc_jose_jwe_encryption_is_supported(apr_pool_t *pool, const char *enc) {
	return oidc_jose_array_has_string(oidc_jose_jwe_supported_encryptions(pool), enc);
}

/*
 * get (optional) string from JWT
 */
apr_byte_t oidc_jose_get_string(apr_pool_t *pool, const json_t *json, const char *claim_name, apr_byte_t is_mandatory,
				char **result, oidc_jose_error_t *err) {
	const json_t *v = json_object_get(json, claim_name);
	if (v != NULL) {
		if (json_is_string(v)) {
			*result = apr_pstrdup(pool, json_string_value(v));
		} else if (is_mandatory) {
			oidc_jose_error(err, "mandatory JSON key \"%s\" was found but the type is not a string",
					claim_name);
			return FALSE;
		}
	} else if (is_mandatory) {
		oidc_jose_error(err, "mandatory JSON key \"%s\" could not be found", claim_name);
		return FALSE;
	}
	return TRUE;
}

/*
 * parse (optional) timestamp from payload
 */
apr_byte_t oidc_jose_get_timestamp(apr_pool_t *pool, const json_t *json, const char *claim_name,
				   apr_byte_t is_mandatory, double *result, oidc_jose_error_t *err) {
	*result = OIDC_JWT_CLAIM_TIME_EMPTY;
	const json_t *v = json_object_get(json, claim_name);
	if (v != NULL) {
		if (json_is_number(v)) {
			*result = json_number_value(v);
		} else if (is_mandatory) {
			oidc_jose_error(err, "mandatory JSON key \"%s\" was found but the type is not a number",
					claim_name);
			return FALSE;
		}
	} else if (is_mandatory) {
		oidc_jose_error(err, "mandatory JSON key \"%s\" could not be found", claim_name);
		return FALSE;
	}
	return TRUE;
}

#ifdef USE_LIBBROTLI

/*
 * deflate using libbrotli
 */
static apr_byte_t oidc_jose_brotli_compress(apr_pool_t *pool, const char *input, int input_len, char **output,
					    int *output_len, oidc_jose_error_t *err) {
	size_t len = BrotliEncoderMaxCompressedSize(input_len);
	*output = apr_pcalloc(pool, len);
	if (BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_TEXT, input_len,
				  (const uint8_t *)input, &len, (uint8_t *)*output) != BROTLI_TRUE) {
		oidc_jose_error(err, "BrotliEncoderCompress failed: compression error or buffer too small");
		return FALSE;
	}
	*output_len = len;
	return TRUE;
}

/*
 * inflate using libbrotli
 */
static apr_byte_t oidc_jose_brotli_uncompress(apr_pool_t *pool, const char *input, int input_len, char **output,
					      int *output_len, oidc_jose_error_t *err) {
	size_t len = 4 * input_len;
	*output = apr_pcalloc(pool, len);
	if (BrotliDecoderDecompress(input_len, (const uint8_t *)input, &len, (uint8_t *)*output) !=
	    BROTLI_DECODER_RESULT_SUCCESS) {
		oidc_jose_error(err, "BrotliDecoderDecompress failed: decompression error or buffer too small");
		return FALSE;
	}
	*output_len = len;
	return TRUE;
}

#elif USE_ZLIB

/*
 * deflate using zlib
 */
static apr_byte_t oidc_jose_zlib_compress(apr_pool_t *pool, const char *input, int input_len, char **output,
					  int *output_len, oidc_jose_error_t *err) {
	apr_byte_t rv = FALSE;
	int status = Z_OK;
	z_stream zlib;

	zlib.zalloc = Z_NULL;
	zlib.zfree = Z_NULL;
	zlib.opaque = Z_NULL;
	zlib.next_in = (Bytef *)input;
	zlib.avail_in = input_len;

	*output = apr_pcalloc(pool, input_len * 2);
	zlib.next_out = (Bytef *)(*output);
	zlib.avail_out = input_len * 2;

	status = deflateInit(&zlib, Z_BEST_COMPRESSION);
	if (status != Z_OK) {
		oidc_jose_error(err, "deflateInit() failed: %d", status);
		goto end;
	}

	status = deflate(&zlib, Z_FINISH);
	if (status != Z_STREAM_END) {
		oidc_jose_error(err, "deflate() failed: %d", status);
		goto end;
	}

	*output_len = (int)zlib.total_out;

	rv = TRUE;

end:

	deflateEnd(&zlib);

	return rv;
}

#define OIDC_CJOSE_UNCOMPRESS_CHUNK 8192
/* absolute cap on the inflated output to prevent decompression bombs */
#define OIDC_CJOSE_UNCOMPRESS_MAX (10 * 1024 * 1024)

/*
 * inflate using zlib
 */
static apr_byte_t oidc_jose_zlib_uncompress(apr_pool_t *pool, const char *input, int input_len, char **output,
					    int *output_len, oidc_jose_error_t *err) {
	apr_byte_t rv = FALSE;
	int status = Z_OK;
	size_t len = OIDC_CJOSE_UNCOMPRESS_CHUNK;
	char *tmp = NULL;
	char *buf = apr_pcalloc(pool, len);
	z_stream zlib;

	zlib.zalloc = Z_NULL;
	zlib.zfree = Z_NULL;
	zlib.opaque = Z_NULL;
	zlib.avail_in = (uInt)input_len;
	zlib.next_in = (Bytef *)input;
	zlib.total_out = 0;

	status = inflateInit(&zlib);
	if (status != Z_OK) {
		oidc_jose_error(err, "inflateInit() failed: %d", status);
		goto end;
	}

	while (status == Z_OK) {
		if (zlib.total_out >= OIDC_CJOSE_UNCOMPRESS_CHUNK) {
			if (len + OIDC_CJOSE_UNCOMPRESS_CHUNK > OIDC_CJOSE_UNCOMPRESS_MAX) {
				oidc_jose_error(err, "inflate() output would exceed %d bytes",
						OIDC_CJOSE_UNCOMPRESS_MAX);
				goto end;
			}
			tmp = apr_pcalloc(pool, len + OIDC_CJOSE_UNCOMPRESS_CHUNK);
			_oidc_memcpy(tmp, buf, len);
			len += OIDC_CJOSE_UNCOMPRESS_CHUNK;
			buf = tmp;
		}
		zlib.next_out = (Bytef *)(buf + zlib.total_out);
		zlib.avail_out = (uInt)(len - zlib.total_out);
		status = inflate(&zlib, Z_SYNC_FLUSH);
	}

	if (status != Z_STREAM_END) {
		oidc_jose_error(err, "inflate() failed: %d", status);
		goto end;
	}

	*output_len = (int)zlib.total_out;
	*output = buf;

	rv = TRUE;

end:

	inflateEnd(&zlib);

	return rv;
}

#endif

/*
 * compress using (compile-time) zlib or libbrotli, otherwise just plain copy
 */
apr_byte_t oidc_jose_compress(apr_pool_t *pool, const char *input, int input_len, char **output, int *output_len,
			      oidc_jose_error_t *err) {
#ifdef USE_LIBBROTLI
	return oidc_jose_brotli_compress(pool, input, input_len, output, output_len, err);
#elif USE_ZLIB
	return oidc_jose_zlib_compress(pool, input, input_len, output, output_len, err);
#else
	*output = apr_pmemdup(pool, input, input_len);
	*output_len = input_len;
	return TRUE;
#endif
}

/*
 * decompress using (compile-time) zlib or libbrotli, otherwise just plain copy
 */
apr_byte_t oidc_jose_uncompress(apr_pool_t *pool, const char *input, int input_len, char **output, int *output_len,
				oidc_jose_error_t *err) {
#ifdef USE_LIBBROTLI
	return oidc_jose_brotli_uncompress(pool, input, input_len, output, output_len, err);
#elif USE_ZLIB
	return oidc_jose_zlib_uncompress(pool, input, input_len, output, output_len, err);
#else
	*output = apr_pmemdup(pool, input, input_len);
	*output_len = input_len;
	return TRUE;
#endif
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000) || defined(LIBRESSL_VERSION_NUMBER)
EVP_MD_CTX *EVP_MD_CTX_new() {
	return malloc(sizeof(EVP_MD_CTX));
}
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
	if (ctx)
		free(ctx);
}
#endif

#define OIDC_JOSE_CJOSE_VERSION_DEPRECATED "0.4."

/*
 * return the version string of the underlying JOSE backend library
 */
const char *oidc_jose_version(void) {
	return cjose_version();
}

/*
 * check for a version of cjose < 0.5.0 that has a version of
 * cjose_jws_verify that resources after a verification failure
 */
apr_byte_t oidc_jose_version_deprecated(apr_pool_t *pool) {
	const char *version = apr_pstrdup(pool, cjose_version());
	return (_oidc_strstr(version, OIDC_JOSE_CJOSE_VERSION_DEPRECATED) == version);
}

/*
 * hash a byte sequence with the specified algorithm
 */
apr_byte_t oidc_jose_hash_bytes(apr_pool_t *pool, const char *s_digest, const unsigned char *input,
				unsigned int input_len, unsigned char **output, unsigned int *output_len,
				oidc_jose_error_t *err) {
	apr_byte_t rv = FALSE;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	const EVP_MD *evp_digest = NULL;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_MD_CTX_init(ctx);

	if ((evp_digest = EVP_get_digestbyname(s_digest)) == NULL) {
		oidc_jose_error(err, "no OpenSSL digest algorithm found for algorithm \"%s\"", s_digest);
		goto end;
	}

	if (!EVP_DigestInit_ex(ctx, evp_digest, NULL)) {
		oidc_jose_error_openssl(err, "EVP_DigestInit_ex");
		goto end;
	}

	if (!EVP_DigestUpdate(ctx, input, input_len)) {
		oidc_jose_error_openssl(err, "EVP_DigestUpdate");
		goto end;
	}

	if (!EVP_DigestFinal(ctx, md_value, output_len)) {
		oidc_jose_error_openssl(err, "EVP_DigestFinal");
		goto end;
	}

	*output = apr_pmemdup(pool, md_value, *output_len);

	rv = TRUE;

end:

	if (ctx)
		EVP_MD_CTX_free(ctx);

	return rv;
}

/*
 * return the OpenSSL hash algorithm associated with a specified JWT algorithm
 */
static char *oidc_jose_alg_to_openssl_digest(const char *alg) {
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS256) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS256) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES256) == 0)) {
		return LN_sha256;
	}
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS384) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS384) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS384) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)) {
		return LN_sha384;
	}
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS512) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS512) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS512) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES512) == 0)) {
		return LN_sha512;
	}
	return NULL;
}

/*
 * hash a string value with the specified algorithm
 */
apr_byte_t oidc_jose_hash_string(apr_pool_t *pool, const char *alg, const char *msg, char **hash,
				 unsigned int *hash_len, oidc_jose_error_t *err) {

	const char *s_digest = oidc_jose_alg_to_openssl_digest(alg);
	if (s_digest == NULL) {
		oidc_jose_error(err, "no OpenSSL digest algorithm name found for algorithm \"%s\"", alg);
		return FALSE;
	}

	return oidc_jose_hash_bytes(pool, s_digest, (const unsigned char *)msg, (unsigned int)_oidc_strlen(msg),
				    (unsigned char **)hash, hash_len, err);
}

/*
 * return hash length for the specified JOSE algorithm
 */
int oidc_jose_hash_length(const char *alg) {
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS256) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS256) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES256) == 0)) {
		return 32;
	}
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS384) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS384) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS384) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)) {
		return 48;
	}
	if ((_oidc_strcmp(alg, CJOSE_HDR_ALG_RS512) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_PS512) == 0) ||
	    (_oidc_strcmp(alg, CJOSE_HDR_ALG_HS512) == 0) || (_oidc_strcmp(alg, CJOSE_HDR_ALG_ES512) == 0)) {
		return 64;
	}
	return 0;
}
