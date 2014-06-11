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
 * Initially based on mod_auth_cas.c:
 * https://github.com/Jasig/mod_auth_cas
 *
 * Other code copied/borrowed/adapted:
 * AES crypto: http://saju.net.in/code/misc/openssl_aes.c.txt
 * session handling: Apache 2.4 mod_session.c
 * session handling backport: http://contribsoft.caixamagica.pt/browser/internals/2012/apachecc/trunk/mod_session-port/src/util_port_compat.c
 * shared memory caching: mod_auth_mellon
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

#include <stdio.h>
#include <errno.h>

#include <openssl/evp.h>

#include "apr.h"
#include "apr_errno.h"
#include "apr_general.h"
#include "apr_time.h"
#include "jose/apr_jose.h"
#include "apr_base64.h"

static int test_nr_run = 0;
static char TST_ERR_MSG[512];
static int TST_RC;

#define TST_FORMAT(fmt) \
	" # %s: error in %s: result \"" fmt "\" != expected \"" fmt "\""

#define TST_ASSERT(message, test) \
	if (!(test)) { \
		sprintf(TST_ERR_MSG, TST_FORMAT("%d"), __FUNCTION__, message, test, 1); \
		return TST_ERR_MSG; \
	}

#define TST_ASSERT_STR(message, result, expected) \
	TST_RC = ((!result) || (!expected)) ? (result != expected) : strcmp(result, expected); \
	if (TST_RC) { \
		sprintf(TST_ERR_MSG, TST_FORMAT("%s"), __FUNCTION__, message, result, expected); \
		return TST_ERR_MSG; \
	}

#define TST_ASSERT_LONG(message, result, expected) \
	if (result != expected) { \
		sprintf(TST_ERR_MSG, TST_FORMAT("%ld"), __FUNCTION__, message, result, expected); \
		return TST_ERR_MSG; \
	}

#define TST_RUN(test, pool) char *message = test(pool); test_nr_run++; if (message) return message;

static char * test_jwt_parse(apr_pool_t *pool) {

	// from http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20
	// 3.1.  Example JWT
	char *s = apr_pstrdup(pool,
			"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" \
			".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" \
			".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

	apr_jwt_t *jwt = NULL;

	TST_ASSERT("apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, NULL));

	TST_ASSERT_STR("header.alg", jwt->header.alg, "HS256");
	TST_ASSERT_STR("header.enc", jwt->header.enc, NULL);
	TST_ASSERT_STR("header.kid", jwt->header.kid, NULL);

	TST_ASSERT_STR("payload.iss", jwt->payload.iss, "joe");
	TST_ASSERT_LONG("payload.exp", (long)apr_time_sec(jwt->payload.exp), 1300819380L);

	char *str_key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
	char *raw_key = NULL;
	int raw_key_len = apr_jwt_base64url_decode(pool, &raw_key, str_key, 1);

	TST_ASSERT("apr_jws_verify_hmac", apr_jws_verify_hmac(pool, jwt, raw_key, raw_key_len));

	s[5] = '.';
	TST_ASSERT("corrupted header (1) apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, NULL) == FALSE);

	s[0] = '\0';
	TST_ASSERT("corrupted header (2) apr_jwt_parse", apr_jwt_parse(pool, s, &jwt, NULL, NULL) == FALSE);

	return 0;
}

static char * all_tests(apr_pool_t *pool) {
	TST_RUN(test_jwt_parse, pool);
	return 0;
}

int main(int argc, char **argv, char **env) {
	if (apr_app_initialize(&argc, (const char *const **) argv, (const char *const **) env) != APR_SUCCESS) {
		printf("apr_app_initialize failed\n");
		return -1;
	}

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, NULL);;
	OpenSSL_add_all_digests();

	char *result = all_tests(pool);
	if (result != 0) {
		printf("Failed: %s\n", result);
	} else {
		printf("All %d tests passed!\n", test_nr_run);
	}

	EVP_cleanup();
	apr_pool_destroy(pool);
	apr_terminate();

	return result != 0;
}

