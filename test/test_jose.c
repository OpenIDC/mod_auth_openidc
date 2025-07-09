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
 *
 **************************************************************************/

#include <check.h>
#include <stdbool.h>
#include <stdlib.h>

#include <openssl/evp.h>

#include "cfg/cfg.h"
#include "jose.h"

static apr_pool_t *pool = NULL;

// supported

START_TEST(test_jose_jws_supported_algorithms) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jws_supported_algorithms(pool);
	ck_assert_msg(arr != NULL, "list of supported signing algorithms is empty");
}
END_TEST

START_TEST(test_jose_jws_algorithm_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jws_algorithm_is_supported(pool, "RS256");
	ck_assert_msg(rv == TRUE, "algorithm RS256 is not supported");
	rv = oidc_jose_jws_algorithm_is_supported(pool, "NO256");
	ck_assert_msg(rv == FALSE, "algorithm NO256 should not be supported");
#ifdef OIDC_JOSE_EC_SUPPORT
	rv = oidc_jose_jws_algorithm_is_supported(pool, "ES256");
	ck_assert_msg(rv == TRUE, "algorithm ES256 is not supported");
#endif
}
END_TEST

START_TEST(test_jose_jwe_supported_algorithms) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jwe_supported_algorithms(pool);
	ck_assert_msg(arr != NULL, "list of supported encryption algorithms is empty");
}
END_TEST

START_TEST(test_jose_jwe_algorithm_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jwe_algorithm_is_supported(pool, "A128KW");
	ck_assert_msg(rv == TRUE, "algorithm A128KW is not supported");
}
END_TEST

START_TEST(test_jose_jwe_supported_encryptions) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jwe_supported_encryptions(pool);
	ck_assert_msg(arr != NULL, "list of supported encryption ciphers is empty");
}
END_TEST

START_TEST(test_jose_jwe_encryption_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jwe_encryption_is_supported(pool, "A128CBC-HS256");
	ck_assert_msg(rv == TRUE, "cipher A128CBC-HS256 is not supported");
#if (OIDC_JOSE_GCM_SUPPORT)
	rv = oidc_jose_jwe_encryption_is_supported(pool, "A256GCM");
	ck_assert_msg(rv == TRUE, "cipher A256GCM is not supported");
#endif
}
END_TEST

static void setup(void) {
	apr_initialize();
	oidc_pre_config_init();
	apr_pool_create(&pool, NULL);
}

static void teardown(void) {
	EVP_cleanup();
	apr_pool_destroy(pool);
	apr_terminate();
}

int main(void) {
	int n_failed = 0;

	TCase *sup = tcase_create("supported");
	tcase_add_checked_fixture(sup, setup, teardown);

	tcase_add_test(sup, test_jose_jws_supported_algorithms);
	tcase_add_test(sup, test_jose_jws_algorithm_is_supported);
	tcase_add_test(sup, test_jose_jwe_supported_algorithms);
	tcase_add_test(sup, test_jose_jwe_algorithm_is_supported);
	tcase_add_test(sup, test_jose_jwe_supported_encryptions);
	tcase_add_test(sup, test_jose_jwe_encryption_is_supported);

	Suite *s = suite_create("jose");
	suite_add_tcase(s, sup);

	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	n_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (n_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
