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

#include "helper.h"
#include "jose.h"

// supported

START_TEST(test_jose_jws_supported_algorithms) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jws_supported_algorithms(oidc_test_pool_get());
	ck_assert_msg(arr != NULL, "list of supported signing algorithms is empty");
}
END_TEST

START_TEST(test_jose_jws_algorithm_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jws_algorithm_is_supported(oidc_test_pool_get(), "RS256");
	ck_assert_msg(rv == TRUE, "algorithm RS256 is not supported");
	rv = oidc_jose_jws_algorithm_is_supported(oidc_test_pool_get(), "NO256");
	ck_assert_msg(rv == FALSE, "algorithm NO256 should not be supported");
#ifdef OIDC_JOSE_EC_SUPPORT
	rv = oidc_jose_jws_algorithm_is_supported(oidc_test_pool_get(), "ES256");
	ck_assert_msg(rv == TRUE, "algorithm ES256 is not supported");
#endif
}
END_TEST

START_TEST(test_jose_jwe_supported_algorithms) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jwe_supported_algorithms(oidc_test_pool_get());
	ck_assert_msg(arr != NULL, "list of supported encryption algorithms is empty");
}
END_TEST

START_TEST(test_jose_jwe_algorithm_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jwe_algorithm_is_supported(oidc_test_pool_get(), "A128KW");
	ck_assert_msg(rv == TRUE, "algorithm A128KW is not supported");
}
END_TEST

START_TEST(test_jose_jwe_supported_encryptions) {
	apr_array_header_t *arr = NULL;
	arr = oidc_jose_jwe_supported_encryptions(oidc_test_pool_get());
	ck_assert_msg(arr != NULL, "list of supported encryption ciphers is empty");
}
END_TEST

START_TEST(test_jose_jwe_encryption_is_supported) {
	apr_byte_t rv = FALSE;
	rv = oidc_jose_jwe_encryption_is_supported(oidc_test_pool_get(), "A128CBC-HS256");
	ck_assert_msg(rv == TRUE, "cipher A128CBC-HS256 is not supported");
#if (OIDC_JOSE_GCM_SUPPORT)
	rv = oidc_jose_jwe_encryption_is_supported(oidc_test_pool_get(), "A256GCM");
	ck_assert_msg(rv == TRUE, "cipher A256GCM is not supported");
#endif
}
END_TEST

int main(void) {
	TCase *sup = tcase_create("supported");
	tcase_add_checked_fixture(sup, oidc_test_setup, oidc_test_teardown);

	tcase_add_test(sup, test_jose_jws_supported_algorithms);
	tcase_add_test(sup, test_jose_jws_algorithm_is_supported);
	tcase_add_test(sup, test_jose_jwe_supported_algorithms);
	tcase_add_test(sup, test_jose_jwe_algorithm_is_supported);
	tcase_add_test(sup, test_jose_jwe_supported_encryptions);
	tcase_add_test(sup, test_jose_jwe_encryption_is_supported);

	Suite *s = suite_create("jose");
	suite_add_tcase(s, sup);

	return oidc_test_suite_run(s);
}
