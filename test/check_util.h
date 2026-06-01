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

#ifndef _MOD_AUTH_OPENIDC_TEST_CHECK_UTIL_H_
#define _MOD_AUTH_OPENIDC_TEST_CHECK_UTIL_H_

#include <apr_tables.h>
#include <check.h>

#ifndef _ck_assert_ptr_null
#define _ck_assert_ptr_null(X, OP)                                                                                     \
	do {                                                                                                           \
		const void *_ck_x = (X);                                                                               \
		ck_assert_msg(_ck_x OP NULL, "Assertion '%s' failed: %s == %#lx", #X " " #OP " NULL", #X,              \
			      (unsigned long)(uintptr_t)_ck_x);                                                        \
	} while (0)
#define ck_assert_ptr_null(X) _ck_assert_ptr_null(X, ==)
#define ck_assert_ptr_nonnull(X) _ck_assert_ptr_null(X, !=)
#endif

#ifndef _ck_assert_ptr
#define _ck_assert_ptr(X, OP, Y)                                                                                       \
	do {                                                                                                           \
		const void *_ck_x = (X);                                                                               \
		const void *_ck_y = (Y);                                                                               \
		ck_assert_msg(_ck_x OP _ck_y, "Assertion '%s' failed: %s == %#lx, %s == %#lx", #X " " #OP " " #Y, #X,  \
			      (unsigned long)(uintptr_t)_ck_x, #Y, (unsigned long)(uintptr_t)_ck_y);                   \
	} while (0)
#define ck_assert_ptr_eq(X, Y) _ck_assert_ptr(X, ==, Y)
#define ck_assert_ptr_ne(X, Y) _ck_assert_ptr(X, !=, Y)
#endif

/*
 * domain-specific assertions for the libcheck tests
 *
 * The module passes claims and metadata to the request as apr_table entries
 * (headers, subprocess_env, ...), so the tests check those constantly. These
 * wrap the apr_table_get + ck_assert pattern and, unlike a bare
 * ck_assert_str_eq(apr_table_get(...), ...), fail cleanly with the key name
 * instead of dereferencing NULL when the entry is absent.
 */

/* assert that table entry KEY is present and equals EXPECTED */
#define ck_assert_table_str(tbl, key, expected)                                                                        \
	do {                                                                                                           \
		const char *_ck_tv = apr_table_get((tbl), (key));                                                      \
		ck_assert_msg(_ck_tv != NULL, "table entry '%s' is missing", (key));                                   \
		ck_assert_str_eq(_ck_tv, (expected));                                                                  \
	} while (0)

/* assert that table entry KEY is absent */
#define ck_assert_table_unset(tbl, key) ck_assert_ptr_null(apr_table_get((tbl), (key)))

/*
 * assert that oidc_jwt_parse() of S succeeds, reporting the jose error string
 * on failure (the bare ck_assert_int_eq(oidc_jwt_parse(...), TRUE) only says
 * "!= TRUE", not why). COMPRESS is FALSE, matching every call site. The
 * including TU must pull in jose.h (oidc_jwt_parse / oidc_jose_e2s).
 */
#define ck_assert_jwt_parses(pool, s, jwt, keys, err)                                                                  \
	ck_assert_msg(oidc_jwt_parse((pool), (s), &(jwt), (keys), FALSE, &(err)) == TRUE, "oidc_jwt_parse failed: %s", \
		      oidc_jose_e2s((pool), (err)))

int oidc_test_suite_run(Suite *s);

#endif // _MOD_AUTH_OPENIDC_TEST_CHECK_UTIL_H_
