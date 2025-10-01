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

#ifndef _MOD_AUTH_OPENIDC_TEST_COMMON_H_
#define _MOD_AUTH_OPENIDC_TEST_COMMON_H_

#include "const.h" // for the PACKAGE_* defines
#include <apr_pools.h>
#include <check.h>
#include <httpd.h>
#include <stdbool.h>
#include <stdlib.h>

#include "cfg/cfg.h"

void oidc_test_setup(void);
void oidc_test_teardown(void);
int oidc_test_suite_run(Suite *s);
apr_pool_t *oidc_test_pool_get();
request_rec *oidc_test_request_get();
oidc_cfg_t *oidc_test_cfg_get();
cmd_parms *oidc_test_cmd_get(const char *primitive);

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
#endif

#endif // _MOD_AUTH_OPENIDC_TEST_COMMON_H_
