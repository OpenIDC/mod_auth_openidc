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

#ifndef _MOD_AUTH_OPENIDC_TEST_UTIL_H_
#define _MOD_AUTH_OPENIDC_TEST_UTIL_H_

#include "const.h" // for the PACKAGE_* defines
#include <apr_pools.h>
#include <httpd.h>
#include <stdbool.h>
#include <stdlib.h>

#include "cfg/cfg.h"

void oidc_test_setup(void);
void oidc_test_teardown(void);
apr_pool_t *oidc_test_pool_get(void);
request_rec *oidc_test_request_get(void);
oidc_cfg_t *oidc_test_cfg_get(void);
cmd_parms *oidc_test_cmd_get(const char *primitive);
void oidc_test_set_auth_type(const char *auth_type);
void oidc_test_crypto_passphrase_rederive(oidc_cfg_t *cfg);

/*
 * the server-lifetime hooks the module registers with httpd, recorded by the ap_hook_* stubs so a
 * test can call them the way httpd would; NULL until auth_openidc_module.register_hooks() has run
 */
typedef int (*oidc_test_hook_post_config_fn)(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s);
typedef void (*oidc_test_hook_child_init_fn)(apr_pool_t *p, server_rec *s);
typedef void (*oidc_test_hook_insert_filter_fn)(request_rec *r);
typedef apr_status_t (*oidc_test_input_filter_fn)(ap_filter_t *f, apr_bucket_brigade *b, ap_input_mode_t mode,
						  apr_read_type_e block, apr_off_t nbytes);
oidc_test_hook_post_config_fn oidc_test_hook_post_config_get(void);
oidc_test_hook_child_init_fn oidc_test_hook_child_init_get(void);
oidc_test_hook_insert_filter_fn oidc_test_hook_insert_filter_get(void);
oidc_test_input_filter_fn oidc_test_input_filter_get(void);

/* the name ap_add_input_filter was last called with, i.e. whether the module inserted its filter */
const char *oidc_test_added_input_filter_get(void);
void oidc_test_added_input_filter_reset(void);

/* prime the next ap_get_brigade() call to yield `body` followed by EOS, and to return `rc` */
void oidc_test_brigade_prime(const char *body, apr_status_t rc);

/* the first authz_provider the module registered, for driving its parse_require_line */
const void *oidc_test_authz_provider_get(void);

#endif // _MOD_AUTH_OPENIDC_TEST_UTIL_H_
