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

#ifndef _MOD_AUTH_OPENIDC_CFG_PARSE_H_
#define _MOD_AUTH_OPENIDC_CFG_PARSE_H_

#include "cfg/cfg.h"

typedef struct oidc_cfg_option_t {
	int val;
	char *str;
} oidc_cfg_option_t;

char *oidc_cfg_parse_option(apr_pool_t *pool, const oidc_cfg_option_t options[], int n, const char *arg, int *v);
char *oidc_cfg_parse_option_ignore_case(apr_pool_t *pool, const oidc_cfg_option_t options[], int n, const char *arg,
					int *v);
char *oidc_cfg_parse_options_flatten(apr_pool_t *pool, const oidc_cfg_option_t options[], int n);

char *oidc_cfg_parse_flatten_options(apr_pool_t *pool, const char *options[]);
const char *oidc_cfg_parse_is_valid_option(apr_pool_t *pool, const char *arg, const char *options[]);
const char *oidc_cfg_parse_is_valid_int(apr_pool_t *pool, int value, int min_value, int max_value);
const char *oidc_cfg_parse_is_valid_url(apr_pool_t *pool, const char *arg, const char *scheme);
const char *oidc_cfg_parse_is_valid_http_url(apr_pool_t *pool, const char *arg);
const char *oidc_cfg_parse_is_valid_response_type(apr_pool_t *pool, const char *arg);
const char *oidc_cfg_parse_is_valid_response_mode(apr_pool_t *pool, const char *arg);
const char *oidc_cfg_parse_is_valid_signed_response_alg(apr_pool_t *pool, const char *arg);
const char *oidc_cfg_parse_is_valid_encrypted_response_alg(apr_pool_t *pool, const char *arg);
const char *oidc_cfg_parse_is_valid_encrypted_response_enc(apr_pool_t *pool, const char *arg);

const char *oidc_cfg_parse_boolean(apr_pool_t *pool, const char *arg, int *bool_value);
const char *oidc_cfg_parse_int(apr_pool_t *pool, const char *arg, int *int_value);
const char *oidc_cfg_parse_int_min_max(apr_pool_t *pool, const char *arg, int *int_value, int min_value, int max_value);
const char *oidc_cfg_parse_timeout_min_max(apr_pool_t *pool, const char *arg, apr_interval_time_t *timeout_value,
					   apr_interval_time_t min_value, apr_interval_time_t max_value);
const char *oidc_cfg_parse_dirname(apr_pool_t *pool, const char *arg, char **value);
const char *oidc_cfg_parse_filename(apr_pool_t *pool, const char *arg, char **value);
const char *oidc_cfg_parse_relative_or_absolute_url(apr_pool_t *pool, const char *arg, char **value);
const char *oidc_cfg_parse_key_record(apr_pool_t *pool, const char *tuple, char **kid, char **key, int *key_len,
				      char **use, apr_byte_t triplet);
const char *oidc_cfg_parse_action_on_error_refresh_as(apr_pool_t *pool, const char *arg,
						      oidc_on_error_action_t *action);
const char *oidc_cfg_parse_passphrase(apr_pool_t *pool, const char *arg, char **passphrase);
const char *oidc_cfg_parse_public_key_files(apr_pool_t *pool, const char *arg, apr_array_header_t **keys);

typedef const char *(*oidc_valid_function_t)(apr_pool_t *, const char *);

oidc_valid_function_t oidc_cfg_get_valid_endpoint_auth_function(oidc_cfg_t *cfg);
const char *oidc_parse_remote_user_claim(apr_pool_t *pool, const char *v1, const char *v2, const char *v3,
					 oidc_remote_user_claim_t *remote_user_claim);
const char *oidc_cfg_parse_http_timeout(apr_pool_t *pool, const char *arg1, const char *arg2, const char *arg3,
					oidc_http_timeout_t *http_timeout);

#endif // _MOD_AUTH_OPENIDC_CFG_PARSE_H_
