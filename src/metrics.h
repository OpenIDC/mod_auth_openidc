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
 * Copyright (C) 2017-2023 ZmartZone Holding BV
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

#ifndef MOD_AUTH_OPENIDC_METRICS_H_
#define MOD_AUTH_OPENIDC_METRICS_H_

apr_byte_t oidc_metrics_cache_post_config(server_rec *s);
apr_status_t oidc_metrics_cache_child_init(apr_pool_t *p, server_rec *s);
apr_status_t oidc_metrics_cache_cleanup(server_rec *s);
int oidc_metrics_handle_request(request_rec *r);
void oidc_metrics_counter_add(request_rec *r, const char *metric_name, const char *label_name, const char *label_value,
			      const char *desc);
void oidc_metrics_timing_add(request_rec *r, const char *key, apr_time_t elapsed, const char *desc);

#define OIDC_METRICS_TIMING_START(r, cfg)                                                                              \
	apr_time_t _oidc_metrics_tstart;                                                                               \
	if (cfg->metrics_hook_data != NULL)                                                                            \
		_oidc_metrics_tstart = apr_time_now();

#define OIDC_METRICS_TIMING_ADD(r, cfg, main_key, sub_key, desc)                                                       \
	if (cfg->metrics_hook_data != NULL)                                                                            \
		if (apr_hash_get(cfg->metrics_hook_data, main_key, APR_HASH_KEY_STRING) != NULL) {                     \
			oidc_metrics_timing_add(r, apr_psprintf(r->pool, "%s.%s", main_key, sub_key),                  \
						apr_time_now() - _oidc_metrics_tstart, desc);                          \
		}

#define OIDC_METRICS_COUNTER_ADD(r, cfg, metric_name, label_name, label_value, desc)                                   \
	if (cfg->metrics_hook_data != NULL)                                                                            \
		if (apr_hash_get(cfg->metrics_hook_data, metric_name, APR_HASH_KEY_STRING) != NULL)                    \
			oidc_metrics_counter_add(r, metric_name, label_name, label_value, desc);

#endif /* MOD_AUTH_OPENIDC_METRICS_H_ */
