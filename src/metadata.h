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
 * Copyright (C) 2017-2024 ZmartZone Holding BV
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

#ifndef _MOD_AUTH_OPENIDC_METADATA_H_
#define _MOD_AUTH_OPENIDC_METADATA_H_

#include "cfg/cfg.h"
#include "cfg/provider.h"

apr_byte_t oidc_metadata_provider_get(request_rec *r, oidc_cfg_t *cfg, const char *issuer, json_t **j_provider,
				      apr_byte_t allow_discovery);
apr_byte_t oidc_metadata_provider_retrieve(request_rec *r, oidc_cfg_t *cfg, const char *issuer, const char *url,
					   json_t **j_metadata, char **response);
apr_byte_t oidc_metadata_provider_parse(request_rec *r, oidc_cfg_t *cfg, json_t *j_provider, oidc_provider_t *provider);
apr_byte_t oidc_metadata_provider_is_valid(request_rec *r, oidc_cfg_t *cfg, json_t *j_provider, const char *issuer);
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg_t *cfg, apr_array_header_t **arr);
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg_t *cfg, const char *selected, oidc_provider_t **provider,
			     apr_byte_t allow_discovery);
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg_t *cfg, const oidc_jwks_uri_t *jwks_uri,
				  int ssl_validate_server, json_t **j_jwks, apr_byte_t *refresh);
apr_byte_t oidc_oauth_metadata_provider_parse(request_rec *r, oidc_cfg_t *c, json_t *j_provider);

#endif /* _MOD_AUTH_OPENIDC_METADATA_H_ */
