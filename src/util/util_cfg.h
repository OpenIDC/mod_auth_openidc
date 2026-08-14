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

#ifndef _MOD_AUTH_OPENIDC_UTIL_CFG_H_
#define _MOD_AUTH_OPENIDC_UTIL_CFG_H_

/* Configuration-dependent utilities, split out to keep cfg headers out of util/util.h. */

#include "cfg/cfg.h"
#include "cfg/dir.h"
#include "util/util.h"

// appinfo.c
void oidc_util_appinfo_set(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix,
			   oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding);
void oidc_util_appinfo_set_all(request_rec *r, oidc_json_t *j_attrs, const char *claim_prefix,
			       const char *claim_delimiter, oidc_appinfo_pass_in_t pass_in,
			       oidc_appinfo_encoding_t encoding);

// util.c
/* redact a secret/token for the debug log, unless OIDCDebugMaskSecrets is Off for this server.
 * Config-dependent, hence declared here rather than in the config-free util.h */
const char *oidc_util_mask_value(request_rec *r, const char *value);
/* whether secrets are to be masked in the log for this request's server */
apr_byte_t oidc_util_log_mask_secrets(request_rec *r);

// expr.c
char *oidc_util_apr_expr_parse(cmd_parms *cmd, const char *str, oidc_apr_expr_t **expr,
			       oidc_apr_expr_result_t result_type);
const char *oidc_util_apr_expr_exec(request_rec *r, const oidc_apr_expr_t *expr, oidc_apr_expr_result_t result_type);

// jwt.c
apr_byte_t oidc_util_jwt_create(request_rec *r, const oidc_crypto_passphrase_t *passphrase, const char *s_payload,
				char **compact_encoded_jwt);
apr_byte_t oidc_util_jwt_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
				const char *compact_encoded_jwt, char **s_payload);

// url.c
const char *oidc_util_url_cur_host(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers);
char *oidc_util_url_cur(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers);
apr_byte_t oidc_util_url_cur_is_secure(const request_rec *r, const oidc_cfg_t *c);
const char *oidc_util_url_abs(request_rec *r, const oidc_cfg_t *cfg, const char *url);
const char *oidc_util_url_redirect_uri(request_rec *r, const oidc_cfg_t *c);
apr_byte_t oidc_util_url_matches_redirect_uri(request_rec *r, const oidc_cfg_t *cfg);

// util.c
void oidc_util_set_trace_parent(request_rec *r, const oidc_cfg_t *c, const char *span);

#endif // _MOD_AUTH_OPENIDC_UTIL_CFG_H_
