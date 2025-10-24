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

#ifndef _MOD_AUTH_OPENIDC_UTIL_H_
#define _MOD_AUTH_OPENIDC_UTIL_H_

#include "cfg/cfg.h"
#include "cfg/dir.h"
#include "jose.h"

// appinfo.c
void oidc_util_appinfo_set(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix,
			   oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding);
void oidc_util_appinfo_set_all(request_rec *r, json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter,
			       oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding);

// base64.c
char *oidc_util_base64_decode(apr_pool_t *pool, const char *input, char **output, int *output_len);
int oidc_util_base64url_encode(request_rec *r, char **dst, const char *src, int src_len, int remove_padding);
int oidc_util_base64url_decode(apr_pool_t *pool, char **dst, const char *src);

// expr.c
apr_byte_t oidc_util_regexp_substitute(apr_pool_t *pool, const char *input, const char *regexp, const char *replace,
				       char **output, char **error_str);
apr_byte_t oidc_util_regexp_first_match(apr_pool_t *pool, const char *input, const char *regexp, char **output,
					char **error_str);
char *oidc_util_apr_expr_parse(cmd_parms *cmd, const char *str, oidc_apr_expr_t **expr, apr_byte_t result_is_str);
const char *oidc_util_apr_expr_exec(request_rec *r, const oidc_apr_expr_t *expr, apr_byte_t result_is_str);

// file.c
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, apr_pool_t *pool, char **result);
apr_byte_t oidc_util_file_write(request_rec *r, const char *path, const char *data);

// html.c
int oidc_util_html_send(request_rec *r, const char *title, const char *html_head, const char *on_load,
			const char *html_body, int status_code);
int oidc_util_html_content_prep(request_rec *r, const char *request_state_key, const char *title, const char *html_head,
				const char *on_load, const char *html_body);
int oidc_util_html_content_send(request_rec *r);
int oidc_util_html_send_error(request_rec *r, const char *error, const char *description, int status_code);
char *oidc_util_html_escape(apr_pool_t *pool, const char *input);
char *oidc_util_html_javascript_escape(apr_pool_t *pool, const char *input);
int oidc_util_html_send_in_template(request_rec *r, const char *filename, char **static_template_content,
				    const char *arg1, int arg1_esc, const char *arg2, int arg2_esc);

// jq.c
const char *oidc_util_jq_filter(request_rec *r, const char *input, const char *filter);

// json.c
char *oidc_util_json_encode(apr_pool_t *pool, json_t *json, size_t flags);
apr_byte_t oidc_util_json_decode_object_err(request_rec *r, const char *str, json_t **json, apr_byte_t log_err);
apr_byte_t oidc_util_json_decode_object(request_rec *r, const char *str, json_t **json);
apr_byte_t oidc_util_json_check_error(request_rec *r, json_t *json);
apr_byte_t oidc_util_json_decode_and_check_error(request_rec *r, const char *str, json_t **json);
apr_byte_t oidc_util_json_object_get_string(apr_pool_t *pool, json_t *json, const char *name, char **value,
					    const char *default_value);
apr_byte_t oidc_util_json_object_get_string_array(apr_pool_t *pool, json_t *json, const char *name,
						  apr_array_header_t **value, const apr_array_header_t *default_value);
apr_byte_t oidc_util_json_object_get_int(const json_t *json, const char *name, int *value, const int default_value);
apr_byte_t oidc_util_json_object_get_bool(const json_t *json, const char *name, int *value, const int default_value);
apr_byte_t oidc_util_json_merge(request_rec *r, json_t *src, json_t *dst);
apr_byte_t oidc_util_json_array_has_value(request_rec *r, json_t *haystack, const char *needle);

// jwt.c
apr_byte_t oidc_util_jwt_create(request_rec *r, const oidc_crypto_passphrase_t *passphrase, const char *s_payload,
				char **compact_encoded_jwt);
apr_byte_t oidc_util_jwt_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
				const char *compact_encoded_jwt, char **s_payload);

// key.c
apr_byte_t oidc_util_key_symmetric_create(request_rec *r, const char *client_secret, unsigned int r_key_len,
					  const char *hash_algo, apr_byte_t set_kid, oidc_jwk_t **jwk);
apr_hash_t *oidc_util_key_sets_merge(apr_pool_t *pool, apr_hash_t *k1, const apr_array_header_t *k2);
apr_hash_t *oidc_util_key_sets_hash_merge(apr_pool_t *pool, apr_hash_t *k1, apr_hash_t *k2);
apr_hash_t *oidc_util_key_symmetric_merge(apr_pool_t *pool, const apr_array_header_t *keys, oidc_jwk_t *jwk);
oidc_jwk_t *oidc_util_key_list_first(const apr_array_header_t *key_list, int kty, const char *use);

// random.c
unsigned int oidc_util_rand_int(unsigned int mod);
apr_byte_t oidc_util_rand_str(request_rec *r, char **output, int byte_len, apr_byte_t to_hex);

// url.c
const char *oidc_util_url_cur_host(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers);
char *oidc_util_url_cur(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers);
apr_byte_t oidc_util_url_cur_is_secure(request_rec *r, oidc_cfg_t *c);
apr_byte_t oidc_util_url_cur_matches(request_rec *r, const char *url);
const char *oidc_util_url_abs(request_rec *r, oidc_cfg_t *cfg, const char *url);
const char *oidc_util_url_redirect_uri(request_rec *r, oidc_cfg_t *c);
apr_byte_t oidc_util_url_has_parameter(request_rec *r, const char *param);
apr_byte_t oidc_util_url_parameter_get(request_rec *r, char *name, char **value);

// util.c
char *oidc_util_hex_encode(request_rec *r, const unsigned char *bytes, unsigned int len);
apr_byte_t oidc_util_hash_string_and_base64url_encode(request_rec *r, const char *openssl_hash_algo, const char *input,
						      char **output);
int oidc_util_strnenvcmp(const char *a, const char *b, int len);
char *oidc_util_openssl_version(apr_pool_t *pool);
apr_byte_t oidc_util_issuer_match(const char *a, const char *b);
apr_hash_t *oidc_util_spaced_string_to_hashtable(apr_pool_t *pool, const char *str);
apr_byte_t oidc_util_spaced_string_equals(apr_pool_t *pool, const char *a, const char *b);
apr_byte_t oidc_util_spaced_string_contains(apr_pool_t *pool, const char *str, const char *match);
void oidc_util_table_add_query_encoded_params(apr_pool_t *pool, apr_table_t *table, const char *params);
apr_byte_t oidc_util_cookie_domain_valid(const char *hostname, const char *cookie_domain);
const char *oidc_util_strcasestr(const char *s1, const char *s2);
void oidc_util_set_trace_parent(request_rec *r, oidc_cfg_t *c, const char *span);
void oidc_util_apr_hash_clear(apr_hash_t *ht);

#endif /* _MOD_AUTH_OPENIDC_UTIL_H_ */
