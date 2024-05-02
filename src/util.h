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

#ifndef _MOD_AUTH_OPENIDC_UTIL_H_
#define _MOD_AUTH_OPENIDC_UTIL_H_

#include "cfg/cfg.h"
#include "cfg/dir.h"
#include "jose.h"

apr_byte_t oidc_util_generate_random_string(request_rec *r, char **output, int len);
apr_byte_t oidc_util_jwt_create(request_rec *r, const oidc_crypto_passphrase_t *passphrase, const char *s_payload,
				char **compact_encoded_jwt);
apr_byte_t oidc_util_jwt_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
				const char *compact_encoded_jwt, char **s_payload);
apr_byte_t oidc_util_hash_string_and_base64url_encode(request_rec *r, const char *openssl_hash_algo, const char *input,
						      char **output);
apr_byte_t oidc_util_create_symmetric_key(request_rec *r, const char *client_secret, unsigned int r_key_len,
					  const char *hash_algo, apr_byte_t set_kid, oidc_jwk_t **jwk);
char *oidc_util_encode_json_object(request_rec *r, json_t *json, size_t flags);
apr_byte_t oidc_util_decode_json_object(request_rec *r, const char *str, json_t **json);
apr_byte_t oidc_util_random_bytes(unsigned char *buf, apr_size_t length);
apr_byte_t oidc_util_generate_random_bytes(request_rec *r, unsigned char *buf, apr_size_t length);
apr_byte_t oidc_util_generate_random_hex_string(request_rec *r, char **hex_str, int byte_len);
int oidc_util_strnenvcmp(const char *a, const char *b, int len);
char *oidc_util_base64_decode(apr_pool_t *pool, const char *input, char **output, int *output_len);
int oidc_util_base64url_encode(request_rec *r, char **dst, const char *src, int src_len, int remove_padding);
int oidc_util_base64url_decode(apr_pool_t *pool, char **dst, const char *src);
const char *oidc_util_current_url_host(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers);
apr_byte_t oidc_util_request_matches_url(request_rec *r, const char *url);
char *oidc_util_current_url(request_rec *r, oidc_hdr_x_forwarded_t x_forwarded_headers);
const char *oidc_util_absolute_url(request_rec *r, oidc_cfg_t *cfg, const char *url);
const char *oidc_util_redirect_uri(request_rec *r, oidc_cfg_t *c);
const char *oidc_util_redirect_uri_iss(request_rec *r, oidc_cfg_t *c, oidc_provider_t *provider);
apr_byte_t oidc_util_request_is_secure(request_rec *r, oidc_cfg_t *c);
char *oidc_util_openssl_version(apr_pool_t *pool);
apr_byte_t oidc_util_request_matches_url(request_rec *r, const char *url);
apr_byte_t oidc_util_decode_json_and_check_error(request_rec *r, const char *str, json_t **json);
int oidc_util_html_send(request_rec *r, const char *title, const char *html_head, const char *on_load,
			const char *html_body, int status_code);
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, apr_pool_t *pool, char **result);
apr_byte_t oidc_util_file_write(request_rec *r, const char *path, const char *data);
apr_byte_t oidc_util_issuer_match(const char *a, const char *b);
int oidc_util_html_send_error(request_rec *r, const char *html_template, const char *error, const char *description,
			      int status_code);
apr_byte_t oidc_util_json_array_has_value(request_rec *r, json_t *haystack, const char *needle);
void oidc_util_set_app_info(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix,
			    oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding);
void oidc_util_set_app_infos(request_rec *r, json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter,
			     oidc_appinfo_pass_in_t pass_in, oidc_appinfo_encoding_t encoding);
apr_hash_t *oidc_util_spaced_string_to_hashtable(apr_pool_t *pool, const char *str);
apr_byte_t oidc_util_spaced_string_equals(apr_pool_t *pool, const char *a, const char *b);
apr_byte_t oidc_util_spaced_string_contains(apr_pool_t *pool, const char *str, const char *match);
apr_byte_t oidc_util_json_object_get_string(apr_pool_t *pool, json_t *json, const char *name, char **value,
					    const char *default_value);
apr_byte_t oidc_util_json_object_get_int(const json_t *json, const char *name, int *value, const int default_value);
apr_byte_t oidc_util_json_object_get_bool(const json_t *json, const char *name, int *value, const int default_value);
char *oidc_util_html_escape(apr_pool_t *pool, const char *input);
char *oidc_util_javascript_escape(apr_pool_t *pool, const char *input);
void oidc_util_table_add_query_encoded_params(apr_pool_t *pool, apr_table_t *table, const char *params);
apr_hash_t *oidc_util_merge_key_sets(apr_pool_t *pool, apr_hash_t *k1, const apr_array_header_t *k2);
apr_hash_t *oidc_util_merge_key_sets_hash(apr_pool_t *pool, apr_hash_t *k1, apr_hash_t *k2);
apr_byte_t oidc_util_regexp_substitute(apr_pool_t *pool, const char *input, const char *regexp, const char *replace,
				       char **output, char **error_str);
apr_byte_t oidc_util_regexp_first_match(apr_pool_t *pool, const char *input, const char *regexp, char **output,
					char **error_str);
apr_byte_t oidc_util_json_merge(request_rec *r, json_t *src, json_t *dst);
apr_byte_t oidc_util_cookie_domain_valid(const char *hostname, const char *cookie_domain);
apr_hash_t *oidc_util_merge_symmetric_key(apr_pool_t *pool, const apr_array_header_t *keys, oidc_jwk_t *jwk);
const char *oidc_util_strcasestr(const char *s1, const char *s2);
oidc_jwk_t *oidc_util_key_list_first(const apr_array_header_t *key_list, int kty, const char *use);
const char *oidc_util_jq_filter(request_rec *r, const char *input, const char *filter);
void oidc_util_set_trace_parent(request_rec *r, oidc_cfg_t *c, const char *span);
void oidc_util_apr_hash_clear(apr_hash_t *ht);
apr_byte_t oidc_util_html_send_in_template(request_rec *r, const char *filename, char **static_template_content,
					   const char *arg1, int arg1_esc, const char *arg2, int arg2_esc,
					   int status_code);
char *oidc_util_apr_expr_parse(cmd_parms *cmd, const char *str, oidc_apr_expr_t **expr, apr_byte_t result_is_str);
const char *oidc_util_apr_expr_exec(request_rec *r, const oidc_apr_expr_t *expr, apr_byte_t result_is_str);

#endif /* _MOD_AUTH_OPENIDC_UTIL_H_ */
