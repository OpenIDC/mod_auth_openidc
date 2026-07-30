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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

/*
 * Tests for the server-lifetime half of mod_auth_openidc.c: the post_config hook and the
 * configuration completeness checks it runs over the server_rec chain.
 *
 * Those functions are static, so they are driven the way httpd drives them: the module's
 * register_hooks is called, the ap_hook_* stubs in stub.c record the function pointers, and the
 * tests call the recorded post_config against server_recs carrying deliberately broken configs.
 * That also exercises oidc_register_hooks itself.
 *
 * NB: post_config deliberately does nothing on its first invocation - httpd calls it twice and the
 *     module uses a process-pool userdata flag to skip the "sanity check" pass - so every test here
 *     calls it twice and asserts on the second.
 */

#include "cfg/cfg_int.h"
#include "cfg/dir.h"
#include "check_util.h"
#include "mod_auth_openidc.h"
#include "util.h"
#include "util/util.h"
#include <mod_auth.h>

/* one passphrase for all of them: oidc_config_ensure_crypto_passphrase runs a ~210,000-iteration
 * PBKDF2 per distinct secret, and its kdf_cache only spans a single post_config pass */
#define OIDC_TEST_PASSPHRASE "12345678901234567890123456789012"

/*
 * a bare server_rec sharing the fixture's process_rec, carrying a fresh (empty) module config
 */
static server_rec *oidc_test_server_create(apr_pool_t *pool, const server_rec *base) {
	server_rec *s = apr_pcalloc(pool, sizeof(server_rec));
	s->process = base->process;
	s->server_hostname = "www.example.com";
	s->module_config = apr_pcalloc(pool, sizeof(void *) * 1);
	oidc_cfg_t *cfg = oidc_cfg_server_create(pool, s);
	ap_set_module_config(s->module_config, &auth_openidc_module, cfg);
	cfg->crypto_passphrase.secret1 = OIDC_TEST_PASSPHRASE;
	return s;
}

static oidc_cfg_t *oidc_test_server_cfg(const server_rec *s) {
	return (oidc_cfg_t *)ap_get_module_config(s->module_config, &auth_openidc_module);
}

/* a cmd_parms aimed at one of the server_recs above, for the directive handlers that take one */
static cmd_parms *oidc_test_server_cmd(apr_pool_t *pool, server_rec *s, const char *primitive) {
	cmd_parms *cmd = apr_pcalloc(pool, sizeof(cmd_parms));
	cmd->server = s;
	cmd->pool = pool;
	cmd->temp_pool = pool;
	cmd->directive = apr_pcalloc(pool, sizeof(ap_directive_t));
	cmd->directive->directive = primitive;
	return cmd;
}

/*
 * a server_rec that would pass the OpenID Connect RP checks: the minimum of a statically
 * configured provider plus a redirect URI
 */
static server_rec *oidc_test_server_create_openidc(apr_pool_t *pool, const server_rec *base) {
	server_rec *s = oidc_test_server_create(pool, base);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);
	oidc_cfg_provider_issuer_set(pool, oidc_cfg_provider_get(cfg), "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(pool, oidc_cfg_provider_get(cfg),
							 "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(pool, oidc_cfg_provider_get(cfg), "client_id");
	cfg->redirect_uri = "https://www.example.com/protected/";
	return s;
}

/*
 * run the recorded post_config hook the way httpd would, i.e. twice, and return what the second
 * (real) pass reports
 */
static int oidc_test_post_config(apr_pool_t *pool, server_rec *s) {
	oidc_test_hook_post_config_fn post_config = NULL;
	auth_openidc_module.register_hooks(pool);
	post_config = oidc_test_hook_post_config_get();
	ck_assert_ptr_nonnull(post_config);
	/* the first pass only records that it ran */
	ck_assert_int_eq(post_config(pool, pool, pool, s), OK);
	return post_config(pool, pool, pool, s);
}

START_TEST(test_config_post_config_ok) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);

	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
}
END_TEST

START_TEST(test_config_post_config_runs_once) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);
	oidc_test_hook_post_config_fn post_config = NULL;

	auth_openidc_module.register_hooks(pool);
	post_config = oidc_test_hook_post_config_get();
	ck_assert_ptr_nonnull(post_config);

	/* the config is incomplete, but the first pass short-circuits before checking anything */
	oidc_cfg_provider_issuer_set(pool, oidc_cfg_provider_get(oidc_test_server_cfg(s)), "https://idp.example.com");
	ck_assert_int_eq(post_config(pool, pool, pool, s), OK);
	/* ... and the second does not */
	ck_assert_int_eq(post_config(pool, pool, pool, s), HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

/*
 * a server with no OIDC and no OAuth settings at all is left alone: neither role's completeness
 * check applies, so an unconfigured vhost still starts
 */
START_TEST(test_config_post_config_unconfigured_server) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);

	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
}
END_TEST

/* an unset crypto passphrase is auto-generated for a server that is the only one in play */
START_TEST(test_config_crypto_passphrase_autogenerated) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	cfg->crypto_passphrase.secret1 = NULL;
	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
	ck_assert_ptr_nonnull(oidc_cfg_crypto_passphrase_secret1_get(cfg));
}
END_TEST

START_TEST(test_config_openidc_missing_redirect_uri) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);

	oidc_test_server_cfg(s)->redirect_uri = NULL;
	ck_assert_int_eq(oidc_test_post_config(pool, s), HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

START_TEST(test_config_openidc_missing_client_id) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);

	oidc_cfg_provider_client_id_set(pool, oidc_cfg_provider_get(oidc_test_server_cfg(s)), NULL);
	ck_assert_int_eq(oidc_test_post_config(pool, s), HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

START_TEST(test_config_openidc_missing_authorization_endpoint) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	/* a statically configured provider needs its authorization endpoint; build one without it
	 * rather than clearing it, since the setters reject a NULL value */
	oidc_cfg_provider_issuer_set(pool, oidc_cfg_provider_get(cfg), "https://idp.example.com");
	oidc_cfg_provider_client_id_set(pool, oidc_cfg_provider_get(cfg), "client_id");
	cfg->redirect_uri = "https://www.example.com/protected/";
	ck_assert_int_eq(oidc_test_post_config(pool, s), HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

/* OIDCMetadataDir and OIDCProviderMetadataURL are mutually exclusive */
START_TEST(test_config_openidc_metadata_dir_and_url) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	cfg->metadata_dir = "/tmp";
	oidc_cfg_provider_metadata_url_set(pool, oidc_cfg_provider_get(cfg), "https://idp.example.com/.well-known");
	ck_assert_int_eq(oidc_test_post_config(pool, s), HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

/* with only OIDCMetadataDir the per-provider settings are not required */
START_TEST(test_config_openidc_metadata_dir_only) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	cfg->metadata_dir = "/tmp";
	cfg->redirect_uri = "https://www.example.com/protected/";
	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
}
END_TEST

/* a non-https OIDCProviderMetadataURL and a non-https OIDCRedirectURI are warnings, not errors */
START_TEST(test_config_openidc_insecure_urls_warn_only) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	oidc_cfg_provider_metadata_url_set(pool, oidc_cfg_provider_get(cfg), "http://idp.example.com/.well-known");
	oidc_cfg_provider_client_id_set(pool, oidc_cfg_provider_get(cfg), "client_id");
	cfg->redirect_uri = "http://www.example.com/protected/";
	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
}
END_TEST

/* a relative OIDCRedirectURI combined with OIDCCookieDomain warns but starts */
START_TEST(test_config_openidc_relative_redirect_uri_with_cookie_domain) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	cfg->redirect_uri = "/protected/";
	cfg->cookie_domain = "example.com";
	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
}
END_TEST

/* an OIDCCookieDomain that does not match the redirect URI host would break cookies: an error */
START_TEST(test_config_openidc_cookie_domain_mismatch) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	cfg->cookie_domain = "elsewhere.example.org";
	ck_assert_int_eq(oidc_test_post_config(pool, s), HTTP_INTERNAL_SERVER_ERROR);

	/* the matching one is accepted */
	cfg->cookie_domain = "example.com";
	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
}
END_TEST

/* DPoP needs a signing key; without one the server refuses to start */
START_TEST(test_config_openidc_dpop_without_signing_key) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	oidc_cfg_provider_dpop_mode_int_set(oidc_cfg_provider_get(cfg), OIDC_DPOP_MODE_REQUIRED);
	ck_assert_int_eq(oidc_test_post_config(pool, s), HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

/*
 * the OAuth 2.0 Resource Server checks; the role is only checked at all once one of its
 * directives is set
 */
START_TEST(test_config_oauth_no_verification_method) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	/* a client_id alone puts the RS role in scope but leaves it without any way to verify */
	ck_assert_ptr_null(
	    oidc_cmd_oauth_client_id_set(oidc_test_server_cmd(pool, s, OIDCOAuthClientID), NULL, "rs_client_id"));
	ck_assert_int_eq(oidc_test_post_config(pool, s), HTTP_INTERNAL_SERVER_ERROR);
	(void)cfg;
}
END_TEST

START_TEST(test_config_oauth_metadata_url_insecure_warns) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);
	ck_assert_ptr_null(
	    oidc_cmd_oauth_metadata_url_set(oidc_test_server_cmd(pool, s, OIDCOAuthServerMetadataURL), NULL,
					    "http://as.example.com/.well-known/oauth-authorization-server"));
	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
}
END_TEST

/* local JWT validation without OIDCOAuthVerifyAudience warns but starts */
START_TEST(test_config_oauth_local_validation_without_audience) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	ck_assert_ptr_null(oidc_cfg_oauth_verify_jwks_uri_set(pool, cfg, "https://as.example.com/jwks"));
	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);
}
END_TEST

/* introspection and local validation are mutually exclusive */
START_TEST(test_config_oauth_introspection_and_local_validation) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create(pool, r->server);
	oidc_cfg_t *cfg = oidc_test_server_cfg(s);

	ck_assert_ptr_null(
	    oidc_cfg_oauth_introspection_endpoint_url_set(pool, cfg, "https://as.example.com/introspect"));
	ck_assert_ptr_null(oidc_cfg_oauth_verify_jwks_uri_set(pool, cfg, "https://as.example.com/jwks"));
	ck_assert_int_eq(oidc_test_post_config(pool, s), HTTP_INTERNAL_SERVER_ERROR);

	/* introspection on its own is fine; a fresh server, since the setters reject a NULL value */
	server_rec *s2 = oidc_test_server_create(pool, r->server);
	ck_assert_ptr_null(oidc_cfg_oauth_introspection_endpoint_url_set(pool, oidc_test_server_cfg(s2),
									 "https://as.example.com/introspect"));
	ck_assert_int_eq(oidc_test_post_config(pool, s2), OK);
}
END_TEST

/*
 * the merged-vhost path: with at least one merged config in the chain every merged server is
 * checked in full, while the (never-merged) base server only has its passphrase settled
 */
START_TEST(test_config_merged_vhosts) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *base = oidc_test_server_create(pool, r->server);
	server_rec *vhost = oidc_test_server_create_openidc(pool, r->server);

	/* the base server is deliberately left without a passphrase of its own: a vhost sets one */
	oidc_test_server_cfg(base)->crypto_passphrase.secret1 = NULL;
	oidc_test_server_cfg(vhost)->merged = TRUE;
	base->next = vhost;

	ck_assert_int_eq(oidc_test_post_config(pool, base), OK);
	/* the base keeps starting up without one rather than silently gaining a generated one */
	ck_assert_ptr_null(oidc_cfg_crypto_passphrase_secret1_get(oidc_test_server_cfg(base)));
	ck_assert_ptr_nonnull(oidc_cfg_crypto_passphrase_secret1_get(oidc_test_server_cfg(vhost)));
}
END_TEST

/* a broken merged vhost fails the whole startup, not just its own config */
START_TEST(test_config_merged_vhosts_one_broken) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *base = oidc_test_server_create(pool, r->server);
	server_rec *vhost = oidc_test_server_create_openidc(pool, r->server);

	oidc_test_server_cfg(vhost)->merged = TRUE;
	oidc_test_server_cfg(vhost)->redirect_uri = NULL;
	base->next = vhost;

	ck_assert_int_eq(oidc_test_post_config(pool, base), HTTP_INTERNAL_SERVER_ERROR);
}
END_TEST

/* the child_init hook is registered and runs against a configured server */
START_TEST(test_config_child_init) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	server_rec *s = oidc_test_server_create_openidc(pool, r->server);
	oidc_test_hook_child_init_fn child_init = NULL;

	ck_assert_int_eq(oidc_test_post_config(pool, s), OK);

	child_init = oidc_test_hook_child_init_get();
	ck_assert_ptr_nonnull(child_init);
	child_init(pool, s);
}
END_TEST

/*
 * the input filter that replays the POST parameters preserved across an authentication round trip:
 * oidc_filter_in_insert_filter decides whether to insert it, oidc_filter_in_filter appends the
 * captured parameters to the request body when it sees the end of the stream
 */

/* the filter is only inserted for a request that actually has preserved POST parameters */
START_TEST(test_config_insert_filter) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	oidc_test_hook_insert_filter_fn insert_filter = NULL;
	apr_table_t *params = NULL;

	auth_openidc_module.register_hooks(pool);
	insert_filter = oidc_test_hook_insert_filter_get();
	ck_assert_ptr_nonnull(insert_filter);

	/* nothing preserved: no filter */
	oidc_test_added_input_filter_reset();
	insert_filter(r);
	ck_assert_ptr_null(oidc_test_added_input_filter_get());

	/* with preserved parameters the filter goes in */
	params = apr_table_make(r->pool, 1);
	apr_table_set(params, "foo", "bar");
	apr_pool_userdata_set(params, OIDC_USERDATA_POST_PARAMS_KEY, NULL, r->pool);
	insert_filter(r);
	ck_assert_ptr_nonnull(oidc_test_added_input_filter_get());

	/* ... but never for a sub-request */
	oidc_test_added_input_filter_reset();
	r->main = r;
	insert_filter(r);
	ck_assert_ptr_null(oidc_test_added_input_filter_get());
	r->main = NULL;

	/* ... nor when the module is not enabled for the request at all */
	oidc_test_set_auth_type("none");
	insert_filter(r);
	ck_assert_ptr_null(oidc_test_added_input_filter_get());
	oidc_test_set_auth_type(NULL);
}
END_TEST

/* the filter appends the preserved parameters to the body and fixes up Content-Length */
START_TEST(test_config_input_filter_appends_post_params) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	oidc_test_input_filter_fn filter = NULL;
	apr_table_t *params = apr_table_make(r->pool, 1);
	ap_filter_t f;
	apr_bucket_brigade *bb = NULL;
	char *body = NULL;
	apr_size_t len = 0;

	auth_openidc_module.register_hooks(pool);
	filter = oidc_test_input_filter_get();
	ck_assert_ptr_nonnull(filter);

	apr_table_set(params, "foo", "bar");
	apr_pool_userdata_set(params, OIDC_USERDATA_POST_PARAMS_KEY, NULL, r->pool);
	oidc_http_hdr_in_set(r, OIDC_HTTP_HDR_CONTENT_LENGTH, "3");

	_oidc_memset(&f, 0, sizeof(f));
	f.r = r;
	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	oidc_test_brigade_prime("a=b", APR_SUCCESS);

	ck_assert_int_eq(filter(&f, bb, AP_MODE_READBYTES, APR_BLOCK_READ, 8192), APR_SUCCESS);

	ck_assert_int_eq(apr_brigade_pflatten(bb, &body, &len, r->pool), APR_SUCCESS);
	ck_assert_str_eq(apr_pstrmemdup(r->pool, body, len), "a=b&foo=bar");
	/* the recomputed Content-Length covers the original body plus what was appended */
	ck_assert_str_eq(oidc_http_hdr_in_content_length_get(r), "11");

	/* the preserved parameters are consumed, so a second pass appends nothing */
	ck_assert_ptr_null(oidc_test_added_input_filter_get());
}
END_TEST

/* an error from the next filter in the chain is passed straight back */
START_TEST(test_config_input_filter_propagates_error) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	oidc_test_input_filter_fn filter = NULL;
	ap_filter_t f;
	apr_bucket_brigade *bb = NULL;

	auth_openidc_module.register_hooks(pool);
	filter = oidc_test_input_filter_get();
	ck_assert_ptr_nonnull(filter);

	_oidc_memset(&f, 0, sizeof(f));
	f.r = r;
	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	oidc_test_brigade_prime(NULL, APR_EGENERAL);

	ck_assert_int_eq(filter(&f, bb, AP_MODE_READBYTES, APR_BLOCK_READ, 8192), APR_EGENERAL);
}
END_TEST

/* AP_MODE_EATCRLF returns immediately, without touching the brigade */
START_TEST(test_config_input_filter_eatcrlf) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	oidc_test_input_filter_fn filter = NULL;
	ap_filter_t f;
	apr_bucket_brigade *bb = NULL;

	auth_openidc_module.register_hooks(pool);
	filter = oidc_test_input_filter_get();
	ck_assert_ptr_nonnull(filter);

	_oidc_memset(&f, 0, sizeof(f));
	f.r = r;
	bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	oidc_test_brigade_prime(NULL, APR_SUCCESS);

	ck_assert_int_eq(filter(&f, bb, AP_MODE_EATCRLF, APR_BLOCK_READ, 8192), APR_SUCCESS);
	ck_assert(APR_BRIGADE_EMPTY(bb));
}
END_TEST

/*
 * the "Require claim ..." line is parsed once at config time into an ap_expr; a syntactically
 * invalid expression is reported back to httpd as a configuration error
 */
START_TEST(test_config_parse_require_line) {
	apr_pool_t *pool = oidc_test_pool_get();
	request_rec *r = oidc_test_request_get();
	const authz_provider *provider = NULL;
	const void *parsed = NULL;
	cmd_parms *cmd = NULL;

	auth_openidc_module.register_hooks(pool);
	provider = (const authz_provider *)oidc_test_authz_provider_get();
	ck_assert_ptr_nonnull(provider);
	ck_assert_ptr_nonnull(provider->parse_require_line);

	cmd = oidc_test_server_cmd(pool, r->server, "Require");
	ck_assert_ptr_null(provider->parse_require_line(cmd, "sub:someone", &parsed));
	ck_assert_ptr_nonnull(parsed);

	/* the stubbed ap_expr parser rejects "#" */
	parsed = NULL;
	ck_assert_ptr_nonnull(provider->parse_require_line(cmd, "#", &parsed));
}
END_TEST

int main(void) {
	TCase *c = tcase_create("config");
	tcase_add_checked_fixture(c, oidc_test_setup, oidc_test_teardown);
	tcase_set_timeout(c, 60);

	tcase_add_test(c, test_config_post_config_ok);
	tcase_add_test(c, test_config_post_config_runs_once);
	tcase_add_test(c, test_config_post_config_unconfigured_server);
	tcase_add_test(c, test_config_crypto_passphrase_autogenerated);
	tcase_add_test(c, test_config_openidc_missing_redirect_uri);
	tcase_add_test(c, test_config_openidc_missing_client_id);
	tcase_add_test(c, test_config_openidc_missing_authorization_endpoint);
	tcase_add_test(c, test_config_openidc_metadata_dir_and_url);
	tcase_add_test(c, test_config_openidc_metadata_dir_only);
	tcase_add_test(c, test_config_openidc_insecure_urls_warn_only);
	tcase_add_test(c, test_config_openidc_relative_redirect_uri_with_cookie_domain);
	tcase_add_test(c, test_config_openidc_cookie_domain_mismatch);
	tcase_add_test(c, test_config_openidc_dpop_without_signing_key);
	tcase_add_test(c, test_config_oauth_no_verification_method);
	tcase_add_test(c, test_config_oauth_metadata_url_insecure_warns);
	tcase_add_test(c, test_config_oauth_local_validation_without_audience);
	tcase_add_test(c, test_config_oauth_introspection_and_local_validation);
	tcase_add_test(c, test_config_merged_vhosts);
	tcase_add_test(c, test_config_merged_vhosts_one_broken);
	tcase_add_test(c, test_config_child_init);
	tcase_add_test(c, test_config_insert_filter);
	tcase_add_test(c, test_config_input_filter_appends_post_params);
	tcase_add_test(c, test_config_input_filter_propagates_error);
	tcase_add_test(c, test_config_input_filter_eatcrlf);
	tcase_add_test(c, test_config_parse_require_line);

	Suite *s = suite_create("config");
	suite_add_tcase(s, c);

	return oidc_test_suite_run(s);
}
