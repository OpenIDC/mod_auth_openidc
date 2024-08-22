/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include "mod_auth_openidc.h"

#include <oauth2/apache.h>
#include <oauth2/cfg.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>
#include <oauth2/openidc.h>
#include <oauth2/proto.h>
#include <oauth2/session.h>
#include <oauth2/util.h>

#include <httpd.h>

#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_request.h>

#include <apr_strings.h>

OAUTH2_APACHE_LOG(auth_openidc)

typedef struct openidc_cfg_dir_t {
	oauth2_cfg_openidc_t *openidc;
	oauth2_cfg_target_pass_t *target_pass;
} openidc_cfg_dir_t;

static apr_status_t openidc_cfg_dir_cleanup(void *data)
{
	openidc_cfg_dir_t *cfg = (openidc_cfg_dir_t *)data;
	oauth2_cfg_openidc_free(NULL, cfg->openidc);
	oauth2_cfg_target_pass_free(NULL, cfg->target_pass);
	oauth2_mem_free(cfg);
	return APR_SUCCESS;
}

static void *openidc_cfg_dir_create(apr_pool_t *pool, char *path)
{
	openidc_cfg_dir_t *cfg = oauth2_mem_alloc(sizeof(openidc_cfg_dir_t));
	oauth2_cfg_openidc_free(NULL, cfg->openidc);
	cfg->openidc = oauth2_cfg_openidc_init(NULL);
	cfg->target_pass = oauth2_cfg_target_pass_init(NULL);
	apr_pool_cleanup_register(pool, cfg, openidc_cfg_dir_cleanup,
				  openidc_cfg_dir_cleanup);
	return cfg;
}

static void *openidc_cfg_dir_merge(apr_pool_t *pool, void *b, void *a)
{
	openidc_cfg_dir_t *cfg = openidc_cfg_dir_create(pool, NULL);
	openidc_cfg_dir_t *base = b;
	openidc_cfg_dir_t *add = a;
	oauth2_cfg_openidc_merge(NULL, cfg->openidc, base->openidc,
				 add->openidc);
	oauth2_cfg_target_pass_merge(NULL, cfg->target_pass, base->target_pass,
				     add->target_pass);
	return cfg;
}

OAUTH2_APACHE_HANDLERS(auth_openidc)

OAUTH2_APACHE_CMD_ARGS1(auth_openidc, openidc_cfg_dir_t, passphrase,
			oauth2_crypto_passphrase_set, NULL)
OAUTH2_APACHE_CMD_ARGS2(auth_openidc, openidc_cfg_dir_t, cache,
			oauth2_cfg_set_cache, NULL)
OAUTH2_APACHE_CMD_ARGS2(auth_openidc, openidc_cfg_dir_t, session,
			oauth2_cfg_session_set_options, NULL)
OAUTH2_APACHE_CMD_ARGS3(auth_openidc, openidc_cfg_dir_t, provider,
			oauth2_cfg_openidc_provider_resolver_set_options,
			cfg->openidc)
OAUTH2_APACHE_CMD_ARGS3(auth_openidc, openidc_cfg_dir_t, client,
			oauth2_openidc_client_set_options, cfg->openidc)
OAUTH2_APACHE_CMD_ARGS1(auth_openidc, openidc_cfg_dir_t, config,
			oauth2_cfg_openidc_set_options, cfg->openidc)
OAUTH2_APACHE_CMD_ARGS1(auth_openidc, openidc_cfg_dir_t, target_pass,
			oauth2_cfg_set_target_pass_options, cfg->target_pass)

// clang-format off

static const command_rec OAUTH2_APACHE_COMMANDS(auth_openidc)[] = {

	OAUTH2_APACHE_CMD_ARGS(auth_openidc, 1,
		"OpenIDCCryptoPassphrase",
		passphrase,
		"Set crypto passphrase."),

	OAUTH2_APACHE_CMD_ARGS(auth_openidc, 12,
		"OpenIDCCache",
		cache,
		"Set cache backend and options."),

	OAUTH2_APACHE_CMD_ARGS(auth_openidc, 12,
		"OpenIDCSession",
		session,
		"Set session backend and options."),

	OAUTH2_APACHE_CMD_ARGS(auth_openidc, 23,
		"OpenIDCProvider",
		provider,
		"Configures a resolver for OpenID Connect Provider configuration data."),

	OAUTH2_APACHE_CMD_ARGS(auth_openidc, 23,
		"OpenIDCClient",
		client,
		"Set client configuration."),

	OAUTH2_APACHE_CMD_ARGS(auth_openidc, 1,
		"OpenIDCConfig",
		config,
		"Set OpenID Connect configuration."),

	OAUTH2_APACHE_CMD_ARGS(auth_openidc, 1,
		"OpenIDCTargetPass",
		target_pass,
		"Configures in which format claims are passed to the target application."),

	{ NULL }
};

// clang-format on

static int openidc_request_handler(oauth2_cfg_openidc_t *cfg,
				   oauth2_cfg_target_pass_t *target_pass,
				   oauth2_apache_request_ctx_t *ctx)
{
	int rv = DECLINED;
	bool rc = false;
	oauth2_http_response_t *response = NULL;
	json_t *claims = NULL;
	char *s_claims = NULL;

	oauth2_debug(ctx->log, "enter");

	oauth2_apache_scrub_headers(ctx, target_pass);

	rc = oauth2_openidc_handle(ctx->log, cfg, ctx->request, &response,
				   &claims);
	if (rc == false) {
		rv = HTTP_INTERNAL_SERVER_ERROR;
		goto end;
	}

	rv = oauth2_http_response_status_code_get(ctx->log, response);
	// TODO: HTTP_OK = 200?

	if (oauth2_apache_http_response_set(ctx->log, response, ctx->r) ==
	    false) {
		rv = HTTP_INTERNAL_SERVER_ERROR;
		goto end;
	}

	//	if (oauth2_apache_http_response_status_code_get() == 200)
	//		rv = OK;

	s_claims = oauth2_json_encode(ctx->log, claims, 0);
	oauth2_debug(ctx->log, "claims: %s", s_claims);

	if (claims) {
		// TODO:
		ctx->r->user = apr_pstrdup(
		    ctx->r->pool,
		    json_string_value(json_object_get(claims, "sub")));
		if (ctx->r->user == NULL)
			ctx->r->user = apr_pstrdup(ctx->r->pool, "(dummy)");
		oauth2_debug(ctx->log, "r->user: %s",
			     ctx->r->user ? ctx->r->user : "(null)");
		oauth2_apache_target_pass(ctx, target_pass, NULL, claims);
		rv = OK;
	}

end:

	if (s_claims)
		oauth2_mem_free(s_claims);
	if (claims)
		json_decref(claims);
	if (response)
		oauth2_http_response_free(ctx->log, response);

	return rv;
}

static int openidc_check_user_id_handler(request_rec *r)
{
	openidc_cfg_dir_t *cfg = NULL;
	oauth2_apache_request_ctx_t *ctx = NULL;

	if (ap_auth_type(r) == NULL)
		return DECLINED;

	if (ap_is_initial_req(r) == 0) {

		if (r->main != NULL)
			r->user = r->main->user;
		else if (r->prev != NULL)
			r->user = r->prev->user;

		if (r->user != NULL) {

			ap_log_rerror(
			    APLOG_MARK, APLOG_DEBUG, 0, r,
			    "recycling user '%s' from initial request "
			    "for sub-request",
			    r->user);

			return OK;
		}
	}

	cfg = ap_get_module_config(r->per_dir_config, &auth_openidc_module);
	ctx = OAUTH2_APACHE_REQUEST_CTX(r, auth_openidc);

	oauth2_debug(ctx->log,
		     "incoming request: \"%s?%s\" ap_is_initial_req=%d",
		     r->parsed_uri.path, r->args, ap_is_initial_req(r));

	// TODO: don't really need oauth2_openidc_is_request_to_redirect_uri...
	if ((strcasecmp((const char *)ap_auth_type(r), OPENIDC_AUTH_TYPE) ==
	     0) ||
	    (strcasecmp((const char *)ap_auth_type(r),
			OPENIDC_AUTH_TYPE_OPENIDC) == 0) ||
	    (oauth2_openidc_is_request_to_redirect_uri(ctx->log, cfg->openidc,
						       ctx->request)))
		return openidc_request_handler(cfg->openidc, cfg->target_pass,
					       ctx);

	return DECLINED;
}

static void auth_openidc_register_hooks(apr_pool_t *p)
{
	static const char *const aszPre[] = {"mod_oauth2.c", NULL};
	ap_hook_post_config(OAUTH2_APACHE_POST_CONFIG(auth_openidc), aszPre,
			    NULL, APR_HOOK_MIDDLE);
	ap_hook_check_authn(openidc_check_user_id_handler, aszPre, NULL,
			    APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

// clang-format off
OAUTH2_APACHE_MODULE_DECLARE_EX(
	auth_openidc,
	openidc_cfg_dir_create,
	openidc_cfg_dir_merge
)
// clang-format on
