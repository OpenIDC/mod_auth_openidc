/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone IT BV - www.zmartzone.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include "mod_oauth2.h"

#include <oauth2/apache.h>
#include <oauth2/cfg.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>
#include <oauth2/proto.h>
#include <oauth2/util.h>

#include <httpd.h>

#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_request.h>

#include <apr_strings.h>

OAUTH2_APACHE_LOG(oauth2)

// TODO: move the type into liboauth and use the Apache macro's (as in mod_sts)?
typedef struct oauth2_cfg_dir_t {
	oauth2_cfg_source_token_t *source_token;
	oauth2_cfg_token_verify_t *verify;
	oauth2_cfg_target_pass_t *target_pass;
} oauth2_cfg_dir_t;

static apr_status_t oauth2_cfg_dir_cleanup(void *data)
{
	oauth2_cfg_dir_t *cfg = (oauth2_cfg_dir_t *)data;
	oauth2_cfg_source_token_free(NULL, cfg->source_token);
	if (cfg->verify)
		oauth2_cfg_token_verify_free(NULL, cfg->verify);
	oauth2_cfg_target_pass_free(NULL, cfg->target_pass);
	oauth2_mem_free(cfg);
	return APR_SUCCESS;
}

static void *oauth2_cfg_dir_create(apr_pool_t *pool, char *path)
{
	oauth2_cfg_dir_t *cfg = oauth2_mem_alloc(sizeof(oauth2_cfg_dir_t));
	cfg->source_token = oauth2_cfg_source_token_init(NULL);
	cfg->verify = NULL;
	cfg->target_pass = oauth2_cfg_target_pass_init(NULL);
	apr_pool_cleanup_register(pool, cfg, oauth2_cfg_dir_cleanup,
				  oauth2_cfg_dir_cleanup);
	return cfg;
}

static void *oauth2_cfg_dir_merge(apr_pool_t *pool, void *b, void *a)
{
	oauth2_cfg_dir_t *cfg = oauth2_cfg_dir_create(pool, NULL);
	oauth2_cfg_dir_t *base = b;
	oauth2_cfg_dir_t *add = a;
	oauth2_cfg_source_token_merge(NULL, cfg->source_token,
				      base->source_token, add->source_token);
	cfg->verify = add->verify
			  ? oauth2_cfg_token_verify_clone(NULL, add->verify)
			  : oauth2_cfg_token_verify_clone(NULL, base->verify);
	oauth2_cfg_target_pass_merge(NULL, cfg->target_pass, base->target_pass,
				     add->target_pass);
	return cfg;
}

static int oauth2_request_handler(oauth2_cfg_source_token_t *cfg,
				  oauth2_cfg_token_verify_t *verify,
				  oauth2_cfg_target_pass_t *target_pass,
				  oauth2_apache_request_ctx_t *ctx,
				  bool error_if_no_token_found)
{
	int rv = DECLINED;
	json_t *json_token = NULL;
	char *source_token = NULL;

	oauth2_debug(ctx->log, "enter");

	oauth2_apache_scrub_headers(ctx, target_pass);

	source_token = oauth2_get_source_token(
	    ctx->log, cfg, ctx->request, &oauth2_apache_server_callback_funcs,
	    ctx->r);
	if (source_token == NULL) {
		if (error_if_no_token_found) {
			rv = oauth2_apache_return_www_authenticate(
			    cfg, ctx, HTTP_UNAUTHORIZED,
			    OAUTH2_ERROR_INVALID_REQUEST,
			    "No bearer token found in the request.");
		}
		goto end;
	}

	if (oauth2_token_verify(ctx->log, verify, source_token, &json_token) ==
	    false) {
		rv = oauth2_apache_return_www_authenticate(
		    cfg, ctx, HTTP_UNAUTHORIZED, OAUTH2_ERROR_INVALID_TOKEN,
		    "Token could not be verified.");
		goto end;
	}

	if (oauth2_apache_set_request_user(target_pass, ctx, json_token) ==
	    false) {
		rv = oauth2_apache_return_www_authenticate(
		    cfg, ctx, HTTP_UNAUTHORIZED, OAUTH2_ERROR_INVALID_TOKEN,
		    "Could not determine remote user.");
		goto end;
	}

	oauth2_apache_target_pass(ctx, target_pass, source_token, json_token);

	rv = OK;

end:

	if (source_token)
		oauth2_mem_free(source_token);
	if (json_token)
		json_decref(json_token);

	oauth2_debug(ctx->log, "leave");

	return rv;
}

static int oauth2_check_user_id_handler(request_rec *r)
{
	oauth2_cfg_dir_t *cfg = NULL;
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

	cfg = ap_get_module_config(r->per_dir_config, &oauth2_module);
	ctx = OAUTH2_APACHE_REQUEST_CTX(r, oauth2);

	oauth2_debug(ctx->log,
		     "incoming request: \"%s?%s\" ap_is_initial_req=%d",
		     r->parsed_uri.path, r->args, ap_is_initial_req(r));

	if (strcasecmp((const char *)ap_auth_type(r), OAUTH2_AUTH_TYPE) == 0)
		return oauth2_request_handler(cfg->source_token, cfg->verify,
					      cfg->target_pass, ctx, true);

	if (strcasecmp((const char *)ap_auth_type(r),
		       OAUTH2_AUTH_TYPE_OPENIDC) == 0)
		return oauth2_request_handler(cfg->source_token, cfg->verify,
					      cfg->target_pass, ctx, false);

	return DECLINED;
}

// TODO: probably macro-ize this
//       and rename oauth2_cfg_token_verify_add_options to
//       oauth2_cfg_set_token_verify_
static const char *oauth2_cfg_set_token_verify(cmd_parms *cmd, void *m,
					       const char *type,
					       const char *value,
					       const char *options)
{
	const char *rv = NULL;
	oauth2_cfg_dir_t *dir_cfg = NULL;
	oauth2_apache_cfg_srv_t *srv_cfg = NULL;

	dir_cfg = (oauth2_cfg_dir_t *)m;
	srv_cfg =
	    ap_get_module_config(cmd->server->module_config, &oauth2_module);
	rv = oauth2_cfg_token_verify_add_options(srv_cfg->log, &dir_cfg->verify,
						 type, value, options);
	return rv;
}

static const char *oauth2_cfg_set_accept_token_in(cmd_parms *cmd, void *m,
						  const char *type,
						  const char *options)
{
	const char *rv = NULL;
	oauth2_cfg_dir_t *dir_cfg = NULL;
	oauth2_apache_cfg_srv_t *srv_cfg = NULL;

	dir_cfg = (oauth2_cfg_dir_t *)m;
	srv_cfg =
	    ap_get_module_config(cmd->server->module_config, &oauth2_module);
	rv = oauth2_cfg_source_token_set_accept_in(
	    srv_cfg->log, dir_cfg->source_token, type, options);
	return rv;
}

static const char *oauth2_cfg_set_target_pass(cmd_parms *cmd, void *m,
					      const char *options)
{
	const char *rv = NULL;
	oauth2_cfg_dir_t *dir_cfg = NULL;
	oauth2_apache_cfg_srv_t *srv_cfg = NULL;

	dir_cfg = (oauth2_cfg_dir_t *)m;
	srv_cfg =
	    ap_get_module_config(cmd->server->module_config, &oauth2_module);
	rv = oauth2_cfg_set_target_pass_options(srv_cfg->log,
						dir_cfg->target_pass, options);
	return rv;
}

// clang-format off

OAUTH2_APACHE_HANDLERS(oauth2)

#define OAUTH2_CFG_CMD_ARGS(nargs, cmd, member, desc) \
	AP_INIT_TAKE##nargs( \
		cmd, \
		oauth2_cfg_set_##member, \
		NULL, \
		RSRC_CONF | ACCESS_CONF | OR_AUTHCFG, \
		desc)

static const command_rec OAUTH2_APACHE_COMMANDS(oauth2)[] = {

	OAUTH2_CFG_CMD_ARGS(23,
		"OAuth2TokenVerify",
		token_verify,
		"Set token verification method and options."),

	OAUTH2_CFG_CMD_ARGS(12,
		"OAuth2AcceptTokenIn",
		accept_token_in,
		"Configures in which format tokens can be presented."),

	OAUTH2_CFG_CMD_ARGS(1,
		"OAuth2TargetPass",
		target_pass,
		"Configures in which format claims are passed to the target application."),

	{ NULL }
};

static void oauth2_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(OAUTH2_APACHE_POST_CONFIG(oauth2), NULL, NULL,
			    APR_HOOK_MIDDLE);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_hook_check_authn(oauth2_check_user_id_handler, NULL, NULL,
			    APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
#else
	ap_hook_check_user_id(oauth2_check_user_id_handler, NULL, NULL,
			      APR_HOOK_MIDDLE);
#endif

	// TODO: register content handler for "special" stuff like returning the
	// JWKs that
	//       the peer may use to encrypt the token and the private key
	//       material that we use to sign e.g. client authentication
	//       assertions
	// ap_hook_handler(oidc_content_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

OAUTH2_APACHE_MODULE_DECLARE_EX(
	oauth2,
	oauth2_cfg_dir_create,
	oauth2_cfg_dir_merge
)
// clang-format on
