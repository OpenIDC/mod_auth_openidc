/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
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

#define OAUTH2_REQUEST_STATE_KEY_CLAIMS "C"

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

	if (oauth2_token_verify(ctx->log, ctx->request, verify, source_token,
				&json_token) == false) {
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

	oauth2_apache_request_state_set_json(
	    ctx, OAUTH2_REQUEST_STATE_KEY_CLAIMS, json_token);
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

#define OAUTH2_BEARER_SCOPE_ERROR "OAUTH2_BEARER_SCOPE_ERROR"

static authz_status
oauth2_authz_checker(request_rec *r, const char *require_args,
		     const void *parsed_require_args,
		     oauth2_apache_authz_match_claim_fn_type match_claim_fn)
{
	json_t *claims = NULL;
	oauth2_cfg_dir_t *cfg = NULL;
	oauth2_apache_request_ctx_t *ctx = NULL;
	authz_status rc = AUTHZ_DENIED_NO_USER;
	const char *value = NULL;

	cfg = ap_get_module_config(r->per_dir_config, &oauth2_module);
	ctx = OAUTH2_APACHE_REQUEST_CTX(r, oauth2);

	oauth2_debug(ctx->log, "enter");

	if (r->user != NULL && strlen(r->user) == 0)
		r->user = NULL;

	oauth2_apache_request_state_get_json(
	    ctx, OAUTH2_REQUEST_STATE_KEY_CLAIMS, &claims);

	rc = oauth2_apache_authorize(ctx, claims, require_args, match_claim_fn);
	if (claims)
		json_decref(claims);

	if ((rc == AUTHZ_DENIED) && ap_auth_type(r)) {
		oauth2_apache_return_www_authenticate(
		    cfg->source_token, ctx, HTTP_UNAUTHORIZED,
		    OAUTH2_ERROR_INSUFFICIENT_SCOPE,
		    "Different scope(s) or other claims required.");
		value = apr_table_get(r->err_headers_out,
				      OAUTH2_HTTP_HDR_WWW_AUTHENTICATE);
		apr_table_unset(r->err_headers_out,
				OAUTH2_HTTP_HDR_WWW_AUTHENTICATE);
		oauth2_debug(ctx->log,
			     "setting environment variable %s to \"%s\" for "
			     "usage in mod_headers",
			     OAUTH2_BEARER_SCOPE_ERROR, value);
		apr_table_set(r->subprocess_env, OAUTH2_BEARER_SCOPE_ERROR,
			      value);
	}

	oauth2_debug(ctx->log, "leave");

	return rc;
}

static authz_status oauth2_authz_checker_claim(request_rec *r,
					       const char *require_args,
					       const void *parsed_require_args)
{
	return oauth2_authz_checker(r, require_args, parsed_require_args,
				    oauth2_apache_authz_match_claim);
}

static const authz_provider oauth2_authz_claim_provider = {
    &oauth2_authz_checker_claim, NULL};

#define OAUTH2_REQUIRE_OAUTH2_CLAIM "oauth2_claim"

OAUTH2_APACHE_HANDLERS(oauth2)

static void oauth2_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(OAUTH2_APACHE_POST_CONFIG(oauth2), NULL, NULL,
			    APR_HOOK_MIDDLE);

	static const char *const aszPre[] = {"mod_ssl.c", NULL};
	static const char *const aszSucc[] = {"mod_auth_openidc.c", NULL};
	ap_hook_check_authn(oauth2_check_user_id_handler, aszPre, aszSucc,
			    APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);

	ap_register_auth_provider(
	    p, AUTHZ_PROVIDER_GROUP, OAUTH2_REQUIRE_OAUTH2_CLAIM, "0",
	    &oauth2_authz_claim_provider, AP_AUTH_INTERNAL_PER_CONF);

	// TODO: register content handler for "special" stuff like returning the
	// JWKs that
	//       the peer may use to encrypt the token and the private key
	//       material that we use to sign e.g. client authentication
	//       assertions
	// ap_hook_handler(oauth2_content_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

OAUTH2_APACHE_CMD_ARGS1(oauth2, oauth2_cfg_dir_t, passphrase,
			oauth2_crypto_passphrase_set, NULL)
OAUTH2_APACHE_CMD_ARGS2(oauth2, oauth2_cfg_dir_t, cache, oauth2_cfg_set_cache,
			NULL)
OAUTH2_APACHE_CMD_ARGS3(oauth2, oauth2_cfg_dir_t, token_verify,
			oauth2_cfg_token_verify_add_options, &cfg->verify)
OAUTH2_APACHE_CMD_ARGS2(oauth2, oauth2_cfg_dir_t, accept_token_in,
			oauth2_cfg_source_token_set_accept_in,
			cfg->source_token)
OAUTH2_APACHE_CMD_ARGS1(oauth2, oauth2_cfg_dir_t, target_pass,
			oauth2_cfg_set_target_pass_options, cfg->target_pass)

// clang-format off

static const command_rec OAUTH2_APACHE_COMMANDS(oauth2)[] = {

	OAUTH2_APACHE_CMD_ARGS(oauth2, 1,
		"OAuth2CryptoPassphrase",
		passphrase,
		"Set crypto passphrase."),

	OAUTH2_APACHE_CMD_ARGS(oauth2, 23,
		"OAuth2TokenVerify",
		token_verify,
		"Set token verification method and options."),

	OAUTH2_APACHE_CMD_ARGS(oauth2, 12,
		"OAuth2AcceptTokenIn",
		accept_token_in,
		"Configures in which format source tokens can be presented."),

	OAUTH2_APACHE_CMD_ARGS(oauth2, 1,
		"OAuth2TargetPass",
		target_pass,
		"Configures in which format claims are passed to the target application."),

	OAUTH2_APACHE_CMD_ARGS(oauth2, 12,
		"OAuth2Cache",
		cache,
		"Set cache backend and options."),

	{ NULL }
};

OAUTH2_APACHE_MODULE_DECLARE_EX(
	oauth2,
	oauth2_cfg_dir_create,
	oauth2_cfg_dir_merge
)
// clang-format on
