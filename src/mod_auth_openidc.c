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

#include "mod_auth_openidc.h"

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

// override ap_config_auto "" but to allow that we first have to undefine
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "config.h"

#include <apr_strings.h>

OAUTH2_APACHE_LOG(auth_openidc)

// clang-format off

OAUTH2_APACHE_HANDLERS(auth_openidc)

static const command_rec OAUTH2_APACHE_COMMANDS(auth_openidc)[] = {
	{ NULL }
};

static int openidc_check_user_id_handler(request_rec *r)
{
	oauth2_apache_request_ctx_t *ctx = OAUTH2_APACHE_REQUEST_CTX(r, auth_openidc)
	// make it compile for now
	r = ctx->r;
	return DECLINED;
}

static void auth_openidc_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(OAUTH2_APACHE_POST_CONFIG(auth_openidc), NULL, NULL,
			    APR_HOOK_MIDDLE);
	ap_hook_check_authn(openidc_check_user_id_handler, NULL, NULL,
			    APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

OAUTH2_APACHE_MODULE_DECLARE_EX(
	auth_openidc,
	NULL,
	NULL
)
// clang-format on
