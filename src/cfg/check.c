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

/*
 * post-config validation of the module's server configuration: mandatory directives, the
 * relationship between OIDCRedirectURI and OIDCCookieDomain, the OAuth resource-server settings
 * and the crypto passphrase / key derivation.
 *
 * This is configuration knowledge, so it belongs beside the rest of cfg/ rather than in the module
 * core it was written in; oidc_cfg_check_vhosts() is the single entry point post_config calls.
 */

#include "cfg/check.h"

#include "cfg/dir.h"
#include "cfg/oauth.h"
#include "cfg/provider.h"
#include "const.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

#include <apr_hash.h>
#include <apr_strings.h>

/*
 * identify the (virtual) host that a message below applies to: httpd does not record which
 * server_rec a post_config message was logged against, so in a configuration with more than one
 * vhost the message on its own does not say which one needs fixing - and a single offending vhost
 * aborts the startup of the whole server
 */
static const char *oidc_check_config_vhost(const server_rec *s) {
	apr_pool_t *pool = s->process->pconf;
	const char *name = (s->server_hostname != NULL) ? s->server_hostname : "(no ServerName)";
	if (s->defn_name == NULL)
		return name;
	if (s->defn_line_number == 0)
		return apr_psprintf(pool, "%s (%s)", name, s->defn_name);
	return apr_psprintf(pool, "%s (%s:%u)", name, s->defn_name, s->defn_line_number);
}

#define oidc_check_serror(s, fmt, ...) oidc_serror(s, "[%s] " fmt, oidc_check_config_vhost(s), ##__VA_ARGS__)
#define oidc_check_swarn(s, fmt, ...) oidc_swarn(s, "[%s] " fmt, oidc_check_config_vhost(s), ##__VA_ARGS__)

/*
 * report a config error
 */
static int oidc_check_config_error(server_rec *s, const char *config_str) {
	oidc_check_serror(s, "mandatory parameter '%s' is not set", config_str);
	return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * validate the provider source configuration: OIDCMetadataDir vs OIDCProviderMetadataURL vs static provider settings
 */
static int oidc_check_config_openid_openidc_provider(apr_pool_t *pool, server_rec *s, oidc_cfg_t *c) {
	if (oidc_cfg_metadata_dir_get(c) != NULL) {
		if (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)) != NULL) {
			oidc_check_serror(s, "only one of '" OIDCProviderMetadataURL "' or '" OIDCMetadataDir
					     "' should be set");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		return OK;
	}

	if (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)) == NULL) {
		if (oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)) == NULL)
			return oidc_check_config_error(s, OIDCProviderIssuer);
		if (oidc_cfg_provider_authorization_endpoint_url_get(oidc_cfg_provider_get(c)) == NULL)
			return oidc_check_config_error(s, OIDCProviderAuthorizationEndpoint);
	} else {
		apr_uri_t r_uri;
		apr_uri_parse(pool, oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)), &r_uri);
		if ((r_uri.scheme == NULL) || (_oidc_strnatcasecmp(r_uri.scheme, "https") != 0)) {
			oidc_check_swarn(s,
					 "the URL scheme (%s) of the configured " OIDCProviderMetadataURL
					 " SHOULD be \"https\" for security reasons!",
					 r_uri.scheme);
		}
	}

	if (oidc_cfg_provider_client_id_get(oidc_cfg_provider_get(c)) == NULL)
		return oidc_check_config_error(s, OIDCClientID);

	return OK;
}

/*
 * validate OIDCCookieDomain against the redirect_uri's hostname
 */
static int oidc_check_config_openid_openidc_cookie_domain(server_rec *s, const oidc_cfg_t *c, const apr_uri_t *r_uri,
							  apr_byte_t redirect_uri_is_relative) {
	if (oidc_cfg_cookie_domain_get(c) == NULL)
		return OK;

	if (redirect_uri_is_relative) {
		oidc_check_swarn(s, "if the configured " OIDCRedirectURI " is relative, " OIDCCookieDomain
				    " SHOULD be empty");
		return OK;
	}

	if (!oidc_util_cookie_domain_valid(r_uri->hostname, oidc_cfg_cookie_domain_get(c))) {
		oidc_check_serror(s,
				  "the domain (%s) configured in " OIDCCookieDomain
				  " does not match the URL hostname (%s) of the configured " OIDCRedirectURI
				  " (%s): setting \"state\" and \"session\" cookies will not work!",
				  oidc_cfg_cookie_domain_get(c), r_uri->hostname, oidc_cfg_redirect_uri_get(c));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * check the config required for the OpenID Connect RP role
 */
static int oidc_check_config_openid_openidc(apr_pool_t *pool, server_rec *s, oidc_cfg_t *c) {

	if ((oidc_cfg_metadata_dir_get(c) == NULL) &&
	    (oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(c)) == NULL) &&
	    (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(c)) == NULL)) {
		oidc_check_serror(s, "one of '" OIDCProviderIssuer "', '" OIDCProviderMetadataURL
				     "' or '" OIDCMetadataDir "' must be set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (oidc_cfg_redirect_uri_get(c) == NULL)
		return oidc_check_config_error(s, OIDCRedirectURI);

	int rc = oidc_check_config_openid_openidc_provider(pool, s, c);
	if (rc != OK)
		return rc;

	apr_byte_t redirect_uri_is_relative = (oidc_cfg_redirect_uri_get(c)[0] == OIDC_CHAR_FORWARD_SLASH);
	apr_uri_t r_uri;
	apr_uri_parse(pool, oidc_cfg_redirect_uri_get(c), &r_uri);

	if (!redirect_uri_is_relative && (_oidc_strnatcasecmp(r_uri.scheme, "https") != 0)) {
		oidc_check_swarn(s,
				 "the URL scheme (%s) of the configured " OIDCRedirectURI
				 " SHOULD be \"https\" for security reasons (moreover: some Providers may reject "
				 "non-HTTPS URLs)",
				 r_uri.scheme);
	}

	rc = oidc_check_config_openid_openidc_cookie_domain(s, c, &r_uri, redirect_uri_is_relative);
	if (rc != OK)
		return rc;

	if ((oidc_proto_profile_dpop_mode_get(oidc_cfg_provider_get(c)) != OIDC_DPOP_MODE_OFF) &&
	    (oidc_util_key_list_first(oidc_cfg_private_keys_get(c), -1, OIDC_JOSE_JWK_SIG_STR) == NULL)) {
		oidc_check_serror(s, "'" OIDCDPoPMode "' is configured but the required signing keys have not been "
				     "provided in '" OIDCPrivateKeyFiles "'/'" OIDCPublicKeyFiles "'");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * check the config required for the OAuth 2.0 RS role
 */
static int oidc_check_config_oauth(apr_pool_t *pool, server_rec *s, const oidc_cfg_t *c) {

	apr_uri_t r_uri;

	oidc_check_swarn(
	    s, "The OAuth 2.0 Resource Server functionality is deprecated and superseded by a new module, see: "
	       "https://github.com/OpenIDC/mod_oauth2!");

	if (oidc_cfg_oauth_metadata_url_get(c) != NULL) {
		apr_uri_parse(pool, oidc_cfg_oauth_metadata_url_get(c), &r_uri);
		if ((r_uri.scheme == NULL) || (_oidc_strnatcasecmp(r_uri.scheme, "https") != 0)) {
			oidc_check_swarn(s,
					 "the URL scheme (%s) of the configured " OIDCOAuthServerMetadataURL
					 " SHOULD be \"https\" for security reasons!",
					 r_uri.scheme);
		}
		return OK;
	}

	if (oidc_cfg_oauth_introspection_endpoint_url_get(c) == NULL) {

		if ((oidc_cfg_oauth_verify_jwks_uri_get(c) == NULL) &&
		    (oidc_cfg_oauth_verify_public_keys_get(c) == NULL) &&
		    (oidc_cfg_oauth_verify_shared_keys_get(c) == NULL)) {
			oidc_check_serror(s, "one of '" OIDCOAuthServerMetadataURL "', '" OIDCOAuthIntrospectionEndpoint
					     "', '" OIDCOAuthVerifyJwksUri "', '" OIDCOAuthVerifySharedKeys
					     "' or '" OIDCOAuthVerifyCertFiles "' must be set");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (oidc_cfg_oauth_verify_aud_values_get(c) == NULL)
			oidc_check_swarn(
			    s, "JWT access tokens are validated locally but '" OIDCOAuthVerifyAudience
			       "' is not set, so any token signed by the configured key(s) is accepted, "
			       "including one issued for a different resource server; set '" OIDCOAuthVerifyAudience
			       "' to the identifier(s) of this resource server");

	} else if ((oidc_cfg_oauth_verify_jwks_uri_get(c) != NULL) ||
		   (oidc_cfg_oauth_verify_public_keys_get(c) != NULL) ||
		   (oidc_cfg_oauth_verify_shared_keys_get(c) != NULL)) {
		oidc_check_serror(
		    s, "only '" OIDCOAuthIntrospectionEndpoint "' OR one (or more) out of ('" OIDCOAuthVerifyJwksUri
		       "', '" OIDCOAuthVerifySharedKeys "' or '" OIDCOAuthVerifyCertFiles "') must be set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * derive this server's PBKDF2 key material for its crypto passphrase, once finalized; unlike
 * the OIDC/OAuth completeness checks below, this must happen for every server config that
 * could end up handling a live request -- including the base server even when other vhosts
 * have merged configs of their own -- since the base server can still directly serve requests
 * (e.g. as the fallback vhost) and each oidc_cfg_t carries its own copy of the passphrase and
 * (once derived) its key material.
 *
 * when auto_generate is TRUE, an unset passphrase is first auto-generated -- the original
 * behavior for a server config that is the only one in play (no vhosts override it). When
 * FALSE, an unset passphrase is left alone: the base server may deliberately be left without
 * its own crypto passphrase when vhosts each set/override their own OIDCCryptoPassphrase, and
 * must keep starting up that way rather than silently gaining a freshly-manufactured one.
 *
 * kdf_cache memoizes the (expensive, ~210,000-iteration PBKDF2) derivation by secret text across
 * every server_rec checked in this post_config pass -- see oidc_crypto_passphrase_derive_keys_cached().
 * A deployment with hundreds of <VirtualHost>s that all inherit/set the same OIDCCryptoPassphrase
 * would otherwise re-run the KDF once per vhost instead of once per distinct secret, which can
 * turn into a multi-second startup/graceful-restart delay.
 */
static int oidc_config_ensure_crypto_passphrase(server_rec *s, oidc_cfg_t *cfg, apr_byte_t auto_generate,
						apr_hash_t *kdf_cache) {
	if (oidc_cfg_crypto_passphrase_secret1_get(cfg) == NULL) {
		if (!auto_generate)
			return OK;
		oidc_cfg_crypto_passphrase_secret1_set(cfg, oidc_util_rand_hex_str(NULL, s->process->pool, 32));
	}

	if (oidc_cfg_crypto_passphrase_derive_keys_cached(s->process->pool, kdf_cache, cfg) == FALSE) {
		oidc_check_serror(s, "oidc_cfg_crypto_passphrase_derive_keys_cached failed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * check the config of a vhost
 */
static int oidc_config_check_vhost_config(apr_pool_t *pool, server_rec *s, apr_hash_t *kdf_cache) {
	oidc_cfg_t *cfg = ap_get_module_config(s->module_config, &auth_openidc_module);

	oidc_sdebug(s, "enter");

	/*
	 * turning the masking off is a deliberate, temporary troubleshooting step, so say so on every
	 * start: it is the one setting whose whole effect is to write credentials - access, refresh and
	 * ID tokens, client secrets, authorization codes - to the error log in the clear, where the log
	 * shipper and everyone with read access to it will pick them up. A warning here is what keeps it
	 * from being switched on for an incident and quietly left on afterwards.
	 */
	if (oidc_cfg_debug_mask_secrets_get(cfg) == 0)
		oidc_check_swarn(
		    s,
		    "%s is Off: secrets and tokens are written to the log unmasked whenever LogLevel is "
		    "debug or higher. Intended for short-lived troubleshooting only - turn it back On, and "
		    "treat any log written meanwhile as containing live credentials",
		    OIDCDebugMaskSecrets);

	if (oidc_config_ensure_crypto_passphrase(s, cfg, TRUE, kdf_cache) != OK)
		return HTTP_INTERNAL_SERVER_ERROR;

	const int openidc_configured = (oidc_cfg_metadata_dir_get(cfg) != NULL) ||
				       (oidc_cfg_provider_issuer_get(oidc_cfg_provider_get(cfg)) != NULL) ||
				       (oidc_cfg_provider_metadata_url_get(oidc_cfg_provider_get(cfg)) != NULL);

	const int oauth_configured =
	    (oidc_cfg_oauth_metadata_url_get(cfg) != NULL) || (oidc_cfg_oauth_client_id_get(cfg) != NULL) ||
	    (oidc_cfg_oauth_client_secret_get(cfg) != NULL) ||
	    (oidc_cfg_oauth_introspection_endpoint_url_get(cfg) != NULL) ||
	    (oidc_cfg_oauth_verify_jwks_uri_get(cfg) != NULL) || (oidc_cfg_oauth_verify_public_keys_get(cfg) != NULL) ||
	    (oidc_cfg_oauth_verify_shared_keys_get(cfg) != NULL);

	/* a vhost that sets OIDCRedirectURI *itself* without any OAuth 2.0 RS settings intends to act
	 * as an OpenID Connect RP: run the RP check even when no provider source is configured, so
	 * that omission is a startup error instead of a request-time authentication/discovery failure.
	 *
	 * an inherited one says nothing about this vhost's intent: OIDCRedirectURI is commonly set
	 * once at server level, from where it lands in the merged config of every vhost - including
	 * those that do no OpenID Connect at all (a static site, a health check, a redirect-only
	 * vhost). Inferring RP intent there would refuse to start the whole server over a vhost that
	 * never asked for an RP in the first place */
	const int rp_intent = (oidc_cfg_redirect_uri_get(cfg) != NULL) && (!oidc_cfg_redirect_uri_inherited_get(cfg)) &&
			      (!oauth_configured);

	if ((openidc_configured || rp_intent) && (oidc_check_config_openid_openidc(pool, s, cfg) != OK))
		return HTTP_INTERNAL_SERVER_ERROR;

	if (oauth_configured && (oidc_check_config_oauth(pool, s, cfg) != OK))
		return HTTP_INTERNAL_SERVER_ERROR;

	return OK;
}

/*
 * check the config of a merged vhost
 */
static int oidc_config_check_merged_vhost_configs(apr_pool_t *pool, server_rec *s) {
	int status = OK;
	server_rec *sp = s;
	/* shared across every server_rec below, so hundreds of vhosts inheriting/setting the same
	 * OIDCCryptoPassphrase only pay for the PBKDF2 derivation once per distinct secret -- see
	 * oidc_config_ensure_crypto_passphrase() */
	apr_hash_t *kdf_cache = apr_hash_make(pool);
	while ((sp != NULL) && (status == OK)) {
		oidc_cfg_t *cfg = ap_get_module_config(sp->module_config, &auth_openidc_module);
		if (oidc_cfg_merged_get(cfg)) {
			/* a merged vhost config is checked in full, exactly as before */
			status = oidc_config_check_vhost_config(pool, sp, kdf_cache);
		} else {
			/* the base server "s" itself is never flagged as merged (its config comes
			 * straight from create_server_config, not merge_server_config). Derive keys for
			 * it only if it already has its own explicitly-configured passphrase (do not
			 * auto-generate one): both leaving the base without a passphrase (vhosts set/
			 * override their own) and the full OIDC/OAuth completeness checks must keep
			 * behaving exactly as before */
			status = oidc_config_ensure_crypto_passphrase(sp, cfg, FALSE, kdf_cache);
		}
		sp = sp->next;
	}
	return status;
}

/*
 * check if any merged vhost configs exist
 */
static int oidc_config_merged_vhost_configs_exist(server_rec *s) {
	server_rec *sp = s;
	while (sp != NULL) {
		const oidc_cfg_t *cfg = ap_get_module_config(sp->module_config, &auth_openidc_module);
		if (oidc_cfg_merged_get(cfg)) {
			return TRUE;
		}
		sp = sp->next;
	}
	return FALSE;
}

/*
 * Apache has a base vhost that true vhosts derive from.
 * There are two startup scenarios:
 *
 * 1. Only the base vhost contains OIDC settings.
 *    No server configs have been merged.
 *    Only the base vhost needs to be checked.
 *
 * 2. The base vhost contains zero or more OIDC settings.
 *    One or more vhosts override these.
 *    These vhosts have a merged config.
 *    All merged configs need to be checked.
 */
int oidc_cfg_check_vhosts(apr_pool_t *pool, server_rec *s) {
	if (!oidc_config_merged_vhost_configs_exist(s)) {
		/* nothing merged, only check the base vhost -- a single server_rec, so there is
		 * nothing for a kdf_cache to deduplicate */
		return oidc_config_check_vhost_config(pool, s, NULL);
	}
	return oidc_config_check_merged_vhost_configs(pool, s);
}
