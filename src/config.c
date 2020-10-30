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
 * Copyright (C) 2017-2020 ZmartZone IAM
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
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
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 */

#include <apr.h>
#include <apr_errno.h>
#include <apr_strings.h>
#include <apr_portable.h>
#include <apr_base64.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include <ap_provider.h>

#include <curl/curl.h>

#include "mod_auth_openidc.h"
#include "parse.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#if (OPENSSL_VERSION_NUMBER < 0x01000000)
#define OPENSSL_NO_THREADID
#endif

/* validate SSL server certificates by default */
#define OIDC_DEFAULT_SSL_VALIDATE_SERVER 1
/* validate issuer by default */
#define OIDC_DEFAULT_VALIDATE_ISSUER 1
/* default scope requested from the OP */
#define OIDC_DEFAULT_SCOPE "openid"
/* default claim delimiter for multi-valued claims passed in a HTTP header */
#define OIDC_DEFAULT_CLAIM_DELIMITER ","
/* default prefix for claim names being passed in HTTP headers */
#define OIDC_DEFAULT_CLAIM_PREFIX "OIDC_CLAIM_"
/* default name for the claim that will contain the REMOTE_USER value for OpenID Connect protected paths */
#define OIDC_DEFAULT_CLAIM_REMOTE_USER "sub@"
/* default name for the claim that will contain the REMOTE_USER value for OAuth 2.0 protected paths */
#define OIDC_DEFAULT_OAUTH_CLAIM_REMOTE_USER "sub"
/* default name of the session cookie */
#define OIDC_DEFAULT_COOKIE "mod_auth_openidc_session"
/* default for the HTTP header name in which the remote user name is passed */
#define OIDC_DEFAULT_AUTHN_HEADER NULL
/* default client_name the client uses for dynamic client registration */
#define OIDC_DEFAULT_CLIENT_NAME "OpenID Connect Apache Module (mod_auth_openidc)"
/* timeouts in seconds for HTTP calls that may take a long time */
#define OIDC_DEFAULT_HTTP_TIMEOUT_LONG  60
/* timeouts in seconds for HTTP calls that should take a short time (registry/discovery related) */
#define OIDC_DEFAULT_HTTP_TIMEOUT_SHORT  5
/* default session storage type */
#define OIDC_DEFAULT_SESSION_TYPE OIDC_SESSION_TYPE_SERVER_CACHE
/* default client-cookie chunking size */
#define OIDC_DEFAULT_SESSION_CLIENT_COOKIE_CHUNK_SIZE 4000
/* timeout in seconds after which state expires */
#define OIDC_DEFAULT_STATE_TIMEOUT 300
/* maximum number of parallel state cookies; 0 means unlimited, until the browser or server gives up */
#define OIDC_DEFAULT_MAX_NUMBER_OF_STATE_COOKIES 7
/* default setting for deleting the oldest state cookies */
#define OIDC_DEFAULT_DELETE_OLDEST_STATE_COOKIES 0
/* default session inactivity timeout */
#define OIDC_DEFAULT_SESSION_INACTIVITY_TIMEOUT 300
/* default session max duration */
#define OIDC_DEFAULT_SESSION_MAX_DURATION 3600 * 8
/* default OpenID Connect authorization response type */
#define OIDC_DEFAULT_RESPONSE_TYPE OIDC_PROTO_CODE
/* default duration in seconds after which retrieved JWS should be refreshed */
#define OIDC_DEFAULT_JWKS_REFRESH_INTERVAL 3600
/* default max cache size for shm */
#define OIDC_DEFAULT_CACHE_SHM_SIZE 500
/* default max cache entry size for shm: # value + # key + # overhead */
#define OIDC_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX 16384 + 512 + 17
/* minimum size of a cache entry */
#define OIDC_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX 8192 + 512 + 17
/* for issued-at timestamp (iat) checking */
#define OIDC_DEFAULT_IDTOKEN_IAT_SLACK 600
/* for file-based caching: clean interval in seconds */
#define OIDC_DEFAULT_CACHE_FILE_CLEAN_INTERVAL 60
/* set httponly flag on cookies */
#define OIDC_DEFAULT_COOKIE_HTTPONLY 1
/* set Same-Site flag on cookies */
#define OIDC_DEFAULT_COOKIE_SAME_SITE 0
/* default cookie path */
#define OIDC_DEFAULT_COOKIE_PATH "/"
/* default OAuth 2.0 introspection token parameter name */
#define OIDC_DEFAULT_OAUTH_TOKEN_PARAM_NAME "token"
/* default OAuth 2.0 introspection call HTTP method */
#define OIDC_DEFAULT_OAUTH_ENDPOINT_METHOD OIDC_INTROSPECTION_METHOD_POST
/* default OAuth 2.0 non-spec compliant introspection expiry claim name */
#define OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME OIDC_PROTO_EXPIRES_IN
/* default OAuth 2.0 non-spec compliant introspection expiry claim format */
#define OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT OIDC_CLAIM_FORMAT_RELATIVE
/* default OAuth 2.0 non-spec compliant introspection expiry claim required */
#define OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED TRUE
/* default refresh interval in seconds after which claims from the user info endpoint should be refreshed */
#define OIDC_DEFAULT_USERINFO_REFRESH_INTERVAL 0
/* default for preserving POST parameters across authentication requests */
#define OIDC_DEFAULT_PRESERVE_POST 0
/* default for passing the access token in a header/environment variable */
#define OIDC_DEFAULT_PASS_REFRESH_TOKEN 0
/* default for passing app info in headers */
#define OIDC_DEFAULT_PASS_APP_INFO_IN_HEADERS 1
/* default for passing app info in environment variables */
#define OIDC_DEFAULT_PASS_APP_INFO_IN_ENVVARS 1
/* default value for the token introspection interval (0 = disabled, no expiry of claims) */
#define OIDC_DEFAULT_TOKEN_INTROSPECTION_INTERVAL 0
/* default action to take on an incoming unauthenticated request */
#define OIDC_DEFAULT_UNAUTH_ACTION OIDC_UNAUTH_AUTHENTICATE
/* default action to take on an incoming authorized request */
#define OIDC_DEFAULT_UNAUTZ_ACTION OIDC_UNAUTZ_RETURN403
/* defines for how long provider metadata will be cached */
#define OIDC_DEFAULT_PROVIDER_METADATA_REFRESH_INTERVAL 0
/* defines the default token binding policy for a provider */
#define OIDC_DEFAULT_PROVIDER_TOKEN_BINDING_POLICY OIDC_TOKEN_BINDING_POLICY_OPTIONAL
/* defines the default token binding policy for OAuth 2.0 access tokens */
#define OIDC_DEFAULT_OAUTH_ACCESS_TOKEN_BINDING_POLICY OIDC_TOKEN_BINDING_POLICY_OPTIONAL
/* define the default HTTP method used to send the authentication request to the provider */
#define OIDC_DEFAULT_AUTH_REQUEST_METHOD OIDC_AUTH_REQUEST_METHOD_GET
/* define whether the issuer will be added to the redirect uri by default to mitigate the IDP mixup attack */
#define OIDC_DEFAULT_PROVIDER_ISSUER_SPECIFIC_REDIRECT_URI 0
/* define the default number of seconds that the access token needs to be valid for; -1 = no refresh */
#define OIDC_DEFAULT_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY -1
/* default setting for calculating the fingerprint of the state from request headers during authentication */
#define OIDC_DEFAULT_STATE_INPUT_HEADERS (OIDC_STATE_INPUT_HEADERS_USER_AGENT | OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR)
/* default prefix of the state cookie that binds the state in the authorization request/response to the browser */
#define OIDC_DEFAULT_STATE_COOKIE_PREFIX "mod_auth_openidc_state_"

#define OIDCProviderMetadataURL                "OIDCProviderMetadataURL"
#define OIDCProviderIssuer                     "OIDCProviderIssuer"
#define OIDCProviderAuthorizationEndpoint      "OIDCProviderAuthorizationEndpoint"
#define OIDCProviderTokenEndpoint              "OIDCProviderTokenEndpoint"
#define OIDCProviderTokenEndpointAuth          "OIDCProviderTokenEndpointAuth"
#define OIDCProviderTokenEndpointParams        "OIDCProviderTokenEndpointParams"
#define OIDCProviderRegistrationEndpointJson   "OIDCProviderRegistrationEndpointJson"
#define OIDCProviderUserInfoEndpoint           "OIDCProviderUserInfoEndpoint"
#define OIDCProviderRevocationEndpoint         "OIDCProviderRevocationEndpoint"
#define OIDCProviderCheckSessionIFrame         "OIDCProviderCheckSessionIFrame"
#define OIDCProviderEndSessionEndpoint         "OIDCProviderEndSessionEndpoint"
#define OIDCProviderBackChannelLogoutSupported "OIDCProviderBackChannelLogoutSupported"
#define OIDCProviderJwksUri                    "OIDCProviderJwksUri"
#define OIDCResponseType                       "OIDCResponseType"
#define OIDCResponseMode                       "OIDCResponseMode"
#define OIDCPublicKeyFiles                     "OIDCPublicKeyFiles"
#define OIDCClientJwksUri                      "OIDCClientJwksUri"
#define OIDCIDTokenSignedResponseAlg           "OIDCIDTokenSignedResponseAlg"
#define OIDCIDTokenEncryptedResponseAlg        "OIDCIDTokenEncryptedResponseAlg"
#define OIDCIDTokenEncryptedResponseEnc        "OIDCIDTokenEncryptedResponseEnc"
#define OIDCUserInfoSignedResponseAlg          "OIDCUserInfoSignedResponseAlg"
#define OIDCUserInfoEncryptedResponseAlg       "OIDCUserInfoEncryptedResponseAlg"
#define OIDCUserInfoEncryptedResponseEnc       "OIDCUserInfoEncryptedResponseEnc"
#define OIDCUserInfoTokenMethod                "OIDCUserInfoTokenMethod"
#define OIDCTokenBindingPolicy                 "OIDCTokenBindingPolicy"
#define OIDCSSLValidateServer                  "OIDCSSLValidateServer"
#define OIDCValidateIssuer                     "OIDCValidateIssuer"
#define OIDCClientName                         "OIDCClientName"
#define OIDCClientContact                      "OIDCClientContact"
#define OIDCScope                              "OIDCScope"
#define OIDCPathScope                          "OIDCPathScope"
#define OIDCJWKSRefreshInterval                "OIDCJWKSRefreshInterval"
#define OIDCIDTokenIatSlack                    "OIDCIDTokenIatSlack"
#define OIDCSessionMaxDuration                 "OIDCSessionMaxDuration"
#define OIDCAuthRequestParams                  "OIDCAuthRequestParams"
#define OIDCPathAuthRequestParams              "OIDCPathAuthRequestParams"
#define OIDCPKCEMethod                         "OIDCPKCEMethod"
#define OIDCClientID                           "OIDCClientID"
#define OIDCClientSecret                       "OIDCClientSecret"
#define OIDCClientTokenEndpointCert            "OIDCClientTokenEndpointCert"
#define OIDCClientTokenEndpointKey             "OIDCClientTokenEndpointKey"
#define OIDCDefaultLoggedOutURL                "OIDCDefaultLoggedOutURL"
#define OIDCCookieHTTPOnly                     "OIDCCookieHTTPOnly"
#define OIDCCookieSameSite                     "OIDCCookieSameSite"
#define OIDCOutgoingProxy                      "OIDCOutgoingProxy"
#define OIDCCryptoPassphrase                   "OIDCCryptoPassphrase"
#define OIDCClaimDelimiter                     "OIDCClaimDelimiter"
#define OIDCPassIDTokenAs                      "OIDCPassIDTokenAs"
#define OIDCPassUserInfoAs                     "OIDCPassUserInfoAs"
#define OIDCOAuthClientID                      "OIDCOAuthClientID"
#define OIDCOAuthClientSecret                  "OIDCOAuthClientSecret"
#define OIDCOAuthIntrospectionClientAuthBearerToken "OIDCOAuthIntrospectionClientAuthBearerToken"
#define OIDCOAuthIntrospectionEndpoint         "OIDCOAuthIntrospectionEndpoint"
#define OIDCOAuthIntrospectionEndpointMethod   "OIDCOAuthIntrospectionEndpointMethod"
#define OIDCOAuthIntrospectionEndpointParams   "OIDCOAuthIntrospectionEndpointParams"
#define OIDCOAuthIntrospectionEndpointAuth     "OIDCOAuthIntrospectionEndpointAuth"
#define OIDCOAuthIntrospectionEndpointCert     "OIDCOAuthIntrospectionEndpointCert"
#define OIDCOAuthIntrospectionEndpointKey      "OIDCOAuthIntrospectionEndpointKey"
#define OIDCOAuthIntrospectionTokenParamName   "OIDCOAuthIntrospectionTokenParamName"
#define OIDCOAuthTokenExpiryClaim              "OIDCOAuthTokenExpiryClaim"
#define OIDCOAuthSSLValidateServer             "OIDCOAuthSSLValidateServer"
#define OIDCOAuthVerifyCertFiles               "OIDCOAuthVerifyCertFiles"
#define OIDCOAuthVerifySharedKeys              "OIDCOAuthVerifySharedKeys"
#define OIDCOAuthVerifyJwksUri                 "OIDCOAuthVerifyJwksUri"
#define OIDCHTTPTimeoutLong                    "OIDCHTTPTimeoutLong"
#define OIDCHTTPTimeoutShort                   "OIDCHTTPTimeoutShort"
#define OIDCStateTimeout                       "OIDCStateTimeout"
#define OIDCStateMaxNumberOfCookies            "OIDCStateMaxNumberOfCookies"
#define OIDCSessionInactivityTimeout           "OIDCSessionInactivityTimeout"
#define OIDCMetadataDir                        "OIDCMetadataDir"
#define OIDCSessionCacheFallbackToCookie       "OIDCSessionCacheFallbackToCookie"
#define OIDCSessionCookieChunkSize             "OIDCSessionCookieChunkSize"
#define OIDCScrubRequestHeaders                "OIDCScrubRequestHeaders"
#define OIDCCacheType                          "OIDCCacheType"
#define OIDCCacheEncrypt                       "OIDCCacheEncrypt"
#define OIDCCacheDir                           "OIDCCacheDir"
#define OIDCCacheFileCleanInterval             "OIDCCacheFileCleanInterval"
#define OIDCRedisCachePassword                 "OIDCRedisCachePassword"
#define OIDCHTMLErrorTemplate                  "OIDCHTMLErrorTemplate"
#define OIDCDiscoverURL                        "OIDCDiscoverURL"
#define OIDCPassCookies                        "OIDCPassCookies"
#define OIDCStripCookies                       "OIDCStripCookies"
#define OIDCAuthNHeader                        "OIDCAuthNHeader"
#define OIDCCookie                             "OIDCCookie"
#define OIDCUnAuthAction                       "OIDCUnAuthAction"
#define OIDCUnAutzAction                       "OIDCUnAutzAction"
#define OIDCPassClaimsAs                       "OIDCPassClaimsAs"
#define OIDCOAuthAcceptTokenAs                 "OIDCOAuthAcceptTokenAs"
#define OIDCUserInfoRefreshInterval            "OIDCUserInfoRefreshInterval"
#define OIDCOAuthTokenIntrospectionInterval    "OIDCOAuthTokenIntrospectionInterval"
#define OIDCPreservePost                       "OIDCPreservePost"
#define OIDCPassRefreshToken                   "OIDCPassRefreshToken"
#define OIDCRequestObject                      "OIDCRequestObject"
#define OIDCProviderMetadataRefreshInterval    "OIDCProviderMetadataRefreshInterval"
#define OIDCProviderAuthRequestMethod          "OIDCProviderAuthRequestMethod"
#define OIDCBlackListedClaims                  "OIDCBlackListedClaims"
#define OIDCOAuthServerMetadataURL             "OIDCOAuthServerMetadataURL"
#define OIDCOAuthAccessTokenBindingPolicy      "OIDCOAuthAccessTokenBindingPolicy"
#define OIDCRefreshAccessTokenBeforeExpiry     "OIDCRefreshAccessTokenBeforeExpiry"
#define OIDCStateInputHeaders                  "OIDCStateInputHeaders"
#define OIDCRedirectURLsAllowed                "OIDCRedirectURLsAllowed"
#define OIDCStateCookiePrefix                  "OIDCStateCookiePrefix"
#define OIDCCABundlePath                       "OIDCCABundlePath"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

/*
 * directory related configuration
 */
typedef struct oidc_dir_cfg {
	char *discover_url;
	char *cookie_path;
	char *cookie;
	char *authn_header;
	int unauth_action;
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_expr_info_t *unauth_expression;
#endif
	int unautz_action;
	apr_array_header_t *pass_cookies;
	apr_array_header_t *strip_cookies;
	int pass_info_in_headers;
	int pass_info_in_env_vars;
	int oauth_accept_token_in;
	apr_hash_t *oauth_accept_token_options;
	int oauth_token_introspect_interval;
	int preserve_post;
	int pass_refresh_token;
	char *path_auth_request_params;
	char *path_scope;
	int refresh_access_token_before_expiry;
	int logout_on_error_refresh;
	char *state_cookie_prefix;
} oidc_dir_cfg;

#define OIDC_CONFIG_DIR_RV(cmd, rv) rv != NULL ? apr_psprintf(cmd->pool, "Invalid value for directive '%s': %s", cmd->directive->directive, rv) : NULL

/*
 * set a boolean value in the server config
 */
static const char *oidc_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	return ap_set_flag_slot(cmd, cfg, arg);
}

/*
 * set a string value in the server config
 */
static const char *oidc_set_string_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	return ap_set_string_slot(cmd, cfg, arg);
}

/*
 * set an integer value in the server config
 */
static const char *oidc_set_int_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	return ap_set_int_slot(cmd, cfg, arg);
}

/*
 * set a URL value in a config record
 */
static const char *oidc_set_url_slot_type(cmd_parms *cmd, void *ptr,
		const char *arg, const char *type) {
	const char *rv =
			type != NULL ?
					oidc_valid_url(cmd->pool, arg, type) :
					oidc_valid_http_url(cmd->pool, arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, ptr, arg);
	return rv;
}

/*
 * set a HTTPS value in the server config
 */
static const char *oidc_set_https_slot(cmd_parms *cmd, void *ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	return oidc_set_url_slot_type(cmd, cfg, arg, "https");
}

/*
 * set a HTTPS/HTTP value in the server config
 */
static const char *oidc_set_url_slot(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	return oidc_set_url_slot_type(cmd, cfg, arg, NULL);
}

/*
 * set a relative or absolute URL value in a config rec
 */
static const char *oidc_set_relative_or_absolute_url_slot_dir_cfg(
		cmd_parms *cmd, void *ptr, const char *arg) {
	if (arg[0] == OIDC_CHAR_FORWARD_SLASH) {
		// relative uri
		apr_uri_t uri;
		if (apr_uri_parse(cmd->pool, arg, &uri) != APR_SUCCESS) {
			const char *rv = apr_psprintf(cmd->pool,
					"cannot parse '%s' as relative URI", arg);
			return OIDC_CONFIG_DIR_RV(cmd, rv);
		} else {
			return ap_set_string_slot(cmd, ptr, arg);
		}
	} else {
		// absolute uri
		return oidc_set_url_slot_type(cmd, ptr, arg, NULL);
	}
}

/*
 * set a relative or absolute URL value in the server config
 */
static const char *oidc_set_relative_or_absolute_url_slot(cmd_parms *cmd,
		void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	return oidc_set_relative_or_absolute_url_slot_dir_cfg(cmd, cfg, arg);
}

/*
 * set a directory value in the server config
 */
// TODO: it's not really a syntax error... (could be fixed at runtime but then we'd have to restart the server)
static const char *oidc_set_dir_slot(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_valid_dir(cmd->pool, arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, cfg, arg);
	return rv;
}

/*
 * set a path value in the server config, converting to absolute if necessary
 */
static const char *oidc_set_path_slot(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *full_path = oidc_util_get_full_path(cmd->pool, arg);
	return ap_set_string_slot(cmd, cfg, full_path);
}

/*
 * set a string value in the server config with exec support
 */
static const char *oidc_set_passphrase_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	int arglen = strlen(arg);
	char **argv;
	char *result;
	const char *passphrase;
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);

	/* Based on code from mod_session_crypto. */
	if (arglen > 5 && strncmp(arg, "exec:", 5) == 0) {
		if (apr_tokenize_to_argv(arg + 5, &argv, cmd->temp_pool) != APR_SUCCESS) {
			return apr_pstrcat(cmd->pool,
				"Unable to parse exec arguments from ", arg + 5, NULL);
		}
		argv[0] = ap_server_root_relative(cmd->temp_pool, argv[0]);

		if (!argv[0]) {
			return apr_pstrcat(cmd->pool,
				"Invalid ", cmd->cmd->name, " exec location:", arg + 5, NULL);
		}
		result = ap_get_exec_line(cmd->pool, argv[0], (const char * const *)argv);

		if (!result) {
			return apr_pstrcat(cmd->pool,
				"Unable to get passphrase from exec of ", arg + 5, NULL);
		}

		passphrase = result;
	} else {
		passphrase = arg;
	}

	return ap_set_string_slot(cmd, cfg, passphrase);
}

/*
 * set the cookie domain in the server config and check it syntactically
 */
static const char *oidc_set_cookie_domain(cmd_parms *cmd, void *ptr,
		const char *value) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_valid_cookie_domain(cmd->pool, value);
	if (rv == NULL)
		cfg->cookie_domain = apr_pstrdup(cmd->pool, value);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the session storage type
 */
static const char *oidc_set_session_type(cmd_parms *cmd, void *ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_session_type(cmd->pool, arg, &cfg->session_type,
			&cfg->persistent_session_cookie);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the maximum size of a shared memory cache entry and enforces a minimum
 */
static const char *oidc_set_cache_shm_entry_size_max(cmd_parms *cmd, void *ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_cache_shm_entry_size_max(cmd->pool, arg,
			&cfg->cache_shm_entry_size_max);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the cache type
 */
static const char *oidc_set_cache_type(cmd_parms *cmd, void *ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_cache_type(cmd->pool, arg, &cfg->cache);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set SSL validation slot
 */
static const char *oidc_set_ssl_validate_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	int b = 0;
	const char *rv = oidc_parse_boolean(cmd->pool, arg, &b);
	if (rv == NULL)
		rv = ap_set_flag_slot(cmd, cfg, b);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set validate issuer slot
 */
static const char *oidc_set_validate_issuer_slot(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	int b = 0;
	const char *rv = oidc_parse_boolean(cmd->pool, arg, &b);
	if (rv == NULL)
		rv = ap_set_flag_slot(cmd, cfg, b);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * return the right token endpoint authentication method validation function, based on whether private keys are set
 */
oidc_valid_function_t oidc_cfg_get_valid_endpoint_auth_function(oidc_cfg *cfg) {
	return (cfg->private_keys != NULL) ?
			oidc_valid_endpoint_auth_method :
			oidc_valid_endpoint_auth_method_no_private_key;
}

/*
 * set an authentication method for an endpoint and check it is one that we support
 */
static const char *oidc_set_endpoint_auth_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_cfg_get_valid_endpoint_auth_function(cfg)(cmd->pool,
			arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, cfg, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the response type used
 */
static const char *oidc_set_response_type(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);

	const char *rv = oidc_valid_response_type(cmd->pool, arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, cfg, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

const char *oidc_parse_pkce_type(apr_pool_t *pool, const char *arg,
		oidc_proto_pkce_t **type) {
	const char *rv = oidc_valid_pkce_method(pool, arg);
	if (rv != NULL)
		return rv;

	if (apr_strnatcmp(arg, OIDC_PKCE_METHOD_PLAIN) == 0) {
		*type = &oidc_pkce_plain;
	} else if (apr_strnatcmp(arg, OIDC_PKCE_METHOD_S256) == 0) {
		*type = &oidc_pkce_s256;
	} else if (apr_strnatcmp(arg, OIDC_PKCE_METHOD_REFERRED_TB) == 0) {
		*type = &oidc_pkce_referred_tb;
	}

	return NULL;
}

/*
 * define the PCKE method to use
 */
static const char *oidc_set_pkce_method(cmd_parms *cmd, void *ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_pkce_type(cmd->pool, arg, &cfg->provider.pkce);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the response mode used
 */
static const char *oidc_set_response_mode(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);

	const char *rv = oidc_valid_response_mode(cmd->pool, arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, cfg, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the signing algorithm to be used by the OP (id_token/user_info)
 */
static const char *oidc_set_signed_response_alg(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_valid_signed_response_alg(cmd->pool, arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, cfg, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the Content Encryption Key encryption algorithm to be used by the OP (id_token/user_info)
 */
static const char *oidc_set_encrypted_response_alg(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_valid_encrypted_response_alg(cmd->pool, arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, cfg, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the content encryption algorithm to be used by the OP (id_token/user_info)
 */
static const char *oidc_set_encrypted_response_enc(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_valid_encrypted_response_enc(cmd->pool, arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, cfg, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the userinfo endpoint token presentation method
 */
static const char *oidc_set_userinfo_token_method(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_userinfo_token_method(cmd->pool, arg,
			&cfg->provider.userinfo_token_method);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the session inactivity timeout
 */
static const char *oidc_set_session_inactivity_timeout(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_session_inactivity_timeout(cmd->pool, arg,
			&cfg->session_inactivity_timeout);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the maximum session duration; 0 means take it from the ID token expiry time
 */
static const char *oidc_set_session_max_duration(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_session_max_duration(cmd->pool, arg,
			&cfg->provider.session_max_duration);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

typedef struct oidc_cleanup_keys_ctx {
	apr_pool_t *pool;
	apr_hash_t *keys;
} oidc_cleanup_keys_ctx;

static apr_status_t oidc_cleanup_keys(void *data) {
	oidc_cleanup_keys_ctx *ctx = (oidc_cleanup_keys_ctx *) data;
	oidc_jwk_t *jwk = NULL;
	apr_hash_index_t *hi;
	for (hi = apr_hash_first(ctx->pool, ctx->keys); hi;
			hi = apr_hash_next(hi)) {
		apr_hash_this(hi, NULL, NULL, (void **) &jwk);
		oidc_jwk_destroy(jwk);
	}
	return APR_SUCCESS;
}

/*
 * add a public key from an X.509 file to our list of JWKs with public keys
 */
static const char *oidc_set_public_key_files(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;

	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);

	int offset = (int) (long) cmd->info;
	apr_hash_t **public_keys = (apr_hash_t **) ((char *) cfg + offset);

	char *kid = NULL, *fname = NULL;
	int fname_len;
	const char *rv = oidc_parse_enc_kid_key_tuple(cmd->pool, arg, &kid, &fname,
			&fname_len, FALSE);
	if (rv != NULL)
		return rv;

	fname = oidc_util_get_full_path(cmd->pool, fname);

	if (oidc_jwk_parse_rsa_public_key(cmd->pool, kid, fname, &jwk, &err)
			== FALSE) {
		return apr_psprintf(cmd->pool,
				"oidc_jwk_parse_rsa_public_key failed for (kid=%s) \"%s\": %s",
				kid, fname, oidc_jose_e2s(cmd->pool, err));
	}

	if (*public_keys == NULL) {
		*public_keys = apr_hash_make(cmd->pool);
		oidc_cleanup_keys_ctx *ctx = apr_pcalloc(cmd->pool,
				sizeof(oidc_cleanup_keys_ctx));
		ctx->pool = cmd->pool;
		ctx->keys = *public_keys;
		apr_pool_cleanup_register(cmd->pool, ctx, oidc_cleanup_keys,
				oidc_cleanup_keys);
	}
	apr_hash_set(*public_keys, jwk->kid, APR_HASH_KEY_STRING, jwk);

	return NULL;
}

/*
 * add a shared key to a list of JWKs with shared keys
 */
static const char *oidc_set_shared_keys(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;

	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	int offset = (int) (long) cmd->info;
	apr_hash_t **shared_keys = (apr_hash_t **) ((char *) cfg + offset);

	char *kid = NULL, *secret = NULL;
	int key_len = 0;
	const char *rv = oidc_parse_enc_kid_key_tuple(cmd->pool, arg, &kid, &secret,
			&key_len, TRUE);
	if (rv != NULL)
		return rv;

	jwk = oidc_jwk_create_symmetric_key(cmd->pool, kid,
			(const unsigned char *) secret, key_len, TRUE, &err);
	if (jwk == NULL) {
		return apr_psprintf(cmd->pool,
				"oidc_jwk_create_symmetric_key failed for (kid=%s) \"%s\": %s",
				kid, secret, oidc_jose_e2s(cmd->pool, err));
	}

	if (*shared_keys == NULL)
		*shared_keys = apr_hash_make(cmd->pool);
	apr_hash_set(*shared_keys, jwk->kid,
			APR_HASH_KEY_STRING, jwk);

	return NULL;
}

/*
 * add a private key from an RSA private key file to our list of JWKs with private keys
 */
static const char *oidc_set_private_key_files_enc(cmd_parms *cmd, void *dummy,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	oidc_jwk_t *jwk = NULL;
	oidc_jose_error_t err;

	char *kid = NULL, *fname = NULL;
	int fname_len;
	const char *rv = oidc_parse_enc_kid_key_tuple(cmd->pool, arg, &kid, &fname,
			&fname_len, FALSE);
	if (rv != NULL)
		return rv;

	fname = oidc_util_get_full_path(cmd->pool, fname);

	if (oidc_jwk_parse_rsa_private_key(cmd->pool, kid, fname, &jwk, &err)
			== FALSE) {
		return apr_psprintf(cmd->pool,
				"oidc_jwk_parse_rsa_private_key failed for (kid=%s) \"%s\": %s",
				kid, fname, oidc_jose_e2s(cmd->pool, err));
	}

	if (cfg->private_keys == NULL) {
		cfg->private_keys = apr_hash_make(cmd->pool);
		oidc_cleanup_keys_ctx *ctx = apr_pcalloc(cmd->pool,
				sizeof(oidc_cleanup_keys_ctx));
		ctx->pool = cmd->pool;
		ctx->keys = cfg->private_keys;
		apr_pool_cleanup_register(cmd->pool, ctx, oidc_cleanup_keys,
				oidc_cleanup_keys);
	}

	apr_hash_set(cfg->private_keys, jwk->kid, APR_HASH_KEY_STRING, jwk);

	return NULL;
}

/*
 * define how to pass the id_token/claims in HTTP headers
 */
static const char * oidc_set_pass_idtoken_as(cmd_parms *cmd, void *dummy,
		const char *v1, const char *v2, const char *v3) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_pass_idtoken_as(cmd->pool, v1, v2, v3,
			&cfg->pass_idtoken_as);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * define how to pass the userinfo/claims in HTTP headers
 */
static const char * oidc_set_pass_userinfo_as(cmd_parms *cmd, void *dummy,
		const char *v1, const char *v2, const char *v3) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_pass_userinfo_as(cmd->pool, v1, v2, v3,
			&cfg->pass_userinfo_as);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * define which method of pass an OAuth Bearer token is accepted
 */
static const char * oidc_set_accept_oauth_token_in(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_dir_cfg *dir_cfg = (oidc_dir_cfg *) m;
	const char *rv = oidc_parse_accept_oauth_token_in(cmd->pool, arg,
			&dir_cfg->oauth_accept_token_in,
			dir_cfg->oauth_accept_token_options);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the syntax of the token expiry claim in the introspection response
 */
static const char * oidc_set_token_expiry_claim(cmd_parms *cmd, void *dummy,
		const char *claim_name, const char *claim_format,
		const char *claim_required) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);

	const char *rv = NULL;

	cfg->oauth.introspection_token_expiry_claim_name = apr_pstrdup(cmd->pool,
			claim_name);

	if ((rv == NULL) && (claim_format != NULL)) {
		rv = oidc_valid_claim_format(cmd->pool, claim_format);
		if (rv == NULL)
			cfg->oauth.introspection_token_expiry_claim_format = apr_pstrdup(
					cmd->pool, claim_format);
	}

	if ((rv == NULL) && (claim_required != NULL)) {
		rv = oidc_parse_claim_required(cmd->pool, claim_required,
				&cfg->oauth.introspection_token_expiry_claim_required);
	}

	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * specify cookies names to pass/strip
 */
static const char * oidc_set_cookie_names(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_dir_cfg *dir_cfg = (oidc_dir_cfg *) m;
	int offset = (int) (long) cmd->info;
	apr_array_header_t **cookie_names =
			(apr_array_header_t **) ((char *) dir_cfg + offset);
	if (*cookie_names == NULL)
		*cookie_names = apr_array_make(cmd->pool, 3, sizeof(const char *));
	*(const char**) apr_array_push((*cookie_names)) = arg;
	return NULL;
}

/*
 * set the HTTP method to use in an OAuth 2.0 token introspection/validation call
 */
static const char * oidc_set_introspection_method(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_valid_introspection_method(cmd->pool, arg);
	if (rv == NULL)
		rv = ap_set_string_slot(cmd, cfg, arg);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set POST preservation behavior
 */
static const char *oidc_set_preserve_post(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_dir_cfg *dir_cfg = (oidc_dir_cfg *) m;
	int b = 0;
	const char *rv = oidc_parse_boolean(cmd->pool, arg, &b);
	if (rv == NULL)
		rv = ap_set_flag_slot(cmd, dir_cfg, b);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the remote user name claims, optionally plus the regular expression applied to it
 */
static const char *oidc_set_remote_user_claim(cmd_parms *cmd, void *struct_ptr,
		const char *v1, const char *v2, const char *v3) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);

	int offset = (int) (long) cmd->info;
	oidc_remote_user_claim_t *remote_user_claim =
			(oidc_remote_user_claim_t *) ((char *) cfg + offset);

	remote_user_claim->claim_name = v1;
	if (v2)
		remote_user_claim->reg_exp = v2;
	if (v3)
		remote_user_claim->replace = v3;

	return NULL;
}

/*
 * define how to pass claims information to the application: in headers and/or environment variables
 */
static const char * oidc_set_pass_claims_as(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_dir_cfg *dir_cfg = (oidc_dir_cfg *) m;
	const char *rv = oidc_parse_set_claims_as(cmd->pool, arg,
			&dir_cfg->pass_info_in_headers, &dir_cfg->pass_info_in_env_vars);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * define how to act on unauthenticated requests
 */
static const char * oidc_set_unauth_action(cmd_parms *cmd, void *m,
		const char *arg1, const char *arg2) {
	oidc_dir_cfg *dir_cfg = (oidc_dir_cfg *) m;
	const char *rv = oidc_parse_unauth_action(cmd->pool, arg1,
			&dir_cfg->unauth_action);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	const char *expr_err = NULL;
	if ((rv == NULL) && (arg2 != NULL)) {
		dir_cfg->unauth_expression = ap_expr_parse_cmd(cmd, arg2,
				AP_EXPR_FLAG_DONT_VARY & AP_EXPR_FLAG_RESTRICTED, &expr_err,
				NULL);
		if (expr_err != NULL) {
			rv = apr_pstrcat(cmd->temp_pool, "cannot parse expression: ",
					expr_err, NULL);
		}
	}
#endif
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * define how to act on unauthorized requests
 */
static const char * oidc_set_unautz_action(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_dir_cfg *dir_cfg = (oidc_dir_cfg *) m;
	const char *rv = oidc_parse_unautz_action(cmd->pool, arg,
			&dir_cfg->unautz_action);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the JWKS refresh interval
 */
static const char *oidc_set_jwks_refresh_interval(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_jwks_refresh_interval(cmd->pool, arg,
			&cfg->provider.jwks_refresh_interval);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the ID token "iat" slack
 */
static const char *oidc_set_idtoken_iat_slack(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_idtoken_iat_slack(cmd->pool, arg,
			&cfg->provider.idtoken_iat_slack);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the userinfo refresh interval
 */
static const char *oidc_set_userinfo_refresh_interval(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_userinfo_refresh_interval(cmd->pool, arg,
			&cfg->provider.userinfo_refresh_interval);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * define which data will be returned from the info hook
 */
static const char * oidc_set_info_hook_data(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_info_hook_data(cmd->pool, arg,
			&cfg->info_hook_data);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

static const char * oidc_set_filtered_claims(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	int offset = (int) (long) cmd->info;
	apr_hash_t **list = (apr_hash_t **) ((char *) cfg + offset);
	if (*list == NULL)
		*list = apr_hash_make(cmd->pool);
	apr_hash_set(*list, arg, APR_HASH_KEY_STRING, arg);
	return NULL;
}

/*
 * set the token binding policy
 */
static const char *oidc_set_token_binding_policy(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	int offset = (int) (long) cmd->info;
	int *token_binding_policy = (int *) ((char *) cfg + offset);
	const char *rv = oidc_parse_token_binding_policy(cmd->pool, arg,
			token_binding_policy);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the claim prefix
 */
static const char *oidc_cfg_set_claim_prefix(cmd_parms *cmd, void *struct_ptr,
		const char *args) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	char *w = ap_getword_conf(cmd->pool, &args);
	if (*w == '\0' || *args != 0)
		cfg->claim_prefix = "";
	else
		cfg->claim_prefix = w;
	return NULL;
}

/*
 * get the claim prefix
 */
const char *oidc_cfg_claim_prefix(request_rec *r) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	if (cfg->claim_prefix == NULL)
		return OIDC_DEFAULT_CLAIM_PREFIX;
	return cfg->claim_prefix;
}

/*
 * set the HTTP method used to send the authentication request to the provider
 */
const char *oidc_set_auth_request_method(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_auth_request_method(cmd->pool, arg,
			&cfg->provider.auth_request_method);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * set the introspection authorization static bearer token
 */
static const char *oidc_set_client_auth_bearer_token(cmd_parms *cmd,
		void *struct_ptr, const char *args) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	char *w = ap_getword_conf(cmd->pool, &args);
	cfg->oauth.introspection_client_auth_bearer_token =
			(*w == '\0' || *args != 0) ? "" : w;
	return NULL;
}

/*
 * set the maximun number of parallel state cookies
 */
static const char *oidc_set_max_number_of_state_cookies(cmd_parms *cmd,
		void *struct_ptr, const char *arg1, const char *arg2) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_max_number_of_state_cookies(cmd->pool, arg1,
			arg2, &cfg->max_number_of_state_cookies,
			&cfg->delete_oldest_state_cookies);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

/*
 * return the maximun number of parallel state cookies
 */
int oidc_cfg_max_number_of_state_cookies(oidc_cfg *cfg) {
	if (cfg->max_number_of_state_cookies == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_MAX_NUMBER_OF_STATE_COOKIES;
	return cfg->max_number_of_state_cookies;
}

/*
 * return the number of oldest state cookies that need to be deleted
 */
int oidc_cfg_delete_oldest_state_cookies(oidc_cfg *cfg) {
	if (cfg->delete_oldest_state_cookies == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_DELETE_OLDEST_STATE_COOKIES;
	return cfg->delete_oldest_state_cookies;
}

/*
 * set the time in seconds that the access token needs to be valid for
 */
static const char * oidc_set_refresh_access_token_before_expiry(cmd_parms *cmd,
		void *m, const char *arg1, const char *arg2) {
	oidc_dir_cfg *dir_cfg = (oidc_dir_cfg *) m;
	const char *rv1 = oidc_parse_refresh_access_token_before_expiry(cmd->pool,
			arg1, &dir_cfg->refresh_access_token_before_expiry);
	if (rv1 != NULL)
		return apr_psprintf(cmd->pool, "Invalid value for directive '%s': %s",
				cmd->directive->directive, rv1);

	if (arg2) {
		const char *rv2 = oidc_parse_logout_on_error_refresh_as(cmd->pool, arg2,
				&dir_cfg->logout_on_error_refresh);
		return OIDC_CONFIG_DIR_RV(cmd, rv2);
	}

	return NULL;
}

/*
 * define which header we use for calculating the fingerprint of the state during authentication
 */
static const char * oidc_set_state_input_headers_as(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	const char *rv = oidc_parse_set_state_input_headers_as(cmd->pool, arg,
			&cfg->state_input_headers);
	return OIDC_CONFIG_DIR_RV(cmd, rv);
}

static const char * oidc_set_redirect_urls_allowed(cmd_parms *cmd, void *m,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_openidc_module);
	if (cfg->redirect_urls_allowed == NULL)
		cfg->redirect_urls_allowed = apr_hash_make(cmd->pool);
	apr_hash_set(cfg->redirect_urls_allowed, arg, APR_HASH_KEY_STRING, arg);
	return NULL;
}

int oidc_cfg_dir_refresh_access_token_before_expiry(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->refresh_access_token_before_expiry == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_REFRESH_ACCESS_TOKEN_BEFORE_EXPIRY;
	return dir_cfg->refresh_access_token_before_expiry;
}

int oidc_cfg_dir_logout_on_error_refresh(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->logout_on_error_refresh == OIDC_CONFIG_POS_INT_UNSET)
		return 0; // no mask
	return dir_cfg->logout_on_error_refresh;
}

char *oidc_cfg_dir_state_cookie_prefix(request_rec *r) {
    oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
                                                 &auth_openidc_module);
    if ((dir_cfg->state_cookie_prefix == NULL)
        || ((dir_cfg->state_cookie_prefix != NULL)
            && (apr_strnatcmp(dir_cfg->state_cookie_prefix, OIDC_CONFIG_STRING_UNSET)
                == 0)))
        return OIDC_DEFAULT_STATE_COOKIE_PREFIX;
    return dir_cfg->state_cookie_prefix;
}

void oidc_cfg_provider_init(oidc_provider_t *provider) {
	provider->metadata_url = NULL;
	provider->issuer = NULL;
	provider->authorization_endpoint_url = NULL;
	provider->token_endpoint_url = NULL;
	provider->token_endpoint_auth = NULL;
	provider->token_endpoint_params = NULL;
	provider->userinfo_endpoint_url = NULL;
	provider->revocation_endpoint_url = NULL;
	provider->client_id = NULL;
	provider->client_secret = NULL;
	provider->token_endpoint_tls_client_cert = NULL;
	provider->token_endpoint_tls_client_key = NULL;
	provider->registration_endpoint_url = NULL;
	provider->registration_endpoint_json = NULL;
	provider->check_session_iframe = NULL;
	provider->end_session_endpoint = NULL;
	provider->jwks_uri = NULL;
	provider->backchannel_logout_supported = OIDC_CONFIG_POS_INT_UNSET;

	provider->ssl_validate_server = OIDC_DEFAULT_SSL_VALIDATE_SERVER;
	provider->validate_issuer = OIDC_DEFAULT_VALIDATE_ISSUER;
	provider->client_name = OIDC_DEFAULT_CLIENT_NAME;
	provider->client_contact = NULL;
	provider->registration_token = NULL;
	provider->scope = OIDC_DEFAULT_SCOPE;
	provider->response_type = OIDC_DEFAULT_RESPONSE_TYPE;
	provider->response_mode = NULL;
	provider->jwks_refresh_interval = OIDC_DEFAULT_JWKS_REFRESH_INTERVAL;
	provider->idtoken_iat_slack = OIDC_DEFAULT_IDTOKEN_IAT_SLACK;
	provider->session_max_duration = OIDC_DEFAULT_SESSION_MAX_DURATION;
	provider->auth_request_params = NULL;
	provider->pkce = NULL;

	provider->client_jwks_uri = NULL;
	provider->client_signing_keys = NULL;
	provider->client_encryption_keys = NULL;

	provider->id_token_signed_response_alg = NULL;
	provider->id_token_encrypted_response_alg = NULL;
	provider->id_token_encrypted_response_enc = NULL;
	provider->userinfo_signed_response_alg = NULL;
	provider->userinfo_encrypted_response_alg = NULL;
	provider->userinfo_encrypted_response_enc = NULL;
	provider->userinfo_token_method = OIDC_USER_INFO_TOKEN_METHOD_HEADER;
	provider->auth_request_method = OIDC_DEFAULT_AUTH_REQUEST_METHOD;
}

/*
 * create a new server config record with defaults
 */
void *oidc_create_server_config(apr_pool_t *pool, server_rec *svr) {
	oidc_cfg *c = apr_pcalloc(pool, sizeof(oidc_cfg));

	c->merged = FALSE;

	c->redirect_uri = NULL;
	c->default_sso_url = NULL;
	c->default_slo_url = NULL;
	c->public_keys = NULL;
	c->private_keys = NULL;

	oidc_cfg_provider_init(&c->provider);

	c->oauth.ssl_validate_server = OIDC_DEFAULT_SSL_VALIDATE_SERVER;
	c->oauth.metadata_url = NULL;
	c->oauth.client_id = NULL;
	c->oauth.client_secret = NULL;
	c->oauth.introspection_endpoint_tls_client_cert = NULL;
	c->oauth.introspection_endpoint_tls_client_key = NULL;
	c->oauth.introspection_endpoint_url = NULL;
	c->oauth.introspection_endpoint_method = OIDC_DEFAULT_OAUTH_ENDPOINT_METHOD;
	c->oauth.introspection_endpoint_params = NULL;
	c->oauth.introspection_endpoint_auth = NULL;
	c->oauth.introspection_client_auth_bearer_token = NULL;
	c->oauth.introspection_token_param_name =
			OIDC_DEFAULT_OAUTH_TOKEN_PARAM_NAME;

	c->oauth.introspection_token_expiry_claim_name =
			OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME;
	c->oauth.introspection_token_expiry_claim_format =
			OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT;
	c->oauth.introspection_token_expiry_claim_required =
			OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED;

	c->oauth.remote_user_claim.claim_name =
			OIDC_DEFAULT_OAUTH_CLAIM_REMOTE_USER;
	c->oauth.remote_user_claim.reg_exp = NULL;
	c->oauth.remote_user_claim.replace = NULL;

	c->oauth.verify_jwks_uri = NULL;
	c->oauth.verify_public_keys = NULL;
	c->oauth.verify_shared_keys = NULL;

	c->oauth.access_token_binding_policy =
			OIDC_DEFAULT_OAUTH_ACCESS_TOKEN_BINDING_POLICY;

	c->cache = &oidc_cache_shm;
	c->cache_cfg = NULL;
	c->cache_encrypt = OIDC_CONFIG_POS_INT_UNSET;

	c->cache_file_dir = NULL;
	c->cache_file_clean_interval = OIDC_DEFAULT_CACHE_FILE_CLEAN_INTERVAL;
#ifdef USE_MEMCACHE
	c->cache_memcache_servers = NULL;
#endif
	c->cache_shm_size_max = OIDC_DEFAULT_CACHE_SHM_SIZE;
	c->cache_shm_entry_size_max = OIDC_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX;
#ifdef USE_LIBHIREDIS
	c->cache_redis_server = NULL;
	c->cache_redis_password = NULL;
#endif

	c->metadata_dir = NULL;
	c->session_type = OIDC_DEFAULT_SESSION_TYPE;
	c->session_cache_fallback_to_cookie = OIDC_CONFIG_POS_INT_UNSET;
	c->persistent_session_cookie = 0;
	c->session_cookie_chunk_size =
			OIDC_DEFAULT_SESSION_CLIENT_COOKIE_CHUNK_SIZE;

	c->http_timeout_long = OIDC_DEFAULT_HTTP_TIMEOUT_LONG;
	c->http_timeout_short = OIDC_DEFAULT_HTTP_TIMEOUT_SHORT;
	c->state_timeout = OIDC_DEFAULT_STATE_TIMEOUT;
	c->max_number_of_state_cookies = OIDC_CONFIG_POS_INT_UNSET;
	c->delete_oldest_state_cookies = OIDC_CONFIG_POS_INT_UNSET;
	c->session_inactivity_timeout = OIDC_DEFAULT_SESSION_INACTIVITY_TIMEOUT;

	c->cookie_domain = NULL;
	c->claim_delimiter = OIDC_DEFAULT_CLAIM_DELIMITER;
	c->claim_prefix = NULL;
	c->remote_user_claim.claim_name = OIDC_DEFAULT_CLAIM_REMOTE_USER;
	c->remote_user_claim.reg_exp = NULL;
	c->remote_user_claim.replace = NULL;
	c->pass_idtoken_as = OIDC_PASS_IDTOKEN_AS_CLAIMS;
	c->pass_userinfo_as = OIDC_PASS_USERINFO_AS_CLAIMS;
	c->cookie_http_only = OIDC_DEFAULT_COOKIE_HTTPONLY;
	c->cookie_same_site = OIDC_DEFAULT_COOKIE_SAME_SITE;

	c->outgoing_proxy = NULL;
	c->crypto_passphrase = NULL;

	c->error_template = NULL;

	c->provider.userinfo_refresh_interval =
			OIDC_DEFAULT_USERINFO_REFRESH_INTERVAL;
	c->provider.request_object = NULL;

	c->provider_metadata_refresh_interval =
			OIDC_DEFAULT_PROVIDER_METADATA_REFRESH_INTERVAL;

	c->provider.token_binding_policy =
			OIDC_DEFAULT_PROVIDER_TOKEN_BINDING_POLICY;

	c->info_hook_data = NULL;
	c->black_listed_claims = NULL;
	c->white_listed_claims = NULL;

	c->provider.issuer_specific_redirect_uri =
			OIDC_DEFAULT_PROVIDER_ISSUER_SPECIFIC_REDIRECT_URI;

	c->state_input_headers = OIDC_DEFAULT_STATE_INPUT_HEADERS;

	c->redirect_urls_allowed = NULL;

	c->ca_bundle_path = NULL;

	return c;
}

/*
 * merge a new server config with a base one
 */
void *oidc_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_cfg *c = apr_pcalloc(pool, sizeof(oidc_cfg));
	oidc_cfg *base = BASE;
	oidc_cfg *add = ADD;

	c->merged = TRUE;

	c->redirect_uri =
			add->redirect_uri != NULL ? add->redirect_uri : base->redirect_uri;
	c->default_sso_url =
			add->default_sso_url != NULL ?
					add->default_sso_url : base->default_sso_url;
	c->default_slo_url =
			add->default_slo_url != NULL ?
					add->default_slo_url : base->default_slo_url;
	c->public_keys =
			add->public_keys != NULL ? add->public_keys : base->public_keys;
	c->private_keys =
			add->private_keys != NULL ? add->private_keys : base->private_keys;

	c->provider.metadata_url =
			add->provider.metadata_url != NULL ?
					add->provider.metadata_url : base->provider.metadata_url;
	c->provider.issuer =
			add->provider.issuer != NULL ?
					add->provider.issuer : base->provider.issuer;
	c->provider.authorization_endpoint_url =
			add->provider.authorization_endpoint_url != NULL ?
					add->provider.authorization_endpoint_url :
					base->provider.authorization_endpoint_url;
	c->provider.token_endpoint_url =
			add->provider.token_endpoint_url != NULL ?
					add->provider.token_endpoint_url :
					base->provider.token_endpoint_url;
	c->provider.token_endpoint_auth =
			add->provider.token_endpoint_auth != NULL ?
					add->provider.token_endpoint_auth :
					base->provider.token_endpoint_auth;
	c->provider.token_endpoint_params =
			add->provider.token_endpoint_params != NULL ?
					add->provider.token_endpoint_params :
					base->provider.token_endpoint_params;
	c->provider.userinfo_endpoint_url =
			add->provider.userinfo_endpoint_url != NULL ?
					add->provider.userinfo_endpoint_url :
					base->provider.userinfo_endpoint_url;
	c->provider.revocation_endpoint_url =
			add->provider.revocation_endpoint_url != NULL ?
					add->provider.revocation_endpoint_url :
					base->provider.revocation_endpoint_url;
	c->provider.jwks_uri =
			add->provider.jwks_uri != NULL ?
					add->provider.jwks_uri : base->provider.jwks_uri;
	c->provider.client_id =
			add->provider.client_id != NULL ?
					add->provider.client_id : base->provider.client_id;
	c->provider.client_secret =
			add->provider.client_secret != NULL ?
					add->provider.client_secret : base->provider.client_secret;

	c->provider.token_endpoint_tls_client_key =
			add->provider.token_endpoint_tls_client_key != NULL ?
					add->provider.token_endpoint_tls_client_key :
					base->provider.token_endpoint_tls_client_key;
	c->provider.token_endpoint_tls_client_cert =
			add->provider.token_endpoint_tls_client_cert != NULL ?
					add->provider.token_endpoint_tls_client_cert :
					base->provider.token_endpoint_tls_client_cert;

	c->provider.registration_endpoint_url =
			add->provider.registration_endpoint_url != NULL ?
					add->provider.registration_endpoint_url :
					base->provider.registration_endpoint_url;
	c->provider.registration_endpoint_json =
			add->provider.registration_endpoint_json != NULL ?
					add->provider.registration_endpoint_json :
					base->provider.registration_endpoint_json;

	c->provider.check_session_iframe =
			add->provider.check_session_iframe != NULL ?
					add->provider.check_session_iframe :
					base->provider.check_session_iframe;
	c->provider.end_session_endpoint =
			add->provider.end_session_endpoint != NULL ?
					add->provider.end_session_endpoint :
					base->provider.end_session_endpoint;
	c->provider.backchannel_logout_supported =
			add->provider.backchannel_logout_supported
			!= OIDC_CONFIG_POS_INT_UNSET ?
					add->provider.backchannel_logout_supported :
					base->provider.backchannel_logout_supported;

	c->provider.ssl_validate_server =
			add->provider.ssl_validate_server
			!= OIDC_DEFAULT_SSL_VALIDATE_SERVER ?
					add->provider.ssl_validate_server :
					base->provider.ssl_validate_server;
	c->provider.validate_issuer =
			add->provider.validate_issuer != OIDC_DEFAULT_VALIDATE_ISSUER ?
					add->provider.validate_issuer :
					base->provider.validate_issuer;
	c->provider.client_name =
			apr_strnatcmp(add->provider.client_name, OIDC_DEFAULT_CLIENT_NAME)
			!= 0 ?
					add->provider.client_name : base->provider.client_name;
	c->provider.client_contact =
			add->provider.client_contact != NULL ?
					add->provider.client_contact :
					base->provider.client_contact;
	c->provider.registration_token =
			add->provider.registration_token != NULL ?
					add->provider.registration_token :
					base->provider.registration_token;
	c->provider.scope =
			apr_strnatcmp(add->provider.scope, OIDC_DEFAULT_SCOPE) != 0 ?
					add->provider.scope : base->provider.scope;
	c->provider.response_type =
			apr_strnatcmp(add->provider.response_type,
					OIDC_DEFAULT_RESPONSE_TYPE) != 0 ?
							add->provider.response_type : base->provider.response_type;
	c->provider.response_mode =
			add->provider.response_mode != NULL ?
					add->provider.response_mode : base->provider.response_mode;
	c->provider.jwks_refresh_interval =
			add->provider.jwks_refresh_interval
			!= OIDC_DEFAULT_JWKS_REFRESH_INTERVAL ?
					add->provider.jwks_refresh_interval :
					base->provider.jwks_refresh_interval;
	c->provider.idtoken_iat_slack =
			add->provider.idtoken_iat_slack != OIDC_DEFAULT_IDTOKEN_IAT_SLACK ?
					add->provider.idtoken_iat_slack :
					base->provider.idtoken_iat_slack;
	c->provider.session_max_duration =
			add->provider.session_max_duration
			!= OIDC_DEFAULT_SESSION_MAX_DURATION ?
					add->provider.session_max_duration :
					base->provider.session_max_duration;
	c->provider.auth_request_params =
			add->provider.auth_request_params != NULL ?
					add->provider.auth_request_params :
					base->provider.auth_request_params;
	c->provider.pkce =
			add->provider.pkce != NULL ?
					add->provider.pkce : base->provider.pkce;

	c->provider.client_jwks_uri =
			add->provider.client_jwks_uri != NULL ?
					add->provider.client_jwks_uri :
					base->provider.client_jwks_uri;
	c->provider.client_signing_keys =
			add->provider.client_signing_keys != NULL ?
					add->provider.client_signing_keys :
					base->provider.client_signing_keys;
	c->provider.client_encryption_keys =
			add->provider.client_encryption_keys != NULL ?
					add->provider.client_encryption_keys :
					base->provider.client_encryption_keys;

	c->provider.id_token_signed_response_alg =
			add->provider.id_token_signed_response_alg != NULL ?
					add->provider.id_token_signed_response_alg :
					base->provider.id_token_signed_response_alg;
	c->provider.id_token_encrypted_response_alg =
			add->provider.id_token_encrypted_response_alg != NULL ?
					add->provider.id_token_encrypted_response_alg :
					base->provider.id_token_encrypted_response_alg;
	c->provider.id_token_encrypted_response_enc =
			add->provider.id_token_encrypted_response_enc != NULL ?
					add->provider.id_token_encrypted_response_enc :
					base->provider.id_token_encrypted_response_enc;
	c->provider.userinfo_signed_response_alg =
			add->provider.userinfo_signed_response_alg != NULL ?
					add->provider.userinfo_signed_response_alg :
					base->provider.userinfo_signed_response_alg;
	c->provider.userinfo_encrypted_response_alg =
			add->provider.userinfo_encrypted_response_alg != NULL ?
					add->provider.userinfo_encrypted_response_alg :
					base->provider.userinfo_encrypted_response_alg;
	c->provider.userinfo_encrypted_response_enc =
			add->provider.userinfo_encrypted_response_enc != NULL ?
					add->provider.userinfo_encrypted_response_enc :
					base->provider.userinfo_encrypted_response_enc;
	c->provider.userinfo_token_method =
			add->provider.userinfo_token_method
			!= OIDC_USER_INFO_TOKEN_METHOD_HEADER ?
					add->provider.userinfo_token_method :
					base->provider.userinfo_token_method;
	c->provider.auth_request_method =
			add->provider.auth_request_method
			!= OIDC_DEFAULT_AUTH_REQUEST_METHOD ?
					add->provider.auth_request_method :
					base->provider.auth_request_method;

	c->oauth.ssl_validate_server =
			add->oauth.ssl_validate_server != OIDC_DEFAULT_SSL_VALIDATE_SERVER ?
					add->oauth.ssl_validate_server :
					base->oauth.ssl_validate_server;
	c->oauth.metadata_url =
			add->oauth.metadata_url != NULL ?
					add->oauth.metadata_url : base->oauth.metadata_url;
	c->oauth.client_id =
			add->oauth.client_id != NULL ?
					add->oauth.client_id : base->oauth.client_id;
	c->oauth.client_secret =
			add->oauth.client_secret != NULL ?
					add->oauth.client_secret : base->oauth.client_secret;

	c->oauth.introspection_endpoint_tls_client_key =
			add->oauth.introspection_endpoint_tls_client_key != NULL ?
					add->oauth.introspection_endpoint_tls_client_key :
					base->oauth.introspection_endpoint_tls_client_key;
	c->oauth.introspection_endpoint_tls_client_cert =
			add->oauth.introspection_endpoint_tls_client_cert != NULL ?
					add->oauth.introspection_endpoint_tls_client_cert :
					base->oauth.introspection_endpoint_tls_client_cert;

	c->oauth.introspection_endpoint_url =
			add->oauth.introspection_endpoint_url != NULL ?
					add->oauth.introspection_endpoint_url :
					base->oauth.introspection_endpoint_url;
	c->oauth.introspection_endpoint_method =
			apr_strnatcmp(add->oauth.introspection_endpoint_method,
					OIDC_DEFAULT_OAUTH_ENDPOINT_METHOD) != 0 ?
							add->oauth.introspection_endpoint_method :
							base->oauth.introspection_endpoint_method;
	c->oauth.introspection_endpoint_params =
			add->oauth.introspection_endpoint_params != NULL ?
					add->oauth.introspection_endpoint_params :
					base->oauth.introspection_endpoint_params;
	c->oauth.introspection_endpoint_auth =
			add->oauth.introspection_endpoint_auth != NULL ?
					add->oauth.introspection_endpoint_auth :
					base->oauth.introspection_endpoint_auth;
	c->oauth.introspection_client_auth_bearer_token =
			add->oauth.introspection_client_auth_bearer_token != NULL ?
					add->oauth.introspection_client_auth_bearer_token :
					base->oauth.introspection_client_auth_bearer_token;
	c->oauth.introspection_token_param_name =
			apr_strnatcmp(add->oauth.introspection_token_param_name,
					OIDC_DEFAULT_OAUTH_TOKEN_PARAM_NAME) != 0 ?
							add->oauth.introspection_token_param_name :
							base->oauth.introspection_token_param_name;

	c->oauth.introspection_token_expiry_claim_name =
			apr_strnatcmp(add->oauth.introspection_token_expiry_claim_name,
					OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME) != 0 ?
							add->oauth.introspection_token_expiry_claim_name :
							base->oauth.introspection_token_expiry_claim_name;
	c->oauth.introspection_token_expiry_claim_format =
			apr_strnatcmp(add->oauth.introspection_token_expiry_claim_format,
					OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT) != 0 ?
							add->oauth.introspection_token_expiry_claim_format :
							base->oauth.introspection_token_expiry_claim_format;
	c->oauth.introspection_token_expiry_claim_required =
			add->oauth.introspection_token_expiry_claim_required
			!= OIDC_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED ?
					add->oauth.introspection_token_expiry_claim_required :
					base->oauth.introspection_token_expiry_claim_required;

	c->oauth.remote_user_claim.claim_name =
			apr_strnatcmp(add->oauth.remote_user_claim.claim_name,
					OIDC_DEFAULT_OAUTH_CLAIM_REMOTE_USER) != 0 ?
							add->oauth.remote_user_claim.claim_name :
							base->oauth.remote_user_claim.claim_name;
	c->oauth.remote_user_claim.reg_exp =
			add->oauth.remote_user_claim.reg_exp != NULL ?
					add->oauth.remote_user_claim.reg_exp :
					base->oauth.remote_user_claim.reg_exp;
	c->oauth.remote_user_claim.replace =
			add->oauth.remote_user_claim.replace != NULL ?
					add->oauth.remote_user_claim.replace :
					base->oauth.remote_user_claim.replace;

	c->oauth.verify_jwks_uri =
			add->oauth.verify_jwks_uri != NULL ?
					add->oauth.verify_jwks_uri : base->oauth.verify_jwks_uri;
	c->oauth.verify_public_keys =
			add->oauth.verify_public_keys != NULL ?
					add->oauth.verify_public_keys :
					base->oauth.verify_public_keys;
	c->oauth.verify_shared_keys =
			add->oauth.verify_shared_keys != NULL ?
					add->oauth.verify_shared_keys :
					base->oauth.verify_shared_keys;

	c->oauth.access_token_binding_policy =
			add->oauth.access_token_binding_policy
			!= OIDC_DEFAULT_OAUTH_ACCESS_TOKEN_BINDING_POLICY ?
					add->oauth.access_token_binding_policy :
					base->oauth.access_token_binding_policy;

	c->http_timeout_long =
			add->http_timeout_long != OIDC_DEFAULT_HTTP_TIMEOUT_LONG ?
					add->http_timeout_long : base->http_timeout_long;
	c->http_timeout_short =
			add->http_timeout_short != OIDC_DEFAULT_HTTP_TIMEOUT_SHORT ?
					add->http_timeout_short : base->http_timeout_short;
	c->state_timeout =
			add->state_timeout != OIDC_DEFAULT_STATE_TIMEOUT ?
					add->state_timeout : base->state_timeout;
	c->max_number_of_state_cookies =
			add->max_number_of_state_cookies != OIDC_CONFIG_POS_INT_UNSET ?
					add->max_number_of_state_cookies :
					base->max_number_of_state_cookies;
	c->delete_oldest_state_cookies =
			add->delete_oldest_state_cookies != OIDC_CONFIG_POS_INT_UNSET ?
					add->delete_oldest_state_cookies :
					base->delete_oldest_state_cookies;
	c->session_inactivity_timeout =
			add->session_inactivity_timeout
			!= OIDC_DEFAULT_SESSION_INACTIVITY_TIMEOUT ?
					add->session_inactivity_timeout :
					base->session_inactivity_timeout;

	if (add->cache != &oidc_cache_shm) {
		c->cache = add->cache;
	} else {
		c->cache = base->cache;
	}

	c->cache_encrypt =
			add->cache_encrypt != OIDC_CONFIG_POS_INT_UNSET ?
					add->cache_encrypt : base->cache_encrypt;

	c->cache_cfg = NULL;

	c->cache_file_dir =
			add->cache_file_dir != NULL ?
					add->cache_file_dir : base->cache_file_dir;
	c->cache_file_clean_interval =
			add->cache_file_clean_interval
			!= OIDC_DEFAULT_CACHE_FILE_CLEAN_INTERVAL ?
					add->cache_file_clean_interval :
					base->cache_file_clean_interval;

#ifdef USE_MEMCACHE
	c->cache_memcache_servers =
			add->cache_memcache_servers != NULL ?
					add->cache_memcache_servers : base->cache_memcache_servers;
#endif
	c->cache_shm_size_max =
			add->cache_shm_size_max != OIDC_DEFAULT_CACHE_SHM_SIZE ?
					add->cache_shm_size_max : base->cache_shm_size_max;
	c->cache_shm_entry_size_max =
			add->cache_shm_entry_size_max
			!= OIDC_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX ?
					add->cache_shm_entry_size_max :
					base->cache_shm_entry_size_max;

#ifdef USE_LIBHIREDIS
	c->cache_redis_server =
			add->cache_redis_server != NULL ?
					add->cache_redis_server : base->cache_redis_server;
	c->cache_redis_password =
			add->cache_redis_password != NULL ?
					add->cache_redis_password : base->cache_redis_password;
#endif

	c->metadata_dir =
			add->metadata_dir != NULL ? add->metadata_dir : base->metadata_dir;
	c->session_type =
			add->session_type != OIDC_DEFAULT_SESSION_TYPE ?
					add->session_type : base->session_type;
	c->session_cache_fallback_to_cookie =
			add->session_cache_fallback_to_cookie != OIDC_CONFIG_POS_INT_UNSET ?
					add->session_cache_fallback_to_cookie :
					base->session_cache_fallback_to_cookie;
	c->persistent_session_cookie =
			add->persistent_session_cookie != 0 ?
					add->persistent_session_cookie :
					base->persistent_session_cookie;
	c->session_cookie_chunk_size =
			add->session_cookie_chunk_size
			!= OIDC_DEFAULT_SESSION_CLIENT_COOKIE_CHUNK_SIZE ?
					add->session_cookie_chunk_size :
					base->session_cookie_chunk_size;

	c->cookie_domain =
			add->cookie_domain != NULL ?
					add->cookie_domain : base->cookie_domain;
	c->claim_delimiter =
			apr_strnatcmp(add->claim_delimiter, OIDC_DEFAULT_CLAIM_DELIMITER)
			!= 0 ? add->claim_delimiter : base->claim_delimiter;
	c->claim_prefix =
			add->claim_prefix != NULL ? add->claim_prefix : base->claim_prefix;
	c->remote_user_claim.claim_name =
			apr_strnatcmp(add->remote_user_claim.claim_name,
					OIDC_DEFAULT_CLAIM_REMOTE_USER) != 0 ?
							add->remote_user_claim.claim_name :
							base->remote_user_claim.claim_name;
	c->remote_user_claim.reg_exp =
			add->remote_user_claim.reg_exp != NULL ?
					add->remote_user_claim.reg_exp :
					base->remote_user_claim.reg_exp;
	c->remote_user_claim.replace =
			add->remote_user_claim.replace != NULL ?
					add->remote_user_claim.replace :
					base->remote_user_claim.replace;
	c->pass_idtoken_as =
			add->pass_idtoken_as != OIDC_PASS_IDTOKEN_AS_CLAIMS ?
					add->pass_idtoken_as : base->pass_idtoken_as;
	c->pass_userinfo_as =
			add->pass_userinfo_as != OIDC_PASS_USERINFO_AS_CLAIMS ?
					add->pass_userinfo_as : base->pass_userinfo_as;
	c->cookie_http_only =
			add->cookie_http_only != OIDC_DEFAULT_COOKIE_HTTPONLY ?
					add->cookie_http_only : base->cookie_http_only;
	c->cookie_same_site =
			add->cookie_same_site != OIDC_DEFAULT_COOKIE_SAME_SITE ?
					add->cookie_same_site : base->cookie_same_site;

	c->outgoing_proxy =
			add->outgoing_proxy != NULL ?
					add->outgoing_proxy : base->outgoing_proxy;

	c->crypto_passphrase =
			add->crypto_passphrase != NULL ?
					add->crypto_passphrase : base->crypto_passphrase;

	c->error_template =
			add->error_template != NULL ?
					add->error_template : base->error_template;

	c->provider.userinfo_refresh_interval =
			add->provider.userinfo_refresh_interval
			!= OIDC_DEFAULT_USERINFO_REFRESH_INTERVAL ?
					add->provider.userinfo_refresh_interval :
					base->provider.userinfo_refresh_interval;
	c->provider.request_object =
			add->provider.request_object != NULL ?
					add->provider.request_object :
					base->provider.request_object;

	c->provider_metadata_refresh_interval =
			add->provider_metadata_refresh_interval
			!= OIDC_DEFAULT_PROVIDER_METADATA_REFRESH_INTERVAL ?
					add->provider_metadata_refresh_interval :
					base->provider_metadata_refresh_interval;

	c->provider.token_binding_policy =
			add->provider.token_binding_policy
			!= OIDC_DEFAULT_PROVIDER_TOKEN_BINDING_POLICY ?
					add->provider.token_binding_policy :
					base->provider.token_binding_policy;

	c->info_hook_data =
			add->info_hook_data != NULL ?
					add->info_hook_data : base->info_hook_data;
	c->black_listed_claims =
			add->black_listed_claims != NULL ?
					add->black_listed_claims : base->black_listed_claims;
	c->white_listed_claims =
			add->white_listed_claims != NULL ?
					add->white_listed_claims : base->white_listed_claims;

	c->provider.issuer_specific_redirect_uri =
			add->provider.issuer_specific_redirect_uri
			!= OIDC_DEFAULT_PROVIDER_ISSUER_SPECIFIC_REDIRECT_URI ?
					add->provider.issuer_specific_redirect_uri :
					base->provider.issuer_specific_redirect_uri;

	c->state_input_headers =
			add->state_input_headers != OIDC_DEFAULT_STATE_INPUT_HEADERS ?
					add->state_input_headers : base->state_input_headers;

	c->redirect_urls_allowed =
			add->redirect_urls_allowed != NULL ?
					add->redirect_urls_allowed : base->redirect_urls_allowed;

	c->ca_bundle_path =
			add->ca_bundle_path != NULL ?
					add->ca_bundle_path : base->ca_bundle_path;

	return c;
}

int oidc_cfg_cache_encrypt(request_rec *r) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	if (cfg->cache_encrypt == OIDC_CONFIG_POS_INT_UNSET)
		return cfg->cache->encrypt_by_default;
	return cfg->cache_encrypt;
}

int oidc_cfg_session_cache_fallback_to_cookie(request_rec *r) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	if (cfg->session_cache_fallback_to_cookie == OIDC_CONFIG_POS_INT_UNSET)
		return 0;
	return cfg->session_cache_fallback_to_cookie;
}

/*
 * create a new directory config record with defaults
 */
void *oidc_create_dir_config(apr_pool_t *pool, char *path) {
	oidc_dir_cfg *c = apr_pcalloc(pool, sizeof(oidc_dir_cfg));
	c->discover_url = OIDC_CONFIG_STRING_UNSET;
	c->cookie = OIDC_CONFIG_STRING_UNSET;
	c->cookie_path = OIDC_CONFIG_STRING_UNSET;
	c->authn_header = OIDC_CONFIG_STRING_UNSET;
	c->unauth_action = OIDC_CONFIG_POS_INT_UNSET;
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	c->unauth_expression = NULL;
#endif
	c->unautz_action = OIDC_CONFIG_POS_INT_UNSET;
	c->pass_cookies = NULL;
	c->strip_cookies = NULL;
	c->pass_info_in_headers = OIDC_CONFIG_POS_INT_UNSET;
	c->pass_info_in_env_vars = OIDC_CONFIG_POS_INT_UNSET;
	c->oauth_accept_token_in = OIDC_CONFIG_POS_INT_UNSET;
	c->oauth_accept_token_options = apr_hash_make(pool);
	c->oauth_token_introspect_interval = -2;
	c->preserve_post = OIDC_CONFIG_POS_INT_UNSET;
	c->pass_refresh_token = OIDC_CONFIG_POS_INT_UNSET;
	c->path_auth_request_params = NULL;
	c->path_scope = NULL;
	c->refresh_access_token_before_expiry = OIDC_CONFIG_POS_INT_UNSET;
	c->logout_on_error_refresh = OIDC_CONFIG_POS_INT_UNSET;
	c->state_cookie_prefix = OIDC_CONFIG_STRING_UNSET;
	return (c);
}

char *oidc_cfg_dir_discover_url(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if ((dir_cfg->discover_url != NULL) && (apr_strnatcmp(dir_cfg->discover_url,
			OIDC_CONFIG_STRING_UNSET) == 0))
		return NULL;
	return dir_cfg->discover_url;
}

char *oidc_cfg_dir_cookie(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if ((dir_cfg->cookie == NULL)
			|| ((dir_cfg->cookie != NULL)
					&& (apr_strnatcmp(dir_cfg->cookie, OIDC_CONFIG_STRING_UNSET)
							== 0)))
		return OIDC_DEFAULT_COOKIE;
	return dir_cfg->cookie;
}

char *oidc_cfg_dir_cookie_path(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if ((dir_cfg->cookie_path == NULL)
			|| ((dir_cfg->cookie_path != NULL)
					&& (apr_strnatcmp(dir_cfg->cookie_path,
							OIDC_CONFIG_STRING_UNSET) == 0)))
		return OIDC_DEFAULT_COOKIE_PATH;
	return dir_cfg->cookie_path;
}

char *oidc_cfg_dir_authn_header(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if ((dir_cfg->authn_header == NULL)
			|| ((dir_cfg->authn_header != NULL)
					&& (apr_strnatcmp(dir_cfg->authn_header,
							OIDC_CONFIG_STRING_UNSET) == 0)))
		return OIDC_DEFAULT_AUTHN_HEADER;
	return dir_cfg->authn_header;
}

apr_byte_t oidc_cfg_dir_pass_info_in_headers(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->pass_info_in_headers == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_PASS_APP_INFO_IN_HEADERS;
	return dir_cfg->pass_info_in_headers;
}

apr_byte_t oidc_cfg_dir_pass_info_in_envvars(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->pass_info_in_env_vars == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_PASS_APP_INFO_IN_ENVVARS;
	return dir_cfg->pass_info_in_env_vars;
}

apr_byte_t oidc_cfg_dir_pass_refresh_token(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->pass_refresh_token == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_PASS_REFRESH_TOKEN;
	return dir_cfg->pass_refresh_token;
}

apr_byte_t oidc_cfg_dir_accept_token_in(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->oauth_accept_token_in == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT;
	return dir_cfg->oauth_accept_token_in;
}

char *oidc_cfg_dir_accept_token_in_option(request_rec *r, const char *key) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	return apr_hash_get(dir_cfg->oauth_accept_token_options, key,
			APR_HASH_KEY_STRING);
}

int oidc_cfg_token_introspection_interval(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->oauth_token_introspect_interval <= -2)
		return OIDC_DEFAULT_TOKEN_INTROSPECTION_INTERVAL;
	return dir_cfg->oauth_token_introspect_interval;
}

int oidc_cfg_dir_preserve_post(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->preserve_post == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_PRESERVE_POST;
	return dir_cfg->preserve_post;
}

apr_array_header_t *oidc_dir_cfg_pass_cookies(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	return dir_cfg->pass_cookies;
}

apr_array_header_t *oidc_dir_cfg_strip_cookies(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	return dir_cfg->strip_cookies;
}

int oidc_dir_cfg_unauth_action(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);

	if (dir_cfg->unauth_action == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_UNAUTH_ACTION;

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	int rc = 0;
	const char *err_str = NULL;
	if (dir_cfg->unauth_expression == NULL)
		return dir_cfg->unauth_action;

	rc = ap_expr_exec(r, dir_cfg->unauth_expression, &err_str);

	if (rc < 0) {
		oidc_warn(r, "executing expression failed");
		return OIDC_DEFAULT_UNAUTH_ACTION;
	}

	return (rc > 0) ? dir_cfg->unauth_action : OIDC_DEFAULT_UNAUTH_ACTION;
#else
	return dir_cfg->unauth_action;
#endif
}

apr_byte_t oidc_dir_cfg_unauth_expr_is_set(request_rec *r) {
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	return (dir_cfg->unauth_expression != NULL) ? TRUE : FALSE;
#else
	return FALSE;
#endif
}

int oidc_dir_cfg_unautz_action(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	if (dir_cfg->unautz_action == OIDC_CONFIG_POS_INT_UNSET)
		return OIDC_DEFAULT_UNAUTZ_ACTION;
	return dir_cfg->unautz_action;
}

char *oidc_dir_cfg_path_auth_request_params(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	return dir_cfg->path_auth_request_params;
}

char *oidc_dir_cfg_path_scope(request_rec *r) {
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config,
			&auth_openidc_module);
	return dir_cfg->path_scope;
}

/*
 * merge a new directory config with a base one
 */
void *oidc_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_dir_cfg *c = apr_pcalloc(pool, sizeof(oidc_dir_cfg));
	oidc_dir_cfg *base = BASE;
	oidc_dir_cfg *add = ADD;
	c->discover_url =
			(apr_strnatcmp(add->discover_url, OIDC_CONFIG_STRING_UNSET) != 0) ?
					add->discover_url : base->discover_url;
	c->cookie =
			(apr_strnatcmp(add->cookie, OIDC_CONFIG_STRING_UNSET) != 0) ?
					add->cookie : base->cookie;
	c->cookie_path =
			(apr_strnatcmp(add->cookie_path, OIDC_CONFIG_STRING_UNSET) != 0) ?
					add->cookie_path : base->cookie_path;
	c->authn_header =
			(apr_strnatcmp(add->authn_header, OIDC_CONFIG_STRING_UNSET) != 0) ?
					add->authn_header : base->authn_header;
	c->unauth_action =
			add->unauth_action != OIDC_CONFIG_POS_INT_UNSET ?
					add->unauth_action : base->unauth_action;
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	c->unauth_expression =
			add->unauth_expression != NULL ?
					add->unauth_expression : base->unauth_expression;
#endif
	c->unautz_action =
			add->unautz_action != OIDC_CONFIG_POS_INT_UNSET ?
					add->unautz_action : base->unautz_action;

	c->pass_cookies =
			add->pass_cookies != NULL ? add->pass_cookies : base->pass_cookies;
	c->strip_cookies =
			add->strip_cookies != NULL ?
					add->strip_cookies : base->strip_cookies;

	c->pass_info_in_headers =
			add->pass_info_in_headers != OIDC_CONFIG_POS_INT_UNSET ?
					add->pass_info_in_headers : base->pass_info_in_headers;
	c->pass_info_in_env_vars =
			add->pass_info_in_env_vars != OIDC_CONFIG_POS_INT_UNSET ?
					add->pass_info_in_env_vars : base->pass_info_in_env_vars;
	c->oauth_accept_token_in =
			add->oauth_accept_token_in != OIDC_CONFIG_POS_INT_UNSET ?
					add->oauth_accept_token_in : base->oauth_accept_token_in;
	c->oauth_accept_token_options =
			apr_hash_count(add->oauth_accept_token_options) > 0 ?
					add->oauth_accept_token_options :
					base->oauth_accept_token_options;
	c->oauth_token_introspect_interval =
			add->oauth_token_introspect_interval >= -1 ?
					add->oauth_token_introspect_interval :
					base->oauth_token_introspect_interval;
	c->preserve_post =
			add->preserve_post != OIDC_CONFIG_POS_INT_UNSET ?
					add->preserve_post : base->preserve_post;
	c->pass_refresh_token =
			add->pass_refresh_token != OIDC_CONFIG_POS_INT_UNSET ?
					add->pass_refresh_token : base->pass_refresh_token;
	c->path_auth_request_params =
			add->path_auth_request_params != NULL ?
					add->path_auth_request_params :
					base->path_auth_request_params;
	c->path_scope =
			add->path_scope != NULL ? add->path_scope : base->path_scope;

	c->refresh_access_token_before_expiry =
			add->refresh_access_token_before_expiry != OIDC_CONFIG_POS_INT_UNSET ?
					add->refresh_access_token_before_expiry :
					base->refresh_access_token_before_expiry;

	c->logout_on_error_refresh =
			add->logout_on_error_refresh != OIDC_CONFIG_POS_INT_UNSET ?
					add->logout_on_error_refresh :
					base->logout_on_error_refresh;

    c->state_cookie_prefix =
            (apr_strnatcmp(add->state_cookie_prefix, OIDC_CONFIG_STRING_UNSET) != 0) ?
            add->state_cookie_prefix : base->state_cookie_prefix;

	return (c);
}

/*
 * report a config error
 */
static int oidc_check_config_error(server_rec *s, const char *config_str) {
	oidc_serror(s, "mandatory parameter '%s' is not set", config_str);
	return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * check the config required for the OpenID Connect RP role
 */
static int oidc_check_config_openid_openidc(server_rec *s, oidc_cfg *c) {

	apr_uri_t r_uri;
	apr_byte_t redirect_uri_is_relative;

	if ((c->metadata_dir == NULL) && (c->provider.issuer == NULL)
			&& (c->provider.metadata_url == NULL)) {
		oidc_serror(s,
				"one of '" OIDCProviderIssuer "', '" OIDCProviderMetadataURL "' or '" OIDCMetadataDir "' must be set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (c->redirect_uri == NULL)
		return oidc_check_config_error(s, OIDCRedirectURI);
	redirect_uri_is_relative = (c->redirect_uri[0] == OIDC_CHAR_FORWARD_SLASH);

	if (c->crypto_passphrase == NULL)
		return oidc_check_config_error(s, OIDCCryptoPassphrase);

	if (c->metadata_dir == NULL) {
		if (c->provider.metadata_url == NULL) {
			if (c->provider.issuer == NULL)
				return oidc_check_config_error(s, OIDCProviderIssuer);
			if (c->provider.authorization_endpoint_url == NULL)
				return oidc_check_config_error(s,
						OIDCProviderAuthorizationEndpoint);
		} else {
			apr_uri_parse(s->process->pconf, c->provider.metadata_url, &r_uri);
			if ((r_uri.scheme == NULL)
					|| (apr_strnatcmp(r_uri.scheme, "https") != 0)) {
				oidc_swarn(s,
						"the URL scheme (%s) of the configured " OIDCProviderMetadataURL " SHOULD be \"https\" for security reasons!",
						r_uri.scheme);
			}
		}
		if (c->provider.client_id == NULL)
			return oidc_check_config_error(s, OIDCClientID);
	} else {
		if (c->provider.metadata_url != NULL) {
			oidc_serror(s,
					"only one of '" OIDCProviderMetadataURL "' or '" OIDCMetadataDir "' should be set");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	apr_uri_parse(s->process->pconf, c->redirect_uri, &r_uri);
	if (!redirect_uri_is_relative) {
		if (apr_strnatcmp(r_uri.scheme, "https") != 0) {
			oidc_swarn(s,
					"the URL scheme (%s) of the configured " OIDCRedirectURI " SHOULD be \"https\" for security reasons (moreover: some Providers may reject non-HTTPS URLs)",
					r_uri.scheme);
		}
	}

	if (c->cookie_domain != NULL) {
		if (redirect_uri_is_relative) {
			oidc_swarn(s,
					"if the configured " OIDCRedirectURI " is relative, " OIDCCookieDomain " SHOULD be empty");
		} else if (!oidc_util_cookie_domain_valid(r_uri.hostname,
				c->cookie_domain)) {
			oidc_serror(s,
					"the domain (%s) configured in " OIDCCookieDomain " does not match the URL hostname (%s) of the configured " OIDCRedirectURI " (%s): setting \"state\" and \"session\" cookies will not work!",
					c->cookie_domain, r_uri.hostname, c->redirect_uri);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	return OK;
}

/*
 * check the config required for the OAuth 2.0 RS role
 */
static int oidc_check_config_oauth(server_rec *s, oidc_cfg *c) {

	apr_uri_t r_uri;

	oidc_swarn(s,
			"The OAuth 2.0 Resource Server functionality is deprecated and superseded by a new module, see: https://github.com/zmartzone/mod_oauth2!");

	if (c->oauth.metadata_url != NULL) {
		apr_uri_parse(s->process->pconf, c->oauth.metadata_url, &r_uri);
		if ((r_uri.scheme == NULL)
				|| (apr_strnatcmp(r_uri.scheme, "https") != 0)) {
			oidc_swarn(s,
					"the URL scheme (%s) of the configured " OIDCOAuthServerMetadataURL " SHOULD be \"https\" for security reasons!",
					r_uri.scheme);
		}
		return OK;
	}

	if (c->oauth.introspection_endpoint_url == NULL) {

		if ((c->oauth.verify_jwks_uri == NULL)
				&& (c->oauth.verify_public_keys == NULL)
				&& (c->oauth.verify_shared_keys == NULL)) {
			oidc_serror(s,
					"one of '" OIDCOAuthServerMetadataURL "', '" OIDCOAuthIntrospectionEndpoint "', '" OIDCOAuthVerifyJwksUri "', '" OIDCOAuthVerifySharedKeys "' or '" OIDCOAuthVerifyCertFiles "' must be set");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

	} else if ((c->oauth.verify_jwks_uri != NULL)
			|| (c->oauth.verify_public_keys != NULL)
			|| (c->oauth.verify_shared_keys != NULL)) {
		oidc_serror(s,
				"only '" OIDCOAuthIntrospectionEndpoint "' OR one (or more) out of ('" OIDCOAuthVerifyJwksUri "', '" OIDCOAuthVerifySharedKeys "' or '" OIDCOAuthVerifyCertFiles "') must be set");
		return HTTP_INTERNAL_SERVER_ERROR;

	}

	if ((c->cache_encrypt == 1) && (c->crypto_passphrase == NULL))
		return oidc_check_config_error(s, OIDCCryptoPassphrase);

	return OK;
}

/*
 * check the config of a vhost
 */
static int oidc_config_check_vhost_config(apr_pool_t *pool, server_rec *s) {
	oidc_cfg *cfg = ap_get_module_config(s->module_config,
			&auth_openidc_module);

	oidc_sdebug(s, "enter");

	if ((cfg->metadata_dir != NULL) || (cfg->provider.issuer != NULL)
			|| (cfg->provider.metadata_url != NULL)) {
		if (oidc_check_config_openid_openidc(s, cfg) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((cfg->oauth.metadata_url != NULL) || (cfg->oauth.client_id != NULL)
			|| (cfg->oauth.client_secret != NULL)
			|| (cfg->oauth.introspection_endpoint_url != NULL)
			|| (cfg->oauth.verify_jwks_uri != NULL)
			|| (cfg->oauth.verify_public_keys != NULL)
			|| (cfg->oauth.verify_shared_keys != NULL)) {
		if (oidc_check_config_oauth(s, cfg) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * check the config of a merged vhost
 */
static int oidc_config_check_merged_vhost_configs(apr_pool_t *pool,
		server_rec *s) {
	int status = OK;
	while (s != NULL && status == OK) {
		oidc_cfg *cfg = ap_get_module_config(s->module_config,
				&auth_openidc_module);
		if (cfg->merged) {
			status = oidc_config_check_vhost_config(pool, s);
		}
		s = s->next;
	}
	return status;
}

/*
 * check if any merged vhost configs exist
 */
static int oidc_config_merged_vhost_configs_exist(server_rec *s) {
	while (s != NULL) {
		oidc_cfg *cfg = ap_get_module_config(s->module_config,
				&auth_openidc_module);
		if (cfg->merged) {
			return TRUE;
		}
		s = s->next;
	}
	return FALSE;
}

/*
 * SSL initialization magic copied from mod_auth_cas
 */
#if ((OPENSSL_VERSION_NUMBER < 0x10100000) && defined(OPENSSL_THREADS) && APR_HAS_THREADS)

static apr_thread_mutex_t **ssl_locks;
static int ssl_num_locks;

static void oidc_ssl_locking_callback(int mode, int type, const char *file,
		int line) {
	if (type < ssl_num_locks) {
		if (mode & CRYPTO_LOCK)
			apr_thread_mutex_lock(ssl_locks[type]);
		else
			apr_thread_mutex_unlock(ssl_locks[type]);
	}
}

#ifdef OPENSSL_NO_THREADID
static unsigned long oidc_ssl_id_callback(void) {
	return (unsigned long) apr_os_thread_current();
}
#else
static void oidc_ssl_id_callback(CRYPTO_THREADID *id) {
	CRYPTO_THREADID_set_numeric(id, (unsigned long) apr_os_thread_current());
}
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */

static apr_status_t oidc_cleanup_child(void *data) {
	server_rec *sp = (server_rec *) data;
	while (sp != NULL) {
		oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(sp->module_config,
				&auth_openidc_module);
		if (cfg->cache->destroy != NULL) {
			if (cfg->cache->destroy(sp) != APR_SUCCESS) {
				oidc_serror(sp, "cache destroy function failed");
			}
		}

		// can do this even though we haven't got a deep copy
		// since references within the object will be set to NULL
		oidc_jwk_list_destroy(sp->process->pool, cfg->oauth.verify_public_keys);
		oidc_jwk_list_destroy(sp->process->pool, cfg->oauth.verify_shared_keys);
		oidc_jwk_list_destroy(sp->process->pool, cfg->public_keys);
		oidc_jwk_list_destroy(sp->process->pool, cfg->private_keys);

		sp = sp->next;
	}

	return APR_SUCCESS;
}

static apr_status_t oidc_cleanup_parent(void *data) {

	oidc_cleanup_child(data);

#if ((OPENSSL_VERSION_NUMBER < 0x10100000) && defined (OPENSSL_THREADS) && APR_HAS_THREADS)
	if (CRYPTO_get_locking_callback() == oidc_ssl_locking_callback)
		CRYPTO_set_locking_callback(NULL);
#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_id_callback() == oidc_ssl_id_callback)
		CRYPTO_set_id_callback(NULL);
#else
	if (CRYPTO_THREADID_get_callback() == oidc_ssl_id_callback)
		CRYPTO_THREADID_set_callback(NULL);
#endif /* OPENSSL_NO_THREADID */

#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000) && defined (OPENSSL_THREADS) && APR_HAS_THREADS */

	EVP_cleanup();
	curl_global_cleanup();

	ap_log_error(APLOG_MARK, APLOG_INFO, 0, (server_rec * ) data,
			"%s - shutdown", NAMEVERSION);

	return APR_SUCCESS;
}

/*
 * handler that is called (twice) after the configuration phase; check if everything is OK
 */
static int oidc_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2,
		server_rec *s) {
	const char *userdata_key = "oidc_post_config";
	void *data = NULL;

	/* Since the post_config hook is invoked twice (once
	 * for 'sanity checking' of the config and once for
	 * the actual server launch, we have to use a hack
	 * to not run twice
	 */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (data == NULL) {
		apr_pool_userdata_set((const void *) 1, userdata_key,
				apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
			"%s - init - cjose %s, %s, EC=%s, GCM=%s, Memcache=%s, Redis=%s, JQ=%s",
			NAMEVERSION, cjose_version(), OPENSSL_VERSION_TEXT,
			OIDC_JOSE_EC_SUPPORT ? "yes" : "no",
					OIDC_JOSE_GCM_SUPPORT ? "yes" : "no",
#ifdef USE_MEMCACHE
							"yes"
#else
							"no"
#endif
							,
#ifdef USE_LIBHIREDIS
							"yes"
#else
							"no"
#endif
							,
#ifdef USE_LIBJQ
							"yes"
#else
							"no"
#endif
	);

	curl_global_init(CURL_GLOBAL_ALL);
	OpenSSL_add_all_digests();

#if ((OPENSSL_VERSION_NUMBER < 0x10100000) && defined (OPENSSL_THREADS) && APR_HAS_THREADS)
	ssl_num_locks = CRYPTO_num_locks();
	ssl_locks = apr_pcalloc(s->process->pool,
			ssl_num_locks * sizeof(*ssl_locks));

	int i;
	for (i = 0; i < ssl_num_locks; i++)
		apr_thread_mutex_create(&(ssl_locks[i]), APR_THREAD_MUTEX_DEFAULT,
				s->process->pool);

#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_locking_callback() == NULL && CRYPTO_get_id_callback() == NULL) {
		CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
		CRYPTO_set_id_callback(oidc_ssl_id_callback);
	}
#else
	if (CRYPTO_get_locking_callback() == NULL
			&& CRYPTO_THREADID_get_callback() == NULL) {
		CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
		CRYPTO_THREADID_set_callback(oidc_ssl_id_callback);
	}
#endif /* OPENSSL_NO_THREADID */

#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000) && defined (OPENSSL_THREADS) && APR_HAS_THREADS */

	apr_pool_cleanup_register(pool, s, oidc_cleanup_parent,
			apr_pool_cleanup_null);

	server_rec *sp = s;
	while (sp != NULL) {
		oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(sp->module_config,
				&auth_openidc_module);
		if (cfg->cache->post_config != NULL) {
			if (cfg->cache->post_config(sp) != OK)
				return HTTP_INTERNAL_SERVER_ERROR;
		}
		sp = sp->next;
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
	if (!oidc_config_merged_vhost_configs_exist(s)) {
		/* nothing merged, only check the base vhost */
		return oidc_config_check_vhost_config(pool, s);
	}
	return oidc_config_check_merged_vhost_configs(pool, s);
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
static const char *oidc_parse_config(cmd_parms *cmd, const char *require_line,
		const void **parsed_require_line) {
	const char *expr_err = NULL;
	ap_expr_info_t *expr;

	expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
			&expr_err, NULL);

	if (expr_err)
		return apr_pstrcat(cmd->temp_pool,
				"Cannot parse expression in require line: ", expr_err, NULL);

	*parsed_require_line = expr;

	return NULL;
}

static const authz_provider oidc_authz_claim_provider = {
		&oidc_authz_checker_claim, &oidc_parse_config, };
#ifdef USE_LIBJQ
static const authz_provider oidc_authz_claims_expr_provider = {
		&oidc_authz_checker_claims_expr,
		NULL,
};
#endif
#endif

/*
 * initialize cache context in child process if required
 */
static void oidc_child_init(apr_pool_t *p, server_rec *s) {
	server_rec *sp = s;
	while (sp != NULL) {
		oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(sp->module_config,
				&auth_openidc_module);
		if (cfg->cache->child_init != NULL) {
			if (cfg->cache->child_init(p, sp) != APR_SUCCESS) {
				oidc_serror(sp, "cfg->cache->child_init failed");
			}
		}
		sp = sp->next;
	}
	apr_pool_cleanup_register(p, s, oidc_cleanup_child, apr_pool_cleanup_null);
}

static const char oidcFilterName[] = "oidc_filter_in_filter";

static void oidc_filter_in_insert_filter(request_rec *r) {

	if (oidc_enabled(r) == FALSE)
		return;

	if (ap_is_initial_req(r) == 0)
		return;

	apr_table_t *userdata_post_params = NULL;
	apr_pool_userdata_get((void **) &userdata_post_params,
			OIDC_USERDATA_POST_PARAMS_KEY, r->pool);
	if (userdata_post_params == NULL)
		return;

	ap_add_input_filter(oidcFilterName, NULL, r, r->connection);
}

typedef struct oidc_filter_in_context {
	apr_bucket_brigade *pbbTmp;
	apr_size_t nbytes;
} oidc_filter_in_context;

static apr_status_t oidc_filter_in_filter(ap_filter_t *f,
		apr_bucket_brigade *brigade, ap_input_mode_t mode,
		apr_read_type_e block, apr_off_t nbytes) {
	oidc_filter_in_context *ctx = NULL;
	apr_bucket *b_in = NULL, *b_out = NULL;
	char *buf = NULL;
	apr_table_t *userdata_post_params = NULL;
	apr_status_t rc = APR_SUCCESS;

	if (!(ctx = f->ctx)) {
		f->ctx = ctx = apr_palloc(f->r->pool, sizeof *ctx);
		ctx->pbbTmp = apr_brigade_create(f->r->pool,
				f->r->connection->bucket_alloc);
		ctx->nbytes = 0;
	}

	if (APR_BRIGADE_EMPTY(ctx->pbbTmp)) {
		rc = ap_get_brigade(f->next, ctx->pbbTmp, mode, block, nbytes);

		if (mode == AP_MODE_EATCRLF || rc != APR_SUCCESS)
			return rc;
	}

	while (!APR_BRIGADE_EMPTY(ctx->pbbTmp)) {

		b_in = APR_BRIGADE_FIRST(ctx->pbbTmp);

		if (APR_BUCKET_IS_EOS(b_in)) {

			APR_BUCKET_REMOVE(b_in);

			apr_pool_userdata_get((void **) &userdata_post_params,
					OIDC_USERDATA_POST_PARAMS_KEY, f->r->pool);

			if (userdata_post_params != NULL) {
				buf = apr_psprintf(f->r->pool, "%s%s",
						ctx->nbytes > 0 ? "&" : "",
								oidc_util_http_form_encoded_data(f->r,
										userdata_post_params));
				b_out = apr_bucket_heap_create(buf, strlen(buf), 0,
						f->r->connection->bucket_alloc);

				APR_BRIGADE_INSERT_TAIL(brigade, b_out);

				ctx->nbytes += strlen(buf);

				if (oidc_util_hdr_in_content_length_get(f->r) != NULL)
					oidc_util_hdr_in_set(f->r, OIDC_HTTP_HDR_CONTENT_LENGTH,
							apr_psprintf(f->r->pool, "%ld", ctx->nbytes));

				apr_pool_userdata_set(NULL, OIDC_USERDATA_POST_PARAMS_KEY,
						NULL, f->r->pool);
			}

			APR_BRIGADE_INSERT_TAIL(brigade, b_in);

			break;
		}

		APR_BUCKET_REMOVE(b_in);
		APR_BRIGADE_INSERT_TAIL(brigade, b_in);
		ctx->nbytes += b_in->length;
	}

	return rc;
}

/*
 * register our authentication and authorization functions
 */
void oidc_register_hooks(apr_pool_t *pool) {
	ap_hook_post_config(oidc_post_config, NULL, NULL, APR_HOOK_LAST);
	ap_hook_child_init(oidc_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(oidc_content_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_insert_filter(oidc_filter_in_insert_filter, NULL, NULL,
			APR_HOOK_MIDDLE);
	ap_register_input_filter(oidcFilterName, oidc_filter_in_filter, NULL,
			AP_FTYPE_RESOURCE);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_hook_check_authn(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE,
			AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP,
			OIDC_REQUIRE_CLAIM_NAME, "0", &oidc_authz_claim_provider,
			AP_AUTH_INTERNAL_PER_CONF);
#ifdef USE_LIBJQ			
	ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP,
			OIDC_REQUIRE_CLAIMS_EXPR_NAME, "0",
			&oidc_authz_claims_expr_provider, AP_AUTH_INTERNAL_PER_CONF);
#endif
#else
	static const char * const authzSucc[] = {"mod_authz_user.c", NULL};
	ap_hook_check_user_id(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(oidc_auth_checker, NULL, authzSucc, APR_HOOK_MIDDLE);
#endif
}

/*
 * set of configuration primitives
 */
const command_rec oidc_config_cmds[] = {

		AP_INIT_TAKE1(OIDCProviderMetadataURL,
				oidc_set_url_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.metadata_url),
				RSRC_CONF,
				"OpenID Connect OP configuration metadata URL."),
		AP_INIT_TAKE1(OIDCProviderIssuer,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.issuer),
				RSRC_CONF,
				"OpenID Connect OP issuer identifier."),
		AP_INIT_TAKE1(OIDCProviderAuthorizationEndpoint,
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.authorization_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP Authorization Endpoint URL (e.g.: https://localhost:9031/as/authorization.oauth2)"),
		AP_INIT_TAKE1(OIDCProviderTokenEndpoint,
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP Token Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1(OIDCProviderTokenEndpointAuth,
				oidc_set_endpoint_auth_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_auth),
				RSRC_CONF,
				"Specify an authentication method for the OpenID OP Token Endpoint (e.g.: client_secret_basic)"),
		AP_INIT_TAKE1(OIDCProviderTokenEndpointParams,
				oidc_set_string_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_params),
				RSRC_CONF,
				"Define extra parameters that will be posted to the OpenID OP Token Endpoint (e.g.: param1=value1&param2=value2, all urlencoded)."),
		AP_INIT_TAKE1(OIDCProviderRegistrationEndpointJson,
				oidc_set_string_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.registration_endpoint_json),
				RSRC_CONF,
				"Define a JSON object with parameters that will be merged into the client registration request to the OpenID OP Registration Endpoint (e.g.: { \"request_uris\" : [ \"https://example.com/uri\"] })."),
		AP_INIT_TAKE1(OIDCProviderUserInfoEndpoint,
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.userinfo_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP UserInfo Endpoint URL (e.g.: https://localhost:9031/idp/userinfo.openid)"),
		AP_INIT_TAKE1(OIDCProviderRevocationEndpoint,
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.revocation_endpoint_url),
				RSRC_CONF,
				"Define the RFC 7009 Token Revocation Endpoint URL (e.g.: https://localhost:9031/as/revoke_token.oauth2)"),
		AP_INIT_TAKE1(OIDCProviderCheckSessionIFrame,
				oidc_set_url_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.check_session_iframe),
				RSRC_CONF,
				"Define the OpenID OP Check Session iFrame URL."),
		AP_INIT_TAKE1(OIDCProviderEndSessionEndpoint,
				oidc_set_url_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.end_session_endpoint),
				RSRC_CONF,
				"Define the OpenID OP End Session Endpoint URL."),
		AP_INIT_FLAG(OIDCProviderBackChannelLogoutSupported,
				oidc_set_flag_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.backchannel_logout_supported),
				RSRC_CONF,
				"Define whether the OP supports OpenID Connect Back Channel Logout."),
		AP_INIT_TAKE1(OIDCProviderJwksUri,
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.jwks_uri),
				RSRC_CONF,
				"Define the OpenID OP JWKS URL (e.g.: https://localhost:9031/pf/JWKS)"),
		AP_INIT_TAKE1(OIDCResponseType,
				oidc_set_response_type,
				(void *)APR_OFFSETOF(oidc_cfg, provider.response_type),
				RSRC_CONF,
				"The response type (or OpenID Connect Flow) used; must be one of \"code\", \"id_token\", \"id_token token\", \"code id_token\", \"code token\" or \"code id_token token\" (serves as default value for discovered OPs too)"),
		AP_INIT_TAKE1(OIDCResponseMode,
				oidc_set_response_mode,
				(void *)APR_OFFSETOF(oidc_cfg, provider.response_mode),
				RSRC_CONF,
				"The response mode used; must be one of \"fragment\", \"query\" or \"form_post\" (serves as default value for discovered OPs too)"),

		AP_INIT_ITERATE(OIDCPublicKeyFiles,
				oidc_set_public_key_files,
				(void *)APR_OFFSETOF(oidc_cfg, public_keys),
				RSRC_CONF,
				"The fully qualified names of the files that contain the X.509 certificates that contains the RSA public keys that can be used for encryption by the OP."),
		AP_INIT_ITERATE(OIDCPrivateKeyFiles,
				oidc_set_private_key_files_enc,
				NULL,
				RSRC_CONF,
				"The fully qualified names of the files that contain the RSA private keys that can be used to decrypt content sent to us by the OP."),

		AP_INIT_TAKE1(OIDCClientJwksUri,
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.client_jwks_uri),
				RSRC_CONF,
				"Define the Client JWKS URL (e.g.: https://localhost/protected/?jwks=rsa)"),
		AP_INIT_TAKE1(OIDCIDTokenSignedResponseAlg,
				oidc_set_signed_response_alg,
				(void *)APR_OFFSETOF(oidc_cfg, provider.id_token_signed_response_alg),
				RSRC_CONF,
				"The algorithm that the OP must use to sign the ID token."),
		AP_INIT_TAKE1(OIDCIDTokenEncryptedResponseAlg,
				oidc_set_encrypted_response_alg,
				(void *)APR_OFFSETOF(oidc_cfg, provider.id_token_encrypted_response_alg),
				RSRC_CONF,
				"The algorithm that the OP should use to encrypt the Content Encryption Key that is used to encrypt the id_token (used only in dynamic client registration); must be one of [RSA1_5|A128KW|A256KW|RSA-OAEP]"),
		AP_INIT_TAKE1(OIDCIDTokenEncryptedResponseEnc,
				oidc_set_encrypted_response_enc,
				(void *)APR_OFFSETOF(oidc_cfg, provider.id_token_encrypted_response_enc),
				RSRC_CONF,
				"The algorithm that the OP should use to encrypt to the id_token with the Content Encryption Key (used only in dynamic client registration); must be one of [A128CBC-HS256|A256CBC-HS512|A256GCM]"),
		AP_INIT_TAKE1(OIDCUserInfoSignedResponseAlg,
				oidc_set_signed_response_alg,
				(void *)APR_OFFSETOF(oidc_cfg, provider.userinfo_signed_response_alg),
				RSRC_CONF,
				"The algorithm that the OP should use to sign the UserInfo response (used only in dynamic client registration); must be one of [RS256|RS384|RS512|PS256|PS384|PS512|HS256|HS384|HS512]"),
		AP_INIT_TAKE1(OIDCUserInfoEncryptedResponseAlg,
				oidc_set_encrypted_response_alg,
				(void *)APR_OFFSETOF(oidc_cfg, provider.userinfo_encrypted_response_alg),
				RSRC_CONF,
				"The algorithm that the OP should use to encrypt the Content Encryption Key that is used to encrypt the UserInfo response (used only in dynamic client registration); must be one of [RSA1_5|A128KW|A256KW|RSA-OAEP]"),
		AP_INIT_TAKE1(OIDCUserInfoEncryptedResponseEnc,
				oidc_set_encrypted_response_enc,
				(void *)APR_OFFSETOF(oidc_cfg, provider.userinfo_encrypted_response_enc),
				RSRC_CONF,
				"The algorithm that the OP should use to encrypt to encrypt the UserInfo response with the Content Encryption Key (used only in dynamic client registration); must be one of [A128CBC-HS256|A256CBC-HS512|A256GCM]"),
		AP_INIT_TAKE1(OIDCUserInfoTokenMethod,
				oidc_set_userinfo_token_method,
				(void *)APR_OFFSETOF(oidc_cfg, provider.userinfo_token_method),
				RSRC_CONF,
				"The method that is used to present the access token to the userinfo endpoint; must be one of [authz_header|post_param]"),
		AP_INIT_TAKE1(OIDCTokenBindingPolicy,
				oidc_set_token_binding_policy,
				(void *)APR_OFFSETOF(oidc_cfg, provider.token_binding_policy),
				RSRC_CONF,
				"The token binding policy used with the provider; must be one of [disabled|optional|required|enforced]"),

		AP_INIT_TAKE1(OIDCSSLValidateServer,
				oidc_set_ssl_validate_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.ssl_validate_server),
				RSRC_CONF,
				"Require validation of the OpenID Connect OP SSL server certificate for successful authentication (On or Off)"),
		AP_INIT_TAKE1(OIDCValidateIssuer,
				oidc_set_validate_issuer_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.validate_issuer),
				RSRC_CONF,
				"Require validation of token issuer for successful authentication  (On or Off)"),
		AP_INIT_TAKE1(OIDCClientName,
				oidc_set_string_slot,
				(void *) APR_OFFSETOF(oidc_cfg, provider.client_name),
				RSRC_CONF,
				"Define the (client_name) name that the client uses for dynamic registration to the OP."),
		AP_INIT_TAKE1(OIDCClientContact,
				oidc_set_string_slot,
				(void *) APR_OFFSETOF(oidc_cfg, provider.client_contact),
				RSRC_CONF,
				"Define the contact that the client registers in dynamic registration with the OP."),
		AP_INIT_TAKE1(OIDCScope,
				oidc_set_string_slot,
				(void *) APR_OFFSETOF(oidc_cfg, provider.scope),
				RSRC_CONF,
				"Define the OpenID Connect scope that is requested from the OP."),
		AP_INIT_TAKE1(OIDCPathScope,
				ap_set_string_slot,
				(void*)APR_OFFSETOF(oidc_dir_cfg, path_scope),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Define the OpenID Connect scope that is requested from all providers for a specific path/context."),
		AP_INIT_TAKE1(OIDCJWKSRefreshInterval,
				oidc_set_jwks_refresh_interval,
				(void*)APR_OFFSETOF(oidc_cfg, provider.jwks_refresh_interval),
				RSRC_CONF,
				"Duration in seconds after which retrieved JWS should be refreshed."),
		AP_INIT_TAKE1(OIDCIDTokenIatSlack,
				oidc_set_idtoken_iat_slack,
				(void*)APR_OFFSETOF(oidc_cfg, provider.idtoken_iat_slack),
				RSRC_CONF,
				"Acceptable offset (both before and after) for checking the \"iat\" (= issued at) timestamp in the id_token."),
		AP_INIT_TAKE1(OIDCSessionMaxDuration,
				oidc_set_session_max_duration,
				(void*)APR_OFFSETOF(oidc_cfg, provider.session_max_duration),
				RSRC_CONF,
				"Maximum duration of a session in seconds."),
		AP_INIT_TAKE1(OIDCAuthRequestParams,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.auth_request_params),
				RSRC_CONF,
				"Extra parameters that need to be sent in the Authorization Request (must be query-encoded like \"display=popup&prompt=consent\"."),
		AP_INIT_TAKE1(OIDCPathAuthRequestParams,
				ap_set_string_slot,
				(void*)APR_OFFSETOF(oidc_dir_cfg, path_auth_request_params),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Extra parameters that need to be sent in the Authorization Request (must be query-encoded like \"display=popup&prompt=consent\"."),
		AP_INIT_TAKE1(OIDCPKCEMethod,
				oidc_set_pkce_method,
				(void *)APR_OFFSETOF(oidc_cfg, provider.pkce),
				RSRC_CONF,
				"The RFC 7636 PCKE mode used; must be one of \"plain\", \"S256\" or \"referred_tb\""),

		AP_INIT_TAKE1(OIDCClientID,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.client_id),
				RSRC_CONF,
				"Client identifier used in calls to OpenID Connect OP."),
		AP_INIT_TAKE1(OIDCClientSecret,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.client_secret),
				RSRC_CONF,
				"Client secret used in calls to OpenID Connect OP."),

		AP_INIT_TAKE1(OIDCClientTokenEndpointCert,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_tls_client_cert),
				RSRC_CONF,
				"TLS client certificate used for calls to OpenID Connect OP token endpoint."),
		AP_INIT_TAKE1(OIDCClientTokenEndpointKey,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_tls_client_key),
				RSRC_CONF,
				"TLS client certificate private key used for calls to OpenID Connect OP token endpoint."),

		AP_INIT_TAKE1(OIDCRedirectURI,
				oidc_set_relative_or_absolute_url_slot,
				(void *)APR_OFFSETOF(oidc_cfg, redirect_uri),
				RSRC_CONF,
				"Define the Redirect URI (e.g.: https://localhost:9031/protected/example/)"),
		AP_INIT_TAKE1(OIDCDefaultURL,
				oidc_set_url_slot,
				(void *)APR_OFFSETOF(oidc_cfg, default_sso_url),
				RSRC_CONF,
				"Defines the default URL where the user is directed to in case of 3rd-party initiated SSO."),
		AP_INIT_TAKE1(OIDCDefaultLoggedOutURL,
				oidc_set_url_slot,
				(void *)APR_OFFSETOF(oidc_cfg, default_slo_url),
				RSRC_CONF,
				"Defines the default URL where the user is directed to after logout."),
		AP_INIT_TAKE1(OIDCCookieDomain,
				oidc_set_cookie_domain,
				NULL,
				RSRC_CONF,
				"Specify domain element for OIDC session cookie."),
		AP_INIT_FLAG(OIDCCookieHTTPOnly,
				oidc_set_flag_slot,
				(void *) APR_OFFSETOF(oidc_cfg, cookie_http_only),
				RSRC_CONF,
				"Defines whether or not the cookie httponly flag is set on cookies."),
		AP_INIT_FLAG(OIDCCookieSameSite,
				oidc_set_flag_slot,
				(void *) APR_OFFSETOF(oidc_cfg, cookie_same_site),
				RSRC_CONF,
				"Defines whether or not the cookie Same-Site flag is set on cookies."),
		AP_INIT_TAKE1(OIDCOutgoingProxy,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, outgoing_proxy),
				RSRC_CONF,
				"Specify an outgoing proxy for your network (<host>[:<port>]."),
		AP_INIT_TAKE1(OIDCCryptoPassphrase,
				oidc_set_passphrase_slot,
				(void*)APR_OFFSETOF(oidc_cfg, crypto_passphrase),
				RSRC_CONF,
				"Passphrase used for AES crypto on cookies and state."),
		AP_INIT_TAKE1(OIDCClaimDelimiter,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, claim_delimiter),
				RSRC_CONF,
				"The delimiter to use when setting multi-valued claims in the HTTP headers."),
		AP_INIT_RAW_ARGS(OIDCClaimPrefix,
				oidc_cfg_set_claim_prefix,
				(void*)APR_OFFSETOF(oidc_cfg, claim_prefix),
				RSRC_CONF,
				"The prefix to use when setting claims in the HTTP headers."),
		AP_INIT_TAKE123(OIDCRemoteUserClaim,
				oidc_set_remote_user_claim,
				(void*)APR_OFFSETOF(oidc_cfg, remote_user_claim),
				RSRC_CONF,
				"The claim that is used when setting the REMOTE_USER variable for OpenID Connect protected paths."),
		AP_INIT_TAKE123(OIDCPassIDTokenAs,
				oidc_set_pass_idtoken_as,
				NULL,
				RSRC_CONF,
				"The format in which the id_token is passed in (a) header(s); must be one or more of: claims|payload|serialized"),
		AP_INIT_TAKE123(OIDCPassUserInfoAs,
				oidc_set_pass_userinfo_as,
				NULL,
				RSRC_CONF,
				"The format in which the userinfo is passed in (a) header(s); must be one or more of: claims|json|jwt"),

		AP_INIT_TAKE1(OIDCOAuthClientID,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.client_id),
				RSRC_CONF,
				"Client identifier used in calls to OAuth 2.0 Authorization server validation calls."),
		AP_INIT_TAKE1(OIDCOAuthClientSecret,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.client_secret),
				RSRC_CONF,
				"Client secret used in calls to OAuth 2.0 Authorization server validation calls."),

		AP_INIT_TAKE1(OIDCOAuthIntrospectionEndpoint,
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, oauth.introspection_endpoint_url),
				RSRC_CONF,
				"Define the OAuth AS Introspection Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1(OIDCOAuthIntrospectionEndpointMethod,
				oidc_set_introspection_method,
				(void *)APR_OFFSETOF(oidc_cfg, oauth.introspection_endpoint_method),
				RSRC_CONF,
				"Define the HTTP method to use for the introspection call: one of \"GET\" or \"POST\" (default)"),
		AP_INIT_TAKE1(OIDCOAuthIntrospectionEndpointParams,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.introspection_endpoint_params),
				RSRC_CONF,
				"Extra parameters that need to be sent in the token introspection request (must be query-encoded like \"grant_type=urn%3Apingidentity.com%3Aoauth2%3Agrant_type%3Avalidate_bearer\"."),

		AP_INIT_TAKE1(OIDCOAuthIntrospectionEndpointAuth,
				oidc_set_endpoint_auth_slot,
				(void *)APR_OFFSETOF(oidc_cfg, oauth.introspection_endpoint_auth),
				RSRC_CONF,
				"Specify an authentication method for the OAuth AS Introspection Endpoint (e.g.: client_secret_basic)"),
        AP_INIT_RAW_ARGS(OIDCOAuthIntrospectionClientAuthBearerToken,
				oidc_set_client_auth_bearer_token,
				NULL,
				RSRC_CONF,
				"Specify a bearer token to authorize against the OAuth AS Introspection Endpoint (e.g.: 55554ee-2491-11e3-be72-001fe2e44345 or empty to use the introspected token itself)"),
		AP_INIT_TAKE1(OIDCOAuthIntrospectionEndpointCert,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.introspection_endpoint_tls_client_cert),
				RSRC_CONF,
				"TLS client certificate used for calls to the OAuth 2.0 Authorization server introspection endpoint."),
		AP_INIT_TAKE1(OIDCOAuthIntrospectionEndpointKey,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.introspection_endpoint_tls_client_key),
				RSRC_CONF,
				"TLS client certificate private key used for calls to the OAuth 2.0 Authorization server introspection endpoint."),

		AP_INIT_TAKE1(OIDCOAuthIntrospectionTokenParamName,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.introspection_token_param_name),
				RSRC_CONF,
				"Name of the parameter whose value carries the access token value in an validation request to the token introspection endpoint."),
		AP_INIT_TAKE123(OIDCOAuthTokenExpiryClaim,
				oidc_set_token_expiry_claim,
				NULL,
				RSRC_CONF,
				"Name of the claim that carries the token expiry value in the introspection result, optionally followed by absolute|relative, optionally followed by optional|mandatory"),
		AP_INIT_TAKE1(OIDCOAuthSSLValidateServer,
				oidc_set_ssl_validate_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.ssl_validate_server),
				RSRC_CONF,
				"Require validation of the OAuth 2.0 AS Validation Endpoint SSL server certificate for successful authentication (On or Off)"),
		AP_INIT_TAKE123(OIDCOAuthRemoteUserClaim,
				oidc_set_remote_user_claim,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.remote_user_claim),
				RSRC_CONF,
				"The claim that is used when setting the REMOTE_USER variable for OAuth 2.0 protected paths."),
		AP_INIT_ITERATE(OIDCOAuthVerifyCertFiles,
				oidc_set_public_key_files,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.verify_public_keys),
				RSRC_CONF,
				"The fully qualified names of the files that contain the X.509 certificates that contains the RSA public keys that can be used for access token validation."),
		AP_INIT_ITERATE(OIDCOAuthVerifySharedKeys,
				oidc_set_shared_keys,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.verify_shared_keys),
				RSRC_CONF,
				"Shared secret(s) that is/are used to verify signed JWT access tokens locally."),
		AP_INIT_TAKE1(OIDCOAuthVerifyJwksUri,
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, oauth.verify_jwks_uri),
				RSRC_CONF,
				"The JWKs URL on which the Authorization publishes the keys used to sign its JWT access tokens."),

		AP_INIT_TAKE1(OIDCHTTPTimeoutLong,
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, http_timeout_long),
				RSRC_CONF,
				"Timeout for long duration HTTP calls (default)."),
		AP_INIT_TAKE1(OIDCHTTPTimeoutShort,
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, http_timeout_short),
				RSRC_CONF,
				"Timeout for short duration HTTP calls (registry/discovery)."),
		AP_INIT_TAKE1(OIDCStateTimeout,
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, state_timeout),
				RSRC_CONF,
				"Time to live in seconds for state parameter (cq. interval in which the authorization request and the corresponding response need to be completed)."),
		AP_INIT_TAKE12(OIDCStateMaxNumberOfCookies,
				oidc_set_max_number_of_state_cookies,
				(void*)APR_OFFSETOF(oidc_cfg, max_number_of_state_cookies),
				RSRC_CONF,
				"Maximun number of parallel state cookies i.e. outstanding authorization requests and whether to delete the oldest cookie(s)."),
		AP_INIT_TAKE1(OIDCSessionInactivityTimeout,
				oidc_set_session_inactivity_timeout,
				(void*)APR_OFFSETOF(oidc_cfg, session_inactivity_timeout),
				RSRC_CONF,
				"Inactivity interval after which the session is invalidated when no interaction has occurred."),

		AP_INIT_TAKE1(OIDCMetadataDir,
				oidc_set_dir_slot,
				(void*)APR_OFFSETOF(oidc_cfg, metadata_dir),
				RSRC_CONF,
				"Directory that contains provider and client metadata files."),
		AP_INIT_TAKE1(OIDCSessionType,
				oidc_set_session_type,
				(void*)APR_OFFSETOF(oidc_cfg, session_type),
				RSRC_CONF,
				"OpenID Connect session storage type (Apache 2.0/2.2 only). Must be one of \"server-cache\" or \"client-cookie\" with an optional suffix \":persistent\"."),
		AP_INIT_FLAG(OIDCSessionCacheFallbackToCookie,
				oidc_set_flag_slot,
				(void*)APR_OFFSETOF(oidc_cfg, session_cache_fallback_to_cookie),
				RSRC_CONF,
				"Fallback to client-side cookie session storage when server side cache fails."),
		AP_INIT_TAKE1(OIDCSessionCookieChunkSize,
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, session_cookie_chunk_size),
				RSRC_CONF,
				"Chunk size for client-cookie session storage type in bytes. Defaults to 4k. Set 0 to suppress chunking."),

		AP_INIT_TAKE1(OIDCCacheType,
				oidc_set_cache_type,
				(void*)APR_OFFSETOF(oidc_cfg, cache), RSRC_CONF,
				"Cache type; must be one of \"file\", \"memcache\" or \"shm\"."),
		AP_INIT_FLAG(OIDCCacheEncrypt,
				oidc_set_flag_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_encrypt),
				RSRC_CONF,
				"Encrypt the data in the cache backend (On or Off)"),
		AP_INIT_TAKE1(OIDCCacheDir,
				oidc_set_dir_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_file_dir),
				RSRC_CONF,
				"Directory used for file-based caching."),
		AP_INIT_TAKE1(OIDCCacheFileCleanInterval,
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_file_clean_interval),
				RSRC_CONF,
				"Cache file clean interval in seconds."),
#ifdef USE_MEMCACHE
		AP_INIT_TAKE1(OIDCMemCacheServers,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_memcache_servers),
				RSRC_CONF,
				"Memcache servers used for caching (space separated list of <hostname>[:<port>] tuples)"),
#endif
		AP_INIT_TAKE1(OIDCCacheShmMax,
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_shm_size_max),
				RSRC_CONF,
				"Maximum number of cache entries to use for \"shm\" caching."),
		AP_INIT_TAKE1(OIDCCacheShmEntrySizeMax,
				oidc_set_cache_shm_entry_size_max,
				(void*)APR_OFFSETOF(oidc_cfg, cache_shm_entry_size_max),
				RSRC_CONF,
				"Maximum size of a single cache entry used for \"shm\" caching."),
#ifdef USE_LIBHIREDIS
		AP_INIT_TAKE1(OIDCRedisCacheServer,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_redis_server),
				RSRC_CONF,
				"Redis server used for caching (<hostname>[:<port>])"),
		AP_INIT_TAKE1(OIDCRedisCachePassword,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_redis_password),
				RSRC_CONF,
				"Password for authentication to the Redis servers."),
#endif
		AP_INIT_TAKE1(OIDCHTMLErrorTemplate,
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, error_template),
				RSRC_CONF,
				"Name of a HTML error template: needs to contain two \"%s\" characters, one for the error message, one for the description."),

		AP_INIT_TAKE1(OIDCDiscoverURL,
				oidc_set_relative_or_absolute_url_slot_dir_cfg,
				(void *)APR_OFFSETOF(oidc_dir_cfg, discover_url),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Defines an external IDP Discovery page"),
		AP_INIT_ITERATE(OIDCPassCookies,
				oidc_set_cookie_names,
				(void *) APR_OFFSETOF(oidc_dir_cfg, pass_cookies),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify cookies that need to be passed from the browser on to the backend to the OP/AS."),
		AP_INIT_ITERATE(OIDCStripCookies,
				oidc_set_cookie_names,
				(void *) APR_OFFSETOF(oidc_dir_cfg, strip_cookies),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify cookies that should be stripped from the incoming request before passing it on to the backend."),
		AP_INIT_TAKE1(OIDCAuthNHeader,
				ap_set_string_slot,
				(void *) APR_OFFSETOF(oidc_dir_cfg, authn_header),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify the HTTP header variable to set with the name of the authenticated user. By default no explicit header is added but Apache's default REMOTE_USER will be set."),
		AP_INIT_TAKE1(OIDCCookiePath,
				ap_set_string_slot,
				(void *) APR_OFFSETOF(oidc_dir_cfg, cookie_path),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Define the cookie path for the session cookie."),
		AP_INIT_TAKE1(OIDCCookie,
				ap_set_string_slot,
				(void *) APR_OFFSETOF(oidc_dir_cfg, cookie),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Define the cookie name for the session cookie."),
		AP_INIT_TAKE12(OIDCUnAuthAction,
				oidc_set_unauth_action,
				(void *) APR_OFFSETOF(oidc_dir_cfg, unauth_action),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Sets the action taken when an unauthenticated request occurs: must be one of \"auth\" (default), \"pass\" , \"401\", \"407\", or \"410\"."),
		AP_INIT_TAKE1(OIDCUnAutzAction,
				oidc_set_unautz_action,
				(void *) APR_OFFSETOF(oidc_dir_cfg, unautz_action),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Sets the action taken when an unauthorized request occurs: must be one of \"401\" (default), \"403\" or \"auth\"."),
		AP_INIT_TAKE1(OIDCPassClaimsAs,
				oidc_set_pass_claims_as, NULL,
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify how claims are passed to the application(s); must be one of \"none\", \"headers\", \"environment\" or \"both\" (default)."),
		AP_INIT_ITERATE(OIDCOAuthAcceptTokenAs,
				oidc_set_accept_oauth_token_in,
				NULL,
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"The method in which an OAuth token can be presented; must be one or more of: header|post|query|cookie"),
		AP_INIT_TAKE1(OIDCUserInfoRefreshInterval,
				oidc_set_userinfo_refresh_interval,
				(void*)APR_OFFSETOF(oidc_cfg, provider.userinfo_refresh_interval),
				RSRC_CONF,
				"Duration in seconds after which retrieved claims from the userinfo endpoint should be refreshed."),
		AP_INIT_TAKE1(OIDCOAuthTokenIntrospectionInterval,
				ap_set_int_slot,
				(void *) APR_OFFSETOF(oidc_dir_cfg, oauth_token_introspect_interval),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Sets the token introspection refresh interval."),
		AP_INIT_TAKE1(OIDCPreservePost,
				oidc_set_preserve_post,
				(void *) APR_OFFSETOF(oidc_dir_cfg, preserve_post),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Indicates whether POST parameters will be preserved across authentication requests."),
		AP_INIT_FLAG(OIDCPassRefreshToken,
				ap_set_flag_slot,
				(void*)APR_OFFSETOF(oidc_dir_cfg, pass_refresh_token),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Pass the refresh token in a header and/or environment variable (On or Off)"),
		AP_INIT_TAKE1(OIDCRequestObject,
				oidc_set_string_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.request_object),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"The default request object settings"),
		AP_INIT_TAKE1(OIDCProviderMetadataRefreshInterval,
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider_metadata_refresh_interval),
				RSRC_CONF,
				"Provider metadata refresh interval in seconds."),
		AP_INIT_TAKE1(OIDCProviderAuthRequestMethod,
				oidc_set_auth_request_method,
				(void*)APR_OFFSETOF(oidc_cfg, provider.auth_request_method),
				RSRC_CONF,
				"HTTP method used to send the authentication request to the provider (GET or POST)."),
		AP_INIT_ITERATE(OIDCInfoHook,
				oidc_set_info_hook_data,
				(void *)APR_OFFSETOF(oidc_cfg, info_hook_data),
				RSRC_CONF,
				"The data that will be returned from the info hook."),
		AP_INIT_ITERATE(OIDCBlackListedClaims,
				oidc_set_filtered_claims,
				(void *) APR_OFFSETOF(oidc_cfg, black_listed_claims),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify claims that should be removed from the userinfo and/or id_token before storing them in the session."),
		AP_INIT_ITERATE(OIDCWhiteListedClaims,
				oidc_set_filtered_claims,
				(void *) APR_OFFSETOF(oidc_cfg, white_listed_claims),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify claims from the userinfo and/or id_token that should be stored in the session (all other claims will be discarded)."),
		AP_INIT_TAKE1(OIDCOAuthServerMetadataURL,
				oidc_set_url_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.metadata_url),
				RSRC_CONF,
				"Authorization Server metadata URL."),
		AP_INIT_TAKE1(OIDCOAuthAccessTokenBindingPolicy,
				oidc_set_token_binding_policy,
				(void *)APR_OFFSETOF(oidc_cfg, oauth.access_token_binding_policy),
				RSRC_CONF,
				"The token binding policy used for access tokens; must be one of [disabled|optional|required|enforced]"),

		AP_INIT_TAKE12(OIDCRefreshAccessTokenBeforeExpiry,
				oidc_set_refresh_access_token_before_expiry,
				(void *)APR_OFFSETOF(oidc_dir_cfg, refresh_access_token_before_expiry),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Ensure the access token is valid for at least <x> seconds by refreshing it if required; must be: <x> [logout_on_error]; the logout_on_error performs a logout on refresh error."),

		AP_INIT_TAKE1(OIDCStateInputHeaders,
				oidc_set_state_input_headers_as,
				NULL,
				RSRC_CONF,
				"Specify header name which is used as the input for calculating the fingerprint of the state during authentication; must be one of \"none\", \"user-agent\", \"x-forwarded-for\" or \"both\" (default)."),

		AP_INIT_ITERATE(OIDCRedirectURLsAllowed,
				oidc_set_redirect_urls_allowed,
				(void *) APR_OFFSETOF(oidc_cfg, redirect_urls_allowed),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify one or more regular expressions that define URLs allowed for post logout and other redirects."),

		AP_INIT_TAKE1(OIDCStateCookiePrefix,
				ap_set_string_slot,
				(void *) APR_OFFSETOF(oidc_dir_cfg, state_cookie_prefix),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Define the cookie prefix for the state cookie."),

		AP_INIT_TAKE1(OIDCCABundlePath,
				oidc_set_path_slot,
				(void *) APR_OFFSETOF(oidc_cfg, ca_bundle_path),
				RSRC_CONF,
				"Sets the path to the CA bundle to be used by cURL."),

		{ NULL }
};
