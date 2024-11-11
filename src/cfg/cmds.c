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

#include "cfg/cache.h"
#include "cfg/cfg.h"
#include "cfg/dir.h"
#include "cfg/oauth.h"
#include "cfg/provider.h"

// clang-format off

#define OIDC_CFG_CMD_DEF(take, prefix, cmd, member, scope, desc) \
	take(cmd, oidc_cmd##prefix##_##member##_set, NULL, scope, desc)

#define OIDC_CFG_CMD(take, cmd, member, desc) \
	OIDC_CFG_CMD_DEF(take, , cmd, member, RSRC_CONF, desc)

#define OIDC_CFG_CMD_PROVIDER(take, cmd, member, desc) \
	OIDC_CFG_CMD_DEF(take, _provider, cmd, member, RSRC_CONF, desc)

#define OIDC_CFG_CMD_OAUTH(take, cmd, member, desc) \
	OIDC_CFG_CMD_DEF(take, _oauth, cmd, member, RSRC_CONF, desc)

#define OIDC_CFG_CMD_DIR(take, cmd, member, desc) \
	OIDC_CFG_CMD_DEF(take, _dir, cmd, member, RSRC_CONF | ACCESS_CONF | OR_AUTHCFG, desc)

const command_rec oidc_cfg_cmds[] = {

	// base

	OIDC_CFG_CMD(
		AP_INIT_ITERATE,
		OIDCPublicKeyFiles,
		public_keys,
		"The fully qualified names of the files that contain the RSA/EC public keys or X.509 certificates that contains the RSA/EC public keys that can be used for signature validation or encryption by the OP."),
	OIDC_CFG_CMD(
		AP_INIT_ITERATE,
		OIDCPrivateKeyFiles,
		private_keys,
		"The	AP_INIT_TAKE1,qualified names of the files that contain the RSA/EC private keys that can be used to decrypt content sent to us by the OP."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCRedirectURI,
		redirect_uri,
		"Define the Redirect URI (e.g.: https://localhost:9031/protected/example/)"),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCDefaultURL,
		default_sso_url,
		"Defines the default URL where the user is directed to in case of 3rd-party initiated SSO."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCDefaultLoggedOutURL,
		default_slo_url,
		"Defines the default URL where the user is directed to after logout."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCookieDomain,
		cookie_domain,
		"Specify domain element for OIDC session cookie."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCookieHTTPOnly,
		cookie_http_only,
		"Defines whether or not the cookie httponly flag is set on cookies."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCookieSameSite,
		cookie_same_site,
		"Defines whether or not the cookie Same-Site flag is set on cookies."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE123,
		OIDCOutgoingProxy,
		outgoing_proxy,
		"Specify an outgoing proxy for your network (<host>[:<port>]."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE12,
		OIDCCryptoPassphrase,
		crypto_passphrase,
		"Passphrase used for AES crypto on cookies and state."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCClaimDelimiter,
		claim_delimiter,
		"The delimiter to use when setting multi-valued claims in the HTTP headers."),
	OIDC_CFG_CMD(
		AP_INIT_RAW_ARGS,
		OIDCClaimPrefix,
		claim_prefix,
		"The prefix to use when setting claims in the HTTP headers."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE123,
		OIDCRemoteUserClaim,
		remote_user_claim,
		"The claim that is used when setting the REMOTE_USER variable for OpenID Connect protected paths."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE123,
		OIDCHTTPTimeoutLong,
		http_timeout_long,
		"Timeout for long duration HTTP calls (default)."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE123,
		OIDCHTTPTimeoutShort,
		http_timeout_short,
		"Timeout for short duration HTTP calls (registry/discovery)."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCStateTimeout,
		state_timeout,
		"Time to live in seconds for state parameter (cq. interval in which the authorization request and the corresponding response need to be completed)."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE12,
		OIDCStateMaxNumberOfCookies,
		max_number_of_state_cookies,
		"Maximum number of parallel state cookies i.e. outstanding authorization requests and whether to delete the oldest cookie(s)."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCSessionInactivityTimeout,
		session_inactivity_timeout,
		"Inactivity interval after which the session is invalidated when no interaction has occurred."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCMetadataDir,
		metadata_dir,
		"Directory that contains provider and client metadata files."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCSessionType,
		session_type,
		"OpenID Connect session storage type (Apache 2.0/2.2 only). Must be one of \"server-cache\" or \"client-cookie\" with an optional suffix \":persistent\"."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCSessionCacheFallbackToCookie,
		session_cache_fallback_to_cookie,
		"Fallback to client-side cookie session storage when server side cache fails."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCSessionCookieChunkSize,
		session_cookie_chunk_size,
		"Chunk size for client-cookie session storage type in bytes. Defaults to 4k. Set 0 to suppress chunking."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE2,
		OIDCPreservePostTemplates,
		post_preserve_templates,
		"Name of POST preserve and restore templates:"
		"1) preserve: needs to contain two \"%s\" characters, the first for the JSON POST data, the second for the URL to redirect to."
		"2) restore: needs to contain one \"%s\", which contains the (original) URL to POST the restored data to"
		),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCProviderMetadataRefreshInterval,
		provider_metadata_refresh_interval,
		"Provider metadata refresh interval in seconds."),
	OIDC_CFG_CMD(
		AP_INIT_ITERATE,
		OIDCInfoHook,
		info_hook_data,
		"The data that will be returned from the info hook."),
	OIDC_CFG_CMD(
		AP_INIT_ITERATE,
		OIDCMetricsData,
		metrics_hook_data,
		"The data that will be returned from the metrics hook."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCMetricsPublish,
		metrics_path,
		"Define the URL where the metrics will be published (e.g.: /metrics)"),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCTraceParent,
		trace_parent,
		"Propagate or generate a traceparent header"),
	OIDC_CFG_CMD(
		AP_INIT_ITERATE,
		OIDCBlackListedClaims,
		black_listed_claims,
		"Specify claims that should be removed from the userinfo and/or id_token before storing them in the session."),
	OIDC_CFG_CMD(
		AP_INIT_ITERATE,
		OIDCWhiteListedClaims,
		white_listed_claims,
		"Specify claims from the userinfo and/or id_token that should be stored in the session (all other claims will be discarded)."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCStateInputHeaders,
		state_input_headers,
		"Specify header name which is used as the input for calculating the fingerprint of the state during authentication; must be one of \"none\", \"user-agent\", \"x-forwarded-for\" or \"both\" (default)."),
	OIDC_CFG_CMD(
		AP_INIT_ITERATE,
		OIDCRedirectURLsAllowed,
		redirect_urls_allowed,
		"Specify one or more regular expressions that define URLs allowed for post logout and other redirects."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCABundlePath,
		ca_bundle_path,
		"Sets the path to the CA bundle to be used by cURL."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCLogoutXFrameOptions,
		logout_x_frame_options,
		"Sets the value of the X-Frame-Options header on front channel logout."),
	OIDC_CFG_CMD(
		AP_INIT_ITERATE,
		OIDCXForwardedHeaders,
		x_forwarded_headers,
		"Sets the value of the interpreted X-Forwarded-* headers."),
#ifdef USE_LIBJQ
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCFilterClaimsExpr,
		filter_claims_expr,
		"Sets the JQ expression to be executed on the claims from id_token/userinfo endpoint before storing them in the session"),
#endif

	// cache

	AP_INIT_TAKE1(
		OIDCCacheType,
		oidc_cmd_cache_type_set,
		NULL,
		RSRC_CONF,
		"cache backend must be one of ['shm'|"
#ifdef USE_MEMCACHE
		"'memcache'|"
#endif
#ifdef USE_LIBHIREDIS
		"'redis'|"
#endif
		"'file']."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCacheEncrypt,
		cache_encrypt,
		"Encrypt the data in the cache backend (On or Off)"),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCacheShmMax,
		cache_shm_size_max,
		"Maximum number of cache entries to use for \"shm\" caching."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCacheShmEntrySizeMax,
		cache_shm_entry_size_max,
		"Maximum size of a single cache entry used for \"shm\" caching."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCacheDir,
		cache_file_dir,
		"Directory used for file-based caching."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCCacheFileCleanInterval,
		cache_file_clean_interval,
		"Cache file clean interval in seconds."),
#ifdef USE_MEMCACHE
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCMemCacheServers,
		cache_memcache_servers,
		"Memcache servers used for caching (space separated list of <hostname>[:<port>] tuples)"),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCMemCacheConnectionsMin,
		cache_memcache_min,
		"Minimum number of connections to each Memcache server per process"),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCMemCacheConnectionsSMax,
		cache_memcache_smax,
		"Soft maximum number of connections to each Memcache server per process"),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCMemCacheConnectionsHMax,
		cache_memcache_hmax,
		"Hard maximum number of connections to each Memcache server per process"),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCMemCacheConnectionsTTL,
		cache_memcache_ttl,
		"Maximum time in seconds a connection to a Memcache server can be idle before being closed"),
#endif
#ifdef USE_LIBHIREDIS
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCRedisCacheServer,
		cache_redis_server,
		"Redis server used for caching (<hostname>[:<port>])"),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCRedisCacheUsername,
		cache_redis_username,
		"Username for authentication to the Redis server."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCRedisCachePassword,
		cache_redis_password,
		"Password for authentication to the Redis server."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCRedisCacheDatabase,
		cache_redis_database,
		"Database to select on the Redis server."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE12,
		OIDCRedisCacheConnectTimeout,
		cache_redis_connect_timeout,
		"Timeout for connecting to the Redis server."),
	OIDC_CFG_CMD(
		AP_INIT_TAKE1,
		OIDCRedisCacheTimeout,
		cache_redis_timeout,
		"Timeout waiting for a response of the Redis server."),
#endif

	// provider

	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderMetadataURL,
		metadata_url,
		"OpenID Connect OP configuration metadata URL."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderIssuer,
		issuer,
		"OpenID Connect OP issuer identifier."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderAuthorizationEndpoint,
		authorization_endpoint_url,
		"Define the OpenID OP Authorization Endpoint URL (e.g.: https://localhost:9031/as/authorization.oauth2)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderTokenEndpoint,
		token_endpoint_url,
		"Define the OpenID OP Token Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderTokenEndpointAuth,
		token_endpoint_auth,
		"Specify an authentication method for the OpenID OP Token Endpoint (e.g.: client_secret_basic)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderTokenEndpointParams,
		token_endpoint_params,
		"Define extra parameters that will be posted to the OpenID OP Token Endpoint (e.g.: param1=value1&param2=value2, all urlencoded)."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderRegistrationEndpointJson,
		registration_endpoint_json,
		"Define a JSON object with parameters that will be merged into the client registration request to the OpenID OP Registration Endpoint (e.g.: { \"request_uris\" : [ \"https://example.com/uri\"] })."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderUserInfoEndpoint,
		userinfo_endpoint_url,
		"Define the OpenID OP UserInfo Endpoint URL (e.g.: https://localhost:9031/idp/userinfo.openid)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_RAW_ARGS,
		OIDCProviderRevocationEndpoint,
		revocation_endpoint_url,
		"Define the RFC 7009 Token Revocation Endpoint URL (e.g.: https://localhost:9031/as/revoke_token.oauth2)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderPushedAuthorizationRequestEndpoint,
		pushed_authorization_request_endpoint_url,
		"Define the OAuth 2.0 Pushed Authorization Endpoint URL (e.g.: https://localhost:9031/as/par.oauth2)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderCheckSessionIFrame,
		check_session_iframe,
		"Define the OpenID OP Check Session iFrame URL."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderEndSessionEndpoint,
		end_session_endpoint,
		"Define the OpenID OP End Session Endpoint URL."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderBackChannelLogoutSupported,
		backchannel_logout_supported,
		"Define whether the OP supports OpenID Connect Back Channel Logout."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderJwksUri,
		jwks_uri,
		"Define the OpenID OP JWKS URL (e.g.: https://localhost:9031/pf/JWKS)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE2,
		OIDCProviderSignedJwksUri,
		signed_jwks_uri,
		"Define the OpenID Connect OP Signed JWKS URI and a JWK that can be used to verify the data on that URL."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_ITERATE,
		OIDCProviderVerifyCertFiles,
		verify_public_keys,
		"The fully qualified names of the files that contain the X.509 certificates that contains the RSA/EC public keys that can be used for ID token validation."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCResponseType,
		response_type,
		"The response type (or OpenID Connect Flow) used; must be one of \"code\", \"id_token\", \"id_token token\", \"code id_token\", \"code token\" or \"code id_token token\" (serves as default value for discovered OPs too)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCResponseMode,
		response_mode,
		"The response mode used; must be one of \"fragment\", \"query\" or \"form_post\" (serves as default value for discovered OPs too)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCClientJwksUri,
		client_jwks_uri,
		"Define the Client JWKS URL (e.g.: https://localhost/protected/?jwks=rsa)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCIDTokenSignedResponseAlg,
		id_token_signed_response_alg,
		"The algorithm that the OP must use to sign the ID token."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCIDTokenEncryptedResponseAlg,
		id_token_encrypted_response_alg,
		"The algorithm that the OP should use to encrypt the Content Encryption Key that is used to encrypt the id_token (used only in dynamic client registration); must be one of [RSA1_5|A128KW|A256KW|RSA-OAEP]"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCIDTokenEncryptedResponseEnc,
		id_token_encrypted_response_enc,
		"The algorithm that the OP should use to encrypt to the id_token with the Content Encryption Key (used only in dynamic client registration); must be one of [A128CBC-HS256|A256CBC-HS512|A256GCM]"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_ITERATE,
		OIDCIDTokenAudValues,
		id_token_aud_values,
		"Accepted \"aud\" claim values in the ID token."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCUserInfoSignedResponseAlg,
		userinfo_signed_response_alg,
		"The algorithm that the OP should use to sign the UserInfo response (used only in dynamic client registration); must be one of [RS256|RS384|RS512|PS256|PS384|PS512|HS256|HS384|HS512]"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCUserInfoEncryptedResponseAlg,
		userinfo_encrypted_response_alg,
		"The algorithm that the OP should use to encrypt the Content Encryption Key that is used to encrypt the UserInfo response (used only in dynamic client registration); must be one of [RSA1_5|A128KW|A256KW|RSA-OAEP]"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCUserInfoEncryptedResponseEnc,
		userinfo_encrypted_response_enc,
		"The algorithm that the OP should use to encrypt to encrypt the UserInfo response with the Content Encryption Key (used only in dynamic client registration); must be one of [A128CBC-HS256|A256CBC-HS512|A256GCM]"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCUserInfoTokenMethod,
		userinfo_token_method,
		"The method that is used to present the access token to the userinfo endpoint; must be one of [authz_header|post_param]"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCSSLValidateServer,
		ssl_validate_server,
		"Require validation of the OpenID Connect OP SSL server certificate for successful authentication (On or Off)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCValidateIssuer,
		validate_issuer,
		"Require validation of token issuer for successful authentication  (On or Off)"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCClientName,
		client_name,
		"Define the (client_name) name that the client uses for dynamic registration to the OP."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCClientContact,
		client_contact,
		"Define the contact that the client registers in dynamic registration with the OP."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCScope,
		scope,
		"Define the OpenID Connect scope that is requested from the OP."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCJWKSRefreshInterval,
		jwks_uri_refresh_interval,
		"Duration in seconds after which retrieved JWS should be refreshed."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCIDTokenIatSlack,
		idtoken_iat_slack,
		"Acceptable offset (both before and after) for checking the \"iat\" (= issued at) timestamp in the id_token."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCSessionMaxDuration,
		session_max_duration,
		"Maximum duration of a session in seconds."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCAuthRequestParams,
		auth_request_params,
		"Extra parameters that need to be sent in the Authorization Request (must be query-encoded like \"display=popup&prompt=consent\"."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCLogoutRequestParams,
		logout_request_params,
		"Extra parameters that need to be sent in the Logout Request (must be query-encoded like \"client_id=myclient&prompt=none\"."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCPKCEMethod,
		pkce,
		"The RFC 7636 PCKE mode used; must be one of \"plain\" or \"S256\""),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE12,
		OIDCDPoPMode,
		dpop_mode,
		"The RFC 9449 DPoP mode used; must be one of \"off\", \"optional\" or \"required\""),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCClientID,
		client_id,
		"Client identifier used in calls to OpenID Connect OP."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCClientSecret,
		client_secret,
		"Client secret used in calls to OpenID Connect OP."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCClientTokenEndpointCert,
		token_endpoint_tls_client_cert,
		"TLS client certificate used for calls to OpenID Connect OP token endpoint."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCClientTokenEndpointKey,
		token_endpoint_tls_client_key,
		"TLS client certificate private key used for calls to OpenID Connect OP token endpoint."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCClientTokenEndpointKeyPassword,
		token_endpoint_tls_client_key_pwd,
		"TLS client certificate private key password used for calls to OpenID Connect OP token endpoint."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE12,
		OIDCUserInfoRefreshInterval,
		userinfo_refresh_interval,
		"Duration in seconds after which retrieved claims from the userinfo endpoint should be refreshed."),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCRequestObject,
		request_object,
		"The default request object settings"),
	OIDC_CFG_CMD_PROVIDER(
		AP_INIT_TAKE1,
		OIDCProviderAuthRequestMethod,
		auth_request_method,
		"HTTP method used to send the authentication request to the provider (GET or POST)."),

	// oauth

	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthServerMetadataURL,
		metadata_url,
		"Authorization Server metadata URL."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthClientID,
		client_id,
		"Client identifier used in calls to OAuth 2.0 Authorization server validation calls."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthClientSecret,
		client_secret,
		"Client secret used in calls to OAuth 2.0 Authorization server validation calls."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthIntrospectionEndpoint,
		introspection_endpoint_url,
		"Define the OAuth AS Introspection Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthIntrospectionEndpointMethod,
		introspection_endpoint_method,
		"Define the HTTP method to use for the introspection call: one of \"GET\" or \"POST\" (default)"),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthIntrospectionEndpointParams,
		introspection_endpoint_params,
		"Extra parameters that need to be sent in the token introspection request (must be query-encoded like \"grant_type=urn%3Apingidentity.com%3Aoauth2%3Agrant_type%3Avalidate_bearer\"."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthIntrospectionEndpointAuth,
		introspection_endpoint_auth,
		"Specify an authentication method for the OAuth AS Introspection Endpoint (e.g.: client_secret_basic)"),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_RAW_ARGS,
		OIDCOAuthIntrospectionClientAuthBearerToken,
		introspection_client_auth_bearer_token,
		"Specify a bearer token to authorize against the OAuth AS Introspection Endpoint (e.g.: 55554ee-2491-11e3-be72-001fe2e44345 or empty to use the introspected token itself)"),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthIntrospectionEndpointCert,
		introspection_endpoint_tls_client_cert,
		"TLS client certificate used for calls to the OAuth 2.0 Authorization server introspection endpoint."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthIntrospectionEndpointKey,
		introspection_endpoint_tls_client_key,
		"TLS client certificate private key used for calls to the OAuth 2.0 Authorization server introspection endpoint."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthIntrospectionEndpointKeyPassword,
		introspection_endpoint_tls_client_key_pwd,
		"TLS client certificate private key password used for calls to the OAuth 2.0 Authorization server introspection endpoint."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthIntrospectionTokenParamName,
		introspection_token_param_name,
		"Name of the parameter whose value carries the access token value in an validation request to the token introspection endpoint."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE123,
		OIDCOAuthTokenExpiryClaim,
		token_expiry_claim,
		"Name of the claim that carries the token expiry value in the introspection result, optionally followed by absolute|relative, optionally followed by optional|mandatory"),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthSSLValidateServer,
		ssl_validate_server,
		"Require validation of the OAuth 2.0 AS Validation Endpoint SSL server certificate for successful authentication (On or Off)"),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE123,
		OIDCOAuthRemoteUserClaim,
		remote_user_claim,
		"The claim that is used when setting the REMOTE_USER variable for OAuth 2.0 protected paths."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_ITERATE,
		OIDCOAuthVerifyCertFiles,
		verify_public_keys,
		"The fully qualified names of the files that contain the X.509 certificates that contains the RSA/EC public keys that can be used for access token validation."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_ITERATE,
		OIDCOAuthVerifySharedKeys,
		verify_shared_keys,
		"Shared secret(s) that is/are used to verify signed JWT access tokens locally."),
	OIDC_CFG_CMD_OAUTH(
		AP_INIT_TAKE1,
		OIDCOAuthVerifyJwksUri,
		verify_jwks_uri,
		"The JWKs URL on which the Authorization publishes the keys used to sign its JWT access tokens."),

	// dir

	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCPathScope,
		path_scope,
		"Define the OpenID Connect scope that is sent in the authentication request for a specific path/context."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCPathAuthRequestParams,
		path_auth_request_params,
		"Extra parameters that need to be sent in the authentication request: must be query-encoded like \"display=popup&prompt=consent\"."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCDiscoverURL,
		discover_url,
		"Define an external IDP discovery page"),
	OIDC_CFG_CMD_DIR(
		AP_INIT_ITERATE,
		OIDCPassCookies,
		pass_cookies,
		"Specify cookies that need to be passed from the browser on to the backend to the OP/AS."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_ITERATE,
		OIDCStripCookies,
		strip_cookies,
		"Specify cookies that should be stripped from the incoming request before passing it on to the backend."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCAuthNHeader,
		authn_header,
		"Specify the HTTP header variable to set with the name of the authenticated user. By default no explicit header is added but Apache's default REMOTE_USER will be set."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCCookiePath,
		cookie_path,
		"Define the cookie path for the session cookie."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCStateCookiePrefix,
		state_cookie_prefix,
		"Define the cookie prefix for the state cookie."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCCookie,
		cookie,
		"Define the cookie name for the session cookie."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE12,
		OIDCUnAuthAction,
		unauth_action,
		"Set the action taken when an unauthenticated request occurs: must be one of auth | pass | 401 | 407 |410."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE12,
		OIDCUnAutzAction,
		unautz_action,
		"Set the action taken when an unauthorized request occurs: must be one of: 401 [<text>] | 403 [<text>] | 302 [<url>] | auth."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE12,
		OIDCPassClaimsAs,
		pass_claims_as,
		"Specify how claims are passed to the application(s); must be one of: none | headers | environment | both."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_ITERATE,
		OIDCOAuthAcceptTokenAs,
		accept_oauth_token_in,
		"The method in which an OAuth token can be presented; must be one or more of: header | post | query | cookie."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCOAuthTokenIntrospectionInterval,
		token_introspection_interval,
		"Set the token introspection refresh interval."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCPreservePost,
		preserve_post,
		"Indicates whether POST parameters will be preserved across authentication requests."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCPassAccessToken,
		pass_access_token,
		"Pass the access token in a header and/or environment variable (On or Off)"),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCPassRefreshToken,
		pass_refresh_token,
		"Pass the refresh token in a header and/or environment variable (On or Off)"),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE123,
		OIDCPassIDTokenAs,
		pass_idtoken_as,
		"Set the format in which the id_token is passed in (a) header(s); must be one or more of: claims | payload | serialized"),
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE12,
		OIDCRefreshAccessTokenBeforeExpiry,
		refresh_access_token_before_expiry,
		"Ensure the access token is valid for at least <secs> seconds by refreshing it if required; must be: <secs> [logout_on_error | authenticate_on_error]."),
	OIDC_CFG_CMD_DIR(
		AP_INIT_ITERATE,
		OIDCPassUserInfoAs,
		pass_userinfo_as,
		"The format in which the userinfo is passed in (a) header(s); must be one or more of: claims | json | jwt | signed_jwt"),
#ifdef USE_LIBJQ
	OIDC_CFG_CMD_DIR(
		AP_INIT_TAKE1,
		OIDCUserInfoClaimsExpr,
		userinfo_claims_expr,
		"Sets the JQ expression to be executed on the claims from the userinfo endpoint stored in the session before propagating them"),
#endif
		{ NULL }
};

// clang-format on
