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

#ifndef _MOD_AUTH_OPENIDC_CFG_DIRECTIVES_H_
#define _MOD_AUTH_OPENIDC_CFG_DIRECTIVES_H_

/*
 * Single source of truth for the names of the OIDC* Apache configuration
 * directives.
 *
 * Each directive name is defined as a macro whose value equals its own spelling
 * (#define OIDCFoo "OIDCFoo"). That redundancy buys two things:
 *   - the cfg/cmds.c command table and the log/error messages reference one
 *     symbol instead of repeating the literal, so a rename happens in one place;
 *   - a misspelled directive becomes a *compile* error (unknown identifier)
 *     rather than a silently-ignored bare string.
 *
 * The names used to live scattered across cfg.h / provider.h / oauth.h / dir.h /
 * cache.h, interleaved with the accessor-generating macros. They are collected
 * here so those headers carry only structure and API. This header is pulled in
 * via cfg.h, which every other cfg header includes.
 *
 * Grouping below mirrors the config struct that owns each directive; ordering
 * within a group is historical. The memcache/redis names are defined
 * unconditionally (a string macro is free); only their *use* in cmds.c is
 * guarded by USE_MEMCACHE / USE_LIBHIREDIS.
 */

/*
 * base / server-level (see oidc_cfg_t in cfg/cfg_int.h)
 */
#define OIDCPublicKeyFiles "OIDCPublicKeyFiles"
#define OIDCDefaultLoggedOutURL "OIDCDefaultLoggedOutURL"
#define OIDCCookieHTTPOnly "OIDCCookieHTTPOnly"
#define OIDCCookieSameSite "OIDCCookieSameSite"
#define OIDCOutgoingProxy "OIDCOutgoingProxy"
#define OIDCClaimDelimiter "OIDCClaimDelimiter"
#define OIDCHTTPTimeoutLong "OIDCHTTPTimeoutLong"
#define OIDCHTTPTimeoutShort "OIDCHTTPTimeoutShort"
#define OIDCStateTimeout "OIDCStateTimeout"
#define OIDCStateMaxNumberOfCookies "OIDCStateMaxNumberOfCookies"
#define OIDCSessionInactivityTimeout "OIDCSessionInactivityTimeout"
#define OIDCMetadataDir "OIDCMetadataDir"
#define OIDCSessionCacheFallbackToCookie "OIDCSessionCacheFallbackToCookie"
#define OIDCSessionCookieChunkSize "OIDCSessionCookieChunkSize"
#define OIDCPreservePostTemplates "OIDCPreservePostTemplates"
#define OIDCProviderMetadataRefreshInterval "OIDCProviderMetadataRefreshInterval"
#define OIDCBlackListedClaims "OIDCBlackListedClaims"
#define OIDCStateInputHeaders "OIDCStateInputHeaders"
#define OIDCRedirectURLsAllowed "OIDCRedirectURLsAllowed"
#define OIDCCABundlePath "OIDCCABundlePath"
#define OIDCLogoutXFrameOptions "OIDCLogoutXFrameOptions"
#define OIDCXForwardedHeaders "OIDCXForwardedHeaders"
#define OIDCFilterClaimsExpr "OIDCFilterClaimsExpr"
#define OIDCTraceParent "OIDCTraceParent"
#define OIDCPrivateKeyFiles "OIDCPrivateKeyFiles"
#define OIDCRedirectURI "OIDCRedirectURI"
#define OIDCDefaultURL "OIDCDefaultURL"
#define OIDCCookieDomain "OIDCCookieDomain"
#define OIDCClaimPrefix "OIDCClaimPrefix"
#define OIDCRemoteUserClaim "OIDCRemoteUserClaim"
#define OIDCOAuthRemoteUserClaim "OIDCOAuthRemoteUserClaim"
#define OIDCSessionType "OIDCSessionType"
#define OIDCInfoHook "OIDCInfoHook"
#define OIDCMetricsData "OIDCMetricsData"
#define OIDCMetricsPublish "OIDCMetricsPublish"
#define OIDCWhiteListedClaims "OIDCWhiteListedClaims"
#define OIDCCryptoPassphrase "OIDCCryptoPassphrase"

/*
 * provider (see oidc_provider_t in cfg/provider.c)
 */
#define OIDCProviderMetadataURL "OIDCProviderMetadataURL"
#define OIDCProviderIssuer "OIDCProviderIssuer"
#define OIDCProviderAuthorizationEndpoint "OIDCProviderAuthorizationEndpoint"
#define OIDCProviderTokenEndpoint "OIDCProviderTokenEndpoint"
#define OIDCProviderTokenEndpointAuth "OIDCProviderTokenEndpointAuth"
#define OIDCProviderTokenEndpointParams "OIDCProviderTokenEndpointParams"
#define OIDCProviderRegistrationEndpointJson "OIDCProviderRegistrationEndpointJson"
#define OIDCProviderUserInfoEndpoint "OIDCProviderUserInfoEndpoint"
#define OIDCProviderRevocationEndpoint "OIDCProviderRevocationEndpoint"
#define OIDCProviderPushedAuthorizationRequestEndpoint "OIDCProviderPushedAuthorizationRequestEndpoint"
#define OIDCProviderCheckSessionIFrame "OIDCProviderCheckSessionIFrame"
#define OIDCProviderEndSessionEndpoint "OIDCProviderEndSessionEndpoint"
#define OIDCProviderBackChannelLogoutSupported "OIDCProviderBackChannelLogoutSupported"
#define OIDCProviderJwksUri "OIDCProviderJwksUri"
#define OIDCProviderSignedJwksUri "OIDCProviderSignedJwksUri"
#define OIDCProviderVerifyCertFiles "OIDCProviderVerifyCertFiles"
#define OIDCResponseType "OIDCResponseType"
#define OIDCProviderAuthRequestMethod "OIDCProviderAuthRequestMethod"
#define OIDCProfile "OIDCProfile"
#define OIDCPKCEMethod "OIDCPKCEMethod"
#define OIDCDPoPMode "OIDCDPoPMode"
#define OIDCResponseMode "OIDCResponseMode"
#define OIDCClientJwksUri "OIDCClientJwksUri"
#define OIDCIDTokenSignedResponseAlg "OIDCIDTokenSignedResponseAlg"
#define OIDCIDTokenEncryptedResponseAlg "OIDCIDTokenEncryptedResponseAlg"
#define OIDCIDTokenEncryptedResponseEnc "OIDCIDTokenEncryptedResponseEnc"
#define OIDCIDTokenAudValues "OIDCIDTokenAudValues"
#define OIDCUserInfoSignedResponseAlg "OIDCUserInfoSignedResponseAlg"
#define OIDCUserInfoEncryptedResponseAlg "OIDCUserInfoEncryptedResponseAlg"
#define OIDCUserInfoEncryptedResponseEnc "OIDCUserInfoEncryptedResponseEnc"
#define OIDCUserInfoTokenMethod "OIDCUserInfoTokenMethod"
#define OIDCSSLValidateServer "OIDCSSLValidateServer"
#define OIDCValidateIssuer "OIDCValidateIssuer"
#define OIDCClientName "OIDCClientName"
#define OIDCClientContact "OIDCClientContact"
#define OIDCScope "OIDCScope"
#define OIDCJWKSRefreshInterval "OIDCJWKSRefreshInterval"
#define OIDCIDTokenIatSlack "OIDCIDTokenIatSlack"
#define OIDCSessionMaxDuration "OIDCSessionMaxDuration"
#define OIDCAuthRequestParams "OIDCAuthRequestParams"
#define OIDCLogoutRequestParams "OIDCLogoutRequestParams"
#define OIDCClientID "OIDCClientID"
#define OIDCClientSecret "OIDCClientSecret"
#define OIDCClientTokenEndpointCert "OIDCClientTokenEndpointCert"
#define OIDCClientTokenEndpointKey "OIDCClientTokenEndpointKey"
#define OIDCClientTokenEndpointKeyPassword "OIDCClientTokenEndpointKeyPassword"
#define OIDCUserInfoRefreshInterval "OIDCUserInfoRefreshInterval"
#define OIDCRequestObject "OIDCRequestObject"

/*
 * OAuth 2.0 resource server (see oidc_oauth_t in cfg/oauth.c)
 */
#define OIDCOAuthServerMetadataURL "OIDCOAuthServerMetadataURL"
#define OIDCOAuthClientID "OIDCOAuthClientID"
#define OIDCOAuthClientSecret "OIDCOAuthClientSecret"
#define OIDCOAuthIntrospectionClientAuthBearerToken "OIDCOAuthIntrospectionClientAuthBearerToken"
#define OIDCOAuthIntrospectionEndpoint "OIDCOAuthIntrospectionEndpoint"
#define OIDCOAuthIntrospectionEndpointMethod "OIDCOAuthIntrospectionEndpointMethod"
#define OIDCOAuthIntrospectionEndpointParams "OIDCOAuthIntrospectionEndpointParams"
#define OIDCOAuthIntrospectionEndpointAuth "OIDCOAuthIntrospectionEndpointAuth"
#define OIDCOAuthIntrospectionEndpointCert "OIDCOAuthIntrospectionEndpointCert"
#define OIDCOAuthIntrospectionEndpointKey "OIDCOAuthIntrospectionEndpointKey"
#define OIDCOAuthIntrospectionEndpointKeyPassword "OIDCOAuthIntrospectionEndpointKeyPassword"
#define OIDCOAuthIntrospectionTokenParamName "OIDCOAuthIntrospectionTokenParamName"
#define OIDCOAuthTokenExpiryClaim "OIDCOAuthTokenExpiryClaim"
#define OIDCOAuthSSLValidateServer "OIDCOAuthSSLValidateServer"
#define OIDCOAuthVerifyCertFiles "OIDCOAuthVerifyCertFiles"
#define OIDCOAuthVerifySharedKeys "OIDCOAuthVerifySharedKeys"
#define OIDCOAuthVerifyJwksUri "OIDCOAuthVerifyJwksUri"

/*
 * per-directory (see oidc_dir_cfg_t in cfg/dir.c)
 */
#define OIDCPathScope "OIDCPathScope"
#define OIDCPathAuthRequestParams "OIDCPathAuthRequestParams"
#define OIDCDiscoverURL "OIDCDiscoverURL"
#define OIDCPassCookies "OIDCPassCookies"
#define OIDCStripCookies "OIDCStripCookies"
#define OIDCAuthNHeader "OIDCAuthNHeader"
#define OIDCCookie "OIDCCookie"
#define OIDCUnAuthAction "OIDCUnAuthAction"
#define OIDCUnAutzAction "OIDCUnAutzAction"
#define OIDCPassClaimsAs "OIDCPassClaimsAs"
#define OIDCOAuthAcceptTokenAs "OIDCOAuthAcceptTokenAs"
#define OIDCOAuthTokenIntrospectionInterval "OIDCOAuthTokenIntrospectionInterval"
#define OIDCPreservePost "OIDCPreservePost"
#define OIDCPassAccessToken "OIDCPassAccessToken"
#define OIDCPassRefreshToken "OIDCPassRefreshToken"
#define OIDCRefreshAccessTokenBeforeExpiry "OIDCRefreshAccessTokenBeforeExpiry"
#define OIDCStateCookiePrefix "OIDCStateCookiePrefix"
#define OIDCPassIDTokenAs "OIDCPassIDTokenAs"
#define OIDCPassUserInfoAs "OIDCPassUserInfoAs"
#define OIDCUserInfoClaimsExpr "OIDCUserInfoClaimsExpr"
#define OIDCCookiePath "OIDCCookiePath"

/*
 * cache (see oidc_cfg_cache_t in cfg/cfg_int.h); the memcache/redis names are
 * guarded like the rest of those backends, mirroring cfg/cache.h
 */
#define OIDCCacheType "OIDCCacheType"
#define OIDCCacheEncrypt "OIDCCacheEncrypt"
#define OIDCCacheShmMax "OIDCCacheShmMax"
#define OIDCCacheShmEntrySizeMax "OIDCCacheShmEntrySizeMax"
#define OIDCCacheDir "OIDCCacheDir"
#define OIDCCacheFileCleanInterval "OIDCCacheFileCleanInterval"

#ifdef USE_MEMCACHE
#define OIDCMemCacheServers "OIDCMemCacheServers"
#define OIDCMemCacheConnectionsMin "OIDCMemCacheConnectionsMin"
#define OIDCMemCacheConnectionsSMax "OIDCMemCacheConnectionsSMax"
#define OIDCMemCacheConnectionsHMax "OIDCMemCacheConnectionsHMax"
#define OIDCMemCacheConnectionsTTL "OIDCMemCacheConnectionsTTL"
#endif // USE_MEMCACHE

#ifdef USE_LIBHIREDIS
#define OIDCRedisCacheServer "OIDCRedisCacheServer"
#define OIDCRedisCacheUsername "OIDCRedisCacheUsername"
#define OIDCRedisCachePassword "OIDCRedisCachePassword"
#define OIDCRedisCacheDatabase "OIDCRedisCacheDatabase"
#define OIDCRedisCacheConnectTimeout "OIDCRedisCacheConnectTimeout"
#define OIDCRedisCacheTimeout "OIDCRedisCacheTimeout"
#endif // USE_LIBHIREDIS

#endif // _MOD_AUTH_OPENIDC_CFG_DIRECTIVES_H_
