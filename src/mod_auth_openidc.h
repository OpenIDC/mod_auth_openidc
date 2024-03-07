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
 * Copyright (C) 2013-2017 Ping Identity Corporation
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

#ifndef MOD_AUTH_OPENIDC_H_
#define MOD_AUTH_OPENIDC_H_

#include "const.h"

// clang-format off

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <mod_auth.h>

// clang-format on

#include <apr_base64.h>
#include <apr_lib.h>
#include <apr_sha1.h>
#include <apr_uuid.h>

#include "cache/cache.h"
#include "http.h"
#include "jose.h"
#include "parse.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_openidc);
#endif

#define OIDC_AUTH_TYPE_OPENID_CONNECT "openid-connect"
#define OIDC_AUTH_TYPE_OPENID_OAUTH20 "oauth20"
#define OIDC_AUTH_TYPE_OPENID_BOTH "auth-openidc"

/* keys for storing info in the request state */
#define OIDC_REQUEST_STATE_KEY_IDTOKEN "i"
#define OIDC_REQUEST_STATE_KEY_CLAIMS "c"
#define OIDC_REQUEST_STATE_KEY_DISCOVERY "d"
#define OIDC_REQUEST_STATE_KEY_AUTHN "a"
#define OIDC_REQUEST_STATE_KEY_SAVE "s"
#define OIDC_REQUEST_STATE_TRACE_ID "t"

/* parameter name of the callback URL in the discovery response */
#define OIDC_DISC_CB_PARAM "oidc_callback"
/* parameter name of the OP provider selection in the discovery response */
#define OIDC_DISC_OP_PARAM "iss"
/* parameter name of the user URL in the discovery response */
#define OIDC_DISC_USER_PARAM "disc_user"
/* parameter name of the original URL in the discovery response */
#define OIDC_DISC_RT_PARAM "target_link_uri"
/* parameter name of the original method in the discovery response */
#define OIDC_DISC_RM_PARAM "method"
/* parameter name of login hint in the discovery response */
#define OIDC_DISC_LH_PARAM "login_hint"
/* parameter name of parameters that need to be passed in the authentication request */
#define OIDC_DISC_AR_PARAM "auth_request_params"
/* parameter name of the scopes required in the discovery response */
#define OIDC_DISC_SC_PARAM "scopes"

/* value that indicates to use server-side cache based session tracking */
#define OIDC_SESSION_TYPE_SERVER_CACHE 0
/* value that indicates to use client cookie based session tracking */
#define OIDC_SESSION_TYPE_CLIENT_COOKIE 1

/* nonce bytes length */
#define OIDC_PROTO_NONCE_LENGTH 32

/* code verifier length */
#define OIDC_PROTO_CODE_VERIFIER_LENGTH 32

/* pass id_token as individual claims in headers (default) */
#define OIDC_PASS_IDTOKEN_AS_CLAIMS 1
/* pass id_token payload as JSON object in header */
#define OIDC_PASS_IDTOKEN_AS_PAYLOAD 2
/* pass id_token in compact serialized format in header */
#define OIDC_PASS_IDTOKEN_AS_SERIALIZED 4

/* pass userinfo as individual claims in headers (default) */
#define OIDC_PASS_USERINFO_AS_CLAIMS 1
/* pass userinfo payload as JSON object in header */
#define OIDC_PASS_USERINFO_AS_JSON_OBJECT 2
/* pass userinfo as a JWT in header (when returned as a JWT) */
#define OIDC_PASS_USERINFO_AS_JWT 3
/* pass as re-signed JWT including id_token claims */
#define OIDC_PASS_USERINFO_AS_SIGNED_JWT 4

#define OIDC_PASS_APP_INFO_AS_NONE 0
#define OIDC_PASS_APP_INFO_AS_BASE64URL 1
#define OIDC_PASS_APP_INFO_AS_LATIN1 2

/* actions to be taken on access token / userinfo refresh error */
#define OIDC_ON_ERROR_CONTINUE 0
#define OIDC_ON_ERROR_LOGOUT 1
#define OIDC_ON_ERROR_AUTHENTICATE 2

#define OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT 0
/* accept bearer token in header (default) */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER 1
/* accept bearer token as a post parameter */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_POST 2
/* accept bearer token as a query parameter */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY 4
/* accept bearer token as a cookie parameter (PingAccess) */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE 8
/* accept bearer token as basic auth password (non-oauth clients) */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC 16

/* the hash key of the cookie name value in the list of options */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME "cookie-name"

/* introspection method options */
#define OIDC_INTROSPECTION_METHOD_GET "GET"
#define OIDC_INTROSPECTION_METHOD_POST "POST"

/* HTTP methods to send authentication requests */
#define OIDC_AUTH_REQUEST_METHOD_GET 0
#define OIDC_AUTH_REQUEST_METHOD_POST 1

/* default prefix for information passed in HTTP headers */
#define OIDC_DEFAULT_HEADER_PREFIX "OIDC_"

/* the (global) key for the mod_auth_openidc related state that is stored in the request userdata context */
#define OIDC_USERDATA_KEY "mod_auth_openidc_state"
#define OIDC_USERDATA_SESSION "mod_auth_openidc_session"
#define OIDC_USERDATA_POST_PARAMS_KEY "oidc_userdata_post_params"

#define OIDC_POST_PRESERVE_ESCAPE_NONE 0
#define OIDC_POST_PRESERVE_ESCAPE_HTML 1
#define OIDC_POST_PRESERVE_ESCAPE_JAVASCRIPT 2

/* input filter hook name */
#define OIDC_UTIL_HTTP_SENDSTRING "OIDC_UTIL_HTTP_SENDSTRING"

/* the name of the keyword that follows the Require primitive to indicate claims-based authorization */
#define OIDC_REQUIRE_CLAIM_NAME "claim"
#ifdef USE_LIBJQ
/* the name of the keyword that follows the Require primitive to indicate claims-expression-based authorization */
#define OIDC_REQUIRE_CLAIMS_EXPR_NAME "claims_expr"
#endif

/* defines for how long provider metadata will be cached */
#define OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT 86400

/* define the parameter value for the "logout" request that indicates a GET-style logout call from the OP */
#define OIDC_GET_STYLE_LOGOUT_PARAM_VALUE "get"
#define OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE "img"
#define OIDC_BACKCHANNEL_STYLE_LOGOUT_PARAM_VALUE "backchannel"

/* define the name of the cookie/parameter for CSRF protection */
#define OIDC_CSRF_NAME "x_csrf"

/* http methods */
#define OIDC_METHOD_GET "get"
#define OIDC_METHOD_FORM_POST "form_post"

/* the maximum size of data that we accept in a single POST value: 1MB */
#define OIDC_MAX_POST_DATA_LEN 1024 * 1024

#define OIDC_UNAUTH_AUTHENTICATE 1
#define OIDC_UNAUTH_PASS 2
#define OIDC_UNAUTH_RETURN401 3
#define OIDC_UNAUTH_RETURN410 4
#define OIDC_UNAUTH_RETURN407 5

#define OIDC_UNAUTZ_RETURN403 1
#define OIDC_UNAUTZ_RETURN401 2
#define OIDC_UNAUTZ_AUTHENTICATE 3
#define OIDC_UNAUTZ_RETURN302 4

#define OIDC_USER_INFO_TOKEN_METHOD_HEADER 0
#define OIDC_USER_INFO_TOKEN_METHOD_POST 1

#define OIDC_COOKIE_EXT_SAME_SITE_LAX "SameSite=Lax"
#define OIDC_COOKIE_EXT_SAME_SITE_STRICT "SameSite=Strict"
#define OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r) oidc_util_request_is_secure(r, c) ? "SameSite=None" : NULL

#define OIDC_COOKIE_SAMESITE_STRICT(c, r)                                                                              \
	c->cookie_same_site ? OIDC_COOKIE_EXT_SAME_SITE_STRICT : OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r)
#define OIDC_COOKIE_SAMESITE_LAX(c, r)                                                                                 \
	c->cookie_same_site ? OIDC_COOKIE_EXT_SAME_SITE_LAX : OIDC_COOKIE_EXT_SAME_SITE_NONE(c, r)

#define OIDC_ERROR_ENVVAR "OIDC_ERROR"
#define OIDC_ERROR_DESC_ENVVAR "OIDC_ERROR_DESC"

#define OIDC_STATE_INPUT_HEADERS_USER_AGENT 1
#define OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR 2

#define OIDC_HDR_X_FORWARDED_HOST 1
#define OIDC_HDR_X_FORWARDED_PORT 2
#define OIDC_HDR_X_FORWARDED_PROTO 4
#define OIDC_HDR_FORWARDED 8

#define OIDC_TRACE_PARENT_OFF 0
#define OIDC_TRACE_PARENT_PROPAGATE 1
#define OIDC_TRACE_PARENT_GENERATE 2

typedef apr_byte_t (*oidc_proto_pkce_state)(request_rec *r, char **state);
typedef apr_byte_t (*oidc_proto_pkce_challenge)(request_rec *r, const char *state, char **code_challenge);
typedef apr_byte_t (*oidc_proto_pkce_verifier)(request_rec *r, const char *state, char **code_verifier);

typedef struct oidc_proto_pkce_t {
	const char *method;
	oidc_proto_pkce_state state;
	oidc_proto_pkce_verifier verifier;
	oidc_proto_pkce_challenge challenge;
} oidc_proto_pkce_t;

extern oidc_proto_pkce_t oidc_pkce_plain;
extern oidc_proto_pkce_t oidc_pkce_s256;

typedef struct oidc_jwks_uri_t {
	char *uri;
	int refresh_interval;
	char *signed_uri;
	apr_array_header_t *jwk_list;
} oidc_jwks_uri_t;

typedef struct oidc_provider_t {
	char *metadata_url;
	char *issuer;
	char *authorization_endpoint_url;
	char *token_endpoint_url;
	char *token_endpoint_auth;
	char *token_endpoint_params;
	char *userinfo_endpoint_url;
	char *revocation_endpoint_url;
	char *registration_endpoint_url;
	char *check_session_iframe;
	char *end_session_endpoint;
	oidc_jwks_uri_t jwks_uri;
	apr_array_header_t *verify_public_keys;
	char *client_id;
	char *client_secret;
	char *token_endpoint_tls_client_key;
	char *token_endpoint_tls_client_key_pwd;
	char *token_endpoint_tls_client_cert;
	int backchannel_logout_supported;

	// the next ones function as global default settings too
	int ssl_validate_server;
	int validate_issuer;
	char *client_name;
	char *client_contact;
	char *registration_token;
	char *registration_endpoint_json;
	char *scope;
	char *response_type;
	char *response_mode;
	int idtoken_iat_slack;
	char *auth_request_params;
	char *logout_request_params;
	int session_max_duration;
	oidc_proto_pkce_t *pkce;
	int userinfo_refresh_interval;
	apr_array_header_t *client_keys;
	char *client_jwks_uri;
	char *id_token_signed_response_alg;
	char *id_token_encrypted_response_alg;
	char *id_token_encrypted_response_enc;
	char *userinfo_signed_response_alg;
	char *userinfo_encrypted_response_alg;
	char *userinfo_encrypted_response_enc;
	int userinfo_token_method;
	char *request_object;
	int auth_request_method;

	int issuer_specific_redirect_uri;
} oidc_provider_t;

typedef struct oidc_remote_user_claim_t {
	const char *claim_name;
	const char *reg_exp;
	const char *replace;
} oidc_remote_user_claim_t;

typedef struct oidc_apr_expr_t {
#if HAVE_APACHE_24
	ap_expr_info_t *expr;
#endif
	char *str;
} oidc_apr_expr_t;

typedef struct oidc_oauth_t {
	int ssl_validate_server;
	char *client_id;
	char *client_secret;
	char *metadata_url;
	char *introspection_endpoint_tls_client_key;
	char *introspection_endpoint_tls_client_key_pwd;
	char *introspection_endpoint_tls_client_cert;
	char *introspection_endpoint_url;
	char *introspection_endpoint_method;
	char *introspection_endpoint_params;
	char *introspection_endpoint_auth;
	char *introspection_client_auth_bearer_token;
	char *introspection_token_param_name;
	char *introspection_token_expiry_claim_name;
	char *introspection_token_expiry_claim_format;
	int introspection_token_expiry_claim_required;
	oidc_remote_user_claim_t remote_user_claim;
	apr_hash_t *verify_shared_keys;
	char *verify_jwks_uri;
	apr_array_header_t *verify_public_keys;
} oidc_oauth_t;

typedef struct oidc_crypto_passphrase_t {
	char *secret1;
	char *secret2;
} oidc_crypto_passphrase_t;

typedef struct oidc_cfg {
	/* indicates whether this is a derived config, merged from a base one */
	unsigned int merged;

	/* HTML to display error messages+description */
	char *error_template;
	/* Javascript template to preserve POST data */
	char *post_preserve_template;
	/* Javascript template to restore POST data */
	char *post_restore_template;

	/* the redirect URI as configured with the OpenID Connect OP's that we talk to */
	char *redirect_uri;
	/* (optional) default URL for 3rd-party initiated SSO */
	char *default_sso_url;
	/* (optional) default URL to go to after logout */
	char *default_slo_url;

	/* public keys in JWK format, used by parters for encrypting JWTs sent to us */
	apr_array_header_t *public_keys;
	/* private keys in JWK format used for decrypting encrypted JWTs sent to us */
	apr_array_header_t *private_keys;

	/* a pointer to the (single) provider that we connect to */
	/* NB: if metadata_dir is set, these settings will function as defaults for the metadata read from there) */
	oidc_provider_t provider;
	/* a pointer to the oauth server settings */
	oidc_oauth_t oauth;

	/* directory that holds the provider & client metadata files */
	char *metadata_dir;
	/* type of session management/storage */
	int session_type;
	/* session cookie or persistent cookie */
	int persistent_session_cookie;
	/* store the id_token in the session */
	apr_byte_t store_id_token;
	/* session cookie chunk size */
	int session_cookie_chunk_size;

	/* pointer to cache functions */
	oidc_cache_t *cache;
	void *cache_cfg;
	/* cache_type = file: directory that holds the cache files (if not set, we'll try and use an OS defined one like
	 * "/tmp" */
	char *cache_file_dir;
	/* cache_type = file: clean interval */
	int cache_file_clean_interval;
#ifdef USE_MEMCACHE
	/* cache_type= memcache: list of memcache host/port servers to use */
	char *cache_memcache_servers;
	/* cache_type= memcache: minimum number of connections to each memcache server per process*/
	apr_uint32_t cache_memcache_min;
	/* cache_type= memcache: soft maximum number of connections to each memcache server per process */
	apr_uint32_t cache_memcache_smax;
	/* cache_type= memcache: hard maximum number of connections to each memcache server per process */
	apr_uint32_t cache_memcache_hmax;
	/* cache_type= memcache: maximum time in microseconds a connection to a memcache server can be idle before being
	 * closed */
	apr_uint32_t cache_memcache_ttl;
#endif
	/* cache_type = shm: size of the shared memory segment (cq. max number of cached entries) */
	int cache_shm_size_max;
	/* cache_type = shm: maximum size in bytes of a cache entry */
	int cache_shm_entry_size_max;
#ifdef USE_LIBHIREDIS
	/* cache_type= redis: Redis host/port server to use */
	char *cache_redis_server;
	char *cache_redis_username;
	char *cache_redis_password;
	int cache_redis_database;
	int cache_redis_connect_timeout;
	int cache_redis_keepalive;
	int cache_redis_timeout;
#endif
	int cache_encrypt;

	oidc_http_timeout_t http_timeout_long;
	oidc_http_timeout_t http_timeout_short;
	int state_timeout;
	int max_number_of_state_cookies;
	int delete_oldest_state_cookies;
	int session_inactivity_timeout;
	int session_cache_fallback_to_cookie;

	char *cookie_domain;
	char *claim_delimiter;
	char *claim_prefix;
	oidc_remote_user_claim_t remote_user_claim;
	int cookie_http_only;
	int cookie_same_site;

	oidc_http_outgoing_proxy_t outgoing_proxy;

	oidc_crypto_passphrase_t crypto_passphrase;

	int provider_metadata_refresh_interval;

	apr_hash_t *info_hook_data;
	apr_hash_t *metrics_hook_data;
	char *metrics_path;
	int trace_parent;

	apr_hash_t *black_listed_claims;
	apr_hash_t *white_listed_claims;
	oidc_apr_expr_t *filter_claims_expr;

	apr_byte_t state_input_headers;
	apr_hash_t *redirect_urls_allowed;
	char *ca_bundle_path;
	char *logout_x_frame_options;
	apr_byte_t x_forwarded_headers;
	int action_on_userinfo_error;
	oidc_cache_mutex_t *refresh_mutex;
} oidc_cfg;

typedef struct {
	char *uuid;	   /* unique id */
	char *remote_user; /* user who owns this particular session */
	json_t *state;	   /* the state for this session, encoded in a JSON object */
	apr_time_t expiry; /* if > 0, the time of expiry of this session */
	char *sid;
} oidc_session_t;

void oidc_pre_config_init();
int oidc_fixups(request_rec *r);
int oidc_check_user_id(request_rec *r);
void oidc_request_state_set(request_rec *r, const char *key, const char *value);
const char *oidc_request_state_get(request_rec *r, const char *key);
void oidc_scrub_headers(request_rec *r);
void oidc_strip_cookies(request_rec *r);
apr_byte_t oidc_get_remote_user(request_rec *r, const char *claim_name, const char *replace, const char *reg_exp,
				json_t *json, char **request_user);
apr_byte_t oidc_get_provider_from_session(request_rec *r, oidc_cfg *c, oidc_session_t *session,
					  oidc_provider_t **provider);
apr_byte_t oidc_session_pass_tokens(request_rec *r, oidc_cfg *cfg, oidc_session_t *session, apr_byte_t *needs_save);
void oidc_log_session_expires(request_rec *r, const char *msg, apr_time_t session_expires);
apr_byte_t oidc_provider_static_config(request_rec *r, oidc_cfg *c, oidc_provider_t **provider);
const char *oidc_original_request_method(request_rec *r, oidc_cfg *cfg, apr_byte_t handle_discovery_response);
oidc_provider_t *oidc_get_provider_for_issuer(request_rec *r, oidc_cfg *c, const char *issuer,
					      apr_byte_t allow_discovery);
char *oidc_get_state_cookie_name(request_rec *r, const char *state);
int oidc_clean_expired_state_cookies(request_rec *r, oidc_cfg *c, const char *currentCookieName, int delete_oldest);
char *oidc_get_browser_state_hash(request_rec *r, oidc_cfg *c, const char *nonce);
apr_byte_t oidc_is_auth_capable_request(request_rec *r);

#define OIDC_REDIRECT_URI_REQUEST_INFO "info"
#define OIDC_REDIRECT_URI_REQUEST_LOGOUT "logout"
#define OIDC_REDIRECT_URI_REQUEST_JWKS "jwks"
#define OIDC_REDIRECT_URI_REQUEST_SESSION "session"
#define OIDC_REDIRECT_URI_REQUEST_REFRESH "refresh"
#define OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE "remove_at_cache"
#define OIDC_REDIRECT_URI_REQUEST_REVOKE_SESSION "revoke_session"
#define OIDC_REDIRECT_URI_REQUEST_REQUEST_URI "request_uri"
#define OIDC_REDIRECT_URI_REQUEST_SID "sid"
#define OIDC_REDIRECT_URI_REQUEST_ISS "iss"

// oidc_oauth
int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c, const char *access_token);
apr_byte_t oidc_oauth_get_bearer_token(request_rec *r, const char **access_token);

// oidc_proto.c
#define OIDC_PROTO_ISS "iss"
#define OIDC_PROTO_CODE "code"
#define OIDC_PROTO_CLIENT_ID "client_id"
#define OIDC_PROTO_CLIENT_SECRET "client_secret"
#define OIDC_PROTO_CLIENT_ASSERTION "client_assertion"
#define OIDC_PROTO_CLIENT_ASSERTION_TYPE "client_assertion_type"
#define OIDC_PROTO_ACCESS_TOKEN "access_token"
#define OIDC_PROTO_ID_TOKEN "id_token"
#define OIDC_PROTO_STATE "state"
#define OIDC_PROTO_GRANT_TYPE "grant_type"
#define OIDC_PROTO_REDIRECT_URI "redirect_uri"
#define OIDC_PROTO_CODE_VERIFIER "code_verifier"
#define OIDC_PROTO_CODE_CHALLENGE "code_challenge"
#define OIDC_PROTO_CODE_CHALLENGE_METHOD "code_challenge_method"
#define OIDC_PROTO_SCOPE "scope"
#define OIDC_PROTO_REFRESH_TOKEN "refresh_token"
#define OIDC_PROTO_TOKEN_TYPE "token_type"
#define OIDC_PROTO_TOKEN_TYPE_HINT "token_type_hint"
#define OIDC_PROTO_TOKEN "token"
#define OIDC_PROTO_EXPIRES_IN "expires_in"
#define OIDC_PROTO_RESPONSE_TYPE "response_type"
#define OIDC_PROTO_RESPONSE_MODE "response_mode"
#define OIDC_PROTO_NONCE "nonce"
#define OIDC_PROTO_PROMPT "prompt"
#define OIDC_PROTO_LOGIN_HINT "login_hint"
#define OIDC_PROTO_ID_TOKEN_HINT "id_token_hint"
#define OIDC_PROTO_REQUEST_URI "request_uri"
#define OIDC_PROTO_REQUEST_OBJECT "request"
#define OIDC_PROTO_SESSION_STATE "session_state"
#define OIDC_PROTO_ACTIVE "active"
#define OIDC_PROTO_LOGOUT_TOKEN "logout_token"

#define OIDC_PROTO_RESPONSE_TYPE_CODE "code"
#define OIDC_PROTO_RESPONSE_TYPE_IDTOKEN "id_token"
#define OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN "id_token token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN "code id_token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN "code token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN "code id_token token"
#define OIDC_PROTO_RESPONSE_TYPE_TOKEN "token"

#define OIDC_PROTO_RESPONSE_MODE_QUERY "query"
#define OIDC_PROTO_RESPONSE_MODE_FRAGMENT "fragment"
#define OIDC_PROTO_RESPONSE_MODE_FORM_POST "form_post"

#define OIDC_PROTO_SCOPE_OPENID "openid"
#define OIDC_PROTO_PROMPT_NONE "none"
#define OIDC_PROTO_ERROR "error"
#define OIDC_PROTO_ERROR_DESCRIPTION "error_description"
#define OIDC_PROTO_REALM "realm"

#define OIDC_PROTO_ERR_INVALID_TOKEN "invalid_token"
#define OIDC_PROTO_ERR_INVALID_REQUEST "invalid_request"

#define OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE "authorization_code"
#define OIDC_PROTO_GRANT_TYPE_REFRESH_TOKEN "refresh_token"

#define OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#define OIDC_PROTO_CLIENT_SECRET_BASIC "client_secret_basic"
#define OIDC_PROTO_CLIENT_SECRET_POST "client_secret_post"
#define OIDC_PROTO_CLIENT_SECRET_JWT "client_secret_jwt"
#define OIDC_PROTO_PRIVATE_KEY_JWT "private_key_jwt"
#define OIDC_PROTO_BEARER_ACCESS_TOKEN "bearer_access_token"
#define OIDC_PROTO_ENDPOINT_AUTH_NONE "none"

#define OIDC_PROTO_BEARER "Bearer"
#define OIDC_PROTO_BASIC "Basic"

#define OIDC_CLAIM_ISS "iss"
#define OIDC_CLAIM_AUD "aud"
#define OIDC_CLAIM_AZP "azp"
#define OIDC_CLAIM_SUB "sub"
#define OIDC_CLAIM_JTI "jti"
#define OIDC_CLAIM_EXP "exp"
#define OIDC_CLAIM_IAT "iat"
#define OIDC_CLAIM_NONCE "nonce"
#define OIDC_CLAIM_AT_HASH "at_hash"
#define OIDC_CLAIM_C_HASH "c_hash"
#define OIDC_CLAIM_RFP "rfp"
#define OIDC_CLAIM_TARGET_LINK_URI "target_link_uri"
#define OIDC_CLAIM_SID "sid"
#define OIDC_CLAIM_EVENTS "events"

#define OIDC_HOOK_INFO_FORMAT_JSON "json"
#define OIDC_HOOK_INFO_FORMAT_HTML "html"
#define OIDC_HOOK_INFO_TIMESTAMP "iat"
#define OIDC_HOOK_INFO_ACCES_TOKEN "access_token"
#define OIDC_HOOK_INFO_ACCES_TOKEN_EXP "access_token_expires"
#define OIDC_HOOK_INFO_ID_TOKEN_HINT "id_token_hint"
#define OIDC_HOOK_INFO_ID_TOKEN "id_token"
#define OIDC_HOOK_INFO_USER_INFO "userinfo"
#define OIDC_HOOK_INFO_SESSION "session"
#define OIDC_HOOK_INFO_SESSION_STATE "state"
#define OIDC_HOOK_INFO_SESSION_UUID "uuid"
#define OIDC_HOOK_INFO_SESSION_EXP "exp"
#define OIDC_HOOK_INFO_SESSION_TIMEOUT "timeout"
#define OIDC_HOOK_INFO_SESSION_REMOTE_USER "remote_user"
#define OIDC_HOOK_INFO_REFRESH_TOKEN "refresh_token"

#define OIDC_STR_SPACE " "
#define OIDC_STR_EQUAL "="
#define OIDC_STR_AMP "&"
#define OIDC_STR_QUERY "?"
#define OIDC_STR_COLON ":"
#define OIDC_STR_SEMI_COLON ";"
#define OIDC_STR_FORWARD_SLASH "/"
#define OIDC_STR_AT "@"
#define OIDC_STR_COMMA ","
#define OIDC_STR_HASH "#"

#define OIDC_CHAR_EQUAL '='
#define OIDC_CHAR_COLON ':'
#define OIDC_CHAR_TILDE '~'
#define OIDC_CHAR_SPACE ' '
#define OIDC_CHAR_COMMA ','
#define OIDC_CHAR_QUERY '?'
#define OIDC_CHAR_DOT '.'
#define OIDC_CHAR_AT '@'
#define OIDC_CHAR_FORWARD_SLASH '/'
#define OIDC_CHAR_PIPE '|'
#define OIDC_CHAR_AMP '&'
#define OIDC_CHAR_SEMI_COLON ';'

#define OIDC_APP_INFO_REFRESH_TOKEN "refresh_token"
#define OIDC_APP_INFO_ACCESS_TOKEN "access_token"
#define OIDC_APP_INFO_ACCESS_TOKEN_EXP "access_token_expires"
#define OIDC_APP_INFO_ID_TOKEN "id_token"
#define OIDC_APP_INFO_ID_TOKEN_PAYLOAD "id_token_payload"
#define OIDC_APP_INFO_USERINFO_JSON "userinfo_json"
#define OIDC_APP_INFO_USERINFO_JWT "userinfo_jwt"
#define OIDC_APP_INFO_SIGNED_JWT "signed_jwt"

typedef json_t oidc_proto_state_t;

oidc_proto_state_t *oidc_proto_state_new();
void oidc_proto_state_destroy(oidc_proto_state_t *proto_state);
oidc_proto_state_t *oidc_proto_state_from_cookie(request_rec *r, oidc_cfg *c, const char *cookieValue);
char *oidc_proto_state_to_cookie(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state);
char *oidc_proto_state_to_string(request_rec *r, oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_issuer(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_nonce(oidc_proto_state_t *proto_state);
apr_time_t oidc_proto_state_get_timestamp(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_state(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_original_url(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_prompt(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_response_type(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_response_mode(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_original_url(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_original_method(oidc_proto_state_t *proto_state);
const char *oidc_proto_state_get_pkce_state(oidc_proto_state_t *proto_state);
void oidc_proto_state_set_state(oidc_proto_state_t *proto_state, const char *state);
void oidc_proto_state_set_issuer(oidc_proto_state_t *proto_state, const char *issuer);
void oidc_proto_state_set_original_url(oidc_proto_state_t *proto_state, const char *original_url);
void oidc_proto_state_set_original_method(oidc_proto_state_t *proto_state, const char *original_method);
void oidc_proto_state_set_response_mode(oidc_proto_state_t *proto_state, const char *response_mode);
void oidc_proto_state_set_response_type(oidc_proto_state_t *proto_state, const char *response_type);
void oidc_proto_state_set_nonce(oidc_proto_state_t *proto_state, const char *nonce);
void oidc_proto_state_set_prompt(oidc_proto_state_t *proto_state, const char *prompt);
void oidc_proto_state_set_pkce_state(oidc_proto_state_t *proto_state, const char *pkce_state);
void oidc_proto_state_set_timestamp_now(oidc_proto_state_t *proto_state);

apr_byte_t oidc_proto_token_endpoint_auth(request_rec *r, oidc_cfg *cfg, const char *token_endpoint_auth,
					  const char *client_id, const char *client_secret,
					  const apr_array_header_t *client_keys, const char *audience,
					  apr_table_t *params, const char *bearer_access_token, char **basic_auth_str,
					  char **bearer_auth_str);

char *oidc_proto_peek_jwt_header(request_rec *r, const char *jwt, char **alg, char **enc, char **kid);
int oidc_proto_authorization_request(request_rec *r, struct oidc_provider_t *provider, const char *login_hint,
				     const char *redirect_uri, const char *state, oidc_proto_state_t *proto_state,
				     const char *id_token_hint, const char *code_challenge,
				     const char *auth_request_params, const char *path_scope);
apr_byte_t oidc_proto_is_post_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_is_redirect_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_refresh_request(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *rtoken,
				      char **id_token, char **access_token, char **token_type, int *expires_in,
				      char **refresh_token);
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider,
				       const char *id_token_sub, const char *access_token, char **response,
				       char **userinfo_jwt, long *response_code);
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg, const char *acct, char **issuer);
apr_byte_t oidc_proto_url_based_discovery(request_rec *r, oidc_cfg *cfg, const char *url, char **issuer);
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *id_token,
				    const char *nonce, oidc_jwt_t **jwt, apr_byte_t is_code_flow);
int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c);
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool);
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow);
apr_byte_t oidc_proto_validate_authorization_response(request_rec *r, const char *response_type,
						      const char *requested_response_mode, char **code, char **id_token,
						      char **access_token, char **token_type,
						      const char *used_response_mode);
apr_byte_t oidc_proto_jwt_verify(request_rec *r, oidc_cfg *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri,
				 int ssl_validate_server, apr_hash_t *symmetric_keys, const char *alg);
apr_byte_t oidc_proto_validate_jwt(request_rec *r, oidc_jwt_t *jwt, const char *iss, apr_byte_t exp_is_mandatory,
				   apr_byte_t iat_is_mandatory, int iat_slack);
apr_byte_t oidc_proto_generate_nonce(request_rec *r, char **nonce, int len);
apr_byte_t oidc_proto_validate_aud_and_azp(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider,
					   oidc_jwt_payload_t *id_token_payload);

apr_byte_t oidc_proto_authorization_response_code_idtoken_token(request_rec *r, oidc_cfg *c,
								oidc_proto_state_t *proto_state,
								oidc_provider_t *provider, apr_table_t *params,
								const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_authorization_response_code_idtoken(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state,
							  oidc_provider_t *provider, apr_table_t *params,
							  const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_code_token(request_rec *r, oidc_cfg *c,
							       oidc_proto_state_t *proto_state,
							       oidc_provider_t *provider, apr_table_t *params,
							       const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_code(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state,
							 oidc_provider_t *provider, apr_table_t *params,
							 const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_idtoken_token(request_rec *r, oidc_cfg *c,
								  oidc_proto_state_t *proto_state,
								  oidc_provider_t *provider, apr_table_t *params,
								  const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_idtoken(request_rec *r, oidc_cfg *c,
							    oidc_proto_state_t *proto_state, oidc_provider_t *provider,
							    apr_table_t *params, const char *response_mode,
							    oidc_jwt_t **jwt);
apr_byte_t oidc_proto_generate_random_string(request_rec *r, char **output, int len);

// non-static for test.c
apr_byte_t oidc_proto_validate_access_token(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
					    const char *response_type, const char *access_token);
apr_byte_t oidc_proto_validate_code(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt,
				    const char *response_type, const char *code);
apr_byte_t oidc_proto_validate_nonce(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *nonce,
				     oidc_jwt_t *jwt);
apr_byte_t oidc_validate_redirect_url(request_rec *r, oidc_cfg *c, const char *redirect_to_url,
				      apr_byte_t restrict_to_host, char **err_str, char **err_desc);

int oidc_oauth_return_www_authenticate(request_rec *r, const char *error, const char *error_description);

// oidc_config.c

#define OIDCPrivateKeyFiles "OIDCPrivateKeyFiles"
#define OIDCRedirectURI "OIDCRedirectURI"
#define OIDCDefaultURL "OIDCDefaultURL"
#define OIDCCookieDomain "OIDCCookieDomain"
#define OIDCClaimPrefix "OIDCClaimPrefix"
#define OIDCRemoteUserClaim "OIDCRemoteUserClaim"
#define OIDCOAuthRemoteUserClaim "OIDCOAuthRemoteUserClaim"
#define OIDCSessionType "OIDCSessionType"
#define OIDCMemCacheServers "OIDCMemCacheServers"
#define OIDCMemCacheConnectionsMin "OIDCMemCacheConnectionsMin"
#define OIDCMemCacheConnectionsSMax "OIDCMemCacheConnectionsSMax"
#define OIDCMemCacheConnectionsHMax "OIDCMemCacheConnectionsHMax"
#define OIDCMemCacheConnectionsTTL "OIDCMemCacheConnectionsTTL"
#define OIDCCacheShmMax "OIDCCacheShmMax"
#define OIDCCacheShmEntrySizeMax "OIDCCacheShmEntrySizeMax"
#define OIDCRedisCacheServer "OIDCRedisCacheServer"
#define OIDCCookiePath "OIDCCookiePath"
#define OIDCInfoHook "OIDCInfoHook"
#define OIDCMetricsData "OIDCMetricsData"
#define OIDCMetricsPublish "OIDCMetricsPublish"
#define OIDCWhiteListedClaims "OIDCWhiteListedClaims"
#define OIDCCryptoPassphrase "OIDCCryptoPassphrase"

void *oidc_create_server_config(apr_pool_t *pool, server_rec *svr);
void *oidc_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD);
void *oidc_create_dir_config(apr_pool_t *pool, char *path);
void *oidc_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
void oidc_register_hooks(apr_pool_t *pool);
char *oidc_cfg_dir_discover_url(request_rec *r);
char *oidc_cfg_dir_cookie(request_rec *r);
char *oidc_cfg_dir_cookie_path(request_rec *r);
char *oidc_cfg_dir_authn_header(request_rec *r);
apr_byte_t oidc_cfg_dir_pass_info_in_headers(request_rec *r);
apr_byte_t oidc_cfg_dir_pass_info_in_envvars(request_rec *r);
int oidc_cfg_dir_pass_info_encoding(request_rec *r);
apr_byte_t oidc_cfg_dir_pass_refresh_token(request_rec *r);
apr_byte_t oidc_cfg_dir_pass_access_token(request_rec *r);
apr_byte_t oidc_cfg_dir_accept_token_in(request_rec *r);
char *oidc_cfg_dir_accept_token_in_option(request_rec *r, const char *key);
int oidc_cfg_token_introspection_interval(request_rec *r);
int oidc_cfg_dir_preserve_post(request_rec *r);
apr_array_header_t *oidc_dir_cfg_pass_cookies(request_rec *r);
apr_array_header_t *oidc_dir_cfg_strip_cookies(request_rec *r);
int oidc_dir_cfg_unauth_action(request_rec *r);
apr_byte_t oidc_dir_cfg_unauth_expr_is_set(request_rec *r);
int oidc_dir_cfg_unautz_action(request_rec *r);
char *oidc_dir_cfg_unauthz_arg(request_rec *r);
const char *oidc_dir_cfg_path_auth_request_params(request_rec *r);
apr_array_header_t *oidc_dir_cfg_pass_user_info_as(request_rec *r);
int oidc_dir_cfg_pass_id_token_as(request_rec *r);
const char *oidc_dir_cfg_userinfo_claims_expr(request_rec *r);
const char *oidc_dir_cfg_path_scope(request_rec *r);
oidc_valid_function_t oidc_cfg_get_valid_endpoint_auth_function(oidc_cfg *cfg);
int oidc_cfg_cache_encrypt(request_rec *r);
int oidc_cfg_session_cache_fallback_to_cookie(request_rec *r);
const char *oidc_parse_pkce_type(apr_pool_t *pool, const char *arg, oidc_proto_pkce_t **type);
const char *oidc_cfg_claim_prefix(request_rec *r);
int oidc_cfg_max_number_of_state_cookies(oidc_cfg *cfg);
int oidc_cfg_dir_refresh_access_token_before_expiry(request_rec *r);
int oidc_cfg_dir_action_on_error_refresh(request_rec *r);
char *oidc_cfg_dir_state_cookie_prefix(request_rec *r);
int oidc_cfg_delete_oldest_state_cookies(oidc_cfg *cfg);
oidc_provider_t *oidc_cfg_provider_create(apr_pool_t *pool);
oidc_provider_t *oidc_cfg_provider_copy(apr_pool_t *pool, const oidc_provider_t *src);
void oidc_config_check_x_forwarded(request_rec *r, const apr_byte_t x_forwarded_headers);

// oidc_util.c
apr_byte_t oidc_util_random_bytes(unsigned char *buf, apr_size_t length);
apr_byte_t oidc_util_generate_random_bytes(request_rec *r, unsigned char *buf, apr_size_t length);
apr_byte_t oidc_proto_generate_random_hex_string(request_rec *r, char **hex_str, int byte_len);
int oidc_strnenvcmp(const char *a, const char *b, int len);
int oidc_base64url_encode(request_rec *r, char **dst, const char *src, int src_len, int remove_padding);
int oidc_base64url_decode(apr_pool_t *pool, char **dst, const char *src);
const char *oidc_get_current_url_host(request_rec *r, const apr_byte_t x_forwarded_headers);
apr_byte_t oidc_util_request_matches_url(request_rec *r, const char *url);
char *oidc_get_current_url(request_rec *r, const apr_byte_t x_forwarded_headers);
const char *oidc_get_absolute_url(request_rec *r, oidc_cfg *cfg, const char *url);
const char *oidc_get_redirect_uri(request_rec *r, oidc_cfg *c);
const char *oidc_get_redirect_uri_iss(request_rec *r, oidc_cfg *c, oidc_provider_t *provider);
apr_byte_t oidc_util_request_is_secure(request_rec *r, const oidc_cfg *c);
char *oidc_util_openssl_version(apr_pool_t *pool);
apr_byte_t oidc_util_request_matches_url(request_rec *r, const char *url);
char *oidc_util_encode_json_object(request_rec *r, json_t *json, size_t flags);
apr_byte_t oidc_util_decode_json_object(request_rec *r, const char *str, json_t **json);
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
			    apr_byte_t as_header, apr_byte_t as_env_var, int pass_as);
void oidc_util_set_app_infos(request_rec *r, json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter,
			     apr_byte_t as_header, apr_byte_t as_env_var, int pass_as);
apr_hash_t *oidc_util_spaced_string_to_hashtable(apr_pool_t *pool, const char *str);
apr_byte_t oidc_util_spaced_string_equals(apr_pool_t *pool, const char *a, const char *b);
apr_byte_t oidc_util_spaced_string_contains(apr_pool_t *pool, const char *str, const char *match);
apr_byte_t oidc_json_object_get_string(apr_pool_t *pool, json_t *json, const char *name, char **value,
				       const char *default_value);
apr_byte_t oidc_json_object_get_int(const json_t *json, const char *name, int *value, const int default_value);
apr_byte_t oidc_json_object_get_bool(const json_t *json, const char *name, int *value, const int default_value);
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
int oidc_util_cookie_domain_valid(const char *hostname, char *cookie_domain);
apr_byte_t oidc_util_hash_string_and_base64url_encode(request_rec *r, const char *openssl_hash_algo, const char *input,
						      char **output);
apr_byte_t oidc_util_jwt_create(request_rec *r, const oidc_crypto_passphrase_t *passphrase, const char *s_payload,
				char **compact_encoded_jwt);
apr_byte_t oidc_util_jwt_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
				const char *compact_encoded_jwt, char **s_payload);
apr_byte_t oidc_util_create_symmetric_key(request_rec *r, const char *client_secret, unsigned int r_key_len,
					  const char *hash_algo, apr_byte_t set_kid, oidc_jwk_t **jwk);
apr_hash_t *oidc_util_merge_symmetric_key(apr_pool_t *pool, const apr_array_header_t *keys, oidc_jwk_t *jwk);
char *oidc_util_get_full_path(apr_pool_t *pool, const char *abs_or_rel_filename);
apr_byte_t oidc_enabled(request_rec *r);
const char *oidc_util_strcasestr(const char *s1, const char *s2);
oidc_jwk_t *oidc_util_key_list_first(const apr_array_header_t *key_list, int kty, const char *use);
const char *oidc_util_jq_filter(request_rec *r, const char *input, const char *filter);
char *oidc_util_apr_expr_parse(cmd_parms *cmd, const char *str, oidc_apr_expr_t **expr, apr_byte_t result_is_str);
const char *oidc_util_apr_expr_exec(request_rec *r, const oidc_apr_expr_t *expr, apr_byte_t result_is_str);
void oidc_util_set_trace_parent(request_rec *r, oidc_cfg *c, const char *span);
void oidc_util_apr_hash_clear(apr_hash_t *ht);

apr_byte_t oidc_util_html_send_in_template(request_rec *r, const char *filename, char **static_template_content,
					   const char *arg1, int arg1_esc, const char *arg2, int arg2_esc,
					   int status_code);

// oidc_metadata.c
apr_byte_t oidc_metadata_provider_get(request_rec *r, oidc_cfg *cfg, const char *issuer, json_t **j_provider,
				      apr_byte_t allow_discovery);
apr_byte_t oidc_metadata_provider_retrieve(request_rec *r, oidc_cfg *cfg, const char *issuer, const char *url,
					   json_t **j_metadata, char **response);
apr_byte_t oidc_metadata_provider_parse(request_rec *r, oidc_cfg *cfg, json_t *j_provider, oidc_provider_t *provider);
apr_byte_t oidc_metadata_provider_is_valid(request_rec *r, oidc_cfg *cfg, json_t *j_provider, const char *issuer);
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg *cfg, apr_array_header_t **arr);
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg *cfg, const char *selected, oidc_provider_t **provider,
			     apr_byte_t allow_discovery);
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg *cfg, const oidc_jwks_uri_t *jwks_uri,
				  int ssl_validate_server, json_t **j_jwks, apr_byte_t *refresh);
apr_byte_t oidc_oauth_metadata_provider_parse(request_rec *r, oidc_cfg *c, json_t *j_provider);

// oidc_session.c
apr_byte_t oidc_session_load(request_rec *r, oidc_session_t **z);
apr_byte_t oidc_session_get(request_rec *r, oidc_session_t *z, const char *key, char **value);
apr_byte_t oidc_session_set(request_rec *r, oidc_session_t *z, const char *key, const char *value);
apr_byte_t oidc_session_save(request_rec *r, oidc_session_t *z, apr_byte_t first_time);
apr_byte_t oidc_session_kill(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_free(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_extract(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_load_cache_by_uuid(request_rec *r, oidc_cfg *c, const char *uuid, oidc_session_t *z);
void oidc_session_id_new(request_rec *r, oidc_session_t *z);

void oidc_session_set_userinfo_jwt(request_rec *r, oidc_session_t *z, const char *userinfo_jwt);
const char *oidc_session_get_userinfo_jwt(request_rec *r, oidc_session_t *z);
void oidc_session_set_userinfo_claims(request_rec *r, oidc_session_t *z, const char *claims);
const char *oidc_session_get_userinfo_claims(request_rec *r, oidc_session_t *z);
json_t *oidc_session_get_userinfo_claims_json(request_rec *r, oidc_session_t *z);
void oidc_session_set_idtoken_claims(request_rec *r, oidc_session_t *z, const char *idtoken_claims);
const char *oidc_session_get_idtoken_claims(request_rec *r, oidc_session_t *z);
json_t *oidc_session_get_idtoken_claims_json(request_rec *r, oidc_session_t *z);
void oidc_session_set_idtoken(request_rec *r, oidc_session_t *z, const char *s_id_token);
const char *oidc_session_get_idtoken(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token(request_rec *r, oidc_session_t *z, const char *access_token);
const char *oidc_session_get_access_token(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token_expires(request_rec *r, oidc_session_t *z, const int expires_in);
apr_time_t oidc_session_get_access_token_expires(request_rec *r, oidc_session_t *z);
const char *oidc_session_get_access_token_expires2str(request_rec *r, oidc_session_t *z);
void oidc_session_set_refresh_token(request_rec *r, oidc_session_t *z, const char *refresh_token);
const char *oidc_session_get_refresh_token(request_rec *r, oidc_session_t *z);
void oidc_session_set_session_expires(request_rec *r, oidc_session_t *z, const apr_time_t expires);
apr_time_t oidc_session_get_session_expires(request_rec *r, oidc_session_t *z);
void oidc_session_set_cookie_domain(request_rec *r, oidc_session_t *z, const char *cookie_domain);
const char *oidc_session_get_cookie_domain(request_rec *r, oidc_session_t *z);
void oidc_session_reset_userinfo_last_refresh(request_rec *r, oidc_session_t *z);
void oidc_session_set_userinfo_refresh_interval(request_rec *r, oidc_session_t *z, const int interval);
apr_time_t oidc_session_get_userinfo_refresh_interval(request_rec *r, oidc_session_t *z);
apr_time_t oidc_session_get_userinfo_last_refresh(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token_last_refresh(request_rec *r, oidc_session_t *z, apr_time_t ts);
apr_time_t oidc_session_get_access_token_last_refresh(request_rec *r, oidc_session_t *z);
void oidc_session_set_request_state(request_rec *r, oidc_session_t *z, const char *request_state);
const char *oidc_session_get_request_state(request_rec *r, oidc_session_t *z);
void oidc_session_set_original_url(request_rec *r, oidc_session_t *z, const char *original_url);
const char *oidc_session_get_original_url(request_rec *r, oidc_session_t *z);
void oidc_session_set_session_state(request_rec *r, oidc_session_t *z, const char *session_state);
const char *oidc_session_get_session_state(request_rec *r, oidc_session_t *z);
void oidc_session_set_issuer(request_rec *r, oidc_session_t *z, const char *issuer);
const char *oidc_session_get_issuer(request_rec *r, oidc_session_t *z);
void oidc_session_set_client_id(request_rec *r, oidc_session_t *z, const char *client_id);

#endif /* MOD_AUTH_OPENIDC_H_ */
