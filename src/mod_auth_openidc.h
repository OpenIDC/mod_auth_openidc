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

#ifndef MOD_AUTH_OPENIDC_H_
#define MOD_AUTH_OPENIDC_H_

#include <stdint.h>
#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <mod_auth.h>

#include "jose.h"
#include "cache/cache.h"
#include "parse.h"
#include <apr_uuid.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_openidc);
#endif

#ifndef OIDC_DEBUG
#define OIDC_DEBUG APLOG_DEBUG
#endif

#define oidc_log(r, level, fmt, ...) ap_log_rerror(APLOG_MARK, level, 0, r,"%s: %s", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
#define oidc_slog(s, level, fmt, ...) ap_log_error(APLOG_MARK, level, 0, s, "%s: %s", __FUNCTION__, apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))
//#define oidc_log(r, level, fmt, ...) fprintf(stderr, "# %s: %s\n", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
//#define oidc_slog(s, level, fmt, ...) fprintf(stderr, "## %s: %s\n", __FUNCTION__, apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))

#define oidc_debug(r, fmt, ...) oidc_log(r, OIDC_DEBUG, fmt, ##__VA_ARGS__)
#define oidc_warn(r, fmt, ...) oidc_log(r, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define oidc_error(r, fmt, ...) oidc_log(r, APLOG_ERR, fmt, ##__VA_ARGS__)

#define oidc_sdebug(s, fmt, ...) oidc_slog(s, OIDC_DEBUG, fmt, ##__VA_ARGS__)
#define oidc_swarn(s, fmt, ...) oidc_slog(s, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define oidc_serror(s, fmt, ...) oidc_slog(s, APLOG_ERR, fmt, ##__VA_ARGS__)

#ifndef NAMEVER
#define NAMEVERSION "mod_auth_openidc-0.0.0"
#else
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define NAMEVERSION TOSTRING(NAMEVER)
#endif

/* keys for storing info in the request state */
#define OIDC_REQUEST_STATE_KEY_IDTOKEN "i"
#define OIDC_REQUEST_STATE_KEY_CLAIMS  "c"

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
#define OIDC_PASS_IDTOKEN_AS_CLAIMS     1
/* pass id_token payload as JSON object in header */
#define OIDC_PASS_IDTOKEN_AS_PAYLOAD    2
/* pass id_token in compact serialized format in header */
#define OIDC_PASS_IDTOKEN_AS_SERIALIZED 4

/* pass userinfo as individual claims in headers (default) */
#define OIDC_PASS_USERINFO_AS_CLAIMS      1
/* pass userinfo payload as JSON object in header */
#define OIDC_PASS_USERINFO_AS_JSON_OBJECT 2
/* pass userinfo as a JWT in header (when returned as a JWT) */
#define OIDC_PASS_USERINFO_AS_JWT         4

/* logout on refresh error before expiry */
#define OIDC_LOGOUT_ON_ERROR_REFRESH 1

#define OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT 0
/* accept bearer token in header (default) */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER  1
/* accept bearer token as a post parameter */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_POST    2
/* accept bearer token as a query parameter */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY   4
/* accept bearer token as a cookie parameter (PingAccess) */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE  8
/* accept bearer token as basic auth password (non-oauth clients) */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_BASIC   16

/* the hash key of the cookie name value in the list of options */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME "cookie-name"

/* introspection method options */
#define OIDC_INTROSPECTION_METHOD_GET  "GET"
#define OIDC_INTROSPECTION_METHOD_POST "POST"

/* HTTP methods to send authentication requests */
#define OIDC_AUTH_REQUEST_METHOD_GET  0
#define OIDC_AUTH_REQUEST_METHOD_POST 1

/* prefix of the cookie that binds the state in the authorization request/response to the browser */
#define OIDC_STATE_COOKIE_PREFIX  "mod_auth_openidc_state_"

/* default prefix for information passed in HTTP headers */
#define OIDC_DEFAULT_HEADER_PREFIX "OIDC_"

/* the (global) key for the mod_auth_openidc related state that is stored in the request userdata context */
#define OIDC_USERDATA_KEY "mod_auth_openidc_state"
#define OIDC_USERDATA_POST_PARAMS_KEY "oidc_userdata_post_params"

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
#define OIDC_METHOD_GET       "get"
#define OIDC_METHOD_FORM_POST "form_post"

/* the maximum size of data that we accept in a single POST value: 1MB */
#define OIDC_MAX_POST_DATA_LEN 1024 * 1024

#define OIDC_UNAUTH_AUTHENTICATE 1
#define OIDC_UNAUTH_PASS         2
#define OIDC_UNAUTH_RETURN401    3
#define OIDC_UNAUTH_RETURN410    4
#define OIDC_UNAUTH_RETURN407    5

#define OIDC_UNAUTZ_RETURN403    1
#define OIDC_UNAUTZ_RETURN401    2
#define OIDC_UNAUTZ_AUTHENTICATE 3

#define OIDC_REQUEST_URI_CACHE_DURATION 30

#define OIDC_USER_INFO_TOKEN_METHOD_HEADER 0
#define OIDC_USER_INFO_TOKEN_METHOD_POST   1

#define OIDC_COOKIE_EXT_SAME_SITE_LAX    "SameSite=Lax"
#define OIDC_COOKIE_EXT_SAME_SITE_STRICT "SameSite=Strict"
#define OIDC_COOKIE_EXT_SAME_SITE_NONE   "SameSite=None"

/* https://tools.ietf.org/html/draft-ietf-tokbind-ttrp-01 */
#define OIDC_TB_CFG_PROVIDED_ENV_VAR     "Sec-Provided-Token-Binding-ID"
/* https://www.ietf.org/id/draft-ietf-oauth-mtls-12 */
#define OIDC_TB_CFG_FINGERPRINT_ENV_VAR  "TB_SSL_CLIENT_CERT_FINGERPRINT"

#define OIDC_TOKEN_BINDING_POLICY_DISABLED  0
#define OIDC_TOKEN_BINDING_POLICY_OPTIONAL  1
#define OIDC_TOKEN_BINDING_POLICY_REQUIRED  2
#define OIDC_TOKEN_BINDING_POLICY_ENFORCED  3

#define OIDC_STATE_INPUT_HEADERS_USER_AGENT 1
#define OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR 2

typedef apr_byte_t (*oidc_proto_pkce_state)(request_rec *r, char **state);
typedef apr_byte_t (*oidc_proto_pkce_challenge)(request_rec *r, const char *state, char **code_challenge);
typedef apr_byte_t (*oidc_proto_pkce_verifier)(request_rec *r, const char *state, char **code_verifier);

typedef struct oidc_proto_pkce_t {
	const char *method;
	oidc_proto_pkce_state     state;
	oidc_proto_pkce_verifier  verifier;
	oidc_proto_pkce_challenge challenge;
} oidc_proto_pkce_t;

extern oidc_proto_pkce_t oidc_pkce_plain;
extern oidc_proto_pkce_t oidc_pkce_s256;
extern oidc_proto_pkce_t oidc_pkce_referred_tb;

typedef struct oidc_jwks_uri_t {
	const char *url;
	int refresh_interval;
	int ssl_validate_server;
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
	char *jwks_uri;
	char *client_id;
	char *client_secret;
	char *token_endpoint_tls_client_key;
	char *token_endpoint_tls_client_cert;
	int backchannel_logout_supported;

	// the next ones function as global default settings too
	int ssl_validate_server;
	char *client_name;
	char *client_contact;
	char *registration_token;
	char *registration_endpoint_json;
	char *scope;
	char *response_type;
	char *response_mode;
	int jwks_refresh_interval;
	int idtoken_iat_slack;
	char *auth_request_params;
	int session_max_duration;
	oidc_proto_pkce_t *pkce;
	int userinfo_refresh_interval;

	apr_hash_t *client_signing_keys;
	apr_hash_t *client_encryption_keys;

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
	int token_binding_policy;

	int issuer_specific_redirect_uri;
} oidc_provider_t ;

typedef struct oidc_remote_user_claim_t {
	const char *claim_name;
	const char *reg_exp;
	const char *replace;
} oidc_remote_user_claim_t;

typedef struct oidc_oauth_t {
	int ssl_validate_server;
	char *client_id;
	char *client_secret;
	char *metadata_url;
	char *introspection_endpoint_tls_client_key;
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
	apr_hash_t *verify_public_keys;
	int access_token_binding_policy;
} oidc_oauth_t;

typedef struct oidc_cfg {
	/* indicates whether this is a derived config, merged from a base one */
	unsigned int merged;

	/* HTML to display error messages+description */
	char *error_template;

	/* the redirect URI as configured with the OpenID Connect OP's that we talk to */
	char *redirect_uri;
	/* (optional) default URL for 3rd-party initiated SSO */
	char *default_sso_url;
	/* (optional) default URL to go to after logout */
	char *default_slo_url;

	/* public keys in JWK format, used by parters for encrypting JWTs sent to us */
	apr_hash_t *public_keys;
	/* private keys in JWK format used for decrypting encrypted JWTs sent to us */
	apr_hash_t *private_keys;

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
	/* session cookie chunk size */
	int session_cookie_chunk_size;

	/* pointer to cache functions */
	oidc_cache_t *cache;
	void *cache_cfg;
	/* cache_type = file: directory that holds the cache files (if not set, we'll try and use an OS defined one like "/tmp" */
	char *cache_file_dir;
	/* cache_type = file: clean interval */
	int cache_file_clean_interval;
#ifdef USE_MEMCACHE
	/* cache_type= memcache: list of memcache host/port servers to use */
	char *cache_memcache_servers;
#endif
	/* cache_type = shm: size of the shared memory segment (cq. max number of cached entries) */
	int cache_shm_size_max;
	/* cache_type = shm: maximum size in bytes of a cache entry */
	int cache_shm_entry_size_max;
#ifdef USE_LIBHIREDIS
	/* cache_type= redis: Redis host/port server to use */
	char *cache_redis_server;
	char *cache_redis_password;
#endif
	int cache_encrypt;

	int http_timeout_long;
	int http_timeout_short;
	int state_timeout;
	int max_number_of_state_cookies;
	int delete_oldest_state_cookies;
	int session_inactivity_timeout;
	int session_cache_fallback_to_cookie;

	char *cookie_domain;
	char *claim_delimiter;
	char *claim_prefix;
	oidc_remote_user_claim_t remote_user_claim;
	int pass_idtoken_as;
	int pass_userinfo_as;
	int cookie_http_only;
	int cookie_same_site;

	char *outgoing_proxy;

	char *crypto_passphrase;

	int provider_metadata_refresh_interval;

	apr_hash_t *info_hook_data;
	apr_hash_t *black_listed_claims;
	apr_hash_t *white_listed_claims;

	apr_byte_t state_input_headers;

} oidc_cfg;

int oidc_check_user_id(request_rec *r);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status oidc_authz_checker_claim(request_rec *r, const char *require_args, const void *parsed_require_args);
#ifdef USE_LIBJQ
authz_status oidc_authz_checker_claims_expr(request_rec *r, const char *require_args, const void *parsed_require_args);
#endif
#else
int oidc_auth_checker(request_rec *r);
#endif
void oidc_request_state_set(request_rec *r, const char *key, const char *value);
const char*oidc_request_state_get(request_rec *r, const char *key);
int oidc_handle_jwks(request_rec *r, oidc_cfg *c);
int oidc_handle_remove_at_cache(request_rec *r, oidc_cfg *c);
apr_byte_t oidc_post_preserve_javascript(request_rec *r, const char *location, char **javascript, char **javascript_method);
void oidc_scrub_headers(request_rec *r);
void oidc_strip_cookies(request_rec *r);
int oidc_content_handler(request_rec *r);
apr_byte_t oidc_get_remote_user(request_rec *r, const char *claim_name, const char *replace, const char *reg_exp,
                                json_t *json, char **request_user);

#define OIDC_REDIRECT_URI_REQUEST_INFO             "info"
#define OIDC_REDIRECT_URI_REQUEST_LOGOUT           "logout"
#define OIDC_REDIRECT_URI_REQUEST_JWKS             "jwks"
#define OIDC_REDIRECT_URI_REQUEST_SESSION          "session"
#define OIDC_REDIRECT_URI_REQUEST_REFRESH          "refresh"
#define OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE  "remove_at_cache"
#define OIDC_REDIRECT_URI_REQUEST_REQUEST_URI      "request_uri"

// oidc_oauth
int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c, const char *access_token);
apr_byte_t oidc_oauth_get_bearer_token(request_rec *r, const char **access_token);

// oidc_proto.c
#define OIDC_PROTO_ISS                   "iss"
#define OIDC_PROTO_CODE                  "code"
#define OIDC_PROTO_CLIENT_ID             "client_id"
#define OIDC_PROTO_CLIENT_SECRET         "client_secret"
#define OIDC_PROTO_CLIENT_ASSERTION      "client_assertion"
#define OIDC_PROTO_CLIENT_ASSERTION_TYPE "client_assertion_type"
#define OIDC_PROTO_ACCESS_TOKEN          "access_token"
#define OIDC_PROTO_ID_TOKEN              "id_token"
#define OIDC_PROTO_STATE                 "state"
#define OIDC_PROTO_GRANT_TYPE            "grant_type"
#define OIDC_PROTO_REDIRECT_URI          "redirect_uri"
#define OIDC_PROTO_CODE_VERIFIER         "code_verifier"
#define OIDC_PROTO_CODE_CHALLENGE        "code_challenge"
#define OIDC_PROTO_CODE_CHALLENGE_METHOD "code_challenge_method"
#define OIDC_PROTO_SCOPE                 "scope"
#define OIDC_PROTO_REFRESH_TOKEN         "refresh_token"
#define OIDC_PROTO_TOKEN_TYPE            "token_type"
#define OIDC_PROTO_EXPIRES_IN            "expires_in"
#define OIDC_PROTO_RESPONSE_TYPE         "response_type"
#define OIDC_PROTO_RESPONSE_MODE         "response_mode"
#define OIDC_PROTO_NONCE                 "nonce"
#define OIDC_PROTO_PROMPT                "prompt"
#define OIDC_PROTO_LOGIN_HINT            "login_hint"
#define OIDC_PROTO_ID_TOKEN_HINT         "id_token_hint"
#define OIDC_PROTO_REQUEST_URI           "request_uri"
#define OIDC_PROTO_REQUEST_OBJECT        "request"
#define OIDC_PROTO_SESSION_STATE         "session_state"
#define OIDC_PROTO_ACTIVE                "active"
#define OIDC_PROTO_LOGOUT_TOKEN          "logout_token"

#define OIDC_PROTO_RESPONSE_TYPE_CODE               "code"
#define OIDC_PROTO_RESPONSE_TYPE_IDTOKEN            "id_token"
#define OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN      "id_token token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN       "code id_token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN         "code token"
#define OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN "code id_token token"
#define OIDC_PROTO_RESPONSE_TYPE_TOKEN              "token"

#define OIDC_PROTO_RESPONSE_MODE_QUERY     "query"
#define OIDC_PROTO_RESPONSE_MODE_FRAGMENT  "fragment"
#define OIDC_PROTO_RESPONSE_MODE_FORM_POST "form_post"

#define OIDC_PROTO_SCOPE_OPENID           "openid"
#define OIDC_PROTO_PROMPT_NONE            "none"
#define OIDC_PROTO_ERROR                  "error"
#define OIDC_PROTO_ERROR_DESCRIPTION      "error_description"
#define OIDC_PROTO_REALM                  "realm"

#define OIDC_PROTO_ERR_INVALID_TOKEN          "invalid_token"
#define OIDC_PROTO_ERR_INVALID_REQUEST        "invalid_request"

#define OIDC_PROTO_GRANT_TYPE_AUTHZ_CODE    "authorization_code"
#define OIDC_PROTO_GRANT_TYPE_REFRESH_TOKEN "refresh_token"

#define OIDC_PROTO_CLIENT_ASSERTION_TYPE_JWT_BEARER "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#define OIDC_PROTO_CLIENT_SECRET_BASIC "client_secret_basic"
#define OIDC_PROTO_CLIENT_SECRET_POST  "client_secret_post"
#define OIDC_PROTO_CLIENT_SECRET_JWT   "client_secret_jwt"
#define OIDC_PROTO_PRIVATE_KEY_JWT     "private_key_jwt"
#define OIDC_PROTO_BEARER_ACCESS_TOKEN "bearer_access_token"
#define OIDC_PROTO_ENDPOINT_AUTH_NONE  "none"

#define OIDC_PROTO_BEARER  "Bearer"
#define OIDC_PROTO_BASIC   "Basic"

#define OIDC_CLAIM_ISS             "iss"
#define OIDC_CLAIM_AUD             "aud"
#define OIDC_CLAIM_AZP             "azp"
#define OIDC_CLAIM_SUB             "sub"
#define OIDC_CLAIM_JTI             "jti"
#define OIDC_CLAIM_EXP             "exp"
#define OIDC_CLAIM_IAT             "iat"
#define OIDC_CLAIM_NONCE           "nonce"
#define OIDC_CLAIM_AT_HASH         "at_hash"
#define OIDC_CLAIM_C_HASH          "c_hash"
#define OIDC_CLAIM_RFP             "rfp"
#define OIDC_CLAIM_TARGET_LINK_URI "target_link_uri"
#define OIDC_CLAIM_CNF             "cnf"
#define OIDC_CLAIM_CNF_TBH         "tbh"
#define OIDC_CLAIM_CNF_X5T_S256    "x5t#S256"
#define OIDC_CLAIM_SID             "sid"
#define OIDC_CLAIM_EVENTS          "events"

#define OIDC_JWK_X5T       "x5t"
#define OIDC_JWK_KEYS      "keys"
#define OIDC_JWK_USE       "use"
#define OIDC_JWK_SIG       "sig"
#define OIDC_JWK_ENC       "enc"

#define OIDC_HOOK_INFO_FORMAT_JSON         "json"
#define OIDC_HOOK_INFO_FORMAT_HTML         "html"
#define OIDC_HOOK_INFO_TIMESTAMP           "iat"
#define OIDC_HOOK_INFO_ACCES_TOKEN         "access_token"
#define OIDC_HOOK_INFO_ACCES_TOKEN_EXP     "access_token_expires"
#define OIDC_HOOK_INFO_ID_TOKEN            "id_token"
#define OIDC_HOOK_INFO_USER_INFO           "userinfo"
#define OIDC_HOOK_INFO_SESSION             "session"
#define OIDC_HOOK_INFO_SESSION_STATE       "state"
#define OIDC_HOOK_INFO_SESSION_UUID        "uuid"
#define OIDC_HOOK_INFO_SESSION_EXP         "exp"
#define OIDC_HOOK_INFO_SESSION_TIMEOUT     "timeout"
#define OIDC_HOOK_INFO_SESSION_REMOTE_USER "remote_user"
#define OIDC_HOOK_INFO_REFRESH_TOKEN       "refresh_token"

#define OIDC_CONTENT_TYPE_JSON          "application/json"
#define OIDC_CONTENT_TYPE_JWT           "application/jwt"
#define OIDC_CONTENT_TYPE_FORM_ENCODED  "application/x-www-form-urlencoded"
#define OIDC_CONTENT_TYPE_IMAGE_PNG     "image/png"
#define OIDC_CONTENT_TYPE_TEXT_HTML     "text/html"
#define OIDC_CONTENT_TYPE_APP_XHTML_XML "application/xhtml+xml"
#define OIDC_CONTENT_TYPE_ANY           "*/*"

#define OIDC_STR_SPACE         " "
#define OIDC_STR_EQUAL         "="
#define OIDC_STR_AMP           "&"
#define OIDC_STR_QUERY         "?"
#define OIDC_STR_COLON         ":"
#define OIDC_STR_SEMI_COLON    ";"
#define OIDC_STR_FORWARD_SLASH "/"
#define OIDC_STR_AT            "@"
#define OIDC_STR_COMMA         ","
#define OIDC_STR_HASH          "#"

#define OIDC_CHAR_EQUAL         '='
#define OIDC_CHAR_COLON         ':'
#define OIDC_CHAR_TILDE         '~'
#define OIDC_CHAR_SPACE         ' '
#define OIDC_CHAR_COMMA         ','
#define OIDC_CHAR_QUERY         '?'
#define OIDC_CHAR_DOT           '.'
#define OIDC_CHAR_AT            '@'
#define OIDC_CHAR_FORWARD_SLASH '/'
#define OIDC_CHAR_PIPE          '|'
#define OIDC_CHAR_AMP           '&'
#define OIDC_CHAR_SEMI_COLON    ';'

#define OIDC_APP_INFO_REFRESH_TOKEN     "refresh_token"
#define OIDC_APP_INFO_ACCESS_TOKEN      "access_token"
#define OIDC_APP_INFO_ACCESS_TOKEN_EXP  "access_token_expires"
#define OIDC_APP_INFO_ID_TOKEN          "id_token"
#define OIDC_APP_INFO_ID_TOKEN_PAYLOAD  "id_token_payload"
#define OIDC_APP_INFO_USERINFO_JSON     "userinfo_json"
#define OIDC_APP_INFO_USERINFO_JWT      "userinfo_jwt"

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

apr_byte_t oidc_proto_token_endpoint_auth(request_rec *r, oidc_cfg *cfg, const char *token_endpoint_auth, const char *client_id, const char *client_secret, apr_hash_t *client_signing_keys, const char *audience, apr_table_t *params, const char *bearer_access_token, char **basic_auth_str, char **bearer_auth_str);

char *oidc_proto_peek_jwt_header(request_rec *r, const char *jwt, char **alg);
int oidc_proto_authorization_request(request_rec *r, struct oidc_provider_t *provider, const char *login_hint, const char *redirect_uri, const char *state, oidc_proto_state_t *proto_state, const char *id_token_hint, const char *code_challenge, const char *auth_request_params, const char *path_scope);
apr_byte_t oidc_proto_is_post_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_is_redirect_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_refresh_request(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *rtoken, char **id_token, char **access_token, char **token_type, int *expires_in, char **refresh_token);
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *id_token_sub, const char *access_token, char **response, char **userinfo_jwt);
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg, const char *acct, char **issuer);
apr_byte_t oidc_proto_url_based_discovery(request_rec *r, oidc_cfg *cfg, const char *url, char **issuer);
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *id_token, const char *nonce, oidc_jwt_t **jwt, apr_byte_t is_code_flow);
int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c);
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool);
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow);
apr_byte_t oidc_proto_validate_authorization_response(request_rec *r, const char *response_type, const char *requested_response_mode, char **code, char **id_token, char **access_token, char **token_type, const char *used_response_mode);
apr_byte_t oidc_proto_jwt_verify(request_rec *r, oidc_cfg *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri, apr_hash_t *symmetric_keys, const char *alg);
apr_byte_t oidc_proto_validate_jwt(request_rec *r, oidc_jwt_t *jwt, const char *iss, apr_byte_t exp_is_mandatory, apr_byte_t iat_is_mandatory, int iat_slack, int token_binding_policy);
apr_byte_t oidc_proto_generate_nonce(request_rec *r, char **nonce, int len);
apr_byte_t oidc_proto_validate_aud_and_azp(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, oidc_jwt_payload_t *id_token_payload);

apr_byte_t oidc_proto_authorization_response_code_idtoken_token(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_authorization_response_code_idtoken(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_code_token(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_code(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_idtoken_token(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_idtoken(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);

// non-static for test.c
apr_byte_t oidc_proto_validate_access_token(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt, const char *response_type, const char *access_token);
apr_byte_t oidc_proto_validate_code(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt, const char *response_type, const char *code);
apr_byte_t oidc_proto_validate_nonce(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *nonce, oidc_jwt_t *jwt);

// oidc_authz.c
typedef apr_byte_t (*oidc_authz_match_claim_fn_type)(request_rec *, const char * const, const json_t * const);
apr_byte_t oidc_authz_match_claim(request_rec *r, const char * const attr_spec, const json_t * const claims);
#ifdef USE_LIBJQ
apr_byte_t oidc_authz_match_claims_expr(request_rec *r, const char * const attr_spec, const json_t * const claims);
#endif
#if MODULE_MAGIC_NUMBER_MAJOR < 20100714
int oidc_authz_worker22(request_rec *r, const json_t *const claims, const require_line *const reqs, int nelts);
#else
authz_status oidc_authz_worker24(request_rec *r, const json_t * const claims, const char *require_args, const void *parsed_require_args, oidc_authz_match_claim_fn_type match_claim_fn);
#endif
int oidc_oauth_return_www_authenticate(request_rec *r, const char *error, const char *error_description);

// oidc_config.c

#define OIDCPrivateKeyFiles                  "OIDCPrivateKeyFiles"
#define OIDCRedirectURI                      "OIDCRedirectURI"
#define OIDCDefaultURL                       "OIDCDefaultURL"
#define OIDCCookieDomain                     "OIDCCookieDomain"
#define OIDCClaimPrefix                      "OIDCClaimPrefix"
#define OIDCRemoteUserClaim                  "OIDCRemoteUserClaim"
#define OIDCOAuthRemoteUserClaim             "OIDCOAuthRemoteUserClaim"
#define OIDCSessionType                      "OIDCSessionType"
#define OIDCMemCacheServers                  "OIDCMemCacheServers"
#define OIDCCacheShmMax                      "OIDCCacheShmMax"
#define OIDCCacheShmEntrySizeMax             "OIDCCacheShmEntrySizeMax"
#define OIDCRedisCacheServer                 "OIDCRedisCacheServer"
#define OIDCCookiePath                       "OIDCCookiePath"
#define OIDCInfoHook                         "OIDCInfoHook"
#define OIDCWhiteListedClaims                "OIDCWhiteListedClaims"

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
apr_byte_t oidc_cfg_dir_pass_refresh_token(request_rec *r);
apr_byte_t oidc_cfg_dir_accept_token_in(request_rec *r);
char *oidc_cfg_dir_accept_token_in_option(request_rec *r, const char *key);
int oidc_cfg_token_introspection_interval(request_rec *r);
int oidc_cfg_dir_preserve_post(request_rec *r);
apr_array_header_t *oidc_dir_cfg_pass_cookies(request_rec *r);
apr_array_header_t *oidc_dir_cfg_strip_cookies(request_rec *r);
int oidc_dir_cfg_unauth_action(request_rec *r);
int oidc_dir_cfg_unautz_action(request_rec *r);
char *oidc_dir_cfg_path_auth_request_params(request_rec *r);
char *oidc_dir_cfg_path_scope(request_rec *r);
oidc_valid_function_t oidc_cfg_get_valid_endpoint_auth_function(oidc_cfg *cfg);
int oidc_cfg_cache_encrypt(request_rec *r);
int oidc_cfg_session_cache_fallback_to_cookie(request_rec *r);
const char *oidc_parse_pkce_type(apr_pool_t *pool, const char *arg, oidc_proto_pkce_t **type);
const char *oidc_cfg_claim_prefix(request_rec *r);
int oidc_cfg_max_number_of_state_cookies(oidc_cfg *cfg);
int oidc_cfg_dir_refresh_access_token_before_expiry(request_rec *r);
int oidc_cfg_dir_logout_on_error_refresh(request_rec *r);
int oidc_cfg_delete_oldest_state_cookies(oidc_cfg *cfg);
void oidc_cfg_provider_init(oidc_provider_t *provider);

// oidc_util.c
int oidc_strnenvcmp(const char *a, const char *b, int len);
int oidc_base64url_encode(request_rec *r, char **dst, const char *src, int src_len, int remove_padding);
int oidc_base64url_decode(apr_pool_t *pool, char **dst, const char *src);
const char *oidc_get_current_url_host(request_rec *r);
char *oidc_get_current_url(request_rec *r);
const char *oidc_get_redirect_uri(request_rec *r, oidc_cfg *c);
const char *oidc_get_redirect_uri_iss(request_rec *r, oidc_cfg *c, oidc_provider_t *provider);
char *oidc_url_encode(const request_rec *r, const char *str, const char *charsToEncode);
char *oidc_normalize_header_name(const request_rec *r, const char *str);
void oidc_util_set_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires, const char *ext);
char *oidc_util_get_cookie(request_rec *r, const char *cookieName);
apr_byte_t oidc_util_http_get(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth, const char *bearer_token, int ssl_validate_server, char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key);
apr_byte_t oidc_util_http_post_form(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth, const char *bearer_token, int ssl_validate_server, char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key);
apr_byte_t oidc_util_http_post_json(request_rec *r, const char *url, json_t *data, const char *basic_auth, const char *bearer_token, int ssl_validate_server, char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key);
apr_byte_t oidc_util_request_matches_url(request_rec *r, const char *url);
apr_byte_t oidc_util_request_has_parameter(request_rec *r, const char* param);
apr_byte_t oidc_util_get_request_parameter(request_rec *r, char *name, char **value);
char *oidc_util_encode_json_object(request_rec *r, json_t *json, size_t flags);
apr_byte_t oidc_util_decode_json_object(request_rec *r, const char *str, json_t **json);
apr_byte_t oidc_util_decode_json_and_check_error(request_rec *r, const char *str, json_t **json);
int oidc_util_http_send(request_rec *r, const char *data, size_t data_len, const char *content_type, int success_rvalue);
int oidc_util_html_send(request_rec *r, const char *title, const char *html_head, const char *on_load, const char *html_body, int status_code);
char *oidc_util_escape_string(const request_rec *r, const char *str);
char *oidc_util_unescape_string(const request_rec *r, const char *str);
apr_byte_t oidc_util_read_form_encoded_params(request_rec *r, apr_table_t *table, char *data);
apr_byte_t oidc_util_read_post_params(request_rec *r, apr_table_t *table, apr_byte_t propagate, const char *strip_param_name);
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, apr_pool_t *pool, char **result);
apr_byte_t oidc_util_file_write(request_rec *r, const char *path, const char *data);
apr_byte_t oidc_util_issuer_match(const char *a, const char *b);
int oidc_util_html_send_error(request_rec *r, const char *html_template, const char *error, const char *description, int status_code);
apr_byte_t oidc_util_json_array_has_value(request_rec *r, json_t *haystack, const char *needle);
void oidc_util_set_app_info(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix, apr_byte_t as_header, apr_byte_t as_env_var);
void oidc_util_set_app_infos(request_rec *r, const json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter, apr_byte_t as_header, apr_byte_t as_env_var);
apr_hash_t *oidc_util_spaced_string_to_hashtable(apr_pool_t *pool, const char *str);
apr_byte_t oidc_util_spaced_string_equals(apr_pool_t *pool, const char *a, const char *b);
apr_byte_t oidc_util_spaced_string_contains(apr_pool_t *pool, const char *str, const char *match);
apr_byte_t oidc_json_object_get_string(apr_pool_t *pool, json_t *json, const char *name, char **value, const char *default_value);
apr_byte_t oidc_json_object_get_int(apr_pool_t *pool, json_t *json, const char *name, int *value, const int default_value);
apr_byte_t oidc_json_object_get_bool(apr_pool_t *pool, json_t *json, const char *name, int *value, const int default_value);
char *oidc_util_html_escape(apr_pool_t *pool, const char *input);
void oidc_util_table_add_query_encoded_params(apr_pool_t *pool, apr_table_t *table, const char *params);
apr_hash_t * oidc_util_merge_key_sets(apr_pool_t *pool, apr_hash_t *k1, apr_hash_t *k2);
apr_byte_t oidc_util_regexp_substitute(apr_pool_t *pool, const char *input, const char *regexp, const char *replace, char **output, char **error_str);
apr_byte_t oidc_util_regexp_first_match(apr_pool_t *pool, const char *input, const char *regexp, char **output, char **error_str);
apr_byte_t oidc_util_json_merge(request_rec *r, json_t *src, json_t *dst);
int oidc_util_cookie_domain_valid(const char *hostname, char *cookie_domain);
apr_byte_t oidc_util_hash_string_and_base64url_encode(request_rec *r, const char *openssl_hash_algo, const char *input, char **output);
apr_byte_t oidc_util_jwt_create(request_rec *r, const char *secret, json_t *payload, char **compact_encoded_jwt);
apr_byte_t oidc_util_jwt_verify(request_rec *r, const char *secret, const char *compact_encoded_jwt, json_t **result);
char *oidc_util_get_chunked_cookie(request_rec *r, const char *cookieName, int cookie_chunk_size);
void oidc_util_set_chunked_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires, int chunkSize, const char *ext);
apr_byte_t oidc_util_create_symmetric_key(request_rec *r, const char *client_secret, unsigned int r_key_len, const char *hash_algo, apr_byte_t set_kid, oidc_jwk_t **jwk);
apr_hash_t * oidc_util_merge_symmetric_key(apr_pool_t *pool, apr_hash_t *private_keys, oidc_jwk_t *jwk);
const char *oidc_util_get_provided_token_binding_id(const request_rec *r);
char *oidc_util_http_query_encoded_url(request_rec *r, const char *url, const apr_table_t *params);
char *oidc_util_get_full_path(apr_pool_t *pool, const char *abs_or_rel_filename);
apr_byte_t oidc_enabled(request_rec *r);
char *oidc_util_http_form_encoded_data(request_rec *r, const apr_table_t *params);

/* HTTP header constants */
#define OIDC_HTTP_HDR_COOKIE							"Cookie"
#define OIDC_HTTP_HDR_SET_COOKIE						"Set-Cookie"
#define OIDC_HTTP_HDR_USER_AGENT						"User-Agent"
#define OIDC_HTTP_HDR_X_FORWARDED_FOR					"X-Forwarded-For"
#define OIDC_HTTP_HDR_CONTENT_TYPE						"Content-Type"
#define OIDC_HTTP_HDR_CONTENT_LENGTH					"Content-Length"
#define OIDC_HTTP_HDR_X_REQUESTED_WITH					"X-Requested-With"
#define OIDC_HTTP_HDR_ACCEPT							"Accept"
#define OIDC_HTTP_HDR_AUTHORIZATION						"Authorization"
#define OIDC_HTTP_HDR_X_FORWARDED_PROTO					"X-Forwarded-Proto"
#define OIDC_HTTP_HDR_X_FORWARDED_PORT					"X-Forwarded-Port"
#define OIDC_HTTP_HDR_X_FORWARDED_HOST					"X-Forwarded-Host"
#define OIDC_HTTP_HDR_HOST								"Host"
#define OIDC_HTTP_HDR_LOCATION							"Location"
#define OIDC_HTTP_HDR_CACHE_CONTROL						"Cache-Control"
#define OIDC_HTTP_HDR_PRAGMA							"Pragma"
#define OIDC_HTTP_HDR_P3P								"P3P"
#define OIDC_HTTP_HDR_EXPIRES							"Expires"
#define OIDC_HTTP_HDR_X_FRAME_OPTIONS					"X-Frame-Options"
#define OIDC_HTTP_HDR_WWW_AUTHENTICATE					"WWW-Authenticate"
#define OIDC_HTTP_HDR_INCLUDE_REFERRED_TOKEN_BINDING_ID	"Include-Referred-Token-Binding-ID"

#define OIDC_HTTP_HDR_VAL_XML_HTTP_REQUEST				"XMLHttpRequest"

void oidc_util_hdr_in_set(const request_rec *r, const char *name, const char *value);
const char *oidc_util_hdr_in_cookie_get(const request_rec *r);
void oidc_util_hdr_in_cookie_set(const request_rec *r, const char *value);
const char *oidc_util_hdr_in_user_agent_get(const request_rec *r);
const char *oidc_util_hdr_in_x_forwarded_for_get(const request_rec *r);
const char *oidc_util_hdr_in_content_type_get(const request_rec *r);
const char *oidc_util_hdr_in_content_length_get(const request_rec *r);
const char *oidc_util_hdr_in_x_requested_with_get(const request_rec *r);
const char *oidc_util_hdr_in_accept_get(const request_rec *r);
const char *oidc_util_hdr_in_authorization_get(const request_rec *r);
const char *oidc_util_hdr_in_x_forwarded_proto_get(const request_rec *r);
const char *oidc_util_hdr_in_x_forwarded_port_get(const request_rec *r);
const char *oidc_util_hdr_in_x_forwarded_host_get(const request_rec *r);
const char *oidc_util_hdr_in_host_get(const request_rec *r);
void oidc_util_hdr_out_location_set(const request_rec *r, const char *value);
const char *oidc_util_hdr_out_location_get(const request_rec *r);
void oidc_util_hdr_err_out_add(const request_rec *r, const char *name, const char *value);
apr_byte_t oidc_util_hdr_in_accept_contains(const request_rec *r, const char *needle);
apr_byte_t oidc_util_json_validate_cnf(request_rec *r, json_t *jwt, int token_binding_policy);

// oidc_metadata.c
apr_byte_t oidc_metadata_provider_retrieve(request_rec *r, oidc_cfg *cfg, const char *issuer, const char *url, json_t **j_metadata, char **response);
apr_byte_t oidc_metadata_provider_parse(request_rec *r, oidc_cfg *cfg, json_t *j_provider, oidc_provider_t *provider);
apr_byte_t oidc_metadata_provider_is_valid(request_rec *r, oidc_cfg *cfg, json_t *j_provider, const char *issuer);
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg *cfg, apr_array_header_t **arr);
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg *cfg, const char *selected, oidc_provider_t **provider, apr_byte_t allow_discovery);
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg *cfg, const oidc_jwks_uri_t *jwks_uri, json_t **j_jwks, apr_byte_t *refresh);
apr_byte_t oidc_oauth_metadata_provider_parse(request_rec *r, oidc_cfg *c, json_t *j_provider);

// oidc_session.c
typedef struct {
	char uuid[APR_UUID_FORMATTED_LENGTH + 1]; /* unique id */
    const char *remote_user;                  /* user who owns this particular session */
    json_t *state;                            /* the state for this session, encoded in a JSON object */
    apr_time_t expiry;                        /* if > 0, the time of expiry of this session */
    const char *sid;
} oidc_session_t;

apr_byte_t oidc_session_load(request_rec *r, oidc_session_t **z);
apr_byte_t oidc_session_get(request_rec *r, oidc_session_t *z, const char *key, const char **value);
apr_byte_t oidc_session_set(request_rec *r, oidc_session_t *z, const char *key, const char *value);
apr_byte_t oidc_session_save(request_rec *r, oidc_session_t *z, apr_byte_t first_time);
apr_byte_t oidc_session_kill(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_free(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_extract(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_load_cache_by_uuid(request_rec *r, oidc_cfg *c, const char *uuid, oidc_session_t *z);

void oidc_session_set_userinfo_jwt(request_rec *r, oidc_session_t *z, const char *userinfo_jwt);
const char * oidc_session_get_userinfo_jwt(request_rec *r, oidc_session_t *z);
void oidc_session_set_userinfo_claims(request_rec *r, oidc_session_t *z, const char *claims);
const char * oidc_session_get_userinfo_claims(request_rec *r, oidc_session_t *z);
json_t *oidc_session_get_userinfo_claims_json(request_rec *r, oidc_session_t *z);
void oidc_session_set_idtoken_claims(request_rec *r, oidc_session_t *z, const char *idtoken_claims);
const char * oidc_session_get_idtoken_claims(request_rec *r, oidc_session_t *z);
json_t *oidc_session_get_idtoken_claims_json(request_rec *r, oidc_session_t *z);
void oidc_session_set_idtoken(request_rec *r, oidc_session_t *z, const char *s_id_token);
const char * oidc_session_get_idtoken(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token(request_rec *r, oidc_session_t *z, const char *access_token);
const char * oidc_session_get_access_token(request_rec *r, oidc_session_t *z);
void oidc_session_set_access_token_expires(request_rec *r, oidc_session_t *z, const int expires_in);
const char * oidc_session_get_access_token_expires(request_rec *r, oidc_session_t *z);
void oidc_session_set_refresh_token(request_rec *r, oidc_session_t *z, const char *refresh_token);
const char * oidc_session_get_refresh_token(request_rec *r, oidc_session_t *z);
void oidc_session_set_session_expires(request_rec *r, oidc_session_t *z, const apr_time_t expires);
apr_time_t oidc_session_get_session_expires(request_rec *r, oidc_session_t *z);
void oidc_session_set_cookie_domain(request_rec *r, oidc_session_t *z, const char *cookie_domain);
const char * oidc_session_get_cookie_domain(request_rec *r, oidc_session_t *z);
void oidc_session_reset_userinfo_last_refresh(request_rec *r, oidc_session_t *z);
apr_time_t oidc_session_get_userinfo_last_refresh(request_rec *r, oidc_session_t *z);
void oidc_session_reset_access_token_last_refresh(request_rec *r, oidc_session_t *z);
apr_time_t oidc_session_get_access_token_last_refresh(request_rec *r, oidc_session_t *z);
void oidc_session_set_request_state(request_rec *r, oidc_session_t *z, const char *request_state);
const char * oidc_session_get_request_state(request_rec *r, oidc_session_t *z);
void oidc_session_set_original_url(request_rec *r, oidc_session_t *z, const char *original_url);
const char * oidc_session_get_original_url(request_rec *r, oidc_session_t *z);
void oidc_session_set_session_state(request_rec *r, oidc_session_t *z, const char *session_state);
const char * oidc_session_get_session_state(request_rec *r, oidc_session_t *z);
void oidc_session_set_issuer(request_rec *r, oidc_session_t *z, const char *issuer);
const char * oidc_session_get_issuer(request_rec *r, oidc_session_t *z);
void oidc_session_set_client_id(request_rec *r, oidc_session_t *z, const char *client_id);

char *oidc_parse_base64(apr_pool_t *pool, const char *input, char **output, int *output_len);

#endif /* MOD_AUTH_OPENIDC_H_ */
