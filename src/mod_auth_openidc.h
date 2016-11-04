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
 * Copyright (C) 2013-2016 Ping Identity Corporation
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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
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

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(auth_openidc);
#endif

#ifndef OIDC_DEBUG
#define OIDC_DEBUG APLOG_DEBUG
#endif

#define oidc_log(r, level, fmt, ...) ap_log_rerror(APLOG_MARK, level, 0, r,"%s: %s", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
#define oidc_slog(s, level, fmt, ...) ap_log_error(APLOG_MARK, level, 0, s, "%s: %s", __FUNCTION__, apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))

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

/* key for storing the claims in the session context */
#define OIDC_CLAIMS_SESSION_KEY "claims"
/* key for storing the id_token in the session context */
#define OIDC_IDTOKEN_CLAIMS_SESSION_KEY "id_token_claims"
/* key for storing the raw id_token in the session context */
#define OIDC_IDTOKEN_SESSION_KEY "id_token"
/* key for storing the access_token in the session context */
#define OIDC_ACCESSTOKEN_SESSION_KEY "access_token"
/* key for storing the access_token expiry in the session context */
#define OIDC_ACCESSTOKEN_EXPIRES_SESSION_KEY "access_token_expires"
/* key for storing the refresh_token in the session context */
#define OIDC_REFRESHTOKEN_SESSION_KEY "refresh_token"
/* key for storing maximum session duration in the session context */
#define OIDC_SESSION_EXPIRES_SESSION_KEY "session_expires"
/* key for storing the cookie domain in the session context */
#define OIDC_COOKIE_DOMAIN_SESSION_KEY "cookie_domain"
/* key for storing last user info refresh timestamp in the session context */
#define OIDC_USERINFO_LAST_REFRESH_SESSION_KEY "userinfo_last_refresh"
/* key for storing request state */
#define OIDC_REQUEST_STATE_SESSION_KEY "request_state"
/* key for storing the original URL */
#define OIDC_REQUEST_ORIGINAL_URL "original_url"

/* key for storing the session_state in the session context */
#define OIDC_SESSION_STATE_SESSION_KEY "session_state"
/* key for storing the issuer in the session context */
#define OIDC_ISSUER_SESSION_KEY "issuer"
/* key for storing the client_id in the session context */
#define OIDC_CLIENTID_SESSION_KEY "client_id"
/* key for storing the check_session_iframe in the session context */
#define OIDC_CHECK_IFRAME_SESSION_KEY "check_session_iframe"
/* key for storing the end_session_endpoint in the session context */
#define OIDC_LOGOUT_ENDPOINT_SESSION_KEY "end_session_endpoint"

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
/* pass id_token payload as JSON object in header*/
#define OIDC_PASS_IDTOKEN_AS_PAYLOAD    2
/* pass id_token in compact serialized format in header*/
#define OIDC_PASS_IDTOKEN_AS_SERIALIZED 4

#define OIDC_OAUTH_ACCEPT_TOKEN_IN_DEFAULT 0
/* accept bearer token in header (default) */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_HEADER  1
/* accept bearer token as a post parameter */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_POST    2
/* accept bearer token as a query parameter */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_QUERY   4
/* accept bearer token as a cookie parameter (PingAccess) */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_COOKIE  8

/* the hash key of the cookie name value in the list of options */
#define OIDC_OAUTH_ACCEPT_TOKEN_IN_OPTION_COOKIE_NAME "cookie-name"

/* introspection method options */
#define OIDC_INTROSPECTION_METHOD_GET  "GET"
#define OIDC_INTROSPECTION_METHOD_POST "POST"

/* prefix of the cookie that binds the state in the authorization request/response to the browser */
#define OIDCStateCookiePrefix  "mod_auth_openidc_state_"

/* default prefix for information passed in HTTP headers */
#define OIDC_DEFAULT_HEADER_PREFIX "OIDC_"

/* the (global) key for the mod_auth_openidc related state that is stored in the request userdata context */
#define OIDC_USERDATA_KEY "mod_auth_openidc_state"

#define OIDC_USERDATA_ENV_KEY "mod_auth_openidc_env"

/* input filter hook name */
#define OIDC_UTIL_HTTP_SENDSTRING "OIDC_UTIL_HTTP_SENDSTRING"

/* the name of the keyword that follows the Require primitive to indicate claims-based authorization */
#define OIDC_REQUIRE_NAME "claim"

/* defines for how long provider metadata will be cached */
#define OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT 86400

/* define the parameter value for the "logout" request that indicates a GET-style logout call from the OP */
#define OIDC_GET_STYLE_LOGOUT_PARAM_VALUE "get"
#define OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE "img"

/* define the name of the cookie/parameter for CSRF protection */
#define OIDC_CSRF_NAME "x_csrf"

/* cache sections */
#define OIDC_CACHE_SECTION_JTI "jti"
#define OIDC_CACHE_SECTION_SESSION "session"
#define OIDC_CACHE_SECTION_NONCE "nonce"
#define OIDC_CACHE_SECTION_JWKS "jwks"
#define OIDC_CACHE_SECTION_ACCESS_TOKEN "access_token"
#define OIDC_CACHE_SECTION_PROVIDER "provider"
#define OIDC_CACHE_SECTION_REQUEST_URI "request_uri"

/* http methods */
#define OIDC_METHOD_GET       "get"
#define OIDC_METHOD_FORM_POST "form_post"

/* the maximum size of data that we accept in a single POST value: 1MB */
#define OIDC_MAX_POST_DATA_LEN 1024 * 1024

#define OIDC_UNAUTH_AUTHENTICATE 1
#define OIDC_UNAUTH_PASS         2
#define OIDC_UNAUTH_RETURN401    3
#define OIDC_UNAUTH_RETURN410    4

#define OIDC_REQUEST_URI_CACHE_DURATION 30

#define OIDC_USER_INFO_TOKEN_METHOD_HEADER 0
#define OIDC_USER_INFO_TOKEN_METHOD_POST   1

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
	char *registration_endpoint_url;
	char *check_session_iframe;
	char *end_session_endpoint;
	char *jwks_uri;
	char *client_id;
	char *client_secret;
	char *token_endpoint_tls_client_key;
	char *token_endpoint_tls_client_cert;

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
	char *pkce_method;
	int userinfo_refresh_interval;

	char *client_jwks_uri;
	char *id_token_signed_response_alg;
	char *id_token_encrypted_response_alg;
	char *id_token_encrypted_response_enc;
	char *userinfo_signed_response_alg;
	char *userinfo_encrypted_response_alg;
	char *userinfo_encrypted_response_enc;
	int userinfo_token_method;
	char *request_object;
} oidc_provider_t ;

typedef struct oidc_remote_user_claim_t {
	const char *claim_name;
	const char *reg_exp;
} oidc_remote_user_claim_t;

typedef struct oidc_oauth_t {
	int ssl_validate_server;
	char *client_id;
	char *client_secret;
	char *introspection_endpoint_tls_client_key;
	char *introspection_endpoint_tls_client_cert;
	char *introspection_endpoint_url;
	char *introspection_endpoint_method;
	char *introspection_endpoint_params;
	char *introspection_endpoint_auth;
	char *introspection_token_param_name;
	char *introspection_token_expiry_claim_name;
	char *introspection_token_expiry_claim_format;
	int introspection_token_expiry_claim_required;
	oidc_remote_user_claim_t remote_user_claim;
	apr_hash_t *verify_shared_keys;
	char *verify_jwks_uri;
	apr_hash_t *verify_public_keys;
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
	/* cache_type= memcache: list of memcache host/port servers to use */
	char *cache_memcache_servers;
	/* cache_type = shm: size of the shared memory segment (cq. max number of cached entries) */
	int cache_shm_size_max;
	/* cache_type = shm: maximum size in bytes of a cache entry */
	int cache_shm_entry_size_max;
#ifdef USE_LIBHIREDIS
	/* cache_type= redis: Redis host/port server to use */
	char *cache_redis_server;
	char *cache_redis_password;
#endif

	/* tell the module to strip any mod_auth_openidc related headers that already have been set by the user-agent, normally required for secure operation */
	int scrub_request_headers;

	int http_timeout_long;
	int http_timeout_short;
	int state_timeout;
	int session_inactivity_timeout;

	char *cookie_domain;
	char *claim_delimiter;
	char *claim_prefix;
	oidc_remote_user_claim_t remote_user_claim;
	int pass_idtoken_as;
	int cookie_http_only;

	char *outgoing_proxy;

	char *crypto_passphrase;

	int provider_metadata_refresh_interval;

} oidc_cfg;

int oidc_check_user_id(request_rec *r);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status oidc_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args);
#else
int oidc_auth_checker(request_rec *r);
#endif
void oidc_request_state_set(request_rec *r, const char *key, const char *value);
const char*oidc_request_state_get(request_rec *r, const char *key);
int oidc_handle_jwks(request_rec *r, oidc_cfg *c);
apr_byte_t oidc_post_preserve_javascript(request_rec *r, const char *location, char **javascript, char **javascript_method);

// oidc_oauth
int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c);

// oidc_proto.c
char *oidc_proto_peek_jwt_header(request_rec *r, const char *jwt, char **alg);
int oidc_proto_authorization_request(request_rec *r, struct oidc_provider_t *provider, const char *login_hint, const char *redirect_uri, const char *state, json_t *proto_state, const char *id_token_hint, const char *code_challenge, const char *auth_request_params);
apr_byte_t oidc_proto_is_post_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_is_redirect_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_refresh_request(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *rtoken, char **id_token, char **access_token, char **token_type, int *expires_in, char **refresh_token);
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *id_token_sub, const char *access_token, const char **response);
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg, const char *acct, char **issuer);
apr_byte_t oidc_proto_url_based_discovery(request_rec *r, oidc_cfg *cfg, const char *url, char **issuer);
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *id_token, const char *nonce, oidc_jwt_t **jwt, apr_byte_t is_code_flow);
int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c);
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool);
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow);
apr_byte_t oidc_proto_validate_authorization_response(request_rec *r, const char *response_type, const char *requested_response_mode, char **code, char **id_token, char **access_token, char **token_type, const char *used_response_mode);
apr_byte_t oidc_proto_jwt_verify(request_rec *r, oidc_cfg *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri, apr_hash_t *symmetric_keys);
apr_byte_t oidc_proto_validate_jwt(request_rec *r, oidc_jwt_t *jwt, const char *iss, apr_byte_t exp_is_mandatory, apr_byte_t iat_is_mandatory, int iat_slack);
apr_byte_t oidc_proto_generate_nonce(request_rec *r, char **nonce, int len);
apr_byte_t oidc_proto_generate_code_verifier(request_rec *r, char **code_verifier, int len);
apr_byte_t oidc_proto_generate_code_challenge(request_rec *r, const char *code_verifier, char **code_challenge, const char *challenge_method);

apr_byte_t oidc_proto_authorization_response_code_idtoken_token(request_rec *r, oidc_cfg *c, json_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_authorization_response_code_idtoken(request_rec *r, oidc_cfg *c, json_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_code_token(request_rec *r, oidc_cfg *c, json_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_code(request_rec *r, oidc_cfg *c, json_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_idtoken_token(request_rec *r, oidc_cfg *c, json_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);
apr_byte_t oidc_proto_handle_authorization_response_idtoken(request_rec *r, oidc_cfg *c, json_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt);

// non-static for test.c
apr_byte_t oidc_proto_validate_access_token(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt, const char *response_type, const char *access_token);
apr_byte_t oidc_proto_validate_code(request_rec *r, oidc_provider_t *provider, oidc_jwt_t *jwt, const char *response_type, const char *code);
apr_byte_t oidc_proto_validate_nonce(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *nonce, oidc_jwt_t *jwt);

// oidc_authz.c
int oidc_authz_worker(request_rec *r, const json_t *const claims, const require_line *const reqs, int nelts);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status oidc_authz_worker24(request_rec *r, const json_t * const claims, const char *require_line);
#endif
int oidc_oauth_return_www_authenticate(request_rec *r, const char *error, const char *error_description);

// oidc_config.c
void *oidc_create_server_config(apr_pool_t *pool, server_rec *svr);
void *oidc_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD);
void *oidc_create_dir_config(apr_pool_t *pool, char *path);
void *oidc_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
void oidc_register_hooks(apr_pool_t *pool);
char *oidc_cfg_dir_discover_url(request_rec *r);
char *oidc_cfg_dir_cookie(request_rec *r);
char *oidc_cfg_dir_cookie_path(request_rec *r);
char *oidc_cfg_dir_authn_header(request_rec *r);
int oidc_cfg_dir_pass_info_in_headers(request_rec *r);
int oidc_cfg_dir_pass_info_in_envvars(request_rec *r);
int oidc_cfg_dir_pass_refresh_token(request_rec *r);
int oidc_cfg_dir_accept_token_in(request_rec *r);
char *oidc_cfg_dir_accept_token_in_option(request_rec *r, const char *key);
int oidc_cfg_token_introspection_interval(request_rec *r);
int oidc_cfg_dir_preserve_post(request_rec *r);
apr_array_header_t *oidc_dir_cfg_pass_cookies(request_rec *r);
apr_array_header_t *oidc_dir_cfg_strip_cookies(request_rec *r);
int oidc_dir_cfg_unauth_action(request_rec *r);
oidc_valid_function_t oidc_cfg_get_valid_endpoint_auth_function(oidc_cfg *cfg);

// oidc_util.c
int oidc_strnenvcmp(const char *a, const char *b, int len);
int oidc_base64url_encode(request_rec *r, char **dst, const char *src, int src_len, int remove_padding);
int oidc_base64url_decode(apr_pool_t *pool, char **dst, const char *src);
const char *oidc_get_current_url_host(request_rec *r);
char *oidc_get_current_url(request_rec *r);
char *oidc_url_encode(const request_rec *r, const char *str, const char *charsToEncode);
char *oidc_normalize_header_name(const request_rec *r, const char *str);
void oidc_util_set_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires);
char *oidc_util_get_cookie(request_rec *r, const char *cookieName);
apr_byte_t oidc_util_http_get(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth, const char *bearer_token, int ssl_validate_server, const char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key);
apr_byte_t oidc_util_http_post_form(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth, const char *bearer_token, int ssl_validate_server, const char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key);
apr_byte_t oidc_util_http_post_json(request_rec *r, const char *url, const json_t *data, const char *basic_auth, const char *bearer_token, int ssl_validate_server, const char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies, const char *ssl_cert, const char *ssl_key);
apr_byte_t oidc_util_request_matches_url(request_rec *r, const char *url);
apr_byte_t oidc_util_request_has_parameter(request_rec *r, const char* param);
apr_byte_t oidc_util_get_request_parameter(request_rec *r, char *name, char **value);
apr_byte_t oidc_util_decode_json_object(request_rec *r, const char *str, json_t **json);
apr_byte_t oidc_util_decode_json_and_check_error(request_rec *r, const char *str, json_t **json);
int oidc_util_http_send(request_rec *r, const char *data, int data_len, const char *content_type, int success_rvalue);
int oidc_util_html_send(request_rec *r, const char *title, const char *html_head, const char *on_load, const char *html_body, int status_code);
char *oidc_util_escape_string(const request_rec *r, const char *str);
char *oidc_util_unescape_string(const request_rec *r, const char *str);
apr_byte_t oidc_util_read_form_encoded_params(request_rec *r, apr_table_t *table, char *data);
apr_byte_t oidc_util_read_post_params(request_rec *r, apr_table_t *table);
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, apr_pool_t *pool, char **result);
apr_byte_t oidc_util_issuer_match(const char *a, const char *b);
int oidc_util_html_send_error(request_rec *r, const char *html_template, const char *error, const char *description, int status_code);
apr_byte_t oidc_util_json_array_has_value(request_rec *r, json_t *haystack, const char *needle);
void oidc_util_set_header(request_rec *r, const char *s_name, const char *s_value);
void oidc_util_set_app_info(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix, apr_byte_t as_header, apr_byte_t as_env_var);
void oidc_util_set_app_infos(request_rec *r, const json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter, apr_byte_t as_header, apr_byte_t as_env_var);
apr_hash_t *oidc_util_spaced_string_to_hashtable(apr_pool_t *pool, const char *str);
apr_byte_t oidc_util_spaced_string_equals(apr_pool_t *pool, const char *a, const char *b);
apr_byte_t oidc_util_spaced_string_contains(apr_pool_t *pool, const char *str, const char *match);
apr_byte_t oidc_json_object_get_string(apr_pool_t *pool, json_t *json, const char *name, char **value, const char *default_value);
apr_byte_t oidc_json_object_get_int(apr_pool_t *pool, json_t *json, const char *name, int *value, const int default_value);
char *oidc_util_html_escape(apr_pool_t *pool, const char *input);
void oidc_util_table_add_query_encoded_params(apr_pool_t *pool, apr_table_t *table, const char *params);
apr_hash_t * oidc_util_merge_key_sets(apr_pool_t *pool, apr_hash_t *k1, apr_hash_t *k2);
apr_byte_t oidc_util_regexp_first_match(apr_pool_t *pool, const char *input, const char *regexp, char **output, char **error_str);
apr_byte_t oidc_util_json_merge(json_t *src, json_t *dst);
int oidc_util_cookie_domain_valid(const char *hostname, char *cookie_domain);
apr_byte_t oidc_util_hash_string_and_base64url_encode(request_rec *r, const char *openssl_hash_algo, const char *input, char **output);
apr_byte_t oidc_util_jwt_create(request_rec *r, const char *secret, json_t *payload, char **compact_encoded_jwt);
apr_byte_t oidc_util_jwt_verify(request_rec *r, const char *secret, const char *compact_encoded_jwt, json_t **result);
char *oidc_util_get_chunked_cookie(request_rec *r, const char *cookieName, int cookie_chunk_size);
void oidc_util_set_chunked_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires, int chunkSize);
apr_byte_t oidc_util_create_symmetric_key(request_rec *r, const char *client_secret, int r_key_len, const char *hash_algo, apr_byte_t set_kid, oidc_jwk_t **jwk);
apr_hash_t * oidc_util_merge_symmetric_key(apr_pool_t *pool, apr_hash_t *private_keys, oidc_jwk_t *jwk);

// oidc_metadata.c
apr_byte_t oidc_metadata_provider_retrieve(request_rec *r, oidc_cfg *cfg, const char *issuer, const char *url, json_t **j_metadata, const char **response);
apr_byte_t oidc_metadata_provider_parse(request_rec *r, oidc_cfg *cfg, json_t *j_provider, oidc_provider_t *provider);
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg *cfg, apr_array_header_t **arr);
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg *cfg, const char *selected, oidc_provider_t **provider, apr_byte_t allow_discovery);
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg *cfg, const oidc_jwks_uri_t *jwks_uri, json_t **j_jwks, apr_byte_t *refresh);

// oidc_session.c
typedef struct {
    const char *remote_user;  /* user who owns this particular session */
    json_t *state;            /* the state for this session, encoded in a JSON object */
    apr_time_t expiry;        /* if > 0, the time of expiry of this session */
} oidc_session_t;

apr_byte_t oidc_session_load(request_rec *r, oidc_session_t **z);
apr_byte_t oidc_session_get(request_rec *r, oidc_session_t *z, const char *key, const char **value);
apr_byte_t oidc_session_set(request_rec *r, oidc_session_t *z, const char *key, const char *value);
apr_byte_t oidc_session_save(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_kill(request_rec *r, oidc_session_t *z);
apr_byte_t oidc_session_free(request_rec *r, oidc_session_t *z);

#endif /* MOD_AUTH_OPENIDC_H_ */
