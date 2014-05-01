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
 * Copyright (C) 2013-2014 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
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
 * OpenID Connect metadata handling routines, for both OP discovery and client registration
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <apr_hash.h>
#include <apr_time.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include <httpd.h>
#include <http_log.h>

// for converting JWKs
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "mod_auth_openidc.h"

extern module AP_MODULE_DECLARE_DATA auth_openidc_module;

#define OIDC_METADATA_SUFFIX_PROVIDER "provider"
#define OIDC_METADATA_SUFFIX_CLIENT "client"
#define OIDC_METADATA_SUFFIX_CONF "conf"

/*
 * get the metadata filename for a specified issuer (cq. urlencode it)
 */
static const char *oidc_metadata_issuer_to_filename(request_rec *r,
		const char *issuer) {

	/* strip leading https:// */
	char *p = strstr(issuer, "https://");
	if (p == issuer) {
		p = apr_pstrdup(r->pool, issuer + strlen("https://"));
	} else {
		p = apr_pstrdup(r->pool, issuer);
	}

	/* strip trailing '/' */
	int n = strlen(p);
	if (p[n - 1] == '/')
		p[n - 1] = '\0';

	return oidc_util_escape_string(r, p);
}

/*
 * get the issuer from a metadata filename (cq. urldecode it)
 */
static const char *oidc_metadata_filename_to_issuer(request_rec *r,
		const char *filename) {
	char *result = apr_pstrdup(r->pool, filename);
	char *p = strrchr(result, '.');
	*p = '\0';
	p = oidc_util_unescape_string(r, result);
	return (strcmp(p, "accounts.google.com") == 0) ?
			p : apr_psprintf(r->pool, "https://%s", p);
}

/*
 * get the full path to the metadata file for a specified issuer and directory
 */
static const char *oidc_metadata_file_path(request_rec *r, oidc_cfg *cfg,
		const char *issuer, const char *type) {
	return apr_psprintf(r->pool, "%s/%s.%s", cfg->metadata_dir,
			oidc_metadata_issuer_to_filename(r, issuer), type);
}

/*
 * get the full path to the provider metadata file for a specified issuer
 */
static const char *oidc_metadata_provider_file_path(request_rec *r,
		const char *issuer) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer,
	OIDC_METADATA_SUFFIX_PROVIDER);
}

/*
 * get the full path to the client metadata file for a specified issuer
 */
static const char *oidc_metadata_client_file_path(request_rec *r,
		const char *issuer) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CLIENT);
}

/*
 * get the full path to the custom config file for a specified issuer
 */
static const char *oidc_metadata_conf_path(request_rec *r, const char *issuer) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CONF);
}

/*
 * get the full path to the jwks metadata file for a specified issuer
 */
static const char *oidc_metadata_jwks_cache_key(request_rec *r,
		const char *issuer) {
	return apr_psprintf(r->pool, "%s.jwks", issuer);
}

/*
 * read a JSON metadata file from disk
 */
static apr_byte_t oidc_metadata_file_read_json(request_rec *r, const char *path,
		apr_json_value_t **result) {
	apr_status_t rc = APR_SUCCESS;
	char *buf = NULL;

	/* read the file contents */
	if (oidc_util_file_read(r, path, &buf) == FALSE)
		return FALSE;

	/* decode the JSON contents of the buffer */
	if ((rc = apr_json_decode(result, buf, strlen(buf), r->pool)) != APR_SUCCESS) {
		/* something went wrong */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_file_read_json: JSON parsing (%s) returned an error: (%d)",
				path, rc);
		return FALSE;
	}

	if ((*result == NULL) || ((*result)->type != APR_JSON_OBJECT)) {
		/* oops, no JSON */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_file_read_json: parsed JSON from (%s) did not contain a JSON object",
				path);
		return FALSE;
	}

	/* log successful metadata retrieval */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_metadata_file_read_json: JSON parsed from file \"%s\"", path);

	return TRUE;
}

/*
 * check to see if JSON provider metadata is valid
 */
static apr_byte_t oidc_metadata_provider_is_valid(request_rec *r,
		apr_json_value_t *j_provider, const char *issuer) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_metadata_provider_is_valid: entering");

	/* get the "issuer" from the provider metadata and double-check that it matches what we looked for */
	apr_json_value_t *j_issuer = apr_hash_get(j_provider->value.object,
			"issuer", APR_HASH_KEY_STRING);
	if ((j_issuer == NULL) || (j_issuer->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_provider_is_valid: provider (%s) JSON metadata did not contain an \"issuer\" string",
				issuer);
		return FALSE;
	}

	/* check that the issuer matches */
	if (oidc_util_issuer_match(issuer, j_issuer->value.string.p) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_provider_is_valid: requested issuer (%s) does not match the \"issuer\" value in the provider metadata file: %s",
				issuer, j_issuer->value.string.p);
		return FALSE;
	}

	/* verify that the provider supports the a flow that we implement */
	apr_json_value_t *j_response_types_supported = apr_hash_get(
			j_provider->value.object, "response_types_supported",
			APR_HASH_KEY_STRING);
	if ((j_response_types_supported != NULL)
			&& (j_response_types_supported->type == APR_JSON_ARRAY)) {
		int i = 0;
		for (i = 0; i < j_response_types_supported->value.array->nelts; i++) {
			apr_json_value_t *elem = APR_ARRAY_IDX(
					j_response_types_supported->value.array, i,
					apr_json_value_t *);
			if (elem->type != APR_JSON_STRING) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"oidc_metadata_provider_is_valid: unhandled in-array JSON non-string object type [%d]",
						elem->type);
				continue;
			}
			if (oidc_proto_flow_is_supported(r->pool, elem->value.string.p))
				break;
		}
		if (i == j_response_types_supported->value.array->nelts) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_metadata_provider_is_valid: could not find a supported response type in provider metadata (%s) for entry \"response_types_supported\"; assuming that \"code\" flow is supported...",
					issuer);
			//return FALSE;
		}
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_metadata_provider_is_valid: provider (%s) JSON metadata did not contain a \"response_types_supported\" array; assuming that \"code\" flow is supported...",
				issuer);
		// TODO: hey, this is required-by-spec stuff right?
	}

	/* verify that the provider supports a response_mode that we implement */
	apr_json_value_t *response_modes_supported = apr_hash_get(
			j_provider->value.object, "response_modes_supported",
			APR_HASH_KEY_STRING);
	if ((response_modes_supported != NULL)
			&& (response_modes_supported->type == APR_JSON_ARRAY)) {
		int i = 0;
		for (i = 0; i < response_modes_supported->value.array->nelts; i++) {
			apr_json_value_t *elem = APR_ARRAY_IDX(
					response_modes_supported->value.array, i,
					apr_json_value_t *);
			if (elem->type != APR_JSON_STRING) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"oidc_metadata_provider_is_valid: unhandled in-array JSON non-string object type [%d]",
						elem->type);
				continue;
			}
			if ((apr_strnatcmp(elem->value.string.p, "fragment") == 0)
					|| (apr_strnatcmp(elem->value.string.p, "query") == 0)
					|| (apr_strnatcmp(elem->value.string.p, "form_post") == 0))
				break;
		}
		if (i == response_modes_supported->value.array->nelts) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_metadata_provider_is_valid: could not find a supported response mode in provider metadata (%s) for entry \"response_modes_supported\"",
					issuer);
			return FALSE;
		}
	} else {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_metadata_provider_is_valid: provider (%s) JSON metadata did not contain a \"response_modes_supported\" array; assuming that \"fragment\" and \"query\" are supported",
				issuer);
	}

	/* get a handle to the authorization endpoint */
	apr_json_value_t *j_authorization_endpoint = apr_hash_get(
			j_provider->value.object, "authorization_endpoint",
			APR_HASH_KEY_STRING);
	if ((j_authorization_endpoint == NULL)
			|| (j_authorization_endpoint->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_provider_is_valid: provider (%s) JSON metadata did not contain an \"authorization_endpoint\" string",
				issuer);
		return FALSE;
	}

	/* get a handle to the token endpoint */
	apr_json_value_t *j_token_endpoint = apr_hash_get(j_provider->value.object,
			"token_endpoint", APR_HASH_KEY_STRING);
	if ((j_token_endpoint == NULL)
			|| (j_token_endpoint->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_metadata_provider_is_valid: provider (%s) JSON metadata did not contain a \"token_endpoint\" string",
				issuer);
		//return FALSE;
	}

	/* get a handle to the user_info endpoint */
	apr_json_value_t *j_userinfo_endpoint = apr_hash_get(
			j_provider->value.object, "userinfo_endpoint", APR_HASH_KEY_STRING);
	if ((j_userinfo_endpoint != NULL)
			&& (j_userinfo_endpoint->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_metadata_provider_is_valid: provider (%s) JSON metadata contains a \"userinfo_endpoint\" entry, but it is not a string value",
				issuer);
	}
	// TODO: check for valid URL

	/* get a handle to the jwks_uri */
	apr_json_value_t *j_jwks_uri = apr_hash_get(j_provider->value.object,
			"jwks_uri", APR_HASH_KEY_STRING);
	if ((j_jwks_uri == NULL) || (j_jwks_uri->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_metadata_provider_is_valid: provider (%s) JSON metadata did not contain a \"jwks_uri\" string",
				issuer);
		//return FALSE;
	}

	/* find out what type of authentication the token endpoint supports (we only support post or basic) */
	apr_json_value_t *j_token_endpoint_auth_methods_supported = apr_hash_get(
			j_provider->value.object, "token_endpoint_auth_methods_supported",
			APR_HASH_KEY_STRING);
	if ((j_token_endpoint_auth_methods_supported == NULL)
			|| (j_token_endpoint_auth_methods_supported->type != APR_JSON_ARRAY)) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_metadata_provider_is_valid: provider (%s) JSON metadata did not contain a \"token_endpoint_auth_methods_supported\" array, assuming \"client_secret_basic\" is supported",
				issuer);
	} else {
		int i;
		for (i = 0;
				i < j_token_endpoint_auth_methods_supported->value.array->nelts;
				i++) {
			apr_json_value_t *elem = APR_ARRAY_IDX(
					j_token_endpoint_auth_methods_supported->value.array, i,
					apr_json_value_t *);
			if (elem->type != APR_JSON_STRING) {
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
						"oidc_metadata_provider_is_valid: unhandled in-array JSON object type [%d] in provider (%s) metadata for entry \"token_endpoint_auth_methods_supported\"",
						elem->type, issuer);
				continue;
			}
			if (strcmp(elem->value.string.p, "client_secret_post") == 0) {
				break;
			}
			if (strcmp(elem->value.string.p, "client_secret_basic") == 0) {
				break;
			}
		}
		if (i == j_token_endpoint_auth_methods_supported->value.array->nelts) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_metadata_provider_is_valid: could not find a supported value [client_secret_post|client_secret_basic] in provider (%s) metadata for entry \"token_endpoint_auth_methods_supported\"",
					issuer);
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * check to see if dynamically registered JSON client metadata is valid and has not expired
 */
static apr_byte_t oidc_metadata_client_is_valid(request_rec *r,
		apr_json_value_t *j_client, const char *issuer) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_metadata_client_is_valid: entering");

	/* get a handle to the client_id we need to use for this provider */
	apr_json_value_t *j_client_id = apr_hash_get(j_client->value.object,
			"client_id", APR_HASH_KEY_STRING);
	if ((j_client_id == NULL) || (j_client_id->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_client_is_valid: client (%s) JSON metadata did not contain a \"client_id\" string",
				issuer);
		return FALSE;
	}

	/* get a handle to the client_secret we need to use for this provider */
	apr_json_value_t *j_client_secret = apr_hash_get(j_client->value.object,
			"client_secret", APR_HASH_KEY_STRING);
	if ((j_client_secret == NULL)
			|| (j_client_secret->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_metadata_client_is_valid: client (%s) JSON metadata did not contain a \"client_secret\" string",
				issuer);
		//return FALSE;
	}

	/* the expiry timestamp from the JSON object */
	apr_json_value_t *expires_at = apr_hash_get(j_client->value.object,
			"client_secret_expires_at", APR_HASH_KEY_STRING);
	if ((expires_at == NULL) || (expires_at->type != APR_JSON_LONG)) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_metadata_client_is_valid: client (%s) metadata did not contain a \"client_secret_expires_at\" setting",
				issuer);
		/* assume that it never expires */
		return TRUE;
	}

	/* see if it is unrestricted */
	if (expires_at->value.lnumber == 0) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_metadata_client_is_valid: client (%s) metadata never expires (client_secret_expires_at=0)",
				issuer);
		return TRUE;
	}

	/* check if the value >= now */
	if (apr_time_sec(apr_time_now()) > expires_at->value.lnumber) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_metadata_client_is_valid: client (%s) secret expired",
				issuer);
		return FALSE;
	}

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_metadata_client_is_valid: client (%s) metadata is valid",
			issuer);

	return TRUE;
}

/*
 * checks if a parsed JWKs file is a valid one, cq. contains "keys"
 */
static apr_byte_t oidc_metadata_jwks_is_valid(request_rec *r,
		apr_json_value_t *j_jwks, const char *issuer) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_metadata_jwks_is_valid: entering");

	apr_json_value_t *keys = apr_hash_get(j_jwks->value.object, "keys",
	APR_HASH_KEY_STRING);
	if ((keys == NULL) || (keys->type != APR_JSON_ARRAY)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_jwks_is_valid: provider (%s) JWKS JSON metadata did not contain a \"keys\" array",
				issuer);
		return FALSE;
	}
	return TRUE;
}

/*
 * write JSON metadata to a file
 */
static apr_byte_t oidc_metadata_file_write(request_rec *r, const char *path,
		const char *data) {

	// TODO: completely erase the contents of the file if it already exists....

	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_written = 0;
	char s_err[128];

	/* try to open the metadata file for writing, creating it if it does not exist */
	if ((rc = apr_file_open(&fd, path, (APR_FOPEN_WRITE | APR_FOPEN_CREATE),
	APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_file_write: file \"%s\" could not be opened (%s)",
				path, apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* lock the file and move the write pointer to the start of it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* calculate the length of the data, which is a string length */
	apr_size_t len = strlen(data);

	/* (blocking) write the number of bytes in the buffer */
	rc = apr_file_write_full(fd, data, len, &bytes_written);

	/* check for a system error */
	if (rc != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_file_write: could not write to: \"%s\" (%s)",
				path, apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* check that all bytes from the header were written */
	if (bytes_written != len) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_file_write: could not write enough bytes to: \"%s\", bytes_written (%" APR_SIZE_T_FMT ") != len (%" APR_SIZE_T_FMT ")",
				path, bytes_written, len);
		return FALSE;
	}

	/* unlock and close the written file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_metadata_file_write: file \"%s\" written; number of bytes (%" APR_SIZE_T_FMT ")",
			path, len);

	return TRUE;
}

/* callback function type for checking metadata validity (provider or client) */
typedef apr_byte_t (*oidc_is_valid_function_t)(request_rec *,
		apr_json_value_t *, const char *);

/*
 * helper function to get the JSON (client or provider) metadata from the specified file path and check its validity
 */
static apr_byte_t oidc_metadata_get_and_check(request_rec *r, const char *path,
		const char *issuer, oidc_is_valid_function_t metadata_is_valid,
		apr_json_value_t **j_metadata) {

	apr_finfo_t fi;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];

	/* read the metadata from a file in to a variable */
	if (oidc_metadata_file_read_json(r, path, j_metadata) == FALSE)
		goto error_delete;

	if (metadata_is_valid) {
		/* we've got metadata that is JSON and no error-JSON, but now we check provider/client validity */
		if (metadata_is_valid(r, *j_metadata, issuer) == FALSE)
			goto error_delete;
	}

	/* all OK if we got here */
	return TRUE;

error_delete:

	/*
	 * this is expired or otherwise invalid metadata, we're probably going to get
	 * new metadata, so delete the file first, if it (still) exists at all
	 */
	if (apr_stat(&fi, path, APR_FINFO_MTIME, r->pool) == APR_SUCCESS) {

		if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_metadata_get_and_check: could not delete invalid metadata file %s (%s)",
					path, apr_strerror(rc, s_err, sizeof(s_err)));
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_metadata_get_and_check: removed invalid metadata file %s",
					path);
		}
	}

	return FALSE;
}

/*
 * helper function to retrieve (client or provider) metadata from a URL, check it and store it
 */
static apr_byte_t oidc_metadata_retrieve_and_store(request_rec *r,
		oidc_cfg *cfg, const char *url, int action, apr_table_t *params,
		int ssl_validate_server, const char *issuer,
		oidc_is_valid_function_t f_is_valid, const char *path,
		apr_json_value_t **j_metadata, const char *bearer_token) {
	const char *response = NULL;

	/* no valid provider metadata, get it at the specified URL with the specified parameters */
	if (oidc_util_http_call(r, url, action, params, NULL, bearer_token,
			ssl_validate_server, &response, cfg->http_timeout_short) == FALSE)
		return FALSE;

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, response, j_metadata) == FALSE)
		return FALSE;

	/* check to see if it is valid metadata */
	if (f_is_valid(r, *j_metadata, issuer) == FALSE)
		return FALSE;

	/* since it is valid, write the obtained provider metadata file */
	if (oidc_metadata_file_write(r, path, response) == FALSE)
		return FALSE;

	/* all OK */
	return TRUE;
}

/*
 * helper function to get the JWKs for the specified issuer
 */
static apr_byte_t oidc_metadata_jwks_retrieve_and_store(request_rec *r,
		oidc_cfg *cfg, oidc_provider_t *provider, apr_json_value_t **j_jwks) {

	const char *response = NULL;

	/* no valid provider metadata, get it at the specified URL with the specified parameters */
	if (oidc_util_http_call(r, provider->jwks_uri, OIDC_HTTP_GET, NULL, NULL,
			NULL, provider->ssl_validate_server, &response,
			cfg->http_timeout_long) == FALSE)
		return FALSE;

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, response, j_jwks) == FALSE)
		return FALSE;

	/* check to see if it is valid metadata */
	if (oidc_metadata_jwks_is_valid(r, *j_jwks, provider->issuer) == FALSE)
		return FALSE;

	/* store the JWKs in the cache */
	cfg->cache->set(r, oidc_metadata_jwks_cache_key(r, provider->issuer),
			response,
			apr_time_now() + apr_time_from_sec(provider->jwks_refresh_interval));

	return TRUE;
}

/*
 * return JWKs for the specified issuer
 */
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, apr_json_value_t **j_jwks,
		apr_byte_t *refresh) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_metadata_jwks_get: entering (issuer=%s, refresh=%d)",
			provider->issuer, *refresh);

	/* see if we need to do a forced refresh */
	if (*refresh == TRUE) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_metadata_jwks_get: doing a forced refresh of the JWKs for issuer \"%s\"",
				provider->issuer);
		if (oidc_metadata_jwks_retrieve_and_store(r, cfg, provider,
				j_jwks) == TRUE)
			return TRUE;
		// else: fallback on any cached JWKs
	}

	/* see if the JWKs is cached */
	const char *value = NULL;
	cfg->cache->get(r, oidc_metadata_jwks_cache_key(r, provider->issuer),
			&value);

	if (value == NULL) {
		/* it is non-existing or expired: do a forced refresh */
		*refresh = TRUE;
		return oidc_metadata_jwks_retrieve_and_store(r, cfg, provider, j_jwks);
	}

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, value, j_jwks) == FALSE)
		return FALSE;

	return TRUE;
}

/*
 * see if we have provider metadata and check its validity
 * if not, use OpenID Connect Provider Issuer Discovery to get it, check it and store it
 */
static apr_byte_t oidc_metadata_provider_get(request_rec *r, oidc_cfg *cfg,
		const char *issuer, apr_json_value_t **j_provider) {

	/* get the full file path to the provider metadata for this issuer */
	const char *provider_path = oidc_metadata_provider_file_path(r, issuer);

	/* see if we have valid metadata already, if so, return it */
	if (oidc_metadata_get_and_check(r, provider_path, issuer,
			oidc_metadata_provider_is_valid, j_provider) == TRUE)
		return TRUE;

	// TODO: how to do validity/expiry checks on provider metadata

	/* assemble the URL to the .well-known OpenID metadata */
	const char *url = apr_psprintf(r->pool, "%s",
			((strstr(issuer, "http://") == issuer)
					|| (strstr(issuer, "https://") == issuer)) ?
					issuer : apr_psprintf(r->pool, "https://%s", issuer));
	url = apr_psprintf(r->pool, "%s%s.well-known/openid-configuration", url,
			url[strlen(url) - 1] != '/' ? "/" : "");

	/* try and get it from there, checking it and storing it if successful */
	return oidc_metadata_retrieve_and_store(r, cfg, url, OIDC_HTTP_GET, NULL,
			cfg->provider.ssl_validate_server, issuer,
			oidc_metadata_provider_is_valid, provider_path, j_provider, NULL);
}

/*
 * see if we have config metadata
 */
static apr_byte_t oidc_metadata_conf_get(request_rec *r, oidc_cfg *cfg,
		const char *issuer, apr_json_value_t **j_conf) {

	if (j_conf == NULL)
		return TRUE;

	/* get the full file path to the conf metadata for this issuer */
	const char *conf_path = oidc_metadata_conf_path(r, issuer);

	/* see if we have valid metadata already, if so, return it */
	return oidc_metadata_get_and_check(r, conf_path, issuer, NULL, j_conf);
}

/*
 * see if we have client metadata and check its validity
 * if not, use OpenID Connect Client Registration to get it, check it and store it
 */
static apr_byte_t oidc_metadata_client_get(request_rec *r, oidc_cfg *cfg,
		const char *issuer, const char *registration_url,
		apr_json_value_t **j_client) {

	/* get the full file path to the provider metadata for this issuer */
	const char *client_path = oidc_metadata_client_file_path(r, issuer);

	/* see if we already have valid client metadata, if so, return TRUE */
	if (oidc_metadata_get_and_check(r, client_path, issuer,
			oidc_metadata_client_is_valid, j_client) == TRUE)
		return TRUE;

	/* at this point we have no valid client metadata, see if there's a registration endpoint for this provider */
	if (registration_url == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_client_get: no (valid) client metadata exists and provider JSON object did not contain a (valid) \"registration_endpoint\" string");
		return FALSE;
	}

	/* go and use Dynamic Client registration to fetch ourselves new client metadata */
	apr_table_t *params = apr_table_make(r->pool, 3);
	apr_table_addn(params, "client_name", cfg->provider.client_name);

	if (cfg->id_token_alg != NULL) {
		apr_table_addn(params, "id_token_signed_response_alg",
				cfg->id_token_alg);
	}

	int action = OIDC_HTTP_POST_JSON;

	/* hack away for pre-standard PingFederate client registration... */
	if (strstr(registration_url, "idp/client-registration.openid") != NULL) {

		/* add PF specific client registration parameters */
		apr_table_addn(params, "operation", "client_register");
		apr_table_addn(params, "redirect_uris", cfg->redirect_uri);
		if (cfg->provider.client_contact != NULL) {
			apr_table_addn(params, "contacts", cfg->provider.client_contact);
		}

		action = OIDC_HTTP_POST_FORM;

	} else {

		// TODO: also hacky, we need arrays for the next three values
		apr_table_addn(params, "redirect_uris",
				apr_psprintf(r->pool, "[\"%s\"]", cfg->redirect_uri));

		apr_array_header_t *flows = oidc_proto_supported_flows(r->pool);
		char *response_types = apr_pstrdup(r->pool, "[");
		int i;
		for (i = 0; i < flows->nelts; i++) {
			response_types = apr_psprintf(r->pool, "%s\"%s\"%s", response_types,
					((const char**) flows->elts)[i],
					(i < flows->nelts - 1) ? "," : "]");
		}
		apr_table_addn(params, "response_types", response_types);

		if (cfg->provider.client_contact != NULL) {
			apr_table_addn(params, "contacts",
					apr_psprintf(r->pool, "[\"%s\"]",
							cfg->provider.client_contact));
		}
	}

	/* try and get it from there, checking it and storing it if successful */
	return oidc_metadata_retrieve_and_store(r, cfg, registration_url, action,
			params, cfg->provider.ssl_validate_server, issuer,
			oidc_metadata_client_is_valid, client_path, j_client,
			cfg->provider.registration_token);
}

/*
 * return both provider and client metadata for the specified issuer
 *
 * TODO: should we use a modification timestamp on client metadata to skip
 *       validation if it has been done recently, or is that overkill?
 *
 *       at least it is not overkill for blacklisting providers that registration fails for
 *       but maybe we should just delete the provider data for those?
 */
static apr_byte_t oidc_metadata_get_provider_and_client(request_rec *r,
		oidc_cfg *cfg, const char *issuer, apr_json_value_t **j_provider,
		apr_json_value_t **j_client, apr_json_value_t **j_conf) {

	const char *registration_url = NULL;
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_metadata_get_provider_and_client: entering; issuer=\"%s\"",
			issuer);

	/* see if we can get valid provider metadata (possibly bootstrapping with Discovery), if not, return FALSE */
	if (oidc_metadata_provider_get(r, cfg, issuer, j_provider) == FALSE)
		return FALSE;

	/* get a reference to the registration endpoint, if it exists */
	apr_json_value_t *j_registration_endpoint = apr_hash_get(
			(*j_provider)->value.object, "registration_endpoint",
			APR_HASH_KEY_STRING);
	if ((j_registration_endpoint != NULL)
			&& (j_registration_endpoint->type == APR_JSON_STRING)) {
		registration_url = j_registration_endpoint->value.string.p;
	}

	if (oidc_metadata_client_get(r, cfg, issuer, registration_url,
			j_client) == FALSE)
		return FALSE;

	/* see if we can get valid config metadata, if not, that's not a problem */
	oidc_metadata_conf_get(r, cfg, issuer, j_conf);

	/* all OK */
	return TRUE;
}

/*
 * get a list of configured OIDC providers based on the entries in the provider metadata directory
 */
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg *cfg,
		apr_array_header_t **list) {
	apr_status_t rc;
	apr_dir_t *dir;
	apr_finfo_t fi;
	char s_err[128];

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_metadata_list: entering");

	/* open the metadata directory */
	if ((rc = apr_dir_open(&dir, cfg->metadata_dir, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_metadata_list: error opening metadata directory '%s' (%s)",
				cfg->metadata_dir, apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* allocate some space in the array that will hold the list of providers */
	*list = apr_array_make(r->pool, 5, sizeof(sizeof(const char*)));
	/* BTW: we could estimate the number in the array based on # directory entries... */

	/* loop over the entries in the provider metadata directory */
	while (apr_dir_read(&fi, APR_FINFO_NAME, dir) == APR_SUCCESS) {

		/* skip "." and ".." entries */
		if (fi.name[0] == '.')
			continue;
		/* skip other non-provider entries */
		char *ext = strrchr(fi.name, '.');
		if ((ext == NULL)
				|| (strcmp(++ext, OIDC_METADATA_SUFFIX_PROVIDER) != 0))
			continue;

		/* get the issuer from the filename */
		const char *issuer = oidc_metadata_filename_to_issuer(r, fi.name);

		/* pointer to the parsed JSON metadata for the provider */
		apr_json_value_t *j_provider = NULL;
		/* pointer to the parsed JSON metadata for the client */
		apr_json_value_t *j_client = NULL;

		/* get the provider and client metadata, do all checks and registration if possible */
		if (oidc_metadata_get_provider_and_client(r, cfg, issuer, &j_provider,
				&j_client, NULL) == FALSE)
			continue;

		/* push the decoded issuer filename in to the array */
		*(const char**) apr_array_push(*list) = issuer;
	}

	/* we're done, cleanup now */
	apr_dir_close(dir);

	return TRUE;
}

/*
 * find out what type of authentication we must provide to the token endpoint (we only support post or basic)
 */
static const char * oidc_metadata_token_endpoint_auth(request_rec *r,
		apr_json_value_t *j_client, apr_json_value_t *j_provider) {

	const char *result = "client_secret_basic";

	/* see if one is defined in the client metadata */
	apr_json_value_t *token_endpoint_auth_method = apr_hash_get(
			j_client->value.object, "token_endpoint_auth_method",
			APR_HASH_KEY_STRING);
	if (token_endpoint_auth_method != NULL) {
		if (token_endpoint_auth_method->type == APR_JSON_STRING) {
			if (strcmp(token_endpoint_auth_method->value.string.p,
					"client_secret_post") == 0) {
				result = "client_secret_post";
				return result;
			}
			if (strcmp(token_endpoint_auth_method->value.string.p,
					"client_secret_basic") == 0) {
				result = "client_secret_basic";
				return result;
			}
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_metadata_token_endpoint_auth: unsupported client auth method \"%s\" in client metadata for entry \"token_endpoint_auth_method\"",
					token_endpoint_auth_method->value.string.p);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_metadata_token_endpoint_auth: unexpected JSON object type [%d] (!= APR_JSON_STRING) in client metadata for entry \"token_endpoint_auth_method\"",
					token_endpoint_auth_method->type);
		}
	}

	/* no supported value in the client metadata, find a supported one in the provider metadata */
	apr_json_value_t *j_token_endpoint_auth_methods_supported = apr_hash_get(
			j_provider->value.object, "token_endpoint_auth_methods_supported",
			APR_HASH_KEY_STRING);

	if ((j_token_endpoint_auth_methods_supported != NULL)
			&& (j_token_endpoint_auth_methods_supported->type == APR_JSON_ARRAY)) {
		int i;
		for (i = 0;
				i < j_token_endpoint_auth_methods_supported->value.array->nelts;
				i++) {
			apr_json_value_t *elem = APR_ARRAY_IDX(
					j_token_endpoint_auth_methods_supported->value.array, i,
					apr_json_value_t *);
			if (elem->type != APR_JSON_STRING) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"oidc_metadata_token_endpoint_auth: unhandled in-array JSON object type [%d] in provider metadata for entry \"token_endpoint_auth_methods_supported\"",
						elem->type);
				continue;
			}
			if (strcmp(elem->value.string.p, "client_secret_post") == 0) {
				result = "client_secret_post";
				break;
			}
			if (strcmp(elem->value.string.p, "client_secret_basic") == 0) {
				result = "client_secret_basic";
				break;
			}
		}
	}

	return result;
}

/*
 * get the metadata for a specified issuer
 *
 * this fill the oidc_op_meta_t struct based on the issuer filename by reading and merging
 * contents from both provider metadata directory and client metadata directory
 */
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg *cfg, const char *issuer,
		oidc_provider_t **result) {

	/* pointer to the parsed JSON metadata for the provider */
	apr_json_value_t *j_provider = NULL;
	/* pointer to the parsed JSON metadata for the client */
	apr_json_value_t *j_client = NULL;
	/* pointer to the parsed conf metadata for the client */
	apr_json_value_t *j_conf = NULL;

	/* get the provider and client metadata */
	if (oidc_metadata_get_provider_and_client(r, cfg, issuer, &j_provider,
			&j_client, &j_conf) == FALSE)
		return FALSE;

	/* allocate space for a parsed-and-merged metadata struct */
	*result = apr_pcalloc(r->pool, sizeof(oidc_provider_t));
	/* provide easy pointer */
	oidc_provider_t *provider = *result;

	// PROVIDER

	/* get the "issuer" from the provider metadata */
	oidc_json_object_get_string(r->pool, j_provider, "issuer",
			&provider->issuer, NULL);

	/* get a handle to the authorization endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "authorization_endpoint",
			&provider->authorization_endpoint_url, NULL);

	/* get a handle to the token endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "token_endpoint",
			&provider->token_endpoint_url, NULL);
	/* get the authentication method for the token endpoint */
	provider->token_endpoint_auth = apr_pstrdup(r->pool,
			oidc_metadata_token_endpoint_auth(r, j_client, j_provider));

	/* get a handle to the user_info endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "userinfo_endpoint",
			&provider->userinfo_endpoint_url, NULL);

	/* get a handle to the jwks_uri endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "jwks_uri",
			&provider->jwks_uri, NULL);

	// CLIENT

	/* get a handle to the client_id we need to use for this provider */
	oidc_json_object_get_string(r->pool, j_client, "client_id",
			&provider->client_id, NULL);

	/* get a handle to the client_secret we need to use for this provider */
	oidc_json_object_get_string(r->pool, j_client, "client_secret",
			&provider->client_secret, NULL);

	// CONF

	/* find out if we need to perform SSL server certificate validation on the token_endpoint and user_info_endpoint for this provider */
	oidc_json_object_get_int(r->pool, j_conf, "ssl_validate_server",
			&provider->ssl_validate_server, cfg->provider.ssl_validate_server);

	/* find out what scopes we should be requesting from this provider */
	// TODO: use the provider "scopes_supported" to mix-and-match with what we've configured for the client
	// TODO: check that "openid" is always included in the configured scopes, right?
	oidc_json_object_get_string(r->pool, j_conf, "scope", &provider->scope,
			cfg->provider.scope);

	/* see if we've got a custom JWKs refresh interval */
	oidc_json_object_get_int(r->pool, j_conf, "jwks_refresh_interval",
			&provider->jwks_refresh_interval,
			cfg->provider.jwks_refresh_interval);

	/* see if we've got a custom IAT slack interval */
	oidc_json_object_get_int(r->pool, j_conf, "idtoken_iat_slack",
			&provider->idtoken_iat_slack, cfg->provider.idtoken_iat_slack);

	/* get the response mode to use */
	oidc_json_object_get_string(r->pool, j_conf, "response_mode",
			&provider->response_mode, cfg->provider.response_mode);

	/* get the client name */
	oidc_json_object_get_string(r->pool, j_conf, "client_name",
			&provider->client_name, cfg->provider.client_name);

	/* get the client contact */
	oidc_json_object_get_string(r->pool, j_conf, "client_contact",
			&provider->client_contact, cfg->provider.client_contact);

	/* get the dynamic client registration token */
	oidc_json_object_get_string(r->pool, j_conf, "registration_token",
			&provider->registration_token, cfg->provider.registration_token);

	/* get the flow to use */
	provider->response_type = cfg->provider.response_type;

	/*
	 * get the response_type to use conf defined takes priority over provider or client defined
	 */
	apr_json_value_t *j_conf_response_type = apr_hash_get(j_conf->value.object,
			"response_type", APR_HASH_KEY_STRING);
	if ((j_conf_response_type != NULL)
			&& (j_conf_response_type->type == APR_JSON_STRING)) {
		provider->response_type = apr_pstrdup(r->pool,
				j_conf_response_type->value.string.p);
	} else {
		/* "response_types" is an array in the client metadata as by spec */
		apr_json_value_t *j_response_types = apr_hash_get(
				j_client->value.object, "response_types", APR_HASH_KEY_STRING);
		if ((j_response_types != NULL)
				&& (j_response_types->type == APR_JSON_ARRAY)) {
			/* if there's an array we'll prefer the configured response_type if supported */
			if (oidc_util_json_array_has_value(r, j_response_types,
					provider->response_type) == FALSE) {
				/* if the configured response_type is not supported, we'll fallback to the first one that is listed */
				apr_json_value_t *j_response_type = APR_ARRAY_IDX(
						j_response_types->value.array, 0, apr_json_value_t *);
				if (j_response_type->type == APR_JSON_STRING) {
					provider->response_type = apr_pstrdup(r->pool,
							j_response_type->value.string.p);
				}
			}
		}
	}

	return TRUE;
}

