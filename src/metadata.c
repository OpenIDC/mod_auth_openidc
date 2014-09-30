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
		p = strstr(issuer, "http://");
		if (p == issuer) {
			p = apr_pstrdup(r->pool, issuer + strlen("http://"));
		} else {
			p = apr_pstrdup(r->pool, issuer);
		}
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
		json_t **result) {
	char *buf = NULL;

	/* read the file contents */
	if (oidc_util_file_read(r, path, &buf) == FALSE)
		return FALSE;

	/* decode the JSON contents of the buffer */
	json_error_t json_error;
	*result = json_loads(buf, 0, &json_error);

	if (*result == NULL) {
		/* something went wrong */
		oidc_error(r, "JSON parsing (%s) returned an error: %s", path,
				json_error.text);
		return FALSE;
	}

	if (!json_is_object(*result)) {
		/* oops, no JSON */
		oidc_error(r, "parsed JSON from (%s) did not contain a JSON object",
				path);
		json_decref(*result);
		return FALSE;
	}

	/* log successful metadata retrieval */
	oidc_debug(r, "JSON parsed from file \"%s\"", path);

	return TRUE;
}

/*
 * check to see if JSON provider metadata is valid
 */
static apr_byte_t oidc_metadata_provider_is_valid(request_rec *r,
		json_t *j_provider, const char *issuer) {

	/* get the "issuer" from the provider metadata and double-check that it matches what we looked for */
	json_t *j_issuer = json_object_get(j_provider, "issuer");
	if ((j_issuer == NULL) || (!json_is_string(j_issuer))) {
		oidc_error(r,
				"provider (%s) JSON metadata did not contain an \"issuer\" string",
				issuer);
		return FALSE;
	}

	/* check that the issuer matches */
	if (oidc_util_issuer_match(issuer, json_string_value(j_issuer)) == FALSE) {
		oidc_warn(r,
				"requested issuer (%s) does not match the \"issuer\" value in the provider metadata file: %s",
				issuer, json_string_value(j_issuer));
		//return FALSE;
	}

	/* verify that the provider supports the a flow that we implement */
	json_t *j_response_types_supported = json_object_get(j_provider,
			"response_types_supported");
	if ((j_response_types_supported != NULL)
			&& (json_is_array(j_response_types_supported))) {
		int i = 0;
		for (i = 0; i < json_array_size(j_response_types_supported); i++) {
			json_t *elem = json_array_get(j_response_types_supported, i);
			if (!json_is_string(elem)) {
				oidc_error(r,
						"unhandled in-array JSON non-string object type [%d]",
						elem->type);
				continue;
			}
			if (oidc_proto_flow_is_supported(r->pool, json_string_value(elem)))
				break;
		}
		if (i == json_array_size(j_response_types_supported)) {
			oidc_warn(r,
					"could not find a supported response type in provider metadata (%s) for entry \"response_types_supported\"; assuming that \"code\" flow is supported...",
					issuer);
			//return FALSE;
		}
	} else {
		oidc_warn(r,
				"provider (%s) JSON metadata did not contain a \"response_types_supported\" array; assuming that \"code\" flow is supported...",
				issuer);
		// TODO: hey, this is required-by-spec stuff right?
	}

	/* verify that the provider supports a response_mode that we implement */
	json_t *response_modes_supported = json_object_get(j_provider,
			"response_modes_supported");
	if ((response_modes_supported != NULL)
			&& (json_is_array(response_modes_supported))) {
		int i = 0;
		for (i = 0; i < json_array_size(response_modes_supported); i++) {
			json_t *elem = json_array_get(response_modes_supported, i);
			if (!json_is_string(elem)) {
				oidc_error(r,
						"unhandled in-array JSON non-string object type [%d]",
						elem->type);
				continue;
			}
			if ((apr_strnatcmp(json_string_value(elem), "fragment") == 0)
					|| (apr_strnatcmp(json_string_value(elem), "query") == 0)
					|| (apr_strnatcmp(json_string_value(elem), "form_post") == 0))
				break;
		}
		if (i == json_array_size(response_modes_supported)) {
			oidc_warn(r,
					"could not find a supported response mode in provider metadata (%s) for entry \"response_modes_supported\"",
					issuer);
			return FALSE;
		}
	} else {
		oidc_debug(r,
				"provider (%s) JSON metadata did not contain a \"response_modes_supported\" array; assuming that \"fragment\" and \"query\" are supported",
				issuer);
	}

	/* get a handle to the authorization endpoint */
	json_t *j_authorization_endpoint = json_object_get(j_provider,
			"authorization_endpoint");
	if ((j_authorization_endpoint == NULL)
			|| (!json_is_string(j_authorization_endpoint))) {
		oidc_error(r,
				"provider (%s) JSON metadata did not contain an \"authorization_endpoint\" string",
				issuer);
		return FALSE;
	}

	/* get a handle to the token endpoint */
	json_t *j_token_endpoint = json_object_get(j_provider, "token_endpoint");
	if ((j_token_endpoint == NULL) || (!json_is_string(j_token_endpoint))) {
		oidc_warn(r,
				"provider (%s) JSON metadata did not contain a \"token_endpoint\" string",
				issuer);
		//return FALSE;
	}

	/* get a handle to the user_info endpoint */
	json_t *j_userinfo_endpoint = json_object_get(j_provider,
			"userinfo_endpoint");
	if ((j_userinfo_endpoint != NULL)
			&& (!json_is_string(j_userinfo_endpoint))) {
		oidc_debug(r,
				"provider (%s) JSON metadata contains a \"userinfo_endpoint\" entry, but it is not a string value",
				issuer);
	}
	// TODO: check for valid URL

	/* get a handle to the jwks_uri */
	json_t *j_jwks_uri = json_object_get(j_provider, "jwks_uri");
	if ((j_jwks_uri == NULL) || (!json_is_string(j_jwks_uri))) {
		oidc_warn(r,
				"provider (%s) JSON metadata did not contain a \"jwks_uri\" string",
				issuer);
		//return FALSE;
	}

	/* find out what type of authentication the token endpoint supports (we only support post or basic) */
	json_t *j_token_endpoint_auth_methods_supported = json_object_get(
			j_provider, "token_endpoint_auth_methods_supported");
	if ((j_token_endpoint_auth_methods_supported == NULL)
			|| (!json_is_array(j_token_endpoint_auth_methods_supported))) {
		oidc_debug(r,
				"provider (%s) JSON metadata did not contain a \"token_endpoint_auth_methods_supported\" array, assuming \"client_secret_basic\" is supported",
				issuer);
	} else {
		int i;
		for (i = 0;
				i < json_array_size(j_token_endpoint_auth_methods_supported);
				i++) {
			json_t *elem = json_array_get(
					j_token_endpoint_auth_methods_supported, i);
			if (!json_is_string(elem)) {
				oidc_warn(r,
						"unhandled in-array JSON object type [%d] in provider (%s) metadata for entry \"token_endpoint_auth_methods_supported\"",
						elem->type, issuer);
				continue;
			}
			if (strcmp(json_string_value(elem), "client_secret_post") == 0) {
				break;
			}
			if (strcmp(json_string_value(elem), "client_secret_basic") == 0) {
				break;
			}
		}
		if (i == json_array_size(j_token_endpoint_auth_methods_supported)) {
			oidc_error(r,
					"could not find a supported value [client_secret_post|client_secret_basic] in provider (%s) metadata for entry \"token_endpoint_auth_methods_supported\"",
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
		json_t *j_client, const char *issuer) {

	/* get a handle to the client_id we need to use for this provider */
	json_t *j_client_id = json_object_get(j_client, "client_id");
	if ((j_client_id == NULL) || (!json_is_string(j_client_id))) {
		oidc_error(r,
				"client (%s) JSON metadata did not contain a \"client_id\" string",
				issuer);
		return FALSE;
	}

	/* get a handle to the client_secret we need to use for this provider */
	json_t *j_client_secret = json_object_get(j_client, "client_secret");
	if ((j_client_secret == NULL) || (!json_is_string(j_client_secret))) {
		oidc_warn(r,
				"client (%s) JSON metadata did not contain a \"client_secret\" string",
				issuer);
		//return FALSE;
	}

	/* the expiry timestamp from the JSON object */
	json_t *expires_at = json_object_get(j_client, "client_secret_expires_at");
	if ((expires_at == NULL) || (!json_is_integer(expires_at))) {
		oidc_debug(r,
				"client (%s) metadata did not contain a \"client_secret_expires_at\" setting",
				issuer);
		/* assume that it never expires */
		return TRUE;
	}

	/* see if it is unrestricted */
	if (json_integer_value(expires_at) == 0) {
		oidc_debug(r,
				"client (%s) metadata never expires (client_secret_expires_at=0)",
				issuer);
		return TRUE;
	}

	/* check if the value >= now */
	if (apr_time_sec(apr_time_now()) > json_integer_value(expires_at)) {
		oidc_warn(r, "client (%s) secret expired", issuer);
		return FALSE;
	}

	oidc_debug(r, "client (%s) metadata is valid", issuer);

	return TRUE;
}

/*
 * checks if a parsed JWKs file is a valid one, cq. contains "keys"
 */
static apr_byte_t oidc_metadata_jwks_is_valid(request_rec *r, json_t *j_jwks,
		const char *issuer) {

	json_t *keys = json_object_get(j_jwks, "keys");
	if ((keys == NULL) || (!json_is_array(keys))) {
		oidc_error(r,
				"provider (%s) JWKS JSON metadata did not contain a \"keys\" array",
				issuer);
		return FALSE;
	}
	return TRUE;
}

static apr_byte_t oidc_metadata_conf_jose_is_supported(request_rec *r,
		json_t *j_conf, const char *issuer, const char *key,
		apr_jose_is_supported_function_t jose_is_supported_function) {
	json_t *value = json_object_get(j_conf, key);
	if (value != NULL) {
		if (!json_is_string(value)) {
			oidc_error(r,
					"(%s) JSON conf data has \"%s\" entry but it is not a string",
					issuer, key);
			return FALSE;
		}
		if (jose_is_supported_function(r->pool,
				json_string_value(value)) == FALSE) {
			oidc_error(r,
					"(%s) JSON conf data has \"%s\" entry but it contains an unsupported algorithm or encryption type: \"%s\"",
					issuer, key, json_string_value(value));
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * check to see if JSON configuration data is valid
 */
static apr_byte_t oidc_metadata_conf_is_valid(request_rec *r, json_t *j_conf,
		const char *issuer) {

	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			"id_token_signed_response_alg",
			apr_jws_algorithm_is_supported) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			"id_token_encrypted_response_alg",
			apr_jwe_algorithm_is_supported) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			"id_token_encrypted_response_enc",
			apr_jwe_encryption_is_supported) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			"userinfo_signed_response_alg",
			apr_jws_algorithm_is_supported) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			"userinfo_encrypted_response_alg",
			apr_jwe_algorithm_is_supported) == FALSE)
		return FALSE;
	if (oidc_metadata_conf_jose_is_supported(r, j_conf, issuer,
			"userinfo_encrypted_response_enc",
			apr_jwe_encryption_is_supported) == FALSE)
		return FALSE;

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
		oidc_error(r, "file \"%s\" could not be opened (%s)", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
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
		oidc_error(r, "could not write to: \"%s\" (%s)", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* check that all bytes from the header were written */
	if (bytes_written != len) {
		oidc_error(r,
				"could not write enough bytes to: \"%s\", bytes_written (%" APR_SIZE_T_FMT ") != len (%" APR_SIZE_T_FMT ")",
				path, bytes_written, len);
		return FALSE;
	}

	/* unlock and close the written file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	oidc_debug(r, "file \"%s\" written; number of bytes (%" APR_SIZE_T_FMT ")",
			path, len);

	return TRUE;
}

/* callback function type for checking metadata validity (provider or client) */
typedef apr_byte_t (*oidc_is_valid_function_t)(request_rec *, json_t *,
		const char *);

/*
 * helper function to get the JSON (client or provider) metadata from the specified file path and check its validity
 */
static apr_byte_t oidc_metadata_get_and_check(request_rec *r, const char *path,
		const char *issuer, oidc_is_valid_function_t metadata_is_valid,
		json_t **j_metadata, apr_byte_t remove_when_invalid) {

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
	if ((remove_when_invalid == TRUE)
			&& (apr_stat(&fi, path, APR_FINFO_MTIME, r->pool) == APR_SUCCESS)) {

		if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
			oidc_error(r, "could not delete invalid metadata file %s (%s)",
					path, apr_strerror(rc, s_err, sizeof(s_err)));
		} else {
			oidc_error(r, "removed invalid metadata file %s", path);
		}
	}

	return FALSE;
}

/*
 * helper function to retrieve provider metadata from a URL, check it and store it
 */
static apr_byte_t oidc_metadata_provider_retrieve_and_store(request_rec *r,
		oidc_cfg *cfg, const char *url, const char *issuer, const char *path,
		json_t **j_metadata) {
	const char *response = NULL;

	/* no valid provider metadata, get it at the specified URL with the specified parameters */
	if (oidc_util_http_get(r, url, NULL, NULL, NULL,
			cfg->provider.ssl_validate_server, &response,
			cfg->http_timeout_short, cfg->outgoing_proxy) == FALSE)
		return FALSE;

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, response, j_metadata) == FALSE)
		return FALSE;

	/* check to see if it is valid metadata */
	if (oidc_metadata_provider_is_valid(r, *j_metadata, issuer) == FALSE)
		return FALSE;

	/* since it is valid, write the obtained provider metadata file */
	if (oidc_metadata_file_write(r, path, response) == FALSE)
		return FALSE;

	/* all OK */
	return TRUE;
}

/*
 * helper function to retrieve client metadata from a dynamic registration URL, check it and store it
 */
static apr_byte_t oidc_metadata_client_retrieve_and_store(request_rec *r,
		oidc_cfg *cfg, const char *url, json_t *data, const char *issuer,
		const char *path, json_t **j_metadata, int ssl_validate_server,
		const char *bearer_token) {
	const char *response = NULL;
	apr_byte_t rc = FALSE;

	/*
	if (strstr(url,
			"idp/client-registration.openid") != NULL) {

		apr_table_t *params = apr_table_make(r->pool, 3);
		json_t *v = json_object_get(data, "client_name");
		apr_table_addn(params, "client_name", json_string_value(v));
		apr_table_addn(params, "operation", "client_register");
		apr_table_addn(params, "redirect_uris", cfg->redirect_uri);
		rc = oidc_util_http_get(r, url, params, NULL, bearer_token,
				ssl_validate_server, &response, cfg->http_timeout_short,
				cfg->outgoing_proxy);

	} else {
	*/

	/* no valid provider metadata, get it at the specified URL with the specified parameters */
	rc = oidc_util_http_post_json(r, url, data, NULL, bearer_token,
			ssl_validate_server, &response, cfg->http_timeout_short,
			cfg->outgoing_proxy);

	json_decref(data);
	if (rc == FALSE)
		return FALSE;

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, response, j_metadata) == FALSE)
		return FALSE;

	/* check to see if it is valid metadata */
	if (oidc_metadata_client_is_valid(r, *j_metadata, issuer) == FALSE)
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
		oidc_cfg *cfg, oidc_provider_t *provider, json_t **j_jwks) {

	const char *response = NULL;

	/* no valid provider metadata, get it at the specified URL with the specified parameters */
	if (oidc_util_http_get(r, provider->jwks_uri, NULL, NULL,
			NULL, provider->ssl_validate_server, &response, cfg->http_timeout_long,
			cfg->outgoing_proxy) == FALSE)
		return FALSE;

	/* decode and see if it is not an error response somehow */
	if (oidc_util_decode_json_and_check_error(r, response, j_jwks) == FALSE)
		return FALSE;

	/* check to see if it is valid metadata */
	if (oidc_metadata_jwks_is_valid(r, *j_jwks, provider->issuer) == FALSE)
		return FALSE;

	/* store the JWKs in the cache */
	cfg->cache->set(r, OIDC_CACHE_SECTION_JWKS,
			oidc_metadata_jwks_cache_key(r, provider->issuer), response,
			apr_time_now() + apr_time_from_sec(provider->jwks_refresh_interval));

	return TRUE;
}

/*
 * return JWKs for the specified issuer
 */
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, json_t **j_jwks, apr_byte_t *refresh) {

	oidc_debug(r, "enter, issuer=%s, refresh=%d", provider->issuer, *refresh);

	/* see if we need to do a forced refresh */
	if (*refresh == TRUE) {
		oidc_debug(r, "doing a forced refresh of the JWKs for issuer \"%s\"",
				provider->issuer);
		if (oidc_metadata_jwks_retrieve_and_store(r, cfg, provider,
				j_jwks) == TRUE)
			return TRUE;
		// else: fallback on any cached JWKs
	}

	/* see if the JWKs is cached */
	const char *value = NULL;
	cfg->cache->get(r, OIDC_CACHE_SECTION_JWKS,
			oidc_metadata_jwks_cache_key(r, provider->issuer), &value);

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
		const char *issuer, json_t **j_provider) {

	/* get the full file path to the provider metadata for this issuer */
	const char *provider_path = oidc_metadata_provider_file_path(r, issuer);

	/* see if we have valid metadata already, if so, return it */
	if (oidc_metadata_get_and_check(r, provider_path, issuer,
			oidc_metadata_provider_is_valid, j_provider, FALSE) == TRUE)
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
	return oidc_metadata_provider_retrieve_and_store(r, cfg, url, issuer,
			provider_path, j_provider);
}

/*
 * see if we have config metadata
 */
static apr_byte_t oidc_metadata_conf_get(request_rec *r, oidc_cfg *cfg,
		const char *issuer, json_t **j_conf) {

	/* get the full file path to the conf metadata for this issuer */
	const char *conf_path = oidc_metadata_conf_path(r, issuer);

	/* the .conf file is optional */
	apr_finfo_t fi;
	if (apr_stat(&fi, conf_path, APR_FINFO_MTIME, r->pool) != APR_SUCCESS)
		return TRUE;

	/* if it exists, parse and validate the conf metadata */
	return oidc_metadata_get_and_check(r, conf_path, issuer,
			oidc_metadata_conf_is_valid, j_conf, FALSE);
}

/*
 * see if we have client metadata and check its validity
 * if not, use OpenID Connect Client Registration to get it, check it and store it
 */
static apr_byte_t oidc_metadata_client_get(request_rec *r, oidc_cfg *cfg,
		const char *issuer, oidc_provider_t *provider, json_t **j_client) {

	/* get the full file path to the provider metadata for this issuer */
	const char *client_path = oidc_metadata_client_file_path(r, issuer);

	/* see if we already have valid client metadata, if so, return TRUE */
	if (oidc_metadata_get_and_check(r, client_path, issuer,
			oidc_metadata_client_is_valid, j_client, TRUE) == TRUE)
		return TRUE;

	/* at this point we have no valid client metadata, see if there's a registration endpoint for this provider */
	if (provider->registration_endpoint_url == NULL) {
		oidc_error(r,
				"no (valid) client metadata exists for provider (%s) and provider JSON object did not contain a (valid) \"registration_endpoint\" string",
				issuer);
		return FALSE;
	}

	/* go and use Dynamic Client registration to fetch ourselves new client metadata */
	json_t *data = json_object();
	json_object_set_new(data, "client_name",
			json_string(provider->client_name));
	json_object_set_new(data, "redirect_uris",
			json_pack("[s]", cfg->redirect_uri));

	json_t *response_types = json_array();
	apr_array_header_t *flows = oidc_proto_supported_flows(r->pool);
	int i;
	for (i = 0; i < flows->nelts; i++) {
		json_array_append_new(response_types,
				json_string(((const char**) flows->elts)[i]));
	}
	json_object_set_new(data, "response_types", response_types);

	if (provider->client_contact != NULL) {
		json_object_set_new(data, "contacts",
				json_pack("[s]", provider->client_contact));
	}

	if (provider->client_jwks_uri) {
		json_object_set_new(data, "jwks_uri",
				json_string(provider->client_jwks_uri));
	} else if (cfg->public_keys != NULL) {
		json_object_set_new(data, "jwks_uri",
				json_string(
						apr_psprintf(r->pool, "%s?jwks=rsa",
								cfg->redirect_uri)));
	}

	if (provider->id_token_signed_response_alg != NULL) {
		json_object_set_new(data, "id_token_signed_response_alg",
				json_string(provider->id_token_signed_response_alg));
	}
	if (provider->id_token_encrypted_response_alg != NULL) {
		json_object_set_new(data, "id_token_encrypted_response_alg",
				json_string(provider->id_token_encrypted_response_alg));
	}
	if (provider->id_token_encrypted_response_enc != NULL) {
		json_object_set_new(data, "id_token_encrypted_response_enc",
				json_string(provider->id_token_encrypted_response_enc));
	}

	if (provider->userinfo_signed_response_alg != NULL) {
		json_object_set_new(data, "userinfo_signed_response_alg",
				json_string(provider->userinfo_signed_response_alg));
	}
	if (provider->userinfo_encrypted_response_alg != NULL) {
		json_object_set_new(data, "userinfo_encrypted_response_alg",
				json_string(provider->userinfo_encrypted_response_alg));
	}
	if (provider->userinfo_encrypted_response_enc != NULL) {
		json_object_set_new(data, "userinfo_encrypted_response_enc",
				json_string(provider->userinfo_encrypted_response_enc));
	}

	json_object_set_new(data, "initiate_login_uri",
			json_string(cfg->redirect_uri));

	/* try and get it from there, checking it and storing it if successful */
	return oidc_metadata_client_retrieve_and_store(r, cfg,
			provider->registration_endpoint_url, data, issuer, client_path,
			j_client, provider->ssl_validate_server,
			provider->registration_token);
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

	oidc_debug(r, "enter");

	/* open the metadata directory */
	if ((rc = apr_dir_open(&dir, cfg->metadata_dir, r->pool)) != APR_SUCCESS) {
		oidc_error(r, "error opening metadata directory '%s' (%s)",
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

		/* get the provider and client metadata, do all checks and registration if possible */
		oidc_provider_t *provider = NULL;
		if (oidc_metadata_get(r, cfg, issuer, &provider) == TRUE) {
			/* push the decoded issuer filename in to the array */
			*(const char**) apr_array_push(*list) = provider->issuer;
		}
	}

	/* we're done, cleanup now */
	apr_dir_close(dir);

	return TRUE;
}

/*
 * find out what type of authentication we must provide to the token endpoint (we only support post or basic)
 */
static const char * oidc_metadata_token_endpoint_auth(request_rec *r,
		json_t *j_client, json_t *j_provider) {

	const char *result = "client_secret_basic";

	/* see if one is defined in the client metadata */
	json_t *token_endpoint_auth_method = json_object_get(j_client,
			"token_endpoint_auth_method");
	if (token_endpoint_auth_method != NULL) {
		if (json_is_string(token_endpoint_auth_method)) {
			if (strcmp(json_string_value(token_endpoint_auth_method),
					"client_secret_post") == 0) {
				result = "client_secret_post";
				return result;
			}
			if (strcmp(json_string_value(token_endpoint_auth_method),
					"client_secret_basic") == 0) {
				result = "client_secret_basic";
				return result;
			}
			oidc_warn(r,
					"unsupported client auth method \"%s\" in client metadata for entry \"token_endpoint_auth_method\"",
					json_string_value(token_endpoint_auth_method));
		} else {
			oidc_warn(r,
					"unexpected JSON object type [%d] (!= APR_JSON_STRING) in client metadata for entry \"token_endpoint_auth_method\"",
					token_endpoint_auth_method->type);
		}
	}

	/* no supported value in the client metadata, find a supported one in the provider metadata */
	json_t *j_token_endpoint_auth_methods_supported = json_object_get(
			j_provider, "token_endpoint_auth_methods_supported");

	if ((j_token_endpoint_auth_methods_supported != NULL)
			&& (json_is_array(j_token_endpoint_auth_methods_supported))) {
		int i;
		for (i = 0;
				i < json_array_size(j_token_endpoint_auth_methods_supported);
				i++) {
			json_t *elem = json_array_get(
					j_token_endpoint_auth_methods_supported, i);
			if (!json_is_string(elem)) {
				oidc_error(r,
						"unhandled in-array JSON object type [%d] in provider metadata for entry \"token_endpoint_auth_methods_supported\"",
						elem->type);
				continue;
			}
			if (strcmp(json_string_value(elem), "client_secret_post") == 0) {
				result = "client_secret_post";
				break;
			}
			if (strcmp(json_string_value(elem), "client_secret_basic") == 0) {
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
	json_t *j_provider = NULL;
	/* pointer to the parsed JSON metadata for the client */
	json_t *j_client = NULL;
	/* pointer to the parsed conf metadata for the client */
	json_t *j_conf = NULL;

	/* allocate space for a parsed-and-merged metadata struct */
	*result = apr_pcalloc(r->pool, sizeof(oidc_provider_t));
	/* convenient helper pointer */
	oidc_provider_t *provider = *result;

	/* see if we can get valid provider metadata (possibly bootstrapping with Discovery), if not, return FALSE */
	if (oidc_metadata_provider_get(r, cfg, issuer, &j_provider) == FALSE) {
		if (j_provider)
			json_decref(j_provider);
		return FALSE;
	}

	/* get the "issuer" from the provider metadata */
	oidc_json_object_get_string(r->pool, j_provider, "issuer",
			&provider->issuer, NULL);

	/* get a handle to the authorization endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "authorization_endpoint",
			&provider->authorization_endpoint_url, NULL);

	/* get a handle to the token endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "token_endpoint",
			&provider->token_endpoint_url, NULL);

	/* get a handle to the user_info endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "userinfo_endpoint",
			&provider->userinfo_endpoint_url, NULL);

	/* get a handle to the jwks_uri endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "jwks_uri",
			&provider->jwks_uri, NULL);

	/* get a handle to the client registration endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "registration_endpoint",
			&provider->registration_endpoint_url, NULL);

	/* get a handle to the check session iframe */
	oidc_json_object_get_string(r->pool, j_provider, "check_session_iframe",
			&provider->check_session_iframe, NULL);

	/* get a handle to the end session endpoint */
	oidc_json_object_get_string(r->pool, j_provider, "end_session_endpoint",
			&provider->end_session_endpoint, NULL);

	/* see if we can get valid config metadata */
	if (oidc_metadata_conf_get(r, cfg, issuer, &j_conf) == FALSE) {
		if (j_provider)
			json_decref(j_provider);
		if (j_conf)
			json_decref(j_conf);
		return FALSE;
	}

	oidc_json_object_get_string(r->pool, j_conf, "client_jwks_uri",
			&provider->client_jwks_uri, cfg->provider.client_jwks_uri);

	oidc_json_object_get_string(r->pool, j_conf, "id_token_signed_response_alg",
			&provider->id_token_signed_response_alg,
			cfg->provider.id_token_signed_response_alg);
	oidc_json_object_get_string(r->pool, j_conf,
			"id_token_encrypted_response_alg",
			&provider->id_token_encrypted_response_alg,
			cfg->provider.id_token_encrypted_response_alg);
	oidc_json_object_get_string(r->pool, j_conf,
			"id_token_encrypted_response_enc",
			&provider->id_token_encrypted_response_enc,
			cfg->provider.id_token_encrypted_response_enc);

	/* get the (optional) signing & encryption settings for the userinfo response */
	oidc_json_object_get_string(r->pool, j_conf, "userinfo_signed_response_alg",
			&provider->userinfo_signed_response_alg,
			cfg->provider.userinfo_signed_response_alg);
	oidc_json_object_get_string(r->pool, j_conf,
			"userinfo_encrypted_response_alg",
			&provider->userinfo_encrypted_response_alg,
			cfg->provider.userinfo_encrypted_response_alg);
	oidc_json_object_get_string(r->pool, j_conf,
			"userinfo_encrypted_response_enc",
			&provider->userinfo_encrypted_response_enc,
			cfg->provider.userinfo_encrypted_response_enc);

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

	/* see if we've got custom authentication request parameter values */
	oidc_json_object_get_string(r->pool, j_conf, "auth_request_params",
			&provider->auth_request_params, cfg->provider.auth_request_params);

	/* see if we've got custom token endpoint parameter values */
	oidc_json_object_get_string(r->pool, j_conf, "token_endpoint_params",
			&provider->token_endpoint_params,
			cfg->provider.token_endpoint_params);

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
	oidc_json_object_get_string(r->pool, j_conf, "response_type",
			&provider->response_type, NULL);

	if (oidc_metadata_client_get(r, cfg, issuer, provider, &j_client) == FALSE) {
		if (j_provider)
			json_decref(j_provider);
		if (j_conf)
			json_decref(j_conf);
		if (j_client)
			json_decref(j_client);
		return FALSE;
	}

	/* get a handle to the client_id we need to use for this provider */
	oidc_json_object_get_string(r->pool, j_client, "client_id",
			&provider->client_id, NULL);

	/* get a handle to the client_secret we need to use for this provider */
	oidc_json_object_get_string(r->pool, j_client, "client_secret",
			&provider->client_secret, NULL);

	/* get the authentication method for the token endpoint */
	provider->token_endpoint_auth = apr_pstrdup(r->pool,
			oidc_metadata_token_endpoint_auth(r, j_client, j_provider));

	/* determine the response type if not set by .conf */
	if (provider->response_type == NULL) {

		provider->response_type = cfg->provider.response_type;

		/* "response_types" is an array in the client metadata as by spec */
		json_t *j_response_types = json_object_get(j_client, "response_types");
		if ((j_response_types != NULL) && (json_is_array(j_response_types))) {
			/* if there's an array we'll prefer the configured response_type if supported */
			if (oidc_util_json_array_has_value(r, j_response_types,
					provider->response_type) == FALSE) {
				/* if the configured response_type is not supported, we'll fallback to the first one that is listed */
				json_t *j_response_type = json_array_get(j_response_types, 0);
				if (json_is_string(j_response_type)) {
					provider->response_type = apr_pstrdup(r->pool,
							json_string_value(j_response_type));
				}
			}
		}
	}

	if (j_provider)
		json_decref(j_provider);
	if (j_conf)
		json_decref(j_conf);
	if (j_client)
		json_decref(j_client);

	return TRUE;
}

