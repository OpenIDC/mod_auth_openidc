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
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * Shared helpers for the metadata subsystem: validators, path/filename
 * conversion, and file I/O.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "metadata/internal.h"

#include "cfg/parse.h"
#include "jose.h"
#include "mod_auth_openidc.h"
#include "util/util.h"

#include <apr_strings.h>

/*
 * get the metadata filename for a specified issuer (cq. urlencode it)
 */
const char *oidc_metadata_issuer_to_filename(request_rec *r, const char *issuer) {

	/* strip leading https:// */
	char *p = _oidc_strstr(issuer, "https://");
	if (p == issuer) {
		p = apr_pstrdup(r->pool, issuer + _oidc_strlen("https://"));
	} else {
		p = _oidc_strstr(issuer, "http://");
		if (p == issuer) {
			p = apr_pstrdup(r->pool, issuer + _oidc_strlen("http://"));
		} else {
			p = apr_pstrdup(r->pool, issuer);
		}
	}

	/* strip trailing '/' */
	int n = (int)_oidc_strlen(p);
	if ((n > 0) && (p[n - 1] == OIDC_CHAR_FORWARD_SLASH))
		p[n - 1] = '\0';

	return oidc_http_url_encode(r, p);
}

/*
 * get the issuer from a metadata filename (cq. urldecode it)
 */
const char *oidc_metadata_filename_to_issuer(request_rec *r, const char *filename) {
	char *result = apr_pstrdup(r->pool, filename);
	char *p = strrchr(result, OIDC_CHAR_DOT);
	*p = '\0';
	p = oidc_http_url_decode(r, result);
	return apr_psprintf(r->pool, "https://%s", p);
}

/*
 * get the full path to the metadata file for a specified issuer and directory
 */
static const char *oidc_metadata_file_path(request_rec *r, const oidc_cfg_t *cfg, const char *issuer,
					   const char *type) {
	return apr_psprintf(r->pool, "%s/%s.%s", oidc_cfg_metadata_dir_get(cfg),
			    oidc_metadata_issuer_to_filename(r, issuer), type);
}

const char *oidc_metadata_provider_file_path(request_rec *r, const char *issuer) {
	const oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_PROVIDER);
}

const char *oidc_metadata_client_file_path(request_rec *r, const char *issuer) {
	const oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CLIENT);
}

const char *oidc_metadata_conf_path(request_rec *r, const char *issuer) {
	const oidc_cfg_t *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CONF);
}

/*
 * read a JSON metadata file from disk
 */
apr_byte_t oidc_metadata_file_read_json(request_rec *r, const char *path, oidc_json_t **result) {
	char *buf = NULL;
	if (oidc_util_file_read(r, path, r->pool, &buf) == FALSE)
		return FALSE;
	return oidc_json_decode_object(r, buf, result);
}

/*
 * check if the specified entry in metadata is a valid URI
 */
apr_byte_t oidc_metadata_is_valid_uri(request_rec *r, const char *type, const char *issuer, const oidc_json_t *json,
				      const char *key, char **value, apr_byte_t is_mandatory) {

	char *s_value = NULL;
	oidc_json_object_get_string(r->pool, json, key, &s_value, NULL);

	if (s_value == NULL) {
		if (is_mandatory) {
			oidc_error(r, "%s (%s) JSON metadata does not contain the mandatory \"%s\" string entry", type,
				   issuer, key);
		}
		return (!is_mandatory);
	}

	if (oidc_cfg_parse_is_valid_http_url(r->pool, s_value) != NULL) {
		oidc_warn(r, "\"%s\" is not a valid http URL for key \"%s\"", s_value, key);
		return FALSE;
	}

	if (value)
		*value = s_value;

	return TRUE;
}

/*
 * try a single array entry against the validator and the preference;
 * returns TRUE when the entry matches the preference and the caller should stop iterating
 */
static apr_byte_t oidc_metadata_array_string_apply(apr_pool_t *pool, const oidc_json_t *elem,
						   oidc_valid_function_t valid_function, char **value,
						   const char *preference, apr_byte_t *found) {
	if (!oidc_json_is_string(elem))
		return FALSE;
	if (valid_function(pool, oidc_json_string_value(elem)) != NULL)
		return FALSE;

	*found = TRUE;

	if (value == NULL)
		return FALSE;

	if ((preference != NULL) && (_oidc_strcmp(oidc_json_string_value(elem), preference) == 0)) {
		*value = apr_pstrdup(pool, oidc_json_string_value(elem));
		return TRUE;
	}

	if (*value == NULL)
		*value = apr_pstrdup(pool, oidc_json_string_value(elem));

	return FALSE;
}

/*
 * check if there's a valid entry in a string of arrays, with a preference
 */
const char *oidc_metadata_valid_string_in_array(apr_pool_t *pool, const oidc_json_t *json, const char *key,
						oidc_valid_function_t valid_function, char **value, apr_byte_t optional,
						const char *preference) {
	if (value)
		*value = NULL;

	const oidc_json_t *json_arr = oidc_json_object_get(json, key);
	if ((json_arr == NULL) || !oidc_json_is_array(json_arr)) {
		if (optional == FALSE)
			return apr_psprintf(pool, "JSON object did not contain a \"%s\" array", key);
		return NULL;
	}

	apr_byte_t found = FALSE;
	for (int i = 0; i < oidc_json_array_size(json_arr); i++) {
		if (oidc_metadata_array_string_apply(pool, oidc_json_array_get(json_arr, i), valid_function, value,
						     preference, &found))
			break;
	}

	if (found == FALSE)
		return apr_psprintf(pool, "could not find a valid array string element for entry \"%s\"", key);

	return NULL;
}

/*
 * parse boolean value from JSON configuration
 */
void oidc_metadata_parse_boolean(request_rec *r, const oidc_json_t *json, const char *key, int *value,
				 int default_value) {
	int int_value = 0;
	char *s_value = NULL;
	if (oidc_json_object_get_bool(json, key, &int_value, default_value) == FALSE) {
		oidc_json_object_get_string(r->pool, json, key, &s_value, NULL);
		if (s_value != NULL) {
			const char *rv = oidc_cfg_parse_boolean(r->pool, s_value, &int_value);
			if (rv != NULL) {
				oidc_warn(r, "%s: %s", key, rv);
				int_value = default_value;
			}
		} else {
			oidc_json_object_get_int(json, key, &int_value, default_value);
		}
	}
	*value = (int_value != 0) ? TRUE : FALSE;
}

/*
 * parse URL value from JSON configuration
 */
void oidc_metadata_parse_url(request_rec *r, const char *type, const char *issuer, const oidc_json_t *json,
			     const char *key, char **value, const char *default_value) {
	*value = NULL;
	if ((oidc_metadata_is_valid_uri(r, type, issuer, json, key, value, FALSE) == FALSE) ||
	    ((*value == NULL) && (default_value != NULL))) {
		*value = apr_pstrdup(r->pool, default_value);
	}
}

/*
 * parse a set of JWKs from a JSON metadata object
 */
void oidc_metadata_get_jwks(request_rec *r, const oidc_json_t *json, apr_array_header_t **jwk_list) {
	const oidc_json_t *keys = NULL;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	const oidc_json_t *elem = NULL;

	keys = oidc_json_object_get(json, OIDC_JOSE_JWKS_KEYS_STR);
	if (keys == NULL)
		return;

	if (!oidc_json_is_array(keys)) {
		oidc_error(r, "trying to parse a list of JWKs but the value for key \"%s\" is not a JSON array",
			   OIDC_JOSE_JWKS_KEYS_STR);
		return;
	}

	for (int i = 0; i < oidc_json_array_size(keys); i++) {

		elem = oidc_json_array_get(keys, i);

		if (oidc_jwk_parse_json(r->pool, elem, &jwk, &err) == FALSE) {
			oidc_warn(r, "oidc_jwk_parse_json failed: %s", oidc_jose_e2s(r->pool, err));
			continue;
		}

		if (*jwk_list == NULL)
			*jwk_list = apr_array_make(r->pool, 4, sizeof(const oidc_jwk_t *));
		APR_ARRAY_PUSH(*jwk_list, const oidc_jwk_t *) = jwk;
	}
}
