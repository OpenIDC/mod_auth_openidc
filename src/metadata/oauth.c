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
 * OAuth 2.0 authorization-server metadata parsing.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "metadata/internal.h"

#include "cfg/oauth.h"
#include "mod_auth_openidc.h"
#include "util/util.h"

/*
 * parse the JSON OAuth 2.0 provider metadata in to the cfg->oauth struct
 */
apr_byte_t oidc_oauth_metadata_provider_parse(request_rec *r, oidc_cfg_t *c, const json_t *j_provider) {

	char *issuer = NULL;
	char *value = NULL;
	const char *rv = NULL;

	/* get the "issuer" from the provider metadata */
	oidc_util_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER, &issuer, NULL);

	// TOOD: should check for "if c->oauth.introspection_endpoint_url == NULL and
	//       allocate the string from the process/config pool
	//
	// https://github.com/OpenIDC/mod_auth_openidc/commit/32321024ed5bdbc02ba8b5d61aabc4a4c3745c89
	// https://groups.google.com/forum/#!topic/mod_auth_openidc/o1K_1Yh-TQA

	/* get a handle to the introspection endpoint */
	oidc_util_json_object_get_string(r->pool, j_provider, OIDC_METADATA_INTROSPECTION_ENDPOINT, &value, NULL);
	if (value != NULL) {
		rv = oidc_cfg_oauth_introspection_endpoint_url_set(r->pool, c, value);
		if (rv != NULL)
			oidc_error(r, "oidc_oauth_introspection_endpoint_url_set error: %s", rv);
	}

	/* get a handle to the jwks_uri endpoint */
	oidc_util_json_object_get_string(r->pool, j_provider, OIDC_METADATA_JWKS_URI, &value, NULL);
	if (value != NULL) {
		rv = oidc_cfg_oauth_verify_jwks_uri_set(r->pool, c, value);
		if (rv != NULL)
			oidc_error(r, "oidc_oauth_verify_jwks_uri_set error: %s", rv);
	}

	if (oidc_metadata_valid_string_in_array(r->pool, j_provider,
						OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED,
						oidc_cfg_get_valid_endpoint_auth_function(c), &value, TRUE,
						OIDC_ENDPOINT_AUTH_CLIENT_SECRET_BASIC) != NULL) {
		oidc_error(r,
			   "could not find a supported token endpoint authentication method in provider metadata (%s) "
			   "for entry \"" OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED "\"",
			   issuer);
		return FALSE;
	} else {
		rv = oidc_cfg_oauth_introspection_endpoint_auth_set(r->pool, c, value);
		if (rv != NULL)
			oidc_error(r, "oidc_oauth_introspection_endpoint_auth_set error: %s", rv);
	}

	return TRUE;
}
