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
apr_byte_t oidc_oauth_metadata_provider_parse(request_rec *r, oidc_cfg_t *c, const oidc_json_t *j_provider) {

	char *issuer = NULL;
	char *value = NULL;
	const char *rv = NULL;

	/* get the "issuer" from the provider metadata */
	oidc_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER, &issuer, NULL);

	/* get a handle to the introspection endpoint */
	oidc_json_object_get_string(r->pool, j_provider, OIDC_METADATA_INTROSPECTION_ENDPOINT, &value, NULL);
	if (value != NULL) {
		rv = oidc_cfg_oauth_introspection_endpoint_url_set(r->pool, c, value);
		if (rv != NULL)
			oidc_error(r, "oidc_oauth_introspection_endpoint_url_set error: %s", rv);
	}

	/* get a handle to the jwks_uri endpoint */
	oidc_json_object_get_string(r->pool, j_provider, OIDC_METADATA_JWKS_URI, &value, NULL);
	if (value != NULL) {
		rv = oidc_cfg_oauth_verify_jwks_uri_set(r->pool, c, value);
		if (rv != NULL)
			oidc_error(r, "oidc_oauth_verify_jwks_uri_set error: %s", rv);
	}

	/* the secret/certificate interplay that decides on RFC 8705 mutual-TLS is documented at
	 * oidc_metadata_endpoint_auth_select */
	if (oidc_metadata_endpoint_auth_select(
		r, c, j_provider, OIDC_METADATA_INTROSPECTON_ENDPOINT_AUTH_METHODS_SUPPORTED,
		oidc_cfg_oauth_client_secret_get(c) != NULL,
		oidc_cfg_oauth_introspection_endpoint_tls_client_cert_get(c) != NULL, &value) != NULL) {
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

	/* RFC 8705 section 5: when using mutual-TLS, prefer the "mtls_endpoint_aliases" introspection endpoint */
	if (oidc_cfg_endpoint_auth_is_mtls(oidc_cfg_oauth_introspection_endpoint_auth_get(c))) {
		value = NULL;
		const oidc_json_t *j_aliases = oidc_metadata_mtls_endpoint_aliases_get(j_provider);
		if (j_aliases != NULL)
			oidc_json_object_get_string(r->pool, j_aliases, OIDC_METADATA_INTROSPECTION_ENDPOINT, &value,
						    NULL);
		if (value != NULL) {
			rv = oidc_cfg_oauth_introspection_endpoint_url_set(r->pool, c, value);
			if (rv != NULL)
				oidc_error(r, "oidc_oauth_introspection_endpoint_url_set error: %s", rv);
		}
	}

	return TRUE;
}
