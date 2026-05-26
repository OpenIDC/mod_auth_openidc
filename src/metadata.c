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
 * Thin orchestrator over the metadata subsystem. The per-domain helpers live
 * under src/metadata/ (provider.c, conf.c, client.c, oauth.c, jwks.c, util.c).
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "metadata/internal.h"

#include "mod_auth_openidc.h"

#include <apr_file_io.h>

/*
 * get the metadata for a specified issuer
 *
 * fills the oidc_provider_t struct by reading and merging the provider, conf
 * and client metadata files for the issuer
 */
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg_t *cfg, const char *issuer, oidc_provider_t **provider,
			     apr_byte_t allow_discovery) {

	apr_byte_t rc = FALSE;

	/* pointers to the parsed JSON metadata */
	json_t *j_provider = NULL;
	json_t *j_client = NULL;
	json_t *j_conf = NULL;

	/* allocate space for a parsed-and-merged metadata struct */
	*provider = oidc_cfg_provider_create(r->pool);

	/*
	 * read and parse the provider, conf and client metadata respectively
	 * NB: order is important here
	 */

	if (oidc_metadata_provider_get(r, cfg, issuer, &j_provider, allow_discovery) == FALSE)
		goto end;
	if (oidc_metadata_provider_parse(r, cfg, j_provider, *provider) == FALSE)
		goto end;

	if (oidc_metadata_conf_get(r, issuer, &j_conf) == FALSE)
		goto end;
	if (oidc_metadata_conf_parse(r, cfg, j_conf, *provider) == FALSE)
		goto end;

	if (oidc_metadata_client_get(r, cfg, issuer, *provider, &j_client) == FALSE)
		goto end;
	if (oidc_metadata_client_parse(r, cfg, j_client, *provider) == FALSE)
		goto end;

	rc = TRUE;

end:

	if (j_provider)
		json_decref(j_provider);
	if (j_conf)
		json_decref(j_conf);
	if (j_client)
		json_decref(j_client);

	return rc;
}

/*
 * get a list of configured OIDC providers based on the entries in the provider metadata directory
 */
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg_t *cfg, apr_array_header_t **list) {
	apr_status_t rc;
	apr_dir_t *dir;
	apr_finfo_t fi;
	char s_err[128];

	oidc_debug(r, "enter");

	/* open the metadata directory */
	if ((rc = apr_dir_open(&dir, oidc_cfg_metadata_dir_get(cfg), r->pool)) != APR_SUCCESS) {
		oidc_error(r, "error opening metadata directory '%s' (%s)", oidc_cfg_metadata_dir_get(cfg),
			   apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* allocate some space in the array that will hold the list of providers */
	*list = apr_array_make(r->pool, 5, sizeof(const char *));
	/* BTW: we could estimate the number in the array based on # directory entries... */

	/* loop over the entries in the provider metadata directory */
	while (apr_dir_read(&fi, APR_FINFO_NAME, dir) == APR_SUCCESS) {

		/* skip "." and ".." entries */
		if (fi.name[0] == OIDC_CHAR_DOT)
			continue;
		/* skip other non-provider entries */
		const char *ext = strrchr(fi.name, OIDC_CHAR_DOT);
		if (ext == NULL)
			continue;
		ext++;
		if (_oidc_strcmp(ext, OIDC_METADATA_SUFFIX_PROVIDER) != 0)
			continue;

		/* get the issuer from the filename */
		const char *issuer = oidc_metadata_filename_to_issuer(r, fi.name);

		/* get the provider and client metadata, do all checks and registration if possible */
		oidc_provider_t *provider = NULL;
		if (oidc_metadata_get(r, cfg, issuer, &provider, FALSE) == TRUE) {
			/* push the decoded issuer filename in to the array */
			APR_ARRAY_PUSH(*list, const char *) = oidc_cfg_provider_issuer_get(provider);
		}
	}

	/* we're done, cleanup now */
	apr_dir_close(dir);

	return TRUE;
}
