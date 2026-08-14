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
 * OIDC provider metadata: validation, parsing, retrieval, and disk cache.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#include "cfg/dir.h"
#include "metadata/internal.h"

#include "cfg/parse.h"
#include "http.h"
#include "metrics.h"
#include "proto/proto.h"
#include "util/util.h"

#include <apr_file_io.h>
#include <apr_strings.h>

/*
 * check to see if JSON provider metadata is valid
 */
apr_byte_t oidc_metadata_provider_is_valid(request_rec *r, const oidc_cfg_t *cfg, const oidc_json_t *j_provider,
					   const char *issuer) {

	/* get the "issuer" from the provider metadata and double-check that it matches what we looked for */
	char *s_issuer = NULL;
	oidc_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER, &s_issuer, NULL);
	if (s_issuer == NULL) {
		oidc_error(r, "provider (%s) JSON metadata did not contain an \"" OIDC_METADATA_ISSUER "\" string",
			   issuer);
		return FALSE;
	}

	/* check that the issuer matches */
	if ((issuer != NULL) && (oidc_util_issuer_match(issuer, s_issuer) == FALSE)) {
		oidc_error(r,
			   "requested issuer (%s) does not match the \"" OIDC_METADATA_ISSUER
			   "\" value in the provider metadata file: %s",
			   issuer, s_issuer);
		return FALSE;
	}

	/* verify that the provider supports the a flow that we implement */
	if (oidc_metadata_valid_string_in_array(r->pool, j_provider, OIDC_METADATA_RESPONSE_TYPES_SUPPORTED,
						oidc_cfg_parse_is_valid_response_type, NULL, FALSE, NULL) != NULL) {
		if (oidc_json_object_get(j_provider, OIDC_METADATA_RESPONSE_TYPES_SUPPORTED) != NULL) {
			oidc_error(r,
				   "could not find a supported response type in provider metadata (%s) for entry "
				   "\"" OIDC_METADATA_RESPONSE_TYPES_SUPPORTED "\"",
				   issuer);
			return FALSE;
		}
		oidc_warn(
		    r,
		    "could not find (required) supported response types  (\"" OIDC_METADATA_RESPONSE_TYPES_SUPPORTED
		    "\") in provider metadata (%s); assuming that \"code\" flow is supported...",
		    issuer);
	}

	/* verify that the provider supports a response_mode that we implement */
	if (oidc_metadata_valid_string_in_array(r->pool, j_provider, OIDC_METADATA_RESPONSE_MODES_SUPPORTED,
						oidc_cfg_parse_is_valid_response_mode, NULL, TRUE, NULL) != NULL) {
		oidc_error(r,
			   "could not find a supported response mode in provider metadata (%s) for entry "
			   "\"" OIDC_METADATA_RESPONSE_MODES_SUPPORTED "\"",
			   issuer);
		return FALSE;
	}

	/* check the required authorization endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider,
				       OIDC_METADATA_AUTHORIZATION_ENDPOINT, NULL, TRUE) == FALSE)
		return FALSE;

	/* check the optional token endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider,
				       OIDC_METADATA_TOKEN_ENDPOINT, NULL, FALSE) == FALSE)
		return FALSE;

	/* check the optional user info endpoint */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider,
				       OIDC_METADATA_USERINFO_ENDPOINT, NULL, FALSE) == FALSE)
		return FALSE;

	/* check the optional JWKs URI */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider, OIDC_METADATA_JWKS_URI,
				       NULL, FALSE) == FALSE)
		return FALSE;

	/* check the optional signed JWKs URI */
	if (oidc_metadata_is_valid_uri(r, OIDC_METADATA_SUFFIX_PROVIDER, issuer, j_provider,
				       OIDC_METADATA_SIGNED_JWKS_URI, NULL, FALSE) == FALSE)
		return FALSE;

	/* find out what type of authentication the token endpoint supports */
	if (oidc_metadata_valid_string_in_array(
		r->pool, j_provider, OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
		oidc_cfg_get_valid_endpoint_auth_function(cfg, TRUE), NULL, TRUE, NULL) != NULL) {
		oidc_error(r,
			   "could not find a supported token endpoint authentication method in provider metadata (%s) "
			   "for entry \"" OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED "\"",
			   issuer);
		return FALSE;
	}

	return TRUE;
}

/*
 * use OpenID Connect Discovery to get metadata for the specified issuer
 */
apr_byte_t oidc_metadata_provider_retrieve(request_rec *r, oidc_cfg_t *cfg, const char *issuer, const char *url,
					   oidc_json_t **j_metadata, char **response) {

	OIDC_METRICS_TIMING_START(r, cfg);

	/* get provider metadata from the specified URL with the specified parameters */
	if (oidc_http_get(r, url, NULL, NULL, NULL, NULL,
			  oidc_cfg_provider_ssl_validate_server_get(oidc_cfg_provider_get(cfg)), response, NULL, NULL,
			  oidc_cfg_http_timeout_short_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
			  oidc_cfg_dir_pass_cookies_get(r), NULL, NULL, NULL) == FALSE) {
		OIDC_METRICS_COUNTER_INC(r, cfg, OM_PROVIDER_METADATA_ERROR);
		return FALSE;
	}

	OIDC_METRICS_TIMING_ADD(r, cfg, OM_PROVIDER_METADATA);

	/* decode and see if it is not an error response somehow */
	if (oidc_json_decode_and_check_error(r, *response, j_metadata) == FALSE) {
		oidc_error(r, "JSON parsing of retrieved Discovery document failed");
		return FALSE;
	}

	/* check to see if it is valid metadata */
	if (oidc_metadata_provider_is_valid(r, cfg, *j_metadata, issuer) == FALSE) {
		oidc_json_decref(*j_metadata);
		*j_metadata = NULL;
		return FALSE;
	}

	/* all OK */
	return TRUE;
}

/*
 * see if we have provider metadata and check its validity
 * if not, use OpenID Connect Discovery to get it, check it and store it
 */
apr_byte_t oidc_metadata_provider_get(request_rec *r, oidc_cfg_t *cfg, const char *issuer, oidc_json_t **j_provider,
				      apr_byte_t allow_discovery) {

	/* holds the response data/string/JSON from the OP */
	char *response = NULL;

	/* get the full file path to the provider metadata for this issuer */
	const char *provider_path = oidc_metadata_provider_file_path(r, issuer);

	/* check the last-modified timestamp */
	apr_byte_t use_cache = TRUE;
	apr_finfo_t fi;
	oidc_json_t *j_cache = NULL;
	apr_byte_t have_cache = FALSE;

	/* see if we are refreshing metadata and we need a refresh */
	if (oidc_cfg_provider_metadata_refresh_interval_get(cfg) > 0) {

		have_cache = (apr_stat(&fi, provider_path, APR_FINFO_MTIME, r->pool) == APR_SUCCESS);

		if (have_cache == TRUE)
			use_cache =
			    (apr_time_now() <
			     fi.mtime + apr_time_from_sec(oidc_cfg_provider_metadata_refresh_interval_get(cfg)));

		oidc_debug(r, "use_cache: %s", use_cache ? "yes" : "no");
	}

	/* see if we have valid metadata already, if so, return it */
	if ((oidc_metadata_file_read_json(r, provider_path, &j_cache) == TRUE) && (use_cache == TRUE)) {
		*j_provider = j_cache;
		return oidc_metadata_provider_is_valid(r, cfg, *j_provider, issuer);
	}

	if ((have_cache == FALSE) && (!allow_discovery)) {
		oidc_warn(r, "no metadata found for the requested issuer (%s), and Discovery is not allowed", issuer);
		return FALSE;
	}

	/* assemble the URL to the .well-known OpenID metadata */
	const char *url =
	    apr_psprintf(r->pool, "%s",
			 ((_oidc_strstr(issuer, "http://") == issuer) || (_oidc_strstr(issuer, "https://") == issuer))
			     ? issuer
			     : apr_psprintf(r->pool, "https://%s", issuer));
	url =
	    apr_psprintf(r->pool, "%s%s.well-known/openid-configuration", url,
			 (url && url[_oidc_strlen(url) - 1] != OIDC_CHAR_FORWARD_SLASH) ? OIDC_STR_FORWARD_SLASH : "");

	/* get the metadata for the issuer using OpenID Connect Discovery and validate it */
	if (oidc_metadata_provider_retrieve(r, cfg, issuer, url, j_provider, &response) == FALSE) {

		oidc_debug(r, "could not retrieve provider metadata; have_cache: %s (data=%pp)",
			   have_cache ? "yes" : "no", j_cache);

		/* see if we can use at least the cache that may have expired by now */
		if ((oidc_cfg_provider_metadata_refresh_interval_get(cfg) > 0) && (have_cache == TRUE) &&
		    (j_cache != NULL)) {

			/* reset the file-modified timestamp so it is cached for a while again */
			apr_file_mtime_set(provider_path, apr_time_now(), r->pool);

			/* return the validated cached data */
			*j_provider = j_cache;
			return oidc_metadata_provider_is_valid(r, cfg, *j_provider, issuer);
		}

		return FALSE;
	}

	/* live discovery produced fresh metadata into *j_provider; drop the stale cached document
	 * we may have read above (it is only handed back to the caller on the retrieve-failure paths) */
	if (j_cache != NULL)
		oidc_json_decref(j_cache);

	/* A cache-file write failure does not invalidate successfully retrieved metadata. */
	if (oidc_util_file_write(r, provider_path, response) == FALSE)
		oidc_warn(
		    r,
		    "could not cache the retrieved provider metadata in \"%s\"; continuing with the in-memory result",
		    provider_path);

	return TRUE;
}

/*
 * Prefer an RFC 8705 mTLS alias when present. A missing alias may fall back to the conventional
 * endpoint; an invalid configured alias must fail rather than silently lose certificate binding.
 */
static apr_byte_t oidc_metadata_provider_parse_url_mtls(request_rec *r, const oidc_provider_t *provider,
							const oidc_json_t *j_provider, const oidc_json_t *j_aliases,
							const char *key, char **value) {

	*value = NULL;

	if ((j_aliases != NULL) && (oidc_json_object_get(j_aliases, key) != NULL)) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_aliases, key, value, NULL);
		if (*value == NULL) {
			oidc_error(r,
				   "provider (%s) advertises a \"" OIDC_METADATA_MTLS_ENDPOINT_ALIASES
				   "\" entry for \"%s\" that is not a valid URL; not falling back to the conventional "
				   "endpoint, since that one would not bind the access token to the TLS client "
				   "certificate",
				   oidc_cfg_provider_issuer_get(provider), key);
			return FALSE;
		}
		return TRUE;
	}

	oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider), j_provider,
				key, value, NULL);

	return TRUE;
}

/*
 * fill an endpoint URL as above; an explicitly configured endpoint is never overridden
 */
#define OIDC_METADATA_PROVIDER_PARSE_URL_MTLS(j_provider, j_aliases, key, member)                                      \
	;                                                                                                              \
	do {                                                                                                           \
		if (oidc_cfg_provider_##member##_get(provider) == NULL) {                                              \
			char *_u_ = NULL;                                                                              \
			if (oidc_metadata_provider_parse_url_mtls(r, provider, j_provider, j_aliases, key, &_u_) ==    \
			    FALSE)                                                                                     \
				return FALSE;                                                                          \
			OIDC_METADATA_PROVIDER_SET(member, _u_);                                                       \
		}                                                                                                      \
	} while (0)

#define OIDC_METADATA_PROVIDER_PARSE_URL(j_provider, key, member)                                                      \
	OIDC_METADATA_PROVIDER_PARSE_URL_MTLS(j_provider, NULL, key, member)

/* Apply RFC 8705 behavior using the resolved per-provider settings. */
static apr_byte_t oidc_metadata_provider_cert_bound_tokens_enabled(request_rec *r, oidc_cfg_t *cfg,
								   const oidc_json_t *j_provider,
								   const oidc_provider_t *provider) {
	const char *auth = oidc_cfg_provider_token_endpoint_auth_get(provider);
	apr_byte_t b_cert = (oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider) != NULL) ||
			    (oidc_cfg_provider_token_endpoint_tls_client_cert_get(oidc_cfg_provider_get(cfg)) != NULL);
	oidc_cert_bound_tokens_t mode = oidc_cfg_provider_cert_bound_tokens_get(provider);

	/* Resolve auto through the global setting and profile before consulting provider metadata. */
	if (mode == OIDC_CERT_BOUND_TOKENS_AUTO)
		mode = oidc_cfg_provider_cert_bound_tokens_get(oidc_cfg_provider_get(cfg));
	if (mode == OIDC_CERT_BOUND_TOKENS_AUTO)
		mode = oidc_proto_profile_cert_bound_tokens_get(provider);

	return oidc_metadata_cert_bound_tokens_enabled(r, j_provider, mode, auth, b_cert);
}

/*
 * RFC 9449 section 5.1: an OP that supports DPoP advertises the signing algorithms it accepts for
 * DPoP proofs, so a non-empty "dpop_signing_alg_values_supported" array is the signal for it
 */
static int oidc_metadata_provider_dpop_supported(const oidc_json_t *j_provider) {
	const oidc_json_t *j_algs = oidc_json_object_get(j_provider, OIDC_METADATA_DPOP_SIGNING_ALG_VALUES_SUPPORTED);
	return (oidc_json_is_array(j_algs) != 0) && (oidc_json_array_size(j_algs) > 0);
}

/*
 * parse the JSON provider metadata in to a oidc_provider_t struct but do not override values already set
 */
apr_byte_t oidc_metadata_provider_parse(request_rec *r, oidc_cfg_t *cfg, const oidc_json_t *j_provider,
					oidc_provider_t *provider) {

	const char *rv = NULL;
	char *value = NULL;
	int ivalue = OIDC_CONFIG_POS_INT_UNSET;
	const oidc_json_t *j_aliases = NULL;

	if (oidc_cfg_provider_issuer_get(provider) == NULL) {
		/* get the "issuer" from the provider metadata */
		oidc_json_object_get_string(r->pool, j_provider, OIDC_METADATA_ISSUER, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(issuer, value);
	}

	/* NB: the token endpoint authentication method is resolved before the endpoints because the
	 *     RFC 8705 mutual-TLS endpoint selection below depends on it */
	if (oidc_cfg_provider_token_endpoint_auth_get(provider) == NULL) {
		/* the secret/certificate interplay that decides on RFC 8705 mutual-TLS is
		 * documented at oidc_metadata_endpoint_auth_select; the secret and certificate
		 * may be configured on this provider or globally */
		apr_byte_t b_secret = (oidc_cfg_provider_client_secret_get(provider) != NULL) ||
				      (oidc_cfg_provider_client_secret_get(oidc_cfg_provider_get(cfg)) != NULL);
		apr_byte_t b_cert =
		    (oidc_cfg_provider_token_endpoint_tls_client_cert_get(provider) != NULL) ||
		    (oidc_cfg_provider_token_endpoint_tls_client_cert_get(oidc_cfg_provider_get(cfg)) != NULL);
		if (oidc_metadata_endpoint_auth_select(r, cfg, j_provider,
						       OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, b_secret,
						       b_cert, &value) != NULL) {
			oidc_error(r,
				   "could not find a supported token endpoint authentication method in provider"
				   "metadata (%s) for entry \"" OIDC_METADATA_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
				   "\"",
				   oidc_cfg_provider_issuer_get(provider));
			return FALSE;
		}
		rv = oidc_cfg_provider_token_endpoint_auth_set(r->pool, cfg, provider, value);
		if (rv != NULL)
			oidc_error(r, "oidc_provider_token_endpoint_auth_set: %s", rv);
	}

	/* Record the RFC 8705 decision so endpoint selection and client registration stay consistent. */
	if (oidc_metadata_provider_cert_bound_tokens_enabled(r, cfg, j_provider, provider) == TRUE) {
		oidc_cfg_provider_cert_bound_tokens_int_set(provider, OIDC_CERT_BOUND_TOKENS_ON);
		j_aliases = oidc_metadata_mtls_endpoint_aliases_get(j_provider);
		if (j_aliases != NULL)
			oidc_debug(
			    r, "preferring the \"" OIDC_METADATA_MTLS_ENDPOINT_ALIASES "\" endpoints of provider (%s)",
			    oidc_cfg_provider_issuer_get(provider));
	} else {
		oidc_cfg_provider_cert_bound_tokens_int_set(provider, OIDC_CERT_BOUND_TOKENS_OFF);
	}

	/* record whether the OP supports RFC 9449 DPoP; a profile that mandates sender-constrained access
	 * tokens through either mutual-TLS or DPoP (FAPI 2.0) needs it to tell the two apart */
	oidc_cfg_provider_dpop_supported_int_set(provider, oidc_metadata_provider_dpop_supported(j_provider));

	OIDC_METADATA_PROVIDER_PARSE_URL(j_provider, OIDC_METADATA_AUTHORIZATION_ENDPOINT, authorization_endpoint_url);
	OIDC_METADATA_PROVIDER_PARSE_URL_MTLS(j_provider, j_aliases, OIDC_METADATA_TOKEN_ENDPOINT, token_endpoint_url);
	OIDC_METADATA_PROVIDER_PARSE_URL_MTLS(j_provider, j_aliases, OIDC_METADATA_USERINFO_ENDPOINT,
					      userinfo_endpoint_url);
	OIDC_METADATA_PROVIDER_PARSE_URL_MTLS(j_provider, j_aliases, OIDC_METADATA_REVOCATION_ENDPOINT,
					      revocation_endpoint_url);
	OIDC_METADATA_PROVIDER_PARSE_URL_MTLS(j_provider, j_aliases, OIDC_METADATA_PAR_ENDPOINT,
					      pushed_authorization_request_endpoint_url);

	/* jwks_uri is a struct; its URI string is reached via a separate accessor */
	if (oidc_cfg_provider_jwks_uri_uri_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_JWKS_URI, &value, NULL);
		OIDC_METADATA_PROVIDER_SET(jwks_uri, value);
	}

	if (oidc_cfg_provider_signed_jwks_uri_get(provider) == NULL) {
		oidc_metadata_parse_url(r, OIDC_METADATA_SUFFIX_PROVIDER, oidc_cfg_provider_issuer_get(provider),
					j_provider, OIDC_METADATA_SIGNED_JWKS_URI, &value, NULL);
		if (value != NULL) {
			rv = oidc_cfg_provider_signed_jwks_uri_set(r->pool, provider, value, NULL);
			if (rv != NULL)
				oidc_error(r, "oidc_provider_signed_jwks_uri_set: %s", rv);
		}
	}

	OIDC_METADATA_PROVIDER_PARSE_URL_MTLS(j_provider, j_aliases, OIDC_METADATA_REGISTRATION_ENDPOINT,
					      registration_endpoint_url);
	OIDC_METADATA_PROVIDER_PARSE_URL(j_provider, OIDC_METADATA_CHECK_SESSION_IFRAME, check_session_iframe);
	OIDC_METADATA_PROVIDER_PARSE_URL(j_provider, OIDC_METADATA_END_SESSION_ENDPOINT, end_session_endpoint);

	// NB: here we don't actually override with the global setting/default, merely apply it when no value is
	// provided
	oidc_metadata_parse_boolean(r, j_provider, OIDC_METADATA_BACKCHANNEL_LOGOUT_SUPPORTED, &ivalue,
				    oidc_cfg_provider_backchannel_logout_supported_get(provider));
	OIDC_METADATA_PROVIDER_SET_INT(backchannel_logout_supported, ivalue);

	return TRUE;
}
