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
 * Copyright (C) 2017-2025 ZmartZone Holding BV
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

#include "cfg/dir.h"
#include "cfg/parse.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util.h"

/*
 * based on a resource perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and store its
 * metadata
 */
static apr_byte_t oidc_proto_webfinger_discovery(request_rec *r, oidc_cfg_t *cfg, const char *resource,
						 const char *domain, char **issuer) {

	const char *url = apr_psprintf(r->pool, "https://%s/.well-known/webfinger", domain);

	apr_table_t *params = apr_table_make(r->pool, 1);
	apr_table_setn(params, "resource", resource);
	apr_table_setn(params, "rel", "http://openid.net/specs/connect/1.0/issuer");

	char *response = NULL;
	if (oidc_http_get(r, url, params, NULL, NULL, NULL,
			  oidc_cfg_provider_ssl_validate_server_get(oidc_cfg_provider_get(cfg)), &response, NULL, NULL,
			  oidc_cfg_http_timeout_short_get(cfg), oidc_cfg_outgoing_proxy_get(cfg),
			  oidc_cfg_dir_pass_cookies_get(r), NULL, NULL, NULL) == FALSE) {
		/* errors will have been logged by now */
		return FALSE;
	}

	/* decode and see if it is not an error response somehow */
	json_t *j_response = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &j_response) == FALSE)
		return FALSE;

	/* get the links parameter */
	json_t *j_links = json_object_get(j_response, "links");
	if ((j_links == NULL) || (!json_is_array(j_links))) {
		oidc_error(r, "response JSON object did not contain a \"links\" array");
		json_decref(j_response);
		return FALSE;
	}

	/* get the one-and-only object in the "links" array */
	json_t *j_object = json_array_get(j_links, 0);
	if ((j_object == NULL) || (!json_is_object(j_object))) {
		oidc_error(
		    r,
		    "response JSON object did not contain a JSON object as the first element in the \"links\" array");
		json_decref(j_response);
		return FALSE;
	}

	/* get the href from that object, which is the issuer value */
	json_t *j_href = json_object_get(j_object, "href");
	if ((j_href == NULL) || (!json_is_string(j_href))) {
		oidc_error(
		    r, "response JSON object did not contain a \"href\" element in the first \"links\" array object");
		json_decref(j_response);
		return FALSE;
	}

	/* check that the link is on secure HTTPs */
	if (oidc_cfg_parse_is_valid_url(r->pool, json_string_value(j_href), "https") != NULL) {
		oidc_error(r, "response JSON object contains an \"href\" value that is not a valid \"https\" URL: %s",
			   json_string_value(j_href));
		json_decref(j_response);
		return FALSE;
	}

	*issuer = apr_pstrdup(r->pool, json_string_value(j_href));

	oidc_debug(r, "returning issuer \"%s\" for resource \"%s\" after doing successful webfinger-based discovery",
		   *issuer, resource);

	json_decref(j_response);

	return TRUE;
}

/*
 * based on an account name, perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and
 * store its metadata
 */
apr_byte_t oidc_proto_discovery_account_based(request_rec *r, oidc_cfg_t *cfg, const char *acct, char **issuer) {

	// TODO: maybe show intermediate/progress screen "discovering..."

	oidc_debug(r, "enter, acct=%s", acct);

	const char *resource = apr_psprintf(r->pool, "acct:%s", acct);
	const char *domain = strrchr(acct, OIDC_CHAR_AT);
	if (domain == NULL) {
		oidc_error(r, "invalid account name");
		return FALSE;
	}
	domain++;

	return oidc_proto_webfinger_discovery(r, cfg, resource, domain, issuer);
}

/*
 * based on user identifier URL, perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and
 * store its metadata
 */
apr_byte_t oidc_proto_discovery_url_based(request_rec *r, oidc_cfg_t *cfg, const char *url, char **issuer) {

	oidc_debug(r, "enter, url=%s", url);

	apr_uri_t uri;
	apr_uri_parse(r->pool, url, &uri);

	char *domain = uri.hostname;
	if (uri.port_str != NULL)
		domain = apr_psprintf(r->pool, "%s:%s", domain, uri.port_str);

	return oidc_proto_webfinger_discovery(r, cfg, url, domain, issuer);
}
