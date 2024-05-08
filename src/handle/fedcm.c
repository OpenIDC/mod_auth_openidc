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
 * Copyright (C) 2017-2024 ZmartZone Holding BV
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

#include "cfg/provider.h"
#include "handle/handle.h"
#include "proto.h"
#include "util.h"

int oidc_fedcm_request(request_rec *r, struct oidc_provider_t *provider, const char *redirect_uri, const char *state,
		       const char *nonce) {

	oidc_debug(r, "enter");

	const char *java_script = "<script type=\"text/javascript\">\n"
				  "  async function signIn() {\n"
				  "    const identityCredential = await navigator.credentials.get({\n"
				  "      identity: {\n"
				  "        providers: [\n"
				  "          {\n"
				  "            configURL: \"%s\",\n"
				  "            clientId: \"%s\",\n"
				  "            nonce: \"%s\",\n"
				  "          },\n"
				  "        ],\n"
				  "      },\n"
				  "    });\n"
				  "    const { token } = identityCredential;\n"
				  "    var input = document.getElementById('token');\n"
				  "    input.value = token;\n"
				  "    document.forms[0].submit();\n"
				  "  }\n"
				  "</script>\n";

	// TODO: get the configURL from the provider metadata/config somehow
	const char *html_head = apr_psprintf(r->pool, java_script, "https://accounts.google.com/gsi/fedcm.json",
					     oidc_cfg_provider_client_id_get(provider), nonce);

	// mimic fragment post
	const char *html_body = apr_psprintf(r->pool,
					     "    <p>Submitting...</p>\n"
					     "    <form method=\"post\" action=\"%s\">\n"
					     "      <p>\n"
					     "        <input type=\"hidden\" id=\"token\" name=\"id_token"
					     "\" value=\"\">\n"
					     "        <input type=\"hidden\" name=\"state"
					     "\" value=\"%s\">\n"
					     "        <input type=\"hidden\" name=\"" OIDC_PROTO_RESPONSE_MODE
					     "\" value=\"" OIDC_PROTO_RESPONSE_MODE_FRAGMENT "\">\n"
					     "      </p>\n"
					     "    </form>\n",
					     redirect_uri, state);

	return oidc_util_html_send(r, "FedCM", html_head, "signIn", html_body, OK);
};
