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
 *
 **************************************************************************/

#include "helper.h"
#include "cfg/cfg_int.h"
#include "cfg/dir.h"
#include <openssl/evp.h>

static apr_pool_t *pool = NULL;
static request_rec *request = NULL;

static request_rec *oidc_test_request_init(apr_pool_t *pool) {
	const unsigned int kIdx = 0;
	const unsigned int kEls = kIdx + 1;
	request_rec *request = (request_rec *)apr_pcalloc(pool, sizeof(request_rec));

	request->pool = pool;
	request->subprocess_env = apr_table_make(request->pool, 0);

	request->headers_in = apr_table_make(request->pool, 0);
	request->headers_out = apr_table_make(request->pool, 0);
	request->err_headers_out = apr_table_make(request->pool, 0);

	apr_table_set(request->headers_in, "Host", "www.example.com");
	apr_table_set(request->headers_in, "OIDC_foo", "some-value");
	apr_table_set(request->headers_in, "Cookie",
		      "foo=bar; "
		      "mod_auth_openidc_session"
		      "=0123456789abcdef; baz=zot");

	request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
	request->server->process = apr_pcalloc(request->pool, sizeof(struct process_rec));
	request->server->process->pool = request->pool;
	request->server->process->pconf = request->pool;
	request->connection = apr_pcalloc(request->pool, sizeof(struct conn_rec));
	request->connection->bucket_alloc = apr_bucket_alloc_create(request->pool);
	request->connection->local_addr = apr_pcalloc(request->pool, sizeof(apr_sockaddr_t));

	apr_pool_userdata_set("https", "scheme", NULL, request->pool);
	request->server->server_hostname = "www.example.com";
	request->connection->local_addr->port = 443;
	request->unparsed_uri = "/bla?foo=bar&param1=value1";
	request->args = "foo=bar&param1=value1";
	apr_uri_parse(request->pool, "https://www.example.com/bla?foo=bar&param1=value1", &request->parsed_uri);

	auth_openidc_module.module_index = kIdx;
	oidc_cfg_t *cfg = oidc_cfg_server_create(request->pool, request->server);

	oidc_cfg_provider_issuer_set(pool, oidc_cfg_provider_get(cfg), "https://idp.example.com");
	oidc_cfg_provider_authorization_endpoint_url_set(pool, oidc_cfg_provider_get(cfg),
							 "https://idp.example.com/authorize");
	oidc_cfg_provider_client_id_set(pool, oidc_cfg_provider_get(cfg), "client_id");

	cfg->redirect_uri = "https://www.example.com/protected/";

	oidc_dir_cfg_t *d_cfg = oidc_cfg_dir_config_create(request->pool, NULL);

	// coverity[suspicious_sizeof]
	request->server->module_config = apr_pcalloc(request->pool, sizeof(void *) * kEls);
	// coverity[suspicious_sizeof]
	request->per_dir_config = apr_pcalloc(request->pool, sizeof(void *) * kEls);
	ap_set_module_config(request->server->module_config, &auth_openidc_module, cfg);
	ap_set_module_config(request->per_dir_config, &auth_openidc_module, d_cfg);

	// TODO:
	cfg->public_keys = apr_array_make(pool, 1, sizeof(const char *));
	cfg->private_keys = apr_array_make(pool, 1, sizeof(const char *));

	cfg->crypto_passphrase.secret1 = "12345678901234567890123456789012";
	cfg->cache.impl = &oidc_cache_shm;
	cfg->cache.cfg = NULL;
	cfg->cache.shm_size_max = 500;
	cfg->cache.shm_entry_size_max = 16384 + 255 + 17;
	cfg->cache.encrypt = 1;
	if (cfg->cache.impl->post_config(request->server) != OK) {
		printf("cfg->cache.impl->post_config failed!\n");
		exit(-1);
	}

	return request;
}

void oidc_test_setup(void) {
	apr_initialize();
	oidc_pre_config_init();
	apr_pool_create(&pool, NULL);
	request = oidc_test_request_init(pool);
}

void oidc_test_teardown(void) {
	EVP_cleanup();
	apr_pool_destroy(pool);
	apr_terminate();
}

apr_pool_t *oidc_test_pool_get() {
	return pool;
}

request_rec *oidc_test_request_get() {
	return request;
}

oidc_cfg_t *oidc_test_cfg_get() {
	return (oidc_cfg_t *)ap_get_module_config(request->server->module_config, &auth_openidc_module);
}

cmd_parms *oidc_test_cmd_get(const char *primitive) {
	request_rec *r = oidc_test_request_get();
	cmd_parms *cmd = apr_pcalloc(r->pool, sizeof(cmd_parms));
	cmd->server = r->server;
	cmd->pool = r->pool;
	cmd->directive = apr_pcalloc(cmd->pool, sizeof(ap_directive_t));
	cmd->directive->directive = primitive;
	return cmd;
}

int oidc_test_suite_run(Suite *s) {
	int n_failed = 0;

	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	n_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (n_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
