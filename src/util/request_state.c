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

/*
 * per-request state store: a hash table hung off the (main) request's pool userdata, used to pass
 * state between the Apache request-processing stages and hook callbacks.
 *
 * This is a plain utility over request_rec and carries no mod_auth_openidc configuration or
 * protocol knowledge, which is why it lives here rather than in the module core: util/util.c and
 * util/html.c needed exactly these symbols and had to include mod_auth_openidc.h to get them.
 */

#include "util/request_state.h"

#include "json.h"

#include <apr_hash.h>
#include <apr_strings.h>

/* the key under which the state hash is stored in the request pool's userdata */
#define OIDC_USERDATA_KEY "mod_auth_openidc_state"
/*
 * get the mod_auth_openidc related context from the (userdata in the) request
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
static apr_hash_t *oidc_request_state(request_rec *rr) {

	/* our state is always stored in the main request */
	request_rec *r = (rr->main != NULL) ? rr->main : rr;

	/* our state is a hash table, get it */
	apr_hash_t *state = NULL;
	apr_pool_userdata_get((void **)&state, OIDC_USERDATA_KEY, r->pool);

	/* if it does not exist, we'll create a new hash table */
	if (state == NULL) {
		state = apr_hash_make(r->pool);
		apr_pool_userdata_set(state, OIDC_USERDATA_KEY, NULL, r->pool);
	}

	/* return the resulting table, always non-null now */
	return state;
}

/*
 * set a name/value pair in the mod_auth_openidc-specific request context
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
void oidc_request_state_set(request_rec *r, const char *key, const char *value) {

	/* get a handle to the global state, which is a hash table */
	apr_hash_t *state = oidc_request_state(r);

	/* put the name/value pair in that hash table */
	apr_hash_set(state, key, APR_HASH_KEY_STRING, value);
}

/*
 * get a name/value pair from the mod_auth_openidc-specific request context
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
const char *oidc_request_state_get(request_rec *r, const char *key) {

	/* get a handle to the global state, which is a hash table */
	apr_hash_t *state = oidc_request_state(r);

	/* return the value from the hash table */
	return (const char *)apr_hash_get(state, key, APR_HASH_KEY_STRING);
}

/*
 * get a name/json object pair from the mod_auth_openidc-specific request context
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
oidc_json_t *oidc_request_state_json_get(request_rec *r, const char *key) {

	/* get a handle to the global state, which is a hash table */
	apr_hash_t *state = oidc_request_state(r);

	/* return the value from the hash table */
	return (oidc_json_t *)apr_hash_get(state, key, APR_HASH_KEY_STRING);
}

/*
 * APR pool cleanup callback that releases a request-state JSON object
 */
static apr_status_t oidc_request_state_json_cleanup(void *json) {
	oidc_json_decref((oidc_json_t *)json);
	return APR_SUCCESS;
}

/*
 * set a name/json object pair in the mod_auth_openidc-specific request context, taking over
 * ownership of (i.e. "stealing", jansson-style "_new" semantics) the provided reference
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
void oidc_request_state_json_set_new(request_rec *r, const char *key, oidc_json_t *value) {

	/* get a handle to the global state, which is a hash table */
	apr_hash_t *state = oidc_request_state(r);

	/* register a cleanup for the json object on the pool of the (main) request that owns the
	 * state hash: a subrequest pool would be destroyed while the state may still be in use */
	request_rec *main_r = (r->main != NULL) ? r->main : r;
	apr_pool_cleanup_register(main_r->pool, value, oidc_request_state_json_cleanup, apr_pool_cleanup_null);

	/* put the name/value pair in that hash table */
	apr_hash_set(state, key, APR_HASH_KEY_STRING, value);
}

/*
 * set a name/json object pair in the mod_auth_openidc-specific request context
 * (used for passing state between various Apache request processing stages and hook callbacks)
 */
void oidc_request_state_json_set(request_rec *r, const char *key, const oidc_json_t *value) {

	/* make a copy of the json object because the session object in the caller will be cleared */
	oidc_request_state_json_set_new(r, key, oidc_json_copy(value));
}
