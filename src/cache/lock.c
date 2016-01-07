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
 * Copyright (C) 2013-2016 Ping Identity Corporation
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
 * global lock implementation
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#ifndef WIN32
#include <unistd.h>
#endif

#include "apr_general.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "../mod_auth_openidc.h"

/* create the cache lock context */
oidc_cache_mutex_t *oidc_cache_mutex_create(apr_pool_t *pool) {
	oidc_cache_mutex_t *ctx = apr_pcalloc(pool, sizeof(oidc_cache_mutex_t));
	ctx->mutex = NULL;
	ctx->mutex_filename = NULL;
	return ctx;
}

apr_byte_t oidc_cache_mutex_post_config(server_rec *s, oidc_cache_mutex_t *m,
		const char *type) {

	apr_status_t rv = APR_SUCCESS;
	const char *dir;

	/* construct the mutex filename */
	apr_temp_dir_get(&dir, s->process->pool);
	m->mutex_filename = apr_psprintf(s->process->pool,
			"%s/mod_auth_openidc_%s_mutex.%ld.%pp", dir, type,
			(long int) getpid(), s);

	/* create the mutex lock */
	rv = apr_global_mutex_create(&m->mutex, (const char *) m->mutex_filename,
			APR_LOCK_DEFAULT, s->process->pool);
	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"apr_global_mutex_create failed to create mutex on file %s",
				m->mutex_filename);
		return FALSE;
	}

	/* need this on Linux */
#ifdef AP_NEED_SET_MUTEX_PERMS
#if MODULE_MAGIC_NUMBER_MAJOR >= 20081201
	rv = ap_unixd_set_global_mutex_perms(m->mutex);
#else
	rv = unixd_set_global_mutex_perms(m->mutex);
#endif
	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"unixd_set_global_mutex_perms failed; could not set permissions ");
		return FALSE;
	}
#endif

	return TRUE;
}

/*
 * initialize the cache lock in a child process
 */
apr_status_t oidc_cache_mutex_child_init(apr_pool_t *p, server_rec *s,
		oidc_cache_mutex_t *m) {

	/* initialize the lock for the child process */
	apr_status_t rv = apr_global_mutex_child_init(&m->mutex,
			(const char *) m->mutex_filename, p);

	if (rv != APR_SUCCESS) {
		oidc_serror(s,
				"apr_global_mutex_child_init failed to reopen mutex on file %s",
				m->mutex_filename);
	}

	return rv;
}

/*
 * global lock
 */
apr_byte_t oidc_cache_mutex_lock(request_rec *r, oidc_cache_mutex_t *m) {

	apr_status_t rv = apr_global_mutex_lock(m->mutex);

	if (rv != APR_SUCCESS) {
		oidc_error(r, "apr_global_mutex_lock() failed [%d]", rv);
		return FALSE;
	}

	return TRUE;
}

/*
 * global unlock
 */
apr_byte_t oidc_cache_mutex_unlock(request_rec *r, oidc_cache_mutex_t *m) {

	apr_status_t rv = apr_global_mutex_unlock(m->mutex);

	if (rv != APR_SUCCESS) {
		oidc_error(r, "apr_global_mutex_unlock() failed [%d]", rv);
		return FALSE;
	}

	return TRUE;
}

/*
 * destroy mutex
 */
apr_byte_t oidc_cache_mutex_destroy(server_rec *s, oidc_cache_mutex_t *m) {

	apr_status_t rv = APR_SUCCESS;

	if (m->mutex != NULL) {
		rv = apr_global_mutex_destroy(m->mutex);
		if (rv != APR_SUCCESS) {
			oidc_swarn(s, "apr_global_mutex_destroy failed: [%d]", rv);
		}
		m->mutex = NULL;
	}

	return rv;
}
