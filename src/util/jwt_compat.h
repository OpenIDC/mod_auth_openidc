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

#ifndef OIDC_JWT_COMPAT_H
#define OIDC_JWT_COMPAT_H

#include "cfg/cfg.h"
#include "jose.h"
#include "session.h"

typedef enum {
	OIDC_JWT_COMPAT_DECLINED = -1, /* no change: continue normal encryption */
	OIDC_JWT_COMPAT_ERROR = 0,     /* compatibility was requested but failed */
	OIDC_JWT_COMPAT_HANDLED = 1,   /* compatibility supplied the encryption key */
} oidc_jwt_compat_result_t;

oidc_jwt_compat_result_t oidc_jwt_compat_create_key(request_rec *r,
		const oidc_crypto_passphrase_t *passphrase, oidc_jwk_t **jwk);
/* Called only after normal verification fails. NULL is allowed for needs_rewrite. */
apr_byte_t oidc_jwt_compat_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
		const char *token, char **payload, apr_byte_t *needs_rewrite);

/* The session layer supplies its private cookie writer after validation succeeds. */
typedef apr_byte_t (*oidc_jwt_compat_persist_fn)(request_rec *r, const oidc_session_t *z,
					     oidc_session_save_t first_time);
apr_byte_t oidc_jwt_compat_session_loaded(request_rec *r, oidc_session_t *z,
					 oidc_jwt_compat_persist_fn persist);

#endif
