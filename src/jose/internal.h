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
 * internal header for the jose/ subdirectory: shared cjose-facing helpers
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#ifndef _MOD_AUTH_OPENIDC_JOSE_INTERNAL_H_
#define _MOD_AUTH_OPENIDC_JOSE_INTERNAL_H_

#include "jose.h"

#include <cjose/cjose.h>

/*
 * render a cjose error into a string; defined here rather than in jose.h so the public header stays free of
 * the cjose error type
 */
#define oidc_cjose_e2s(pool, cjose_err)                                                                                \
	apr_psprintf(pool, "%s [file: %s, function: %s, line: %ld]", cjose_err.message, cjose_err.file,                \
		     cjose_err.function, cjose_err.line)

/*
 * the backend-independent OIDC_JOSE_JWK_KTY_* values carried in oidc_jwk_t.kty are kept identical to the
 * cjose enum so that no translation is needed at the boundary; assert that invariant at compile time so a
 * future cjose renumbering fails the build loudly instead of silently breaking key selection
 */
_Static_assert(OIDC_JOSE_JWK_KTY_RSA == CJOSE_JWK_KTY_RSA, "OIDC_JOSE_JWK_KTY_RSA must match cjose");
_Static_assert(OIDC_JOSE_JWK_KTY_EC == CJOSE_JWK_KTY_EC, "OIDC_JOSE_JWK_KTY_EC must match cjose");
_Static_assert(OIDC_JOSE_JWK_KTY_OCT == CJOSE_JWK_KTY_OCT, "OIDC_JOSE_JWK_KTY_OCT must match cjose");

/* assemble an error report; the oidc_jose_error* macros in jose.h expand to this */
void _oidc_jose_error_set(oidc_jose_error_t *error, const char *source, const int line, const char *function,
			  const char *fmt, ...);

/* return the key type for an algorithm */
int oidc_alg2kty(const char *alg);

/* set a header value in a JWT */
void oidc_jwt_hdr_set(oidc_jwt_t *jwt, const char *key, const char *value);

/* whether the cjose version in use is deprecated */
apr_byte_t oidc_jose_version_deprecated(apr_pool_t *pool);

#endif /* _MOD_AUTH_OPENIDC_JOSE_INTERNAL_H_ */
