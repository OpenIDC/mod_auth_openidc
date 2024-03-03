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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 */

#ifndef MOD_AUTH_OPENIDC_CONST_H_
#define MOD_AUTH_OPENIDC_CONST_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#endif

#include <stdint.h>
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

#include <apr_strings.h>

// clang-format off

#include <httpd.h>
#include <http_log.h>

// clang-format on

#ifdef __STDC_LIB_EXT1__
#define _oidc_memset(b, c, __len) memset_s(b, __len, c, __len)
#define _oidc_memcpy(__dst, __src, __n) memcpy_s(__dst, __src, __n)
#define _oidc_strcpy(__dst, __src) strcpy_s(__dst, __src)
#else
#define _oidc_memset(b, c, __len) memset(b, c, __len)
#define _oidc_memcpy(__dst, __src, __n) memcpy(__dst, __src, __n)
#define _oidc_strcpy(__dst, __src) strcpy(__dst, __src)
#endif

static inline size_t _oidc_strlen(const char *s) {
	return (s ? strlen(s) : 0);
}
static inline int _oidc_strcmp(const char *a, const char *b) {
	return ((a && b) ? apr_strnatcmp(a, b) : -1);
}
static inline int _oidc_strnatcasecmp(const char *a, const char *b) {
	return ((a && b) ? apr_strnatcasecmp(a, b) : -1);
}
static inline int _oidc_strncmp(const char *a, const char *b, size_t n) {
	return ((a && b) ? strncmp(a, b, n) : -1);
}
static inline char *_oidc_strstr(const char *a, const char *b) {
	return ((a && b) ? strstr(a, b) : NULL);
}
static inline apr_time_t _oidc_str_to_time(const char *s, const apr_time_t default_value) {
	apr_time_t v = default_value;
	if (s)
		sscanf(s, "%" APR_TIME_T_FMT, &v);
	return v;
}
static inline int _oidc_str_to_int(const char *s, const int default_value) {
	int v = default_value;
	if (s)
		v = strtol(s, NULL, 10);
	return v;
}

#define HAVE_APACHE_24 MODULE_MAGIC_NUMBER_MAJOR >= 20100714

#ifndef OIDC_DEBUG
#define OIDC_DEBUG APLOG_DEBUG
#endif

#ifndef APLOG_TRACE1
#define APLOG_TRACE1 APLOG_DEBUG
#endif

#ifndef apr_uintptr_t
#define apr_uintptr_t apr_uint64_t
#endif

#ifndef APR_UINT32_MAX
#define APR_UINT32_MAX UINT32_MAX
#endif

#ifndef APR_INT64_MAX
#define APR_INT64_MAX INT64_MAX
#endif

#ifndef apr_time_from_msec
#define apr_time_from_msec(msec) ((apr_time_t)(msec) * 1000)
#endif

#define oidc_log(r, level, fmt, ...)                                                                                   \
	ap_log_rerror(APLOG_MARK, level, 0, r, "%s: %s", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
#define oidc_slog(s, level, fmt, ...)                                                                                  \
	ap_log_error(APLOG_MARK, level, 0, s, "%s: %s", __FUNCTION__,                                                  \
		     apr_psprintf(s->process->pconf, fmt, ##__VA_ARGS__))

#define oidc_debug(r, fmt, ...) oidc_log(r, OIDC_DEBUG, fmt, ##__VA_ARGS__)
#define oidc_warn(r, fmt, ...) oidc_log(r, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define oidc_info(r, fmt, ...) oidc_log(r, APLOG_INFO, fmt, ##__VA_ARGS__)
#define oidc_error(r, fmt, ...) oidc_log(r, APLOG_ERR, fmt, ##__VA_ARGS__)

#define oidc_sdebug(s, fmt, ...) oidc_slog(s, OIDC_DEBUG, fmt, ##__VA_ARGS__)
#define oidc_swarn(s, fmt, ...) oidc_slog(s, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define oidc_serror(s, fmt, ...) oidc_slog(s, APLOG_ERR, fmt, ##__VA_ARGS__)

#ifndef NAMEVER
#define NAMEVERSION "mod_auth_openidc-0.0.0"
#else
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define NAMEVERSION TOSTRING(NAMEVER)
#endif

#endif /* MOD_AUTH_OPENIDC_CONST_H_ */
