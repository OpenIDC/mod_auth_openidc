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
 * Copyright (C) 2017-2023 ZmartZone Holding BV
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
#  include "config.h"
#  undef PACKAGE_NAME
#  undef PACKAGE_STRING
#  undef PACKAGE_TARNAME
#  undef PACKAGE_VERSION
#  undef PACKAGE_BUGREPORT
#endif

#include <stdint.h>
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

#ifdef __STDC_LIB_EXT1__
#define _oidc_memset(b, c, __len) memset_s(b, __len, c, __len)
#define _oidc_memcpy(__dst, __src, __n) memcpy_s(__dst, __src, __n)
#define _oidc_strcpy(__dst, __src) strcpy_s(__dst, __src)
#else
#define _oidc_memset(b, c, __len) memset(b, c, __len)
#define _oidc_memcpy(__dst, __src, __n) memcpy(__dst, __src, __n)
#define _oidc_strcpy(__dst, __src) strcpy(__dst, __src)
#endif

#define _oidc_strlen(s) ( s ? strlen(s) : 0 )
#define _oidc_strcmp(a, b) ( (a && b) ? apr_strnatcmp(a, b) : -1 )
#define _oidc_strncmp(a, b, size) ( (a && b) ? strncmp(a, b, size) : -1 )

#define _oidc_str_to_int(s) (s ? (int)strtol(s, NULL, 10) : 0)

#endif /* MOD_AUTH_OPENIDC_CONST_H_ */
