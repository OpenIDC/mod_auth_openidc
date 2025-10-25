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

#include "util/util.h"

#ifdef USE_URANDOM

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEV_RANDOM "/dev/urandom"

#endif

/*
 * generate a number of random bytes, either using libapr or urandom (no per-request logging)
 */
static apr_byte_t _oidc_util_rand(unsigned char *buf, apr_size_t length) {
	apr_byte_t rv = FALSE;

#ifndef USE_URANDOM

	rv = (apr_generate_random_bytes(buf, length) == APR_SUCCESS);

#else

	int fd = -1;

	do {
		apr_ssize_t rc;

		if (fd == -1) {
			fd = open(DEV_RANDOM, O_RDONLY);
			if (fd == -1)
				return FALSE;
		}

		do {
			rc = read(fd, buf, length);
		} while (rc == -1 && errno == EINTR);

		if (rc < 0) {
			int errnum = errno;
			close(fd);
			return FALSE;
		} else if (rc == 0) {
			close(fd);
			fd = -1; /* force open() again */
		} else {
			buf += rc;
			length -= rc;
		}
	} while (length > 0);

	close(fd);

	rv = TRUE;

#endif

	return rv;
}

/*
 * generate a number of random bytes, either using libapr or urandom
 */
static apr_byte_t _oidc_util_rand_bytes(request_rec *r, unsigned char *buf, apr_size_t len) {
	apr_byte_t rv = TRUE;
#ifndef USE_URANDOM
	const char *gen = "apr";
#else
	const char *gen = DEV_RANDOM;
#endif
	oidc_debug(r, "use [%s] for generating %" APR_SIZE_T_FMT " random bytes", gen, len);
	rv = _oidc_util_rand(buf, len);
	oidc_debug(r, "return: %d", rv);
	return rv;
}

/*
 * generate a random integer value in the specified modulo range
 */
unsigned int oidc_util_rand_int(unsigned int mod) {
	unsigned int v;
	_oidc_util_rand((unsigned char *)&v, sizeof(v));
	return v % mod;
}

/*
 * generate a random string of base64url encoded characters, representing len bytes
 */
apr_byte_t oidc_util_rand_str(request_rec *r, char **str, int len) {
	unsigned char *bytes = apr_pcalloc(r->pool, len);
	if (_oidc_util_rand_bytes(r, bytes, len) != TRUE) {
		oidc_error(r, "_oidc_util_rand_bytes returned an error");
		return FALSE;
	}
	if (oidc_util_base64url_encode(r, str, (const char *)bytes, len, TRUE) <= 0) {
		oidc_error(r, "oidc_base64url_encode returned an error");
		return FALSE;
	}
	return TRUE;
}

/*
 * generate a random string of (lowercase) hexadecimal characters, representing len bytes
 */
char *oidc_util_rand_hex_str(request_rec *r, int len) {
	unsigned char *bytes = apr_pcalloc(r->pool, len);
	if (_oidc_util_rand_bytes(r, bytes, len) != TRUE) {
		oidc_error(r, "_oidc_util_rand_bytes returned an error");
		return NULL;
	}
	return oidc_util_hex_encode(r, bytes, len);
}
