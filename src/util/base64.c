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

#include <apr_base64.h>
/*
 * base64url encode a string
 */
int oidc_util_base64url_encode(request_rec *r, char **dst, const char *src, int src_len, int remove_padding) {
	if ((src == NULL) || (src_len <= 0)) {
		oidc_error(r, "not encoding anything; src=NULL and/or src_len<1");
		return -1;
	}
	unsigned int enc_len = apr_base64_encode_len(src_len);
	char *enc = apr_palloc(r->pool, enc_len);
	apr_base64_encode(enc, src, src_len);
	unsigned int i = 0;
	while (enc[i] != '\0') {
		if (enc[i] == '+')
			enc[i] = '-';
		if (enc[i] == '/')
			enc[i] = '_';
		if (enc[i] == '=')
			enc[i] = ',';
		i++;
	}
	if (remove_padding) {
		/* remove /0 and padding */
		if (enc_len > 0)
			enc_len--;
		if ((enc_len > 0) && (enc[enc_len - 1] == ','))
			enc_len--;
		if ((enc_len > 0) && (enc[enc_len - 1] == ','))
			enc_len--;
		enc[enc_len] = '\0';
	}
	*dst = enc;
	return enc_len;
}

/*
 * parse a base64 encoded binary value from the provided string
 */
char *oidc_util_base64_decode(apr_pool_t *pool, const char *input, char **output, int *output_len) {
	if ((input == NULL) || (output == NULL) || (output_len == 0))
		return apr_psprintf(pool, "base64-decoding of failed: invalid parameters");

	*output = apr_pcalloc(pool, apr_base64_decode_len(input));
	*output_len = apr_base64_decode(*output, input);

	if (*output_len <= 0)
		return apr_psprintf(pool, "base64-decoding of \"%s\" failed", input);

	return NULL;
}

/*
 * base64url decode a string
 */
int oidc_util_base64url_decode(apr_pool_t *pool, char **dst, const char *src) {
	if (src == NULL) {
		return -1;
	}
	char *dec = apr_pstrdup(pool, src);
	int i = 0;
	while (dec[i] != '\0') {
		if (dec[i] == '-')
			dec[i] = '+';
		if (dec[i] == '_')
			dec[i] = '/';
		if (dec[i] == ',')
			dec[i] = '=';
		i++;
	}
	switch (_oidc_strlen(dec) % 4) {
	case 0:
		break;
	case 2:
		dec = apr_pstrcat(pool, dec, "==", NULL);
		break;
	case 3:
		dec = apr_pstrcat(pool, dec, "=", NULL);
		break;
	default:
		return 0;
	}

	int dlen = -1;
	oidc_util_base64_decode(pool, dec, dst, &dlen);
	return dlen;
}
