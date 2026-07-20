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

#include "state.h"
#include "jose.h"
#include "mod_auth_openidc.h"
#include "proto/proto.h"
#include "util/util.h"

/*
 * return the name for the state cookie
 */
char *oidc_state_cookie_name(request_rec *r, const char *state) {
	return apr_psprintf(r->pool, "%s%s", oidc_cfg_dir_state_cookie_prefix_get(r), state);
}

/*
 * calculates a hash value based on request fingerprint plus a provided nonce string.
 */
char *oidc_state_browser_fingerprint(request_rec *r, const oidc_cfg_t *c, const char *nonce) {

	/* helper to hold header values */
	const char *value = NULL;
	/* concatenated hash input */
	char *input = "";
	unsigned char *hash = NULL;
	unsigned int hash_len = 0;
	oidc_jose_error_t err;
	char *result = NULL;

	oidc_debug(r, "enter");

	if (oidc_cfg_state_input_headers_get(c) & OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR) {
		/* get the X-FORWARDED-FOR header value  */
		value = oidc_http_hdr_in_x_forwarded_for_get(r);
		/* if we have a value for this header, concat it to the hash input */
		if (value != NULL)
			input = apr_pstrcat(r->pool, input, value, NULL);
	}

	if (oidc_cfg_state_input_headers_get(c) & OIDC_STATE_INPUT_HEADERS_USER_AGENT) {
		/* get the USER-AGENT header value  */
		value = oidc_http_hdr_in_user_agent_get(r);
		/* if we have a value for this header, concat it to the hash input */
		if (value != NULL)
			input = apr_pstrcat(r->pool, input, value, NULL);
	}

	/* get the remote client IP address or host name */

	/* concat the nonce parameter to the hash input */
	input = apr_pstrcat(r->pool, input, nonce, NULL);

	/* calculate the hash output */
	if (oidc_jose_hash_bytes(r->pool, OIDC_JOSE_ALG_SHA256, (const unsigned char *)input,
				 (unsigned int)_oidc_strlen(input), &hash, &hash_len, &err) == FALSE) {
		oidc_error(r, "oidc_jose_hash_bytes failed: %s", oidc_jose_e2s(r->pool, err));
		return NULL;
	}

	/* base64url-encode the resulting hash and return it */
	oidc_util_base64url_encode(r, &result, (const char *)hash, hash_len, OIDC_BASE64URL_PADDING_STRIP);

	return result;
}

// element in a list of state cookies
typedef struct oidc_state_cookies_t {
	char *name;
	apr_time_t timestamp;
	struct oidc_state_cookies_t *next;
} oidc_state_cookies_t;

/*
 * delete superfluous state cookies i.e. exceeding the maximum, starting with the oldest ones
 */
static int oidc_state_cookies_delete_oldest(request_rec *r, const oidc_cfg_t *c, int number_of_valid_state_cookies,
					    int max_number_of_state_cookies, oidc_state_cookies_t *first) {
	oidc_state_cookies_t *cur = NULL;
	oidc_state_cookies_t *prev = NULL;
	oidc_state_cookies_t *prev_oldest = NULL;
	oidc_state_cookies_t *oldest = NULL;
	// loop over the list of state cookies, deleting the oldest one until we reach an acceptable number
	while (number_of_valid_state_cookies >= max_number_of_state_cookies) {
		oldest = first;
		prev_oldest = NULL;
		prev = first;
		cur = first ? first->next : NULL;
		// find the oldest state cookie in the list (stored in "oldest")
		while (cur) {
			if (cur->timestamp < oldest->timestamp) {
				oldest = cur;
				prev_oldest = prev;
			}
			prev = cur;
			cur = cur->next;
		}
		if (oldest) {
			oidc_warn(r, "deleting oldest state cookie: %s (time until expiry %" APR_TIME_T_FMT " seconds)",
				  oldest->name, apr_time_sec(oldest->timestamp - apr_time_now()));
			oidc_http_set_cookie(r, oldest->name, "", 0, OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r));
			if (prev_oldest)
				prev_oldest->next = oldest->next;
			else
				first = first->next;
		}
		number_of_valid_state_cookies--;
	}
	return number_of_valid_state_cookies;
}

/*
 * append a state cookie record to the tail of the linked list of still-valid cookies
 */
static void oidc_state_cookies_list_append(request_rec *r, oidc_state_cookies_t **first, oidc_state_cookies_t **last,
					   char *name, apr_time_t ts) {
	if (*first == NULL) {
		*first = apr_pcalloc(r->pool, sizeof(oidc_state_cookies_t));
		*last = *first;
	} else {
		(*last)->next = apr_pcalloc(r->pool, sizeof(oidc_state_cookies_t));
		*last = (*last)->next;
	}
	(*last)->name = name;
	(*last)->timestamp = ts;
	(*last)->next = NULL;
}

/*
 * process a single state cookie: skip if it's the current one, delete if expired or undecodable,
 * otherwise append it to the list of valid cookies; returns 1 if the cookie was kept
 */
static int oidc_state_cookies_process_one(request_rec *r, const oidc_cfg_t *c, char *cookieName, const char *value,
					  const char *currentCookieName, oidc_state_cookies_t **first,
					  oidc_state_cookies_t **last) {
	/* never touch the cookie associated with the request currently being processed */
	if ((currentCookieName != NULL) && (_oidc_strcmp(cookieName, currentCookieName) == 0))
		return 0;

	oidc_proto_state_t *proto_state = oidc_proto_state_from_cookie(r, c, value);
	if (proto_state == NULL) {
		oidc_warn(r, "state cookie could not be retrieved/decoded, deleting: %s", cookieName);
		oidc_http_set_cookie(r, cookieName, "", 0, OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r));
		return 0;
	}

	int kept = 0;
	oidc_json_int_t ts = oidc_proto_state_get_timestamp(proto_state);
	if (apr_time_now() > ts + apr_time_from_sec(oidc_cfg_state_timeout_get(c))) {
		oidc_warn(r, "state (%s) has expired (original_url=%s)", cookieName,
			  oidc_proto_state_get_original_url(proto_state));
		oidc_http_set_cookie(r, cookieName, "", 0, OIDC_HTTP_COOKIE_SAMESITE_NONE(c, r));
	} else {
		oidc_state_cookies_list_append(r, first, last, cookieName, ts);
		kept = 1;
	}

	oidc_proto_state_destroy(proto_state);
	return kept;
}

/*
 * parse a single "<name>=<value>" cookie token and dispatch processing if it is a state cookie;
 * returns 1 if the token was kept as a valid state cookie
 */
static int oidc_state_cookies_parse_token(request_rec *r, const oidc_cfg_t *c, char *cookie,
					  const char *currentCookieName, oidc_state_cookies_t **first,
					  oidc_state_cookies_t **last) {
	while (*cookie == OIDC_CHAR_SPACE)
		cookie++;

	if (_oidc_strstr(cookie, oidc_cfg_dir_state_cookie_prefix_get(r)) != cookie)
		return 0;

	char *cookieName = cookie;
	/* stop at the string terminator as well as at '='; the previous "cookie != NULL" condition could
	 * never be false (cookie is only incremented) so a state-prefixed token without a '=' would scan
	 * past the end of the buffer (out-of-bounds read, and a subsequent out-of-bounds NUL write) */
	while ((*cookie != '\0') && (*cookie != OIDC_CHAR_EQUAL))
		cookie++;
	if (*cookie != OIDC_CHAR_EQUAL)
		return 0;

	*cookie = '\0';
	cookie++;

	return oidc_state_cookies_process_one(r, c, cookieName, cookie, currentCookieName, first, last);
}

/*
 * clean state cookies that have expired i.e. for outstanding requests that will never return
 * successfully and return the number of remaining valid cookies/outstanding-requests while
 * doing so
 */
int oidc_state_cookies_clean_expired(request_rec *r, const oidc_cfg_t *c, const char *currentCookieName,
				     int delete_oldest) {
	int number_of_valid_state_cookies = 0;
	oidc_state_cookies_t *first = NULL;
	oidc_state_cookies_t *last = NULL;
	char *tokenizerCtx = NULL;
	char *cookies = apr_pstrdup(r->pool, oidc_http_hdr_in_cookie_get(r));

	if (cookies == NULL)
		goto out;

	char *cookie = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &tokenizerCtx);
	while (cookie != NULL) {
		number_of_valid_state_cookies +=
		    oidc_state_cookies_parse_token(r, c, cookie, currentCookieName, &first, &last);
		cookie = apr_strtok(NULL, OIDC_STR_SEMI_COLON, &tokenizerCtx);
	}

out:

	if (delete_oldest > 0)
		number_of_valid_state_cookies = oidc_state_cookies_delete_oldest(
		    r, c, number_of_valid_state_cookies, oidc_cfg_max_number_of_state_cookies_get(c), first);

	return number_of_valid_state_cookies;
}
