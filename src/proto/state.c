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

#include "proto/proto.h"
#include "util/util.h"

#define OIDC_PROTO_STATE_ISSUER "i"
#define OIDC_PROTO_STATE_ORIGINAL_URL "ou"
#define OIDC_PROTO_STATE_ORIGINAL_METHOD "om"
#define OIDC_PROTO_STATE_RESPONSE_MODE "rm"
#define OIDC_PROTO_STATE_RESPONSE_TYPE "rt"
#define OIDC_PROTO_STATE_NONCE "n"
#define OIDC_PROTO_STATE_TIMESTAMP "t"
#define OIDC_PROTO_STATE_PROMPT "pr"
#define OIDC_PROTO_STATE_PKCE_STATE "ps"
#define OIDC_PROTO_STATE_STATE "s"

/*
 * retrieve a string from the state object
 */
static const char *oidc_proto_state_get_string_value(oidc_proto_state_t *proto_state, const char *name) {
	json_t *v = json_object_get(proto_state, name);
	return v ? json_string_value(v) : NULL;
}

/*
 * set a string value in the state object
 */
static void oidc_proto_state_set_string_value(oidc_proto_state_t *proto_state, const char *name, const char *value) {
	json_object_set_new(proto_state, name, json_string(value));
}

/*
 * create a new state object
 */
oidc_proto_state_t *oidc_proto_state_new() {
	return json_object();
}

/*
 * free up resources allocated for a state object
 */
void oidc_proto_state_destroy(oidc_proto_state_t *proto_state) {
	json_decref(proto_state);
}

/*
 * serialize a state object to a string (for logging/debugging purposes)
 */
char *oidc_proto_state_to_string(request_rec *r, oidc_proto_state_t *proto_state) {
	return oidc_util_json_encode(r->pool, proto_state, JSON_COMPACT);
}

/*
 * retrieve the issuer value from the state object
 */
const char *oidc_proto_state_get_issuer(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_ISSUER);
}

/*
 * retrieve the nonce value from the state object
 */
const char *oidc_proto_state_get_nonce(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_NONCE);
}

/*
 * retrieve the timestamp value from the state object
 */
apr_time_t oidc_proto_state_get_timestamp(oidc_proto_state_t *proto_state) {
	json_t *v = json_object_get(proto_state, OIDC_PROTO_STATE_TIMESTAMP);
	return v ? apr_time_from_sec(json_integer_value(v)) : -1;
}

/*
 * retrieve the prompt value from the state object
 */
const char *oidc_proto_state_get_prompt(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_PROMPT);
}

/*
 * retrieve the response type value from the state object
 */
const char *oidc_proto_state_get_response_type(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_RESPONSE_TYPE);
}

/*
 * retrieve the response mode value from the state object
 */
const char *oidc_proto_state_get_response_mode(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_RESPONSE_MODE);
}

/*
 * retrieve the original URL value from the state object
 */
const char *oidc_proto_state_get_original_url(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_ORIGINAL_URL);
}

/*
 * retrieve the original HTTP method value from the state object
 */
const char *oidc_proto_state_get_original_method(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_ORIGINAL_METHOD);
}

/*
 * retrieve the state (URL parameter) value from the state object
 */
const char *oidc_proto_state_get_state(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_STATE);
}

/*
 * retrieve the PKCE state value from the state object
 */
const char *oidc_proto_state_get_pkce_state(oidc_proto_state_t *proto_state) {
	return oidc_proto_state_get_string_value(proto_state, OIDC_PROTO_STATE_PKCE_STATE);
}

/*
 * set the state (URL parameter) value in the state object
 */
void oidc_proto_state_set_state(oidc_proto_state_t *proto_state, const char *state) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_STATE, state);
}

/*
 * set the issuer value in the state object
 */
void oidc_proto_state_set_issuer(oidc_proto_state_t *proto_state, const char *issuer) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_ISSUER, issuer);
}

/*
 * set the original URL value in the state object
 */
void oidc_proto_state_set_original_url(oidc_proto_state_t *proto_state, const char *original_url) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_ORIGINAL_URL, original_url);
}

/*
 * set the original HTTP method value in the state object
 */
void oidc_proto_state_set_original_method(oidc_proto_state_t *proto_state, const char *original_method) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_ORIGINAL_METHOD, original_method);
}

/*
 * set the response mode value in the state object
 */
void oidc_proto_state_set_response_mode(oidc_proto_state_t *proto_state, const char *response_mode) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_RESPONSE_MODE, response_mode);
}

/*
 * set the response type value in the state object
 */
void oidc_proto_state_set_response_type(oidc_proto_state_t *proto_state, const char *response_type) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_RESPONSE_TYPE, response_type);
}

/*
 * set the nonce value in the state object
 */
void oidc_proto_state_set_nonce(oidc_proto_state_t *proto_state, const char *nonce) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_NONCE, nonce);
}

/*
 * set the prompt value in the state object
 */
void oidc_proto_state_set_prompt(oidc_proto_state_t *proto_state, const char *prompt) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_PROMPT, prompt);
}

/*
 * set the PKCE state value in the state object
 */
void oidc_proto_state_set_pkce_state(oidc_proto_state_t *proto_state, const char *pkce_state) {
	oidc_proto_state_set_string_value(proto_state, OIDC_PROTO_STATE_PKCE_STATE, pkce_state);
}

/*
 * set the current time as timestamp value in the state object
 */
void oidc_proto_state_set_timestamp_now(oidc_proto_state_t *proto_state) {
	json_object_set_new(proto_state, OIDC_PROTO_STATE_TIMESTAMP, json_integer(apr_time_sec(apr_time_now())));
}

/*
 * parse a state object from the provided cookie value
 */
oidc_proto_state_t *oidc_proto_state_from_cookie(request_rec *r, oidc_cfg_t *c, const char *cookieValue) {
	char *s_payload = NULL;
	json_t *result = NULL;
	oidc_util_jwt_verify(r, oidc_cfg_crypto_passphrase_get(c), cookieValue, &s_payload);
	oidc_util_json_decode_object(r, s_payload, &result);
	return result;
}

/*
 * serialize a state object to a signed JWT cookie value
 */
char *oidc_proto_state_to_cookie(request_rec *r, oidc_cfg_t *c, oidc_proto_state_t *proto_state) {
	char *cookieValue = NULL;
	oidc_util_jwt_create(r, oidc_cfg_crypto_passphrase_get(c),
			     oidc_util_json_encode(r->pool, proto_state, JSON_COMPACT), &cookieValue);
	return cookieValue;
}
