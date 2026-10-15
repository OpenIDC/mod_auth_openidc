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

#include "util/jwt_compat.h"
#include "util/util.h"
#include "util/util_cfg.h"

/* Encryption-change release implementation. In ordinary releases, keep these
 * entry points as no-op hooks: create_key returns DECLINED, and verify clears
 * needs_rewrite and returns FALSE; session_loaded returns TRUE without persisting.
 * Callers and the normal crypto path stay put.
 * Retire the migration directives and tests with this implementation. */

/* Temporary SHA-256 derivation used only by the rolling-upgrade helpers below. */
static apr_byte_t oidc_util_jwt_legacy_keys(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
					 oidc_crypto_passphrase_t *legacy) {
	if ((passphrase->secret1 == NULL) || (_oidc_strlen(passphrase->secret1) == 0))
		return FALSE;
	*legacy = *passphrase;
	unsigned char *key = NULL;
	unsigned int key_len = 0;
	oidc_jose_error_t err;
	if ((oidc_jose_hash_bytes(r->pool, OIDC_JOSE_ALG_SHA256, (const unsigned char *)legacy->secret1,
				 (unsigned int)_oidc_strlen(legacy->secret1), &key, &key_len, &err) == FALSE) ||
	    (key_len != sizeof(legacy->derived_key1)))
		return FALSE;
	memcpy(legacy->derived_key1, key, key_len);
	legacy->derived_key1_set = TRUE;
	if (legacy->secret2 != NULL) {
		if ((oidc_jose_hash_bytes(r->pool, OIDC_JOSE_ALG_SHA256, (const unsigned char *)legacy->secret2,
					 (unsigned int)_oidc_strlen(legacy->secret2), &key, &key_len, &err) == FALSE) ||
		    (key_len != sizeof(legacy->derived_key2)))
			return FALSE;
		memcpy(legacy->derived_key2, key, key_len);
		legacy->derived_key2_set = TRUE;
	}
	return TRUE;
}

/*
 * Temporary read compatibility for pre-PBKDF2 internal JWEs. The configuration
 * gate belongs to the caller. Remove with the rolling-upgrade controls.
 */
static apr_byte_t oidc_util_jwt_verify_legacy(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
					       const char *s_json, char **s_payload) {
	int separators = 0;
	for (const char *p = s_json; *p != '\0'; p++)
		if (*p == '.')
			separators++;
	oidc_crypto_passphrase_t legacy;
	if (oidc_util_jwt_legacy_keys(r, passphrase, &legacy) == FALSE)
		return FALSE;
	/* Older writers omitted this fixed protected header, but included it in
	 * the GCM authentication tag. Restore it before authenticated decryption. */
	const char *token = s_json;
	if (separators == 2)
		token = apr_pstrcat(r->pool, "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..", token, NULL);
	apr_byte_t verified = oidc_util_jwt_verify(r, &legacy, token, s_payload);
	/* Older cjose releases serialize the same header with JSON spaces.
	 * Its exact bytes are authenticated, so try that historical encoding too. */
	if ((verified == FALSE) && (separators == 2)) {
		token = apr_pstrcat(r->pool, "eyJhbGciOiAiZGlyIiwgImVuYyI6ICJBMjU2R0NNIn0..", s_json, NULL);
		verified = oidc_util_jwt_verify(r, &legacy, token, s_payload);
	}
	if (verified == FALSE) {
		oidc_error(r, "could not verify legacy internal JWT");
		return FALSE;
	}
	return TRUE;
}

/* Optional replacement for the normal encryption key. A disabled hook does
 * nothing; an enabled failure must stop the write rather than change formats. */
oidc_jwt_compat_result_t oidc_jwt_compat_create_key(request_rec *r,
		const oidc_crypto_passphrase_t *passphrase, oidc_jwk_t **jwk) {
	const oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	if (!oidc_cfg_crypto_legacy_write_get(c))
		return OIDC_JWT_COMPAT_DECLINED;
	if ((passphrase->secret1 == NULL) || (_oidc_strlen(passphrase->secret1) == 0) ||
	    !oidc_util_key_symmetric_create(r, passphrase->secret1, 0, OIDC_JOSE_ALG_SHA256, FALSE, jwk) ||
	    (*jwk == NULL))
		return OIDC_JWT_COMPAT_ERROR;
	return OIDC_JWT_COMPAT_HANDLED;
}

/* Optional fallback after normal verification fails. All acceptance and rewrite
 * policy belongs here; the session layer only persists after validation. */
apr_byte_t oidc_jwt_compat_verify(request_rec *r, const oidc_crypto_passphrase_t *passphrase,
		const char *token, char **payload, apr_byte_t *needs_rewrite) {
	const oidc_cfg_t *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	if (needs_rewrite != NULL)
		*needs_rewrite = FALSE;
	if (!oidc_cfg_crypto_legacy_read_get(c))
		return FALSE;
	if (!oidc_util_jwt_verify_legacy(r, passphrase, token, payload))
		return FALSE;
	if (needs_rewrite != NULL)
		*needs_rewrite = !oidc_cfg_crypto_legacy_write_get(c);
	return TRUE;
}

/* Preserve the validated payload, identifier, and expiry. This migration changes
 * encryption only; no session-payload format conversion or version bump is needed. */
apr_byte_t oidc_jwt_compat_session_loaded(request_rec *r, oidc_session_t *z,
					 oidc_jwt_compat_persist_fn persist) {
	if (!z->needs_rewrite)
		return TRUE;
	if (persist(r, z, OIDC_SESSION_SAVE_UPDATE) == FALSE)
		return FALSE;
	z->needs_rewrite = FALSE;
	return TRUE;
}
