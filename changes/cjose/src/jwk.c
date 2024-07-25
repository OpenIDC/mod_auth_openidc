/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#define OPENSSL_API_COMPAT 0x10000000L

#include "include/jwk_int.h"
#include "include/util_int.h"

#include <cjose/base64.h>
#include <cjose/util.h>

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// internal data structures

static const char CJOSE_JWK_EC_P_256_STR[] = "P-256";
static const char CJOSE_JWK_EC_P_384_STR[] = "P-384";
static const char CJOSE_JWK_EC_P_521_STR[] = "P-521";
static const char CJOSE_JWK_KTY_STR[] = "kty";
static const char CJOSE_JWK_KID_STR[] = "kid";
static const char CJOSE_JWK_KTY_EC_STR[] = "EC";
static const char CJOSE_JWK_KTY_RSA_STR[] = "RSA";
static const char CJOSE_JWK_KTY_OCT_STR[] = "oct";
static const char CJOSE_JWK_CRV_STR[] = "crv";
static const char CJOSE_JWK_X_STR[] = "x";
static const char CJOSE_JWK_Y_STR[] = "y";
static const char CJOSE_JWK_D_STR[] = "d";
static const char CJOSE_JWK_N_STR[] = "n";
static const char CJOSE_JWK_E_STR[] = "e";
static const char CJOSE_JWK_P_STR[] = "p";
static const char CJOSE_JWK_Q_STR[] = "q";
static const char CJOSE_JWK_DP_STR[] = "dp";
static const char CJOSE_JWK_DQ_STR[] = "dq";
static const char CJOSE_JWK_QI_STR[] = "qi";
static const char CJOSE_JWK_K_STR[] = "k";

static const char *JWK_KTY_NAMES[] = { CJOSE_JWK_KTY_RSA_STR, CJOSE_JWK_KTY_EC_STR, CJOSE_JWK_KTY_OCT_STR };

void _cjose_jwk_rsa_get(RSA *rsa, BIGNUM **rsa_n, BIGNUM **rsa_e, BIGNUM **rsa_d)
{
    if (rsa == NULL)
        return;
#if defined(CJOSE_OPENSSL_11X)
    RSA_get0_key(rsa, (const BIGNUM **)rsa_n, (const BIGNUM **)rsa_e, (const BIGNUM **)rsa_d);
#else
    *rsa_n = rsa->n;
    *rsa_e = rsa->e;
    *rsa_d = rsa->d;
#endif
}

bool _cjose_jwk_rsa_set(RSA *rsa, uint8_t *n, size_t n_len, uint8_t *e, size_t e_len, uint8_t *d, size_t d_len)
{
    BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;

    // RSA_set0_key doesn't work without each of those on the first call!
    if ((n == NULL) || (n_len <= 0) || (e == NULL) || (e_len <= 0))
        return false;

    if (n && n_len > 0)
        rsa_n = BN_bin2bn(n, n_len, NULL);
    if (e && e_len > 0)
        rsa_e = BN_bin2bn(e, e_len, NULL);
    if (d && d_len > 0)
        rsa_d = BN_bin2bn(d, d_len, NULL);

#if defined(CJOSE_OPENSSL_11X)
    return RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d) == 1;
#else
    rsa->n = rsa_n;
    rsa->e = rsa_e;
    rsa->d = rsa_d;
    return true;
#endif
}

void _cjose_jwk_rsa_get_factors(RSA *rsa, BIGNUM **p, BIGNUM **q)
{
#if defined(CJOSE_OPENSSL_11X)
    RSA_get0_factors(rsa, (const BIGNUM **)p, (const BIGNUM **)q);
#else
    *p = rsa->p;
    *q = rsa->q;
#endif
}

void _cjose_jwk_rsa_set_factors(RSA *rsa, uint8_t *p, size_t p_len, uint8_t *q, size_t q_len)
{
    BIGNUM *rsa_p = NULL, *rsa_q = NULL;

    if (p && p_len > 0)
        rsa_p = BN_bin2bn(p, p_len, NULL);
    if (q && q_len > 0)
        rsa_q = BN_bin2bn(q, q_len, NULL);

#if defined(CJOSE_OPENSSL_11X)
    RSA_set0_factors(rsa, rsa_p, rsa_q);
#else
    rsa->p = rsa_p;
    rsa->q = rsa_q;
#endif
}

void _cjose_jwk_rsa_get_crt(RSA *rsa, BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp)
{
#if defined(CJOSE_OPENSSL_11X)
    RSA_get0_crt_params(rsa, (const BIGNUM **)dmp1, (const BIGNUM **)dmq1, (const BIGNUM **)iqmp);
#else
    *dmp1 = rsa->dmp1;
    *dmq1 = rsa->dmq1;
    *iqmp = rsa->iqmp;
#endif
}

void _cjose_jwk_rsa_set_crt(
    RSA *rsa, uint8_t *dmp1, size_t dmp1_len, uint8_t *dmq1, size_t dmq1_len, uint8_t *iqmp, size_t iqmp_len)
{
    BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;

    if (dmp1 && dmp1_len > 0)
        rsa_dmp1 = BN_bin2bn(dmp1, dmp1_len, NULL);
    if (dmq1 && dmq1_len > 0)
        rsa_dmq1 = BN_bin2bn(dmq1, dmq1_len, NULL);
    if (iqmp && iqmp_len > 0)
        rsa_iqmp = BN_bin2bn(iqmp, iqmp_len, NULL);

#if defined(CJOSE_OPENSSL_11X)
    RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp);
#else
    rsa->dmp1 = rsa_dmp1;
    rsa->dmq1 = rsa_dmq1;
    rsa->iqmp = rsa_iqmp;
#endif
}

// interface functions -- Generic

const char *cjose_jwk_name_for_kty(cjose_jwk_kty_t kty, cjose_err *err)
{
    if (0 == kty || CJOSE_JWK_KTY_OCT < kty)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    return JWK_KTY_NAMES[kty - CJOSE_JWK_KTY_RSA];
}

cjose_jwk_t *cjose_jwk_retain(cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    ++(jwk->retained);
    // TODO: check for overflow

    return jwk;
}

bool cjose_jwk_release(cjose_jwk_t *jwk)
{
    if (!jwk)
    {
        return false;
    }

    --(jwk->retained);
    if (0 == jwk->retained)
    {
        cjose_get_dealloc()(jwk->kid);
        jwk->kid = NULL;

        // assumes freefunc is set
        if (NULL != jwk->fns->free)
        {
            jwk->fns->free(jwk);
        }
        jwk = NULL;
    }

    return (NULL != jwk);
}

cjose_jwk_kty_t cjose_jwk_get_kty(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return -1;
    }

    return jwk->kty;
}
size_t cjose_jwk_get_keysize(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return 0;
    }
    return jwk->keysize;
}

void *cjose_jwk_get_keydata(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    return jwk->keydata;
}

const char *cjose_jwk_get_kid(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    return jwk->kid;
}

bool cjose_jwk_set_kid(cjose_jwk_t *jwk, const char *kid, size_t len, cjose_err *err)
{
    if (!jwk || !kid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    if (jwk->kid)
    {
        cjose_get_dealloc()(jwk->kid);
    }
    jwk->kid = (char *)cjose_get_alloc()(len + 1);
    if (!jwk->kid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    strncpy(jwk->kid, kid, len + 1);
    return true;
}

char *cjose_jwk_to_json(const cjose_jwk_t *jwk, bool priv, cjose_err *err)
{
    char *result = NULL;

    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    json_t *json = json_object(), *field = NULL;
    if (!json)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }

    // set kty
    const char *kty = cjose_jwk_name_for_kty(jwk->kty, err);
    field = json_string(kty);
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }
    json_object_set(json, "kty", field);
    json_decref(field);
    field = NULL;

    // set kid
    if (NULL != jwk->kid)
    {
        field = json_string(jwk->kid);
        if (!field)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto to_json_cleanup;
        }
        json_object_set(json, CJOSE_JWK_KID_STR, field);
        json_decref(field);
        field = NULL;
    }

    // set public fields
    if (jwk->fns->public_json && !jwk->fns->public_json(jwk, json, err))
    {
        goto to_json_cleanup;
    }

    // set private fields
    if (priv && jwk->fns->private_json && !jwk->fns->private_json(jwk, json, err))
    {
        goto to_json_cleanup;
    }

    // generate the string ...
    char *str_jwk = json_dumps(json, JSON_ENCODE_ANY | JSON_COMPACT | JSON_PRESERVE_ORDER);
    if (!str_jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }
    result = _cjose_strndup(str_jwk, -1, err);
    if (!result)
    {
        cjose_get_dealloc()(str_jwk);
        goto to_json_cleanup;
    }
    cjose_get_dealloc()(str_jwk);

to_json_cleanup:
    if (json)
    {
        json_decref(json);
        json = NULL;
    }
    if (field)
    {
        json_decref(field);
        field = NULL;
    }

    return result;
}

//////////////// Octet String ////////////////
// internal data & functions -- Octet String

static void _oct_free(cjose_jwk_t *jwk);
static bool _oct_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _oct_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable OCT_FNTABLE = { _oct_free, _oct_public_fields, _oct_private_fields };

static cjose_jwk_t *_oct_new(uint8_t *buffer, size_t keysize, cjose_err *err)
{
    cjose_jwk_t *jwk = (cjose_jwk_t *)cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
    }
    else
    {
        memset(jwk, 0, sizeof(cjose_jwk_t));
        jwk->retained = 1;
        jwk->kty = CJOSE_JWK_KTY_OCT;
        jwk->keysize = keysize;
        jwk->keydata = buffer;
        jwk->fns = &OCT_FNTABLE;
    }

    return jwk;
}

static void _oct_free(cjose_jwk_t *jwk)
{
    uint8_t *buffer = (uint8_t *)jwk->keydata;
    jwk->keydata = NULL;
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }
    cjose_get_dealloc()(jwk);
}

static bool _oct_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err) { return true; }

static bool _oct_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    json_t *field = NULL;
    char *k = NULL;
    size_t klen = 0;
    uint8_t *keydata = (uint8_t *)jwk->keydata;
    size_t keysize = jwk->keysize / 8;

    if (!cjose_base64url_encode(keydata, keysize, &k, &klen, err))
    {
        return false;
    }

    field = _cjose_json_stringn(k, klen, err);
    cjose_get_dealloc()(k);
    k = NULL;
    if (!field)
    {
        return false;
    }
    json_object_set(json, "k", field);
    json_decref(field);

    return true;
}

// interface functions -- Octet String

cjose_jwk_t *cjose_jwk_create_oct_random(size_t keysize, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *buffer = NULL;

    if (0 == keysize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_oct_failed;
    }

    // resize to bytes
    size_t buffersize = sizeof(uint8_t) * (keysize / 8);

    buffer = (uint8_t *)cjose_get_alloc()(buffersize);
    if (NULL == buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_oct_failed;
    }
    if (1 != RAND_bytes(buffer, buffersize))
    {
        goto create_oct_failed;
    }

    jwk = _oct_new(buffer, keysize, err);
    if (NULL == jwk)
    {
        goto create_oct_failed;
    }
    return jwk;

create_oct_failed:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
        buffer = NULL;
    }

    return NULL;
}

cjose_jwk_t *cjose_jwk_create_oct_spec(const uint8_t *data, size_t len, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *buffer = NULL;

    if (NULL == data || 0 == len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_oct_failed;
    }

    buffer = (uint8_t *)cjose_get_alloc()(len);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_oct_failed;
    }
    memcpy(buffer, data, len);

    jwk = _oct_new(buffer, len * 8, err);
    if (NULL == jwk)
    {
        goto create_oct_failed;
    }

    return jwk;

create_oct_failed:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
        buffer = NULL;
    }

    return NULL;
}

//////////////// Elliptic Curve ////////////////
// internal data & functions -- Elliptic Curve

static void _EC_free(cjose_jwk_t *jwk);
static bool _EC_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _EC_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable EC_FNTABLE = { _EC_free, _EC_public_fields, _EC_private_fields };

static inline uint8_t _ec_size_for_curve(cjose_jwk_ec_curve crv, cjose_err *err)
{
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        return 32;
    case CJOSE_JWK_EC_P_384:
        return 48;
    case CJOSE_JWK_EC_P_521:
        return 66;
    case CJOSE_JWK_EC_INVALID:
        return 0;
    }

    return 0;
}

static inline const char *_ec_name_for_curve(cjose_jwk_ec_curve crv, cjose_err *err)
{
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        return CJOSE_JWK_EC_P_256_STR;
    case CJOSE_JWK_EC_P_384:
        return CJOSE_JWK_EC_P_384_STR;
    case CJOSE_JWK_EC_P_521:
        return CJOSE_JWK_EC_P_521_STR;
    case CJOSE_JWK_EC_INVALID:
        return NULL;
    }

    return NULL;
}

static inline bool _ec_curve_from_name(const char *name, cjose_jwk_ec_curve *crv, cjose_err *err)
{
    bool retval = true;
    if (strncmp(name, CJOSE_JWK_EC_P_256_STR, sizeof(CJOSE_JWK_EC_P_256_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_256;
    }
    else if (strncmp(name, CJOSE_JWK_EC_P_384_STR, sizeof(CJOSE_JWK_EC_P_384_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_384;
    }
    else if (strncmp(name, CJOSE_JWK_EC_P_521_STR, sizeof(CJOSE_JWK_EC_P_521_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_521;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static inline bool _kty_from_name(const char *name, cjose_jwk_kty_t *kty, cjose_err *err)
{
    bool retval = true;
    if (strncmp(name, CJOSE_JWK_KTY_EC_STR, sizeof(CJOSE_JWK_KTY_EC_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_EC;
    }
    else if (strncmp(name, CJOSE_JWK_KTY_RSA_STR, sizeof(CJOSE_JWK_KTY_RSA_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_RSA;
    }
    else if (strncmp(name, CJOSE_JWK_KTY_OCT_STR, sizeof(CJOSE_JWK_KTY_OCT_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_OCT;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static cjose_jwk_t *_EC_new(cjose_jwk_ec_curve crv, EC_KEY *ec, cjose_err *err)
{
    ec_keydata *keydata = cjose_get_alloc()(sizeof(ec_keydata));
    if (!keydata)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    keydata->crv = crv;
    keydata->key = ec;

    cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        cjose_get_dealloc()(keydata);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_EC;
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        jwk->keysize = 256;
        break;
    case CJOSE_JWK_EC_P_384:
        jwk->keysize = 384;
        break;
    case CJOSE_JWK_EC_P_521:
        jwk->keysize = 521;
        break;
    case CJOSE_JWK_EC_INVALID:
        // should never happen
        jwk->keysize = 0;
        break;
    }
    jwk->keydata = keydata;
    jwk->fns = &EC_FNTABLE;

    return jwk;
}

static void _EC_free(cjose_jwk_t *jwk)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    jwk->keydata = NULL;

    if (keydata)
    {
        EC_KEY *ec = keydata->key;
        keydata->key = NULL;
        if (ec)
        {
            EC_KEY_free(ec);
        }
        cjose_get_dealloc()(keydata);
    }
    cjose_get_dealloc()(jwk);
}

static bool _EC_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    const EC_GROUP *params = NULL;
    const EC_POINT *pub = NULL;
    BIGNUM *bnX = NULL, *bnY = NULL;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0, offset = 0;
    json_t *field = NULL;
    bool result = false;

    // track expected binary data size
    uint8_t numsize = _ec_size_for_curve(keydata->crv, err);

    // output the curve
    field = json_string(_ec_name_for_curve(keydata->crv, err));
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "crv", field);
    json_decref(field);
    field = NULL;

    // obtain the public key
    pub = EC_KEY_get0_public_key(keydata->key);
    params = EC_KEY_get0_group(keydata->key);
    if (!pub || !params)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _ec_to_string_cleanup;
    }

    buffer = cjose_get_alloc()(numsize);
    bnX = BN_new();
    bnY = BN_new();
    if (!buffer || !bnX || !bnY)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    if (1 != EC_POINT_get_affine_coordinates_GFp(params, pub, bnX, bnY, NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }

    // output the x coordinate
    offset = numsize - BN_num_bytes(bnX);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnX, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "x", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    // output the y coordinate
    offset = numsize - BN_num_bytes(bnY);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnY, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "y", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    result = true;

_ec_to_string_cleanup:
    if (field)
    {
        json_decref(field);
    }
    if (bnX)
    {
        BN_free(bnX);
    }
    if (bnY)
    {
        BN_free(bnY);
    }
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }
    if (b64u)
    {
        cjose_get_dealloc()(b64u);
    }

    return result;
}

static bool _EC_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    const BIGNUM *bnD = EC_KEY_get0_private_key(keydata->key);
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0, offset = 0;
    json_t *field = NULL;
    bool result = false;

    // track expected binary data size
    uint8_t numsize = _ec_size_for_curve(keydata->crv, err);

    // short circuit if 'd' is NULL or 0
    if (!bnD || BN_is_zero(bnD))
    {
        return true;
    }

    buffer = cjose_get_alloc()(numsize);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }

    offset = numsize - BN_num_bytes(bnD);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnD, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "d", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    result = true;

_ec_to_string_cleanup:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }

    return result;
}

// interface functions -- Elliptic Curve

cjose_jwk_t *cjose_jwk_create_EC_random(cjose_jwk_ec_curve crv, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EC_KEY *ec = NULL;

    ec = EC_KEY_new_by_curve_name(crv);
    if (!ec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }

    if (1 != EC_KEY_generate_key(ec))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_EC_failed;
    }

    jwk = _EC_new(crv, ec, err);
    if (!jwk)
    {
        goto create_EC_failed;
    }

    return jwk;

create_EC_failed:
    if (jwk)
    {
        cjose_get_dealloc()(jwk);
        jwk = NULL;
    }
    if (ec)
    {
        EC_KEY_free(ec);
        ec = NULL;
    }

    return NULL;
}

cjose_jwk_t *cjose_jwk_create_EC_spec(const cjose_jwk_ec_keyspec *spec, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EC_KEY *ec = NULL;
    EC_GROUP *params = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *bnD = NULL;
    BIGNUM *bnX = NULL;
    BIGNUM *bnY = NULL;

    if (!spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool hasPriv = (NULL != spec->d && 0 < spec->dlen);
    bool hasPub = ((NULL != spec->x && 0 < spec->xlen) && (NULL != spec->y && 0 < spec->ylen));
    if (!hasPriv && !hasPub)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    ec = EC_KEY_new_by_curve_name(spec->crv);
    if (NULL == ec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }

    params = (EC_GROUP *)EC_KEY_get0_group(ec);
    if (NULL == params)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_EC_failed;
    }

    // convert d from octet string to BIGNUM
    if (hasPriv)
    {
        bnD = BN_bin2bn(spec->d, spec->dlen, NULL);
        if (NULL == bnD)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
        if (1 != EC_KEY_set_private_key(ec, bnD))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            goto create_EC_failed;
        }

        // calculate public key from private
        Q = EC_POINT_new(params);
        if (NULL == Q)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
        if (1 != EC_POINT_mul(params, Q, bnD, NULL, NULL, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        // public key is set below
        // ignore provided public key!
        hasPub = false;
    }
    if (hasPub)
    {
        Q = EC_POINT_new(params);
        if (NULL == Q)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        bnX = BN_bin2bn(spec->x, spec->xlen, NULL);
        bnY = BN_bin2bn(spec->y, spec->ylen, NULL);
        if (!bnX || !bnY)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        if (1 != EC_POINT_set_affine_coordinates_GFp(params, Q, bnX, bnY, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
    }

    // always set the public key
    if (1 != EC_KEY_set_public_key(ec, Q))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_EC_failed;
    }

    jwk = _EC_new(spec->crv, ec, err);
    if (!jwk)
    {
        goto create_EC_failed;
    }

    // jump to cleanup
    goto create_EC_cleanup;

create_EC_failed:
    if (jwk)
    {
        cjose_get_dealloc()(jwk);
        jwk = NULL;
    }
    if (ec)
    {
        EC_KEY_free(ec);
        ec = NULL;
    }

create_EC_cleanup:
    if (Q)
    {
        EC_POINT_free(Q);
        Q = NULL;
    }
    if (bnD)
    {
        BN_free(bnD);
        bnD = NULL;
    }
    if (bnX)
    {
        BN_free(bnX);
        bnX = NULL;
    }
    if (bnY)
    {
        BN_free(bnY);
        bnY = NULL;
    }

    return jwk;
}

const cjose_jwk_ec_curve cjose_jwk_EC_get_curve(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (NULL == jwk || CJOSE_JWK_KTY_EC != cjose_jwk_get_kty(jwk, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return CJOSE_JWK_EC_INVALID;
    }

    ec_keydata *keydata = jwk->keydata;
    return keydata->crv;
}

//////////////// RSA ////////////////
// internal data & functions -- RSA

static void _RSA_free(cjose_jwk_t *jwk);
static bool _RSA_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _RSA_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable RSA_FNTABLE = { _RSA_free, _RSA_public_fields, _RSA_private_fields };

static inline cjose_jwk_t *_RSA_new(RSA *rsa, cjose_err *err)
{
    cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_RSA;
    jwk->keysize = RSA_size(rsa) * 8;
    jwk->keydata = rsa;
    jwk->fns = &RSA_FNTABLE;

    return jwk;
}

static void _RSA_free(cjose_jwk_t *jwk)
{
    RSA *rsa = (RSA *)jwk->keydata;
    jwk->keydata = NULL;
    if (rsa)
    {
        RSA_free(rsa);
    }
    cjose_get_dealloc()(jwk);
}

static inline bool _RSA_json_field(BIGNUM *param, const char *name, json_t *json, cjose_err *err)
{
    json_t *field = NULL;
    uint8_t *data = NULL;
    char *b64u = NULL;
    size_t datalen = 0, b64ulen = 0;
    bool result = false;

    if (!param)
    {
        return true;
    }

    datalen = BN_num_bytes(param);
    data = cjose_get_alloc()(sizeof(uint8_t) * datalen);
    if (!data)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto RSA_json_field_cleanup;
    }
    BN_bn2bin(param, data);
    if (!cjose_base64url_encode(data, datalen, &b64u, &b64ulen, err))
    {
        goto RSA_json_field_cleanup;
    }
    field = _cjose_json_stringn(b64u, b64ulen, err);
    if (!field)
    {
        goto RSA_json_field_cleanup;
    }
    json_object_set(json, name, field);
    json_decref(field);
    field = NULL;
    result = true;

RSA_json_field_cleanup:
    if (b64u)
    {
        cjose_get_dealloc()(b64u);
        b64u = NULL;
    }
    if (data)
    {
        cjose_get_dealloc()(data);
        data = NULL;
    }

    return result;
}

static bool _RSA_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    RSA *rsa = (RSA *)jwk->keydata;

    BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
    _cjose_jwk_rsa_get(rsa, &rsa_n, &rsa_e, &rsa_d);

    if (!_RSA_json_field(rsa_e, "e", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_n, "n", json, err))
    {
        return false;
    }

    return true;
}

static bool _RSA_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    RSA *rsa = (RSA *)jwk->keydata;

    BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
    _cjose_jwk_rsa_get(rsa, &rsa_n, &rsa_e, &rsa_d);

    BIGNUM *rsa_p = NULL, *rsa_q;
    _cjose_jwk_rsa_get_factors(rsa, &rsa_p, &rsa_q);

    BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;
    _cjose_jwk_rsa_get_crt(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);

    if (!_RSA_json_field(rsa_d, "d", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_p, "p", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_q, "q", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_dmp1, "dp", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_dmq1, "dq", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_iqmp, "qi", json, err))
    {
        return false;
    }

    return true;
}

// interface functions -- RSA
static const uint8_t *DEFAULT_E_DAT = (const uint8_t *)"\x01\x00\x01";
static const size_t DEFAULT_E_LEN = 3;

cjose_jwk_t *cjose_jwk_create_RSA_random(size_t keysize, const uint8_t *e, size_t elen, cjose_err *err)
{
    if (0 == keysize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    if (NULL == e || 0 >= elen)
    {
        e = DEFAULT_E_DAT;
        elen = DEFAULT_E_LEN;
    }

    RSA *rsa = NULL;
    BIGNUM *bn = NULL;

    rsa = RSA_new();
    if (!rsa)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    bn = BN_bin2bn(e, elen, NULL);
    if (!bn)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    if (0 == RSA_generate_key_ex(rsa, keysize, bn, NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    BN_free(bn);
    return _RSA_new(rsa, err);

create_RSA_random_failed:
    if (bn)
    {
        BN_free(bn);
    }
    if (rsa)
    {
        RSA_free(rsa);
    }
    return NULL;
}

cjose_jwk_t *cjose_jwk_create_RSA_spec(const cjose_jwk_rsa_keyspec *spec, cjose_err *err)
{
    if (NULL == spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool hasPub = (NULL != spec->n && 0 < spec->nlen) && (NULL != spec->e && 0 < spec->elen);
    bool hasPriv = (NULL != spec->n && 0 < spec->nlen) && (NULL != spec->d && 0 < spec->dlen);
    if (!hasPub && !hasPriv)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    RSA *rsa = NULL;
    rsa = RSA_new();
    if (!rsa)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }

    if (hasPriv)
    {
        if (!_cjose_jwk_rsa_set(rsa, spec->n, spec->nlen, spec->e, spec->elen, spec->d, spec->dlen))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            goto create_RSA_spec_failed;
        }
        _cjose_jwk_rsa_set_factors(rsa, spec->p, spec->plen, spec->q, spec->qlen);
        _cjose_jwk_rsa_set_crt(rsa, spec->dp, spec->dplen, spec->dq, spec->dqlen, spec->qi, spec->qilen);
    }
    else if (hasPub)
    {
        if (!_cjose_jwk_rsa_set(rsa, spec->n, spec->nlen, spec->e, spec->elen, NULL, 0))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            goto create_RSA_spec_failed;
        }
    }

    return _RSA_new(rsa, err);

create_RSA_spec_failed:
    if (rsa)
    {
        RSA_free(rsa);
    }

    return NULL;
}

//////////////// Import ////////////////
// internal data & functions -- JWK key import

static const char *_get_json_object_string_attribute(json_t *json, const char *key, cjose_err *err)
{
    const char *attr_str = NULL;
    json_t *attr_json = json_object_get(json, key);
    if (NULL != attr_json)
    {
        attr_str = json_string_value(attr_json);
    }
    return attr_str;
}

/**
 * Internal helper function for extracing an octet string from a base64url
 * encoded field.  Caller provides the json object, the attribute key,
 * and an expected length for the octet string.  On successful decoding,
 * this will return a newly allocated buffer with the decoded octet string
 * of the expected length.
 *
 * Note: caller is responsible for freeing the buffer returned by this function.
 *
 * \param[in]     json the JSON object from which to read the attribute.
 * \param[in]     key the name of the attribute to be decoded.
 * \param[out]    pointer to buffer of octet string (if decoding succeeds).
 * \param[in/out] in as the expected length of the attribute, out as the
 *                actual decoded length.  Note, this method succeeds only
 *                if the actual decoded length matches the expected length.
 *                If the in-value is 0 this indicates there is no particular
 *                expected length (i.e. any length is ok).
 * \returns true  if attribute is either not present or successfully decoded.
 *                false otherwise.
 */
static bool
_decode_json_object_base64url_attribute(json_t *jwk_json, const char *key, uint8_t **buffer, size_t *buflen, cjose_err *err)
{
    // get the base64url encoded string value of the attribute (if any)
    const char *str = _get_json_object_string_attribute(jwk_json, key, err);
    if (str == NULL || strlen(str) == 0)
    {
        *buflen = 0;
        *buffer = NULL;
        return true;
    }

    // if a particular decoded length is expected, check for that
    if (*buflen != 0)
    {
        const char *end = NULL;
        for (end = str + strlen(str) - 1; *end == '=' && end > str; --end)
            ;
        size_t unpadded_len = end + 1 - str - ((*end == '=') ? 1 : 0);
        size_t expected_len = ceil(4 * ((float)*buflen / 3));

        if (expected_len != unpadded_len)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            *buflen = 0;
            *buffer = NULL;
            return false;
        }
    }

    // decode the base64url encoded string to the allocated buffer
    if (!cjose_base64url_decode(str, strlen(str), buffer, buflen, err))
    {
        *buflen = 0;
        *buffer = NULL;
        return false;
    }

    return true;
}

static cjose_jwk_t *_cjose_jwk_import_EC(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *x_buffer = NULL;
    uint8_t *y_buffer = NULL;
    uint8_t *d_buffer = NULL;

    // get the value of the crv attribute
    const char *crv_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_CRV_STR, err);
    if (crv_str == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the curve identifer for the curve named by crv
    cjose_jwk_ec_curve crv;
    if (!_ec_curve_from_name(crv_str, &crv, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the x coordinate
    size_t x_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_X_STR, &x_buffer, &x_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the y coordinate
    size_t y_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_Y_STR, &y_buffer, &y_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the private key d
    size_t d_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // create an ec keyspec
    cjose_jwk_ec_keyspec ec_keyspec;
    memset(&ec_keyspec, 0, sizeof(cjose_jwk_ec_keyspec));
    ec_keyspec.crv = crv;
    ec_keyspec.x = x_buffer;
    ec_keyspec.xlen = x_buflen;
    ec_keyspec.y = y_buffer;
    ec_keyspec.ylen = y_buflen;
    ec_keyspec.d = d_buffer;
    ec_keyspec.dlen = d_buflen;

    // create the jwk
    jwk = cjose_jwk_create_EC_spec(&ec_keyspec, err);

import_EC_cleanup:
    if (NULL != x_buffer)
    {
        cjose_get_dealloc()(x_buffer);
    }
    if (NULL != y_buffer)
    {
        cjose_get_dealloc()(y_buffer);
    }
    if (NULL != d_buffer)
    {
        cjose_get_dealloc()(d_buffer);
    }

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_RSA(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *n_buffer = NULL;
    uint8_t *e_buffer = NULL;
    uint8_t *d_buffer = NULL;
    uint8_t *p_buffer = NULL;
    uint8_t *q_buffer = NULL;
    uint8_t *dp_buffer = NULL;
    uint8_t *dq_buffer = NULL;
    uint8_t *qi_buffer = NULL;

    // get the decoded value of n (buflen = 0 means no particular expected len)
    size_t n_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_N_STR, &n_buffer, &n_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of e
    size_t e_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_E_STR, &e_buffer, &e_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of d
    size_t d_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of p
    size_t p_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_P_STR, &p_buffer, &p_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of q
    size_t q_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_Q_STR, &q_buffer, &q_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of dp
    size_t dp_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_DP_STR, &dp_buffer, &dp_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of dq
    size_t dq_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_DQ_STR, &dq_buffer, &dq_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of qi
    size_t qi_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_QI_STR, &qi_buffer, &qi_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // create an rsa keyspec
    cjose_jwk_rsa_keyspec rsa_keyspec;
    memset(&rsa_keyspec, 0, sizeof(cjose_jwk_rsa_keyspec));
    rsa_keyspec.n = n_buffer;
    rsa_keyspec.nlen = n_buflen;
    rsa_keyspec.e = e_buffer;
    rsa_keyspec.elen = e_buflen;
    rsa_keyspec.d = d_buffer;
    rsa_keyspec.dlen = d_buflen;
    rsa_keyspec.p = p_buffer;
    rsa_keyspec.plen = p_buflen;
    rsa_keyspec.q = q_buffer;
    rsa_keyspec.qlen = q_buflen;
    rsa_keyspec.dp = dp_buffer;
    rsa_keyspec.dplen = dp_buflen;
    rsa_keyspec.dq = dq_buffer;
    rsa_keyspec.dqlen = dq_buflen;
    rsa_keyspec.qi = qi_buffer;
    rsa_keyspec.qilen = qi_buflen;

    // create the jwk
    jwk = cjose_jwk_create_RSA_spec(&rsa_keyspec, err);

import_RSA_cleanup:
    cjose_get_dealloc()(n_buffer);
    cjose_get_dealloc()(e_buffer);
    cjose_get_dealloc()(d_buffer);
    cjose_get_dealloc()(p_buffer);
    cjose_get_dealloc()(q_buffer);
    cjose_get_dealloc()(dp_buffer);
    cjose_get_dealloc()(dq_buffer);
    cjose_get_dealloc()(qi_buffer);

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_oct(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *k_buffer = NULL;

    // get the decoded value of k (buflen = 0 means no particular expected len)
    size_t k_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_K_STR, &k_buffer, &k_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_oct_cleanup;
    }

    // create the jwk
    jwk = cjose_jwk_create_oct_spec(k_buffer, k_buflen, err);

import_oct_cleanup:
    if (NULL != k_buffer)
    {
        cjose_get_dealloc()(k_buffer);
    }

    return jwk;
}

cjose_jwk_t *cjose_jwk_import(const char *jwk_str, size_t len, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;

    // check params
    if ((NULL == jwk_str) || (0 == len))
    {
        return NULL;
    }

    // parse json content from the given string
    json_t *jwk_json = json_loadb(jwk_str, len, 0, NULL);
    if (NULL == jwk_json)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_cleanup;
    }

    jwk = cjose_jwk_import_json((cjose_header_t *)jwk_json, err);

// poor man's "finally"
import_cleanup:
    if (NULL != jwk_json)
    {
        json_decref(jwk_json);
    }

    return jwk;
}

cjose_jwk_t *cjose_jwk_import_json(cjose_header_t *json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;

    json_t *jwk_json = (json_t *)json;

    if (NULL == jwk_json || JSON_OBJECT != json_typeof(jwk_json))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // get the string value of the kty attribute of the jwk
    const char *kty_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_KTY_STR, err);
    if (NULL == kty_str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // get kty corresponding to kty_str (kty is required)
    cjose_jwk_kty_t kty;
    if (!_kty_from_name(kty_str, &kty, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // create a cjose_jwt_t based on the kty
    switch (kty)
    {
    case CJOSE_JWK_KTY_EC:
        jwk = _cjose_jwk_import_EC(jwk_json, err);
        break;

    case CJOSE_JWK_KTY_RSA:
        jwk = _cjose_jwk_import_RSA(jwk_json, err);
        break;

    case CJOSE_JWK_KTY_OCT:
        jwk = _cjose_jwk_import_oct(jwk_json, err);
        break;

    default:
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    if (NULL == jwk)
    {
        // helper function will have already set err
        return NULL;
    }

    // get the value of the kid attribute (kid is optional)
    const char *kid_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_KID_STR, err);
    if (kid_str != NULL)
    {
        jwk->kid = _cjose_strndup(kid_str, -1, err);
        if (!jwk->kid)
        {
            cjose_jwk_release(jwk);
            return NULL;
        }
    }

    return jwk;
}

//////////////// ECDH ////////////////
// internal data & functions -- ECDH derivation

static bool _cjose_jwk_evp_key_from_ec_key(const cjose_jwk_t *jwk, EVP_PKEY **key, cjose_err *err)
{
    // validate that the jwk is of type EC and we have a valid out-param
    if (NULL == jwk || CJOSE_JWK_KTY_EC != jwk->kty || NULL == jwk->keydata || NULL == key || NULL != *key)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jwk_evp_key_from_ec_key_fail;
    }

    // create a blank EVP_PKEY
    *key = EVP_PKEY_new();
    if (NULL == *key)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_evp_key_from_ec_key_fail;
    }

    // assign the EVP_PKEY to reference the jwk's internal EC_KEY structure
    if (1 != EVP_PKEY_set1_EC_KEY(*key, ((struct _ec_keydata_int *)(jwk->keydata))->key))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_evp_key_from_ec_key_fail;
    }

    // happy path
    return true;

// fail path
_cjose_jwk_evp_key_from_ec_key_fail:

    EVP_PKEY_free(*key);
    *key = NULL;

    return false;
}

cjose_jwk_t *cjose_jwk_derive_ecdh_secret(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, const uint8_t *salt, size_t salt_len, cjose_err *err)
{
    return cjose_jwk_derive_ecdh_ephemeral_key(jwk_self, jwk_peer, salt, salt_len, err);
}

cjose_jwk_t *cjose_jwk_derive_ecdh_ephemeral_key(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, const uint8_t *salt, size_t salt_len, cjose_err *err)
{
    uint8_t *secret = NULL;
    size_t secret_len = 0;
    uint8_t *ephemeral_key = NULL;
    size_t ephemeral_key_len = 0;
    cjose_jwk_t *jwk_ephemeral_key = NULL;

    if (!cjose_jwk_derive_ecdh_bits(jwk_self, jwk_peer, &secret, &secret_len, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // HKDF of the DH shared secret (SHA256, no info, 256 bit expand)
    ephemeral_key_len = 32;
    ephemeral_key = (uint8_t *)cjose_get_alloc()(ephemeral_key_len);
    if (!cjose_jwk_hkdf(EVP_sha256(), salt, salt_len, (uint8_t *)"", 0, secret, secret_len, ephemeral_key, ephemeral_key_len, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // create a JWK of the shared secret
    jwk_ephemeral_key = cjose_jwk_create_oct_spec(ephemeral_key, ephemeral_key_len, err);
    if (NULL == jwk_ephemeral_key)
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // happy path
    cjose_get_dealloc()(secret);
    cjose_get_dealloc()(ephemeral_key);

    return jwk_ephemeral_key;

// fail path
_cjose_jwk_derive_shared_secret_fail:

    if (NULL != jwk_ephemeral_key)
    {
        cjose_jwk_release(jwk_ephemeral_key);
    }
    cjose_get_dealloc()(secret);
    cjose_get_dealloc()(ephemeral_key);
    return NULL;
}

bool cjose_jwk_derive_ecdh_bits(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, uint8_t **output, size_t *output_len, cjose_err *err)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey_self = NULL;
    EVP_PKEY *pkey_peer = NULL;
    uint8_t *secret = NULL;
    size_t secret_len = 0;

    // get EVP_KEY from jwk_self
    if (!_cjose_jwk_evp_key_from_ec_key(jwk_self, &pkey_self, err))
    {
        goto _cjose_jwk_derive_bits_fail;
    }

    // get EVP_KEY from jwk_peer
    if (!_cjose_jwk_evp_key_from_ec_key(jwk_peer, &pkey_peer, err))
    {
        goto _cjose_jwk_derive_bits_fail;
    }

    // create derivation context based on local key pair
    ctx = EVP_PKEY_CTX_new(pkey_self, NULL);
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // initialize derivation context
    if (1 != EVP_PKEY_derive_init(ctx))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // provide the peer public key
    if (1 != EVP_PKEY_derive_set_peer(ctx, pkey_peer))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // determine buffer length for shared secret
    if (1 != EVP_PKEY_derive(ctx, NULL, &secret_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // allocate buffer for shared secret
    secret = (uint8_t *)cjose_get_alloc()(secret_len);
    if (NULL == output)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jwk_derive_bits_fail;
    }
    memset(secret, 0, secret_len);

    // derive the shared secret
    if (1 != (EVP_PKEY_derive(ctx, secret, &secret_len)))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jwk_derive_bits_fail;
    }

    // happy path
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey_self);
    EVP_PKEY_free(pkey_peer);

    *output = secret;
    *output_len = secret_len;
    return true;

_cjose_jwk_derive_bits_fail:

    if (NULL != ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    if (NULL != pkey_self)
    {
        EVP_PKEY_free(pkey_self);
    }
    if (NULL != pkey_peer)
    {
        EVP_PKEY_free(pkey_peer);
    }
    cjose_get_dealloc()(secret);

    return false;
}

bool cjose_jwk_hkdf(const EVP_MD *md,
                    const uint8_t *salt,
                    size_t salt_len,
                    const uint8_t *info,
                    size_t info_len,
                    const uint8_t *ikm,
                    size_t ikm_len,
                    uint8_t *okm,
                    unsigned int okm_len,
                    cjose_err *err)
{
    // current impl. is very limited: SHA256, 256 bit output, and no info
    if ((EVP_sha256() != md) || (0 != info_len) || (32 != okm_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // HKDF-Extract, HMAC-SHA256(salt, IKM) -> PRK
    unsigned int prk_len;
    unsigned char prk[EVP_MAX_MD_SIZE];
    if (NULL == HMAC(md, salt, salt_len, ikm, ikm_len, prk, &prk_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    // HKDF-Expand, HMAC-SHA256(PRK,0x01) -> OKM
    const unsigned char t[] = { 0x01 };
    if (NULL == HMAC(md, prk, prk_len, t, sizeof(t), okm, NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}
