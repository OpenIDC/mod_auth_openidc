/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <cjose/jwk.h>

#include <jansson.h>

#ifdef HAVE_OPENSSL_FEC_H

#include <openssl/fec.h>
#include <openssl/fecdh.h>
#include <openssl/fecdsa.h>

#else

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>

#endif

#ifndef SRC_JWK_INT_H
#define SRC_JWK_INT_H

#ifdef _WINDOWS
   #pragma warning(disable : 4996)  
#endif

// key-specific function table
typedef struct _key_fntable_int
{
    void (*free)(cjose_jwk_t *);
    bool (*public_json)(const cjose_jwk_t *, json_t *, cjose_err *err);
    bool (*private_json)(const cjose_jwk_t *, json_t *, cjose_err *err);
} key_fntable;

// JSON Web Key structure
struct _cjose_jwk_int
{
    cjose_jwk_kty_t kty;
    char *kid;
    unsigned int retained;
    size_t keysize;
    void *keydata;
    const key_fntable *fns;
};

// EC-specific keydata
typedef struct _ec_keydata_int
{
    cjose_jwk_ec_curve crv;
    EC_KEY *key;
} ec_keydata;

// RSA-specific keydata = OpenSSL RSA struct
// (just uses RSA struct)
void _cjose_jwk_rsa_get(RSA *rsa, BIGNUM **n, BIGNUM **e, BIGNUM **d);

bool cjose_jwk_derive_ecdh_bits(const cjose_jwk_t *jwk_self,
                                const cjose_jwk_t *jwk_peer,
                                uint8_t **output,
                                size_t *output_len,
                                cjose_err *err);

// HKDF implementation, note it currrently supports only SHA256, no info
// and okm must be exactly 32 bytes.
bool cjose_jwk_hkdf(const EVP_MD *md,
                    const uint8_t *salt,
                    size_t salt_len,
                    const uint8_t *info,
                    size_t info_len,
                    const uint8_t *ikm,
                    size_t ikm_len,
                    uint8_t *okm,
                    unsigned int okm_len,
                    cjose_err *err);

#endif // SRC_JWK_INT_H
