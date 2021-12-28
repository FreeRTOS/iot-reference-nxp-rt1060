// This hkdf implementation (RFC5869) is based upon source code retrieved from
// the following location on 2016-09-22 :
// https://github.com/openssl/openssl/blob/master/crypto/kdf/hkdf.c

/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define HKDF_MAXBUF 1024

unsigned char *HKDF(const EVP_MD *evp_md,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *key, size_t key_len,
                           const unsigned char *info, size_t info_len,
                           unsigned char *okm, size_t okm_len);

unsigned char *HKDF_Extract(const EVP_MD *evp_md,
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *prk, size_t *prk_len);

unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  const unsigned char *info, size_t info_len,
                                  unsigned char *okm, size_t okm_len);

unsigned char *HKDF(const EVP_MD *evp_md,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *key, size_t key_len,
                           const unsigned char *info, size_t info_len,
                           unsigned char *okm, size_t okm_len)
{
    unsigned char prk[EVP_MAX_MD_SIZE];
    size_t prk_len;

    if (!HKDF_Extract(evp_md, salt, salt_len, key, key_len, prk, &prk_len))
        return NULL;

    return HKDF_Expand(evp_md, prk, prk_len, info, info_len, okm, okm_len);
}

unsigned char *HKDF_Extract(const EVP_MD *evp_md,
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *prk, size_t *prk_len)
{
    unsigned int tmp_len;

    if (!HMAC(evp_md, salt, (int)salt_len, key, key_len, prk, &tmp_len))
        return NULL;

    *prk_len = tmp_len;
    return prk;
}

unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  const unsigned char *info, size_t info_len,
                                  unsigned char *okm, size_t okm_len)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX hmacCtx;
#else
    HMAC_CTX *hmacCtx;
#endif

    unsigned int i;

    unsigned char prev[EVP_MAX_MD_SIZE];

    size_t done_len = 0, dig_len = EVP_MD_size(evp_md);

    size_t n = okm_len / dig_len;
    if (okm_len % dig_len)
        n++;

    if (n > 255)
        return NULL;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_init(&hmacCtx);
#else
    hmacCtx = HMAC_CTX_new();
    if (hmacCtx == NULL) {
        return NULL;
    }
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (!HMAC_Init_ex(&hmacCtx, prk, (int)prk_len, evp_md, NULL))
        goto err;

    for (i = 1; i <= n; i++)
    {
        size_t copy_len;
        const unsigned char ctr = (unsigned char)i;

        // T(0) bootstraps (first iteration) as the empty string
        // T(n) = HMAC_SHA256(PRK, T(n-1) | info | n)
        if (i > 1)
        {
            // First clean HMAC's state, leave key and hash function selection in place
            if (!HMAC_Init_ex(&hmacCtx, NULL, 0, NULL, NULL))
                goto err;

            if (!HMAC_Update(&hmacCtx, prev, dig_len))
                goto err;
        }

        if (!HMAC_Update(&hmacCtx, info, info_len))
            goto err;

        if (!HMAC_Update(&hmacCtx, &ctr, 1))
            goto err;

        if (!HMAC_Final(&hmacCtx, prev, NULL))
            goto err;

        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }

    HMAC_CTX_cleanup(&hmacCtx);
    return okm;
#else
    if (!HMAC_Init_ex(hmacCtx, prk, (int)prk_len, evp_md, NULL))
        goto err;

    for (i = 1; i <= n; i++)
    {
        size_t copy_len;
        const unsigned char ctr = (unsigned char)i;

        // T(0) bootstraps (first iteration) as the empty string
        // T(n) = HMAC_SHA256(PRK, T(n-1) | info | n)
        if (i > 1)
        {
            // First clean HMAC's state, leave key and hash function selection in place
            if (!HMAC_Init_ex(hmacCtx, NULL, 0, NULL, NULL))
                goto err;

            if (!HMAC_Update(hmacCtx, prev, dig_len))
                goto err;
        }

        if (!HMAC_Update(hmacCtx, info, info_len))
            goto err;

        if (!HMAC_Update(hmacCtx, &ctr, 1))
            goto err;

        if (!HMAC_Final(hmacCtx, prev, NULL))
            goto err;

        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }

    HMAC_CTX_free(hmacCtx);
    return okm; 
#endif

err:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_cleanup(&hmacCtx);
#else
    HMAC_CTX_free(hmacCtx);
#endif
    return NULL;
}
