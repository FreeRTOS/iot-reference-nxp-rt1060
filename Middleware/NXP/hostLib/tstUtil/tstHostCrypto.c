/**
 * @file tstHostCrypto.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 *  Module implementing host based crypto functionality used in example programs.
 * This module relies on the availability of OpenSSL on the Host plaform.
 * @par HISTORY
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/*******************************************************************
* project specific include files
*******************************************************************/

#include "ax_util.h"
// #include "sm_debug.h"
#include "sm_types.h"
#include "sm_apdu.h"
#include "tst_sm_util.h"
#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>  // TGT_A70CI
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>  // TGT_A70CI
#include <openssl/hmac.h> // TGT_A71CH

/// @cond Enable/Disable debug logging
// #define DBG_TST_HOST_CRYPTO
#ifdef DBG_TST_HOST_CRYPTO
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif
/// @endcond

/*******************************************************************
* global variables and struct definitions
*******************************************************************/
unsigned char *HKDF(const EVP_MD *evp_md,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *key, size_t key_len,
                           const unsigned char *info, size_t info_len,
                           unsigned char *okm, size_t okm_len);

unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  const unsigned char *info, size_t info_len,
                                  unsigned char *okm, size_t okm_len);

#ifdef TGT_A70CI
static RSA * lastGeneratedRsaKeyPair; // TGT_A70CI
static EVP_MD_CTX mctx;               // TGT_A70CI

static void verifyMatchingPublicKey(U8 * pPub, U16 pubKeyLen);
static void verifyMatchingPrivateKey(U8 * pP, U16 lengthP, U8 * pQ, U16 lengthQ, U8 * pDp, U16 lengthDp, U8 * pDq, U16 lengthDq, U8 * pIpq, U16 lengthIpq);
#endif

static int axECCCurveType_2_OpenSSL(ECCCurve_t eccCurve)
{
    int nCurve = 0;

    switch (eccCurve)
    {
        case ECCCurve_NIST_P192:
            nCurve = NID_X9_62_prime192v1;
        break;

        case ECCCurve_NIST_P224:
            // To be checked!
            nCurve = NID_secp224r1;
        break;

        case ECCCurve_NIST_P256:
            nCurve = NID_X9_62_prime256v1;
        break;

#ifdef A7X_ECC_BRAINPOOL_ON_HOST
        // TODO: When are Brainpool curves available in OpenSSL?
        case ECCCurve_BrainPoolP192r1:
            nCurve = NID_brainpoolP192r1;
        break;

        case ECCCurve_BrainPoolP224r1:
            nCurve = NID_brainpoolP224r1;
        break;

        case ECCCurve_BrainPoolP256r1:
            nCurve = NID_brainpoolP256r1;
        break;
#endif

        default:
            // this should not happen
            assert(0);
        break;
    }
    return nCurve;
}

// TODO: Check on buffer size passed as argument
U16 HOSTCRYPTO_Sign(EC_KEY* pKey, U8* pInputData, U16 inputLength, U8* pSignature, U16* pSignatureLength, U8 signatureFormat)
{
    int result = 0;
    U16 nStatus = SW_OK;
    int rSize;
    int sSize;
    ECDSA_SIG *pSig;
    U8 signatureWrapped[256];
    U32 signatureWrappedLen = sizeof(signatureWrapped);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    const BIGNUM *sig_r;
    const BIGNUM *sig_s;
#endif

    assert(pKey != NULL);
    assert(pInputData != NULL);
    assert(inputLength == SHA256_DIGEST_LENGTH);
    assert(pSignature != NULL);
    assert(pSignatureLength != NULL);

    if (signatureFormat == SIGNATURE_ASN_WRAPPED)
    {
        // ECDSA_sign outputs ASN.1-wrapped signature
        result = ECDSA_sign(0, pInputData, inputLength, pSignature, (unsigned int *)&signatureWrappedLen, pKey);
        if (result == 1)
        {
            axPrintByteArray("pSignature", pSignature, (U16)signatureWrappedLen, AX_COLON_32);
            *pSignatureLength = (U16)signatureWrappedLen;
            nStatus = SW_OK;
        }
        else
        {
            printf("ECDSA_sign failed.\n");
            *pSignatureLength = 0;
            nStatus = ERR_CRYPTO_ENGINE_FAILED;
        }
    }
    else if (signatureFormat == SIGNATURE_RAW)
    {
        // ECDSA_do_sign outputs signature as raw data
        pSig = ECDSA_do_sign(pInputData, inputLength, pKey);
        if (pSig == NULL)
        {
            return ERR_CRYPTO_ENGINE_FAILED;
        }

        // check max signature length
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        if ((BN_num_bytes(pSig->r) + BN_num_bytes(pSig->s)) > (*pSignatureLength))
        {
            ECDSA_SIG_free(pSig);
            return ERR_GENERAL_ERROR;
        }
#else
        // void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
        ECDSA_SIG_get0(pSig, &sig_r, &sig_s);
        if ((BN_num_bytes(sig_r) + BN_num_bytes(sig_s)) > (*pSignatureLength))
        {
            ECDSA_SIG_free(pSig);
            return ERR_GENERAL_ERROR;
        }
#endif

        // output signature = r || s
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        rSize = BN_bn2bin(pSig->r, pSignature);
#else
        rSize = BN_bn2bin(sig_r, pSignature);
#endif
        nStatus = axZeroSignExtend(pSignature, (U16)rSize, inputLength);
        if (nStatus != SW_OK)
        {
            ECDSA_SIG_free(pSig);
            return ERR_GENERAL_ERROR;
        }
        rSize = inputLength;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        sSize = BN_bn2bin(pSig->s, pSignature + rSize);
#else
        sSize = BN_bn2bin(sig_s, pSignature + rSize);
#endif
        nStatus = axZeroSignExtend(pSignature + rSize, (U16)sSize, inputLength);
        if (nStatus != SW_OK)
        {
            ECDSA_SIG_free(pSig);
            return ERR_GENERAL_ERROR;
        }
        sSize = inputLength;

        *pSignatureLength = (U16)(rSize + sSize);
        ECDSA_SIG_free(pSig);
    }
    else
    {
        nStatus = ERR_API_ERROR;
    }

    return nStatus;
}

U16 HOSTCRYPTO_ECC_ComputeSharedSecret(EC_KEY *pKey, U8 *pubKey, U16 pubKeyLen, U8 *pSharedSecretData, U16 *pSharedSecretDataLen)
{
    int retval;
    int field_size;
    EC_POINT* pExternalPoint = NULL;
    const EC_GROUP* pGroup;
    int sharedSecretLen;
    U16 nStatus = SW_OK;

    /* Compute the size of the shared secret */
    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pKey));
    sharedSecretLen = (field_size+7)/8;
    if (sharedSecretLen > *pSharedSecretDataLen)
    {
        return ERR_API_ERROR;
    }

    // convert external public key data to POINT
    // external public key curve == local curve
    pGroup = EC_KEY_get0_group(pKey);
    pExternalPoint = EC_POINT_new(pGroup);
    // data has leading 0x04 (uncompressed point representation)
    retval = EC_POINT_oct2point(pGroup, pExternalPoint, pubKey, pubKeyLen, NULL);
    if (retval != 1)
    {
        return ERR_GENERAL_ERROR;
    }

    /* Compute the shared secret, no KDF is applied */
    retval = ECDH_compute_key(pSharedSecretData, sharedSecretLen, pExternalPoint, pKey, NULL);
    EC_POINT_free(pExternalPoint);
    if (retval != sharedSecretLen)
    {
        return ERR_GENERAL_ERROR;
    }


    return nStatus;
}

/**
 * Extract the public key - as a byte array in uncompress format - from an ECC key (in an OpenSSL specific format)
 * @param[in] pKey Reference to ECC key (OpenSSL).
 * @param[in,out] pPublicKeyData IN: Buffer to contain public key; OUT: Public key
 * @param[out] pPublicKeyLen Length of public key \p pPublicKeyData retrieved
 * @param[in] maxPublicKeyLen Size of buffer (\p pPublicKeyData) provided to contain public key
*/
U16 HOSTCRYPTO_GetPublicKey(EC_KEY *pKey, U8 *pPublicKeyData, U16 *pPublicKeyLen, U16 maxPublicKeyLen)
{
    const EC_POINT* pPoint;
    const EC_GROUP* pGroup;

    pGroup = EC_KEY_get0_group(pKey);
    pPoint = EC_KEY_get0_public_key(pKey);
    if (pPoint == NULL)
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    *pPublicKeyLen = (U16)EC_POINT_point2oct(pGroup, pPoint, POINT_CONVERSION_UNCOMPRESSED, pPublicKeyData, maxPublicKeyLen, NULL);
    if (*pPublicKeyLen == 0)
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    return SW_OK;
}

/**
 * Extract the private key - as a byte array restored to nominal key size by sign extension - from an ECC key (in an OpenSSL specific format)
 * @param[in] pKey Reference to ECC key (OpenSSL).
 * @param[in,out] pPrivateKeyData IN: Buffer to contain private key; OUT: Private key
 * @param[out] pPrivateKeyLen Length of private key \p pPrivateKeyData retrieved
 * @param[in] maxPrivateKeyLen Size of buffer (\p pPrivateKeyData) provided to contain private key
*/
U16 HOSTCRYPTO_GetPrivateKey(EC_KEY *pKey, U8 *pPrivateKeyData, U16 *pPrivateKeyLen, U16 maxPrivateKeyLen)
{
    const BIGNUM *privKey = NULL;
    U8 keyArray[256];
    int significantBytes = 0;
    int keyLen = 0;
    U16 sw = SW_OK;

    /* Load private key */
    privKey = EC_KEY_get0_private_key(pKey);
    if (privKey == NULL)
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    significantBytes = BN_bn2bin(privKey, keyArray);
    /* Estimate length of key */
    keyLen = (EC_GROUP_get_degree(EC_KEY_get0_group(pKey))+7)/8;

    if (keyLen > maxPrivateKeyLen)
    {
        return ERR_BUF_TOO_SMALL;
    }

    // Extend byte array with leading 0x00 byte in case private key had
    // been truncated because the MSB were not significant
    if (significantBytes > 0)
    {
        sw = axZeroSignExtend(keyArray, (U16)significantBytes, (U16)keyLen);
        if (sw == SW_OK)
        {
            memcpy(pPrivateKeyData, keyArray, keyLen);
            *pPrivateKeyLen = (U16)keyLen;
        }
        else
        {
            *pPrivateKeyLen = 0;
        }
    }
    else
    {
        *pPrivateKeyLen = 0;
        sw = ERR_GENERAL_ERROR;
    }

    return SW_OK;
}

/**
 * Free ECC key object
 * @post pointer passed as argument is pointing to NULL
 * @param[in] ppKey Reference to pointer (double indirection) to EC_KEY (OpenSSL) data structure
 */
void HOSTCRYPTO_FreeEccKey(EC_KEY** ppKey) {
    assert(ppKey != NULL);

    if (*ppKey != NULL)
    {
       EC_KEY_free(*ppKey);
    }
    *ppKey = NULL;
}

/**
 * Create an ECC key (in an OpenSSL specific format) on the requested curve
 * @param[in] curveType E.g. ECCCurve_NIST_P256. Not all curves defined in ::ECCCurve_t are always supported
     by the underlying OpenSSL crypto library.
 * @param[out] ppKey    Double indirection to EC_KEY (OpenSSL) data structure. In case *ppKey already points
     to a key object, that object is freed first.
*/
U16 HOSTCRYPTO_GenerateEccKey(ECCCurve_t curveType, EC_KEY** ppKey)
{
    int retval;
    int curveName;

    assert(ppKey != NULL);

    curveName = axECCCurveType_2_OpenSSL(curveType);

    // free existing private key
    if (*ppKey != NULL)
    {
       EC_KEY_free(*ppKey);
    }

    // create key
    *ppKey = EC_KEY_new_by_curve_name(curveName);
    if (*ppKey == NULL)
    {
        // key creation failed
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    // generate key material
    retval = EC_KEY_generate_key(*ppKey);

    if (retval == 1)
    {
        return SW_OK;
    }
    else
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }
}

/**
 * Create an OpenSSL specific key structure and fill it up with the ECC key material contained
 * in the crypto library agnostic \p eccKc data structure. In case \p eccKc does not contain a
 * private key, only the public part will be copied into the OpenSSL specific key structure.
 *
 * @param[out] eccRef Double indirection to EC_KEY (OpenSSL) data structure.
 *   In case *ppKey already points to a key object, that object is freed first.
 * @param[in]  eccKc  Data structure containing ECC key material.
 */
U16 HOSTCRYPTO_EccCreateOpenSslEccFromComponents(EC_KEY **eccRef, eccKeyComponents_t *eccKc)
{
    BIGNUM *bn_ecc_priv = NULL;
    BIGNUM *X = NULL;
    BIGNUM *Y = NULL;
    int nByteCoordinate = 0;
    int nCurve = 0;
    EC_GROUP *group = NULL;
    EC_POINT *pubPoint = NULL;
    int retval = 1;
    U16 sw = SW_OK;

    assert(eccRef != NULL);

    // free existing key pair
    if (*eccRef != NULL)
    {
        EC_KEY_free(*eccRef);
    }

    // create key
    nCurve = axECCCurveType_2_OpenSSL(eccKc->curve);
    *eccRef = EC_KEY_new_by_curve_name(nCurve);
    if (*eccRef == NULL)
    {
        printf("EC_KEY_new_by_curve_name call failed.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    // Set private key (if eccKc contains a private key)
    // +++++++++++++++++++++++++++++++++++++++++++++++++
    if (eccKc->privLen != 0)
    {
        bn_ecc_priv = BN_new();
        // No need to call BN_init for OpenSSL 1.0.2
        // if (bn_ecc_priv != NULL) { BN_init(bn_ecc_priv); } else { sw = ERR_MEMORY; goto err; }
        if (bn_ecc_priv == NULL) { sw = ERR_MEMORY; goto err; }
        if (!BN_bin2bn(eccKc->priv, eccKc->privLen, bn_ecc_priv))
        {
            printf("Bignum error priv key.\n");
            sw = ERR_CRYPTO_ENGINE_FAILED;
            goto err;
        }
        DBGPRINTF("bn_ecc_priv: %s\n", BN_bn2hex(bn_ecc_priv));

        if (EC_KEY_set_private_key(*eccRef, bn_ecc_priv) != 1)
        {
            printf("EC_KEY_set_private_key failed.\n");
            sw = ERR_CRYPTO_ENGINE_FAILED;
            goto err;
        }
    }

    // Set public key
    // ++++++++++++++
    group = EC_GROUP_new_by_curve_name(nCurve);
    if (group == NULL)
    {
        printf("Unable to allocate memory for EC_GROUP\n");
        sw = ERR_MEMORY;
        goto err;
    }

    nByteCoordinate = ((eccKc->pubLen)-1) >> 1;

    // Get X coordinate
    X = BN_new();
    // No need to call BN_init for OpenSSL 1.0.2
    // if (X != NULL) { BN_init(X); } else { return ERR_MEMORY; }
    if (X == NULL) { return ERR_MEMORY; }
    if (!BN_bin2bn( &(eccKc->pub[1]), nByteCoordinate, X))
    {
        printf("Bignum error public key (X).\n");
        sw = ERR_CRYPTO_ENGINE_FAILED;
        goto err;
    }
    DBGPRINTF("X: %s\n", BN_bn2hex(X));

    // Get Y coordinate
    Y = BN_new();
    // No need to call BN_init for OpenSSL 1.0.2
    // if (Y != NULL) { BN_init(Y); } else { sw = ERR_MEMORY; goto err; }
    if (Y == NULL) { sw = ERR_MEMORY; goto err; }
    if (!BN_bin2bn( &(eccKc->pub[1+nByteCoordinate]), nByteCoordinate, Y))
    {
        printf("Bignum error public key (Y).\n");
        sw = ERR_CRYPTO_ENGINE_FAILED;
        goto err;
    }
    DBGPRINTF("Y: %s\n", BN_bn2hex(Y));

    // Create a new point object
    pubPoint = EC_POINT_new(group);
    if (pubPoint == NULL)
    {
        printf("EC_POINT_new() failed.\n");
        sw = ERR_MEMORY;
        goto err;
    }
    if ( (retval = EC_POINT_set_affine_coordinates_GFp(group, pubPoint, X, Y, NULL)) != 1 )
    {
        printf("EC_POINT_set_affine_coordinates_GFp failed (retval=%d).\n", retval);
        sw = ERR_CRYPTO_ENGINE_FAILED;
        goto err;
    }
    if (EC_KEY_set_public_key(*eccRef, pubPoint) != 1)
    {
        printf("EC_KEY_set_public_key failed.\n");
        sw = ERR_CRYPTO_ENGINE_FAILED;
        goto err;
    }

    // NOTE: Recalculate Public key from private key
    // ctx = BN_CTX_new();
    // BN_CTX_start(ctx);

    // group = EC_KEY_get0_group(eccKeyTls_A);
    // pubPoint = EC_POINT_new(group);
    // EC_POINT_mul(group, pubPoint, bn_ecc_priv, NULL, NULL, ctx);
    // EC_KEY_set_public_key(eccKeyTls_A, pubPoint);
    sw = SW_OK;

err:
    if (bn_ecc_priv != NULL) { BN_free(bn_ecc_priv); }
    if (X != NULL) { BN_free(X); }
    if (Y != NULL) { BN_free(Y); }
    if (pubPoint != NULL) { EC_POINT_free(pubPoint); }
    if (group != NULL) { EC_GROUP_free(group); }

    if (sw != SW_OK) {
        if (*eccRef != NULL) { EC_KEY_free(*eccRef); }
    }

    return sw;
}

/**
 * Key unwrapping according to RFC3394 (https://tools.ietf.org/html/rfc3394)
 * \note Only tested with an 128 bits wrapKey.
 * @param[in] wrapKey Secret key used to unwrap \p in with. Also called KEK (key encryption key)
 * @param[in] wrapKeyLen Length in byte of wrapKey
 * @param[in,out] out IN: buffer of at least \p outLen byte; OUT: unwrapped key
 * @param[in,out] outLen IN: size of buffer \p out provided; OUT: actual length of unwrapped key
 * @param[in] in Wrapped key to be unwrapped
 * @param[in] inLen Length in byte of key to be unwrapped
 */
U16 HOSTCRYPTO_AesUnwrapKeyRFC3394(const U8 *wrapKey, U16 wrapKeyLen, U8 *out, U16 *outLen, const U8 *in, U16 inLen)
{
    unsigned char *iv = NULL;
    int ret = 0;
    AES_KEY wctx;
    int keybits = wrapKeyLen * 8;
    U16 sw = SW_OK;

    if (*outLen < (inLen - 8))
    {
        return ERR_API_ERROR;
    }

    if (AES_set_decrypt_key(wrapKey, keybits, &wctx))
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    ret = AES_unwrap_key(&wctx, iv, out, in, inLen);

    if (ret == 0)
    {
        // Wrong wrapKey?
        sw = ERR_PATTERN_COMPARE_FAILED;
    }
    else if (ret < 0)
    {
        // Wrong parameters?
        sw = ERR_API_ERROR;
    }
    else
    {
        sw = SW_OK;
        *outLen = (U16)ret;
    }

    return sw;
}

/**
 * Key wrapping according to RFC3394 (https://tools.ietf.org/html/rfc3394)
 * \note Only tested with an 128 bits wrapKey. When wrapping a 128 bit key (16 byte), the resulting
 *  wrapped key is 24 byte long.
 * @param[in] wrapKey Secret key used to wrap \p in. Also called KEK (key encryption key)
 * @param[in] wrapKeyLen Length in byte of wrapKey
 * @param[in,out] out IN: buffer of at least \p outLen byte; OUT: wrapped key
 * @param[in,out] outLen IN: size of buffer \p out provided; OUT: actual length of wrapped key
 * @param[in] in Key to be wrapped
 * @param[in] inLen Length in byte of key to be wrapped
 */
U16 HOSTCRYPTO_AesWrapKeyRFC3394(const U8 *wrapKey, U16 wrapKeyLen, U8 *out, U16 *outLen, const U8 *in, U16 inLen)
{
    unsigned char *iv = NULL;
    int ret = 0;
    AES_KEY wctx;
    int keybits = wrapKeyLen * 8;

    if (*outLen < (inLen + 8))
    {
        return ERR_API_ERROR;
    }

    if (AES_set_encrypt_key(wrapKey, keybits, &wctx))
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    ret = AES_wrap_key(&wctx, iv, out, in, inLen);
    if (ret <= 0)
    {
        return ERR_API_ERROR;
    }

    *outLen = (U16)ret;

    return SW_OK;
}

#if defined(TGT_A71CH) || defined(TGT_A71CL)
U16 HOSTCRYPTO_HkdfExpandSha256(const U8 *secret, U16 secretLen, const U8 *info, U16 infoLen, U8 *derivedData, U16 derivedDataLen)
{
    U16 sw = SW_OK;
    unsigned char *ucRet = NULL;
    const EVP_MD *evp_md = EVP_sha256();

    ucRet = HKDF_Expand(evp_md,
        secret, secretLen,
        info, infoLen,
        derivedData, derivedDataLen);

    if (ucRet == NULL)
    {
        sw = ERR_CRYPTO_ENGINE_FAILED;
    }

    return sw;
}

U16 HOSTCRYPTO_HkdfFullSha256(const U8 *salt, U16 saltLen, const U8 *secret, U16 secretLen, const U8 *info, U16 infoLen, U8 *derivedData, U16 derivedDataLen)
{
    U16 sw = SW_OK;
    unsigned char *ucRet = NULL;
    const EVP_MD *evp_md = EVP_sha256();


    ucRet = HKDF(evp_md,
        salt, saltLen,
        secret, secretLen,
        info, infoLen,
        derivedData, derivedDataLen);


    if (ucRet == NULL)
    {
        sw = ERR_CRYPTO_ENGINE_FAILED;
    }

    return sw;
}

// Implements the CreatePremasterSecret functionality of RFC4279
U16 HOSTCRYPTO_TlsPskCreatePremasterSecret(const U8 *secret, U16 secretLen, U8 *premasterSecret, U16 *premasterSecretLen)
{
    U16 targetLen = 0;

    // Ensure buffer premasterSecret is big enough
    targetLen = 2 * 2 + 2 * secretLen;
    if (*premasterSecretLen < targetLen)
    {
        return ERR_BUF_TOO_SMALL;
    }

    premasterSecret[0] = (U8)(secretLen >> 8);
    premasterSecret[1] = (U8)secretLen;
    memset(&premasterSecret[2], 0x00, secretLen);
    premasterSecret[2+secretLen] = (U8)(secretLen >> 8);
    premasterSecret[3+secretLen] = (U8)secretLen;
    memcpy(&premasterSecret[4+secretLen], secret, secretLen);

    *premasterSecretLen = targetLen;
    return SW_OK;
}

// Implements the CreatePremasterSecret functionality of RFC5489
U16 HOSTCRYPTO_TlsEcdhPskCreatePremasterSecret(const U8 *ecdhSS, U16 ecdhSSLen, const U8 *secret, U16 secretLen, U8 *premasterSecret, U16 *premasterSecretLen)
{
    U16 targetLen = 0;

    // Ensure buffer premasterSecret is big enough
    targetLen = 2 * 2 + ecdhSSLen + secretLen;
    if (*premasterSecretLen < targetLen)
    {
        return ERR_BUF_TOO_SMALL;
    }

    premasterSecret[0] = (U8)(ecdhSSLen >> 8);
    premasterSecret[1] = (U8)ecdhSSLen;
    memcpy(&premasterSecret[2], ecdhSS, ecdhSSLen);
    premasterSecret[2+ecdhSSLen] = (U8)(secretLen >> 8);
    premasterSecret[3+ecdhSSLen] = (U8)secretLen;
    memcpy(&premasterSecret[4+ecdhSSLen], secret, secretLen);

    *premasterSecretLen = targetLen;
    return SW_OK;
}

U16 HOSTCRYPTO_HmacSha256(const U8 *secret, U16 secretLen, const U8 *data, U16 dataLen, U8 *hmacData)
{
    unsigned int uiDerivedDataLen;
    const EVP_MD *evp_md = EVP_sha256();

    if (!HMAC(evp_md, secret, secretLen, data, dataLen, hmacData, &uiDerivedDataLen))
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    return SW_OK;
}

U16 HOSTCRYPTO_Tls1_2_P_Sha256(const U8 *secret, U16 secretLen, const U8 *seed, U16 seedLen, U8 *derivedData, U16 derivedDataLen)
{
    const EVP_MD *evp_md = EVP_sha256();
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX hmacCtx;
#else
    HMAC_CTX *hmacCtx = NULL;
#endif
    unsigned int nPos = 0;

    unsigned char hashed0[EVP_MAX_MD_SIZE];
    unsigned char hashed1[EVP_MAX_MD_SIZE];

    U16 bytesToCopy;

    size_t digLen = EVP_MD_size(evp_md);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    // Initialize HMAC
    HMAC_CTX_init(&hmacCtx);

    // First compute A(1) = HMAC(secret, SEED)
    if (!HMAC_Init_ex(&hmacCtx, secret, secretLen, evp_md, NULL))
        goto err;
    if (!HMAC_Update(&hmacCtx, seed, seedLen))
        goto err;
    if (!HMAC_Final(&hmacCtx, hashed0, NULL))
        goto err;

    while (derivedDataLen)
    {
        // Now compute P(N) = HMAC(secret, A(N) | seed) # N > 0
        if (!HMAC_Init_ex(&hmacCtx, NULL, 0, NULL, NULL))
            goto err;
        if (!HMAC_Update(&hmacCtx, hashed0, digLen))
            goto err;
        if (!HMAC_Update(&hmacCtx, seed, seedLen))
            goto err;
        if (!HMAC_Final(&hmacCtx, hashed1, NULL))
            goto err;

        bytesToCopy = (derivedDataLen < digLen) ? derivedDataLen : (U16)digLen;

        memcpy(&derivedData[nPos], hashed1, bytesToCopy);
        derivedDataLen -= bytesToCopy;
        nPos += bytesToCopy;

        // Compute A(N+1) and store for next round
        if (!HMAC_Init_ex(&hmacCtx, NULL, 0, NULL, NULL))
            goto err;
        if (!HMAC_Update(&hmacCtx, hashed0, digLen))
            goto err;
        if (!HMAC_Final(&hmacCtx, hashed0, NULL))
            goto err;
    }

    HMAC_CTX_cleanup(&hmacCtx);
    return SW_OK;
#else
    // Initialize HMAC
    hmacCtx = HMAC_CTX_new();
    if (hmacCtx == NULL) {
        return HOST_CRYPTO_ERROR;
    }

    // First compute A(1) = HMAC(secret, SEED)
    if (!HMAC_Init_ex(hmacCtx, secret, secretLen, evp_md, NULL))
        goto err;
    if (!HMAC_Update(hmacCtx, seed, seedLen))
        goto err;
    if (!HMAC_Final(hmacCtx, hashed0, NULL))
        goto err;

    while (derivedDataLen)
    {
        // Now compute P(N) = HMAC(secret, A(N) | seed) # N > 0
        if (!HMAC_Init_ex(hmacCtx, NULL, 0, NULL, NULL))
            goto err;
        if (!HMAC_Update(hmacCtx, hashed0, digLen))
            goto err;
        if (!HMAC_Update(hmacCtx, seed, seedLen))
            goto err;
        if (!HMAC_Final(hmacCtx, hashed1, NULL))
            goto err;

        bytesToCopy = (derivedDataLen < digLen) ? derivedDataLen : (U16)digLen;

        memcpy(&derivedData[nPos], hashed1, bytesToCopy);
        derivedDataLen -= bytesToCopy;
        nPos += bytesToCopy;

        // Compute A(N+1) and store for next round
        if (!HMAC_Init_ex(hmacCtx, NULL, 0, NULL, NULL))
            goto err;
        if (!HMAC_Update(hmacCtx, hashed0, digLen))
            goto err;
        if (!HMAC_Final(hmacCtx, hashed0, NULL))
            goto err;
    }

    HMAC_CTX_free(hmacCtx);
    return SW_OK;
#endif

err:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_cleanup(&hmacCtx);
#else
    HMAC_CTX_free(hmacCtx);
#endif
    return ERR_CRYPTO_ENGINE_FAILED;
}

#else // #ifdef TGT_A71CH
static U16 convertKeyPairToByteArrays(RSA *pKeyPair, int bits, U8 *pubKey, U16 *pubKeyLen,
    U8 *prvKey_p, U16 *prvKey_pLen,
    U8 *prvKey_q, U16 *prvKey_qLen,
    U8 *prvKey_dp, U16 *prvKey_dpLen,
    U8 *prvKey_dq, U16 *prvKey_dqLen,
    U8 *prvKey_ipq,  U16 *prvKey_ipqLen)
{
    U16 pubLen = 0;
    U16 pLen = 0;
    U16 qLen = 0;
    U16 dpLen = 0;
    U16 dqLen = 0;
    U16 ipqLen = 0;

    U16 fullLen = 0;
    U16 halfLen = 0;

    switch (bits)
    {
    case 1024:
        fullLen = 128;
        halfLen = 64;
        break;
    case 2048:
        fullLen = 256;
        halfLen = 128;
        break;
    default:
        printf("Rsa bitlength %d not supported.\n", bits);
        return ERR_API_ERROR;
    }

    *pubKeyLen = fullLen;
    *prvKey_pLen = halfLen;
    *prvKey_qLen = halfLen;
    *prvKey_dpLen = halfLen;
    *prvKey_dqLen = halfLen;
    *prvKey_ipqLen = halfLen;

    pubLen = (U16) BN_bn2bin(pKeyPair->n, pubKey);
    if (pubLen < fullLen)
    {
        // prepend with leading zeroes if necessary
        memmove(&pubKey[fullLen-pubLen], pubKey, pubLen);
        memset(pubKey, 0x00, fullLen-pubLen);
    }
#ifdef LOG_HOST_CRYPTO
    axPrintByteArray("pub key", pubKey, pubLen, AX_COLON_32);
#endif
    pLen = (U16) BN_bn2bin(pKeyPair->p, prvKey_p);
    if (pLen < halfLen)
    {
        // prepend with leading zeroes if necessary
        memmove(&prvKey_p[halfLen-pLen], prvKey_p, pLen);
        memset(prvKey_p, 0x00, halfLen-pLen);
    }
    if (pLen != halfLen) { printf("pLen=%d\n", pLen); }
#ifdef LOG_HOST_CRYPTO
    axPrintByteArray("p", prvKey_p, pLen, AX_COLON_32);
#endif
    qLen = (U16) BN_bn2bin(pKeyPair->q, prvKey_q);
    if (qLen < halfLen)
    {
        // prepend with leading zeroes if necessary
        memmove(&prvKey_q[halfLen-qLen], prvKey_q, qLen);
        memset(prvKey_q, 0x00, halfLen-qLen);
    }
    if (qLen != halfLen) { printf("qLen=%d\n", qLen); }
#ifdef LOG_HOST_CRYPTO
    axPrintByteArray("q", prvKey_q, qLen, AX_COLON_32);
#endif
    dpLen = (U16) BN_bn2bin(pKeyPair->dmp1, prvKey_dp);
    if (dpLen < halfLen)
    {
        // prepend with leading zeroes if necessary
        memmove(&prvKey_dp[halfLen-dpLen], prvKey_dp, dpLen);
        memset(prvKey_dp, 0x00, halfLen-dpLen);
    }
    if (dpLen != halfLen) { printf("dpLen=%d\n", dpLen); }
#ifdef LOG_HOST_CRYPTO
    axPrintByteArray("dp", prvKey_dp, dpLen, AX_COLON_32);
#endif
    dqLen = (U16) BN_bn2bin(pKeyPair->dmq1, prvKey_dq);
    if (dqLen < halfLen)
    {
        // prepend with leading zeroes if necessary
        memmove(&prvKey_dq[halfLen-dqLen], prvKey_dq, dqLen);
        memset(prvKey_dq, 0x00, halfLen-dqLen);
    }
    if (dqLen != halfLen) { printf("dqLen=%d\n", dqLen); }
#ifdef LOG_HOST_CRYPTO
    axPrintByteArray("dq", prvKey_dq, dqLen, AX_COLON_32);
#endif
    ipqLen = (U16) BN_bn2bin(pKeyPair->iqmp, prvKey_ipq);
    if (ipqLen < halfLen)
    {
        // prepend with leading zeroes if necessary
        memmove(&prvKey_ipq[halfLen-ipqLen], prvKey_ipq, ipqLen);
        memset(prvKey_ipq, 0x00, halfLen-ipqLen);
    }
    if (ipqLen != halfLen) { printf("ipqLen=%d\n", ipqLen); }
#ifdef LOG_HOST_CRYPTO
    axPrintByteArray("ipq", prvKey_ipq, ipqLen, AX_COLON_32);
#endif
    // printf("%d.%d.%d.%d.%d.%d\n", pubKeyLen, pLen, qLen, dpLen, dqLen, ipqLen);

    return SW_OK;
}

static U16 HOSTCRYPTO_RsaCreateOpenSslRsaFromComponents(RSA **rsaRef, rsaKeyComponents_t *rsaKc)
{
    RSA *rsa;
    int err = 1;
    unsigned long e = RSA_F4; // Setup exponent e = 0x10001 (65537)
    BIGNUM *exponent = BN_new();

    err = BN_set_word(exponent, e);
    if (err != 1)
    {
        printf("Unable to set public exponent.. Exiting..\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    rsa = RSA_new();
    err = RSA_generate_key_ex(rsa, rsaKc->bits, exponent, NULL);
    if (err != 1)
    {
        printf("Unable to generate RSA key.. Exiting.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    // Set flags for Sign / Verify APIs
    rsa->flags |= RSA_FLAG_SIGN_VER;

    // Overwrite references in key object

    // BIGNUM *n;
    // BIGNUM *e;
    // BIGNUM *d; // TODO: ?? not required if other components available ??
    // BIGNUM *p;
    // BIGNUM *q;
    // BIGNUM *dmp1;
    // BIGNUM *dmq1;
    // BIGNUM *iqmp;

    rsa->n = BN_bin2bn(rsaKc->pub, rsaKc->pubLen, NULL);
    rsa->p = BN_bin2bn(rsaKc->privP, rsaKc->privPLen, NULL);
    rsa->q = BN_bin2bn(rsaKc->privQ, rsaKc->privQLen, NULL);
    //
    rsa->dmp1 = BN_bin2bn(rsaKc->privDp, rsaKc->privDpLen, NULL);
    rsa->dmq1 = BN_bin2bn(rsaKc->privDq, rsaKc->privDqLen, NULL);
    rsa->iqmp = BN_bin2bn(rsaKc->privIpq, rsaKc->privIpqLen, NULL);

    *rsaRef = rsa;
    return SW_OK;
}

/*
 * bits = modulus size in bits (e.g. 1024 or 2048)
 */
U16 HOSTCRYPTO_RsaGenerateKeyPairComponents(int bits, U8 *pN, U16 *pNLen, U8 *pP, U16 *pPLen, U8 *pQ, U16 *pQLen, U8 *pDp, U16 *pDpLen, U8 *pDq, U16 *pDqLen, U8 *pIpq, U16 *pIpqLen)
{
    int rv = 0;
    BIGNUM *bn;
    RSA *rsaKey = NULL;
    U16 sw = 0;

    rsaKey = (RSA *) OPENSSL_malloc(sizeof(RSA));
    if (!rsaKey)
    {
        printf("Failed allocating memory for RSA key pair\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    memset(rsaKey, 0, sizeof(RSA));
    rsaKey->meth = RSA_PKCS1_SSLeay();
    if (rsaKey->meth->init)
        rsaKey->meth->init(rsaKey);

    bn = BN_new();
    if (!bn)
    {
        printf("Failed allocating memory for BN (big number).\n");
        OPENSSL_free(rsaKey);
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    BN_set_word(bn, 0x10001);
    rv = RSA_generate_key_ex(rsaKey, bits, bn, NULL);
    if (!rv)
    {
        OPENSSL_free(rsaKey);
        BN_free(bn);
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    BN_free(bn);

    /* convert the generated big integers to byte arrays */
    sw = convertKeyPairToByteArrays(rsaKey, bits, pN, pNLen, pP, pPLen, pQ, pQLen, pDp, pDpLen, pDq, pDqLen, pIpq, pIpqLen);

    OPENSSL_free(rsaKey);
    return sw;
}

U16 HOSTCRYPTO_RsaGenerateKeyPair(int bits, rsaKeyComponents_t *rsaKeypair)
{
    U16 sw = 0;
    // sw = HOSTCRYPTO_RsaGenerateKeyPairComponents(bits, pN, &NLen, pP, &PLen, pQ, &QLen, pDp, &DpLen, pDq, &DqLen, pIpq, &IpqLen);
    sw = HOSTCRYPTO_RsaGenerateKeyPairComponents(bits, rsaKeypair->pub, &(rsaKeypair->pubLen),
        rsaKeypair->privP, &(rsaKeypair->privPLen),
        rsaKeypair->privQ, &(rsaKeypair->privQLen),
        rsaKeypair->privDp, &(rsaKeypair->privDpLen),
        rsaKeypair->privDq, &(rsaKeypair->privDqLen),
        rsaKeypair->privIpq, &(rsaKeypair->privIpqLen));
    if ( (bits <= 0) || (bits > 60000) )
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    rsaKeypair->bits = (U16)bits;
    return sw;
}

//
// KeyLength is implicit in rsaKeyComponents_t typed argument
// TODO:
//  (1) Use (signature) type parameter
//  (2) Clean up memory after call
U16 HOSTCRYPTO_RsaSign(HASHAlgo_t hType, U8 *m, U16 mLen, U8 *sig, U16 *sigLen, rsaKeyComponents_t *rsaKc)
{
    RSA *rsaKp;
    int rv = 0;
    unsigned int uiSigLen;
    U16 sw;
    int type = NID_sha1;

    sw = HOSTCRYPTO_RsaCreateOpenSslRsaFromComponents(&rsaKp, rsaKc);
    if (sw != SW_OK)
    {
        printf("Failed to convert Rsa components into OpenSSL key pair.\n");
        return sw;
    }

    if (hType == HASHAlgo_SHA1) {
        type = NID_sha1;
    }
    else if (hType == HASHAlgo_SHA256) {
        type = NID_sha256;
    }
    else {
        return ERR_API_ERROR;
    }

    // RSA_sign(type, m, m_length, sigret, siglen, rsa);
    rv = RSA_sign(type, m, mLen, sig, &uiSigLen, rsaKp);

    *sigLen = (U16)uiSigLen;

    if (rv != 1)
    {
        printf("Rsa_sign operation failed.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    return SW_OK;
}

// NOTE: The following Sign/Verify functions are almost identical in name to the previous one, but have different functionality!
// TODO: Make the two names more distinct

/**
 * RSA sign operation according PKCS #1 v2.1 (full algorithm)
 * @param[in] hashFunction
 * @param[in] msg
 * @param[in] msgLen
 * @param[in,out] sig
 * @param[in,out] sigLen
 * @param[in] pKey
 * @return  1 on successful verification, 0 on failure
 *
 * Note: this code is example code, it does not clean up or manage openSSL objects properly (no freeing etc.)
 */
U16 HOSTCRYPTO_RSA_Sign(HASHAlgo_t hType, U8 *msg, U32 msgLen, U8 *sig, U16 *sigLen, rsaKeyComponents_t *rsaKc)
{
    int rv = 0;
    U8 hash[32];
    U8 EMSAEncodedMessage[256];
    EVP_MD_CTX sha_ctx;
    unsigned int digestLength = 32;
    RSA *rsaKp;
    U16 sw;

    sw = HOSTCRYPTO_RsaCreateOpenSslRsaFromComponents(&rsaKp, rsaKc);
    if (sw != SW_OK)
    {
        printf("Failed to convert Rsa components into OpenSSL key pair.\n");
        return sw;
    }

    if (hType == HASHAlgo_SHA1)
    {
        EVP_MD_CTX_init(&sha_ctx);
        EVP_DigestInit(&sha_ctx, EVP_sha1());
        EVP_DigestUpdate(&sha_ctx, msg, msgLen);
        EVP_DigestFinal(&sha_ctx, hash, &digestLength);
        EVP_MD_CTX_cleanup(&sha_ctx);

        /* EMSA encoding */
        rv = RSA_padding_add_PKCS1_PSS(rsaKp, EMSAEncodedMessage, hash, EVP_sha1(), -2 /* maximum salt length*/);
    }
    else if (hType == HASHAlgo_SHA256)
    {
        EVP_MD_CTX_init(&sha_ctx);
        EVP_DigestInit(&sha_ctx, EVP_sha256());
        EVP_DigestUpdate(&sha_ctx, msg, msgLen);
        EVP_DigestFinal(&sha_ctx, hash, &digestLength);
        EVP_MD_CTX_cleanup(&sha_ctx);

        /* EMSA encoding */
        rv = RSA_padding_add_PKCS1_PSS(rsaKp, EMSAEncodedMessage, hash, EVP_sha256(), -2 /* maximum salt length*/);
    }
    else {
        printf("hType: %d is undefined\n", hType);
        return ERR_API_ERROR;
    }

    if (!rv)
    {
        printf("Failed PKCS#1 v2.1 padding %i\n", rv);
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    /* perform digital signature */
    rv = RSA_private_encrypt(256, EMSAEncodedMessage, sig, rsaKp, RSA_NO_PADDING);
    if (rv < 0)
    {
        printf("Failed PKCS#1 v2.1 encryption %i\n", rv);
        return ERR_CRYPTO_ENGINE_FAILED;
    }
    else
    {
        *sigLen = (U16)rv;
    }

    return SW_OK;
}

/**
 * RSA verify operation according PKCS #1 v2.1 (full algorithm)
 * @param[in] hashFunction
 * @param[in] msg
 * @param[in] msgLen
 * @param[in] sig
 * @param[in] sigLen
 * @param[in] rsaKc
 * @param[out] pResult  Pointer to the computed result of the verification. (0 for failure; 1 for success)
 *
 * Note: this code is example code, it does not clean up or manage openSSL objects properly (no freeing etc.)
 */
U16 HOSTCRYPTO_RSA_Verify(HASHAlgo_t hType, U8 *msg, U32 msgLen, U8 *sig, U32 sigLen, rsaKeyComponents_t *rsaKc, U8 *pVerified)
{
    int verified = -1;
    int rv = 0;
    U8 decrypted[256];
    U8 digest[32];
    EVP_MD_CTX sha_ctx;
    unsigned int digestLength = 32;
    RSA *rsaKp;
    U16 sw;

    sw = HOSTCRYPTO_RsaCreateOpenSslRsaFromComponents(&rsaKp, rsaKc);
    if (sw != SW_OK)
    {
        printf("Failed to convert Rsa components into OpenSSL key pair.\n");
        return sw;
    }

    if (hType == HASHAlgo_SHA1)
    {
        EVP_MD_CTX_init(&sha_ctx);
        EVP_DigestInit(&sha_ctx, EVP_sha1());
        EVP_DigestUpdate(&sha_ctx, msg, msgLen);
        EVP_DigestFinal(&sha_ctx, digest, &digestLength);
        EVP_MD_CTX_cleanup(&sha_ctx);

        rv = RSA_public_decrypt(sigLen, sig, decrypted, rsaKp, RSA_NO_PADDING);
        if (rv < 0)
        {
            printf("Failed RSA_public_decrypt() %i\n", rv);
            return ERR_CRYPTO_ENGINE_FAILED;
        }

        verified = RSA_verify_PKCS1_PSS(rsaKp, digest, EVP_sha1(), decrypted, -2); // salt length not passed
    }
    else if (hType == HASHAlgo_SHA256)
    {
        EVP_MD_CTX_init(&sha_ctx);
        EVP_DigestInit(&sha_ctx, EVP_sha256());
        EVP_DigestUpdate(&sha_ctx, msg, msgLen);
        EVP_DigestFinal(&sha_ctx, digest, &digestLength);
        EVP_MD_CTX_cleanup(&sha_ctx);

        rv = RSA_public_decrypt(sigLen, sig, decrypted, rsaKp, RSA_NO_PADDING);
        if (rv < 0)
        {
            printf("Failed RSA_public_decrypt() %i\n", rv);
            return ERR_CRYPTO_ENGINE_FAILED;
        }

        verified = RSA_verify_PKCS1_PSS(rsaKp, digest, EVP_sha256(), decrypted, -2); // salt length not passed
    }
    else {
        printf("hType: %d is undefined\n", hType);
        return ERR_API_ERROR;
    }

    *pVerified = (U8)verified;
    return SW_OK;
}
#endif // TGT_A71CH

#ifdef TGT_A70CM
//
// Currently only 128 bits KEK and 128 bit keyToWrap is supported
//
U16 HOSTCRYPTO_WrapKeyDsmr40(U8 *kek, U16 kekLen, U8 *keyToWrap, U16 keyToWrapLen,
    U8 *iv, U16 ivLen, U8 *wrappedKey, U16 *wrappedKeyLen)
{
    U8 buffer[32];
    U8 filler = 0x2F;
    int offset = 0;
    int i = 0;
    S32 sRet = 0;

    if (keyToWrapLen != 16)
    {
        printf("ERROR: Can only work with 128 bit AES keys.\n");
        return ERR_API_ERROR;
    }

    if (*wrappedKeyLen < 32)
    {
        printf("Caller must provide buffer that is big enough.\n");
        return ERR_BUF_TOO_SMALL;
    }

    offset = 0;
    buffer[offset++] = filler;
    buffer[offset++] = filler;
    buffer[offset++] = (U8) ( (keyToWrapLen >> 8) & 0x00FF);
    buffer[offset++] = (U8) ( keyToWrapLen & 0x00FF);
    for (i=0; i<keyToWrapLen; i++)
    {
        buffer[offset++] = keyToWrap[i];
    }

    for (i=0; i < 12; i++)
    {
        buffer[offset++] = filler;
    }

    /**
     * S32 HOST_AES_CBC_Process(U8* pKey, U32 keyLen, U8* pIv, U8 dir, U8* pIn, U32 inLen, U8 * pOut);
     * @retval ERR_API_ERROR
     * @retval HOST_CRYPTO_OK
     * @retval HOST_CRYPTO_ERROR
     */

    sRet = HOST_AES_CBC_Process(kek, kekLen, iv, HOST_ENCRYPT, buffer, 32, wrappedKey);
    *wrappedKeyLen = 32;

    if (sRet == HOST_CRYPTO_OK)
    {
        return SW_OK;
    }
    else
    {
        printf("Invocation of HOST_AES_CBC_Process failed.\n");
        return ERR_GENERAL_ERROR;
    }
}

//
// Currently only 128 bits KEK and 128 bit keyToWrap is supported
//
U16 HOSTCRYPTO_UnwrapKeyDsmr40(U8 *kek, U16 kekLen, U8 *keyToUnwrap, U16 keyToUnwrapLen,
    U8 *iv, U16 ivLen, U8 *unwrappedKey, U16 *unwrappedKeyLen)
{
    U8 filler = 0x2F;
    int i = 0;
    S32 sRet = 0;
    U8 buffer[32];
    U16 tagLen = 0;

    if (keyToUnwrapLen != 32)
    {
        printf("ERROR: Can only work with 128 bit AES keys.\n");
        return ERR_API_ERROR;
    }

    if (*unwrappedKeyLen < 16)
    {
        printf("Caller must provide buffer that is big enough.\n");
        return ERR_BUF_TOO_SMALL;
    }

    /**
     * S32 HOST_AES_CBC_Process(U8* pKey, U32 keyLen, U8* pIv, U8 dir, U8* pIn, U32 inLen, U8 * pOut);
     * @retval ERR_API_ERROR
     * @retval HOST_CRYPTO_OK
     * @retval HOST_CRYPTO_ERROR
     */
    sRet = HOST_AES_CBC_Process(kek, kekLen, iv, HOST_DECRYPT, keyToUnwrap, 32, buffer);
    if (sRet != HOST_CRYPTO_OK)
    {
        printf("Invocation of HOST_AES_CBC_Process failed.\n");
        return ERR_GENERAL_ERROR;
    }

    // Now check on filler && length
    for (i=0; i<2; i++)
    {
        if (buffer[i] != filler)
            return ERR_PATTERN_COMPARE_FAILED;
    }
    tagLen = (buffer[2] << 8) + (buffer[3] & 0x00FF);
    if (tagLen != 16)
    {
        printf("Unwrapped key does not have expected size, size is: %d\n", tagLen);
        return ERR_PATTERN_COMPARE_FAILED;
    }

    memcpy(unwrappedKey, &buffer[4], tagLen);
    *unwrappedKeyLen = tagLen;

    for (i=(4+tagLen); i<keyToUnwrapLen; i++)
    {
        if (buffer[i] != filler)
            return ERR_PATTERN_COMPARE_FAILED;
    }

    return SW_OK;
}
#endif // TGT_A70CM

#ifdef TGT_A70CI
/**
 * @function HOST_RSA_GenerateKeyPair
 * @desctription Generates an RSA2048 key pair, keeps the generated key pair in RSA object available for next
 * operations (this avoids loading in the keys again for RSA_sign, RSA_verify, RSA_Decrypt and RSA_Encrypt etc.
 * @return  1 on success, 0 on failure
 */
int HOST_RSA_GenerateKeyPair(U8 * pN, U16 * pNLen, U8 * pP, U16 * pPLen, U8 * pQ, U16 * pQLen, U8 * pDp, U16 * pDpLen, U8 * pDq, U16 * pDqLen, U8 * pIpq, U16 * pIpqLen)
{
    int rv = 0;
    BIGNUM *bn;
//    EVP_PKEY* pkey = EVP_PKEY_new();
//    int r = 0;
//    int len = 0;

    lastGeneratedRsaKeyPair = (RSA *) OPENSSL_malloc(sizeof(RSA));
    if (!lastGeneratedRsaKeyPair)
    {
        printf("Failed allocating memory for RSA key pair\n");
        return 0;
    }
    memset(lastGeneratedRsaKeyPair, 0, sizeof(RSA));
    lastGeneratedRsaKeyPair->meth = RSA_PKCS1_SSLeay();
    if (lastGeneratedRsaKeyPair->meth->init)
        lastGeneratedRsaKeyPair->meth->init(lastGeneratedRsaKeyPair);

    ERR_clear_error();
    EVP_MD_CTX_init(&mctx);
    bn = BN_new();
    if (!lastGeneratedRsaKeyPair || !bn)
    return 0;
    BN_set_word(bn, 0x10001);
    rv = RSA_generate_key_ex(lastGeneratedRsaKeyPair, 2048, bn, NULL);
    if (!rv)
    {
        return 0;
    }
    BN_free(bn);

    /* convert the generated big integers to byte arrays */
    convertKeyPairToByteArrays(lastGeneratedRsaKeyPair, 2048,
        pN, pNLen,
        pP, pPLen,
        pQ, pQLen,
        pDp, pDpLen,
        pDq, pDqLen,
        pIpq, pIpqLen);

    return 1;
}

/**
 * @function HOST_RSA_Sign
 * @desctription RSA sign operation according PKCS #1 v2.1 (full algorithm)
 * @param hashFunction
 * @param msg
 * @param msgLen
 * @param sig
 * @param sigLen
 * @param pKey
 * @return  1 on successful verification, 0 on failure
 *
 * Note: this code is example code, it does not clean up or manage openSSL objects properly (no freeing etc.)
 */
int HOST_RSA_Sign(U8 hashFunction, U8 *msg, U32 msgLen, U8 *sig, U32 * sigLen,
    U8 * pP, U16 lengthP, U8 * pQ, U16 lengthQ, U8 * pDp, U16 lengthDp, U8 * pDq, U16 lengthDq, U8 * pIpq, U16 lengthIpq)
{
  int rv = 0;
  U8 hash[32];
  U8 EMSAEncodedMessage[256];
  EVP_MD_CTX sha_ctx;
  unsigned int digestLength = 32;

  // make sure that we use the correct key (the last generated key pair is used in this function, NOT the input private key data)
  verifyMatchingPrivateKey(pP, lengthP, pQ, lengthQ, pDp, lengthDp, pDq, lengthDq, pIpq, lengthIpq);

  if (hashFunction == HOST_CRYPTO_USE_SHA1)
  {
      EVP_MD_CTX_init(&sha_ctx);
      EVP_DigestInit(&sha_ctx, EVP_sha1());
      EVP_DigestUpdate(&sha_ctx, msg, msgLen);
      EVP_DigestFinal(&sha_ctx, hash, &digestLength);
      EVP_MD_CTX_cleanup(&sha_ctx);

      /* EMSA encoding */
      rv = RSA_padding_add_PKCS1_PSS(lastGeneratedRsaKeyPair, EMSAEncodedMessage, hash, EVP_sha1(), -2 /* maximum salt length*/);
      if (!rv)
      {
          printf("Failed PKCS#1 v2.1 padding %i\n", rv);
          return 0;
      }

      /* perform digital signature */
      rv = RSA_private_encrypt(256, EMSAEncodedMessage, sig, lastGeneratedRsaKeyPair, RSA_NO_PADDING);
      if (rv < 0)
      {
          printf("Failed PKCS#1 v2.1 encryption %i\n", rv);
          return 0;
      }
      else
      {
          *sigLen = rv;
      }
  }
  else
  {
      EVP_MD_CTX_init(&sha_ctx);
      EVP_DigestInit(&sha_ctx, EVP_sha256());
      EVP_DigestUpdate(&sha_ctx, msg, msgLen);
      EVP_DigestFinal(&sha_ctx, hash, &digestLength);
      EVP_MD_CTX_cleanup(&sha_ctx);

      /* EMSA encoding */
      rv = RSA_padding_add_PKCS1_PSS(lastGeneratedRsaKeyPair, EMSAEncodedMessage, hash, EVP_sha256(), -2 /* maximum salt length*/);
      if (!rv)
      {
          printf("Failed PKCS#1 v2.1 padding %i\n", rv);
          return 0;
      }

      /* perform digital signature */
      rv = RSA_private_encrypt(256, EMSAEncodedMessage, sig, lastGeneratedRsaKeyPair, RSA_NO_PADDING);
      if (rv < 0)
      {
          printf("Failed PKCS#1 v2.1 encryption %i\n", rv);
          return 0;
      }
      else
      {
          *sigLen = rv;
      }
  }

  return 1;
}

/**
 * @function HOST_RSA_Verify
 * @desctription RSA verify operation according PKCS #1 v2.1 (full algorithm)
 * @param hashFunction
 * @param msg
 * @param msgLen
 * @param sig
 * @param sigLen
 * @param pKey
 * @return  1 on successful verification, 0 on failure
 *
 * Note: this code is example code, it does not clean up or manage openSSL objects properly (no freeing etc.)
 */
int HOST_RSA_Verify(U8 hashFunction, U8 *msg, U32 msgLen, U8 *sig, U32 sigLen, U8 * pPubKey, U16 pubKeyLen)
{
  int verified = -1;
  int rv = 0;
  U8 decrypted[256];
  U8 digest[32];
  EVP_MD_CTX sha_ctx;
  unsigned int digestLength = 32;

  // make sure that we use the correct key (the last generated key pair is used in this function, NOT the input public key data)
  verifyMatchingPublicKey(pPubKey, pubKeyLen);

  if (hashFunction == HOST_CRYPTO_USE_SHA1)
  {
      EVP_MD_CTX_init(&sha_ctx);
      EVP_DigestInit(&sha_ctx, EVP_sha1());
      EVP_DigestUpdate(&sha_ctx, msg, msgLen);
      EVP_DigestFinal(&sha_ctx, digest, &digestLength);
      EVP_MD_CTX_cleanup(&sha_ctx);

      rv = RSA_public_decrypt(sigLen, sig, decrypted, lastGeneratedRsaKeyPair, RSA_NO_PADDING);
      if (rv < 0)
      {
          printf("Failed RSA_public_decrypt() %i\n", rv);
      }

      verified = RSA_verify_PKCS1_PSS(lastGeneratedRsaKeyPair, digest, EVP_sha1(), decrypted, -2); // salt length not passed
  }
  else
  {
      EVP_MD_CTX_init(&sha_ctx);
      EVP_DigestInit(&sha_ctx, EVP_sha256());
      EVP_DigestUpdate(&sha_ctx, msg, msgLen);
      EVP_DigestFinal(&sha_ctx, digest, &digestLength);
      EVP_MD_CTX_cleanup(&sha_ctx);

      rv = RSA_public_decrypt(sigLen, sig, decrypted, lastGeneratedRsaKeyPair, RSA_NO_PADDING);
      if (rv < 0)
      {
          printf("Failed RSA_public_decrypt() %i\n", rv);
      }

      verified = RSA_verify_PKCS1_PSS(lastGeneratedRsaKeyPair, digest, EVP_sha256(), decrypted, -2); // salt length not passed
  }

  return verified;
}

/**
 * @function HOST_RSA_Decrypt
 * @desctription RSA decrypt operation (PKCS#1 v2.1) RSAES-OAEP
 * @return  1 on successful decryption, 0 on failure
 *
 * Note: this code is example code, it does not clean up or manage openSSL objects properly (no freeing etc.)
 */
int HOST_RSA_Decrypt(U8 *userId,
    U32 inDataLength,
    U8 *pP,
    U16 lengthP,
    U8 *pQ,
    U16 lengthQ,
    U8 *pDp,
    U16 lengthDp,
    U8 *pDq,
    U16 lengthDq,
    U8 *pIpq,
    U16 lengthIpq,
    U8 *pOutData,
    U16 *pOutDataLength)
{
  U8 oaepMsg[OAEP_MSG_LENGTH];
  int rv = 0;

  // make sure that we use the correct key (the last generated key pair is used in this function, NOT the input private key data)
  verifyMatchingPrivateKey(pP, lengthP, pQ, lengthQ, pDp, lengthDp, pDq, lengthDq, pIpq, lengthIpq);

  rv = RSA_private_decrypt(inDataLength, userId, oaepMsg, lastGeneratedRsaKeyPair, RSA_NO_PADDING);
  if (rv < 0)
  {
    printf("Failed RSA_private_decrypt\n");
    return 0;
  }
  else
  {
      // second part - decode the OAEP encoded message to the output message
      rv = HOST_EME_OAEP_Decode(oaepMsg, 256, pOutData, pOutDataLength);
  }

  return rv;
}

/**
 * RSA decrypt operation (PKCS#1 v2.1) RSAES-OAEP
 * @return  1 on successful verification, 0 on failure
 *
 * Note: this code is example code, it does not clean up or manage openSSL objects properly (no freeing etc.)
 */
int HOST_RSA_Encrypt(U8 *userId, U32 inDataLength, U8 *pPubKey, U16 lengthPubKey, U8 *pOutData, U16 *pOutDataLength)
{
  int rv = 0;
  U8 oaepMsg[OAEP_MSG_LENGTH];
  U16 oaepMsgLen = 0;

  // make sure that we use the correct key (the last generated key pair is used in this function, NOT the input private key data)
  verifyMatchingPublicKey(pPubKey, lengthPubKey);

  // first encode the data
  rv = HOST_EME_OAEP_Encode(userId, inDataLength, oaepMsg, &oaepMsgLen);

#ifdef APPLET_V2_0
    /* important: the input message should be OAEP encoded; this encoding is not done here, but we overwrite the first byte to 0x00
        (as the first byte of the OAEP encoded message would be 0x00 as well) */
    assert(oaepMsg[0] == 0x00);
#endif

  assert(oaepMsgLen == OAEP_MSG_LENGTH);

  rv = RSA_public_encrypt(oaepMsgLen, oaepMsg, pOutData, lastGeneratedRsaKeyPair, RSA_NO_PADDING);
  if (rv < 0)
  {
    printf("encrypt returns %i\n", rv);
    return 0;
  }
  *pOutDataLength = (U16) rv;

  return 1;
}

static void verifyMatchingPublicKey(U8 * pPub, U16 pubKeyLen)
{
    int l = 0;
    U8 pubKey[EXPECTED_RSA2048_PUBKEY_LENGTH];

    assert(pubKeyLen == EXPECTED_RSA2048_PUBKEY_LENGTH);

    l = BN_bn2bin(lastGeneratedRsaKeyPair->n, pubKey);
    assert(memcmp(pubKey, &pPub[EXPECTED_RSA2048_PUBKEY_LENGTH-l], l) == 0);
}

static void verifyMatchingPrivateKey(U8 * pP, U16 lengthP, U8 * pQ, U16 lengthQ, U8 * pDp, U16 lengthDp, U8 * pDq, U16 lengthDq, U8 * pIpq, U16 lengthIpq)
{
    int l = 0;
    RSA * kp = lastGeneratedRsaKeyPair;
    U8 crtComp[EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH];

    assert(lengthP == EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH);
    assert(lengthQ == EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH);
    assert(lengthDp == EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH);
    assert(lengthDq == EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH);
    assert(lengthIpq == EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH);

    l = BN_bn2bin(kp->p, crtComp);
    assert(memcmp(crtComp, &pP[EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH-l], l) == 0);
    l = BN_bn2bin(kp->q, crtComp);
    assert(memcmp(crtComp, &pQ[EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH-l], l) == 0);
    l = BN_bn2bin(kp->dmp1, crtComp);
    assert(memcmp(crtComp, &pDp[EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH-l], l) == 0);
    l = BN_bn2bin(kp->dmq1, crtComp);
    assert(memcmp(crtComp, &pDq[EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH-l], l) == 0);
    l = BN_bn2bin(kp->iqmp, crtComp);
    assert(memcmp(crtComp, &pIpq[EXPECTED_RSA2048_PRVKEY_CRT_COMP_LENGTH-l], l) == 0);
}


U16 HOSTCRYPTO_GenerateEccKeyByName(int curveName, EC_KEY** ppKey)
{
    int retval;

    assert(ppKey != NULL);

    // free existing private key
    if (*ppKey != NULL)
    {
       EC_KEY_free(*ppKey);
    }

    // create key
    *ppKey = EC_KEY_new_by_curve_name(curveName);
    if (*ppKey == NULL)
    {
        // key creation failed
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    // generate key material
    retval = EC_KEY_generate_key(*ppKey);

    if (retval == 1)
    {
        return SW_OK;
    }
    else
    {
        return ERR_CRYPTO_ENGINE_FAILED;
    }
}

/**
 * Generates a key pair for NIST P-256 curve and returns the private and public key as byte arrays.
 * @return HOST_CRYPTO_OK when generation was succesful, HOST_CRYPTO_ERROR when generation failed.
 */
int HOST_ECC_GenerateKeyPair(U8 * pPublicKey, U16 * pPublicKeyLength, U8 * pPrivateKey, U16 * pPrivateKeyLength)
{
    int retval;
    EC_KEY *ecckey;
    const BIGNUM *bnPriv, *bnPub;
    const EC_POINT * pubKey;
    BN_CTX  *ctx=NULL;
    U32 privateEccKeyLen = 256/8;

    // create key
    ecckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecckey == NULL)
    {
        // key creation failed
        return HOST_CRYPTO_ERROR;
    }

    // generate key material
    retval = EC_KEY_generate_key(ecckey);

    bnPriv = EC_KEY_get0_private_key(ecckey);
    *pPrivateKeyLength = (U16) BN_bn2bin(bnPriv, pPrivateKey);

    if ( (*pPrivateKeyLength != privateEccKeyLen) && (*pPrivateKeyLength > 0))
    {
        axZeroSignExtend(pPrivateKey, *pPrivateKeyLength, privateEccKeyLen);
        *pPrivateKeyLength = privateEccKeyLen;
    }

    pubKey = EC_KEY_get0_public_key(ecckey);
    ctx = BN_CTX_new();
    bnPub = EC_POINT_point2bn(
        EC_KEY_get0_group(ecckey),
        pubKey,
        EC_KEY_get_conv_form(ecckey),
        NULL,
        ctx);

    if (bnPub)
       *pPublicKeyLength = (U16) BN_num_bytes(bnPub);

    *pPublicKeyLength = (U16)BN_bn2bin(bnPub, pPublicKey);

    EC_KEY_free(ecckey);

    if (retval == 1) {
        return HOST_CRYPTO_OK;
    }
    else {
        return HOST_CRYPTO_ERROR;
    }
}

int HOST_ECC_ComputeSharedSecret(U8 * pPrvKey, U32 prvKeyLength, U8 * pPubKey, U16 pubKeyLen, U8* pSharedSecretData, U16* pSharedSecretLength, U16 maxSharedSecretLength)
{
    int retval;
    int field_size;
    EC_KEY* pHostKey;
    EC_POINT* pExternalPoint = NULL;
    BIGNUM* pBigNum;
    const EC_GROUP* pGroup;

    // Create host key from supplied private key data
    // the curve is fixed
    int curveName = NID_X9_62_prime256v1;
    pHostKey = EC_KEY_new_by_curve_name(curveName);

    pBigNum = BN_bin2bn(pPrvKey, prvKeyLength, NULL);
    if (pBigNum == NULL) {
        // BigNumber conversion failed
        return HOST_CRYPTO_ERROR;
    }

    // set private key
    retval = EC_KEY_set_private_key(pHostKey, pBigNum);
    if (retval != 1) {
        return HOST_CRYPTO_ERROR;
    }

    // release BIGNUM
    BN_free(pBigNum);

    // convert external public key data to POINT
    // external public key curve == local curve
    pGroup = EC_KEY_get0_group(pHostKey);
    pExternalPoint = EC_POINT_new(pGroup);
    // data has leading 0x04 (uncompressed point representation)
    retval = EC_POINT_oct2point(pGroup, pExternalPoint, pPubKey, pubKeyLen, NULL);
    if (retval != 1) {
        // point creation failed
        return HOST_CRYPTO_ERROR;
    }

    /* Compute the size of the shared secret */
    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pHostKey));
    *pSharedSecretLength = (field_size+7)/8;
    if (*pSharedSecretLength > maxSharedSecretLength) {
        return HOST_CRYPTO_ERROR;
    }

    /* Compute the shared secret, no KDF is applied */
    retval = ECDH_compute_key(pSharedSecretData, *pSharedSecretLength, pExternalPoint, pHostKey, NULL);
    if (retval != *pSharedSecretLength) {
        // computation failed
        return ERR_GENERAL_ERROR;
    }

    // OK
    return HOST_CRYPTO_OK;
}

/* @brief HOST_ECC_Verify()
 * @description Verifies a hash with a signature using the provided public key.
 * @return HOST_CRYPTO_OK when verification passed, HOST_CRYPTO_ERROR when verification failed.
 */
int HOST_ECC_Verify(U8 * pHash, U16 hashLen, U8 * pPubKey, U16 pubKeyLen, U8 * pSig, U16 sigLen)
{
    int rv;
    EC_KEY *ecckey;
    EC_POINT * ecPoint;
    EC_GROUP *ecgroup;

    assert(hashLen == SHA256_DIGEST_LENGTH);

    if (NULL == (ecckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
    {
        // error
        return HOST_CRYPTO_ERROR;
    }

    // set public key
    ecgroup= EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    if ((ecPoint = EC_POINT_new(ecgroup)) == NULL) {
        EC_GROUP_free(ecgroup);
        EC_KEY_free(ecckey);
        return HOST_CRYPTO_ERROR;
    }

    rv = EC_POINT_oct2point(ecgroup, ecPoint, pPubKey, pubKeyLen, NULL);
    if (rv != HOST_CRYPTO_OK)
    {
        return HOST_CRYPTO_ERROR;
    }

    EC_KEY_set_public_key(ecckey, ecPoint);
    rv = ECDSA_verify(0, (const U8*) pHash, SHA256_DIGEST_LENGTH, pSig, sigLen, ecckey);
    if (rv == 1)
    {
        return HOST_CRYPTO_OK;
    }
    else
    {
        return HOST_CRYPTO_ERROR;
    }
}

#endif // TGT_A70CI
