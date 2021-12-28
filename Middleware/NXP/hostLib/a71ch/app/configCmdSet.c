/**
 * @file configCmdSet.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'set'. Includes optional console handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// project specific include files
#include "sm_types.h"
#include "sm_apdu.h"
#include "tst_sm_util.h"
#include "tst_a71ch_util.h"
#include "probeAxUtil.h"
#include "configCmd.h"
#include "configCli.h"
#include "a71_debug.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#ifdef OPENSSL
#include <openssl/pem.h>
#endif

#define FLOW_VERBOSE_PROBE_A70

#ifdef FLOW_VERBOSE_PROBE_A70
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

// Warning: defining DBG_PROBE_A70 also exposes Private Key being set in log
// #define DBG_PROBE_A70

#ifdef DBG_PROBE_A70
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

#ifdef OPENSSL
/*
  The following macro defines a function body with the following
  function signature:

  EC_KEY *PEM_read_eckey(FILE *fp, EC_KEY **x, pem_password_cb *cb, void *u)
*/
IMPLEMENT_PEM_read_fp(eckey, EC_KEY, "EC PRIVATE KEY", ECPrivateKey)
#endif

/**
* Wrap key
*/
int a7xConfigCmdkWrapping(U8 * key, U16 * keyLen, U8 * wrapKey, U16 wrapKeyLen) {
    U8 wrappedKey[72];
    U16 wrappedKeyLen = sizeof(wrappedKey);
    U16 ret = 0;
    if (*keyLen == 65) { // public key
        ret = HOSTCRYPTO_AesWrapKeyRFC3394(wrapKey, wrapKeyLen, wrappedKey, &wrappedKeyLen,
            key + 1, (*keyLen) - 1);
    }
    else {
        ret = HOSTCRYPTO_AesWrapKeyRFC3394(wrapKey, wrapKeyLen, wrappedKey, &wrappedKeyLen,
            key, *keyLen);
    }
    if (ret == SW_OK) {
        *keyLen = wrappedKeyLen;
        memcpy(key, wrappedKey, wrappedKeyLen);
    }
    else {
        return AX_CLI_WRAP_ERROR;
    }


    return AX_CLI_EXEC_OK;
}

/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdSetGp(U16 offset, U8 *gpData, U16 gpDataLen, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdSetGp(offset, gpData, gpDataLen);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for set gp command. Can be called from GUI.
 */
U16 a7xCmdSetGp(U16 offset, U8 *gpData, U16 gpDataLen)
{
    U16 sw;

    sw = A71_SetGpData(offset, gpData, gpDataLen);
    return sw;
}

/**
 * A hook for the command line handler to invoke A71 commands
 */
// #define DUMP_DER_IN_FILE
int a7xConfigCmdSetGpFromPemfile(U16 offset, char *szFilename, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;
    X509 *x;
    FILE *fp;
#ifdef DUMP_DER_IN_FILE
    FILE *fpOut;
#endif

    int len;
    unsigned char *buf;

    printf("Filename: %s\n", szFilename);
    fp = fopen(szFilename, "r");
    if (!fp)
    {
        printf("Unable to open the file: %s\n", szFilename);
        return AX_CLI_FILE_OPEN_FAILED;
    }

    x = PEM_read_X509(fp, NULL, NULL, NULL);
    if (x == NULL)
    {
        printf("%s is not a valid pem file / certificate\n", szFilename);
        fclose(fp);
        return AX_CLI_FILE_PEM_READ_FAILED;
    }

#ifdef DUMP_DER_IN_FILE
    fpOut = fopen("cert.der", "wb");
    if (!fpOut)
    {
        printf("Unable to open the file: cert.der\n");
        return AX_CLI_FILE_OPEN_FAILED;
    }
    i2d_X509_fp(fpOut, x);
    fclose(fpOut);
#endif

    buf = NULL;
    len = i2d_X509(x, &buf);

    if (len < 0)
    {
        fclose(fp);
        return AX_CLI_PEM_CONVERT_FAILED;
    }
    else
    {
        int nStorageSize = A7X_CONFIG_GP_STORAGE_MAX; // No check is done on the actual GP storage size of the device attached
        int nMaxPos = offset + len;

        printf("Certificate Size (DER format) = %d byte\n", len);

        // Write to GP storage
        // (1) Is there enough storage?
        if (nMaxPos > nStorageSize)
        {
            printf("nMaxPos=%d; nStorageSize=%d\n", nMaxPos, nStorageSize);
            // No point in writing certificate as it will not fit
            free(buf);
            fclose(fp);
            return AX_CLI_BUFFER_SIZE_ERROR;
        }

        // (2) Write (and hope no segment is locked along the way)
        *sw = A71_SetGpData(offset, buf, (U16)len);
        free(buf);
        fclose(fp);
    }

    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    else
    {
        error = AX_CLI_EXEC_FAILED;
    }
    return error;
}


/**
* A hook for the command line handler to invoke A71 commands
*/
int a7xConfigCmdSetEccWrap(a71_SecureStorageClass_t ssc, U8 index, eccKeyComponents_t *eccKc, U8 * wrapKey, U16 wrapKeyLen, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;
    switch (ssc)
    {
    case A71_SSC_KEY_PAIR:
        error = a7xConfigCmdkWrapping(eccKc->priv, &eccKc->privLen, wrapKey, wrapKeyLen);
        break;
    case A71_SSC_PUBLIC_KEY:
        error = a7xConfigCmdkWrapping(eccKc->pub, &eccKc->pubLen, wrapKey, wrapKeyLen);
        if (error != AX_CLI_EXEC_OK) { return error; }
        break;
    default:
        break;
    }

    *sw = a7xCmdSetEcc(ssc, index, eccKc);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}


/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdSetEcc(a71_SecureStorageClass_t ssc, U8 index, eccKeyComponents_t *eccKc, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdSetEcc(ssc, index, eccKc);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for set ecc (keypair/pub) command. Can be called from GUI.
 */
U16 a7xCmdSetEcc(a71_SecureStorageClass_t ssc, U8 index, eccKeyComponents_t *eccKc)
{
    U16 sw;

    switch (ssc)
    {
        case A71_SSC_KEY_PAIR:
            sw = A71_SetEccKeyPair(index, eccKc->pub, eccKc->pubLen, eccKc->priv, eccKc->privLen);
            break;

        case A71_SSC_PUBLIC_KEY:
            sw = A71_SetEccPublicKey(index, eccKc->pub, eccKc->pubLen);
            break;

        default:
            sw = A7X_CONFIG_STATUS_API_ERROR;
            break;
    }

    return sw;
}


/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdSetEccFromPemfile(a71_SecureStorageClass_t ssc, U8 index, char *szFilename, int argc, char ** argv, int *argCurrent, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;
    eccKeyComponents_t eccKc;

    eccKc.bits = 256;
    eccKc.curve = ECCCurve_NIST_P256;
    eccKc.privLen = 0;
    eccKc.pubLen = 0;

    error = a7xConfigGetEccKcFromPemfile(&eccKc, ssc, szFilename);
    if (error == AX_CLI_EXEC_OK)
    {
        if (ssc == A71_SSC_KEY_PAIR) {
            error = a7xConfigCmdCheckWrapping(eccKc.priv, &eccKc.privLen, argc, argv, argCurrent);
        }
        else if (ssc == A71_SSC_PUBLIC_KEY) {
            error = a7xConfigCmdCheckWrapping(eccKc.pub, &eccKc.pubLen, argc, argv, argCurrent);
        }
        if (error != AX_CLI_EXEC_OK) { return AX_CLI_EXEC_OK; }
        error = AX_CLI_EXEC_FAILED;
        *sw = a7xCmdSetEcc(ssc, index, &eccKc);
        if (*sw == SW_OK)
        {
            error = AX_CLI_EXEC_OK;
        }
    }
    return error;
}

/**
 * Get ecc (keypair/pub) as key pair components (key value contained in PEM key). Can be called from GUI.
 */
int a7xConfigGetEccKcFromPemfile(eccKeyComponents_t *eccKc, a71_SecureStorageClass_t ssc, const char *szKeyFile)
{
#ifdef OPENSSL
    // eccKeyComponents_t eccKcTls;
    FILE *fp;
    EC_KEY *ec_key = NULL;
    EVP_PKEY * pkey = NULL;
    const EC_POINT *pub_key = NULL;
    const BIGNUM *key_bn = BN_new();
    U16 bufLen = 0;

    /* Read external key file and set public and (optional) private key values */
    fp = fopen(szKeyFile, "r");
    if (!fp)
    {
        printf("Unable to open the file: %s\n", szKeyFile);
        return AX_CLI_FILE_OPEN_FAILED;
    }
    ec_key = PEM_read_eckey(fp, NULL, NULL, NULL);
    // TODO: Evaluate/Investigate whether comparing to NULL captures all error conditions
    if (ec_key == NULL)
    {
        // Need to set the file to start and try to read t for public key
        fseek(fp, 0, SEEK_SET);
        // If pem file contains only public key read it
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        if (pkey != NULL) {
            ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        }
        if (ec_key == NULL)
        {
            printf("Failed to extract ECC key from %s.\n", szKeyFile);
            fclose(fp);
            return AX_CLI_FILE_PEM_READ_FAILED;
        }
    }
    fclose(fp);

    // TODO: Compare the ECC keypair's curve - as stored in the PEM file - with the one claimed in cryptoType/bits
    if (ssc == A71_SSC_KEY_PAIR)
    {
        U16 sw;

        sw = HOSTCRYPTO_GetPrivateKey(ec_key, eccKc->priv, &(eccKc->privLen), (U16)sizeof(eccKc->priv));
        if (sw != SW_OK)
        {
            printf("HOSTCRYPTO_GetPrivateKey failed with 0x%04X.\n", sw);
            return AX_CLI_PEM_CONVERT_FAILED;
        }

        if ( ((eccKc->privLen)*8) != eccKc->bits )
        {
            printf("KeyLen in pemfile (%d) does not match bits (%d) in function invocation.\n", bufLen*8, eccKc->bits);
            return AX_CLI_BIT_CURVE_ERROR;
        }
#ifdef DBG_PROBE_A70
        axPrintByteArray("ECCPrivateKey", eccKc->priv, eccKc->privLen, AX_COLON_32);
#else
        printf("ECCPrivateKey: hidden\n");
#endif
    }

    // How do we know the key length?
    // Set Public Key
    pub_key = EC_KEY_get0_public_key(ec_key);
    key_bn = EC_POINT_point2bn(EC_KEY_get0_group(ec_key), pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
    eccKc->pubLen = (U16)BN_bn2bin(key_bn, eccKc->pub);
    bufLen = (U16)(EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))+7)/8;
    if ( (bufLen*8) != eccKc->bits )
    {
        printf("KeyLen in pemfile (%d) does not match bits (%d) in function invocation.\n", bufLen*8, eccKc->bits);
        return AX_CLI_BIT_CURVE_ERROR;
    }
    // bufLen = 2*bufLen + 1; //Public key length
    axPrintByteArray("ECCPublicKey", eccKc->pub, eccKc->pubLen, AX_COLON_32);
    return AX_CLI_EXEC_OK;
#else
    return AX_CLI_NOT_IMPLEMENTED;
#endif
}


/**
* A hook for the command line handler to invoke A71 commands
* Applied Keywrapping is implicit in the length of the secret
* 16 byte: no key wrapping
* 24 byte: wrapped with rfc3394
*/
int a7xConfigCmdSetSymWrap(U8 index, U8 *symSecret, U16 symSecretLen, U8 * wrapKey, U16 wrapKeyLen, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    if (wrapKeyLen>0) {
        U16 keyLen = symSecretLen;
        error = a7xConfigCmdkWrapping(symSecret, &keyLen, wrapKey, wrapKeyLen);
        if (error != AX_CLI_EXEC_OK) { return error; }
        *sw = a7xCmdSetSym(index, symSecret, keyLen);
        if (*sw == SW_OK)
        {
            error = AX_CLI_EXEC_OK;
        }
    }
    else {
        *sw = a7xCmdSetSym(index, symSecret, symSecretLen);
        if (*sw == SW_OK)
        {
            error = AX_CLI_EXEC_OK;
        }
    }
    return error;
}

/**
 * A hook for the command line handler to invoke A71 commands
 * Applied Keywrapping is implicit in the length of the secret
 * 16 byte: no key wrapping
 * 24 byte: wrapped with rfc3394
 */
int a7xConfigCmdSetSym(U8 index, U8 *symSecret, U16 symSecretLen, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdSetSym(index, symSecret, symSecretLen);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
* API wrapper for set sym command. Can be called from GUI.
* Applied Keywrapping is implicit in the length of the secret
*
*/
U16 a7xCmdSetSymWrap(U8 index, U8 *symSecret, U16 symSecretLen, U8 * wrapKey, U16 wrapKeyLen) {
    U16 error = AX_CLI_EXEC_FAILED;
    if (wrapKeyLen>0) {
        U16 keyLen = symSecretLen;
        error = (U16)a7xConfigCmdkWrapping(symSecret, &keyLen, wrapKey, wrapKeyLen);
        if (error != AX_CLI_EXEC_OK) { return error; }
        return a7xCmdSetSym(index, symSecret, keyLen);
    }
    else {
        return a7xCmdSetSym(index, symSecret, symSecretLen);
    }
}

/**
 * API wrapper for set sym command. Can be called from GUI.
 * Applied Keywrapping is implicit in the length of the secret
 * 16 byte: no key wrapping
 * 24 byte: wrapped with rfc3394
 */
U16 a7xCmdSetSym(U8 index, U8 *symSecret, U16 symSecretLen)
{
    U16 sw;


    switch (symSecretLen)
    {
    case 16:
        sw = A71_SetSymKey(index, symSecret, symSecretLen);
        break;

    case 24:
        sw = A71_SetRfc3394WrappedAesKey(index, symSecret, symSecretLen);
        break;

    default:
        sw = A7X_CONFIG_STATUS_API_ERROR;
        break;
    }

    return sw;
}

/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdSetCnt(U8 index, U8 *cnt, U16 cntLen, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdSetCnt(index, cnt, cntLen);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for set monotonic counter command. Can be called from GUI.
 */
U16 a7xCmdSetCnt(U8 index, U8 *cnt, U16 cntLen)
{
    U16 sw;

    if (cntLen != 4)
    {
        DBGPRINTF("axCmdSetCnt(..., cntLen=%d)\n", cntLen);
        sw = A7X_CONFIG_STATUS_API_ERROR;
    }
    else
    {
        U32 counter;

        counter = (cnt[0] << 24) + (cnt[1] << 16) + (cnt[2] << 8) + cnt[3];
        sw = A71_SetCounter(index, counter);
    }

    return sw;
}

/**
 * A hook for the command line handler to invoke A71 commands
 * Applied Keywrapping is implicit in the length of the config key
 * 16 byte: no key wrapping
 * 24 byte: wrapped with rfc3394
 */
int a7xConfigCmdSetConfigKey(U8 index, U8 *configKey, U16 configKeyLen, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdSetConfigKey(index, configKey, configKeyLen);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for SetConfigKey command. Can be called from GUI.
 * Applied Keywrapping is implicit in the length of the secret
 * 16 byte: no key wrapping
 * 24 byte: wrapped with rfc3394
 */
U16 a7xCmdSetConfigKey(U8 index, U8 *configKey, U16 configKeyLen)
{
    U16 sw;

    switch (configKeyLen)
    {
    case 16:
        sw = A71_SetConfigKey(index, configKey, configKeyLen);
        break;

    case 24:
        sw = A71_SetRfc3394WrappedConfigKey(index, configKey, configKeyLen);
        break;

    default:
        sw = A7X_CONFIG_STATUS_API_ERROR;
        break;
    }

    return sw;
}
