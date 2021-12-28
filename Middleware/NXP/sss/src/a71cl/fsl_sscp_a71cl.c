/*
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fsl_sss_sscp.h>

#if SSS_HAVE_A71CL || SSS_HAVE_SE050_L

#include <HLSEAPI.h>
#include <a71cl_api.h>
#include <a71cl_util.h>
#include <fsl_sscp.h>
#include <fsl_sscp_a71ch.h>
#include <fsl_sscp_a71cl.h>
#include <fsl_sscp_commands.h>
#include <fsl_sss_keyid_map.h>
#include <fsl_sss_util_asn1_der.h>
#include <nxScp03_Types.h>
#include <sm_apdu.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "HostCryptoAPI.h"
#include "ax_api.h"
#include "nxLog_sss.h"
/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
/* Key store N Count */

#define CONVERT_BYTE(x) (x) / 8
#define CONVERT_BIT(x) (x) * 8
#define MAX_RSA_COMPONENT_SIZE (256 + 4 + 256) // rsaModulus + public_exponent + private_exponent
#define MAX_KEY_HEADER_SIZE (12 + 1 + 1 + 1)   //Key header contains 12 bytes cl_id + id_len + keytype + keyid
#define MAX_KEY_ELEMENT_SIZE (3 + 6)           // (key_tag + key_len) * 3 components
#define MAX_TLV_BUF_SIZE (MAX_RSA_COMPONENT_SIZE + MAX_KEY_HEADER_SIZE + MAX_KEY_ELEMENT_SIZE)

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static bool gapplet_mode_default = TRUE;
SE_Connect_Ctx_t pA71Auth_init   = {0};
/* clang-format off */
static U8 KEK[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F};

U8 *grsaPubKey = NULL;
U16 grsaPubKeyLen = 0;
/* clang-format on */

keyStoreTable_t gkeystore_shadow_cl;
keyIdAndTypeIndexLookup_t gLookupEntires_cl[KS_N_ENTIRES_CL];

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

static HLSE_RET_CODE a71cl_GenerateKey(
    keyStoreTable_t *keystore_shadow, uint8_t keyType, uint8_t cipherType, uint32_t KeyID, uint16_t keylen);

static sss_status_t swToSSSResult(uint16_t checkSW);

static HLSE_RET_CODE a71cl_AllocateKeyStore(sss_a71cl_key_store_t *keyStore, uint32_t keyStoreID);

static HLSE_RET_CODE a71cl_loadKeyStore(sss_a71cl_key_store_t *keyStore);
static HLSE_RET_CODE a71cl_saveKeyStore(sss_a71cl_key_store_t *keyStore);

static HLSE_RET_CODE a71cl_AllocateKeyObject(sss_a71cl_key_store_t *keyStore,
    uint32_t extKeyID,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

static U16 a71cl_setKey(keyStoreTable_t *keystore_shadow,
    sss_key_part_t key_part,
    sss_cipher_type_t cipher_type,
    uint32_t extId,
    uint8_t *key,
    size_t keyLen);

static U16 a71cl_rsaSign(keyStoreTable_t *keystore_shadow,
    uint8_t extKeyID,
    uint8_t *pHash,
    uint16_t hashLen,
    uint8_t *pSignature,
    uint16_t *pSignatureLen);

static U16 a71cl_rsaVerify(keyStoreTable_t *keystore_shadow,
    uint8_t extKeyID,
    uint8_t *pHash,
    uint16_t hashLen,
    uint8_t *pSignature,
    uint16_t SignatureLen);

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

static U16 a71cl_Scp02Authenticate()
{
    U16 err = SW_OK;
#ifdef USE_SCP02
    /* clang-format off */
    U8 keyEnc[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };
    U8 keyMac[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };
    U8 keyDek[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };
    /* clang-format on */
    U8 sCounter[3];
    U16 sCounterLen = sizeof(sCounter);
#endif
    if (CL_IsAppletInAuthenticationMode()) {
        gapplet_mode_default = FALSE;
    }
    else {
        gapplet_mode_default = TRUE;
#ifdef USE_SCP02
        err = SCP02_Authenticate(keyEnc, keyMac, keyDek, SCP_KEY_SIZE, sCounter, &sCounterLen);
#endif
    }
    return err;
}

static U16 a71cl_GetCryptType(sss_algorithm_t algo, sss_mode_t mode)
{
    U16 cryptType = (U16)(-1);
    switch (algo) {
    case kAlgorithm_SSS_AES_ECB:
        if (mode == kMode_SSS_Encrypt || mode == kMode_SSS_Decrypt)
            cryptType = eAES_ECB_NOPADDING;
        else if (mode == kMode_SSS_Sign || mode == kMode_SSS_Verify) {
            LOG_E("AES_ECB is not supported for sign and verify");
            cryptType = (U16)(-1);
        }
        break;

    case kAlgorithm_SSS_AES_CBC:
        if (mode == kMode_SSS_Encrypt || mode == kMode_SSS_Decrypt)
            cryptType = eAES_CBC_NOPADDING;
        else if (mode == kMode_SSS_Sign || mode == kMode_SSS_Verify)
            cryptType = eAES_CBC_ISO9797_M1;
        break;

    case kAlgorithm_SSS_DES3_ECB:
        if (mode == kMode_SSS_Encrypt || mode == kMode_SSS_Decrypt)
            cryptType = eDES_ECB_NOPADDING;
        else if (mode == kMode_SSS_Sign || mode == kMode_SSS_Verify) {
            LOG_E("DES_ECB is not supported for sign and verify");
            cryptType = (U16)(-1);
        }
        break;

    case kAlgorithm_SSS_DES3_CBC:
        if (mode == kMode_SSS_Encrypt || mode == kMode_SSS_Decrypt)
            cryptType = eDES_CBC_NOPADDING;
        else if (mode == kMode_SSS_Sign || mode == kMode_SSS_Verify)
            cryptType = eDES_CBC_ISO9797_M1;
        break;

    default:
        LOG_E("Algorithem is not supported by A71CL");
        cryptType = (U16)(-1);
    }
    return cryptType;
}

static U16 a71cl_Get_key(sss_cipher_type_t cipherType, U8 *key, size_t KeyByteLen)
{
    U16 err = ERR_API_ERROR;
    if (cipherType == kSSS_CipherType_RSA) {
        if (grsaPubKey) {
            memcpy(key, grsaPubKey + 2, grsaPubKeyLen);
            KeyByteLen = CONVERT_BIT(grsaPubKeyLen);
            err        = SW_OK;
        }
        else {
            LOG_E("RSA Key Pair not generated");
        }
    }
    else
        LOG_E("Can not get other than RSA Public key.");
    return err;
}

static U16 a71cl_symmCrypt(
    U8 *indata, U16 indataLen, sss_mode_t mode, sss_algorithm_t alg, U8 *iv, U16 ivLen, U8 *outData, size_t *outDataLen)
{
    eCLSymCryptMode CryptMode;
    eCLSymCryptType CryptType = (eCLSymCryptType)a71cl_GetCryptType(alg, mode);
    if (CryptType == (CryptType)-1)
        return ERR_API_ERROR;
    U16 blockSize = (alg == kAlgorithm_SSS_DES3_CBC || alg == kAlgorithm_SSS_DES3_ECB) ? 8 : 16;
    U8 *input     = NULL;
    U16 inputLen  = indataLen;
    U16 outLen    = 256;
    U16 err;
    U16 offset = 0;

    switch (mode) {
    case kMode_SSS_Encrypt:
        CryptMode = eEncrypt;
        inputLen  = indataLen + blockSize - (indataLen % blockSize);
        break;

    case kMode_SSS_Decrypt:
        CryptMode = eDecrypt;
        break;

    default:
        return ERR_API_ERROR;
        ;
    }

    if (alg == kAlgorithm_SSS_DES3_CBC || alg == kAlgorithm_SSS_AES_CBC) {
        inputLen += ivLen;
        input = SSS_MALLOC(inputLen);
        memset(input, 0, inputLen);
        memcpy(input, iv, ivLen);
        offset = ivLen;
    }
    else {
        input = SSS_MALLOC(inputLen);
        memset(input, 0, inputLen);
    }
    memcpy(input + offset, indata, indataLen);

    err         = CL_SymmetricCrypt(input, inputLen, CryptMode, CryptType, 0, outData, &outLen);
    *outDataLen = outLen;
    SSS_FREE(input);
    return err;
}

static U16 a71cl_rsaSign(keyStoreTable_t *keystore_shadow,
    uint8_t extKeyID,
    uint8_t *pHash,
    uint16_t hashLen,
    uint8_t *pSignature,
    uint16_t *pSignatureLen)
{
    U16 ret               = SW_OK;
    eCLAsymCryptMode mode = eAsymSign;
    eCLAsymCryptType type = eRSA_SHA256_PKCS1;
    ret                   = CL_AsymmetricCrypt(pHash, hashLen, mode, type, 0, pSignature, pSignatureLen);
    return ret;
}

static U16 a71cl_rsaVerify(keyStoreTable_t *keystore_shadow,
    uint8_t extKeyID,
    uint8_t *digest,
    uint16_t digestlen,
    uint8_t *pSignature,
    uint16_t SignatureLen)
{
    U16 ret = SW_OK;
    U8 allData[512];
    U16 retDatalen        = sizeof(allData);
    eCLAsymCryptMode mode = eAsymVerifySign;
    eCLAsymCryptType type = eRSA_SHA256_PKCS1;
    ret                   = CL_AsymmetricCrypt(pSignature, SignatureLen, mode, type, 0, allData, &retDatalen);
    return ret;
}

static U16 a71cl_rsaEncrypt(keyStoreTable_t *keystore_shadow,
    uint8_t KeyID,
    uint8_t *inputData,
    uint16_t inputDataLen,
    uint8_t *encryptedData,
    uint16_t *encryptedDataLen)
{
    U16 ret               = SW_OK;
    eCLAsymCryptMode mode = eAsymEncrypt;
    eCLAsymCryptType type = eRSA_SHA1_PKCS1;
    ret                   = CL_AsymmetricCrypt(inputData, inputDataLen, mode, type, 0, encryptedData, encryptedDataLen);
    return ret;
}

static U16 a71cl_rsaDecrypt(keyStoreTable_t *keystore_shadow,
    uint8_t KeyID,
    uint8_t *encryptedData,
    uint16_t encryptedDataLen,
    uint8_t *rawData,
    uint16_t rawDataLen)
{
    U16 ret               = SW_OK;
    eCLAsymCryptMode mode = eAsymDecrypt;
    eCLAsymCryptType type = eRSA_SHA1_PKCS1;
    ret                   = CL_AsymmetricCrypt(encryptedData, encryptedDataLen, mode, type, 0, rawData, &rawDataLen);
    return ret;
}

sss_status_t sscp_a71cl_openSession(const void *connectionData)
{
    HLSE_CONNECTION_PARAMS params      = {0};
    HLSE_COMMUNICATION_STATE commState = {0};
    HLSE_RET_CODE ret_code;
    uint32_t ret                = kStatus_SSS_Fail;
    SE_Connect_Ctx_t *pEncrCtxt = (SE_Connect_Ctx_t *)connectionData;

    commState.atrLen = MAX_APDU_BUF_LENGTH;
    if (pEncrCtxt == NULL) {
        LOG_I("pEncrCtxt is NULL");
        pEncrCtxt = &pA71Auth_init; // initialize pA71Auth parameters
    }
    else {
        params.pParameter = (void *)pEncrCtxt->portName;
        params.connType   = pEncrCtxt->connType;
    }
    if (pEncrCtxt == NULL || pEncrCtxt->portName == NULL)
        params.ulParameterLen = 0;
    else
        params.ulParameterLen = (U16)strlen(pEncrCtxt->portName);
    ret_code = HLSE_Connect(&params, &commState);
    if (ret_code == HLSE_SW_OK)
        ret = kStatus_SSS_Success;
    return (sss_status_t)ret;
}

void sscp_a71cl_closeSession(void)
{
    HLSE_CloseConnection(HLSE_CLOSE_CONNECTION_NO_RESET);
}

sss_status_t sscp_a71cl_init(sscp_a71cl_context_t *context, sss_a71cl_key_store_t *keyStore)
{
    sss_status_t status = kStatus_SSS_Fail;
    U16 err;
    if (context == NULL) {
        goto cleanup;
    }
    /* assign a71cl implementation of ::sscp_invoke_command() */
    context->keyStore               = keyStore;
    context->invoke                 = &sscp_a71cl_invoke_command;
    keyStore->session->sscp_context = (sscp_context_t *)context;
    err                             = a71cl_Scp02Authenticate();
    if (err == SW_OK)
        status = kStatus_SSS_Success;
cleanup:
    return status;
}

void sscp_a71cl_free(sscp_a71cl_context_t *context)
{
    if (context != NULL) {
        memset(context, 0, sizeof(*context));
    }
    if (grsaPubKey) {
        SSS_FREE(grsaPubKey);
        grsaPubKey = NULL;
    }
}

void getA7CLKeyStore(sss_a71cl_key_store_t **ks, sscp_context_reference_t *ref)
{
    switch (ref->type) {
    case kSSCP_ParamContextType_SSS_Symmetric: {
        sss_sscp_symmetric_t *ctx = (sss_sscp_symmetric_t *)ref->ptr;
        *ks                       = (sss_a71cl_key_store_t *)ctx->keyObject->keyStore;
    } break;
    case kSSCP_ParamContextType_SSS_Asymmetric: {
        sss_asymmetric_t *ctx = (sss_asymmetric_t *)ref->ptr;
        *ks                   = (sss_a71cl_key_store_t *)ctx->keyObject->keyStore;
        break;
    }
    case kSSCP_ParamContextType_SSS_Object: {
        sss_object_t *pobj = (sss_object_t *)ref->ptr;
        *ks                = (sss_a71cl_key_store_t *)pobj->keyStore;
        break;
    }
    case kSSCP_ParamContextType_SSS_KeyStore: {
        *ks = (sss_a71cl_key_store_t *)ref->ptr;
        break;
    }
    default:
        break;
    }
}

sscp_status_t sscp_a71cl_invoke_command(
    sscp_context_t *a71clContext, uint32_t commandID, sscp_operation_t *op, uint32_t *returnOrigin)
{
    uint16_t resSW        = SMCOM_SND_FAILED;
    sscp_status_t retSSCP = kStatus_SSCP_Success;
    uint8_t keyId;
    sss_a71cl_key_store_t *a71cl_keystore = NULL;

    sscp_a71cl_context_t *context = (sscp_a71cl_context_t *)a71clContext;
    if (kSSCP_ParamType_ContextReference == SSCP_OP_GET_PARAM(0, op->paramTypes)) {
        getA7CLKeyStore(&a71cl_keystore, &op->params[0].context);
    }
    switch (commandID) {
    case kSSCP_CMD_GENERATE_KEY:
        resSW = a71cl_GenerateKey(a71cl_keystore->keystore_shadow,
            op->params[1].value.a,
            op->params[2].value.b,
            op->params[1].value.b,
            op->params[2].value.a);
        break;

    case kSSCP_CMD_GET_KEY: {
        resSW = a71cl_Get_key(op->params[3].value.b, op->params[2].memref.buffer, (op->params[3].value.a));
    } break;

    case kSSCP_CMD_ALLOCATE_KEYSTORE:
        resSW = a71cl_AllocateKeyStore(a71cl_keystore, op->params[1].value.a);
        resSW = SMCOM_OK;
        break;

    case kSSCP_CMD_LOAD_KEYSTORE:
        resSW = a71cl_loadKeyStore(a71cl_keystore);
        resSW = SMCOM_OK;
        break;

    case kSSCP_CMD_SAVE_KEYSTORE:
        resSW = a71cl_saveKeyStore(a71cl_keystore);
        resSW = SMCOM_OK;
        break;
    case kSSCP_CMD_SET_KEY:
        resSW = a71cl_setKey(a71cl_keystore->keystore_shadow,
            op->params[1].value.a,
            op->params[3].value.b,
            op->params[1].value.b,
            op->params[2].memref.buffer,
            op->params[2].memref.size);
        break;

    case kSSCP_KEYOBJ_CMD_ALLOCATE_HANDLE:
        resSW = a71cl_AllocateKeyObject(a71cl_keystore,
            op->params[1].value.a,
            op->params[1].value.b,
            op->params[3].value.a,
            op->params[2].value.a,
            op->params[2].value.b);
        resSW = SMCOM_OK;
        break;

    case kSSCP_KEYOBJ_CMD_GET_HANDLE:
        resSW = SMCOM_OK;
        break;

    case kSSCP_ASYMMETRIC_CTX_INIT:
        op->params[3].value.a = (0xFFFFFFFFu ^ op->params[2].value.a);
        resSW                 = SMCOM_OK;
        break;
    case kSSCP_ASYMMETRIC_CMD_ENCRYPT:
        keyId = (0xFFFFFFFFu ^ op->params[1].value.a);
        resSW = a71cl_rsaEncrypt(a71cl_keystore->keystore_shadow,
            keyId,
            op->params[2].memref.buffer,
            (uint16_t)op->params[2].memref.size,
            op->params[3].memref.buffer,
            (uint16_t *)&op->params[3].memref.size);
        break;
    case kSSCP_ASYMMETRIC_CMD_DECRYPT:
        keyId = (0xFFFFFFFFu ^ op->params[1].value.a);
        resSW = a71cl_rsaDecrypt(a71cl_keystore->keystore_shadow,
            keyId,
            op->params[2].memref.buffer,
            (uint16_t)op->params[2].memref.size,
            op->params[3].memref.buffer,
            (uint16_t)op->params[3].memref.size);
        break;
    case kSSCP_ASYMMETRIC_CMD_SIGN_DIGEST:
        keyId = (0xFFFFFFFFu ^ op->params[1].value.a);
        resSW = a71cl_rsaSign(a71cl_keystore->keystore_shadow,
            keyId,
            op->params[2].memref.buffer,
            (uint16_t)op->params[2].memref.size,
            op->params[3].memref.buffer,
            (uint16_t *)&op->params[3].memref.size);
        break;
    case kSSCP_ASYMMETRIC_CMD_VERIFY_DIGEST:
        keyId = (0xFFFFFFFFu ^ op->params[1].value.a);
        resSW = a71cl_rsaVerify(context->keyStore->keystore_shadow,
            keyId,
            op->params[2].memref.buffer,
            (uint16_t)op->params[2].memref.size,
            op->params[3].memref.buffer,
            (uint16_t)op->params[3].memref.size);
        break;
    case kSSCP_SYMM_CIPHER_ONE_GO: {
        sss_algorithm_t algorithm = ((sss_sscp_symmetric_t *)op->params[0].context.ptr)->algorithm;
        sss_mode_t mode           = ((sss_sscp_symmetric_t *)op->params[0].context.ptr)->mode;
        resSW                     = a71cl_symmCrypt(op->params[3].memref.buffer,
            (U16)op->params[3].memref.size,
            mode,
            algorithm,
            op->params[2].memref.buffer,
            (U16)op->params[2].memref.size,
            op->params[4].memref.buffer,
            &(op->params[4].memref.size));
        break;
    }
    case kSSCP_SYMM_CIPHER_CTX_INIT:
        op->params[2].value.a = (0xFFFFFFFFu ^ op->params[1].value.a);
        resSW                 = SMCOM_OK;
        break;

    case kSSCP_DERIVE_CTX_INIT:
        op->params[3].value.a = (0xFFFFFFFFu ^ op->params[2].value.a);
        resSW                 = SMCOM_OK;
        break;

    default:
        retSSCP = kStatus_SSCP_Fail;
        LOG_E("Not a SSCP command");
    }
    *returnOrigin = (uint32_t)swToSSSResult(resSW);
    return (retSSCP);
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */
static U16 a71cl_GenerateKey(
    keyStoreTable_t *keystore_shadow, uint8_t keyType, uint8_t cipherType, uint32_t KeyID, uint16_t keybytelen)
{
    U16 ret = ERR_API_ERROR;
    U8 *Key = NULL;
    if (keyType == kSSS_KeyPart_Pair && cipherType == kSSS_CipherType_RSA) {
        if ((keybytelen % 8) && keybytelen > 256) {
            LOG_E(
                "Keylen must be integer multiple of 8 and should be less than "
                "256 Bytes");
        }
        if (grsaPubKey) {
            SSS_FREE(grsaPubKey);
            grsaPubKey = NULL;
        }
        grsaPubKey = SSS_MALLOC(keybytelen + 8);
        if (grsaPubKey == NULL) {
            LOG_E("malloc failed");
            ret = ERR_MEMORY;
            goto cleanup;
            ;
        }
        memset(grsaPubKey, 0, keybytelen + 8);
        if (gapplet_mode_default) {
            ret = CL_GenerateKeyPair(grsaPubKey, keybytelen, eRSA, 0);
        }
        else {
            ret = CL_GenerateKeyPairWithKEK(grsaPubKey, keybytelen, eRSA, 0, KEK, sizeof(KEK));
        }
        if (ret != SW_OK) {
            LOG_E("CL_GenerateKeyPair failed");
            goto cleanup;
        }
        grsaPubKeyLen = keybytelen;
    }
    else if (keyType == kSSS_KeyPart_Default &&
             (cipherType == kSSS_CipherType_DES || cipherType == kSSS_CipherType_AES)) {
        Key = SSS_MALLOC(keybytelen);
        ret = CL_GetChallenge(Key, keybytelen);
        if (ret != SW_OK) {
            LOG_E("Get Random failed with status 0x%X", ret);
            goto cleanup;
        }
        ret = a71cl_setKey(keystore_shadow, keyType, cipherType, 0, Key, keybytelen);
        if (ret != SW_OK) {
            LOG_E("a71cl_setKey failed with status 0x%X", ret);
            goto cleanup;
        }
    }
    else {
        LOG_E("Key Type Not Supported");
        goto cleanup;
    }
cleanup:
    if (Key) {
        SSS_FREE(Key);
    }
    return ret;
}

static sss_status_t swToSSSResult(uint16_t checkSW)
{
    switch (checkSW) {
    case SMCOM_OK:
        return kStatus_SSS_Success;
    default:
        return kStatus_SSS_Fail;
    }
}

static HLSE_RET_CODE a71cl_AllocateKeyStore(sss_a71cl_key_store_t *keyStore, uint32_t keyStoreID)
{
    HLSE_RET_CODE hlseret = SW_OK;
    if (gapplet_mode_default == FALSE) {
        hlseret = HLSE_ERR_API_ERROR;
        HLSE_OBJECT_HANDLE Handles[5];
        U16 HandlesNum = sizeof(Handles) / sizeof(HLSE_OBJECT_HANDLE);
        U16 HandlesNum_copy;
        U8 i                    = 0;
        HLSE_OBJECT_INDEX index = 0;

        /* Search for our data table @ index */
        if (keyStore->shadow_handle == 0) {
            hlseret = HLSE_EnumerateObjects(HLSE_DATA, Handles, &HandlesNum);
            if (hlseret == HLSE_SW_OK) {
                HandlesNum_copy = HandlesNum;
                while (HandlesNum_copy) {
                    if (HLSE_GET_OBJECT_INDEX(Handles[i]) == index) {
                        keyStore->shadow_handle = Handles[i];
                        break;
                    }
                    i++;
                    HandlesNum_copy--;
                }
            }
        }
        /* If it was never there, create it @ index */
        if (keyStore->shadow_handle == 0) {
            /* Could not find it yet*/
            HLSE_KEK_WRAPPED_OBJECT_PARAMS kekparm;
            memcpy(kekparm.KEK, KEK, sizeof(KEK));
            kekparm.KEKLen           = sizeof(KEK);
            kekparm.value            = (U8 *)&gkeystore_shadow_cl;
            kekparm.valueLen         = sizeof(gkeystore_shadow_cl);
            HLSE_OBJECT_TYPE objType = HLSE_DATA;
            U16 templateSize         = 3;
            HLSE_ATTRIBUTE attr[3];
            ks_common_init_fat(&gkeystore_shadow_cl, gLookupEntires_cl, ARRAY_SIZE(gLookupEntires_cl));
            keyStore->keystore_shadow = &gkeystore_shadow_cl;
            attr[0].type              = HLSE_ATTR_OBJECT_TYPE;
            attr[0].value             = &objType;
            attr[0].valueLen          = sizeof(objType);
            attr[1].type              = HLSE_ATTR_OBJECT_INDEX;
            attr[1].value             = &index;
            attr[1].valueLen          = sizeof(index);
            attr[2].type              = HLSE_ATTR_WRAPPED_OBJECT_VALUE;
            attr[2].value             = &kekparm;
            attr[2].valueLen          = sizeof(HLSE_KEK_WRAPPED_OBJECT_PARAMS);

            hlseret = HLSE_CreateObject(attr, templateSize, &keyStore->shadow_handle);
        }

        /* Either we created it. Or it was already existing, read it. */
        if (keyStore->shadow_handle != 0) {
            hlseret = a71cl_loadKeyStore(keyStore);
        }
    }
    return hlseret;
}

static HLSE_RET_CODE a71cl_loadKeyStore(sss_a71cl_key_store_t *keyStore)
{
    HLSE_RET_CODE hlseret = SW_OK;
    if (gapplet_mode_default == FALSE) {
        hlseret = HLSE_ERR_API_ERROR;
        HLSE_ATTRIBUTE attr;
        attr.type     = HLSE_ATTR_OBJECT_VALUE;
        attr.value    = &gkeystore_shadow_cl;
        attr.valueLen = sizeof(gkeystore_shadow_cl);
        /* Read from Key Store and load it here in gkeystore_shadow */
        hlseret                   = HLSE_GetObjectAttribute(keyStore->shadow_handle, &attr);
        keyStore->keystore_shadow = &gkeystore_shadow_cl;
    }
    return hlseret;
}
static HLSE_RET_CODE a71cl_saveKeyStore(sss_a71cl_key_store_t *keyStore)
{
    HLSE_RET_CODE hlseret;
    if (keyStore->shadow_handle == 0) {
        hlseret = HLSE_ERR_API_ERROR;
    }
    else {
        HLSE_ATTRIBUTE attr;
        HLSE_KEK_WRAPPED_OBJECT_PARAMS kekparm;
        memcpy(kekparm.KEK, KEK, sizeof(KEK));
        kekparm.KEKLen   = sizeof(KEK);
        kekparm.value    = (U8 *)keyStore->keystore_shadow;
        kekparm.valueLen = sizeof(*keyStore->keystore_shadow);
        attr.type        = HLSE_ATTR_WRAPPED_OBJECT_VALUE;
        attr.value       = &kekparm;
        attr.valueLen    = sizeof(kekparm);
        /* write gkeystore_shadow */
        hlseret = HLSE_SetObjectAttribute(keyStore->shadow_handle, &attr);
    }
    return hlseret;
}

static U16 a71cl_AllocateKeyObject(sss_a71cl_key_store_t *keyStore,
    uint32_t extKeyID,
    sss_key_part_t key_part,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    HLSE_RET_CODE hlseret = HLSE_SW_OK;
    uint16_t intIndex     = 0;
    sss_status_t ks_status;

    ks_status = ks_common_check_available_int_index(
        keyStore->keystore_shadow, (uint8_t)key_part, cipherType, &intIndex, (uint16_t)keyByteLenMax);

    if (ks_status != kStatus_SSS_Success) {
        hlseret = HLSE_ERR_MEMORY;
    }

    if (hlseret == HLSE_SW_OK) {
        ks_status = ks_common_update_fat(keyStore->keystore_shadow,
            extKeyID,
            (uint8_t)key_part,
            (uint8_t)cipherType,
            (uint8_t)intIndex,
            0,
            (uint16_t)keyByteLenMax);
    }
    if (ks_status != kStatus_SSS_Success) {
        hlseret = HLSE_ERR_MEMORY;
    }
    if (hlseret == HLSE_SW_OK) {
        /* Persist to EEPROM */
        hlseret = a71cl_saveKeyStore(keyStore);
    }
    else {
        /* Reset the structure based on EEPROM */
        a71cl_loadKeyStore(keyStore);
    }
    return hlseret;
}

static U16 a71cl_setKey(keyStoreTable_t *keystore_shadow,
    sss_key_part_t key_part,
    sss_cipher_type_t cipher_type,
    uint32_t extId,
    uint8_t *key,
    size_t keyByteLen)
{
    U16 ret = 0;
    U8 keyBuffer[MAX_TLV_BUF_SIZE];

    /* clang-format off */
    U8 CL[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0x11, 0x22, 0x33, 0x44,};
    /* clang-format on */
    U16 offset = 0;

    keyBuffer[offset++] = sizeof(CL);
    memcpy(keyBuffer + offset, CL, sizeof(CL));
    offset += sizeof(CL);
    keyBuffer[offset++] =
        ((cipher_type == kSSS_CipherType_DES) ? e3DES : (cipher_type == kSSS_CipherType_AES) ? eAES : eRSA);
    keyBuffer[offset++] = 0; // Key ID is always 0

    if (cipher_type == kSSS_CipherType_AES || cipher_type == kSSS_CipherType_DES) {
        keyBuffer[offset++] = ((cipher_type == kSSS_CipherType_DES) ? etag3ES : etagAES);
        keyBuffer[offset++] = (U8)(keyByteLen >> 8);
        keyBuffer[offset++] = keyByteLen & 0xFF;
        memcpy(keyBuffer + offset, key, keyByteLen);
        offset += (U16)keyByteLen;
    }
    else if (key_part == kSSS_KeyPart_Public && cipher_type == kSSS_CipherType_RSA) {
        U8 *rsaN, *rsaE;
        size_t rsaNlen, rsaElen;
        ret = sss_util_asn1_rsa_parse_public(key, keyByteLen, &rsaN, &rsaNlen, &rsaE, &rsaElen);

        if (ret == 0) {
            keyBuffer[offset++] = etagRSA_N;
            keyBuffer[offset++] = (U8)(rsaNlen >> 8);
            keyBuffer[offset++] = rsaNlen & 0xFF;
            memcpy(keyBuffer + offset, rsaN, rsaNlen);
            offset += (U16)rsaNlen;

            keyBuffer[offset++] = etagRSA_E;
            keyBuffer[offset++] = (U8)(rsaElen >> 8);
            keyBuffer[offset++] = rsaElen & 0xFF;
            memcpy(keyBuffer + offset, rsaE, rsaElen);
            offset += (U16)rsaElen;
        }
    }
    else if ((key_part == kSSS_KeyPart_Private || key_part == kSSS_KeyPart_Pair) &&
             cipher_type == kSSS_CipherType_RSA) {
        U8 *rsaN, *rsaE, *rsaD;
        size_t rsaNlen, rsaElen, rsaDlen;

        ret = sss_util_asn1_rsa_parse_private(key,
            keyByteLen,
            cipher_type,
            &rsaN,
            &rsaNlen,
            &rsaE,
            &rsaElen,
            &rsaD,
            &rsaDlen,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL);

        if (ret == 0) {
            keyBuffer[offset++] = etagRSA_N;
            keyBuffer[offset++] = (U8)(rsaNlen >> 8);
            keyBuffer[offset++] = rsaNlen & 0xFF;
            memcpy(keyBuffer + offset, rsaN, rsaNlen);
            offset += (U16)rsaNlen;

            keyBuffer[offset++] = etagRSA_E;
            keyBuffer[offset++] = (U8)(rsaElen >> 8);
            keyBuffer[offset++] = rsaElen & 0xFF;
            memcpy(keyBuffer + offset, rsaE, rsaElen);
            offset += (U16)rsaElen;

            keyBuffer[offset++] = etagRSA_D;
            keyBuffer[offset++] = (U8)(rsaDlen >> 8);
            keyBuffer[offset++] = rsaDlen & 0xFF;
            memcpy(keyBuffer + offset, rsaD, rsaDlen);
            offset += (U16)rsaDlen;
        }
    }
    else {
        LOG_E("Key Type is not Supported");
        return ERR_API_ERROR;
    }
    if (ret == 0) {
        if (gapplet_mode_default) {
            ret = CL_SecurityStorage(keyBuffer, offset);
        }
        else {
            ret = CL_SecurityStorageWithKEK(keyBuffer, offset, KEK, sizeof(KEK));
        }
        if (ret != SW_OK) {
            LOG_E("Security Storage failed with status 0x%X", ret);
            return ret;
        }
    }
    return ret;
}
#endif /* SSS_HAVE_a71cl */
